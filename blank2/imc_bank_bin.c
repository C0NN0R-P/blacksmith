
#define _GNU_SOURCE
/*
 * imc_bank_bin_perf.c
 *
 * Userspace "bank binning" on Intel Skylake-SP / Skylake-X (SKX) using IMC uncore perf counters.
 *
 * Idea (no timing, no kernel module):
 *   For each candidate address:
 *     - program an uncore_imc_X CAS counter with a BANK filter value
 *     - touch the address N times (to generate DRAM reads)
 *     - read the counter delta
 *   The bank filter that produces the largest delta is the most likely bank for that address.
 *
 * This doesn't require decoding SAD/TAD/RIR, and it doesn't need your own kernel module.
 * It *does* require:
 *   - root (typically) for uncore perf
 *   - a kernel exposing uncore_imc_* perf PMUs (e.g., /sys/bus/event_source/devices/uncore_imc_0)
 *
 * Output:
 *   - CSV: va,pa,imc,bank,bg,delta
 *   - JSON: meta + per-item assignments
 *
 * Notes:
 *   - On many SKX systems, bank filters exist (filter_bank / filter_bg). If your PMU doesn't
 *     expose those "format/" entries, this method won't work on that machine/kernel.
 *   - This is probabilistic. If deltas are close across banks, either your accesses are
 *     hitting LLC, your event isn't counting what we think, or filters aren't supported.
 */

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/perf_event.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096ULL
#endif

/* ---------------- small helpers ---------------- */

static void die(const char *fmt, ...) __attribute__((noreturn));
static void die(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    exit(1);
}

static void warnx(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}

static uint64_t parse_u64(const char *s)
{
    errno = 0;
    char *end = NULL;
    unsigned long long v = strtoull(s, &end, 0);
    if (errno || !end || *end != '\0') die("bad integer: '%s'", s);
    return (uint64_t)v;
}

static void pin_to_cpu0(void)
{
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(0, &set);
    if (sched_setaffinity(0, sizeof(set), &set) != 0) {
        warnx("warn: sched_setaffinity failed: %s\n", strerror(errno));
    }
}

static void try_raise_priority(void)
{
    (void)setpriority(PRIO_PROCESS, 0, -10);
}

/* ---------------- VA -> PA via pagemap ---------------- */

static int g_pagemap_fd = -1;

static bool va_to_pa(uint64_t va, uint64_t *pa_out)
{
    if (g_pagemap_fd < 0) {
        g_pagemap_fd = open("/proc/self/pagemap", O_RDONLY);
        if (g_pagemap_fd < 0) return false;
    }

    const uint64_t vpn = va / PAGE_SIZE;
    const off_t off = (off_t)(vpn * 8ULL);

    uint64_t entry = 0;
    ssize_t n = pread(g_pagemap_fd, &entry, sizeof(entry), off);
    if (n != (ssize_t)sizeof(entry)) return false;

    const uint64_t present = (entry >> 63) & 1ULL;
    if (!present) return false;

    const uint64_t pfn = entry & ((1ULL << 55) - 1ULL);
    if (pfn == 0) return false;

    *pa_out = (pfn * PAGE_SIZE) | (va & (PAGE_SIZE - 1ULL));
    return true;
}

/* ---------------- sysfs helpers ---------------- */

static bool read_file_u64(const char *path, uint64_t *out)
{
    char buf[256];
    int fd = open(path, O_RDONLY);
    if (fd < 0) return false;
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return false;
    buf[n] = '\0';
    /* allow hex or dec */
    errno = 0;
    char *end = NULL;
    unsigned long long v = strtoull(buf, &end, 0);
    if (errno) return false;
    *out = (uint64_t)v;
    return true;
}

static bool read_file_str(const char *path, char *out, size_t out_sz)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) return false;
    ssize_t n = read(fd, out, out_sz - 1);
    close(fd);
    if (n <= 0) return false;
    out[n] = '\0';
    /* strip trailing newline */
    while (n > 0 && (out[n-1] == '\n' || out[n-1] == '\r' || out[n-1] == ' ' || out[n-1] == '\t')) {
        out[n-1] = '\0';
        n--;
    }
    return true;
}

/*
 * Parse a perf "format" line like:
 *   "config1:0-3"
 *   "config:8"
 *
 * We only support the simple shapes we actually see in uncore IMC PMUs.
 */
typedef struct {
    int which;      /* 0 => config, 1 => config1, 2 => config2 */
    int lo_bit;
    int hi_bit;
} fmt_bits_t;

static bool parse_format_bits(const char *s, fmt_bits_t *out)
{
    /* expected "configX:a-b" or "configX:a" */
    if (!s || !out) return false;

    int which = -1;
    if (!strncmp(s, "config:", 7)) which = 0;
    else if (!strncmp(s, "config1:", 8)) which = 1;
    else if (!strncmp(s, "config2:", 8)) which = 2;
    else return false;

    const char *p = strchr(s, ':');
    if (!p) return false;
    p++;

    char *end = NULL;
    errno = 0;
    long lo = strtol(p, &end, 10);
    if (errno || end == p) return false;

    long hi = lo;
    if (*end == '-') {
        errno = 0;
        hi = strtol(end + 1, &end, 10);
        if (errno) return false;
    }

    if (lo < 0 || hi < lo || hi > 63) return false;

    out->which = which;
    out->lo_bit = (int)lo;
    out->hi_bit = (int)hi;
    return true;
}

static uint64_t mask_for_range(int lo, int hi)
{
    int width = hi - lo + 1;
    if (width >= 64) return ~0ULL;
    return ((1ULL << width) - 1ULL) << lo;
}


static void set_bits_range_u64(uint64_t *dst, int lo, int hi, uint64_t value)
{
    uint64_t m = mask_for_range(lo, hi);
    uint64_t v = (value << lo) & m;
    *dst = (*dst & ~m) | v;
}

/* ---------------- perf helpers ---------------- */

static long perf_event_open(struct perf_event_attr *attr, pid_t pid, int cpu, int group_fd, unsigned long flags)
{
    return syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

typedef struct {
    int imc_idx;            /* uncore_imc_<idx> */
    uint64_t type;          /* PMU type */
    uint64_t event_config;  /* e.g., cas_count_read event code */
    bool have_filter_bank;
    bool have_filter_bg;
    fmt_bits_t filter_bank_bits;
    fmt_bits_t filter_bg_bits;
} imc_pmu_t;

/*
 * Load PMU metadata from sysfs:
 *   /sys/bus/event_source/devices/uncore_imc_<idx>/{type,events/,format/}
 *
 * We assume the event name is "cas_count_read" by default (override via --event).
 */
static bool load_imc_pmu(int idx, const char *event_name, imc_pmu_t *out)
{
    char path[512];
    char tmp[256];

    memset(out, 0, sizeof(*out));
    out->imc_idx = idx;

    snprintf(path, sizeof(path), "/sys/bus/event_source/devices/uncore_imc_%d/type", idx);
    if (!read_file_u64(path, &out->type)) return false;

    /* Event encoding: /events/<event_name> contains something like "event=0x04" */
    snprintf(path, sizeof(path), "/sys/bus/event_source/devices/uncore_imc_%d/events/%s", idx, event_name);
    if (!read_file_str(path, tmp, sizeof(tmp))) return false;

    /* Parse "event=0x.." from the file. */
    const char *eq = strchr(tmp, '=');
    if (!eq) return false;
    uint64_t ev = 0;
    errno = 0;
    ev = strtoull(eq + 1, NULL, 0);
    if (errno) return false;
    out->event_config = ev;

    /* Filters are optional; if not present, binning won't work. */
    snprintf(path, sizeof(path), "/sys/bus/event_source/devices/uncore_imc_%d/format/filter_bank", idx);
    if (read_file_str(path, tmp, sizeof(tmp))) {
        fmt_bits_t fb;
        if (parse_format_bits(tmp, &fb)) {
            out->have_filter_bank = true;
            out->filter_bank_bits = fb;
        }
    }

    snprintf(path, sizeof(path), "/sys/bus/event_source/devices/uncore_imc_%d/format/filter_bg", idx);
    if (read_file_str(path, tmp, sizeof(tmp))) {
        fmt_bits_t fbg;
        if (parse_format_bits(tmp, &fbg)) {
            out->have_filter_bg = true;
            out->filter_bg_bits = fbg;
        }
    }

    return true;
}

/*
 * Open one counting event for a specific (bank,bg) filter.
 * We keep it per-CPU (cpu=0) because uncore PMUs are system-wide.
 */
static int open_imc_counter(const imc_pmu_t *pmu, int cpu, int bank, int bg)
{
    struct perf_event_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.size = sizeof(attr);

    attr.type = (uint32_t)pmu->type;
    attr.config = pmu->event_config;
    attr.disabled = 1;
    attr.exclude_kernel = 0;
    attr.exclude_hv = 0;

    uint64_t config1 = 0, config2 = 0;

    if (pmu->have_filter_bank) {
        if (pmu->filter_bank_bits.which == 0) set_bits_range_u64(&attr.config, pmu->filter_bank_bits.lo_bit, pmu->filter_bank_bits.hi_bit, (uint64_t)bank);
        else if (pmu->filter_bank_bits.which == 1) set_bits_range_u64(&config1, pmu->filter_bank_bits.lo_bit, pmu->filter_bank_bits.hi_bit, (uint64_t)bank);
        else set_bits_range_u64(&config2, pmu->filter_bank_bits.lo_bit, pmu->filter_bank_bits.hi_bit, (uint64_t)bank);
    }

    if (pmu->have_filter_bg) {
        if (pmu->filter_bg_bits.which == 0) set_bits_range_u64(&attr.config, pmu->filter_bg_bits.lo_bit, pmu->filter_bg_bits.hi_bit, (uint64_t)bg);
        else if (pmu->filter_bg_bits.which == 1) set_bits_range_u64(&config1, pmu->filter_bg_bits.lo_bit, pmu->filter_bg_bits.hi_bit, (uint64_t)bg);
        else set_bits_range_u64(&config2, pmu->filter_bg_bits.lo_bit, pmu->filter_bg_bits.hi_bit, (uint64_t)bg);
    }

    attr.config1 = config1;
    attr.config2 = config2;

    int fd = (int)perf_event_open(&attr, -1 /* pid */, cpu, -1, 0);
    return fd;
}

static uint64_t read_counter(int fd)
{
    uint64_t v = 0;
    ssize_t n = read(fd, &v, sizeof(v));
    if (n != (ssize_t)sizeof(v)) return 0;
    return v;
}

/* ---------------- access pattern ---------------- */

static inline void clflush_line(void *p)
{
    __builtin_ia32_clflush(p);
}

static inline void mfence(void)
{
    __builtin_ia32_mfence();
}

/*
 * Generate DRAM reads for an address.
 * We:
 *   - clflush the line (best-effort) so the next load wants memory
 *   - load it (volatile)
 * Repeat N times.
 *
 * If your system has strong LLC prefetching, consider:
 *   - using a small "eviction buffer" to evict LLC sets
 *   - or using larger stride / random order
 */
static uint64_t touch_reads(volatile uint8_t *p, int touches)
{
    uint64_t acc = 0;
    for (int i = 0; i < touches; i++) {
        clflush_line((void*)p);
        mfence();
        acc += *p;
    }
    return acc;
}

/* ---------------- output structs ---------------- */

typedef struct {
    volatile uint8_t *va;
    uint64_t pa;
    int imc;        /* imc index used for best match */
    int bank;
    int bg;
    uint64_t delta; /* counter delta at best match */
} item_t;

static void write_csv(FILE *f, const item_t *items, int n_items)
{
    fprintf(f, "va,pa,imc,bank,bg,delta\n");
    for (int i = 0; i < n_items; i++) {
        fprintf(f, "0x%016" PRIx64 ",0x%016" PRIx64 ",%d,%d,%d,%" PRIu64 "\n",
                (uint64_t)(uintptr_t)items[i].va,
                items[i].pa,
                items[i].imc,
                items[i].bank,
                items[i].bg,
                items[i].delta);
    }
}

static void write_json(FILE *f,
                       const item_t *items,
                       int n_items,
                       const char *event_name,
                       int touches,
                       int n_imc,
                       int max_bank,
                       int max_bg)
{
    fprintf(f, "{\n");
    fprintf(f, "  \"meta\": {\n");
    fprintf(f, "    \"n_items\": %d,\n", n_items);
    fprintf(f, "    \"event\": \"%s\",\n", event_name);
    fprintf(f, "    \"touches\": %d,\n", touches);
    fprintf(f, "    \"n_imc\": %d,\n", n_imc);
    fprintf(f, "    \"max_bank\": %d,\n", max_bank);
    fprintf(f, "    \"max_bg\": %d\n", max_bg);
    fprintf(f, "  },\n");
    fprintf(f, "  \"items\": [\n");
    for (int i = 0; i < n_items; i++) {
        fprintf(f,
                "    {\"va\":\"0x%016" PRIx64 "\",\"pa\":\"0x%016" PRIx64 "\",\"imc\":%d,\"bank\":%d,\"bg\":%d,\"delta\":%" PRIu64 "}%s\n",
                (uint64_t)(uintptr_t)items[i].va,
                items[i].pa,
                items[i].imc,
                items[i].bank,
                items[i].bg,
                items[i].delta,
                (i == n_items - 1) ? "" : ",");
    }
    fprintf(f, "  ]\n");
    fprintf(f, "}\n");
}

/* ---------------- main ---------------- */

static void usage(const char *argv0)
{
    fprintf(stderr,
        "usage: %s [options]\n"
        "\n"
        "options:\n"
        "  --n N              number of candidate addresses (default 256)\n"
        "  --alloc-mb MB      allocation size in MB (default 256)\n"
        "  --stride BYTES     stride between candidates (default 4096)\n"
        "  --touches N        loads per (imc,bank,bg) probe (default 2000)\n"
        "  --imc N            number of uncore_imc instances to try (default 2)\n"
        "  --banks N          bank values to try [0..N-1] (default 16)\n"
        "  --bgs N            bank-group values to try [0..N-1] (default 4)\n"
        "  --event NAME       uncore event name (default cas_count_read)\n"
        "  --csv PATH         write CSV (default banks.csv)\n"
        "  --json PATH        write JSON (default banks.json)\n"
        "  --no-pin           don't pin to CPU0\n"
        "\n"
        "notes:\n"
        "  - Needs uncore_imc_* perf PMUs and filter_bank (and ideally filter_bg).\n"
        "  - Run as root if perf paranoia blocks uncore.\n",
        argv0);
}

int main(int argc, char **argv)
{
    int n = 256;
    uint64_t alloc_mb = 256;
    uint64_t stride = PAGE_SIZE;
    int touches = 2000;

    int n_imc = 2;     /* try uncore_imc_0 .. uncore_imc_(n_imc-1) */
    int max_bank = 16; /* 16 bank values (0..15) is the common starting point */
    int max_bg = 4;    /* 4 bank groups (0..3) for DDR4 */

    const char *event_name = "cas_count_read";
    const char *csv_path = "banks.csv";
    const char *json_path = "banks.json";
    bool do_pin = true;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--n") && i + 1 < argc) {
            n = (int)parse_u64(argv[++i]);
        } else if (!strcmp(argv[i], "--alloc-mb") && i + 1 < argc) {
            alloc_mb = parse_u64(argv[++i]);
        } else if (!strcmp(argv[i], "--stride") && i + 1 < argc) {
            stride = parse_u64(argv[++i]);
        } else if (!strcmp(argv[i], "--touches") && i + 1 < argc) {
            touches = (int)parse_u64(argv[++i]);
        } else if (!strcmp(argv[i], "--imc") && i + 1 < argc) {
            n_imc = (int)parse_u64(argv[++i]);
        } else if (!strcmp(argv[i], "--banks") && i + 1 < argc) {
            max_bank = (int)parse_u64(argv[++i]);
        } else if (!strcmp(argv[i], "--bgs") && i + 1 < argc) {
            max_bg = (int)parse_u64(argv[++i]);
        } else if (!strcmp(argv[i], "--event") && i + 1 < argc) {
            event_name = argv[++i];
        } else if (!strcmp(argv[i], "--csv") && i + 1 < argc) {
            csv_path = argv[++i];
        } else if (!strcmp(argv[i], "--json") && i + 1 < argc) {
            json_path = argv[++i];
        } else if (!strcmp(argv[i], "--no-pin")) {
            do_pin = false;
        } else if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) {
            usage(argv[0]);
            return 0;
        } else {
            usage(argv[0]);
            die("unknown/invalid option: %s", argv[i]);
        }
    }

    if (n <= 0) die("--n must be > 0");
    if (stride == 0) die("--stride must be > 0");
    if (touches <= 0) die("--touches must be > 0");
    if (n_imc <= 0) die("--imc must be > 0");
    if (max_bank <= 0) die("--banks must be > 0");
    if (max_bg <= 0) die("--bgs must be > 0");

    if (do_pin) pin_to_cpu0();
    try_raise_priority();

    /* Load IMC PMUs we can actually use. */
    imc_pmu_t *pmus = calloc((size_t)n_imc, sizeof(*pmus));
    if (!pmus) die("calloc pmus failed");

    int usable = 0;
    for (int i = 0; i < n_imc; i++) {
        if (!load_imc_pmu(i, event_name, &pmus[i])) {
            warnx("warn: couldn't load uncore_imc_%d (missing sysfs?)\n", i);
            continue;
        }
        if (!pmus[i].have_filter_bank) {
            warnx("warn: uncore_imc_%d has no filter_bank format; can't bin by bank on this PMU\n", i);
            continue;
        }
        usable++;
    }
    if (usable == 0) {
        die("no usable uncore_imc PMUs with filter_bank; check /sys/bus/event_source/devices/uncore_imc_*");
    }

    uint64_t alloc_bytes = alloc_mb * 1024ULL * 1024ULL;

    uint8_t *buf = mmap(NULL, alloc_bytes, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (buf == MAP_FAILED) die("mmap failed: %s", strerror(errno));

    /* Fault in pages. */
    for (uint64_t off = 0; off < alloc_bytes; off += PAGE_SIZE) {
        buf[off] = (uint8_t)(off ^ 0xA5);
    }

    item_t *items = calloc((size_t)n, sizeof(*items));
    if (!items) die("calloc items failed");

    int n_items = 0;
    for (uint64_t off = 0; off < alloc_bytes && n_items < n; off += stride) {
        volatile uint8_t *p = (volatile uint8_t *)(buf + off);
        uint64_t pa = 0;
        (void)va_to_pa((uint64_t)(uintptr_t)p, &pa);
        items[n_items].va = p;
        items[n_items].pa = pa;
        items[n_items].imc = -1;
        items[n_items].bank = -1;
        items[n_items].bg = -1;
        items[n_items].delta = 0;
        n_items++;
    }

    fprintf(stderr,
        "info: n_items=%d touches=%d imc=%d banks=%d bgs=%d event=%s stride=%" PRIu64 " alloc=%" PRIu64 "\n",
        n_items, touches, n_imc, max_bank, max_bg, event_name, stride, alloc_bytes);

    /* Main classification loop. */
    const int cpu = 0;
    for (int i = 0; i < n_items; i++) {
        uint64_t best_delta = 0;
        int best_imc = -1, best_bank = -1, best_bg = -1;

        /* Try each IMC PMU we managed to load. */
        for (int imc = 0; imc < n_imc; imc++) {
            if (!pmus[imc].have_filter_bank) continue;

            for (int bg = 0; bg < max_bg; bg++) {
                for (int bank = 0; bank < max_bank; bank++) {
                    int fd = open_imc_counter(&pmus[imc], cpu, bank, bg);
                    if (fd < 0) {
                        /* Common failures: EPERM / EACCES / ENOENT */
                        continue;
                    }

                    (void)ioctl(fd, PERF_EVENT_IOC_RESET, 0);
                    (void)ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);

                    /* Touch the target address enough times to register in the counter. */
                    (void)touch_reads(items[i].va, touches);

                    (void)ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
                    uint64_t delta = read_counter(fd);
                    close(fd);

                    if (delta > best_delta) {
                        best_delta = delta;
                        best_imc = imc;
                        best_bank = bank;
                        best_bg = bg;
                    }
                }
            }
        }

        items[i].imc = best_imc;
        items[i].bank = best_bank;
        items[i].bg = best_bg;
        items[i].delta = best_delta;

        if ((i % 32) == 0) {
            fprintf(stderr, "progress: %d/%d (latest best imc=%d bank=%d bg=%d delta=%" PRIu64 ")\n",
                    i, n_items, best_imc, best_bank, best_bg, best_delta);
        }
    }

    FILE *fcsv = fopen(csv_path, "w");
    if (!fcsv) die("open csv '%s' failed: %s", csv_path, strerror(errno));
    write_csv(fcsv, items, n_items);
    fclose(fcsv);

    FILE *fjson = fopen(json_path, "w");
    if (!fjson) die("open json '%s' failed: %s", json_path, strerror(errno));
    write_json(fjson, items, n_items, event_name, touches, n_imc, max_bank, max_bg);
    fclose(fjson);

    fprintf(stderr, "done: csv=%s json=%s\n", csv_path, json_path);

    if (g_pagemap_fd >= 0) close(g_pagemap_fd);
    munmap((void*)buf, alloc_bytes);
    free(items);
    free(pmus);
    return 0;
}

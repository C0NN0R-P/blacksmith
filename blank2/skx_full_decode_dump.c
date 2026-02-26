#define _GNU_SOURCE
/*
 * skx_full_decode_dump.c
 *
 * What this DOES (deterministic, userspace-only):
 *   - Allocates memory
 *   - Translates VA->PA via /proc/self/pagemap
 *   - Enumerates SKX IMC-ish PCI functions via /sys/bus/pci/devices
 *   - Reads and prints raw routing/interleave tables (RIR dwords)
 *   - Bins each PA into a *way* within the chosen RIR entry (no timing)
 *   - Exports per-address CSV/JSON plus a big raw register dump so you can
 *     compare against skx_edac and extend into full SAD/TAD decode.
 *
 * What this DOES NOT magically do yet:
 *   - Correct rank/bank/bg/row/col for arbitrary BIOS configs.
 *     That needs SAD/TAD decoding (more regs + more logic) and DIMM geometry.
 *
 * Why I’m giving you this anyway:
 *   - Your current output already shows stable 2-way interleave at 64B stride
 *     (way_sel toggles). This program makes that *explicit* and dumps the raw
 *     config so we can extend it safely.
 *
 * Build:
 *   gcc -O2 -Wall -Wextra -std=c11 skx_full_decode_dump.c -o skx_full_decode_dump
 * Run (root):
 *   sudo ./skx_full_decode_dump --n 256 --alloc-mb 256 --stride 64 --shift 6 \
 *        --csv out.csv --json out.json --dump-pci
 */

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <unistd.h>

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096ULL
#endif

/* ---------------- logging helpers ---------------- */

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
    fprintf(stderr, "warn: ");
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
    if (sched_setaffinity(0, sizeof(set), &set) != 0)
        warnx("sched_setaffinity failed: %s", strerror(errno));
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
        if (g_pagemap_fd < 0) {
            warnx("open(/proc/self/pagemap) failed: %s", strerror(errno));
            return false;
        }
    }

    const uint64_t vpn = va / PAGE_SIZE;
    const off_t off = (off_t)(vpn * 8ULL);

    uint64_t entry = 0;
    ssize_t n = pread(g_pagemap_fd, &entry, sizeof(entry), off);
    if (n != (ssize_t)sizeof(entry)) {
        warnx("pagemap pread failed va=%#" PRIx64 " n=%zd err=%s", va, n, strerror(errno));
        return false;
    }

    const uint64_t present = (entry >> 63) & 1ULL;
    if (!present) return false;

    const uint64_t pfn = entry & ((1ULL << 55) - 1ULL);
    if (pfn == 0) return false;

    *pa_out = (pfn * PAGE_SIZE) | (va & (PAGE_SIZE - 1ULL));
    return true;
}

/* ---------------- PCI config access via sysfs ---------------- */

static bool read_file_u32_hex(const char *path, uint32_t *out)
{
    FILE *f = fopen(path, "r");
    if (!f) return false;
    unsigned v = 0;
    int ok = fscanf(f, "%x", &v);
    fclose(f);
    if (ok != 1) return false;
    *out = (uint32_t)v;
    return true;
}

static bool read_pci_cfg_u32(const char *devdir, uint32_t off, uint32_t *out)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/config", devdir);

    int fd = open(path, O_RDONLY);
    if (fd < 0) return false;

    uint32_t v = 0;
    ssize_t n = pread(fd, &v, sizeof(v), (off_t)off);
    close(fd);

    if (n != (ssize_t)sizeof(v)) return false;
    *out = v;
    return true;
}

/* ---------------- SKX routing tables: RIR ---------------- */

#define SKX_MAX_RIR 4
#define RIR_BASE    0x108

/*
 * Minimal, conservative interpretation:
 *   - [31] valid
 *   - [30:28] ways_code (ways = 1<<ways_code)
 *
 * We do NOT assume we can derive limit/offset/chan_rank from this dword.
 * (Your older kernel-module prints included those fields, but that required
 * additional decode logic/regs; we’ll dump raw PCI to get there safely.)
 */
static inline unsigned rir_valid(uint32_t v) { return (v >> 31) & 1u; }
static inline unsigned rir_ways_code(uint32_t v) { return (v >> 28) & 0x7u; }
static inline unsigned rir_ways(uint32_t v)
{
    unsigned code = rir_ways_code(v);
    if (code >= 6) code = 6;
    return 1u << code;
}

static inline unsigned select_way(uint64_t pa, unsigned ways, unsigned shift)
{
    if (ways <= 1) return 0;
    return (unsigned)((pa >> shift) & (uint64_t)(ways - 1u));
}

typedef struct {
    char devdir[512];
    char bdf[64];
    uint16_t vendor;
    uint16_t device;
    uint32_t class_u32;
    uint32_t rir_raw[SKX_MAX_RIR];
} imc_dev_t;

static bool is_skx_imc_candidate(uint16_t vendor, uint16_t device, uint32_t class_u32)
{
    if (vendor != 0x8086) return false;

    /* class 0x0880 == system peripheral / other (what lspci shows for IMC funcs)
       class file is 0x00bbsspp (we only compare high 2 bytes). */
    const uint32_t class_hi = (class_u32 >> 8) & 0xffffu;
    if (class_hi != 0x0880u && class_hi != 0x0500u) {
        /* 0x0500 (memory controller) sometimes appears (chipset). */
        return false;
    }

    /* IMC-related device IDs you’ve shown: 0x2040..0x2044 and 0x2066.
       Keep filter permissive: accept those, and also accept anything 0x20xx
       so we can see if BIOS exposes more functions. */
    if ((device & 0xff00u) == 0x2000u) return true;
    return false;
}

static size_t enumerate_imc(imc_dev_t **out)
{
    DIR *d = opendir("/sys/bus/pci/devices");
    if (!d) die("opendir /sys/bus/pci/devices failed: %s", strerror(errno));

    imc_dev_t *arr = NULL;
    size_t n = 0, cap = 0;

    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (de->d_name[0] == '.') continue;

        char devdir[512];
        snprintf(devdir, sizeof(devdir), "/sys/bus/pci/devices/%s", de->d_name);

        char vpath[600], dpath[600], cpath[600];
        snprintf(vpath, sizeof(vpath), "%s/vendor", devdir);
        snprintf(dpath, sizeof(dpath), "%s/device", devdir);
        snprintf(cpath, sizeof(cpath), "%s/class", devdir);

        uint32_t vend = 0, devid = 0, class_u32 = 0;
        if (!read_file_u32_hex(vpath, &vend)) continue;
        if (!read_file_u32_hex(dpath, &devid)) continue;
        if (!read_file_u32_hex(cpath, &class_u32)) class_u32 = 0;

        if (!is_skx_imc_candidate((uint16_t)vend, (uint16_t)devid, class_u32)) continue;

        if (n == cap) {
            cap = cap ? cap * 2 : 32;
            arr = realloc(arr, cap * sizeof(*arr));
            if (!arr) die("realloc failed");
        }

        memset(&arr[n], 0, sizeof(arr[n]));
        snprintf(arr[n].devdir, sizeof(arr[n].devdir), "%s", devdir);
        snprintf(arr[n].bdf, sizeof(arr[n].bdf), "%s", de->d_name);
        arr[n].vendor = (uint16_t)vend;
        arr[n].device = (uint16_t)devid;
        arr[n].class_u32 = class_u32;

        for (int i = 0; i < SKX_MAX_RIR; i++) {
            uint32_t v = 0;
            if (!read_pci_cfg_u32(devdir, RIR_BASE + 4u * (uint32_t)i, &v)) v = 0;
            arr[n].rir_raw[i] = v;
        }

        n++;
    }

    closedir(d);
    *out = arr;
    return n;
}

static int choose_imc_device(const imc_dev_t *imcs, size_t n)
{
    /* Heuristic: pick the first device that has at least one VALID RIR and ways>1. */
    for (size_t i = 0; i < n; i++) {
        for (int r = 0; r < SKX_MAX_RIR; r++) {
            uint32_t v = imcs[i].rir_raw[r];
            if (rir_valid(v) && rir_ways(v) > 1) return (int)i;
        }
    }
    /* fallback: first device with any valid entry */
    for (size_t i = 0; i < n; i++) {
        for (int r = 0; r < SKX_MAX_RIR; r++) {
            if (rir_valid(imcs[i].rir_raw[r])) return (int)i;
        }
    }
    return (n > 0) ? 0 : -1;
}

/* Dump a chunk of raw PCI config space as hex dwords. */
static void dump_cfg_range_json(FILE *j, const char *devdir, uint32_t start, uint32_t end)
{
    fprintf(j, "[");
    bool first = true;
    for (uint32_t off = start; off < end; off += 4u) {
        uint32_t v = 0;
        if (!read_pci_cfg_u32(devdir, off, &v)) v = 0;
        if (!first) fprintf(j, ",");
        first = false;
        fprintf(j, "{\"off\":%u,\"val\":%u}", off, v);
    }
    fprintf(j, "]");
}

/* ---------------- main ---------------- */

typedef struct {
    uint64_t n;
    uint64_t alloc_mb;
    uint64_t stride;
    uint64_t shift;
    const char *csv_path;
    const char *json_path;
    bool dump_pci;
} opts_t;

static void usage(const char *argv0)
{
    fprintf(stderr,
        "usage: %s [--n N] [--alloc-mb MB] [--stride BYTES] [--shift BITS] [--csv out.csv] [--json out.json] [--dump-pci]\n"
        "\n"
        "defaults: --n 256 --alloc-mb 256 --stride 4096 --shift 6\n"
        "\n"
        "notes:\n"
        "  - --shift is the interleave shift for way selection (6 => 64B)\n"
        "  - --dump-pci adds big raw PCI config dumps into JSON (helpful for extending decode)\n",
        argv0);
}

static opts_t parse_args(int argc, char **argv)
{
    opts_t o;
    memset(&o, 0, sizeof(o));
    o.n = 256;
    o.alloc_mb = 256;
    o.stride = 4096;
    o.shift = 6;
    o.csv_path = "bins.csv";
    o.json_path = "bins.json";
    o.dump_pci = false;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--n") && i + 1 < argc) o.n = parse_u64(argv[++i]);
        else if (!strcmp(argv[i], "--alloc-mb") && i + 1 < argc) o.alloc_mb = parse_u64(argv[++i]);
        else if (!strcmp(argv[i], "--stride") && i + 1 < argc) o.stride = parse_u64(argv[++i]);
        else if (!strcmp(argv[i], "--shift") && i + 1 < argc) o.shift = parse_u64(argv[++i]);
        else if (!strcmp(argv[i], "--csv") && i + 1 < argc) o.csv_path = argv[++i];
        else if (!strcmp(argv[i], "--json") && i + 1 < argc) o.json_path = argv[++i];
        else if (!strcmp(argv[i], "--dump-pci")) o.dump_pci = true;
        else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            usage(argv[0]);
            exit(0);
        } else {
            die("unknown arg: %s (use --help)", argv[i]);
        }
    }

    if (o.stride == 0) die("--stride must be > 0");
    return o;
}

int main(int argc, char **argv)
{
    opts_t o = parse_args(argc, argv);

    pin_to_cpu0();
    try_raise_priority();

    /* Allocate */
    const uint64_t bytes = o.alloc_mb * 1024ULL * 1024ULL;
    void *buf = mmap(NULL, bytes, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (buf == MAP_FAILED) die("mmap(%" PRIu64 " bytes) failed: %s", bytes, strerror(errno));

    /* Fault pages in */
    volatile uint8_t *p = (volatile uint8_t *)buf;
    for (uint64_t off = 0; off < bytes; off += PAGE_SIZE) p[off] = (uint8_t)off;

    /* Enumerate IMCs */
    imc_dev_t *imcs = NULL;
    size_t n_imc = enumerate_imc(&imcs);
    fprintf(stderr, "info: found %zu candidate IMC-ish PCI devices\n", n_imc);
    if (n_imc == 0) die("no IMC-ish PCI devices found; are you on SKX and running as root?");

    for (size_t i = 0; i < n_imc; i++) {
        fprintf(stderr, "  imc[%zu] bdf=%s vendor=%#x device=%#x class=%#x RIR:",
                i, imcs[i].bdf, imcs[i].vendor, imcs[i].device, imcs[i].class_u32);
        for (int r = 0; r < SKX_MAX_RIR; r++) fprintf(stderr, " %08x", imcs[i].rir_raw[r]);
        fprintf(stderr, "\n");
    }

    const int imc_idx = choose_imc_device(imcs, n_imc);
    if (imc_idx < 0) die("failed to choose IMC device");

    /* Choose an RIR entry within that IMC */
    int rir_entry = -1;
    unsigned ways = 1;
    for (int r = 0; r < SKX_MAX_RIR; r++) {
        uint32_t v = imcs[imc_idx].rir_raw[r];
        if (!rir_valid(v)) continue;
        unsigned w = rir_ways(v);
        if (w > ways) { ways = w; rir_entry = r; }
        if (rir_entry < 0) { ways = w; rir_entry = r; }
    }
    if (rir_entry < 0) die("chosen IMC has no valid RIR entries");

    fprintf(stderr, "info: using imc[%d]=%s rir_entry=%d raw=%08x ways=%u shift=%" PRIu64 "\n",
            imc_idx, imcs[imc_idx].bdf, rir_entry, imcs[imc_idx].rir_raw[rir_entry], ways, o.shift);

    /* Open outputs */
    FILE *csv = fopen(o.csv_path, "w");
    if (!csv) die("open csv '%s' failed: %s", o.csv_path, strerror(errno));

    FILE *json = fopen(o.json_path, "w");
    if (!json) die("open json '%s' failed: %s", o.json_path, strerror(errno));

    /* Headers */
    fprintf(csv, "va,pa,imc_bdf,imc_vendor,imc_device,rir_entry,rir_raw,ways,way_sel,channel_guess,notes\n");

    fprintf(json, "{\n");
    fprintf(json, "  \"meta\":{\"n\":%" PRIu64 ",\"alloc_mb\":%" PRIu64 ",\"stride\":%" PRIu64 ",\"shift\":%" PRIu64 ",\"imc_idx\":%d,\"rir_entry\":%d},\n",
            o.n, o.alloc_mb, o.stride, o.shift, imc_idx, rir_entry);

    fprintf(json, "  \"imc_devs\":[\n");
    for (size_t i = 0; i < n_imc; i++) {
        fprintf(json, "    {\"bdf\":\"%s\",\"vendor\":%u,\"device\":%u,\"class\":%u,\"rir\":[%u,%u,%u,%u]",
                imcs[i].bdf,
                (unsigned)imcs[i].vendor,
                (unsigned)imcs[i].device,
                (unsigned)imcs[i].class_u32,
                imcs[i].rir_raw[0], imcs[i].rir_raw[1], imcs[i].rir_raw[2], imcs[i].rir_raw[3]);

        if (o.dump_pci) {
            /* Dump a fairly wide range; you can trim later.
               This is intentionally brute-force and read-only. */
            fprintf(json, ",\"cfg_0x000_0x200\":");
            dump_cfg_range_json(json, imcs[i].devdir, 0x000, 0x200);
        }

        fprintf(json, "}%s\n", (i + 1 < n_imc) ? "," : "");
    }
    fprintf(json, "  ],\n");

    fprintf(json, "  \"rows\":[\n");

    /* Main scan */
    uint64_t produced = 0;
    bool first_row = true;

    for (uint64_t idx = 0; idx < o.n; idx++) {
        uint64_t va = (uint64_t)(uintptr_t)p + idx * o.stride;
        uint64_t pa = 0;
        const char *note = "";
        if (!va_to_pa(va, &pa)) {
            note = "va_to_pa_failed";
            fprintf(stderr, "warn: va_to_pa failed for va=%#" PRIx64 " (idx=%" PRIu64 ")\n", va, idx);
        }

        unsigned way_sel = select_way(pa, ways, (unsigned)o.shift);
        unsigned channel_guess = way_sel; /* only a guess without SAD/TAD; still useful for interleave */

        fprintf(csv,
                "%#016" PRIx64 ",%#016" PRIx64 ",%s,%#x,%#x,%d,%#x,%u,%u,%u,%s\n",
                va, pa,
                imcs[imc_idx].bdf,
                imcs[imc_idx].vendor,
                imcs[imc_idx].device,
                rir_entry,
                imcs[imc_idx].rir_raw[rir_entry],
                ways,
                way_sel,
                channel_guess,
                note);

        if (!first_row) fprintf(json, ",\n");
        first_row = false;
        fprintf(json,
                "    {\"va\":%" PRIu64 ",\"pa\":%" PRIu64 ",\"way_sel\":%u,\"channel_guess\":%u,\"note\":\"%s\"}",
                va, pa, way_sel, channel_guess, note);

        produced++;
    }

    fprintf(json, "\n  ]\n");
    fprintf(json, "}\n");

    fclose(csv);
    fclose(json);

    fprintf(stderr, "done: wrote %s and %s (%" PRIu64 " rows)\n", o.csv_path, o.json_path, produced);

    munmap((void *)buf, bytes);
    free(imcs);
    return 0;
}

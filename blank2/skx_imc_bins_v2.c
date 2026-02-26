#define _GNU_SOURCE
/*
 * skx_userspace_imc_decode.c
 *
 * Goal:
 *   Deterministically bin *physical* addresses by iMC/channel (and optionally rank)
 *   on Intel Skylake-SP / Skylake-E ("SKX") by reading the same PCI config
 *   registers the in-kernel EDAC driver reads.
 *
 * Reality check (so you’re not chasing ghosts):
 *   - Channel / route / interleave is the bit that’s reliable from the IMC routing tables.
 *   - Bank/bg/row/col needs DIMM geometry + the exact address swizzle rules. That’s
 *     doable, but it’s a second phase.
 *
 * This program is deliberately noisy: it dumps what it reads and prints every decision
 * it makes, so if something is off you can see *where* it went off.
 *
 * Requirements:
 *   - Run as root (needs to read /sys/bus/pci/devices/…/config)
 *   - x86_64 Linux
 *
 * Output:
 *   - CSV with VA/PA and decoded (socket, imc, channel, rir_entry, ways, way_sel)
 *   - JSON with the same plus a full register dump in "imc_devs".
 *
 * Notes:
 *   - I’m not using your kernel module. This is userspace-only.
 *   - The exact RIR bitfield layout varies slightly across generations/steppings.
 *     I’ve implemented one plausible layout, but I also dump raw dwords so you can
 *     tweak masks in one place if needed.
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

/* ----------------- small helpers ----------------- */

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

/* ----------------- VA -> PA via pagemap ----------------- */

static int g_pagemap_fd = -1;

/*
 * Translate a userspace virtual address to a physical address.
 * Returns true on success; false if pagemap is blocked or the page isn't present.
 */
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

    /* Bit 63: present, bits 0-54 PFN (when present) on x86_64 */
    const uint64_t present = (entry >> 63) & 1ULL;
    if (!present) return false;

    const uint64_t pfn = entry & ((1ULL << 55) - 1ULL);
    if (pfn == 0) return false;

    *pa_out = (pfn * PAGE_SIZE) | (va & (PAGE_SIZE - 1ULL));
    return true;
}

/* ----------------- PCI config access (sysfs) ----------------- */

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

/* ----------------- SKX IMC routing (RIR) -----------------

   We start with the RIR tables because they’re the most “directly useful”
   thing you can read from PCI config without doing full SAD/TAD.

   Big caveat:
     The exact bit layout varies. So this program:
       - reads and prints raw dwords unconditionally
       - keeps the masks in ONE place

   If the decode is wrong, your first move should be:
     ./skx_imc_bins --dump-imc
   and compare the raw dwords against what skx_edac prints/dumps.
*/

#define SKX_MAX_RIR 4
#define RIR_BASE    0x108

/* Plausible layout (seen on many SKX systems):
 *   [31]     VALID
 *   [30:28]  WAYS code (0->1 way, 1->2 ways, 2->4 ways, ...)
 *
 * If your raw dwords don't match this, tweak here (and only here).
 */
static inline unsigned rir_valid(uint32_t v) { return (v >> 31) & 1u; }
static inline unsigned rir_ways_code(uint32_t v) { return (v >> 28) & 0x7u; }
static inline unsigned rir_ways(uint32_t v)
{
    unsigned code = rir_ways_code(v);
    if (code >= 6) code = 6;
    return 1u << code;
}

/* Select which “way” a PA hits under a simple stripe. */
static inline unsigned select_way(uint64_t pa, unsigned ways, unsigned interleave_shift)
{
    if (ways <= 1) return 0;
    return (unsigned)((pa >> interleave_shift) & (uint64_t)(ways - 1u));
}

typedef struct {
    char devdir[512];
    char bdf[64];
    uint16_t vendor;
    uint16_t device;
    uint8_t bus, dev, fn;

    uint32_t rir_raw[SKX_MAX_RIR];
} imc_dev_t;

static bool parse_bdf(const char *name, uint8_t *bus, uint8_t *dev, uint8_t *fn)
{
    unsigned dom = 0, b = 0, d = 0, f = 0;
    if (sscanf(name, "%x:%x:%x.%x", &dom, &b, &d, &f) != 4) return false;
    *bus = (uint8_t)b;
    *dev = (uint8_t)d;
    *fn  = (uint8_t)f;
    return true;
}

static bool is_skx_imc_device(uint16_t vendor, uint16_t device)
{
    if (vendor != 0x8086) return false;

    /* Based on your lspci dump: */
    if (device >= 0x2040 && device <= 0x2044) return true;
    if (device == 0x2066) return true;
    return false;
}

static int enumerate_imc(imc_dev_t *out, int max_out)
{
    const char *root = "/sys/bus/pci/devices";
    DIR *d = opendir(root);
    if (!d) die("opendir %s failed: %s", root, strerror(errno));

    int n = 0;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (de->d_name[0] == '.') continue;

        char devdir[512];
        snprintf(devdir, sizeof(devdir), "%s/%s", root, de->d_name);

        char p_vendor[512], p_device[512];
        snprintf(p_vendor, sizeof(p_vendor), "%s/vendor", devdir);
        snprintf(p_device, sizeof(p_device), "%s/device", devdir);

        uint32_t v = 0, dev = 0;
        if (!read_file_u32_hex(p_vendor, &v)) continue;
        if (!read_file_u32_hex(p_device, &dev)) continue;

        uint16_t vendor = (uint16_t)v;
        uint16_t device = (uint16_t)dev;

        if (!is_skx_imc_device(vendor, device)) continue;
        if (n >= max_out) break;

        memset(&out[n], 0, sizeof(out[n]));
        snprintf(out[n].devdir, sizeof(out[n].devdir), "%s", devdir);
        snprintf(out[n].bdf, sizeof(out[n].bdf), "%s", de->d_name);
        out[n].vendor = vendor;
        out[n].device = device;
        parse_bdf(de->d_name, &out[n].bus, &out[n].dev, &out[n].fn);

        for (int i = 0; i < SKX_MAX_RIR; i++) {
            uint32_t val = 0;
            if (!read_pci_cfg_u32(out[n].devdir, RIR_BASE + 4u * (uint32_t)i, &val))
                val = 0;
            out[n].rir_raw[i] = val;
        }

        n++;
    }

    closedir(d);
    return n;
}

/* ----------------- decode + binning ----------------- */

typedef struct {
    volatile uint8_t *va;
    uint64_t pa;

    int imc_idx;
    int rir_entry;
    int ways;
    int way_sel;

    int channel_bin;   /* deterministic bin id (not yet “true channel”) */

    uint32_t rir_raw;
} item_t;

/*
 * decode_one():
 *   This is intentionally conservative: we only use “has a valid entry”
 *   + “ways” + a simple striping selector. It gives you stable bins
 *   immediately, and the JSON contains the raw regs to tighten it.
 *
 * When you’re ready:
 *   This is the exact spot you replace with full SAD/TAD/RIR reconstruction.
 */
static void decode_one(const imc_dev_t *imcs, int n_imc,
                       uint64_t pa,
                       unsigned interleave_shift,
                       int *out_imc_idx,
                       int *out_rir_entry,
                       int *out_ways,
                       int *out_way_sel,
                       int *out_channel_bin,
                       uint32_t *out_rir_raw)
{
    *out_imc_idx = -1;
    *out_rir_entry = -1;
    *out_ways = 0;
    *out_way_sel = 0;
    *out_channel_bin = -1;
    *out_rir_raw = 0;

    for (int m = 0; m < n_imc; m++) {
        for (int i = 0; i < SKX_MAX_RIR; i++) {
            uint32_t r = imcs[m].rir_raw[i];
            if (!rir_valid(r)) continue;

            unsigned ways = rir_ways(r);
            unsigned way = select_way(pa, ways, interleave_shift);

            *out_imc_idx = m;
            *out_rir_entry = i;
            *out_ways = (int)ways;
            *out_way_sel = (int)way;
            *out_rir_raw = r;

            /* Debug-friendly “bin id” */
            *out_channel_bin = (m * 256) + (i * 32) + (int)way;
            return;
        }
    }
}

/* ----------------- output ----------------- */

static void write_csv(FILE *f, const item_t *items, int n_items, const imc_dev_t *imcs)
{
    fprintf(f, "va,pa,imc_bdf,imc_vendor,imc_device,rir_entry,rir_raw,ways,way_sel,channel_bin\n");
    for (int i = 0; i < n_items; i++) {
        const char *bdf = (items[i].imc_idx >= 0) ? imcs[items[i].imc_idx].bdf : "NA";
        uint16_t ven = (items[i].imc_idx >= 0) ? imcs[items[i].imc_idx].vendor : 0;
        uint16_t dev = (items[i].imc_idx >= 0) ? imcs[items[i].imc_idx].device : 0;

        fprintf(f,
            "0x%016" PRIx64 ",0x%016" PRIx64 ",%s,0x%04x,0x%04x,%d,0x%08x,%d,%d,%d\n",
            (uint64_t)(uintptr_t)items[i].va,
            items[i].pa,
            bdf,
            ven,
            dev,
            items[i].rir_entry,
            items[i].rir_raw,
            items[i].ways,
            items[i].way_sel,
            items[i].channel_bin);
    }
}

static void write_json(FILE *f,
                       const item_t *items,
                       int n_items,
                       const imc_dev_t *imcs,
                       int n_imc,
                       unsigned interleave_shift,
                       uint64_t alloc_bytes,
                       uint64_t stride_bytes)
{
    fprintf(f, "{\n");
    fprintf(f, "  \"meta\": {\n");
    fprintf(f, "    \"n_items\": %d,\n", n_items);
    fprintf(f, "    \"n_imc_devs\": %d,\n", n_imc);
    fprintf(f, "    \"interleave_shift\": %u,\n", interleave_shift);
    fprintf(f, "    \"alloc_bytes\": %" PRIu64 ",\n", alloc_bytes);
    fprintf(f, "    \"stride_bytes\": %" PRIu64 "\n", stride_bytes);
    fprintf(f, "  },\n");

    fprintf(f, "  \"imc_devs\": [\n");
    for (int i = 0; i < n_imc; i++) {
        fprintf(f, "    {\"idx\":%d,\"bdf\":\"%s\",\"vendor\":\"0x%04x\",\"device\":\"0x%04x\",\"rir_raw\":[",
                i, imcs[i].bdf, imcs[i].vendor, imcs[i].device);
        for (int j = 0; j < SKX_MAX_RIR; j++) {
            fprintf(f, "\"0x%08x\"%s", imcs[i].rir_raw[j], (j == SKX_MAX_RIR - 1) ? "" : ",");
        }
        fprintf(f, "]}%s\n", (i == n_imc - 1) ? "" : ",");
    }
    fprintf(f, "  ],\n");

    fprintf(f, "  \"items\": [\n");
    for (int i = 0; i < n_items; i++) {
        fprintf(f,
                "    {\"va\":\"0x%016" PRIx64 "\",\"pa\":\"0x%016" PRIx64 "\",\"imc_idx\":%d,\"rir_entry\":%d,\"rir_raw\":\"0x%08x\",\"ways\":%d,\"way_sel\":%d,\"channel_bin\":%d}%s\n",
                (uint64_t)(uintptr_t)items[i].va,
                items[i].pa,
                items[i].imc_idx,
                items[i].rir_entry,
                items[i].rir_raw,
                items[i].ways,
                items[i].way_sel,
                items[i].channel_bin,
                (i == n_items - 1) ? "" : ",");
    }
    fprintf(f, "  ]\n");
    fprintf(f, "}\n");
}

/* ----------------- main ----------------- */

static void usage(const char *argv0)
{
    fprintf(stderr,
        "usage: %s [options]\n\n"
        "options:\n"
        "  --n N              number of candidate addresses (default 256)\n"
        "  --alloc-mb MB      allocation size in MB (default 256)\n"
        "  --stride BYTES     stride between candidates (default 4096)\n"
        "  --shift S          interleave shift (default 6 -> 64B)\n"
        "  --line-step BYTES  step within each page (default 64)\n"
        "  --csv PATH         write CSV to PATH (default bins.csv)\n"
        "  --json PATH        write JSON to PATH (default bins.json)\n"
        "  --no-pin           don't pin to CPU0\n"
        "  --dump-imc         dump IMC devices + raw RIR and exit\n",
        argv0);
}

int main(int argc, char **argv)
{
    int n = 256;
    uint64_t alloc_mb = 256;
    uint64_t stride = PAGE_SIZE;
    unsigned shift = 6;
    uint64_t line_step = 64;
    const char *csv_path = "bins.csv";
    const char *json_path = "bins.json";
    bool do_pin = true;
    bool dump_imc = false;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--n") && i + 1 < argc) {
            n = (int)parse_u64(argv[++i]);
        } else if (!strcmp(argv[i], "--alloc-mb") && i + 1 < argc) {
            alloc_mb = parse_u64(argv[++i]);
        } else if (!strcmp(argv[i], "--stride") && i + 1 < argc) {
            stride = parse_u64(argv[++i]);
        } else if (!strcmp(argv[i], "--shift") && i + 1 < argc) {
            shift = (unsigned)parse_u64(argv[++i]);
        } else if (!strcmp(argv[i], "--line-step") && i + 1 < argc) {
            line_step = parse_u64(argv[++i]);
        } else if (!strcmp(argv[i], "--csv") && i + 1 < argc) {
            csv_path = argv[++i];
        } else if (!strcmp(argv[i], "--json") && i + 1 < argc) {
            json_path = argv[++i];
        } else if (!strcmp(argv[i], "--no-pin")) {
            do_pin = false;
        } else if (!strcmp(argv[i], "--dump-imc")) {
            dump_imc = true;
        } else if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) {
            usage(argv[0]);
            return 0;
        } else {
            usage(argv[0]);
            die("unknown/invalid option: %s", argv[i]);
        }
    }

    if (do_pin) pin_to_cpu0();
    try_raise_priority();

    if (geteuid() != 0)
        warnx("not running as root; reading /sys/bus/pci/devices/*/config may fail");

    imc_dev_t imcs[128];
    int n_imc = enumerate_imc(imcs, (int)(sizeof(imcs) / sizeof(imcs[0])));
    fprintf(stderr, "info: found %d candidate IMC-ish PCI devices\n", n_imc);

    for (int i = 0; i < n_imc; i++) {
        fprintf(stderr, "  imc[%d] bdf=%s vendor=0x%04x device=0x%04x RIR:",
                i, imcs[i].bdf, imcs[i].vendor, imcs[i].device);
        for (int j = 0; j < SKX_MAX_RIR; j++)
            fprintf(stderr, " %08x", imcs[i].rir_raw[j]);
        fprintf(stderr, "\n");
    }

    if (dump_imc) {
        fprintf(stderr, "--dump-imc set, stopping here.\n");
        return 0;
    }

    if (shift > 63) die("--shift out of range");
    if (line_step == 0) die("--line-step must be >0");
    if (line_step % 64 != 0) {
        fprintf(stderr, "warn: --line-step=%" PRIu64 " isn't a multiple of 64; you probably want cacheline steps\n", line_step);
    }

    if (n_imc == 0)
        die("no IMC devices found; are you really on SKX?");

    uint64_t alloc_bytes = alloc_mb * 1024ULL * 1024ULL;

    uint8_t *buf = mmap(NULL, alloc_bytes, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (buf == MAP_FAILED) die("mmap failed: %s", strerror(errno));

    for (uint64_t off = 0; off < alloc_bytes; off += PAGE_SIZE)
        buf[off] = (uint8_t)(off ^ 0xA5);

    item_t *items = calloc((size_t)n, sizeof(*items));
    if (!items) die("calloc items failed");

    /*
     * Candidate selection:
     *   - gate pages by --stride (default 4K, so we consider every page)
     *   - but *within* each page, walk by --line-step (default 64B)
     *
     * This avoids the "page-aligned => way_sel always 0" trap when shift=6.
     */
    int n_items = 0;
    for (uint64_t page = 0; page < alloc_bytes && n_items < n; page += PAGE_SIZE) {
        if ((page % stride) != 0) continue;

        for (uint64_t in = 0; in + 64 <= PAGE_SIZE && n_items < n; in += line_step) {
            uint64_t off = page + in;
            if (off >= alloc_bytes) break;

            volatile uint8_t *p = (volatile uint8_t *)(buf + off);
            uint64_t pa = 0;
            (void)va_to_pa((uint64_t)(uintptr_t)p, &pa);

            items[n_items].va = p;
            items[n_items].pa = pa;

            int imc_idx, rir_e, ways, way_sel, chbin;
            uint32_t rir_raw;
            decode_one(imcs, n_imc, pa, shift, &imc_idx, &rir_e, &ways, &way_sel, &chbin, &rir_raw);

            items[n_items].imc_idx = imc_idx;
            items[n_items].rir_entry = rir_e;
            items[n_items].ways = ways;
            items[n_items].way_sel = way_sel;
            items[n_items].channel_bin = chbin;
            items[n_items].rir_raw = rir_raw;

            n_items++;
        }
    }

    FILE *fcsv = fopen(csv_path, "w");
    if (!fcsv) die("open csv '%s' failed: %s", csv_path, strerror(errno));
    write_csv(fcsv, items, n_items, imcs);
    fclose(fcsv);

    FILE *fjson = fopen(json_path, "w");
    if (!fjson) die("open json '%s' failed: %s", json_path, strerror(errno));
    write_json(fjson, items, n_items, imcs, n_imc, shift, alloc_bytes, stride);
    fclose(fjson);

    fprintf(stderr, "done: wrote %s and %s\n", csv_path, json_path);

    if (g_pagemap_fd >= 0) close(g_pagemap_fd);
    munmap((void*)buf, alloc_bytes);
    free(items);
    return 0;
}

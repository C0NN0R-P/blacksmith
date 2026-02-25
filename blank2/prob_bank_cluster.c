#define _GNU_SOURCE
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
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <x86intrin.h>

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096ULL
#endif

/* ----------- small helpers (log/parse/pin) ----------- */

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
        /* Not fatal, but it helps a lot if it works. */
        fprintf(stderr, "warn: sched_setaffinity failed: %s\n", strerror(errno));
    }
}

static void try_raise_priority(void)
{
    /* This is best-effort. */
    if (setpriority(PRIO_PROCESS, 0, -10) != 0) {
        /* Fine; many systems restrict negative nice without extra caps. */
    }
}

/* ----------- VA -> PA using /proc/self/pagemap ----------- */

static int g_pagemap_fd = -1;

/*
 * Translate a userspace virtual address to a physical address.
 * Returns true on success, false if the page isn't present or pagemap is blocked.
 *
 * Safety: this is read-only. It should not crash the machine.
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

/* ----------- timing core ----------- */

/*
 * Serialised timestamp. RDTSCP is partially serialising; we also use fences.
 * (In practice: good enough for this kind of relative comparison.)
 */
static inline uint64_t rdtscp_serial(void)
{
    unsigned aux;
    uint64_t t = __rdtscp(&aux);
    _mm_lfence();
    return t;
}

/* Force a line out of caches. */
static inline void flush_line(void *p)
{
    _mm_clflush(p);
}

/* Timed load from a volatile pointer so it can't be optimised away. */
static inline uint64_t timed_load_cycles(volatile uint8_t *p)
{
    _mm_lfence();
    uint64_t t0 = rdtscp_serial();
    (void)*p;
    uint64_t t1 = rdtscp_serial();
    return t1 - t0;
}

/*
 * Measure baseline: A only. Each iteration flushes A then times a load of A.
 * Returns average cycles per access (double).
 */
static double measure_baseline(volatile uint8_t *a, int iters)
{
    uint64_t sum = 0;
    for (int i = 0; i < iters; i++) {
        flush_line((void*)a);
        _mm_mfence();
        sum += timed_load_cycles(a);
    }
    return (double)sum / (double)iters;
}

/*
 * Measure alternate: ABAB... We time only the A loads, but in the presence of B.
 * Each step flushes the line it is about to touch so both are DRAM-ish.
 */
static double measure_alternate(volatile uint8_t *a, volatile uint8_t *b, int iters)
{
    uint64_t sum_a = 0;
    for (int i = 0; i < iters; i++) {
        flush_line((void*)a);
        flush_line((void*)b);
        _mm_mfence();

        /* Touch B first to disturb row-buffer state, then time A. */
        (void)*b;
        sum_a += timed_load_cycles(a);
    }
    return (double)sum_a / (double)iters;
}

/*
 * Conflict score:
 *   score = avg_A_cycles_with_B / avg_A_cycles_alone
 *
 * Typical interpretation:
 *   - ~1.0  : no measurable interference
 *   - 1.2+  : often "same bank / row-buffer conflict" (very platform/noise dependent)
 *
 * We average across 'repeats' independent measurements.
 */
static double conflict_score(volatile uint8_t *a,
                             volatile uint8_t *b,
                             int iters,
                             int repeats)
{
    double base_sum = 0.0;
    double alt_sum  = 0.0;

    for (int r = 0; r < repeats; r++) {
        base_sum += measure_baseline(a, iters);
        alt_sum  += measure_alternate(a, b, iters);
    }

    double base = base_sum / (double)repeats;
    double alt  = alt_sum  / (double)repeats;

    if (base < 1.0) base = 1.0; /* ultra-defensive; avoid divide-by-zero */
    return alt / base;
}

/* ----------- clustering ----------- */

typedef struct {
    volatile uint8_t *va;
    uint64_t pa;
    int bank_class;
    double score_vs_rep;
} item_t;

typedef struct {
    int rep_index;     /* index into items[] */
    int count;
} class_t;

/*
 * Greedy clustering:
 *  - Start with class 0 using item 0 as rep
 *  - For each new item i:
 *      compute score vs each class rep
 *      if max score >= threshold -> assign to that class
 *      else -> start new class with i as rep
 *
 * This is cheap and "works soon" for demo/progress, but it's not perfect.
 */
static int cluster_items(item_t *items,
                         int n_items,
                         class_t *classes,
                         int max_classes,
                         int iters,
                         int repeats,
                         double threshold)
{
    int n_classes = 0;

    if (n_items <= 0) return 0;

    classes[0].rep_index = 0;
    classes[0].count = 1;
    items[0].bank_class = 0;
    items[0].score_vs_rep = 1.0;
    n_classes = 1;

    for (int i = 1; i < n_items; i++) {
        double best_score = 0.0;
        int best_class = -1;

        for (int c = 0; c < n_classes; c++) {
            int rep = classes[c].rep_index;
            double s = conflict_score(items[rep].va, items[i].va, iters, repeats);
            if (s > best_score) {
                best_score = s;
                best_class = c;
            }
        }

        if (best_class >= 0 && best_score >= threshold) {
            items[i].bank_class = best_class;
            items[i].score_vs_rep = best_score;
            classes[best_class].count++;
        } else {
            if (n_classes >= max_classes) {
                /* If we hit the cap, dump into the "last" class to keep running. */
                items[i].bank_class = n_classes - 1;
                items[i].score_vs_rep = best_score;
                classes[n_classes - 1].count++;
            } else {
                items[i].bank_class = n_classes;
                items[i].score_vs_rep = 1.0;
                classes[n_classes].rep_index = i;
                classes[n_classes].count = 1;
                n_classes++;
            }
        }
    }

    return n_classes;
}

/* ----------- output (CSV/JSON) ----------- */

static void write_csv(FILE *f, const item_t *items, int n_items)
{
    fprintf(f, "va,pa,bank_class,score_vs_rep\n");
    for (int i = 0; i < n_items; i++) {
        fprintf(f, "0x%016" PRIx64 ",0x%016" PRIx64 ",%d,%.3f\n",
                (uint64_t)(uintptr_t)items[i].va,
                items[i].pa,
                items[i].bank_class,
                items[i].score_vs_rep);
    }
}

/* Minimal JSON string escaping for our limited needs. */
static void json_put_escaped(FILE *f, const char *s)
{
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        if (c == '\\' || c == '"') {
            fputc('\\', f);
            fputc(c, f);
        } else if (c >= 0x20) {
            fputc(c, f);
        } else {
            /* Control chars -> \u00XX */
            fprintf(f, "\\u%04x", (unsigned)c);
        }
    }
}

static void write_json(FILE *f,
                       const item_t *items,
                       int n_items,
                       int n_classes,
                       double threshold,
                       int iters,
                       int repeats,
                       uint64_t alloc_bytes,
                       uint64_t stride_bytes)
{
    fprintf(f, "{\n");
    fprintf(f, "  \"meta\": {\n");
    fprintf(f, "    \"n_items\": %d,\n", n_items);
    fprintf(f, "    \"n_classes\": %d,\n", n_classes);
    fprintf(f, "    \"threshold\": %.6f,\n", threshold);
    fprintf(f, "    \"iters\": %d,\n", iters);
    fprintf(f, "    \"repeats\": %d,\n", repeats);
    fprintf(f, "    \"alloc_bytes\": %" PRIu64 ",\n", alloc_bytes);
    fprintf(f, "    \"stride_bytes\": %" PRIu64 "\n", stride_bytes);
    fprintf(f, "  },\n");
    fprintf(f, "  \"items\": [\n");
    for (int i = 0; i < n_items; i++) {
        fprintf(f, "    {\"va\":\"0x%016" PRIx64 "\",\"pa\":\"0x%016" PRIx64 "\",\"bank_class\":%d,\"score_vs_rep\":%.6f}%s\n",
                (uint64_t)(uintptr_t)items[i].va,
                items[i].pa,
                items[i].bank_class,
                items[i].score_vs_rep,
                (i == n_items - 1) ? "" : ",");
    }
    fprintf(f, "  ]\n");
    fprintf(f, "}\n");
}

/* ----------- main ----------- */

static void usage(const char *argv0)
{
    fprintf(stderr,
        "usage: %s [options]\n"
        "\n"
        "options:\n"
        "  --n N              number of candidate addresses (default 1024)\n"
        "  --alloc-mb MB      allocation size in MB (default 256)\n"
        "  --stride BYTES     stride between candidates (default 4096)\n"
        "  --iters I          timing iterations per measurement (default 4000)\n"
        "  --repeats R        measurement repeats (default 5)\n"
        "  --thresh T         conflict threshold (default 1.25)\n"
        "  --max-classes K    cap number of classes (default 64)\n"
        "  --csv PATH         write CSV to PATH\n"
        "  --json PATH        write JSON to PATH\n"
        "  --no-pin           don't pin to CPU0\n"
        "\n"
        "notes:\n"
        "  - VA->PA uses /proc/self/pagemap, which is typically restricted.\n"
        "    If VA->PA fails, we still output VA but PA will be 0.\n"
        , argv0);
}

int main(int argc, char **argv)
{
    int n = 1024;
    uint64_t alloc_mb = 256;
    uint64_t stride = PAGE_SIZE;
    int iters = 4000;
    int repeats = 5;
    double thresh = 1.25;
    int max_classes = 64;
    const char *csv_path = NULL;
    const char *json_path = NULL;
    bool do_pin = true;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--n") && i + 1 < argc) {
            n = (int)parse_u64(argv[++i]);
        } else if (!strcmp(argv[i], "--alloc-mb") && i + 1 < argc) {
            alloc_mb = parse_u64(argv[++i]);
        } else if (!strcmp(argv[i], "--stride") && i + 1 < argc) {
            stride = parse_u64(argv[++i]);
        } else if (!strcmp(argv[i], "--iters") && i + 1 < argc) {
            iters = (int)parse_u64(argv[++i]);
        } else if (!strcmp(argv[i], "--repeats") && i + 1 < argc) {
            repeats = (int)parse_u64(argv[++i]);
        } else if (!strcmp(argv[i], "--thresh") && i + 1 < argc) {
            thresh = strtod(argv[++i], NULL);
        } else if (!strcmp(argv[i], "--max-classes") && i + 1 < argc) {
            max_classes = (int)parse_u64(argv[++i]);
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

    if (do_pin) pin_to_cpu0();
    try_raise_priority();

    uint64_t alloc_bytes = alloc_mb * 1024ULL * 1024ULL;

    /* mmap anonymous memory; page-aligned by definition */
    uint8_t *buf = mmap(NULL, alloc_bytes, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (buf == MAP_FAILED) die("mmap failed: %s", strerror(errno));

    /* Touch each page so it's faulted in before we start translating/timing. */
    for (uint64_t off = 0; off < alloc_bytes; off += PAGE_SIZE) {
        buf[off] = (uint8_t)(off ^ 0xA5);
    }

    item_t *items = calloc((size_t)n, sizeof(*items));
    if (!items) die("calloc items failed");

    /* Enumerate candidates. We keep them within the allocated region. */
    uint64_t max_off = alloc_bytes - 64; /* keep some slack */
    uint64_t off = 0;

    for (int i = 0; i < n; i++) {
        uint64_t this_off = off;
        if (this_off > max_off) {
            /* Wrap if user asked for more items than fit in alloc/stride. */
            this_off = (uint64_t)(i % (int)(max_off / stride + 1)) * stride;
        }

        volatile uint8_t *va = (volatile uint8_t *)(buf + this_off);
        items[i].va = va;

        uint64_t pa = 0;
        if (!va_to_pa((uint64_t)(uintptr_t)va, &pa)) {
            /* Not fatal; we just mark PA unknown. */
            pa = 0;
        }
        items[i].pa = pa;

        items[i].bank_class = -1;
        items[i].score_vs_rep = 0.0;

        off += stride;
    }

    class_t *classes = calloc((size_t)max_classes, sizeof(*classes));
    if (!classes) die("calloc classes failed");

    int n_classes = cluster_items(items, n, classes, max_classes, iters, repeats, thresh);

    /* Default: CSV to stdout if the user didn't ask for files. */
    bool wrote_any = false;

    if (csv_path) {
        FILE *f = fopen(csv_path, "w");
        if (!f) die("failed to open csv: %s", strerror(errno));
        write_csv(f, items, n);
        fclose(f);
        wrote_any = true;
    }

    if (json_path) {
        FILE *f = fopen(json_path, "w");
        if (!f) die("failed to open json: %s", strerror(errno));
        write_json(f, items, n, n_classes, thresh, iters, repeats, alloc_bytes, stride);
        fclose(f);
        wrote_any = true;
    }

    if (!wrote_any) {
        write_csv(stdout, items, n);
    }

    fprintf(stderr, "classes=%d (thresh=%.2f iters=%d repeats=%d)\n",
            n_classes, thresh, iters, repeats);

    /* cleanup */
    if (g_pagemap_fd >= 0) close(g_pagemap_fd);
    munmap((void*)buf, alloc_bytes);
    free(items);
    free(classes);
    return 0;
}

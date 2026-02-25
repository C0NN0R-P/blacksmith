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
        fprintf(stderr, "warn: sched_setaffinity failed: %s\n", strerror(errno));
    }
}

static void try_raise_priority(void)
{
    /* Best-effort: reduces scheduler noise but isn't required. */
    (void)setpriority(PRIO_PROCESS, 0, -10);
}

/* ----------- VA -> PA using /proc/self/pagemap ----------- */

static int g_pagemap_fd = -1;

/*
 * Translate a userspace virtual address to a physical address.
 * Returns true on success, false if the page isn't present or pagemap is blocked.
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

/* Serialised timestamp. */
static inline uint64_t rdtscp_serial(void)
{
    unsigned aux;
    uint64_t t = __rdtscp(&aux);
    _mm_lfence();
    return t;
}

/* Force a cache line out of the caches (so next access tends towards DRAM). */
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
 * Measure alternate: touch B then time A (both flushed first).
 * The intent is to perturb the row-buffer/bank state before the A measurement.
 */
static double measure_alternate(volatile uint8_t *a, volatile uint8_t *b, int iters)
{
    uint64_t sum_a = 0;
    for (int i = 0; i < iters; i++) {
        flush_line((void*)a);
        flush_line((void*)b);
        _mm_mfence();

        (void)*b;
        sum_a += timed_load_cycles(a);
    }
    return (double)sum_a / (double)iters;
}

/*
 * Directional conflict score:
 *   score = avg_A_cycles_with_B / avg_A_cycles_alone
 */
static double conflict_score_dir(volatile uint8_t *a,
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

    if (base < 1.0) base = 1.0;
    return alt / base;
}

/*
 * Symmetric score.
 *
 * Why this matters (this is the bug behind the "everything became bank 63" symptom):
 *   The earlier greedy clustering used a directional score A<-B.
 *   If noise makes many directional scores sit below your threshold, you keep
 *   creating new classes until you hit max_classes; after that, the old code
 *   dumped everything into the *last* class (e.g. 63).
 *
 * Here we:
 *   - compute both directions and average them
 *   - never dump into the last class when we hit the cap; we assign to the
 *     best existing class instead.
 */
static double conflict_score_sym(volatile uint8_t *a,
                                volatile uint8_t *b,
                                int iters,
                                int repeats)
{
    double s1 = conflict_score_dir(a, b, iters, repeats);
    double s2 = conflict_score_dir(b, a, iters, repeats);
    return 0.5 * (s1 + s2);
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
 * Greedy clustering (cheap):
 *  - Start with class 0 using item 0 as rep
 *  - For each new item i:
 *      compute score vs each class rep
 *      if max score >= threshold -> assign to that class
 *      else -> start new class with i as rep (until cap)
 *      if cap reached -> assign to best existing class (do NOT dump into last)
 *
 * Practical defaults:
 *   - if you want something close to "banks", set --max-classes 16
 *   - tune --thresh until you get a sensible number of classes
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
        double best_score = -1.0;
        int best_class = 0;

        for (int c = 0; c < n_classes; c++) {
            int rep = classes[c].rep_index;
            double s = conflict_score_sym(items[rep].va, items[i].va, iters, repeats);
            if (s > best_score) {
                best_score = s;
                best_class = c;
            }
        }

        /* Case 1: strong evidence of interference with an existing class rep. */
        if (best_score >= threshold) {
            items[i].bank_class = best_class;
            items[i].score_vs_rep = best_score;
            classes[best_class].count++;
            continue;
        }

        /* Case 2: no strong match -> create a new class if we still can. */
        if (n_classes < max_classes) {
            items[i].bank_class = n_classes;
            items[i].score_vs_rep = best_score;
            classes[n_classes].rep_index = i;
            classes[n_classes].count = 1;
            n_classes++;
            continue;
        }

        /* Case 3: cap reached -> *still* assign to best existing class. */
        items[i].bank_class = best_class;
        items[i].score_vs_rep = best_score;
        classes[best_class].count++;
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
        fprintf(f,
                "    {\"va\":\"0x%016" PRIx64 "\",\"pa\":\"0x%016" PRIx64 "\",\"bank_class\":%d,\"score_vs_rep\":%.6f}%s\n",
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
        "  --max-classes K    cap number of classes (default 16)\n"
        "  --csv PATH         write CSV to PATH (default banks.csv)\n"
        "  --json PATH        write JSON to PATH (default banks.json)\n"
        "  --no-pin           don't pin to CPU0\n"
        "\n"
        "notes:\n"
        "  - VA->PA uses /proc/self/pagemap, which may be restricted.\n"
        "    If VA->PA fails, PA will be 0 in the output.\n",
        argv0);
}

int main(int argc, char **argv)
{
    int n = 1024;
    uint64_t alloc_mb = 256;
    uint64_t stride = PAGE_SIZE;
    int iters = 4000;
    int repeats = 5;
    double thresh = 1.25;
    int max_classes = 16; /* <- default now matches "16 banks" on DDR4 */
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
    if (iters <= 0 || repeats <= 0) die("--iters/--repeats must be > 0");
    if (max_classes <= 0) die("--max-classes must be > 0");

    if (do_pin) pin_to_cpu0();
    try_raise_priority();

    uint64_t alloc_bytes = alloc_mb * 1024ULL * 1024ULL;

    /* Anonymous allocation; page-aligned by definition. */
    uint8_t *buf = mmap(NULL, alloc_bytes, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (buf == MAP_FAILED) die("mmap failed: %s", strerror(errno));

    /* Fault pages in up front so pagemap sees them and timing isn't dominated by faults. */
    for (uint64_t off = 0; off < alloc_bytes; off += PAGE_SIZE) {
        buf[off] = (uint8_t)(off ^ 0xA5);
    }

    /* Build candidate list. */
    item_t *items = calloc((size_t)n, sizeof(*items));
    if (!items) die("calloc items failed");

    int n_items = 0;
    for (uint64_t off = 0; off < alloc_bytes && n_items < n; off += stride) {
        volatile uint8_t *p = (volatile uint8_t *)(buf + off);
        uint64_t pa = 0;
        (void)va_to_pa((uint64_t)(uintptr_t)p, &pa);

        items[n_items].va = p;
        items[n_items].pa = pa;
        items[n_items].bank_class = -1;
        items[n_items].score_vs_rep = 0.0;
        n_items++;
    }

    if (n_items <= 0) die("no items (allocation too small?)");

    class_t *classes = calloc((size_t)max_classes, sizeof(*classes));
    if (!classes) die("calloc classes failed");

    fprintf(stderr,
            "info: n_items=%d iters=%d repeats=%d thresh=%.3f max_classes=%d stride=%" PRIu64 " alloc=%" PRIu64 "\n",
            n_items, iters, repeats, thresh, max_classes, stride, alloc_bytes);

    int n_classes = cluster_items(items, n_items, classes, max_classes, iters, repeats, thresh);

    /* Emit outputs. */
    FILE *fcsv = fopen(csv_path, "w");
    if (!fcsv) die("open csv '%s' failed: %s", csv_path, strerror(errno));
    write_csv(fcsv, items, n_items);
    fclose(fcsv);

    FILE *fjson = fopen(json_path, "w");
    if (!fjson) die("open json '%s' failed: %s", json_path, strerror(errno));
    write_json(fjson, items, n_items, n_classes, thresh, iters, repeats, alloc_bytes, stride);
    fclose(fjson);

    fprintf(stderr, "done: classes=%d (csv=%s json=%s)\n", n_classes, csv_path, json_path);

    /* Clean up. */
    if (g_pagemap_fd >= 0) close(g_pagemap_fd);
    munmap((void*)buf, alloc_bytes);
    free(classes);
    free(items);
    return 0;
}

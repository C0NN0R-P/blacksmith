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

#ifndef CACHELINE
#define CACHELINE 64ULL
#endif

/* ============================================================
 * Small helpers (log/parse/pin)
 * ============================================================ */

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

/* ============================================================
 * VA -> PA via /proc/self/pagemap (best-effort)
 * ============================================================ */

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

/* ============================================================
 * Timing core
 * ============================================================ */

static inline uint64_t rdtscp_serial(void)
{
    unsigned aux;
    uint64_t t = __rdtscp(&aux);
    _mm_lfence();
    return t;
}

static inline void flush_line(void *p)
{
    _mm_clflush(p);
}

/*
 * Stream baseline:
 *   - Flush A once (start from DRAM-ish)
 *   - Then repeatedly load A for `inner` iterations
 *
 * If the memory system allows it, the repeated loads can become row-buffer hits
 * (or at least more stable than constantly flushing).
 */
static double stream_single(volatile uint8_t *a, int inner)
{
    flush_line((void *)a);
    _mm_mfence();

    uint64_t t0 = rdtscp_serial();
    for (int i = 0; i < inner; i++) {
        (void)*a;
        _mm_lfence();
    }
    uint64_t t1 = rdtscp_serial();

    if (inner <= 0) return 1.0;
    return (double)(t1 - t0) / (double)inner;
}

/*
 * Stream pair:
 *   - Flush A and B once
 *   - Alternate A,B,A,B,... for `inner` iterations
 *
 * If A and B map to the same bank but different rows, alternating tends to
 * create row-buffer conflicts (slower). If they’re different banks, the
 * controller can overlap more, often faster.
 */
static double stream_pair(volatile uint8_t *a, volatile uint8_t *b, int inner)
{
    flush_line((void *)a);
    flush_line((void *)b);
    _mm_mfence();

    uint64_t t0 = rdtscp_serial();
    for (int i = 0; i < inner; i++) {
        (void)*a;
        _mm_lfence();
        (void)*b;
        _mm_lfence();
    }
    uint64_t t1 = rdtscp_serial();

    /* 2 loads per loop */
    if (inner <= 0) return 1.0;
    return (double)(t1 - t0) / (double)(2 * (double)inner);
}

/*
 * Symmetric interference score:
 *   score(a,b) = avg_pair_cycles_per_load(a,b) / avg_single_cycles_per_load(a)
 *
 * Interpreting score:
 *   ~1.00  -> little measurable interference
 *   >1.00  -> alternating with B makes A slower (candidate same-bank conflict)
 *   <1.00  -> alternating looks faster (noise / parallelism / luck)
 *
 * We also compute the reverse and average for symmetry.
 */
static double score_sym(volatile uint8_t *a, volatile uint8_t *b, int inner, int repeats)
{
    double s_ab = 0.0;
    double s_ba = 0.0;

    for (int r = 0; r < repeats; r++) {
        double base_a = stream_single(a, inner);
        double pair_ab = stream_pair(a, b, inner);
        if (base_a < 1.0) base_a = 1.0;
        s_ab += (pair_ab / base_a);

        double base_b = stream_single(b, inner);
        double pair_ba = stream_pair(b, a, inner);
        if (base_b < 1.0) base_b = 1.0;
        s_ba += (pair_ba / base_b);
    }

    s_ab /= (double)repeats;
    s_ba /= (double)repeats;
    return 0.5 * (s_ab + s_ba);
}

/* ============================================================
 * Data model
 * ============================================================ */

typedef struct {
    volatile uint8_t *va;
    uint64_t pa;
    int bank_class;
    double score_vs_rep;
} item_t;

typedef struct {
    int medoid;   /* index into items[] */
    int count;
} class_t;

/* ============================================================
 * Clustering (k-medoids-ish)
 *
 * We treat "similarity" as: higher score => more likely to be same-bank conflict.
 * The bins are “likely same bank” bins (probabilistic).
 * ============================================================ */

/* Pick K seeds using a farthest-first heuristic on similarity.
 * Intuition: avoid having the first K items all become permanent “unique” classes.
 */
static void pick_initial_medoids(const double *S, int n, int K, int *medoids_out)
{
    /* Start with 0. */
    medoids_out[0] = 0;

    for (int k = 1; k < K; k++) {
        int best_i = 0;
        double best_dist = -1.0;

        for (int i = 0; i < n; i++) {
            /* Distance = 1 / max_similarity_to_any_existing_medoid
             * (so if it looks very similar to an existing medoid, it’s "close")
             */
            double max_sim = 0.0;
            for (int j = 0; j < k; j++) {
                int m = medoids_out[j];
                double sim = S[(size_t)i * n + m];
                if (sim > max_sim) max_sim = sim;
            }
            double dist = (max_sim > 1e-9) ? (1.0 / max_sim) : 1e9;
            if (dist > best_dist) {
                best_dist = dist;
                best_i = i;
            }
        }
        medoids_out[k] = best_i;
    }
}

/* Assign each point to the medoid it is MOST similar to. */
static void assign_to_medoids(item_t *items, int n, const double *S,
                              class_t *classes, int K)
{
    for (int c = 0; c < K; c++) classes[c].count = 0;

    for (int i = 0; i < n; i++) {
        int best_c = 0;
        double best_sim = -1.0;

        for (int c = 0; c < K; c++) {
            int m = classes[c].medoid;
            double sim = S[(size_t)i * n + m];
            if (sim > best_sim) {
                best_sim = sim;
                best_c = c;
            }
        }

        items[i].bank_class = best_c;
        items[i].score_vs_rep = best_sim;
        classes[best_c].count++;
    }
}

/* Recompute medoid per cluster as the item with max total similarity to cluster members. */
static void recompute_medoids(const double *S, int n, item_t *items,
                             class_t *classes, int K)
{
    for (int c = 0; c < K; c++) {
        int best_i = classes[c].medoid;
        double best_sum = -1.0;

        for (int i = 0; i < n; i++) {
            if (items[i].bank_class != c) continue;

            double sum = 0.0;
            for (int j = 0; j < n; j++) {
                if (items[j].bank_class != c) continue;
                sum += S[(size_t)i * n + j];
            }

            if (sum > best_sum) {
                best_sum = sum;
                best_i = i;
            }
        }

        classes[c].medoid = best_i;
    }
}

/* Main clustering driver. */
static int cluster_k_medoids(item_t *items, int n, const double *S,
                             class_t *classes, int K, int max_iters)
{
    if (K > n) K = n;
    if (K <= 0) return 0;

    int *medoids = calloc((size_t)K, sizeof(int));
    if (!medoids) die("calloc medoids failed");

    pick_initial_medoids(S, n, K, medoids);

    for (int c = 0; c < K; c++) {
        classes[c].medoid = medoids[c];
        classes[c].count = 0;
    }

    /* Iterate assignment/medoid-update a few times. */
    for (int it = 0; it < max_iters; it++) {
        int old_medoids_same = 1;
        int *old_m = calloc((size_t)K, sizeof(int));
        if (!old_m) die("calloc old_m failed");
        for (int c = 0; c < K; c++) old_m[c] = classes[c].medoid;

        assign_to_medoids(items, n, S, classes, K);
        recompute_medoids(S, n, items, classes, K);

        for (int c = 0; c < K; c++) {
            if (classes[c].medoid != old_m[c]) {
                old_medoids_same = 0;
                break;
            }
        }
        free(old_m);

        if (old_medoids_same) break;
    }

    free(medoids);
    return K;
}

/* ============================================================
 * Output (CSV/JSON)
 * ============================================================ */

static void write_csv(FILE *f, const item_t *items, int n_items)
{
    fprintf(f, "va,pa,bank_class,score_vs_rep\n");
    for (int i = 0; i < n_items; i++) {
        fprintf(f, "0x%016" PRIx64 ",0x%016" PRIx64 ",%d,%.6f\n",
                (uint64_t)(uintptr_t)items[i].va,
                items[i].pa,
                items[i].bank_class,
                items[i].score_vs_rep);
    }
}

static void write_json(FILE *f,
                       const item_t *items,
                       int n_items,
                       const class_t *classes,
                       int K,
                       int inner,
                       int repeats,
                       uint64_t alloc_bytes,
                       uint64_t stride_bytes,
                       int cluster_iters)
{
    fprintf(f, "{\n");
    fprintf(f, "  \"meta\": {\n");
    fprintf(f, "    \"n_items\": %d,\n", n_items);
    fprintf(f, "    \"k\": %d,\n", K);
    fprintf(f, "    \"inner\": %d,\n", inner);
    fprintf(f, "    \"repeats\": %d,\n", repeats);
    fprintf(f, "    \"cluster_iters\": %d,\n", cluster_iters);
    fprintf(f, "    \"alloc_bytes\": %" PRIu64 ",\n", alloc_bytes);
    fprintf(f, "    \"stride_bytes\": %" PRIu64 "\n", stride_bytes);
    fprintf(f, "  },\n");

    fprintf(f, "  \"classes\": [\n");
    for (int c = 0; c < K; c++) {
        fprintf(f, "    {\n");
        fprintf(f, "      \"id\": %d,\n", c);
        fprintf(f, "      \"medoid\": {\n");
        int m = classes[c].medoid;
        fprintf(f, "        \"index\": %d,\n", m);
        fprintf(f, "        \"va\": \"0x%016" PRIx64 "\",\n", (uint64_t)(uintptr_t)items[m].va);
        fprintf(f, "        \"pa\": \"0x%016" PRIx64 "\"\n", items[m].pa);
        fprintf(f, "      },\n");
        fprintf(f, "      \"count\": %d,\n", classes[c].count);

        fprintf(f, "      \"members\": [\n");
        int first = 1;
        for (int i = 0; i < n_items; i++) {
            if (items[i].bank_class != c) continue;
            if (!first) fprintf(f, ",\n");
            first = 0;
            fprintf(f,
                    "        {\"index\":%d,\"va\":\"0x%016" PRIx64 "\",\"pa\":\"0x%016" PRIx64 "\",\"score_vs_medoid\":%.6f}",
                    i,
                    (uint64_t)(uintptr_t)items[i].va,
                    items[i].pa,
                    items[i].score_vs_rep);
        }
        fprintf(f, "\n      ]\n");
        fprintf(f, "    }%s\n", (c == K - 1) ? "" : ",");
    }
    fprintf(f, "  ]\n");
    fprintf(f, "}\n");
}

/* ============================================================
 * Main
 * ============================================================ */

static void usage(const char *argv0)
{
    fprintf(stderr,
        "usage: %s [options]\n"
        "\n"
        "options:\n"
        "  --n N              number of candidate addresses (default 256)\n"
        "  --k K              number of bins/classes to form (default 16)\n"
        "  --alloc-mb MB      allocation size in MB (default 256)\n"
        "  --stride BYTES     stride between candidates (default 4096)\n"
        "  --inner I          inner loop iterations per stream (default 20000)\n"
        "  --repeats R        repeats per score (default 3)\n"
        "  --cluster-iters T  k-medoids iterations (default 6)\n"
        "  --csv PATH         write CSV to PATH (default banks.csv)\n"
        "  --json PATH        write JSON to PATH (default banks.json)\n"
        "  --no-pin           don't pin to CPU0\n"
        "\n"
        "notes:\n"
        "  - This is userspace-only. No kernel module.\n"
        "  - VA->PA uses /proc/self/pagemap and may be restricted; PA may be 0.\n"
        "  - n is default 256 because we compute an O(n^2) similarity matrix.\n",
        argv0);
}

int main(int argc, char **argv)
{
    int n = 256;
    int k = 16;
    uint64_t alloc_mb = 256;
    uint64_t stride = PAGE_SIZE;

    int inner = 20000;
    int repeats = 3;
    int cluster_iters = 6;

    const char *csv_path = "banks.csv";
    const char *json_path = "banks.json";
    bool do_pin = true;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--n") && i + 1 < argc) {
            n = (int)parse_u64(argv[++i]);
        } else if (!strcmp(argv[i], "--k") && i + 1 < argc) {
            k = (int)parse_u64(argv[++i]);
        } else if (!strcmp(argv[i], "--alloc-mb") && i + 1 < argc) {
            alloc_mb = parse_u64(argv[++i]);
        } else if (!strcmp(argv[i], "--stride") && i + 1 < argc) {
            stride = parse_u64(argv[++i]);
        } else if (!strcmp(argv[i], "--inner") && i + 1 < argc) {
            inner = (int)parse_u64(argv[++i]);
        } else if (!strcmp(argv[i], "--repeats") && i + 1 < argc) {
            repeats = (int)parse_u64(argv[++i]);
        } else if (!strcmp(argv[i], "--cluster-iters") && i + 1 < argc) {
            cluster_iters = (int)parse_u64(argv[++i]);
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
    if (k <= 0) die("--k must be > 0");
    if (stride == 0) die("--stride must be > 0");
    if (inner <= 0 || repeats <= 0) die("--inner/--repeats must be > 0");

    if (do_pin) pin_to_cpu0();
    try_raise_priority();

    uint64_t alloc_bytes = alloc_mb * 1024ULL * 1024ULL;

    uint8_t *buf = mmap(NULL, alloc_bytes, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (buf == MAP_FAILED) die("mmap failed: %s", strerror(errno));

    /* Fault pages in up front so timing isn't dominated by page faults. */
    for (uint64_t off = 0; off < alloc_bytes; off += PAGE_SIZE) {
        buf[off] = (uint8_t)(off ^ 0xA5);
    }

    item_t *items = calloc((size_t)n, sizeof(*items));
    if (!items) die("calloc items failed");

    int n_items = 0;
    for (uint64_t off = 0; off + CACHELINE < alloc_bytes && n_items < n; off += stride) {
        /* Use a fixed cache-line offset inside each stride chunk. */
        volatile uint8_t *p = (volatile uint8_t *)(buf + off);

        uint64_t pa = 0;
        (void)va_to_pa((uint64_t)(uintptr_t)p, &pa);

        items[n_items].va = p;
        items[n_items].pa = pa;
        items[n_items].bank_class = -1;
        items[n_items].score_vs_rep = 0.0;
        n_items++;
    }

    if (n_items <= 1) die("need at least 2 items");

    fprintf(stderr,
            "info: n_items=%d k=%d inner=%d repeats=%d stride=%" PRIu64 " alloc=%" PRIu64 "\n",
            n_items, k, inner, repeats, stride, alloc_bytes);

    /* Build similarity matrix S (n_items x n_items). */
    double *S = calloc((size_t)n_items * (size_t)n_items, sizeof(double));
    if (!S) die("calloc similarity matrix failed");

    /* Diagonal = 1.0 by definition (self). */
    for (int i = 0; i < n_items; i++) {
        S[(size_t)i * n_items + i] = 1.0;
    }

    /* Compute upper triangle and mirror. */
    for (int i = 0; i < n_items; i++) {
        for (int j = i + 1; j < n_items; j++) {
            double s = score_sym(items[i].va, items[j].va, inner, repeats);
            S[(size_t)i * n_items + j] = s;
            S[(size_t)j * n_items + i] = s;
        }
    }

    class_t *classes = calloc((size_t)k, sizeof(*classes));
    if (!classes) die("calloc classes failed");

    int K = cluster_k_medoids(items, n_items, S, classes, k, cluster_iters);

    FILE *fcsv = fopen(csv_path, "w");
    if (!fcsv) die("open csv '%s' failed: %s", csv_path, strerror(errno));
    write_csv(fcsv, items, n_items);
    fclose(fcsv);

    FILE *fjson = fopen(json_path, "w");
    if (!fjson) die("open json '%s' failed: %s", json_path, strerror(errno));
    write_json(fjson, items, n_items, classes, K, inner, repeats, alloc_bytes, stride, cluster_iters);
    fclose(fjson);

    fprintf(stderr, "done: k=%d (csv=%s json=%s)\n", K, csv_path, json_path);

    if (g_pagemap_fd >= 0) close(g_pagemap_fd);
    munmap((void*)buf, alloc_bytes);
    free(classes);
    free(S);
    free(items);
    return 0;
}

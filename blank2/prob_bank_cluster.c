#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

/* ------------------------- config ------------------------- */

#define DEFAULT_ALLOC_MB   256
#define DEFAULT_N_ADDRS    1024
#define DEFAULT_STEP       64       /* cache line */
#define DEFAULT_ITERS      4000     /* inner loop per timing sample */
#define DEFAULT_REPEATS    5        /* take median of repeats */
#define DEFAULT_THRESH     1.25     /* alt/baseline ratio threshold */
#define MAX_BANK_CLASSES   128

static size_t g_pagesz;

/* ------------------------- timing + flush ------------------------- */

static inline void clflush(const void *p) {
    asm volatile("clflush (%0)" :: "r"(p) : "memory");
}

static inline uint64_t rdtsc_ordered(void) {
    uint32_t lo, hi;
    /* lfence before/after gives decent ordering on Intel */
    asm volatile("lfence\n\t"
                 "rdtsc\n\t"
                 : "=a"(lo), "=d"(hi)
                 :
                 : "memory");
    return ((uint64_t)hi << 32) | lo;
}

static inline void cpu_relax(void) {
    asm volatile("pause" ::: "memory");
}

/* pin to a CPU to reduce noise */
static void pin_to_cpu0(void) {
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(0, &set);
    (void)sched_setaffinity(0, sizeof(set), &set);
}

/* ------------------------- VA -> PA via pagemap ------------------------- */

static int va_to_pa(void *va, uint64_t *out_pa)
{
    uint64_t v = (uint64_t)(uintptr_t)va;
    uint64_t vpn = v / g_pagesz;
    uint64_t off = v % g_pagesz;

    int fd = open("/proc/self/pagemap", O_RDONLY);
    if (fd < 0) return -1;

    uint64_t entry = 0;
    off_t pos = (off_t)(vpn * sizeof(uint64_t));
    if (lseek(fd, pos, SEEK_SET) == (off_t)-1) { close(fd); return -2; }
    if (read(fd, &entry, sizeof(entry)) != (ssize_t)sizeof(entry)) { close(fd); return -3; }
    close(fd);

    if ((entry & (1ULL << 63)) == 0) return -4; /* not present */
    uint64_t pfn = entry & ((1ULL << 55) - 1);
    if (!pfn) return -5;

    *out_pa = pfn * g_pagesz + off;
    return 0;
}

/* ------------------------- helpers ------------------------- */

static int cmp_u64(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *)a;
    uint64_t y = *(const uint64_t *)b;
    if (x < y) return -1;
    if (x > y) return 1;
    return 0;
}

static uint64_t median_u64(uint64_t *arr, int n) {
    qsort(arr, (size_t)n, sizeof(uint64_t), cmp_u64);
    return arr[n/2];
}

/* ------------------------- DRAM contention tests ------------------------- */
/*
   We measure:
     baseline(A): repeated forced-DRAM loads of A
     alt(A,B): alternating forced-DRAM loads A,B,A,B,...

   If A and B strongly contend (often same bank diff-row), alt time increases.
*/

static uint64_t time_baseline(volatile uint8_t *A, int iters)
{
    uint64_t t0 = rdtsc_ordered();
    for (int i = 0; i < iters; i++) {
        clflush((const void *)A);
        asm volatile("mfence" ::: "memory");
        (void)*A;
    }
    uint64_t t1 = rdtsc_ordered();
    return t1 - t0;
}

static uint64_t time_alternate(volatile uint8_t *A, volatile uint8_t *B, int iters)
{
    uint64_t t0 = rdtsc_ordered();
    for (int i = 0; i < iters; i++) {
        clflush((const void *)A);
        clflush((const void *)B);
        asm volatile("mfence" ::: "memory");
        (void)*A;
        (void)*B;
    }
    uint64_t t1 = rdtsc_ordered();
    return t1 - t0;
}

static double conflict_score(volatile uint8_t *A, volatile uint8_t *B, int iters, int repeats)
{
    /* score = median(alt) / median(baseline) */
    uint64_t b[32], a[32];
    if (repeats > 32) repeats = 32;

    for (int r = 0; r < repeats; r++) {
        /* tiny relax to reduce back-to-back artefacts */
        for (int k = 0; k < 50; k++) cpu_relax();
        b[r] = time_baseline(A, iters);

        for (int k = 0; k < 50; k++) cpu_relax();
        a[r] = time_alternate(A, B, iters);
    }

    uint64_t mb = median_u64(b, repeats);
    uint64_t ma = median_u64(a, repeats);

    if (mb == 0) return 0.0;
    return (double)ma / (double)mb;
}

/* ------------------------- main clustering ------------------------- */

typedef struct {
    void *va;
    uint64_t pa;
    int bank_class;
    double score_vs_rep;
} AddrOut;

typedef struct {
    volatile uint8_t *rep; /* representative VA */
    int count;
} BankClass;

static void usage(const char *argv0)
{
    fprintf(stderr,
        "Usage:\n"
        "  %s [--alloc-mb N] [--n NADDR] [--step BYTES] [--iters N] [--repeats N]\n"
        "     [--thresh RATIO] [--max-classes N] [--csv]\n"
        "\n"
        "Output:\n"
        "  Prints VA, PA, bank_class, score_vs_rep (CSV if --csv)\n"
        "\n"
        "Notes:\n"
        "  - 'bank_class' is a probabilistic grouping based on DRAM contention.\n"
        "  - Requires pagemap access (often needs sudo / CAP_SYS_ADMIN depending on kernel).\n",
        argv0);
}

int main(int argc, char **argv)
{
    pin_to_cpu0();
    g_pagesz = (size_t)getpagesize();

    size_t alloc_mb = DEFAULT_ALLOC_MB;
    size_t want_n = DEFAULT_N_ADDRS;
    size_t step = DEFAULT_STEP;
    int iters = DEFAULT_ITERS;
    int repeats = DEFAULT_REPEATS;
    double thresh = DEFAULT_THRESH;
    int max_classes = MAX_BANK_CLASSES;
    bool csv = false;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--alloc-mb") && i + 1 < argc) {
            alloc_mb = (size_t)strtoull(argv[++i], NULL, 10);
        } else if (!strcmp(argv[i], "--n") && i + 1 < argc) {
            want_n = (size_t)strtoull(argv[++i], NULL, 10);
        } else if (!strcmp(argv[i], "--step") && i + 1 < argc) {
            step = (size_t)strtoull(argv[++i], NULL, 10);
            if (step == 0) step = 64;
        } else if (!strcmp(argv[i], "--iters") && i + 1 < argc) {
            iters = (int)strtol(argv[++i], NULL, 10);
        } else if (!strcmp(argv[i], "--repeats") && i + 1 < argc) {
            repeats = (int)strtol(argv[++i], NULL, 10);
        } else if (!strcmp(argv[i], "--thresh") && i + 1 < argc) {
            thresh = strtod(argv[++i], NULL);
        } else if (!strcmp(argv[i], "--max-classes") && i + 1 < argc) {
            max_classes = (int)strtol(argv[++i], NULL, 10);
            if (max_classes < 1) max_classes = 1;
            if (max_classes > MAX_BANK_CLASSES) max_classes = MAX_BANK_CLASSES;
        } else if (!strcmp(argv[i], "--csv")) {
            csv = true;
        } else {
            usage(argv[0]);
            return 1;
        }
    }

    size_t bytes = alloc_mb * 1024ULL * 1024ULL;
    uint8_t *buf = mmap(NULL, bytes, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (buf == MAP_FAILED) {
        fprintf(stderr, "mmap failed: %s\n", strerror(errno));
        return 1;
    }

    /* fault in pages so pagemap entries exist */
    for (size_t off = 0; off < bytes; off += g_pagesz) {
        buf[off] = (uint8_t)(off & 0xff);
    }

    size_t n_slots = bytes / step;
    if (n_slots < want_n) {
        fprintf(stderr, "allocation too small for requested n (slots=%zu want=%zu)\n", n_slots, want_n);
        munmap(buf, bytes);
        return 1;
    }

    /* pick addresses by simple stride sampling (deterministic, quick) */
    AddrOut *out = calloc(want_n, sizeof(*out));
    if (!out) {
        fprintf(stderr, "calloc out failed\n");
        munmap(buf, bytes);
        return 1;
    }

    size_t got = 0;
    for (size_t idx = 0; idx < n_slots && got < want_n; idx += (4096 / step)) {
        uint8_t *va = buf + idx * step;
        *(volatile uint8_t *)va ^= 1;

        uint64_t pa = 0;
        if (va_to_pa(va, &pa) != 0) continue;

        out[got].va = va;
        out[got].pa = pa;
        got++;
    }

    if (got < want_n) {
        /* fallback: fill remaining linearly */
        for (size_t idx = 0; idx < n_slots && got < want_n; idx++) {
            uint8_t *va = buf + idx * step;
            *(volatile uint8_t *)va ^= 1;

            uint64_t pa = 0;
            if (va_to_pa(va, &pa) != 0) continue;

            out[got].va = va;
            out[got].pa = pa;
            got++;
        }
    }

    if (got < want_n) {
        fprintf(stderr, "only gathered %zu/%zu addresses (pagemap restrictions?)\n", got, want_n);
        free(out);
        munmap(buf, bytes);
        return 2;
    }

    /* clustering */
    BankClass classes[MAX_BANK_CLASSES];
    memset(classes, 0, sizeof(classes));
    int n_classes = 0;

    /* seed first class with first address */
    classes[0].rep = (volatile uint8_t *)out[0].va;
    classes[0].count = 1;
    out[0].bank_class = 0;
    out[0].score_vs_rep = 1.0;
    n_classes = 1;

    for (size_t i = 1; i < want_n; i++) {
        volatile uint8_t *A = (volatile uint8_t *)out[i].va;

        int best_c = -1;
        double best_score = 0.0;

        /* compare against each class rep */
        for (int c = 0; c < n_classes; c++) {
            volatile uint8_t *R = classes[c].rep;
            double s = conflict_score(R, A, iters, repeats);

            if (s > best_score) {
                best_score = s;
                best_c = c;
            }
        }

        if (best_c >= 0 && best_score >= thresh) {
            out[i].bank_class = best_c;
            out[i].score_vs_rep = best_score;
            classes[best_c].count++;
        } else {
            /* new class if we have room */
            if (n_classes < max_classes) {
                int cnew = n_classes++;
                classes[cnew].rep = A;
                classes[cnew].count = 1;
                out[i].bank_class = cnew;
                out[i].score_vs_rep = best_score;
            } else {
                /* forced assignment to best match */
                out[i].bank_class = (best_c >= 0) ? best_c : 0;
                out[i].score_vs_rep = best_score;
                classes[out[i].bank_class].count++;
            }
        }
    }

    /* output */
    if (csv) {
        printf("va,pa,bank_class,score_vs_rep\n");
        for (size_t i = 0; i < want_n; i++) {
            printf("%p,0x%016" PRIx64 ",%d,%.3f\n",
                   out[i].va, out[i].pa, out[i].bank_class, out[i].score_vs_rep);
        }
    } else {
        for (size_t i = 0; i < want_n; i++) {
            printf("VA=%p PA=0x%016" PRIx64 " bank_class=%d score=%.3f\n",
                   out[i].va, out[i].pa, out[i].bank_class, out[i].score_vs_rep);
        }
    }

    fprintf(stderr, "classes=%d (thresh=%.2f iters=%d repeats=%d)\n",
            n_classes, thresh, iters, repeats);

    free(out);
    munmap(buf, bytes);
    return 0;
}

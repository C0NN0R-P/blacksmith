// skx_bank_sweep2.c
// Userspace SKX address decoder + allocator + bank/bin collation.
// Build: gcc -O2 -Wall -Wextra -std=c11 -o skx_bank_sweep2 skx_bank_sweep2.c
// Run:   sudo ./skx_bank_sweep2 --bytes 268435456 --step 64 --max 2000
//
// Notes:
// - Needs root to read /sys/bus/pci/devices/*/config and /proc/self/pagemap on many systems.
// - Only decodes Intel Skylake-SP/Skylake-X style (family 6 model 0x55) memory controllers.
// - bank_id = bg*4 + bank (0..15) for DDR4-style 4 bank-groups x 4 banks.

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/ioctl.h>
#include <linux/perf_event.h>
#include <asm/unistd.h>
#include <sched.h>

#ifndef BIT_ULL
#define BIT_ULL(n) (1ULL << (n))
#endif

#ifndef GENMASK_ULL
#define GENMASK_ULL(h, l) \
    (((~0ULL) - (1ULL << (l)) + 1) & (~0ULL >> (63 - (h))))
#endif

#define GET_BITFIELD(v, lo, hi) \
    (((v) & GENMASK_ULL((hi), (lo))) >> (lo))

#define NUM_IMC      2
#define NUM_CHANNELS 3
#define NUM_DIMMS    2

#define MASK26 0x3FFFFFFULL
#define MASK29 0x1FFFFFFFULL

// ---------- minimal logging ----------
static void die(const char *fmt, ...) __attribute__((noreturn));
static void die(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    exit(1);
}
static void warnx(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}

// ---------- cacheline touch helper (for perf bank validation) ----------
static inline void do_clflush(const void *p) {
#if defined(__x86_64__) || defined(__i386__)
    __asm__ __volatile__("clflush (%0)" :: "r"(p) : "memory");
#else
    (void)p;
#endif
}

static inline void do_mfence(void) {
#if defined(__x86_64__) || defined(__i386__)
    __asm__ __volatile__("mfence" ::: "memory");
#endif
}

static inline void do_lfence(void) {
#if defined(__x86_64__) || defined(__i386__)
    __asm__ __volatile__("lfence" ::: "memory");
#endif
}

static void touch_one_va(uint64_t va, uint64_t iters) {
    // Safety clamp: avoid accidental “hammer the box to death”.
    if (iters < 1000) iters = 1000;
    if (iters > 50000000ULL) {
        warnx("warn: clamping --touch-iters to 50000000 for safety (was %" PRIu64 ")", iters);
        iters = 50000000ULL;
    }

    volatile uint8_t *ptr = (volatile uint8_t *)(uintptr_t)va;
    (void)*ptr; // ensure mapping

    printf("\n=== TOUCH LOOP ===\n");
    printf("VA=0x%016" PRIx64 " iters=%" PRIu64 " (clflush+load)\n", va, iters);

    uint64_t sink = 0;
    for (uint64_t i = 0; i < iters; i++) {
        do_clflush((const void *)ptr);
        do_mfence();
        do_lfence();
        sink += *ptr;
    }
    if (sink == 0xFFFFFFFFFFFFFFFFULL) printf("sink=%" PRIu64 "\n", sink);
    printf("TOUCH LOOP DONE\n");
    printf("==================\n");
}


// ---------- sysfs helpers ----------
static int read_u32_file(const char *path, uint32_t *out) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -errno;
    char buf[64];
    ssize_t n = read(fd, buf, sizeof(buf)-1);
    close(fd);
    if (n <= 0) return -EIO;
    buf[n] = 0;
    // vendor/device files are like "0x8086"
    unsigned long v = strtoul(buf, NULL, 0);
    *out = (uint32_t)v;
    return 0;
}

static int pread_u32(int fd, off_t off, uint32_t *out) {
    uint32_t v = 0;
    ssize_t n = pread(fd, &v, sizeof(v), off);
    if (n != (ssize_t)sizeof(v)) return -errno;
    *out = v;
    return 0;
}

static int open_pci_config(const char *bdf, char *out_path, size_t out_sz) {
    // bdf like "0000:3a:0a.0"
    snprintf(out_path, out_sz, "/sys/bus/pci/devices/%s/config", bdf);
    int fd = open(out_path, O_RDONLY);
    if (fd < 0) return -errno;
    return fd;
}

// Parse sysfs dir name "0000:bb:dd.f"
static int parse_bdf(const char *name, unsigned *seg, unsigned *bus, unsigned *dev, unsigned *fn) {
    if (sscanf(name, "%x:%x:%x.%x", seg, bus, dev, fn) != 4) return -1;
    return 0;
}

static uint8_t pci_devfn(unsigned dev, unsigned fn) {
    return (uint8_t)((dev << 3) | (fn & 7));
}

// ---------- SKX structures (userspace) ----------
struct skx_dimm {
    uint8_t close_pg;
    uint8_t bank_xor_enable;
    uint8_t fine_grain_bank;
    uint8_t rowbits;
    uint8_t colbits;
};

struct skx_channel {
    char bdf[32];          // BDF string for channel device
    int  cfg_fd;           // open fd to config
    struct skx_dimm dimms[NUM_DIMMS];
};

struct skx_imc {
    uint8_t mc;    // system-wide MC number
    uint8_t lmc;   // socket-relative MC number
    uint8_t src_id;
    uint8_t node_id;
    struct skx_channel chan[NUM_CHANNELS];
};

struct skx_dev {
    struct skx_dev *next;
    uint8_t busmap[4];      // bus indices from 0x2016 reg 0xCC
    char sad_all_bdf[32];   // 0x2054
    char util_all_bdf[32];  // 0x2055
    int sad_all_fd;
    int util_all_fd;
    uint32_t mcroute;       // from 0x208e reg 0xB4
    struct skx_imc imc[NUM_IMC];
};

struct decoded_addr {
    struct skx_dev *dev;
    uint64_t addr;
    int socket;
    int imc;
    int channel;
    uint64_t chan_addr;
    int sktways;
    int chanways;
    int dimm;
    int rank;
    int channel_rank;
    uint64_t rank_address;
    int row;
    int column;
    int bank_address;
    int bank_group;
};

// ---------- global TOLM/TOHM ----------
static uint64_t skx_tolm = 0, skx_tohm = 0;

// ---------- scan PCI devices ----------
static int is_dir(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) return 0;
    return S_ISDIR(st.st_mode);
}

struct pci_ent {
    char bdf[32];
    uint16_t vendor;
    uint16_t device;
    uint8_t bus;
    uint8_t devfn;
};

static struct pci_ent *scan_pci(size_t *out_n) {
    const char *root = "/sys/bus/pci/devices";
    DIR *d = opendir(root);
    if (!d) die("failed to open %s: %s", root, strerror(errno));

    size_t cap = 256, n = 0;
    struct pci_ent *arr = calloc(cap, sizeof(*arr));
    if (!arr) die("oom");

    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (de->d_name[0] == '.') continue;
        char path[PATH_MAX];
        snprintf(path, sizeof(path), "%s/%s", root, de->d_name);
        if (!is_dir(path)) continue;

        uint32_t v=0, did=0;
        char vpath[PATH_MAX], dpath[PATH_MAX];
        snprintf(vpath, sizeof(vpath), "%s/vendor", path);
        snprintf(dpath, sizeof(dpath), "%s/device", path);
        if (read_u32_file(vpath, &v) != 0) continue;
        if (read_u32_file(dpath, &did) != 0) continue;

        unsigned seg,bus,dev,fn;
        if (parse_bdf(de->d_name, &seg, &bus, &dev, &fn) != 0) continue;

        if (n == cap) {
            cap *= 2;
            arr = realloc(arr, cap * sizeof(*arr));
            if (!arr) die("oom");
        }
        snprintf(arr[n].bdf, sizeof(arr[n].bdf), "%s", de->d_name);
        arr[n].vendor = (uint16_t)v;
        arr[n].device = (uint16_t)did;
        arr[n].bus = (uint8_t)bus;
        arr[n].devfn = pci_devfn(dev, fn);
        n++;
    }
    closedir(d);
    *out_n = n;
    return arr;
}

static struct pci_ent *find_first(const struct pci_ent *arr, size_t n, uint16_t vendor, uint16_t device) {
    for (size_t i = 0; i < n; i++) {
        if (arr[i].vendor == vendor && arr[i].device == device) return (struct pci_ent*)&arr[i];
    }
    return NULL;
}

static struct skx_dev *skx_devs = NULL;
static int skx_num_sockets = 0;

static struct skx_dev *get_skx_dev_by_bus(uint8_t bus, uint8_t idx) {
    for (struct skx_dev *d = skx_devs; d; d = d->next) {
        if (d->busmap[idx] == bus) return d;
    }
    return NULL;
}

static int skx_get_hi_lo_from_2034(const struct pci_ent *ents, size_t nents) {
    // In-kernel driver uses 0x2034 offsets D0/D4/D8.
    struct pci_ent *p = find_first(ents, nents, 0x8086, 0x2034);
    if (!p) return -ENOENT;

    char cfgpath[PATH_MAX];
    int fd = open_pci_config(p->bdf, cfgpath, sizeof(cfgpath));
    if (fd < 0) return fd;

    uint32_t reg=0;
    if (pread_u32(fd, 0xD0, &reg) != 0) { close(fd); return -EIO; }
    skx_tolm = (uint64_t)reg;

    if (pread_u32(fd, 0xD4, &reg) != 0) { close(fd); return -EIO; }
    skx_tohm = (uint64_t)reg;

    if (pread_u32(fd, 0xD8, &reg) != 0) { close(fd); return -EIO; }
    skx_tohm |= ((uint64_t)reg << 32);

    close(fd);
    return 0;
}

static int get_all_bus_mappings(const struct pci_ent *ents, size_t nents) {
    // Look for all 0x2016 devices; each represents a socket bus mapping.
    for (size_t i = 0; i < nents; i++) {
        if (ents[i].vendor != 0x8086 || ents[i].device != 0x2016) continue;

        char cfgpath[PATH_MAX];
        int fd = open_pci_config(ents[i].bdf, cfgpath, sizeof(cfgpath));
        if (fd < 0) return fd;

        uint32_t reg = 0;
        int rc = pread_u32(fd, 0xCC, &reg);
        close(fd);
        if (rc != 0) continue;

        struct skx_dev *d = calloc(1, sizeof(*d));
        if (!d) die("oom");
        d->busmap[0] = (uint8_t)GET_BITFIELD(reg, 0, 7);
        d->busmap[1] = (uint8_t)GET_BITFIELD(reg, 8, 15);
        d->busmap[2] = (uint8_t)GET_BITFIELD(reg, 16, 23);
        d->busmap[3] = (uint8_t)GET_BITFIELD(reg, 24, 31);
        d->sad_all_fd = -1;
        d->util_all_fd = -1;
        for (int mc = 0; mc < NUM_IMC; mc++) {
            for (int ch = 0; ch < NUM_CHANNELS; ch++) {
                d->imc[mc].chan[ch].cfg_fd = -1;
            }
        }
        d->next = skx_devs;
        skx_devs = d;
        skx_num_sockets++;
    }
    return skx_num_sockets;
}

static int attach_unit_to_socket(struct skx_dev *d, const char *bdf, uint16_t did,
                                 uint8_t devfn, int *out_mc_idx, int *out_ch_idx) {
    // Mirrors skx_edac.c mapping logic:
    // CHAN0: did 0x2040 devfn 10.0 (mc0) or 12.0 (mc1)
    // CHAN1: did 0x2044 devfn 10.4 (mc0) or 12.4 (mc1)
    // CHAN2: did 0x2048 devfn 11.0 (mc0) or 13.0 (mc1)
    // SAD_ALL: did 0x2054
    // UTIL_ALL: did 0x2055
    // SAD: did 0x208e -> mcroute via 0xB4

    int mc = -1, ch = -1;
    if (did == 0x2040) { // CHAN0
        if (devfn == pci_devfn(10,0)) mc = 0;
        else if (devfn == pci_devfn(12,0)) mc = 1;
        else return -1;
        ch = 0;
    } else if (did == 0x2044) { // CHAN1
        if (devfn == pci_devfn(10,4)) mc = 0;
        else if (devfn == pci_devfn(12,4)) mc = 1;
        else return -1;
        ch = 1;
    } else if (did == 0x2048) { // CHAN2
        if (devfn == pci_devfn(11,0)) mc = 0;
        else if (devfn == pci_devfn(13,0)) mc = 1;
        else return -1;
        ch = 2;
    } else if (did == 0x2054) {
        snprintf(d->sad_all_bdf, sizeof(d->sad_all_bdf), "%s", bdf);
        return 0;
    } else if (did == 0x2055) {
        snprintf(d->util_all_bdf, sizeof(d->util_all_bdf), "%s", bdf);
        return 0;
    } else if (did == 0x208e) {
        // handled separately (mcroute)
        return 0;
    } else {
        return -1;
    }

    snprintf(d->imc[mc].chan[ch].bdf, sizeof(d->imc[mc].chan[ch].bdf), "%s", bdf);
    if (out_mc_idx) *out_mc_idx = mc;
    if (out_ch_idx) *out_ch_idx = ch;
    return 0;
}

static int get_src_id(struct skx_dev *d, uint8_t *out) {
    uint32_t reg = 0;
    if (pread_u32(d->util_all_fd, 0xF0, &reg) != 0) return -EIO;
    *out = (uint8_t)GET_BITFIELD(reg, 12, 14);
    return 0;
}

static int get_node_id(struct skx_dev *d, uint8_t *out) {
    uint32_t reg = 0;
    if (pread_u32(d->util_all_fd, 0xF4, &reg) != 0) return -EIO;
    *out = (uint8_t)GET_BITFIELD(reg, 0, 2);
    return 0;
}

static int get_all_munits_and_open(const struct pci_ent *ents, size_t nents) {
    // Attach all relevant devices to each socket.
    for (size_t i = 0; i < nents; i++) {
        if (ents[i].vendor != 0x8086) continue;
        uint16_t did = ents[i].device;
        if (!(did == 0x2054 || did == 0x2055 || did == 0x2040 || did == 0x2044 || did == 0x2048 || did == 0x208e))
            continue;

        // busidx for mapping: per skx_edac.c:
        // 2054/2055/208e use busidx 1, channels use busidx 2.
        uint8_t busidx = (did == 0x2040 || did == 0x2044 || did == 0x2048) ? 2 : 1;
        struct skx_dev *d = get_skx_dev_by_bus(ents[i].bus, busidx);
        if (!d) continue;

        if (did == 0x208e) {
            // build mcroute from non-zero 0xB4 entries, must match
            char cfgpath[PATH_MAX];
            int fd = open_pci_config(ents[i].bdf, cfgpath, sizeof(cfgpath));
            if (fd < 0) continue;
            uint32_t reg = 0;
            if (pread_u32(fd, 0xB4, &reg) == 0 && reg != 0) {
                if (d->mcroute == 0) d->mcroute = reg;
                else if (d->mcroute != reg) {
                    warnx("warn: mcroute mismatch on socket busidx=1 bus=%u (%08x vs %08x)",
                          ents[i].bus, d->mcroute, reg);
                }
            }
            close(fd);
            continue;
        }

        attach_unit_to_socket(d, ents[i].bdf, did, ents[i].devfn, NULL, NULL);
    }

    // Open needed fds now
    for (struct skx_dev *d = skx_devs; d; d = d->next) {
        if (d->sad_all_bdf[0] == 0 || d->util_all_bdf[0] == 0) {
            warnx("warn: missing sad_all/util_all for a socket (busmap=%u,%u,%u,%u)",
                  d->busmap[0], d->busmap[1], d->busmap[2], d->busmap[3]);
            continue;
        }
        char path[PATH_MAX];

        d->sad_all_fd = open_pci_config(d->sad_all_bdf, path, sizeof(path));
        if (d->sad_all_fd < 0) warnx("warn: open %s failed: %s", path, strerror(-d->sad_all_fd));

        d->util_all_fd = open_pci_config(d->util_all_bdf, path, sizeof(path));
        if (d->util_all_fd < 0) warnx("warn: open %s failed: %s", path, strerror(-d->util_all_fd));

        for (int mc = 0; mc < NUM_IMC; mc++) {
            for (int ch = 0; ch < NUM_CHANNELS; ch++) {
                if (d->imc[mc].chan[ch].bdf[0] == 0) continue;
                d->imc[mc].chan[ch].cfg_fd = open_pci_config(d->imc[mc].chan[ch].bdf, path, sizeof(path));
                if (d->imc[mc].chan[ch].cfg_fd < 0)
                    warnx("warn: open %s failed: %s", path, strerror(-d->imc[mc].chan[ch].cfg_fd));
            }
        }

        // fill src_id/node_id into imc structs
        if (d->util_all_fd >= 0) {
            uint8_t src=0, node=0;
            if (get_src_id(d, &src) == 0 && get_node_id(d, &node) == 0) {
                for (int mc = 0; mc < NUM_IMC; mc++) {
                    d->imc[mc].src_id = src;
                    d->imc[mc].node_id = node;
                    d->imc[mc].lmc = (uint8_t)mc;
                }
            }
        }
    }
    return 0;
}

// ---------- DIMM config extraction (from skx_edac.c) ----------
static int get_dimm_attr(uint32_t reg, int lobit, int hibit, int add, int minval, int maxval) {
    uint32_t val = (uint32_t)GET_BITFIELD(reg, lobit, hibit);
    if ((int)val < minval || (int)val > maxval) return -EINVAL;
    return (int)val + add;
}
#define IS_DIMM_PRESENT(mtr) GET_BITFIELD((mtr), 15, 15)
static int numrank(uint32_t reg) { return get_dimm_attr(reg, 12, 13, 0, 1, 2); }
static int numrow(uint32_t reg)  { return get_dimm_attr(reg, 2, 4, 12, 1, 6); }
static int numcol(uint32_t reg)  { return get_dimm_attr(reg, 0, 1, 10, 0, 2); }

static int skx_load_dimm_params(void) {
    // Read per-channel regs:
    // amap: 0x8C, mtr[dimm]: 0x80 + 4*j
    for (struct skx_dev *d = skx_devs; d; d = d->next) {
        for (int mc = 0; mc < NUM_IMC; mc++) {
            for (int ch = 0; ch < NUM_CHANNELS; ch++) {
                int fd = d->imc[mc].chan[ch].cfg_fd;
                if (fd < 0) continue;

                uint32_t amap = 0;
                if (pread_u32(fd, 0x8C, &amap) != 0) continue;

                for (int j = 0; j < NUM_DIMMS; j++) {
                    uint32_t mtr = 0;
                    if (pread_u32(fd, 0x80 + 4*j, &mtr) != 0) continue;

                    if (!IS_DIMM_PRESENT(mtr)) continue;

                    int ranks = numrank(mtr);
                    int rows  = numrow(mtr);
                    int cols  = numcol(mtr);
                    (void)ranks;

                    struct skx_dimm *sd = &d->imc[mc].chan[ch].dimms[j];
                    sd->close_pg = (uint8_t)GET_BITFIELD(mtr, 0, 0);
                    sd->bank_xor_enable = (uint8_t)GET_BITFIELD(mtr, 9, 9);
                    sd->fine_grain_bank = (uint8_t)GET_BITFIELD(amap, 0, 0);
                    sd->rowbits = (uint8_t)rows;
                    sd->colbits = (uint8_t)cols;
                }
            }
        }
    }
    return 0;
}

// ---------- decode logic (adapted from skx_edac.c) ----------
#define SKX_MAX_SAD 24
static int SKX_GET_SAD(struct skx_dev *d, int i, uint32_t *sad) {
    return pread_u32(d->sad_all_fd, 0x60 + 8*i, sad);
}
static int SKX_GET_ILV(struct skx_dev *d, int i, uint32_t *ilv) {
    return pread_u32(d->sad_all_fd, 0x64 + 8*i, ilv);
}
#define SKX_SAD_MOD3MODE(sad) GET_BITFIELD((sad), 30, 31)
#define SKX_SAD_MOD3(sad)     GET_BITFIELD((sad), 27, 27)
#define SKX_SAD_LIMIT(sad)    ((((uint64_t)GET_BITFIELD((sad), 7, 26)) << 26) | MASK26)
#define SKX_SAD_MOD3ASMOD2(sad) GET_BITFIELD((sad), 5, 6)
#define SKX_SAD_ATTR(sad)     GET_BITFIELD((sad), 3, 4)
#define SKX_SAD_INTERLEAVE(sad) GET_BITFIELD((sad), 1, 2)
#define SKX_SAD_ENABLE(sad)   GET_BITFIELD((sad), 0, 0)
#define SKX_ILV_REMOTE(tgt)   ((((tgt) & 8) == 0))
#define SKX_ILV_TARGET(tgt)   ((tgt) & 7)

static bool skx_sad_decode(struct decoded_addr *res) {
    // pick the first socket as starting point (like skx_edac), follow remote if needed
    struct skx_dev *d0 = skx_devs;
    if (!d0) return false;

    struct skx_dev *d = d0;
    uint64_t addr = res->addr;

    if (addr >= skx_tohm || (addr >= skx_tolm && addr < BIT_ULL(32))) {
        warnx("warn: address 0x%llx out of range (tolm=0x%llx tohm=0x%llx)",
              (unsigned long long)addr, (unsigned long long)skx_tolm, (unsigned long long)skx_tohm);
        return false;
    }

    int remote = 0;
restart:
    uint64_t prev_limit = 0;
    for (int i = 0; i < SKX_MAX_SAD; i++) {
        uint32_t sad=0;
        if (SKX_GET_SAD(d, i, &sad) != 0) continue;
        uint64_t limit = SKX_SAD_LIMIT(sad);
        if (SKX_SAD_ENABLE(sad)) {
            if (addr >= prev_limit && addr <= limit) {
                uint32_t ilv=0;
                if (SKX_GET_ILV(d, i, &ilv) != 0) return false;

                int idx=0;
                switch (SKX_SAD_INTERLEAVE(sad)) {
                    case 0: idx = (int)GET_BITFIELD(addr, 6, 8); break;
                    case 1: idx = (int)GET_BITFIELD(addr, 8, 10); break;
                    case 2: idx = (int)GET_BITFIELD(addr, 12, 14); break;
                    case 3: idx = (int)GET_BITFIELD(addr, 30, 32); break;
                    default: return false;
                }
                int tgt = (int)GET_BITFIELD(ilv, 4*idx, 4*idx + 3);

                if (SKX_ILV_REMOTE(tgt)) {
                    if (remote) return false;
                    remote = 1;
                    int want = SKX_ILV_TARGET(tgt);
                    for (struct skx_dev *x = skx_devs; x; x = x->next) {
                        if (x->imc[0].src_id == want) { d = x; goto restart; }
                    }
                    return false;
                }

                int lchan=0, shift=0;
                if (SKX_SAD_MOD3(sad) == 0) {
                    lchan = SKX_ILV_TARGET(tgt);
                } else {
                    switch (SKX_SAD_MOD3MODE(sad)) {
                        case 0: shift = 6; break;
                        case 1: shift = 8; break;
                        case 2: shift = 12; break;
                        default: return false;
                    }
                    switch (SKX_SAD_MOD3ASMOD2(sad)) {
                        case 0: lchan = (int)((addr >> shift) % 3); break;
                        case 1: lchan = (int)((addr >> shift) % 2); break;
                        case 2:
                            lchan = (int)((addr >> shift) % 2);
                            lchan = (lchan << 1) | ~lchan;
                            break;
                        case 3: lchan = (int)(((addr >> shift) % 2) << 1); break;
                        default: return false;
                    }
                    lchan = (lchan << 1) | (SKX_ILV_TARGET(tgt) & 1);
                }

                res->dev = d;
                res->socket = d->imc[0].src_id;
                if (d->mcroute == 0) return false;

                res->imc = (int)GET_BITFIELD(d->mcroute, lchan * 3, lchan * 3 + 2);
                res->channel = (int)GET_BITFIELD(d->mcroute, lchan * 2 + 18, lchan * 2 + 19);
                return true;
            }
        }
        prev_limit = limit + 1;
    }
    return false;
}

#define SKX_MAX_TAD 8
static int SKX_GET_TADBASE(struct skx_dev *d, int mc, int i, uint32_t *reg) {
    // use channel 0 device of that imc (like driver)
    int fd = d->imc[mc].chan[0].cfg_fd;
    if (fd < 0) return -ENOENT;
    return pread_u32(fd, 0x850 + 4*i, reg);
}
static int SKX_GET_TADWAYNESS(struct skx_dev *d, int mc, int i, uint32_t *reg) {
    int fd = d->imc[mc].chan[0].cfg_fd;
    if (fd < 0) return -ENOENT;
    return pread_u32(fd, 0x880 + 4*i, reg);
}
static int SKX_GET_TADCHNILVOFFSET(struct skx_dev *d, int mc, int ch, int i, uint32_t *reg) {
    int fd = d->imc[mc].chan[ch].cfg_fd;
    if (fd < 0) return -ENOENT;
    return pread_u32(fd, 0x90 + 4*i, reg);
}

#define SKX_TAD_BASE(b)       (((uint64_t)GET_BITFIELD((b), 12, 31)) << 26)
#define SKX_TAD_SKT_GRAN(b)   GET_BITFIELD((b), 4, 5)
#define SKX_TAD_CHN_GRAN(b)   GET_BITFIELD((b), 6, 7)
#define SKX_TAD_LIMIT(b)      ((((uint64_t)GET_BITFIELD((b), 12, 31)) << 26) | MASK26)
#define SKX_TAD_OFFSET(b)     (((uint64_t)GET_BITFIELD((b), 4, 23)) << 26)
#define SKX_TAD_SKTWAYS(b)    (1 << GET_BITFIELD((b), 10, 11))
#define SKX_TAD_CHNWAYS(b)    (GET_BITFIELD((b), 8, 9) + 1)

static int skx_granularity[] = { 6, 8, 12, 30 };

static uint64_t skx_do_interleave(uint64_t addr, int shift, int ways, uint64_t lowbits) {
    addr >>= shift;
    addr /= (uint64_t)ways;
    addr <<= shift;
    return addr | (lowbits & ((1ULL << shift) - 1));
}

static bool skx_tad_decode(struct decoded_addr *res) {
    for (int i = 0; i < SKX_MAX_TAD; i++) {
        uint32_t base=0, wayness=0;
        if (SKX_GET_TADBASE(res->dev, res->imc, i, &base) != 0) continue;
        if (SKX_GET_TADWAYNESS(res->dev, res->imc, i, &wayness) != 0) continue;

        if (SKX_TAD_BASE(base) <= res->addr && res->addr <= SKX_TAD_LIMIT(wayness)) {
            res->sktways = (int)SKX_TAD_SKTWAYS(wayness);
            res->chanways = (int)SKX_TAD_CHNWAYS(wayness);

            int skt_interleave_bit = skx_granularity[SKX_TAD_SKT_GRAN(base)];
            int chn_interleave_bit = skx_granularity[SKX_TAD_CHN_GRAN(base)];

            uint32_t chnilvoffset=0;
            if (SKX_GET_TADCHNILVOFFSET(res->dev, res->imc, res->channel, i, &chnilvoffset) != 0)
                return false;

            uint64_t channel_addr = res->addr - SKX_TAD_OFFSET(chnilvoffset);

            if (res->chanways == 3 && skt_interleave_bit > chn_interleave_bit) {
                channel_addr = skx_do_interleave(channel_addr, chn_interleave_bit, res->chanways, channel_addr);
                channel_addr = skx_do_interleave(channel_addr, skt_interleave_bit, res->sktways, channel_addr);
            } else {
                channel_addr = skx_do_interleave(channel_addr, skt_interleave_bit, res->sktways, res->addr);
                channel_addr = skx_do_interleave(channel_addr, chn_interleave_bit, res->chanways, res->addr);
            }
            res->chan_addr = channel_addr;
            return true;
        }
    }
    return false;
}

#define SKX_MAX_RIR 4
static int SKX_GET_RIRWAYNESS(struct skx_dev *d, int mc, int ch, int i, uint32_t *reg) {
    int fd = d->imc[mc].chan[ch].cfg_fd;
    if (fd < 0) return -ENOENT;
    return pread_u32(fd, 0x108 + 4*i, reg);
}
static int SKX_GET_RIRILV(struct skx_dev *d, int mc, int ch, int idx, int i, uint32_t *reg) {
    int fd = d->imc[mc].chan[ch].cfg_fd;
    if (fd < 0) return -ENOENT;
    return pread_u32(fd, 0x120 + 16*idx + 4*i, reg);
}

#define SKX_RIR_VALID(b)      GET_BITFIELD((b), 31, 31)
#define SKX_RIR_LIMIT(b)      ((((uint64_t)GET_BITFIELD((b), 1, 11)) << 29) | MASK29)
#define SKX_RIR_WAYS(b)       (1 << GET_BITFIELD((b), 28, 29))
#define SKX_RIR_CHAN_RANK(b)  GET_BITFIELD((b), 16, 19)
#define SKX_RIR_OFFSET(b)     (((uint64_t)GET_BITFIELD((b), 2, 15)) << 26)

static bool skx_rir_decode(struct decoded_addr *res) {
    struct skx_dimm *dimm0 = &res->dev->imc[res->imc].chan[res->channel].dimms[0];
    int shift = dimm0->close_pg ? 6 : 13;

    uint64_t prev_limit = 0;
    for (int i = 0; i < SKX_MAX_RIR; i++) {
        uint32_t rirway=0;
        if (SKX_GET_RIRWAYNESS(res->dev, res->imc, res->channel, i, &rirway) != 0) continue;
        uint64_t limit = SKX_RIR_LIMIT(rirway);

        if (SKX_RIR_VALID(rirway)) {
            if (prev_limit <= res->chan_addr && res->chan_addr <= limit) {
                uint64_t rank_addr = res->chan_addr >> shift;
                rank_addr /= (uint64_t)SKX_RIR_WAYS(rirway);
                rank_addr <<= shift;
                rank_addr |= (res->chan_addr & GENMASK_ULL(shift-1, 0));

                int idx = (int)((res->chan_addr >> shift) % SKX_RIR_WAYS(rirway));

                uint32_t rirlv=0;
                if (SKX_GET_RIRILV(res->dev, res->imc, res->channel, idx, i, &rirlv) != 0)
                    return false;

                res->rank_address = rank_addr - SKX_RIR_OFFSET(rirlv);

                int chan_rank = (int)SKX_RIR_CHAN_RANK(rirlv);
                res->channel_rank = chan_rank;
                res->dimm = chan_rank / 4;
                res->rank = chan_rank % 4;
                return true;
            }
        }
        prev_limit = limit;
    }
    return false;
}

// MAD bits tables copied from skx_edac.c
static uint8_t skx_close_row[]    = {15,16,17,18,20,21,22,28,10,11,12,13,29,30,31,32,33};
static uint8_t skx_close_column[] = {3,4,5,14,19,23,24,25,26,27};
static uint8_t skx_open_row[]     = {14,15,16,20,28,21,22,23,24,25,26,27,29,30,31,32,33};
static uint8_t skx_open_column[]  = {3,4,5,6,7,8,9,10,11,12};
static uint8_t skx_open_fine_column[] = {3,4,5,7,8,9,10,11,12,13};

static int skx_bits(uint64_t addr, int nbits, uint8_t *bits) {
    int res = 0;
    for (int i = 0; i < nbits; i++)
        res |= (int)(((addr >> bits[i]) & 1ULL) << i);
    return res;
}

static int skx_bank_bits(uint64_t addr, int b0, int b1, int do_xor, int x0, int x1) {
    int ret = (int)GET_BITFIELD(addr, b0, b0) | ((int)GET_BITFIELD(addr, b1, b1) << 1);
    if (do_xor) {
        ret ^= (int)GET_BITFIELD(addr, x0, x0) | ((int)GET_BITFIELD(addr, x1, x1) << 1);
    }
    return ret;
}

static bool skx_mad_decode(struct decoded_addr *r) {
    struct skx_dimm *dimm = &r->dev->imc[r->imc].chan[r->channel].dimms[r->dimm];
    int bg0 = dimm->fine_grain_bank ? 6 : 13;

    if (dimm->close_pg) {
        r->row    = skx_bits(r->rank_address, dimm->rowbits, skx_close_row);
        r->column = skx_bits(r->rank_address, dimm->colbits, skx_close_column);
        r->column |= 0x400;
        r->bank_address = skx_bank_bits(r->rank_address, 8, 9, dimm->bank_xor_enable, 22, 28);
        r->bank_group   = skx_bank_bits(r->rank_address, 6, 7, dimm->bank_xor_enable, 20, 21);
    } else {
        r->row = skx_bits(r->rank_address, dimm->rowbits, skx_open_row);
        if (dimm->fine_grain_bank)
            r->column = skx_bits(r->rank_address, dimm->colbits, skx_open_fine_column);
        else
            r->column = skx_bits(r->rank_address, dimm->colbits, skx_open_column);

        r->bank_address = skx_bank_bits(r->rank_address, 18, 19, dimm->bank_xor_enable, 22, 23);
        r->bank_group   = skx_bank_bits(r->rank_address, bg0, 17, dimm->bank_xor_enable, 20, 21);
    }
    r->row &= (1u << dimm->rowbits) - 1;
    return true;
}

static bool skx_decode(struct decoded_addr *res) {
    return skx_sad_decode(res) && skx_tad_decode(res) && skx_rir_decode(res) && skx_mad_decode(res);
}

// ---------- VA->PA via /proc/self/pagemap ----------
static int va_to_pa(uint64_t va, uint64_t *pa_out) {
    int fd = open("/proc/self/pagemap", O_RDONLY);
    if (fd < 0) return -errno;

    const uint64_t page_sz = 4096ULL;
    uint64_t vpn = va / page_sz;
    off_t off = (off_t)(vpn * 8ULL);

    uint64_t entry = 0;
    ssize_t n = pread(fd, &entry, sizeof(entry), off);
    close(fd);
    if (n != (ssize_t)sizeof(entry)) return -EIO;

    // present bit 63
    if (((entry >> 63) & 1ULL) == 0) return -ENOENT;

    // PFN bits 0..54 on many kernels
    uint64_t pfn = entry & ((1ULL << 55) - 1);
    if (pfn == 0) return -EIO;

    uint64_t pa = (pfn * page_sz) + (va % page_sz);
    *pa_out = pa;
    return 0;
}

// ---------- sweep + binning ----------
struct hit {
    uint64_t va;
    uint64_t pa;
    int bank_id;
    int bg;
    int bank;
    int row;
    int col;
    int socket, imc, channel, dimm, rank;
};

struct vec {
    struct hit *v;
    size_t n, cap;
};

static void vec_push(struct vec *x, struct hit h) {
    if (x->n == x->cap) {
        x->cap = x->cap ? x->cap * 2 : 256;
        x->v = realloc(x->v, x->cap * sizeof(*x->v));
        if (!x->v) die("oom");
    }
    x->v[x->n++] = h;
}


// -----------------------------
// Uncore iMC bank scan via perf_event_open
//
// This is intentionally simple: we open uncore_imc_* PMUs from sysfs, program
// RD_CAS (event=0xB0 for rank0, 0xB1 for rank1 on SKX), and vary UMASK 0..15.
// We then do a clflush+load loop on a chosen VA to generate DRAM reads.
//
// Safety:
//  - touch loop is capped (see --touch-iters clamp)
//  - we only touch VAs inside our own allocation
//  - we do *reads* only
// -----------------------------

#ifndef __NR_perf_event_open
#define __NR_perf_event_open 298
#endif

static long
perf_event_open(struct perf_event_attr *hw_event, pid_t pid,
                int cpu, int group_fd, unsigned long flags)
{
    return syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
}

typedef struct {
    char name[64];
    int  type;
    int  valid;
} imc_pmu_t;

static int
read_int_file(const char *path, int *out)
{
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    long v = -1;
    if (fscanf(f, "%ld", &v) != 1) {
        fclose(f);
        return -1;
    }
    fclose(f);
    *out = (int)v;
    return 0;
}

static size_t
discover_uncore_imcs(imc_pmu_t *imcs, size_t max_imcs)
{
    const char *base = "/sys/bus/event_source/devices";
    DIR *d = opendir(base);
    if (!d) return 0;

    size_t n = 0;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (n >= max_imcs) break;
        if (strncmp(de->d_name, "uncore_imc_", 11) != 0) continue;

        char path[256];
        snprintf(path, sizeof(path), "%s/%s/type", base, de->d_name);
        int type = -1;
        if (read_int_file(path, &type) != 0) continue;

        memset(&imcs[n], 0, sizeof(imcs[n]));
        snprintf(imcs[n].name, sizeof(imcs[n].name), "%s", de->d_name);
        imcs[n].type  = type;
        imcs[n].valid = 1;
        n++;
    }

    closedir(d);
    return n;
}

static int
open_imc_counter(int pmu_type, int cpu, uint8_t event, uint8_t umask)
{
    struct perf_event_attr pe;
    memset(&pe, 0, sizeof(pe));
    pe.type = pmu_type;
    pe.size = sizeof(pe);

    // On Intel uncore PMUs: config[7:0]=event, config[15:8]=umask.
    pe.config = ((uint64_t)event) | (((uint64_t)umask) << 8);

    pe.disabled = 1;
    pe.exclude_kernel = 0;
    pe.exclude_hv = 0;
    pe.exclude_idle = 0;

    // System-wide uncore counters: pid=-1, cpu=<cpu>
    int fd = (int)perf_event_open(&pe, -1, cpu, -1, 0);
    return fd;
}

static int
pin_to_cpu(int cpu)
{
    if (cpu < 0) return 0;
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    if (sched_setaffinity(0, sizeof(set), &set) != 0) {
        warnx("sched_setaffinity(cpu=%d) failed: %s", cpu, strerror(errno));
        return -1;
    }
    return 0;
}

static void
touch_scan_uncore_imcs_and_banks(uint64_t va, uint64_t iters,
                                 uint8_t event, int touch_cpu)
{
    imc_pmu_t imcs[32];
    const size_t n_imc = discover_uncore_imcs(imcs, 32);
    if (n_imc == 0) {
        warnx("Uncore scan: no uncore_imc_* PMUs found in sysfs.");
        return;
    }

    if (pin_to_cpu(touch_cpu) != 0) {
        warnx("Uncore scan: failed to pin to CPU %d (continuing unpinned)", touch_cpu);
    }

    // Open counters: [imc][bank]
    int fds[32][16];
    memset(fds, 0xff, sizeof(fds));

    size_t opened = 0;
    for (size_t i = 0; i < n_imc; i++) {
        for (int b = 0; b < 16; b++) {
            int fd = open_imc_counter(imcs[i].type, touch_cpu >= 0 ? touch_cpu : 0, event, (uint8_t)b);
            fds[i][b] = fd;
            if (fd >= 0) opened++;
        }
    }

    if (opened == 0) {
        warnx("Uncore scan: could not open counters (permission? perf_event_paranoid?).");
        return;
    }

    // Reset+enable all.
    for (size_t i = 0; i < n_imc; i++) {
        for (int b = 0; b < 16; b++) {
            int fd = fds[i][b];
            if (fd < 0) continue;
            ioctl(fd, PERF_EVENT_IOC_RESET, 0);
            ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
        }
    }

    // Generate traffic.
    touch_one_va(va, iters);

    // Disable and read.
    for (size_t i = 0; i < n_imc; i++) {
        uint64_t counts[16];
        memset(counts, 0, sizeof(counts));

        uint64_t sum = 0;
        int topb = -1;
        uint64_t topv = 0;

        for (int b = 0; b < 16; b++) {
            int fd = fds[i][b];
            if (fd < 0) continue;
            ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
            uint64_t v = 0;
            if (read(fd, &v, sizeof(v)) != (ssize_t)sizeof(v)) v = 0;
            counts[b] = v;
            sum += v;
            if (v > topv) { topv = v; topb = b; }
        }

        printf("%s: top bank=%d count=%" PRIu64 " (sum=%" PRIu64 ")\n",
               imcs[i].name, topb, topv, sum);
        printf("  banks:");
        for (int b = 0; b < 16; b++) {
            printf(" %d:%" PRIu64, b, counts[b]);
        }
        printf("\n");
    }

    // Close.
    for (size_t i = 0; i < n_imc; i++) {
        for (int b = 0; b < 16; b++) {
            if (fds[i][b] >= 0) close(fds[i][b]);
        }
    }
}

static void
touch_scan_allbanks(struct vec *banks, uint64_t touch_idx, uint64_t touch_iters, int touch_cpu)
{
    // For each bank_id, pick the idx-th address (if any), pick event based on decoded rank,
    // then scan all uncore_imc_* and UMASK 0..15.
    printf("\n=== UNCORE IMC BANK SCAN (RD_CAS_RANK*: event=0xB0+rank) ===\n");

    for (int bank_id = 0; bank_id < 16; bank_id++) {
        if (banks[bank_id].n == 0) continue;
        if (touch_idx >= banks[bank_id].n) continue;

        struct hit *h = &banks[bank_id].v[touch_idx];
        int rank = h->rank;
        if (rank < 0) rank = 0;
        if (rank > 1) rank = 1;
        uint8_t ev = (uint8_t)(0xB0 + rank);

        printf("\n[scan-all] bank_id=%d expects bg=%d ba=%d  using VA=0x%016" PRIx64 "  rank=%d  event=0x%02x\n",
               bank_id, bank_id/4, bank_id%4, h->va, rank, ev);

        touch_scan_uncore_imcs_and_banks(h->va, touch_iters, ev, touch_cpu);
    }

    printf("=== END UNCORE SCAN ===\n");
}
static void usage(const char *argv0) {
    fprintf(stderr,
        "Usage: sudo %s [--bytes N] [--step N] [--max N] [--print-per-bank N]\n"
        "            [--touch-bank N | --touch-va HEX] [--touch-idx N] [--touch-iters N]\n"
        "            [--touch-scan | --touch-scan-all] [--touch-cpu N]\n"
        "            [--timing-check BANKID] [--timing-iters N] [--timing-max N]\n"
        "            [--dump-banks DIR] [--uncore-validate] [--uncore-samples N]\n"
        "\n"
        "  --bytes          allocation size (default 256MiB)\n"
        "  --step           stride in bytes when sampling (default 64)\n"
        "  --max            max samples to collect total (default 50000)\n"
        "  --print-per-bank number of addresses to print from best bank (default 64)\n"
        "\n"
        "  --touch-bank     after collection, select VA from bank_id (0..15)\n"
        "  --touch-va       after collection, touch the explicit VA (must be within allocation)\n"
        "  --touch-idx      index within selected bank vector (default 0)\n"
        "  --touch-iters    iterations of (clflush+load) (default 5000000; clamped)\n"
        "  --touch-scan     after touching, run uncore iMC scan for this VA\n"
        "  --touch-scan-all scan all bank_id=0..15 (uses --touch-idx from each bank)\n"
        "  --touch-cpu      pin touch thread and perf_event_open CPU (default 0)\n"
        "\n"
        "  --timing-check   run a timing-based bank validation for BANKID\n"
        "  --timing-iters   iterations per measurement (default 200000; clamped)\n"
        "  --timing-max     max pairs per category (same-bank & diff-bank) (default 64; clamped)\n",
        "  --dump-banks     write 16 files bank_00..bank_15 under DIR (decoder output)\n"
        "  --uncore-validate cross-check decoder groups against uncore bank counters\n"
        "  --uncore-samples  samples per bank_id in uncore validate (default 8)\n",
        argv0);
    exit(1);
}

// --------------------------
// Timing sanity-check helpers
// --------------------------

static inline void lfence(void) { __asm__ __volatile__("lfence" ::: "memory"); }
static inline void mfence(void) { __asm__ __volatile__("mfence" ::: "memory"); }

static inline uint64_t rdtsc_ordered(void)
{
    unsigned lo, hi;
    lfence();
    __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
    lfence();
    return ((uint64_t)hi << 32) | lo;
}

static inline void clflush_line(const void *p)
{
    __asm__ __volatile__("clflush (%0)" :: "r"(p));
}

static uint64_t measure_pair_cycles(volatile uint8_t *a, volatile uint8_t *b, uint64_t iters)
{
    // Measures cycles for alternating loads from a and b.
    // We clflush both lines each iteration to force DRAM.
    volatile uint8_t sink = 0;
    uint64_t sum = 0;

    for (uint64_t i = 0; i < iters; i++) {
        clflush_line((const void *)a);
        clflush_line((const void *)b);
        mfence();

        uint64_t t0 = rdtsc_ordered();
        sink ^= *a;
        sink ^= *b;
        uint64_t t1 = rdtsc_ordered();
        sum += (t1 - t0);
    }

    // Prevent the compiler from optimising away the loads.
    if (sink == 0xFF) fprintf(stderr, "");
    return sum;
}

static bool same_ctx(const struct hit *a, const struct hit *b)
{
    return (a->socket  == b->socket) &&
           (a->imc     == b->imc) &&
           (a->channel == b->channel) &&
           (a->dimm    == b->dimm) &&
           (a->rank    == b->rank);
}

static void run_timing_validate_bank(struct vec banks[16], int bank_id,
                                     uint64_t iters, uint64_t max_pairs)
{
    if (bank_id < 0 || bank_id > 15) {
        warnx("timing-check: invalid BANKID=%d (must be 0..15)", bank_id);
        return;
    }
    if (banks[bank_id].n < 2) {
        warnx("timing-check: bank_id=%d has <2 hits; increase --bytes/--max", bank_id);
        return;
    }

    // Pick a context (socket/imc/ch/dimm/rank) with the most entries in this bank.
    // Timing is extremely noisy if we mix contexts.
    struct hit *ref = NULL;
    size_t best_ctx_count = 0;
    for (size_t i = 0; i < banks[bank_id].n; i++) {
        size_t cnt = 0;
        for (size_t j = 0; j < banks[bank_id].n; j++)
            if (same_ctx(&banks[bank_id].v[i], &banks[bank_id].v[j]))
                cnt++;
        if (cnt > best_ctx_count) {
            best_ctx_count = cnt;
            ref = &banks[bank_id].v[i];
        }
    }

    if (!ref || best_ctx_count < 2) {
        warnx("timing-check: could not find a stable context (need >=2 hits) for bank_id=%d", bank_id);
        return;
    }

    printf("\n=== TIMING BANK VALIDATION (bank_id=%d, iters=%" PRIu64 ", max_pairs=%" PRIu64 ") ===\n",
           bank_id, iters, max_pairs);
    printf("Context fixed to: s=%u imc=%u ch=%u d=%u r=%u (ctx_hits=%zu)\n",
           ref->socket, ref->imc, ref->channel, ref->dimm, ref->rank, best_ctx_count);
    printf("Reference: VA=0x%016" PRIx64 " PA=0x%016" PRIx64 " row=%u col=%u\n\n",
           ref->va, ref->pa, ref->row, ref->col);

    // SAME-bank: measure ref vs many other addresses in SAME bank_id, SAME context.
    uint64_t same_sum = 0;
    uint64_t same_n = 0;
    uint64_t same_min = UINT64_MAX, same_max = 0;

    volatile uint8_t *vref = (volatile uint8_t *)(uintptr_t)ref->va;
    for (size_t j = 0; j < banks[bank_id].n && same_n < max_pairs; j++) {
        struct hit *h = &banks[bank_id].v[j];
        if (h == ref) continue;
        if (!same_ctx(h, ref)) continue;
        if (h->row == ref->row) continue; // try to force row-buffer conflicts

        volatile uint8_t *vh = (volatile uint8_t *)(uintptr_t)h->va;
        uint64_t cyc = measure_pair_cycles(vref, vh, iters);
        same_sum += cyc;
        same_n++;
        if (cyc < same_min) same_min = cyc;
        if (cyc > same_max) same_max = cyc;
    }

    // DIFF-bank: measure ref vs many addresses in OTHER bank_id, SAME context.
    uint64_t diff_sum = 0;
    uint64_t diff_n = 0;
    uint64_t diff_min = UINT64_MAX, diff_max = 0;
    for (int ob = 0; ob < 16 && diff_n < max_pairs; ob++) {
        if (ob == bank_id) continue;
        for (size_t j = 0; j < banks[ob].n && diff_n < max_pairs; j++) {
            struct hit *h = &banks[ob].v[j];
            if (!same_ctx(h, ref)) continue;
            if (h->row == ref->row) continue;

            volatile uint8_t *vh = (volatile uint8_t *)(uintptr_t)h->va;
            uint64_t cyc = measure_pair_cycles(vref, vh, iters);
            diff_sum += cyc;
            diff_n++;
            if (cyc < diff_min) diff_min = cyc;
            if (cyc > diff_max) diff_max = cyc;
        }
    }

    if (same_n == 0) {
        warnx("timing-check: no same-bank pairs found (need >=2 hits in same context with different rows)");
        return;
    }
    if (diff_n == 0) {
        warnx("timing-check: no cross-bank same-context pairs found (allocation may not cover other banks in this context)");
        return;
    }

    double same_avg = (double)same_sum / (double)same_n / (double)iters;
    double diff_avg = (double)diff_sum / (double)diff_n / (double)iters;

    printf("SAME-bank: n=%" PRIu64 "  avg=%.1f cyc  min=%.1f  max=%.1f\n",
           same_n, same_avg, (double)same_min/(double)iters, (double)same_max/(double)iters);
    printf("DIFF-bank: n=%" PRIu64 "  avg=%.1f cyc  min=%.1f  max=%.1f\n",
           diff_n, diff_avg, (double)diff_min/(double)iters, (double)diff_max/(double)iters);
    printf("ratio same/diff = %.2fx\n", (diff_avg > 0.0) ? (same_avg / diff_avg) : 0.0);
    printf("=== END TIMING VALIDATION ===\n");
}


/* Dump per-bank address lists to files bank_00.txt .. bank_15.txt */
static void dump_bank_files(const char *outdir, struct bank_vec banks[SKX_NBANKS])
{
    if (!outdir) return;

    if (mkdir(outdir, 0755) != 0 && errno != EEXIST) {
        fprintf(stderr, "dump: mkdir('%s') failed: %s\n", outdir, strerror(errno));
        return;
    }

    for (int b = 0; b < SKX_NBANKS; b++) {
        char path[512];
        snprintf(path, sizeof(path), "%s/bank_%02d.txt", outdir, b);
        FILE *f = fopen(path, "w");
        if (!f) {
            fprintf(stderr, "dump: fopen('%s') failed: %s\n", path, strerror(errno));
            continue;
        }

        fprintf(f, "# bank_id=%d (bg=%d ba=%d) n=%zu\n",
                b, b >> 2, b & 3, banks[b].n);
        fprintf(f, "# columns: VA PA s imc ch d r bg ba row col\n");

        for (size_t i = 0; i < banks[b].n; i++) {
            const struct addr_ent *e = &banks[b].v[i];
            fprintf(f,
                    "0x%016" PRIx64 " 0x%016" PRIx64 " %u %u %u %u %u %u %u %u %u\n",
                    e->va, e->pa,
                    e->s, e->imc, e->ch, e->d, e->r,
                    e->bg, e->ba, e->row, e->col);
        }
        fclose(f);
    }

    fprintf(stderr, "Dumped %d bank files to '%s/'\n", SKX_NBANKS, outdir);
}

/* Measure which uncore bank counter (UMASK 0..15) dominates for a given VA. */
static int uncore_measure_bestbank(uint64_t va, uint64_t touch_iters, int touch_cpu,
                                   int event, int *out_best_imc, int *out_best_bank,
                                   uint64_t *out_best_count, uint64_t *out_best_sum)
{
    int n_imc = 0;
    struct imc_pmu_t imcs[SKX_MAX_IMCS];

    if (scan_pci_imc_pmus(imcs, &n_imc) != 0 || n_imc == 0) {
        fprintf(stderr, "uncore: no uncore_imc_* PMUs found in sysfs.\n");
        return -1;
    }

    int fds[SKX_MAX_IMCS][SKX_NBANKS];
    memset(fds, 0xff, sizeof(fds));

    for (int i = 0; i < n_imc; i++) {
        for (int b = 0; b < SKX_NBANKS; b++) {
            int fd = imc_open_event(&imcs[i], event, b /* umask(bank) */, touch_cpu);
            if (fd < 0) {
                fprintf(stderr, "uncore: could not open %s event=0x%x umask=%d (perm? perf_event_paranoid?).\n",
                        imcs[i].name, event, b);
                goto fail_close;
            }
            fds[i][b] = fd;
        }
    }

    /* reset + enable all */
    for (int i = 0; i < n_imc; i++) {
        for (int b = 0; b < SKX_NBANKS; b++) {
            ioctl(fds[i][b], PERF_EVENT_IOC_RESET, 0);
            ioctl(fds[i][b], PERF_EVENT_IOC_ENABLE, 0);
        }
    }

    touch_loop_clflush_load((volatile char *)va, touch_iters);

    /* disable + read all */
    int best_imc = -1, best_bank = -1;
    uint64_t best_count = 0, best_sum = 0;

    for (int i = 0; i < n_imc; i++) {
        uint64_t sum = 0;
        uint64_t counts[SKX_NBANKS];

        for (int b = 0; b < SKX_NBANKS; b++) {
            ioctl(fds[i][b], PERF_EVENT_IOC_DISABLE, 0);
            uint64_t val = 0;
            if (read(fds[i][b], &val, sizeof(val)) != (ssize_t)sizeof(val)) val = 0;
            counts[b] = val;
            sum += val;
        }

        int top_b = 0;
        for (int b = 1; b < SKX_NBANKS; b++)
            if (counts[b] > counts[top_b]) top_b = b;

        if (sum > best_sum) {
            best_sum = sum;
            best_imc = i;
            best_bank = top_b;
            best_count = counts[top_b];
        }
    }

    if (out_best_imc) *out_best_imc = best_imc;
    if (out_best_bank) *out_best_bank = best_bank;
    if (out_best_count) *out_best_count = best_count;
    if (out_best_sum) *out_best_sum = best_sum;

    for (int i = 0; i < n_imc; i++)
        for (int b = 0; b < SKX_NBANKS; b++)
            close(fds[i][b]);

    return 0;

fail_close:
    for (int i = 0; i < n_imc; i++)
        for (int b = 0; b < SKX_NBANKS; b++)
            if (fds[i][b] >= 0) close(fds[i][b]);
    return -1;
}

/*
 * "Proof" mode: show that the decoder's bank_id groups map to a *stable* uncore
 * bank counter index (0..15) — potentially via a permutation.
 *
 * For each decoder bank_id:
 *  - pick several addresses from that bank in the same (s/imc/ch/d/r) context
 *  - touch each address, and record which uncore bank counter dominates
 *  - report the mode (most frequent) and a "purity" score
 */
static void uncore_validate_bank_groups(struct bank_vec banks[SKX_NBANKS],
                                       uint64_t touch_iters, int touch_cpu,
                                       int per_bank_samples)
{
    fprintf(stderr, "\n=== UNCORE BANK-GROUP VALIDATION (samples=%d, iters=%" PRIu64 ") ===\n",
            per_bank_samples, touch_iters);
    fprintf(stderr, "For each decoder bank_id, we touch several addresses and record\n");
    fprintf(stderr, "the dominant uncore bank counter (UMASK 0..15) on the busiest IMC.\n");
    fprintf(stderr, "If decoder grouping is real, each bank_id should map to a stable UMASK\n");
    fprintf(stderr, "(maybe permuted), with high purity.\n\n");

    for (int b = 0; b < SKX_NBANKS; b++) {
        if (banks[b].n == 0) {
            fprintf(stderr, "bank_id=%2d: (no addresses)\n", b);
            continue;
        }

        /* Pick a reference context from first element, then sample addresses that match it. */
        const struct addr_ent *ref = &banks[b].v[0];
        unsigned ref_s = ref->s, ref_imc = ref->imc, ref_ch = ref->ch, ref_d = ref->d, ref_r = ref->r;

        int hist_imc[SKX_MAX_IMCS];
        int hist_bank[SKX_NBANKS];
        memset(hist_imc, 0, sizeof(hist_imc));
        memset(hist_bank, 0, sizeof(hist_bank));

        int got = 0;
        for (size_t i = 0; i < banks[b].n && got < per_bank_samples; i++) {
            const struct addr_ent *e = &banks[b].v[i];
            if (e->s != ref_s || e->imc != ref_imc || e->ch != ref_ch || e->d != ref_d || e->r != ref_r)
                continue;

            int event = 0xB0 + (int)e->r; /* RD_CAS_RANK* */
            int best_imc = -1, best_bank = -1;
            uint64_t best_count = 0, best_sum = 0;

            if (uncore_measure_bestbank(e->va, touch_iters, touch_cpu, event,
                                        &best_imc, &best_bank, &best_count, &best_sum) == 0) {
                if (best_imc >= 0 && best_imc < SKX_MAX_IMCS) hist_imc[best_imc]++;
                if (best_bank >= 0 && best_bank < SKX_NBANKS) hist_bank[best_bank]++;
                got++;
            }
        }

        if (got == 0) {
            fprintf(stderr, "bank_id=%2d: could not gather samples (uncore unavailable?)\n", b);
            continue;
        }

        int mode_bank = 0;
        for (int k = 1; k < SKX_NBANKS; k++)
            if (hist_bank[k] > hist_bank[mode_bank]) mode_bank = k;

        int mode_imc = 0;
        for (int k = 1; k < SKX_MAX_IMCS; k++)
            if (hist_imc[k] > hist_imc[mode_imc]) mode_imc = k;

        double purity = (double)hist_bank[mode_bank] / (double)got;

        fprintf(stderr,
                "bank_id=%2d (bg=%d ba=%d): ctx s=%u imc=%u ch=%u d=%u r=%u | "
                "uncore: mode_imc=%d, mode_umask=%d, purity=%.2f (%d/%d)\n",
                b, b >> 2, b & 3,
                ref_s, ref_imc, ref_ch, ref_d, ref_r,
                mode_imc, mode_bank, purity, hist_bank[mode_bank], got);
    }

    fprintf(stderr, "=== END UNCORE VALIDATION ===\n");
}
int main(int argc, char **argv) {
    uint64_t bytes = 256ULL * 1024 * 1024;
    uint64_t step = 64;
    uint64_t max_samples = 50000;
    uint64_t print_per_bank = 64;

    bool do_touch = false;
    int touch_bank = -1;
    uint64_t touch_idx = 0;
    uint64_t touch_va = 0;
    uint64_t touch_iters = 5000000;

    bool touch_scan = false;
    bool touch_scan_all = false;
    int touch_cpu = -1;

    bool do_timing = false;
    int timing_bank = -1;
    uint64_t timing_iters = 200000;
    uint64_t timing_max = 64;

    const char *dump_dir = NULL;
    bool do_uncore_validate = false;
    int uncore_samples = 8;


    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--bytes") && i+1 < argc) {
            bytes = strtoull(argv[++i], NULL, 0);
        } else if (!strcmp(argv[i], "--step") && i+1 < argc) {
            step = strtoull(argv[++i], NULL, 0);
        } else if (!strcmp(argv[i], "--max") && i+1 < argc) {
            max_samples = strtoull(argv[++i], NULL, 0);
        } else if (!strcmp(argv[i], "--print-per-bank") && i+1 < argc) {
            print_per_bank = strtoull(argv[++i], NULL, 0);

        } else if (!strcmp(argv[i], "--touch-bank") && i+1 < argc) {
            touch_bank = atoi(argv[++i]);
        } else if (!strcmp(argv[i], "--touch-idx") && i+1 < argc) {
            touch_idx = strtoull(argv[++i], NULL, 0);
        } else if (!strcmp(argv[i], "--touch-va") && i+1 < argc) {
            touch_va = strtoull(argv[++i], NULL, 0);
            touch_bank = -1;
        } else if (!strcmp(argv[i], "--touch-iters") && i+1 < argc) {
            touch_iters = strtoull(argv[++i], NULL, 0);
        } else if (!strcmp(argv[i], "--touch-scan")) {
            touch_scan = true;
        } else if (!strcmp(argv[i], "--touch-scan-all")) {
            touch_scan_all = true;
        } else if (!strcmp(argv[i], "--touch-cpu") && i+1 < argc) {
            touch_cpu = atoi(argv[++i]);
        } else if (!strcmp(argv[i], "--timing-check") && i+1 < argc) {
            do_timing = true;
            timing_bank = atoi(argv[++i]);
        } else if (!strcmp(argv[i], "--timing-iters") && i+1 < argc) {
            timing_iters = strtoull(argv[++i], NULL, 0);
        } else if (!strcmp(argv[i], "--timing-max") && i+1 < argc) {
            timing_max = strtoull(argv[++i], NULL, 0);
        } else if (!strcmp(argv[i], "--dump-banks") && i + 1 < argc) {
            dump_dir = argv[++i];
        } else if (!strcmp(argv[i], "--uncore-validate")) {
            do_uncore_validate = true;
        } else if (!strcmp(argv[i], "--uncore-samples") && i + 1 < argc) {
            uncore_samples = atoi(argv[++i]);
            if (uncore_samples < 1) uncore_samples = 1;
            if (uncore_samples > 64) uncore_samples = 64;
        } else { 
            usage(argv[0]);
            return 2;
        }
    }

    // Decide whether we will do a touch phase. Note: --touch-idx alone does not imply touch.
    do_touch = (touch_bank >= 0) || (touch_va != 0) || touch_scan || touch_scan_all;

    // Clamp touch loop for safety
    if (touch_iters > 5000000ULL) touch_iters = 5000000ULL;

    // Clamp timing knobs
    if (timing_iters < 1000ULL) timing_iters = 1000ULL;
    if (timing_iters > 2000000ULL) timing_iters = 2000000ULL;
    if (timing_max < 1ULL) timing_max = 1ULL;
    if (timing_max > 256ULL) timing_max = 256ULL;

    size_t nents = 0;
    struct pci_ent *ents = scan_pci(&nents);

    if (skx_get_hi_lo_from_2034(ents, nents) != 0)
        die("failed to read TOLM/TOHM (need 8086:2034 accessible)");

    int ns = get_all_bus_mappings(ents, nents);
    if (ns <= 0) die("no 8086:2016 sockets found (not SKX?)");

    get_all_munits_and_open(ents, nents);
    skx_load_dimm_params();

    // Assign MC numbering
    uint8_t mcnum = 0;
    for (struct skx_dev *d = skx_devs; d; d = d->next) {
        for (int mc = 0; mc < NUM_IMC; mc++) {
            d->imc[mc].mc = mcnum++;
        }
    }

    // Allocate
    void *buf = NULL;
    int rc = posix_memalign(&buf, 4096, (size_t)bytes);
    if (rc != 0) die("posix_memalign failed: %s", strerror(rc));

    // Touch pages to ensure mapping
    volatile uint8_t *p = (volatile uint8_t *)buf;
    for (uint64_t off = 0; off < bytes; off += 4096) {
        p[off] ^= 0xA5;
    }

    // Optional: keep in RAM (best effort)
    (void)mlock(buf, (size_t)bytes);

    struct vec banks[16] = {0};

    uint64_t collected = 0;
    for (uint64_t off = 0; off + step <= bytes && collected < max_samples; off += step) {
        uint64_t va = (uint64_t)((uintptr_t)buf + (uintptr_t)off);

        uint64_t pa = 0;
        int prc = va_to_pa(va, &pa);
        if (prc != 0) continue;

        struct decoded_addr da;
        memset(&da, 0, sizeof(da));
        da.addr = pa;

        if (!skx_decode(&da)) continue;

        int bg = da.bank_group & 3;
        int bank = da.bank_address & 3;
        int bank_id = (bg * 4) + bank;
        if (bank_id < 0 || bank_id > 15) continue;

        struct hit h;
        memset(&h, 0, sizeof(h));
        h.va = va;
        h.pa = pa;
        h.bank_id = bank_id;
        h.bg = bg;
        h.bank = bank;
        h.row = da.row;
        h.col = da.column;
        h.socket = da.socket;
        h.imc = da.imc;
        h.channel = da.channel;
        h.dimm = da.dimm;
        h.rank = da.rank;

        vec_push(&banks[bank_id], h);
        collected++;
    }

    // Summary
    printf("TOLM=0x%llx TOHM=0x%llx\n",
           (unsigned long long)skx_tolm, (unsigned long long)skx_tohm);
    printf("Collected %" PRIu64 " decoded addresses from allocation %p (%" PRIu64 " bytes)\n",
           collected, buf, bytes);

    int best = -1;
    size_t best_n = 0;

    for (int b = 0; b < 16; b++) {
        printf("bank_id=%2d (bg=%d bank=%d): %zu\n", b, b/4, b%4, banks[b].n);
        if (banks[b].n > best_n) {
            best_n = banks[b].n;
            best = b;
        }
    }

    if (best < 0 || best_n == 0) {
        printf("No addresses decoded. Likely missing PCI funcs or decode tables not matched.\n");
        return 1;
    }

    printf("\nBest bank_id=%d (bg=%d bank=%d) hits=%zu\n", best, best/4, best%4, best_n);
    printf("Sample addresses for Blacksmith (VA, PA, socket/imc/ch, dimm/rank, row, col):\n");

    size_t to_print = banks[best].n < print_per_bank ? banks[best].n : (size_t)print_per_bank;
    for (size_t i = 0; i < to_print; i++) {
        struct hit *h = &banks[best].v[i];
        printf("  VA=0x%016" PRIx64 "  PA=0x%016" PRIx64
               "  s=%d imc=%d ch=%d  d=%d r=%d  bg=%d ba=%d  row=%d col=%d\n",
               h->va, h->pa, h->socket, h->imc, h->channel,
               h->dimm, h->rank, h->bg, h->bank, h->row, h->col);
    }

    if (do_timing) {
        run_timing_validate_bank(banks, timing_bank, timing_iters, timing_max);
    }

    if (dump_dir) {
        dump_bank_files(dump_dir, banks);
    }

    if (do_uncore_validate) {
        uncore_validate_bank_groups(banks, touch_iters ? touch_iters : 2000000ULL, touch_cpu, uncore_samples);
    }

    if (do_touch) {
        // If requested, scan *all* banks (0..15). This mode does not require --touch-bank/--touch-va.
        if (touch_scan_all) {
            touch_scan_allbanks(banks, touch_idx, touch_iters, touch_cpu);
            return 0;
        }

        uint64_t va = touch_va;
        int sel_rank = 0;

        if (touch_bank >= 0) {
            if (touch_bank < 0 || touch_bank > 15) {
                warnx("touch: invalid --touch-bank %d (must be 0..15)", touch_bank);
                return 2;
            }
            if (banks[touch_bank].n == 0) {
                warnx("touch: bank_id=%d has zero hits; choose another bank_id or increase --max/--bytes", touch_bank);
                return 1;
            }
            if (touch_idx >= banks[touch_bank].n) {
                warnx("touch: --touch-idx %" PRIu64 " out of range (bank has %zu entries)",
                      touch_idx, banks[touch_bank].n);
                return 1;
            }
            va = banks[touch_bank].v[touch_idx].va;
            sel_rank = banks[touch_bank].v[touch_idx].rank;
            printf("\nTouch selected from bank_id=%d (bg=%d bank=%d) idx=%" PRIu64 " => VA=0x%016" PRIx64 "\n",
                   touch_bank, touch_bank/4, touch_bank%4, touch_idx, va);
        } else {
            if (va == 0) {
                warnx("touch: specify --touch-bank or --touch-va (or use --touch-scan-all)");
                return 2;
            }
            // Try to recover rank for this VA from the collected vectors.
            for (int b = 0; b < 16; b++) {
                for (size_t j = 0; j < banks[b].n; j++) {
                    if (banks[b].v[j].va == va) {
                        sel_rank = banks[b].v[j].rank;
                        goto rank_found;
                    }
                }
            }
rank_found:
            printf("\nTouch using explicit VA=0x%016" PRIx64 "\n", va);
        }

        // Guard: VA must be inside our allocation.
        uint64_t base = (uint64_t)(uintptr_t)buf;
        uint64_t end  = base + bytes;
        if (va < base || va >= end) {
            warnx("touch: VA=0x%016" PRIx64 " not within allocation [%p, %p). Refusing to touch.",
                  va, buf, (void *)(uintptr_t)end);
            return 1;
        }

        // Clamp rank -> event.
        if (sel_rank < 0) sel_rank = 0;
        if (sel_rank > 1) sel_rank = 1;
        uint8_t scan_event = (uint8_t)(0xB0 + sel_rank);

        if (touch_scan) {
            printf("\n=== UNCORE IMC BANK SCAN (event=0x%02x, rank=%d) ===\n", scan_event, sel_rank);
            touch_scan_uncore_imcs_and_banks(va, touch_iters, scan_event, touch_cpu);
            printf("=== END UNCORE SCAN ===\n");
        } else {
            touch_one_va(va, touch_iters);
        }
    }


    return 0;
}

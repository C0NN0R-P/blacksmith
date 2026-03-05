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
#include <linux/perf_event.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <asm/unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <dirent.h>

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

static void print_hit(const struct hit *h, const char *tag) {
    if (tag) printf("%s", tag);
    printf("VA=0x%016" PRIx64 "  PA=0x%016" PRIx64 "  s=%d imc=%d ch=%d  d=%d r=%d  bg=%d ba=%d  bank_id=%d  row=%d col=%d\n",
           h->va, h->pa, h->socket, h->imc, h->channel, h->dimm, h->rank,
           h->bg, h->bank, h->bank_id, h->row, h->col);
}

static void suggest_perf_for_hit(const struct hit *h) {
    // Intel SKX uncore iMC banked CAS events are rank-specific:
    //   RD_CAS_RANKk.BANKx : event = 0xB0 + k, umask = x
    //   WR_CAS_RANKk.BANKx : event = 0xB8 + k, umask = x
    // Many systems expose these via perf as raw encodings on uncore_imc_* PMUs.
    if (h->rank < 0 || h->rank > 7 || h->bank_id < 0 || h->bank_id > 15 || h->bg < 0 || h->bg > 3) {
        printf("Perf hint: rank/bank out of expected range; cannot suggest SKX bank events.\n");
        return;
    }
    unsigned rd_evt = 0xB0u + (unsigned)h->rank;
    unsigned wr_evt = 0xB8u + (unsigned)h->rank;
    unsigned bank_um = (unsigned)h->bank_id;
    unsigned bg_um = 0x11u + (unsigned)h->bg; // BANKG0..BANKG3 often map to 0x11..0x14

    printf("\nPerf hint for this address (rank=%d bank_id=%d bg=%d ba=%d):\n",
           h->rank, h->bank_id, h->bg, h->bank);
    printf("  Try RD_CAS_RANK%d.BANK%d:  -e 'uncore_imc_X/event=0x%02x,umask=0x%x/'\n",
           h->rank, h->bank_id, rd_evt, bank_um);
    printf("  Try RD_CAS_RANK%d.BANKG%d (bank-group only): -e 'uncore_imc_X/event=0x%02x,umask=0x%x/'\n",
           h->rank, h->bg, rd_evt, bg_um);
    printf("  (Writes) WR_CAS_RANK%d.BANK%d: -e 'uncore_imc_X/event=0x%02x,umask=0x%x/'\n",
           h->rank, h->bank_id, wr_evt, bank_um);
    printf("  Note: X is the uncore IMC instance. Start with X=%d (from decoder), but if counters stay low, try other uncore_imc_*.\n",
           h->imc);
}

static bool decode_one_va_to_hit(uint64_t va, uint64_t pa, struct hit *out) {
    struct decoded_addr r;
    memset(&r, 0, sizeof(r));
    r.addr = pa;
    if (!skx_decode(&r)) return false;

    out->va = va;
    out->pa = pa;
    out->socket  = r.socket;
    out->imc     = r.imc;
    out->channel = r.channel;
    out->dimm    = r.dimm;
    out->rank    = r.rank;
    out->row     = r.row;
    out->col     = r.column;
    out->bg      = r.bank_group;
    out->bank    = r.bank_address;
    out->bank_id = out->bg * 4 + out->bank;
    return true;
}


// ---------- uncore perf helpers (optional) ----------

static long perf_event_open_wrap(struct perf_event_attr *attr, pid_t pid, int cpu, int group_fd, unsigned long flags) {
    return syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

static int read_int_file(const char *path, int *out) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char buf[128];
    if (!fgets(buf, sizeof(buf), f)) { fclose(f); return -1; }
    fclose(f);
    *out = (int)strtol(buf, NULL, 0);
    return 0;
}

static int parse_format_bits(const char *path, int *lo, int *hi) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char buf[128];
    if (!fgets(buf, sizeof(buf), f)) { fclose(f); return -1; }
    fclose(f);
    for (char *p = buf; *p; p++) if (*p == '\n' || *p == '\r') *p = 0;
    char *c = strchr(buf, ':');
    if (!c) return -1;
    c++;
    int a=-1,b=-1;
    if (sscanf(c, "%d-%d", &a, &b) == 2) { *lo=a; *hi=b; return 0; }
    if (sscanf(c, "%d", &a) == 1) { *lo=a; *hi=a; return 0; }
    return -1;
}

static uint64_t encode_uncore_config(int imc, uint32_t event, uint32_t umask) {
    int ev_lo=0, ev_hi=7, um_lo=8, um_hi=15;
    char p_event[256], p_umask[256];
    snprintf(p_event, sizeof(p_event), "/sys/bus/event_source/devices/uncore_imc_%d/format/event", imc);
    snprintf(p_umask, sizeof(p_umask), "/sys/bus/event_source/devices/uncore_imc_%d/format/umask", imc);
    (void)parse_format_bits(p_event, &ev_lo, &ev_hi);
    (void)parse_format_bits(p_umask, &um_lo, &um_hi);

    uint64_t cfg = 0;
    uint64_t ev_mask = ((1ULL << (ev_hi - ev_lo + 1)) - 1ULL);
    uint64_t um_mask = ((1ULL << (um_hi - um_lo + 1)) - 1ULL);
    cfg |= ((uint64_t)event & ev_mask) << ev_lo;
    cfg |= ((uint64_t)umask & um_mask) << um_lo;
    return cfg;
}

static int open_uncore_imc_counter(int imc, uint32_t event, uint32_t umask, int cpu) {
    char p_type[256];
    snprintf(p_type, sizeof(p_type), "/sys/bus/event_source/devices/uncore_imc_%d/type", imc);
    int type = 0;
    if (read_int_file(p_type, &type) != 0) return -1;

    struct perf_event_attr pea;
    memset(&pea, 0, sizeof(pea));
    pea.size = sizeof(pea);
    pea.type = (uint32_t)type;
    pea.config = encode_uncore_config(imc, event, umask);
    pea.disabled = 1;

    return (int)perf_event_open_wrap(&pea, -1, cpu, -1, 0);
}

static uint64_t read_counter_fd(int fd) {
    uint64_t v = 0;
    if (read(fd, &v, sizeof(v)) != (ssize_t)sizeof(v)) return 0;
    return v;
}

static void touch_scan_uncore_imcs_and_banks(const struct hit *h, uint64_t iters, int cpu) {
    unsigned rd_evt = 0xB0u + (unsigned)h->rank;

    struct imc_scan {
        int imc;
        int fds[16];
        uint64_t vals[16];
        int ok;
    } imcs[32];

    int n_imc = 0;
    for (int imc = 0; imc < 32; imc++) {
        char p_type[256];
        snprintf(p_type, sizeof(p_type), "/sys/bus/event_source/devices/uncore_imc_%d/type", imc);
        if (access(p_type, R_OK) != 0) continue;

        imcs[n_imc].imc = imc;
        imcs[n_imc].ok = 1;
        for (int b = 0; b < 16; b++) {
            int fd = open_uncore_imc_counter(imc, rd_evt, (uint32_t)b, cpu);
            imcs[n_imc].fds[b] = fd;
            imcs[n_imc].vals[b] = 0;
            if (fd < 0) imcs[n_imc].ok = 0;
        }
        n_imc++;
        if (n_imc == 32) break;
    }

    if (n_imc == 0) {
        printf("Uncore scan: no uncore_imc_* PMUs found in sysfs.\n");
        return;
    }

    int any_ok = 0;
    for (int i = 0; i < n_imc; i++) if (imcs[i].ok) { any_ok = 1; break; }
    if (!any_ok) {
        printf("Uncore scan: could not open counters (permission? perf_event_paranoid?).\n");
        for (int i = 0; i < n_imc; i++) for (int b = 0; b < 16; b++) if (imcs[i].fds[b] >= 0) close(imcs[i].fds[b]);
        return;
    }

    for (int i = 0; i < n_imc; i++) {
        if (!imcs[i].ok) continue;
        for (int b = 0; b < 16; b++) {
            ioctl(imcs[i].fds[b], PERF_EVENT_IOC_RESET, 0);
            ioctl(imcs[i].fds[b], PERF_EVENT_IOC_ENABLE, 0);
        }
    }

    // Run the same touch loop
    touch_one_va(h->va, iters);

    for (int i = 0; i < n_imc; i++) {
        if (!imcs[i].ok) continue;
        for (int b = 0; b < 16; b++) {
            ioctl(imcs[i].fds[b], PERF_EVENT_IOC_DISABLE, 0);
            imcs[i].vals[b] = read_counter_fd(imcs[i].fds[b]);
            close(imcs[i].fds[b]);
        }
    }

    printf("\n=== UNCORE IMC BANK SCAN (RD_CAS_RANK%d: event=0x%02x) ===\n", h->rank, rd_evt);
    printf("Touch target expects bank_id=%d (bg=%d ba=%d)\n", h->bank_id, h->bg, h->bank);

    for (int i = 0; i < n_imc; i++) {
        if (!imcs[i].ok) continue;

        int top_b = 0;
        uint64_t top_v = imcs[i].vals[0];
        uint64_t sum = 0;
        for (int b = 0; b < 16; b++) {
            sum += imcs[i].vals[b];
            if (imcs[i].vals[b] > top_v) { top_v = imcs[i].vals[b]; top_b = b; }
        }
        if (sum == 0) continue;

        printf("uncore_imc_%d: top bank=%d count=%" PRIu64 " (sum=%" PRIu64 ")\n", imcs[i].imc, top_b, top_v, sum);
        printf("  banks:");
        for (int b = 0; b < 16; b++) printf(" %d:%" PRIu64, b, imcs[i].vals[b]);
        printf("\n");
    }
    printf("=== END UNCORE SCAN ===\n");
}

static void vec_push(struct vec *x, struct hit h) {
    if (x->n == x->cap) {
        x->cap = x->cap ? x->cap * 2 : 256;
        x->v = realloc(x->v, x->cap * sizeof(*x->v));
        if (!x->v) die("oom");
    }
    x->v[x->n++] = h;
}

static void usage(const char *argv0) {
    fprintf(stderr,
        "Usage: sudo %s [--bytes N] [--step N] [--max N] [--print-per-bank N]\n"
        "            [--touch-bank N] [--touch-idx N] [--touch-iters N]\n"
        "            [--touch-va HEX] [--touch-iters N]\n"
        "            [--dump-dir DIR] [--bs-dir DIR]\n"
        "            [--validate-bank N] [--validate-iters N] [--validate-pairs N]\n"
        "  --bytes          allocation size (default 256MiB)\n"
        "  --step           stride in bytes when sampling (default 64)\n"
        "  --max            max samples to collect total (default 50000)\n"
        "  --print-per-bank number of addresses to print from best bank (default 64)\n"
        "  --touch-bank     after collection, select VA from bank_id (0..15)\n"
        "  --touch-idx      index within that bank vector (default 0)\n"
        "  --touch-va       after collection, touch the explicit VA (must be within allocation)\n"
        "  --touch-iters    iterations of (clflush+load) (default 5000000; clamped for safety)\n"
        "  --dump-dir       write 16 files bank_00.txt..bank_15.txt in DIR\n"
        "  --validate-bank  run timing sanity-check using bank_id N (default: best bank)\n"
        "  --validate-iters inner loop iterations per pair (default 200000)\n"
        "  --validate-pairs max pairs sampled per compared bank (default 64)\n",
        argv0);
}

static inline uint64_t rdtsc_ordered(void) {
    unsigned lo, hi;
    asm volatile("lfence\nrdtsc" : "=a"(lo), "=d"(hi) :: "memory");
    return ((uint64_t)hi << 32) | lo;
}

static inline void clflush_one(const void *p) {
    asm volatile("clflush (%0)" :: "r"(p) : "memory");
}

static double measure_pair_cycles(volatile uint8_t *a, volatile uint8_t *b, uint64_t iters) {
    volatile uint8_t sink = 0;
    uint64_t total = 0;
    for (uint64_t i = 0; i < iters; i++) {
        clflush_one((const void *)a);
        clflush_one((const void *)b);
        asm volatile("mfence" ::: "memory");
        uint64_t t0 = rdtsc_ordered();
        sink ^= *a;
        sink ^= *b;
        uint64_t t1 = rdtsc_ordered();
        total += (t1 - t0);
    }
    if (sink == 0xFF) fprintf(stderr, "\n");
    return (double)total / (double)iters;
}


/* ======================= BLACKSMITH OUTPUT HELPERS ======================= */

static int ensure_dir(const char *dir)
{
    if (!dir || !dir[0]) return -1;
    if (mkdir(dir, 0755) == 0) return 0;
    if (errno == EEXIST) return 0;
    return -1;
}

static uint64_t ctx_key(const struct hit *h)
{
    /* pack s/imc/ch/d/r into a key */
    return ((uint64_t)h->socket   << 32) |
           ((uint64_t)h->imc << 24) |
           ((uint64_t)h->channel  << 16) |
           ((uint64_t)h->dimm   << 8)  |
           ((uint64_t)h->rank   << 0);
}

static int cmp_u64(const void *a, const void *b)
{
    uint64_t x = *(const uint64_t *)a;
    uint64_t y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}

static int cmp_hit_row_col(const void *a, const void *b)
{
    const struct hit *x = (const struct hit *)a;
    const struct hit *y = (const struct hit *)b;
    if (x->row != y->row) return (x->row > y->row) - (x->row < y->row);
    if (x->col != y->col) return (x->col > y->col) - (x->col < y->col);
    return (x->va > y->va) - (x->va < y->va);
}

static uint64_t most_common_ctx(const struct vec *v)
{
    if (v->n == 0) return 0;
    uint64_t *keys = (uint64_t *)malloc(v->n * sizeof(uint64_t));
    if (!keys) return 0;
    for (size_t i = 0; i < v->n; i++) keys[i] = ctx_key(&v->v[i]);
    qsort(keys, v->n, sizeof(uint64_t), cmp_u64);

    uint64_t best = keys[0], cur = keys[0];
    size_t bestc = 1, curc = 1;
    for (size_t i = 1; i < v->n; i++) {
        if (keys[i] == cur) {
            curc++;
        } else {
            if (curc > bestc) { bestc = curc; best = cur; }
            cur = keys[i];
            curc = 1;
        }
    }
    if (curc > bestc) { bestc = curc; best = cur; }
    free(keys);
    return best;
}

/*
 * Write, per bank:
 *   - bank_XX_full.csv : VA,PA,s,imc,ch,d,r,bg,ba,row,col
 *   - bank_XX_va.txt   : VA only (one per line)  [easy to ingest elsewhere]
 *   - bank_XX_pairs.txt: VA1 VA2 (same ctx, same bank_id, different rows)
 *
 * The selection is filtered to the most common (s/imc/ch/d/r) context within
 * each bank, so Blacksmith can later pick "same channel/rank/bank" candidates.
 */
static void write_blacksmith_outputs(const char *dir,
                                     struct vec banks[16],
                                     size_t per_bank,
                                     size_t pairs_per_bank)
{
    if (!dir) return;
    if (ensure_dir(dir) != 0) {
        fprintf(stderr, "bs: could not create dir '%s': %s\n", dir, strerror(errno));
        return;
    }

    for (int b = 0; b < 16; b++) {
        struct vec *v = &banks[b];
        if (v->n == 0) continue;

        uint64_t best_ctx = most_common_ctx(v);

        /* collect hits in best_ctx */
        struct hit *tmp = (struct hit *)malloc(v->n * sizeof(struct hit));
        if (!tmp) continue;

        size_t tn = 0;
        for (size_t i = 0; i < v->n; i++) {
            if (ctx_key(&v->v[i]) == best_ctx) tmp[tn++] = v->v[i];
        }
        if (tn == 0) { free(tmp); continue; }

        qsort(tmp, tn, sizeof(struct hit), cmp_hit_row_col);

        char path_full[512], path_va[512], path_pairs[512];
        snprintf(path_full, sizeof(path_full), "%s/bank_%02d_full.csv", dir, b);
        snprintf(path_va,   sizeof(path_va),   "%s/bank_%02d_va.txt",   dir, b);
        snprintf(path_pairs,sizeof(path_pairs),"%s/bank_%02d_pairs.txt",dir, b);

        FILE *ff = fopen(path_full, "w");
        FILE *fv = fopen(path_va,   "w");
        FILE *fp = fopen(path_pairs,"w");

        if (!ff || !fv || !fp) {
            fprintf(stderr, "bs: fopen failed for bank %d (dir '%s'): %s\n", b, dir, strerror(errno));
            if (ff) fclose(ff);
            if (fv) fclose(fv);
            if (fp) fclose(fp);
            free(tmp);
            continue;
        }

        fprintf(ff, "va,pa,s,imc,ch,d,r,bg,ba,row,col\n");

        /* write up to per_bank, keeping unique rows where possible */
        uint32_t last_row = 0xffffffffu;
        size_t written = 0;

        for (size_t i = 0; i < tn && written < per_bank; i++) {
            const struct hit *h = &tmp[i];
            /* prefer unique rows first */
            if (h->row == last_row && (tn - i) > (per_bank - written)) continue;

            fprintf(ff, "0x%016" PRIx64 ",0x%016" PRIx64 ",%u,%u,%u,%u,%u,%u,%u,%u,%u\n",
                    h->va, h->pa, h->socket, h->imc, h->channel, h->dimm, h->rank, h->bg, h->bank, h->row, h->col);
            fprintf(fv, "0x%016" PRIx64 "\n", h->va);

            last_row = h->row;
            written++;
        }

        /* pairs: take first VA as anchor and pair with different-row VAs */
        const struct hit *anchor = &tmp[0];
        size_t pairs = 0;
        for (size_t i = 1; i < tn && pairs < pairs_per_bank; i++) {
            if (tmp[i].row == anchor->row) continue;
            fprintf(fp, "0x%016" PRIx64 " 0x%016" PRIx64 "\n", anchor->va, tmp[i].va);
            pairs++;
        }

        fclose(ff);
        fclose(fv);
        fclose(fp);
        free(tmp);
    }
}

/* ===================== END BLACKSMITH OUTPUT HELPERS ===================== */


static void dump_bank_files(const char *outdir, struct vec banks[16]) {
    if (mkdir(outdir, 0755) != 0 && errno != EEXIST) {
        die("mkdir(%s): %s", outdir, strerror(errno));
    }

    char path[512];
    for (int b = 0; b < 16; b++) {
        snprintf(path, sizeof(path), "%s/bank_%02d.txt", outdir, b);
        FILE *f = fopen(path, "w");
        if (!f) die("fopen(%s): %s", path, strerror(errno));

        fprintf(f, "# bank_id=%d (bg=%d ba=%d) n=%zu\n", b, b/4, b%4, banks[b].n);
        fprintf(f, "# Columns: VA PA s imc ch dimm rank bg ba row col\n");

        for (size_t i = 0; i < banks[b].n; i++) {
            const struct hit *h = &banks[b].v[i];
            fprintf(f,
                "0x%016" PRIx64 " 0x%016" PRIx64 " %d %d %d %d %d %d %d %d %d\n",
                h->va, h->pa,
                h->socket, h->imc, h->channel, h->dimm, h->rank,
                h->bg, h->bank, h->row, h->col);
        }
        fclose(f);
    }
    printf("\nDumped 16 bank files to: %s/ (bank_00.txt .. bank_15.txt)\n", outdir);
}

static void timing_validate_bank(struct vec banks[16], int bank_id, uint64_t iters, uint64_t max_pairs) {
    if (bank_id < 0 || bank_id > 15) {
        warnx("validate: invalid --validate-bank %d (must be 0..15)", bank_id);
        return;
    }
    if (banks[bank_id].n < 2) {
        warnx("validate: bank_id=%d has <2 hits; increase --max/--bytes", bank_id);
        return;
    }

    const struct hit *ref = &banks[bank_id].v[0];
    unsigned ref_s = ref->socket, ref_imc = ref->imc, ref_ch = ref->channel, ref_d = ref->dimm, ref_r = ref->rank;
    int ref_row = ref->row;

    printf("\n=== TIMING BANK VALIDATION (bank_id=%d, iters=%" PRIu64 ", max_pairs=%" PRIu64 ") ===\n",
           bank_id, iters, max_pairs);
    printf("Context fixed to: s=%u imc=%u ch=%u d=%u r=%u\n", ref_s, ref_imc, ref_ch, ref_d, ref_r);
    printf("Reference: VA=0x%016" PRIx64 " PA=0x%016" PRIx64 " row=%d col=%d\n\n",
           ref->va, ref->pa, ref->row, ref->col);

    for (int b = 0; b < 16; b++) {
        uint64_t n = 0;
        double sum = 0.0;
        double min = 1e30, max = 0.0;

        for (size_t i = 0; i < banks[b].n && n < max_pairs; i++) {
            const struct hit *h = &banks[b].v[i];
            if ((unsigned)h->socket != ref_s || (unsigned)h->imc != ref_imc || (unsigned)h->channel != ref_ch ||
                (unsigned)h->dimm != ref_d || (unsigned)h->rank != ref_r) {
                continue;
            }
            if (h->row == ref_row) continue;

            double cyc = measure_pair_cycles((volatile uint8_t *)(uintptr_t)ref->va,
                                             (volatile uint8_t *)(uintptr_t)h->va,
                                             iters);
            sum += cyc;
            if (cyc < min) min = cyc;
            if (cyc > max) max = cyc;
            n++;
        }

        if (n == 0) {
            printf("bank %2d: n=0 (no same-context diff-row samples)\n", b);
        } else {
            printf("bank %2d: n=%" PRIu64 "  avg=%.1f cyc  min=%.1f  max=%.1f%s\n",
                   b, n, sum / (double)n, min, max, (b == bank_id) ? "  <== decoder bank" : "");
        }
    }

    printf("=== END TIMING VALIDATION ===\n");
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

    const char *dump_dir = NULL;
    const char *bs_dir = NULL;
    size_t bs_per_bank = 1024;
    size_t bs_pairs = 256;
    bool do_validate = false;
    int validate_bank = -1;
    uint64_t validate_iters = 200000;
    uint64_t validate_pairs = 64;
    bool touch_scan = false;
    int touch_cpu = 0;


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
            do_touch = true;
            touch_bank = atoi(argv[++i]);
        } else if (!strcmp(argv[i], "--touch-idx") && i+1 < argc) {
            do_touch = true;
            touch_idx = strtoull(argv[++i], NULL, 0);
        } else if (!strcmp(argv[i], "--touch-va") && i+1 < argc) {
            do_touch = true;
            touch_va = strtoull(argv[++i], NULL, 0);
            touch_bank = -1;
        } else if (!strcmp(argv[i], "--touch-iters") && i+1 < argc) {
            touch_iters = strtoull(argv[++i], NULL, 0);
        } else if (!strcmp(argv[i], "--dump-dir") && i+1 < argc) {
            dump_dir = argv[++i];
        } else if (!strcmp(argv[i], "--bs-dir") && i+1 < argc) {
            bs_dir = argv[++i];
        } else if (!strcmp(argv[i], "--bs-per-bank") && i+1 < argc) {
            bs_per_bank = strtoull(argv[++i], NULL, 0);
        } else if (!strcmp(argv[i], "--bs-pairs") && i+1 < argc) {
            bs_pairs = strtoull(argv[++i], NULL, 0);
        } else if (!strcmp(argv[i], "--validate-bank") && i+1 < argc) {
            do_validate = true;
            validate_bank = atoi(argv[++i]);
        } else if (!strcmp(argv[i], "--validate-iters") && i+1 < argc) {
            do_validate = true;
            validate_iters = strtoull(argv[++i], NULL, 0);
        } else if (!strcmp(argv[i], "--validate-pairs") && i+1 < argc) {
            do_validate = true;
            validate_pairs = strtoull(argv[++i], NULL, 0);
        } else if (!strcmp(argv[i], "--touch-scan")) {
            do_touch = true;
            touch_scan = true;
        } else if (!strcmp(argv[i], "--touch-cpu") && i+1 < argc) {
            touch_cpu = (int)strtoul(argv[++i], NULL, 0);
        } else {
            usage(argv[0]);
            return 2;
        }
    }

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

    if (do_touch) {
        uint64_t va = touch_va;
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
            printf("\nTouch selected from bank_id=%d (bg=%d bank=%d) idx=%" PRIu64 " => VA=0x%016" PRIx64 "\n",
                   touch_bank, touch_bank/4, touch_bank%4, touch_idx, va);
        } else {
            if (va == 0) {
                warnx("touch: specify --touch-bank or --touch-va");
                return 2;
            }
            printf("\nTouch using explicit VA=0x%016" PRIx64 "\n", va);

            // Attempt to decode this VA (if it resolves to a PA).
            uint64_t pa_tmp = 0;
            struct hit tmp;
            memset(&tmp, 0, sizeof(tmp));
            if (va_to_pa(va, &pa_tmp) == 0 && decode_one_va_to_hit(va, pa_tmp, &tmp)) {
                print_hit(&tmp, "Touch entry: ");
                suggest_perf_for_hit(&tmp);
            } else {
                printf("Touch entry: (decode failed for this VA; will still touch if within allocation)\n");
            }
        }

        // Guard: VA must be inside our allocation.
        uint64_t base = (uint64_t)(uintptr_t)buf;
        uint64_t end  = base + bytes;
        if (va < base || va >= end) {
            warnx("touch: VA=0x%016" PRIx64 " not within allocation [%p, %p). Refusing to touch.",
                  va, buf, (void *)(uintptr_t)end);
            return 1;
        }
        if (touch_scan && touch_bank >= 0) {
            const struct hit *th = &banks[touch_bank].v[touch_idx];
            touch_scan_uncore_imcs_and_banks(th, touch_iters, touch_cpu);
        } else {
            if (touch_scan && touch_bank >= 0) {
            const struct hit *th = &banks[touch_bank].v[touch_idx];
            touch_scan_uncore_imcs_and_banks(th, touch_iters, touch_cpu);
        } else {
            touch_one_va(va, touch_iters);
        }
        }
    }

    if (dump_dir) {
        dump_bank_files(dump_dir, banks);
    }

    if (bs_dir) {
        write_blacksmith_outputs(bs_dir, banks, bs_per_bank, bs_pairs);
    }

    if (do_validate) {
        if (validate_bank < 0) validate_bank = best;
        timing_validate_bank(banks, validate_bank, validate_iters, validate_pairs);
    }

    return 0;
}

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/types.h>

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096ULL
#endif

/* ---------------- util ---------------- */

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

#define GENMASK_ULL(h, l) (((~0ULL) - (1ULL << (l)) + 1ULL) & (~0ULL >> (63 - (h))))
#define GET_BITFIELD(v, lo, hi) (((v) & GENMASK_ULL((hi), (lo))) >> (lo))

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

/* ---------------- sysfs PCI config reads ---------------- */

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

/* ---------------- discovery ---------------- */

typedef struct {
    char devdir[512];   /* /sys/bus/pci/devices/0000:bb:dd.f */
    char bdf[64];       /* 0000:bb:dd.f */
    uint16_t vendor;
    uint16_t device;
    uint32_t class_u32; /* 0x00bbsspp */
    uint8_t bus;
    uint8_t dev;
    uint8_t fn;
} pci_node_t;

static bool parse_bdf(const char *bdf, uint8_t *bus, uint8_t *dev, uint8_t *fn)
{
    /* expects "0000:bb:dd.f" */
    unsigned dom=0, b=0, d=0, f=0;
    if (sscanf(bdf, "%x:%x:%x.%x", &dom, &b, &d, &f) != 4) return false;
    *bus = (uint8_t)b;
    *dev = (uint8_t)d;
    *fn  = (uint8_t)f;
    return true;
}

static size_t enumerate_pci(pci_node_t **out)
{
    DIR *dir = opendir("/sys/bus/pci/devices");
    if (!dir) die("opendir(/sys/bus/pci/devices) failed: %s", strerror(errno));

    size_t cap = 256, n = 0;
    pci_node_t *arr = calloc(cap, sizeof(*arr));
    if (!arr) die("oom");

    struct dirent *de;
    while ((de = readdir(dir)) != NULL) {
        if (de->d_name[0] == '.') continue;

        char devdir[512];
        snprintf(devdir, sizeof(devdir), "/sys/bus/pci/devices/%s", de->d_name);

        uint32_t vend = 0, dev = 0, classv = 0;
        char path_vendor[512], path_device[512], path_class[512];
        snprintf(path_vendor, sizeof(path_vendor), "%s/vendor", devdir);
        snprintf(path_device, sizeof(path_device), "%s/device", devdir);
        snprintf(path_class,  sizeof(path_class),  "%s/class",  devdir);

        if (!read_file_u32_hex(path_vendor, &vend)) continue;
        if (!read_file_u32_hex(path_device, &dev)) continue;
        if (!read_file_u32_hex(path_class, &classv)) continue;

        if (n == cap) {
            cap *= 2;
            arr = realloc(arr, cap * sizeof(*arr));
            if (!arr) die("oom");
        }

        pci_node_t *p = &arr[n++];
        snprintf(p->devdir, sizeof(p->devdir), "%s", devdir);
        snprintf(p->bdf, sizeof(p->bdf), "%s", de->d_name);
        p->vendor = (uint16_t)vend;
        p->device = (uint16_t)dev;
        p->class_u32 = classv;

        uint8_t b=0,dv=0,f=0;
        if (parse_bdf(p->bdf, &b, &dv, &f)) {
            p->bus = b; p->dev = dv; p->fn = f;
        }
    }
    closedir(dir);

    *out = arr;
    return n;
}

/* ---------------- SKX structures mirroring skx_edac ---------------- */

#define NUM_IMC      2
#define NUM_CHANNELS 3
#define NUM_DIMMS    2

#define MASK26 0x3FFFFFFULL
#define MASK29 0x1FFFFFFFULL

typedef struct {
    uint8_t close_pg;
    uint8_t bank_xor_enable;
    uint8_t fine_grain_bank;
    uint8_t rowbits;
    uint8_t colbits;
} skx_dimm_t;

typedef struct {
    char cdev_dir[512]; /* channel PCI func dir */
    skx_dimm_t dimms[NUM_DIMMS];
} skx_channel_t;

typedef struct {
    uint8_t mc;   /* system-wide mc index */
    uint8_t lmc;  /* socket-local mc */
    uint8_t src_id, node_id;
    skx_channel_t chan[NUM_CHANNELS];
} skx_imc_t;

typedef struct {
    uint8_t busmap[4];      /* from 0x2016 @ 0xCC */
    char sad_all_dir[512];  /* did 0x2054 */
    char util_all_dir[512]; /* did 0x2055 */
    uint32_t mcroute;       /* from did 0x208e @ 0xB4 (one per core, pick non-zero & consistent) */

    skx_imc_t imc[NUM_IMC];
} skx_socket_t;

typedef struct {
    skx_socket_t *dev;
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
} decoded_addr_t;

/* ---------------- helpers matching skx_edac register macros ---------------- */

/* Hi/Lo memory limits (tolm/tohm) from did 0x2034 regs 0xD0/0xD4/0xD8 */
static uint64_t skx_tolm = 0, skx_tohm = 0;

static bool skx_get_hi_lo(const pci_node_t *nodes, size_t nnodes)
{
    const pci_node_t *p = NULL;
    for (size_t i = 0; i < nnodes; i++) {
        if (nodes[i].vendor == 0x8086 && nodes[i].device == 0x2034) { p = &nodes[i]; break; }
    }
    if (!p) { warnx("can't find PCI 8086:2034 for tolm/tohm"); return false; }

    uint32_t r = 0;
    if (!read_pci_cfg_u32(p->devdir, 0xD0, &r)) return false;
    skx_tolm = r;

    if (!read_pci_cfg_u32(p->devdir, 0xD4, &r)) return false;
    skx_tohm = r;

    if (!read_pci_cfg_u32(p->devdir, 0xD8, &r)) return false;
    skx_tohm |= ((uint64_t)r << 32);

    return true;
}

/* DIMM regs are on channel device:
 *   amap at 0x8C
 *   mtr  at 0x80 + 4*dimm
 *   mtmtr at 0x87c (ECC check, optional)
 */
#define IS_DIMM_PRESENT(mtr) GET_BITFIELD((mtr), 15, 15)
static int get_dimm_attr(uint32_t reg, int lobit, int hibit, int add, int minv, int maxv)
{
    uint32_t val = (uint32_t)GET_BITFIELD(reg, lobit, hibit);
    if ((int)val < minv || (int)val > maxv) return -1;
    return (int)val + add;
}
static int numrank(uint32_t mtr) { return get_dimm_attr(mtr, 12, 13, 0, 1, 2); }
static int numrow (uint32_t mtr) { return get_dimm_attr(mtr,  2,  4, 12, 1, 6); }
static int numcol (uint32_t mtr) { return get_dimm_attr(mtr,  0,  1, 10, 0, 2); }

static bool fill_dimm_geometry(const char *chan_devdir, skx_dimm_t dimms[NUM_DIMMS])
{
    uint32_t amap = 0;
    if (!read_pci_cfg_u32(chan_devdir, 0x8C, &amap)) return false;

    for (int j = 0; j < NUM_DIMMS; j++) {
        uint32_t mtr = 0;
        if (!read_pci_cfg_u32(chan_devdir, 0x80 + 4u*(uint32_t)j, &mtr)) return false;

        if (!IS_DIMM_PRESENT(mtr)) {
            memset(&dimms[j], 0, sizeof(dimms[j]));
            continue;
        }

        int ranks = numrank(mtr);
        int rows  = numrow(mtr);
        int cols  = numcol(mtr);
        if (ranks < 0 || rows < 0 || cols < 0) {
            warnx("bad dimm geometry mtr=%#x", mtr);
            return false;
        }

        dimms[j].close_pg        = (uint8_t)GET_BITFIELD(mtr, 0, 0);
        dimms[j].bank_xor_enable = (uint8_t)GET_BITFIELD(mtr, 9, 9);
        dimms[j].fine_grain_bank = (uint8_t)GET_BITFIELD(amap, 0, 0);
        dimms[j].rowbits         = (uint8_t)rows;
        dimms[j].colbits         = (uint8_t)cols;
    }
    return true;
}

/* ---------------- socket discovery (like get_all_bus_mappings + get_all_munits) ---------------- */

static size_t build_sockets(const pci_node_t *nodes, size_t nnodes, skx_socket_t **out)
{
    /* Find all 0x2016 devices (per socket) and build bus maps */
    skx_socket_t *socks = NULL;
    size_t ns = 0, cap = 4;

    socks = calloc(cap, sizeof(*socks));
    if (!socks) die("oom");

    for (size_t i = 0; i < nnodes; i++) {
        if (!(nodes[i].vendor == 0x8086 && nodes[i].device == 0x2016)) continue;

        uint32_t reg = 0;
        if (!read_pci_cfg_u32(nodes[i].devdir, 0xCC, &reg)) continue;

        if (ns == cap) {
            cap *= 2;
            socks = realloc(socks, cap * sizeof(*socks));
            if (!socks) die("oom");
        }

        skx_socket_t *d = &socks[ns++];
        memset(d, 0, sizeof(*d));
        d->busmap[0] = (uint8_t)GET_BITFIELD(reg, 0, 7);
        d->busmap[1] = (uint8_t)GET_BITFIELD(reg, 8, 15);
        d->busmap[2] = (uint8_t)GET_BITFIELD(reg, 16, 23);
        d->busmap[3] = (uint8_t)GET_BITFIELD(reg, 24, 31);
    }

    if (ns == 0) {
        free(socks);
        *out = NULL;
        return 0;
    }

    /* Attach SAD_ALL (0x2054) and UTIL_ALL (0x2055) per socket, matched by busidx=1 in skx_edac */
    for (size_t i = 0; i < nnodes; i++) {
        if (nodes[i].vendor != 0x8086) continue;
        if (!(nodes[i].device == 0x2054 || nodes[i].device == 0x2055 || nodes[i].device == 0x208e)) continue;

        for (size_t s = 0; s < ns; s++) {
            /* busidx=1 means compare against busmap[1] */
            if (nodes[i].bus != socks[s].busmap[1]) continue;

            if (nodes[i].device == 0x2054) {
                snprintf(socks[s].sad_all_dir, sizeof(socks[s].sad_all_dir), "%s", nodes[i].devdir);
            } else if (nodes[i].device == 0x2055) {
                snprintf(socks[s].util_all_dir, sizeof(socks[s].util_all_dir), "%s", nodes[i].devdir);
            } else if (nodes[i].device == 0x208e) {
                /* many exist; read 0xB4 and keep first non-zero, ensure consistency */
                uint32_t r = 0;
                if (read_pci_cfg_u32(nodes[i].devdir, 0xB4, &r) && r != 0) {
                    if (socks[s].mcroute == 0) socks[s].mcroute = r;
                    else if (socks[s].mcroute != r) {
                        warnx("mcroute mismatch on socket%zu (%#x vs %#x)", s, socks[s].mcroute, r);
                    }
                }
            }
        }
    }

    /* Attach channel devices per socket (busidx=2 in skx_edac) */
    for (size_t i = 0; i < nnodes; i++) {
        if (nodes[i].vendor != 0x8086) continue;
        if (!(nodes[i].device == 0x2040 || nodes[i].device == 0x2044 || nodes[i].device == 0x2048)) continue;

        for (size_t s = 0; s < ns; s++) {
            if (nodes[i].bus != socks[s].busmap[2]) continue;

            /* skx_edac mapping by devfn:
               CHAN0: (10,0)->imc0, (12,0)->imc1
               CHAN1: (10,4)->imc0, (12,4)->imc1
               CHAN2: (11,0)->imc0, (13,0)->imc1
             */
            int which_imc = -1;
            int which_chan = -1;

            if (nodes[i].device == 0x2040) { /* CHAN0 */
                which_chan = 0;
                if (nodes[i].dev == 10 && nodes[i].fn == 0) which_imc = 0;
                if (nodes[i].dev == 12 && nodes[i].fn == 0) which_imc = 1;
            } else if (nodes[i].device == 0x2044) { /* CHAN1 */
                which_chan = 1;
                if (nodes[i].dev == 10 && nodes[i].fn == 4) which_imc = 0;
                if (nodes[i].dev == 12 && nodes[i].fn == 4) which_imc = 1;
            } else if (nodes[i].device == 0x2048) { /* CHAN2 */
                which_chan = 2;
                if (nodes[i].dev == 11 && nodes[i].fn == 0) which_imc = 0;
                if (nodes[i].dev == 13 && nodes[i].fn == 0) which_imc = 1;
            }

            if (which_imc >= 0 && which_chan >= 0) {
                snprintf(socks[s].imc[which_imc].chan[which_chan].cdev_dir,
                         sizeof(socks[s].imc[which_imc].chan[which_chan].cdev_dir),
                         "%s", nodes[i].devdir);
            }
        }
    }

    /* Fill src_id/node_id + dimm geometry */
    for (size_t s = 0; s < ns; s++) {
        if (socks[s].util_all_dir[0] == '\0') continue;

        uint32_t reg = 0;
        if (read_pci_cfg_u32(socks[s].util_all_dir, 0xF0, &reg)) {
            uint8_t src_id = (uint8_t)GET_BITFIELD(reg, 12, 14);
            for (int imc = 0; imc < NUM_IMC; imc++) socks[s].imc[imc].src_id = src_id;
        }
        if (read_pci_cfg_u32(socks[s].util_all_dir, 0xF4, &reg)) {
            uint8_t node_id = (uint8_t)GET_BITFIELD(reg, 0, 2);
            for (int imc = 0; imc < NUM_IMC; imc++) socks[s].imc[imc].node_id = node_id;
        }

        for (int imc = 0; imc < NUM_IMC; imc++) {
            socks[s].imc[imc].lmc = (uint8_t)imc;
            for (int ch = 0; ch < NUM_CHANNELS; ch++) {
                const char *cdir = socks[s].imc[imc].chan[ch].cdev_dir;
                if (cdir[0] == '\0') continue;
                if (!fill_dimm_geometry(cdir, socks[s].imc[imc].chan[ch].dimms)) {
                    warnx("failed to read dimm geometry for socket%zu imc%d ch%d", s, imc, ch);
                }
            }
        }
    }

    *out = socks;
    return ns;
}

/* ---------------- decode: SAD ---------------- */

#define SKX_MAX_SAD 24
#define SKX_GET_SAD(d, i, reg) read_pci_cfg_u32((d)->sad_all_dir, 0x60 + 8u*(uint32_t)(i), &(reg))
#define SKX_GET_ILV(d, i, reg) read_pci_cfg_u32((d)->sad_all_dir, 0x64 + 8u*(uint32_t)(i), &(reg))

#define SKX_SAD_MOD3MODE(sad)  GET_BITFIELD((sad), 30, 31)
#define SKX_SAD_MOD3(sad)      GET_BITFIELD((sad), 27, 27)
#define SKX_SAD_LIMIT(sad)     ((((uint64_t)GET_BITFIELD((sad), 7, 26)) << 26) | MASK26)
#define SKX_SAD_MOD3ASMOD2(sad) GET_BITFIELD((sad), 5, 6)
#define SKX_SAD_INTERLEAVE(sad) GET_BITFIELD((sad), 1, 2)
#define SKX_SAD_ENABLE(sad)    GET_BITFIELD((sad), 0, 0)

#define SKX_ILV_REMOTE(tgt)    (((tgt) & 8) == 0)
#define SKX_ILV_TARGET(tgt)    ((tgt) & 7)

static bool skx_sad_decode(decoded_addr_t *res, skx_socket_t *socks, size_t nsocks)
{
    /* Start with socket0, but may restart on remote target (like skx_edac). */
    skx_socket_t *d = &socks[0];
    uint64_t addr = res->addr;
    int remote = 0;

    if (addr >= skx_tohm || (addr >= skx_tolm && addr < (1ULL << 32))) {
        warnx("address %#" PRIx64 " out of range (tolm=%#" PRIx64 " tohm=%#" PRIx64 ")", addr, skx_tolm, skx_tohm);
        return false;
    }

restart:
    if (d->sad_all_dir[0] == '\0') { warnx("missing sad_all_dir"); return false; }
    if (d->mcroute == 0) { warnx("missing mcroute (did 0x208e route reg)"); return false; }

    uint64_t prev_limit = 0;
    for (int i = 0; i < SKX_MAX_SAD; i++) {
        uint32_t sad = 0;
        if (!SKX_GET_SAD(d, i, sad)) continue;

        uint64_t limit = SKX_SAD_LIMIT(sad);
        if (SKX_SAD_ENABLE(sad)) {
            if (addr >= prev_limit && addr <= limit) {
                uint32_t ilv = 0;
                if (!SKX_GET_ILV(d, i, ilv)) return false;

                int idx = 0;
                switch (SKX_SAD_INTERLEAVE(sad)) {
                    case 0: idx = (int)GET_BITFIELD(addr, 6, 8); break;
                    case 1: idx = (int)GET_BITFIELD(addr, 8, 10); break;
                    case 2: idx = (int)GET_BITFIELD(addr, 12, 14); break;
                    case 3: idx = (int)GET_BITFIELD(addr, 30, 32); break;
                    default: return false;
                }

                int tgt = (int)GET_BITFIELD(ilv, 4*idx, 4*idx + 3);

                if (SKX_ILV_REMOTE(tgt)) {
                    if (remote) { warnx("double remote"); return false; }
                    remote = 1;
                    int want = SKX_ILV_TARGET(tgt);
                    for (size_t s = 0; s < nsocks; s++) {
                        if (socks[s].imc[0].src_id == (uint8_t)want) { d = &socks[s]; goto restart; }
                    }
                    warnx("can't find node for remote tgt=%d", want);
                    return false;
                }

                int lchan = 0;
                if (SKX_SAD_MOD3(sad) == 0) {
                    lchan = SKX_ILV_TARGET(tgt);
                } else {
                    int shift = 0;
                    switch (SKX_SAD_MOD3MODE(sad)) {
                        case 0: shift = 6; break;
                        case 1: shift = 8; break;
                        case 2: shift = 12; break;
                        default: warnx("illegal mod3mode"); return false;
                    }
                    switch (SKX_SAD_MOD3ASMOD2(sad)) {
                        case 0: lchan = (int)((addr >> shift) % 3); break;
                        case 1: lchan = (int)((addr >> shift) % 2); break;
                        case 2: lchan = (int)((addr >> shift) % 2); lchan = (lchan << 1) | (~lchan & 1); break;
                        case 3: lchan = (int)(((addr >> shift) % 2) << 1); break;
                        default: return false;
                    }
                    lchan = (lchan << 1) | (SKX_ILV_TARGET(tgt) & 1);
                }

                res->dev = d;
                res->socket = d->imc[0].src_id;
                res->imc = (int)GET_BITFIELD(d->mcroute, lchan * 3, lchan * 3 + 2);
                res->channel = (int)GET_BITFIELD(d->mcroute, lchan * 2 + 18, lchan * 2 + 19);
                return true;
            }
        }
        prev_limit = limit + 1;
    }

    warnx("no SAD entry for %#" PRIx64, addr);
    return false;
}

/* ---------------- decode: TAD ---------------- */

#define SKX_MAX_TAD 8
#define SKX_GET_TADBASE(d, mc, i, reg) read_pci_cfg_u32((d)->imc[(mc)].chan[0].cdev_dir, 0x850 + 4u*(uint32_t)(i), &(reg))
#define SKX_GET_TADWAYNESS(d, mc, i, reg) read_pci_cfg_u32((d)->imc[(mc)].chan[0].cdev_dir, 0x880 + 4u*(uint32_t)(i), &(reg))
#define SKX_GET_TADCHNILVOFFSET(d, mc, ch, i, reg) read_pci_cfg_u32((d)->imc[(mc)].chan[(ch)].cdev_dir, 0x90 + 4u*(uint32_t)(i), &(reg))

#define SKX_TAD_BASE(b)       (((uint64_t)GET_BITFIELD((b), 12, 31)) << 26)
#define SKX_TAD_SKT_GRAN(b)   GET_BITFIELD((b), 4, 5)
#define SKX_TAD_CHN_GRAN(b)   GET_BITFIELD((b), 6, 7)
#define SKX_TAD_LIMIT(b)      ((((uint64_t)GET_BITFIELD((b), 12, 31)) << 26) | MASK26)
#define SKX_TAD_OFFSET(b)     (((uint64_t)GET_BITFIELD((b), 4, 23)) << 26)
#define SKX_TAD_SKTWAYS(b)    (1 << GET_BITFIELD((b), 10, 11))
#define SKX_TAD_CHNWAYS(b)    (GET_BITFIELD((b), 8, 9) + 1)

static int skx_granularity[] = { 6, 8, 12, 30 };

static uint64_t skx_do_interleave(uint64_t addr, int shift, int ways, uint64_t lowbits)
{
    addr >>= shift;
    addr /= (uint64_t)ways;
    addr <<= shift;
    return addr | (lowbits & ((1ULL << shift) - 1ULL));
}

static bool skx_tad_decode(decoded_addr_t *res)
{
    skx_socket_t *d = res->dev;
    int mc = res->imc;

    for (int i = 0; i < SKX_MAX_TAD; i++) {
        uint32_t base = 0, wayness = 0;
        if (!SKX_GET_TADBASE(d, mc, i, base)) continue;
        if (!SKX_GET_TADWAYNESS(d, mc, i, wayness)) continue;

        if (SKX_TAD_BASE(base) <= res->addr && res->addr <= SKX_TAD_LIMIT(wayness)) {
            res->sktways = (int)SKX_TAD_SKTWAYS(wayness);
            res->chanways = (int)SKX_TAD_CHNWAYS(wayness);

            int skt_interleave_bit = skx_granularity[SKX_TAD_SKT_GRAN(base)];
            int chn_interleave_bit = skx_granularity[SKX_TAD_CHN_GRAN(base)];

            uint32_t chnilvoffset = 0;
            if (!SKX_GET_TADCHNILVOFFSET(d, mc, res->channel, i, chnilvoffset)) return false;

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

    warnx("no TAD entry for %#" PRIx64, res->addr);
    return false;
}

/* ---------------- decode: RIR (rank) ---------------- */

#define SKX_MAX_RIR 4
#define SKX_GET_RIRWAYNESS(d, mc, ch, i, reg) read_pci_cfg_u32((d)->imc[(mc)].chan[(ch)].cdev_dir, 0x108 + 4u*(uint32_t)(i), &(reg))
#define SKX_GET_RIRILV(d, mc, ch, idx, i, reg) read_pci_cfg_u32((d)->imc[(mc)].chan[(ch)].cdev_dir, 0x120 + 16u*(uint32_t)(idx) + 4u*(uint32_t)(i), &(reg))

#define SKX_RIR_VALID(b)      GET_BITFIELD((b), 31, 31)
#define SKX_RIR_LIMIT(b)      ((((uint64_t)GET_BITFIELD((b), 1, 11)) << 29) | MASK29)
#define SKX_RIR_WAYS(b)       (1 << GET_BITFIELD((b), 28, 29))
#define SKX_RIR_CHAN_RANK(b)  GET_BITFIELD((b), 16, 19)
#define SKX_RIR_OFFSET(b)     (((uint64_t)GET_BITFIELD((b), 2, 15)) << 26)

static bool skx_rir_decode(decoded_addr_t *res)
{
    skx_socket_t *d = res->dev;
    skx_dimm_t *dimm0 = &d->imc[res->imc].chan[res->channel].dimms[0];

    int shift = dimm0->close_pg ? 6 : 13;

    uint64_t prev_limit = 0;
    for (int i = 0; i < SKX_MAX_RIR; i++) {
        uint32_t rirway = 0;
        if (!SKX_GET_RIRWAYNESS(d, res->imc, res->channel, i, rirway)) continue;

        uint64_t limit = SKX_RIR_LIMIT(rirway);
        if (SKX_RIR_VALID(rirway)) {
            if (prev_limit <= res->chan_addr && res->chan_addr <= limit) {
                uint64_t rank_addr = res->chan_addr >> shift;
                rank_addr /= (uint64_t)SKX_RIR_WAYS(rirway);
                rank_addr <<= shift;
                rank_addr |= (res->chan_addr & GENMASK_ULL(shift - 1, 0));
                res->rank_address = rank_addr;

                int idx = (int)((res->chan_addr >> shift) % SKX_RIR_WAYS(rirway));
                uint32_t rirlv = 0;
                if (!SKX_GET_RIRILV(d, res->imc, res->channel, idx, i, rirlv)) return false;

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

    warnx("no RIR entry for %#" PRIx64, res->addr);
    return false;
}

/* ---------------- decode: MAD (row/col/bank/bg) ---------------- */

/* bit tables copied from skx_edac */
static uint8_t skx_close_row[]    = { 15, 16, 17, 18, 20, 21, 22, 28, 10, 11, 12, 13, 29, 30, 31, 32, 33 };
static uint8_t skx_close_column[] = {  3,  4,  5, 14, 19, 23, 24, 25, 26, 27 };

static uint8_t skx_open_row[]     = { 14, 15, 16, 20, 28, 21, 22, 23, 24, 25, 26, 27, 29, 30, 31, 32, 33 };
static uint8_t skx_open_column[]  = {  3,  4,  5,  6,  7,  8,  9, 10, 11, 12 };
static uint8_t skx_open_fine_column[] = { 3, 4, 5, 7, 8, 9, 10, 11, 12, 13 };

static int skx_bits(uint64_t addr, int nbits, uint8_t *bits)
{
    int res = 0;
    for (int i = 0; i < nbits; i++) {
        res |= (int)(((addr >> bits[i]) & 1ULL) << i);
    }
    return res;
}

static int skx_bank_bits(uint64_t addr, int b0, int b1, int do_xor, int x0, int x1)
{
    int ret = (int)GET_BITFIELD(addr, b0, b0) | ((int)GET_BITFIELD(addr, b1, b1) << 1);
    if (do_xor) {
        ret ^= (int)GET_BITFIELD(addr, x0, x0) | ((int)GET_BITFIELD(addr, x1, x1) << 1);
    }
    return ret;
}

static bool skx_mad_decode(decoded_addr_t *r)
{
    skx_socket_t *d = r->dev;
    skx_dimm_t *dimm = &d->imc[r->imc].chan[r->channel].dimms[r->dimm];

    int bg0 = dimm->fine_grain_bank ? 6 : 13;

    if (dimm->close_pg) {
        r->row = skx_bits(r->rank_address, dimm->rowbits, skx_close_row);
        r->column = skx_bits(r->rank_address, dimm->colbits, skx_close_column);
        r->column |= 0x400; /* C10 autoprecharge always set */
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

    r->row &= (1u << dimm->rowbits) - 1u;
    return true;
}

static bool skx_decode(decoded_addr_t *res, skx_socket_t *socks, size_t nsocks)
{
    return skx_sad_decode(res, socks, nsocks) &&
           skx_tad_decode(res) &&
           skx_rir_decode(res) &&
           skx_mad_decode(res);
}

/* ---------------- main ---------------- */

static void usage(const char *argv0)
{
    fprintf(stderr,
        "usage:\n"
        "  %s --va <hex_va>\n"
        "  %s --pa <hex_pa>\n"
        "\n"
        "notes:\n"
        "  - run as root (sudo) so /sys/bus/pci/devices/.../config is readable\n"
        "  - --va uses /proc/self/pagemap to translate VA->PA\n",
        argv0, argv0);
    exit(1);
}

int main(int argc, char **argv)
{
    uint64_t addr_pa = 0;
    bool have_pa = false;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--va") && i + 1 < argc) {
            uint64_t va = parse_u64(argv[++i]);
            if (!va_to_pa(va, &addr_pa)) die("VA->PA failed for va=%#" PRIx64 " (try sudo / check pagemap perms)", va);
            have_pa = true;
        } else if (!strcmp(argv[i], "--pa") && i + 1 < argc) {
            addr_pa = parse_u64(argv[++i]);
            have_pa = true;
        } else {
            usage(argv[0]);
        }
    }
    if (!have_pa) usage(argv[0]);

    pci_node_t *nodes = NULL;
    size_t nnodes = enumerate_pci(&nodes);
    if (nnodes == 0) die("no pci nodes enumerated?");

    if (!skx_get_hi_lo(nodes, nnodes)) {
        die("failed to read tolm/tohm (are you on SKX and running as root?)");
    }

    skx_socket_t *socks = NULL;
    size_t nsocks = build_sockets(nodes, nnodes, &socks);
    if (nsocks == 0) die("no SKX sockets found (missing 8086:2016?)");

    decoded_addr_t res;
    memset(&res, 0, sizeof(res));
    res.addr = addr_pa;

    if (!skx_decode(&res, socks, nsocks)) {
        die("decode failed for pa=%#" PRIx64 " (did not match tables / missing PCI funcs)", addr_pa);
    }

    printf("PA=%#" PRIx64 "\n", addr_pa);
    printf("socket(src_id)=%d  imc=%d  channel=%d\n", res.socket, res.imc, res.channel);
    printf("chan_addr=%#" PRIx64 "  rank_addr=%#" PRIx64 "\n", res.chan_addr, res.rank_address);
    printf("dimm=%d  rank=%d  chan_rank=%d\n", res.dimm, res.rank, res.channel_rank);
    printf("bg=%d  bank=%d  row=%d  col=%d\n", res.bank_group, res.bank_address, res.row, res.column);

    free(nodes);
    free(socks);
    return 0;
}

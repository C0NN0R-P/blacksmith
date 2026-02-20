#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/perf_event.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/ioctl.h>
#include <time.h>

/* ---- bit helpers ---- */

#define BIT_ULL(n) (1ULL << (n))

static inline uint32_t get_bitfield_u32(uint64_t v, int lo, int hi)
{
    /* inclusive [lo..hi] */
    return (uint32_t)((v >> lo) & ((1ULL << (hi - lo + 1)) - 1ULL));
}

#define GET_BITFIELD(v, lo, hi) get_bitfield_u32((uint64_t)(v), (lo), (hi))

/* ---- rng ---- */

static inline uint64_t xorshift64star(uint64_t *state)
{
    uint64_t x = *state;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    *state = x;
    return x * 2685821657736338717ULL;
}

/* ---- VA -> PA (pagemap) ---- */

static size_t g_pagesz;

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

/* ---- PCI config via sysfs ---- */

typedef struct {
    char bdf[32];     /* 0000:3a:0a.0 */
    uint16_t vendor;
    uint16_t device;
    int fd_cfg;       /* /sys/bus/pci/devices/<bdf>/config */
} PciDev;

static int read_hex16_file(const char *path, uint16_t *out)
{
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    unsigned x = 0;
    int rc = fscanf(f, "0x%x", &x);
    fclose(f);
    if (rc != 1) return -2;
    *out = (uint16_t)x;
    return 0;
}

static int pci_open_cfg(PciDev *d)
{
    char path[256];
    snprintf(path, sizeof(path), "/sys/bus/pci/devices/%s/config", d->bdf);
    d->fd_cfg = open(path, O_RDONLY);
    return d->fd_cfg;
}

static int pci_read_u32(PciDev *d, off_t off, uint32_t *out)
{
    uint32_t v = 0;
    ssize_t n = pread(d->fd_cfg, &v, sizeof(v), off);
    if (n != (ssize_t)sizeof(v)) return -1;
    *out = v;
    return 0;
}

static bool parse_bdf(const char *bdf, uint16_t *seg, uint8_t *bus, uint8_t *dev, uint8_t *fn)
{
    unsigned s, b, d, f;
    if (sscanf(bdf, "%x:%x:%x.%x", &s, &b, &d, &f) != 4) return false;
    *seg = (uint16_t)s;
    *bus = (uint8_t)b;
    *dev = (uint8_t)d;
    *fn  = (uint8_t)f;
    return true;
}

static int load_all_pci(PciDev **out, size_t *out_n)
{
    DIR *dir = opendir("/sys/bus/pci/devices");
    if (!dir) return -1;

    size_t cap = 256, n = 0;
    PciDev *arr = calloc(cap, sizeof(PciDev));
    if (!arr) { closedir(dir); return -2; }

    struct dirent *de;
    while ((de = readdir(dir))) {
        if (de->d_name[0] == '.') continue;
        if (strlen(de->d_name) < 12) continue;

        if (n == cap) {
            cap *= 2;
            PciDev *tmp = realloc(arr, cap * sizeof(PciDev));
            if (!tmp) { free(arr); closedir(dir); return -3; }
            arr = tmp;
        }

        PciDev *d = &arr[n];
        snprintf(d->bdf, sizeof(d->bdf), "%s", de->d_name);

        char vpath[256], dpath[256];
        snprintf(vpath, sizeof(vpath), "/sys/bus/pci/devices/%s/vendor", d->bdf);
        snprintf(dpath, sizeof(dpath), "/sys/bus/pci/devices/%s/device", d->bdf);

        if (read_hex16_file(vpath, &d->vendor) != 0) continue;
        if (read_hex16_file(dpath, &d->device) != 0) continue;

        d->fd_cfg = -1;
        n++;
    }

    closedir(dir);
    *out = arr;
    *out_n = n;
    return 0;
}

static void close_all_pci(PciDev *arr, size_t n)
{
    for (size_t i = 0; i < n; i++)
        if (arr[i].fd_cfg >= 0) close(arr[i].fd_cfg);
    free(arr);
}

static PciDev *find_dev(PciDev *all, size_t n, uint8_t bus, uint8_t dev, uint8_t fn, uint16_t did)
{
    for (size_t i = 0; i < n; i++) {
        if (all[i].vendor != 0x8086) continue;
        if (all[i].device != did) continue;
        uint16_t seg; uint8_t b, d, f;
        if (!parse_bdf(all[i].bdf, &seg, &b, &d, &f)) continue;
        if (b == bus && d == dev && f == fn) return &all[i];
    }
    return NULL;
}

/* ---- minimal SKX model ---- */

#define MASK26 0x3FFFFFFu
#define MASK29 0x1FFFFFFFu

#define SKX_MAX_SAD 24
#define SKX_MAX_TAD 8
#define SKX_MAX_RIR 4

typedef struct {
    bool close_pg;
    bool bank_xor_enable;
    bool fine_grain_bank;
    int rowbits;
    int colbits;
} SkxDimm;

typedef struct {
    PciDev *cdev; /* 0x2040/0x2044/0x2048 */
    SkxDimm dimms[2];
} SkxChan;

typedef struct {
    SkxChan chan[3];
} SkxImc;

typedef struct {
    int socket;      /* 0 or 1 */
    uint8_t bus;     /* 0x3a or 0xae */
    PciDev *sad_all; /* 0x2054 at <bus>:1d.0 */
    SkxImc imc[2];   /* IMC0: 0a/0b, IMC1: 0c/0d */
} SkxSocket;

/* ---- decoded address ---- */

typedef struct {
    uint64_t addr;
    int socket;
    int imc;
    int channel;
    uint64_t chan_addr;
    int sktways;
    int chanways;
    int dimm;
    int cs;
    int rank;
    int channel_rank;
    uint64_t rank_address;
    int row;
    int column;
    int bank_address;
    int bank_group;
} DecodedAddr;

/* ---- register access macros from skx_base.c ---- */

#define SKX_GET_SAD(s, i, reg) \
    pci_read_u32((s)->sad_all, 0x60 + 8 * (i), &(reg))

#define SKX_GET_ILV(s, i, reg) \
    pci_read_u32((s)->sad_all, 0x64 + 8 * (i), &(reg))

#define SKX_GET_TADBASE(s, mc, i, reg) \
    pci_read_u32((s)->imc[(mc)].chan[0].cdev, 0x850 + 4 * (i), &(reg))

#define SKX_GET_TADWAYNESS(s, mc, i, reg) \
    pci_read_u32((s)->imc[(mc)].chan[0].cdev, 0x880 + 4 * (i), &(reg))

#define SKX_GET_TADCHNILVOFFSET(s, mc, ch, i, reg) \
    pci_read_u32((s)->imc[(mc)].chan[(ch)].cdev, 0x90 + 4 * (i), &(reg))

#define SKX_GET_RIRWAYNESS(s, mc, ch, i, reg) \
    pci_read_u32((s)->imc[(mc)].chan[(ch)].cdev, 0x108 + 4 * (i), &(reg))

#define SKX_GET_RIRILV(s, mc, ch, idx, i, reg) \
    pci_read_u32((s)->imc[(mc)].chan[(ch)].cdev, 0x120 + 16 * (idx) + 4 * (i), &(reg))

#define SKX_SAD_MOD3MODE(sad)      GET_BITFIELD((sad), 30, 31)
#define SKX_SAD_MOD3(sad)          GET_BITFIELD((sad), 27, 27)
#define SKX_SAD_LIMIT(sad)         (((uint64_t)GET_BITFIELD((sad), 7, 26) << 26) | MASK26)
#define SKX_SAD_MOD3ASMOD2(sad)    GET_BITFIELD((sad), 5, 6)
#define SKX_SAD_INTERLEAVE(sad)    GET_BITFIELD((sad), 1, 2)
#define SKX_SAD_ENABLE(sad)        GET_BITFIELD((sad), 0, 0)

#define SKX_ILV_REMOTE(tgt)        (((tgt) & 8) == 0)
#define SKX_ILV_TARGET(tgt)        ((tgt) & 7)

#define SKX_TAD_BASE(b)            ((uint64_t)GET_BITFIELD((b), 12, 31) << 26)
#define SKX_TAD_LIMIT(b)           (((uint64_t)GET_BITFIELD((b), 12, 31) << 26) | MASK26)
#define SKX_TAD_OFFSET(b)          ((uint64_t)GET_BITFIELD((b), 4, 23) << 26)
#define SKX_TAD_SKTWAYS(b)         (1 << GET_BITFIELD((b), 10, 11))
#define SKX_TAD_CHNWAYS(b)         (GET_BITFIELD((b), 8, 9) + 1)

#define SKX_RIR_VALID(b)           GET_BITFIELD((b), 31, 31)
#define SKX_RIR_LIMIT(b)           (((uint64_t)GET_BITFIELD((b), 1, 11) << 29) | MASK29)
#define SKX_RIR_WAYS(b)            (1 << GET_BITFIELD((b), 28, 29))
#define SKX_RIR_CHAN_RANK(b)       GET_BITFIELD((b), 16, 19)
#define SKX_RIR_OFFSET(b)          ((uint64_t)(GET_BITFIELD((b), 2, 15) << 26))

/* ---- skx_base.c address bit tables/helpers (copied) ---- */

static const int skx_open_row[20] =
    { 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37 };
static const int skx_open_column[10] =
    { 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
static const int skx_open_fine_column[10] =
    { 6, 7, 8, 9, 10, 11, 12, 13, 16, 17 };

static const int skx_close_row[20] =
    { 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36 };
static const int skx_close_column[10] =
    { 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };

static inline uint32_t skx_bits(uint64_t v, int nbits, const int *map)
{
    uint32_t out = 0;
    for (int i = 0; i < nbits; i++)
        out |= ((v >> map[i]) & 1ULL) << i;
    return out;
}

static inline int skx_bank_bits(uint64_t v, int b0, int b1, bool xor_en, int x0, int x1)
{
    int r0 = (int)((v >> b0) & 1ULL);
    int r1 = (int)((v >> b1) & 1ULL);
    if (xor_en) {
        r0 ^= (int)((v >> x0) & 1ULL);
        r1 ^= (int)((v >> x1) & 1ULL);
    }
    return (r1 << 1) | r0;
}

/* ---- DIMM config extraction (from your skx_get_dimm_config/skx_get_dimm_info usage) ---- */

#define IS_DIMM_PRESENT(mtr) (GET_BITFIELD((mtr), 31, 31) == 1)

static int skx_init_dimms_for_socket(SkxSocket *s)
{
    /* mcmtr effective from channel 0 only */
    uint32_t mcmtr = 0;
    if (pci_read_u32(s->imc[0].chan[0].cdev, 0x87c, &mcmtr) != 0) return -1;

    for (int mc = 0; mc < 2; mc++) {
        for (int ch = 0; ch < 3; ch++) {
            uint32_t amap = 0;
            if (pci_read_u32(s->imc[mc].chan[ch].cdev, 0x8c, &amap) != 0) return -2;

            for (int d = 0; d < 2; d++) {
                uint32_t mtr = 0;
                if (pci_read_u32(s->imc[mc].chan[ch].cdev, 0x80 + 4 * d, &mtr) != 0) return -3;

                SkxDimm *dd = &s->imc[mc].chan[ch].dimms[d];
                /*if (!IS_DIMM_PRESENT(mtr)) {
                    memset(dd, 0, sizeof(*dd));
                    continue;
                }*/

                /* treat bit31 as advisory; geometry bits are what MAD needs */
                int rows = (int)GET_BITFIELD(mtr, 2, 4) + 12;
                int cols = (int)GET_BITFIELD(mtr, 0, 1) + 10;

                /* reject obvious garbage */
                if (rows < 12 || rows > 20 || cols < 10 || cols > 12) {
                     memset(dd, 0, sizeof(*dd));
                     continue;
                }

                /* this mirrors the bits used by skx_get_dimm_info() */
                int ranks = (int)GET_BITFIELD(mtr, 12, 13);
                //int rows  = (int)GET_BITFIELD(mtr,  2,  4) + 12;
                //int cols  = (int)GET_BITFIELD(mtr,  0,  1) + 10;

                dd->close_pg        = GET_BITFIELD(mcmtr, 0, 0);
                dd->bank_xor_enable = GET_BITFIELD(mcmtr, 9, 9);
                dd->fine_grain_bank = GET_BITFIELD(amap,  0, 0);
                dd->rowbits         = rows;
                dd->colbits         = cols;

                (void)ranks; /* ranks used in RIR stage */
            }
        }
    }
    return 0;
}

/* ---- SAD/TAD/RIR/MAD decode (ported from skx_base.c, but using sockets[]) ---- */

static uint64_t g_tolm = 0;
static uint64_t g_tohm = 0;

static int find_socket_by_target(SkxSocket socks[2], int tgt)
{
    /* kernel code compares src_id; here we treat tgt 0/1 as socket index */
    if (tgt == 0) return 0;
    if (tgt == 1) return 1;
    return -1;
}

static bool skx_sad_decode(SkxSocket socks[2], DecodedAddr *res)
{
    SkxSocket *s = &socks[0];
    uint64_t addr = res->addr;
    int i, idx, tgt, lchan, shift;
    uint32_t sad, ilv;
    uint64_t limit, prev_limit;
    int remote = 0;

    if (addr >= g_tohm || (addr >= g_tolm && addr < BIT_ULL(32)))
        return false;

restart:
    prev_limit = 0;
    for (i = 0; i < SKX_MAX_SAD; i++) {
        if (SKX_GET_SAD(s, i, sad) != 0) return false;
        limit = SKX_SAD_LIMIT(sad);
        if (SKX_SAD_ENABLE(sad)) {
            if (addr >= prev_limit && addr <= limit)
                goto sad_found;
        }
        prev_limit = limit + 1;
    }
    return false;

sad_found:
    if (SKX_GET_ILV(s, i, ilv) != 0) return false;

    switch (SKX_SAD_INTERLEAVE(sad)) {
    case 0: idx = GET_BITFIELD(addr,  6,  8); break;
    case 1: idx = GET_BITFIELD(addr,  8, 10); break;
    case 2: idx = GET_BITFIELD(addr, 12, 14); break;
    case 3: idx = GET_BITFIELD(addr, 30, 32); break;
    default: return false;
    }

    tgt = GET_BITFIELD(ilv, 4 * idx, 4 * idx + 3);

    if (SKX_ILV_REMOTE(tgt)) {
        if (remote) return false;
        remote = 1;
        int si = find_socket_by_target(socks, SKX_ILV_TARGET(tgt));
        if (si < 0) return false;
        s = &socks[si];
        goto restart;
    }

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
        case 0: lchan = (addr >> shift) % 3; break;
        case 1: lchan = (addr >> shift) % 2; break;
        case 2: lchan = (addr >> shift) % 2; lchan = (lchan << 1) | !lchan; break;
        case 3: lchan = ((addr >> shift) % 2) << 1; break;
        default: return false;
        }
        lchan = (lchan << 1) | (SKX_ILV_TARGET(tgt) & 1);
    }

    /* lchan is socket-local channel index (0..5) */
    res->socket  = s->socket;
    res->imc     = lchan / 3;
    res->channel = lchan % 3;

    return true;
}

static void dump_tad_regs(SkxSocket socks[2], int sock, int imc, int chan)
{
    SkxSocket *s = &socks[sock];

    fprintf(stderr, "TAD DUMP: sock=%d imc=%d chan=%d dev=%s\n",
            sock, imc, chan, s->imc[imc].chan[chan].cdev->bdf);

    for (int i = 0; i < SKX_MAX_TAD; i++) {
        uint32_t regb = 0, regw = 0, cho = 0;
        uint32_t b0 = 0, w0 = 0, o0 = 0;

        /* what we currently read */
        (void)SKX_GET_TADBASE(s, imc, i, regb);
        (void)SKX_GET_TADWAYNESS(s, imc, i, regw);
        (void)SKX_GET_TADCHNILVOFFSET(s, imc, chan, i, cho);

        /* also show raw reads directly from that channel dev for sanity */
        pci_read_u32(s->imc[imc].chan[chan].cdev, 0x850 + 4*i, &b0);
        pci_read_u32(s->imc[imc].chan[chan].cdev, 0x880 + 4*i, &w0);
        pci_read_u32(s->imc[imc].chan[chan].cdev, 0x90  + 4*i, &o0);

        fprintf(stderr,
                "  i=%d base=0x%08x way=0x%08x off=0x%08x | raw(base)=0x%08x raw(way)=0x%08x raw(off)=0x%08x\n",
                i, regb, regw, cho, b0, w0, o0);
    }
}


static bool skx_tad_decode(SkxSocket socks[2], DecodedAddr *r)
{
    SkxSocket *s = &socks[r->socket];
    uint64_t addr = r->addr;

    for (int i = 0; i < SKX_MAX_TAD; i++) {
        uint32_t base_reg = 0, lim_reg = 0, way_reg = 0, off_reg = 0;

        /* base/limit are 8-byte entries: base at +8*i, limit at +8*i+4 */
        if (pci_read_u32(s->imc[r->imc].chan[0].cdev, 0x850 + 8*i,     &base_reg) != 0) return false;
        if (pci_read_u32(s->imc[r->imc].chan[0].cdev, 0x850 + 8*i + 4, &lim_reg)  != 0) return false;

        if (pci_read_u32(s->imc[r->imc].chan[0].cdev, 0x880 + 4*i, &way_reg) != 0) return false;
        if (pci_read_u32(s->imc[r->imc].chan[r->channel].cdev, 0x90 + 4*i, &off_reg) != 0) return false;

        uint64_t base  = SKX_TAD_BASE(base_reg);
        uint64_t limit = SKX_TAD_LIMIT(lim_reg);

        if (addr < base || addr > limit) continue;

        r->sktways  = SKX_TAD_SKTWAYS(way_reg);
        r->chanways = SKX_TAD_CHNWAYS(way_reg);

        r->chan_addr = addr - base;
        r->chan_addr += SKX_TAD_OFFSET(off_reg);

        return true;
    }

    return false;
}

static void dump_rir_regs(SkxSocket socks[2], int sock, int imc, int chan)
{
    SkxSocket *s = &socks[sock];
    PciDev *dev = s->imc[imc].chan[chan].cdev;

    fprintf(stderr, "RIR DUMP: sock=%d imc=%d chan=%d dev=%s\n", sock, imc, chan, dev->bdf);

    for (int i = 0; i < SKX_MAX_RIR; i++) {
        uint32_t way = 0;
        pci_read_u32(dev, 0x108 + 4*i, &way);
        fprintf(stderr, "  way[%d]=0x%08x valid=%u ways=%u limit=0x%llx chan_rank=%u off=0x%llx\n",
                i,
                way,
                (unsigned)SKX_RIR_VALID(way),
                (unsigned)SKX_RIR_WAYS(way),
                (unsigned long long)SKX_RIR_LIMIT(way),
                (unsigned)SKX_RIR_CHAN_RANK(way),
                (unsigned long long)SKX_RIR_OFFSET(way));
    }

    /* ILV tables: dump first few dwords so we see structure */
    for (int idx = 0; idx < 8; idx++) {
        fprintf(stderr, "  ilv_idx=%d:", idx);
        for (int w = 0; w < 8; w++) {
            uint32_t ilv = 0;
            pci_read_u32(dev, 0x120 + 32*idx + 4*w, &ilv);
            fprintf(stderr, " %08x", ilv);
        }
        fprintf(stderr, "\n");
    }
}


static bool skx_rir_decode(SkxSocket socks[2], DecodedAddr *r)
{
    /* RIR = Rank Interleave Rules. This stage maps a channel address to a channel-rank
     * and produces a rank-relative address (rank_address) used by MAD decode. */
    dump_rir_regs(socks, r->socket, r->imc, r->channel);

    SkxSocket *s = &socks[r->socket];
    uint64_t addr = r->chan_addr;

    uint32_t way = 0;
    uint64_t prev_limit = 0;

    int rule = -1;

    fprintf(stderr, "RIR: begin sock=%d imc=%d chan=%d chan_addr=%#" PRIx64 "\n",
            r->socket, r->imc, r->channel, addr);

    for (int i = 0; i < SKX_MAX_RIR; i++) {
        int rc = SKX_GET_RIRWAYNESS(s, r->imc, r->channel, i, way);
        if (rc != 0) {
            fprintf(stderr, "RIR_FAIL: read RIRWAYNESS i=%d rc=%d\n", i, rc);
            return false;
        }

        fprintf(stderr, "RIR: wayness[%d]=0x%08x valid=%u ways=%u limit=0x%llx chan_rank=%u off=0x%llx prev_limit=0x%llx\n",
                i,
                way,
                (unsigned)SKX_RIR_VALID(way),
                (unsigned)SKX_RIR_WAYS(way),
                (unsigned long long)SKX_RIR_LIMIT(way),
                (unsigned)SKX_RIR_CHAN_RANK(way),
                (unsigned long long)SKX_RIR_OFFSET(way),
                (unsigned long long)prev_limit);

        if (!SKX_RIR_VALID(way)) {
            fprintf(stderr, "RIR: skip i=%d (invalid)\n", i);
            continue;
        }

        uint64_t limit = SKX_RIR_LIMIT(way);

        if (addr >= prev_limit && addr <= limit) {
            r->chanways = SKX_RIR_WAYS(way);
            rule = i;
            fprintf(stderr, "RIR: selected rule=%d (addr in [0x%llx..0x%llx]) chanways=%d\n",
                    rule,
                    (unsigned long long)prev_limit,
                    (unsigned long long)limit,
                    r->chanways);
            break;
        }

        fprintf(stderr, "RIR: addr not in range for i=%d (range [0x%llx..0x%llx])\n",
                i,
                (unsigned long long)prev_limit,
                (unsigned long long)limit);

        prev_limit = limit + 1;
    }

    if (rule < 0) {
        fprintf(stderr, "RIR_FAIL: no matching RIR rule for chan_addr=%#" PRIx64 "\n", addr);
        return false;
    }

    /* ways is power-of-two (1/2/4/8). idx uses bit 6 upward. */
    int idx = (int)((addr >> 6) & (uint64_t)(r->chanways - 1));
    fprintf(stderr, "RIR: rule=%d chanways=%d -> ilv_idx=%d (from (addr>>6)&(ways-1))\n",
            rule, r->chanways, idx);

    /* ILV table is 8 dwords per idx (32 bytes). scan all entries. */
    uint32_t ilv_base = 0x120 + 32U * (uint32_t)idx;

    for (int w = 0; w < 8; w++) {
        uint32_t ilv = 0;
        int rc = pci_read_u32(s->imc[r->imc].chan[r->channel].cdev,
                              ilv_base + 4U * (uint32_t)w, &ilv);
        if (rc != 0) {
            fprintf(stderr, "RIR_FAIL: read ILV idx=%d w=%d rc=%d reg=0x%x\n",
                    idx, w, rc, ilv_base + 4U * (uint32_t)w);
            return false;
        }

        fprintf(stderr, "RIR: ilv[idx=%d][w=%d] @0x%x = 0x%08x\n",
                idx, w, ilv_base + 4U * (uint32_t)w, ilv);

        if (ilv == 0) {
            fprintf(stderr, "RIR: skip ilv entry (zero)\n");
            continue;
        }

        r->channel_rank = (int)SKX_RIR_CHAN_RANK(ilv);
        r->rank_address = addr + SKX_RIR_OFFSET(ilv);

        r->dimm = (r->channel_rank >> 1) & 1;
        r->cs   = r->channel_rank & 1;
        r->rank = r->channel_rank;

        fprintf(stderr, "RIR: choose w=%d -> channel_rank=%d dimm=%d cs=%d rank=%d rank_address=%#" PRIx64 "\n",
                w, r->channel_rank, r->dimm, r->cs, r->rank, r->rank_address);

        return true;
    }

    fprintf(stderr, "RIR_FAIL: no non-zero ILV entry for idx=%d (chanways=%d)\n",
            idx, r->chanways);
    return false;
}




static bool skx_mad_decode(SkxSocket socks[2], DecodedAddr *r)
{
    SkxSocket *s = &socks[r->socket];
    SkxDimm *dimm = &s->imc[r->imc].chan[r->channel].dimms[r->dimm];
    int bg0 = dimm->fine_grain_bank ? 6 : 13;

    if (dimm->rowbits <= 0 || dimm->colbits <= 0) return false;

    if (dimm->close_pg) {
        r->row    = (int)skx_bits(r->rank_address, dimm->rowbits, skx_close_row);
        r->column = (int)skx_bits(r->rank_address, dimm->colbits, skx_close_column);
        r->column |= 0x400;
        r->bank_address = skx_bank_bits(r->rank_address, 8, 9, dimm->bank_xor_enable, 22, 28);
        r->bank_group   = skx_bank_bits(r->rank_address, 6, 7, dimm->bank_xor_enable, 20, 21);
    } else {
        r->row = (int)skx_bits(r->rank_address, dimm->rowbits, skx_open_row);
        if (dimm->fine_grain_bank)
            r->column = (int)skx_bits(r->rank_address, dimm->colbits, skx_open_fine_column);
        else
            r->column = (int)skx_bits(r->rank_address, dimm->colbits, skx_open_column);

        r->bank_address = skx_bank_bits(r->rank_address, 18, 19, dimm->bank_xor_enable, 22, 23);
        r->bank_group   = skx_bank_bits(r->rank_address, bg0, 17, dimm->bank_xor_enable, 20, 21);
    }

    r->row &= (1u << dimm->rowbits) - 1;
    return true;
}

static bool skx_decode(SkxSocket socks[2], DecodedAddr *r)
{
    if (!skx_sad_decode(socks, r)) {
        fprintf(stderr, "FAIL: SAD (PA=%#" PRIx64 ")\n", r->addr);
        return false;
    }

    if (!skx_tad_decode(socks, r)) {
        fprintf(stderr, "FAIL: TAD (PA=%#" PRIx64 " sock=%d imc=%d chan=%d)\n",
                r->addr, r->socket, r->imc, r->channel);
        return false;
    }

    if (!skx_rir_decode(socks, r)) {
        fprintf(stderr, "FAIL: RIR (PA=%#" PRIx64 " sock=%d imc=%d chan=%d chan_addr=%#" PRIx64 ")\n",
                r->addr, r->socket, r->imc, r->channel, r->chan_addr);
        return false;
    }

    if (!skx_mad_decode(socks, r)) {
        fprintf(stderr, "FAIL: MAD (PA=%#" PRIx64 " sock=%d imc=%d chan=%d dimm=%d)\n",
                r->addr, r->socket, r->imc, r->channel, r->dimm);
        return false;
    }

    return true;
}


/* ---- socket discovery (your observed SKX layout) ---- */

static int build_sockets(PciDev *all, size_t nall, SkxSocket socks[2])
{
    memset(socks, 0, 2 * sizeof(SkxSocket));

    socks[0].socket = 0; socks[0].bus = 0x3a;  /* IMC bus */
    socks[1].socket = 1; socks[1].bus = 0xae;  /* IMC bus */

    for (int si = 0; si < 2; si++) {
        uint8_t imc_bus = socks[si].bus;
        uint8_t sad_bus = (si == 0) ? 0x17 : 0x85;

        socks[si].sad_all = find_dev(all, nall, sad_bus, 0x1d, 0, 0x2054);
        if (!socks[si].sad_all) {
            fprintf(stderr, "missing SAD_ALL at %02x:1d.0 (8086:2054)\n", sad_bus);
            return -1;
        }

        /* IMC0 */
        socks[si].imc[0].chan[0].cdev = find_dev(all, nall, imc_bus, 0x0a, 0, 0x2040);
        socks[si].imc[0].chan[1].cdev = find_dev(all, nall, imc_bus, 0x0a, 4, 0x2044);
        socks[si].imc[0].chan[2].cdev = find_dev(all, nall, imc_bus, 0x0b, 0, 0x2048);

        /* IMC1 */
        socks[si].imc[1].chan[0].cdev = find_dev(all, nall, imc_bus, 0x0c, 0, 0x2040);
        socks[si].imc[1].chan[1].cdev = find_dev(all, nall, imc_bus, 0x0c, 4, 0x2044);
        socks[si].imc[1].chan[2].cdev = find_dev(all, nall, imc_bus, 0x0d, 0, 0x2048);

        for (int mc = 0; mc < 2; mc++) {
            for (int ch = 0; ch < 3; ch++) {
                if (!socks[si].imc[mc].chan[ch].cdev) {
                    fprintf(stderr, "missing channel dev: sock=%d imc_bus=%02x imc=%d ch=%d\n",
                            si, imc_bus, mc, ch);
                    return -2;
                }
            }
        }

        if (skx_init_dimms_for_socket(&socks[si]) != 0) {
            fprintf(stderr, "dimm init failed for socket %d\n", si);
            return -3;
        }
    }

    return 0;
}


/* ---- PMU validation: which uncore_imc_X increments most ---- */

static long perf_event_open_wrap(struct perf_event_attr *attr, pid_t pid, int cpu, int group_fd, unsigned long flags)
{
    return syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

static int read_u64_file(const char *path, uint64_t *out)
{
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    unsigned long long v = 0;
    if (fscanf(f, "%llu", &v) != 1) { fclose(f); return -2; }
    fclose(f);
    *out = (uint64_t)v;
    return 0;
}

static int parse_perf_event_config(const char *path, uint64_t *out_cfg)
{
    /* expects "event=0x..,umask=0x.." etc. */
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char buf[256];
    if (!fgets(buf, sizeof(buf), f)) { fclose(f); return -2; }
    fclose(f);

    uint64_t event = 0, umask = 0;
    char *e = strstr(buf, "event=");
    char *u = strstr(buf, "umask=");
    if (!e || !u) return -3;
    event = strtoull(e + 6, NULL, 0);
    umask = strtoull(u + 6, NULL, 0);

    *out_cfg = event | (umask << 8);
    return 0;
}

static int pmu_best_imc(void *va, int iters)
{
    /* best-effort. if perf blocks uncore, this returns -1. */
    const int MAX_IMC = 16;
    int fds[MAX_IMC];
    uint64_t start[MAX_IMC], end[MAX_IMC];
    int n = 0;

    for (int i = 0; i < MAX_IMC; i++) {
        char tpath[256], epath[256];
        snprintf(tpath, sizeof(tpath), "/sys/bus/event_source/devices/uncore_imc_%d/type", i);
        snprintf(epath, sizeof(epath), "/sys/bus/event_source/devices/uncore_imc_%d/events/cas_count_read", i);

        uint64_t type = 0, cfg = 0;
        if (read_u64_file(tpath, &type) != 0) break;
        if (parse_perf_event_config(epath, &cfg) != 0) break;

        struct perf_event_attr attr;
        memset(&attr, 0, sizeof(attr));
        attr.type = (uint32_t)type;
        attr.size = sizeof(attr);
        attr.config = cfg;
        attr.disabled = 1;
        attr.exclude_kernel = 0;
        attr.exclude_hv = 0;

        int fd = (int)perf_event_open_wrap(&attr, -1, 0 /* any cpu */, -1, 0);
        if (fd < 0) {
            return -1;
        }
        fds[n] = fd;
        n++;
    }

    for (int i = 0; i < n; i++) {
        ioctl(fds[i], PERF_EVENT_IOC_RESET, 0);
        ioctl(fds[i], PERF_EVENT_IOC_ENABLE, 0);
        start[i] = 0;
        read(fds[i], &start[i], sizeof(uint64_t));
    }

    volatile uint8_t *p = (volatile uint8_t *)va;
    for (int k = 0; k < iters; k++) {
        asm volatile("clflush (%0)" :: "r"(p) : "memory");
        asm volatile("mfence" ::: "memory");
        (void)*p;
    }

    for (int i = 0; i < n; i++) {
        ioctl(fds[i], PERF_EVENT_IOC_DISABLE, 0);
        end[i] = 0;
        read(fds[i], &end[i], sizeof(uint64_t));
        close(fds[i]);
    }

    int best = 0;
    uint64_t best_delta = 0;
    for (int i = 0; i < n; i++) {
        uint64_t delta = end[i] - start[i];
        if (delta > best_delta) {
            best_delta = delta;
            best = i;
        }
    }
    return best; /* uncore_imc_<best> */
}

/* ---- main ---- */

static void usage(const char *argv0)
{
    fprintf(stderr,
        "usage:\n"
        "  %s --va 0x<hex> [--pmu]\n"
        "  %s --pa 0x<hex>\n"
        "  %s --alloc-mb N --pick-page K [--pmu]\n"
        "  %s --alloc-mb N --n COUNT [--pmu]\n",
        argv0, argv0, argv0, argv0);
}

int main(int argc, char **argv)
{
    g_pagesz = (size_t)getpagesize();

    bool have_va = false, have_pa = false, do_pmu = false;
    uint64_t pa_in = 0;
    void *va_in = NULL;

    size_t alloc_mb = 0;
    size_t pick_page = 0;
    size_t want_n = 0;
    bool do_alloc = false;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--va") && i + 1 < argc) {
            uint64_t v = strtoull(argv[++i], NULL, 0);
            va_in = (void *)(uintptr_t)v;
            have_va = true;
        } else if (!strcmp(argv[i], "--pa") && i + 1 < argc) {
            pa_in = strtoull(argv[++i], NULL, 0);
            have_pa = true;
        } else if (!strcmp(argv[i], "--pmu")) {
            do_pmu = true;
        } else if (!strcmp(argv[i], "--alloc-mb") && i + 1 < argc) {
            alloc_mb = (size_t)strtoull(argv[++i], NULL, 10);
            do_alloc = true;
        } else if (!strcmp(argv[i], "--pick-page") && i + 1 < argc) {
            pick_page = (size_t)strtoull(argv[++i], NULL, 10);
            do_alloc = true;
        } else if (!strcmp(argv[i], "--n") && i + 1 < argc) {
            want_n = (size_t)strtoull(argv[++i], NULL, 10);
        } else {
            usage(argv[0]);
            return 1;
        }
    }

    PciDev *all = NULL;
    size_t nall = 0;
    if (load_all_pci(&all, &nall) != 0) {
        fprintf(stderr, "pci enumerate failed\n");
        return 1;
    }

    for (size_t i = 0; i < nall; i++) {
        if (all[i].vendor != 0x8086) continue;
        pci_open_cfg(&all[i]);
    }

    SkxSocket socks[2];
    if (build_sockets(all, nall, socks) != 0) {
        close_all_pci(all, nall);
        return 1;
    }

    /* tohm/tolm: keep conservative; avoid rejecting normal DRAM */
    g_tolm = 0;
    g_tohm = ~0ULL;

    if (want_n > 0) {
        if (!do_alloc || alloc_mb == 0) {
            fprintf(stderr, "--n requires --alloc-mb\n");
            close_all_pci(all, nall);
            return 1;
        }

        size_t bytes = alloc_mb * 1024ULL * 1024ULL;
        uint8_t *buf = mmap(NULL, bytes, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (buf == MAP_FAILED) {
            fprintf(stderr, "mmap failed: %s\n", strerror(errno));
            close_all_pci(all, nall);
            return 1;
        }

        size_t pages = bytes / g_pagesz;
        if (pages == 0) {
            fprintf(stderr, "alloc too small\n");
            munmap(buf, bytes);
            close_all_pci(all, nall);
            return 1;
        }

        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        uint64_t seed = ((uint64_t)ts.tv_sec << 32) ^ (uint64_t)ts.tv_nsec ^ (uint64_t)getpid();
        if (seed == 0) seed = 1;

        /* track unique cache lines by PA>>6 */
        uint64_t *seen = calloc(want_n, sizeof(uint64_t));
        if (!seen) {
            fprintf(stderr, "calloc failed\n");
            munmap(buf, bytes);
            close_all_pci(all, nall);
            return 1;
        }
        size_t seen_n = 0;

        size_t got = 0;
        size_t attempts = 0;
        size_t max_attempts = want_n * 500000ULL;
        if (max_attempts < 100000) max_attempts = 100000;

        while (got < want_n && attempts < max_attempts) {
            attempts++;

            size_t page = (size_t)(xorshift64star(&seed) % pages);
            size_t cl_off = (size_t)(xorshift64star(&seed) % (g_pagesz / 64)) * 64;
            uint8_t *va = buf + page * g_pagesz + cl_off;

            *(volatile uint8_t *)va = (uint8_t)(attempts & 0xff);

            uint64_t pa = 0;
            if (va_to_pa(va, &pa) != 0) continue;

            uint64_t key = pa >> 6;
            bool dup = false;
            for (size_t i = 0; i < seen_n; i++) {
                if (seen[i] == key) { dup = true; break; }
            }
            if (dup) continue;

            DecodedAddr r;
            memset(&r, 0, sizeof(r));
            r.addr = pa;

            if (!skx_decode(socks, &r)) continue;

            seen[seen_n++] = key;

            printf("VA=%p PA=%#" PRIx64 " -> sock=%d imc=%d chan=%d dimm=%d cs=%d rank=%d bg=%d bank=%d row=%d col=%d\n",
                   (void *)va, pa, r.socket, r.imc, r.channel, r.dimm, r.cs, r.rank,
                   r.bank_group, r.bank_address, r.row, r.column);

            if (do_pmu) {
                int best = pmu_best_imc(va, 50000);
                if (best >= 0) printf("PMU: uncore_imc_%d had max cas_count_read\n", best);
            }

            printf("\n");

            got++;
        }

        if (got < want_n) {
            fprintf(stderr, "only got %zu/%zu decodes (attempts=%zu)\n", got, want_n, attempts);
            free(seen);
            munmap(buf, bytes);
            close_all_pci(all, nall);
            return 2;
        }

        free(seen);
        munmap(buf, bytes);
        close_all_pci(all, nall);
        return 0;
    }

    if (do_alloc) {
        size_t bytes = alloc_mb * 1024ULL * 1024ULL;
        void *buf = mmap(NULL, bytes, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (buf == MAP_FAILED) {
            fprintf(stderr, "mmap failed: %s\n", strerror(errno));
            close_all_pci(all, nall);
            return 1;
        }

        volatile uint8_t *p = (volatile uint8_t *)buf;
        size_t max_pages = bytes / g_pagesz;
        if (pick_page >= max_pages) pick_page = 0;
        p[pick_page * g_pagesz] = 1;

        va_in = (void *)((uintptr_t)buf + pick_page * g_pagesz);
        have_va = true;
    }

    uint64_t pa = 0;
    if (have_pa) {
        pa = pa_in;
    } else if (have_va) {
        if (va_to_pa(va_in, &pa) != 0) {
            fprintf(stderr, "va->pa failed (need root? pagemap restrictions?)\n");
            close_all_pci(all, nall);
            return 1;
        }
    } else {
        usage(argv[0]);
        close_all_pci(all, nall);
        return 1;
    }

    DecodedAddr r;
    memset(&r, 0, sizeof(r));
    r.addr = pa;

    if (!skx_decode(socks, &r)) {
        fprintf(stderr, "decode failed for PA=%#" PRIx64 "\n", pa);
        close_all_pci(all, nall);
        return 2;
    }

    printf("PA=%#" PRIx64 " -> sock=%d imc=%d chan=%d dimm=%d cs=%d rank=%d bg=%d bank=%d row=%d col=%d\n",
           pa, r.socket, r.imc, r.channel, r.dimm, r.cs, r.rank,
           r.bank_group, r.bank_address, r.row, r.column);

    if (do_pmu && have_va) {
        int best = pmu_best_imc(va_in, 50000);
        if (best < 0) {
            printf("PMU: unavailable (perf_event_open failed)\n");
        } else {
            printf("PMU: uncore_imc_%d had max cas_count_read\n", best);
        }
    }

    close_all_pci(all, nall);
    return 0;
}

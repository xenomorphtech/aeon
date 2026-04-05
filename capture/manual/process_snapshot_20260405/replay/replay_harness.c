#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/ucontext.h>
#include <sys/uio.h>
#include <unistd.h>

#ifndef PR_SET_TAGGED_ADDR_CTRL
#define PR_SET_TAGGED_ADDR_CTRL 55
#endif

#ifndef PR_TAGGED_ADDR_ENABLE
#define PR_TAGGED_ADDR_ENABLE (1UL << 0)
#endif

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif

#ifndef __NR_process_vm_readv
#define __NR_process_vm_readv 270
#endif

struct ReplayRegs {
    uint64_t x[31];
    uint64_t sp;
    uint64_t pc;
};

extern void replay_jump(const struct ReplayRegs *regs);

enum RegionKind {
    REGION_FILE = 0,
    REGION_LIVE = 1,
};

struct ReplayRegion {
    enum RegionKind kind;
    uint64_t base;
    uint64_t size;
    int prot;
    int eager;
    int mapped;
    char path[512];
};

struct LiveSeed {
    uint64_t page_base;
};

static long g_page_size = 4096;
static char g_snapshot_dir[512];
static struct ReplayRegion *g_regions = NULL;
static size_t g_region_count = 0;
static pid_t g_live_pid = -1;
static int g_live_mem_fd = -1;

static const char *kKindFile = "file";
static const char *kKindLive = "live";

static const char *kind_name(enum RegionKind kind) {
    return kind == REGION_FILE ? kKindFile : kKindLive;
}

static void append_cstr(char **cursor, char *end, const char *s) {
    while (*s != '\0' && *cursor < end) {
        *(*cursor)++ = *s++;
    }
}

static void append_hex_u64(char **cursor, char *end, uint64_t value) {
    static const char digits[] = "0123456789abcdef";
    char buf[18];
    int idx = 0;

    buf[idx++] = '0';
    buf[idx++] = 'x';
    for (int shift = 60; shift >= 0; shift -= 4) {
        buf[idx++] = digits[(value >> shift) & 0xf];
    }
    append_cstr(cursor, end, buf);
}

static void append_dec_i32(char **cursor, char *end, int value) {
    char buf[32];
    int idx = sizeof(buf) - 1;
    unsigned int abs_value = value < 0 ? (unsigned int)(-value) : (unsigned int)value;

    buf[idx] = '\0';
    do {
        buf[--idx] = (char)('0' + (abs_value % 10U));
        abs_value /= 10U;
    } while (abs_value != 0U && idx > 0);
    if (value < 0 && idx > 0) {
        buf[--idx] = '-';
    }
    append_cstr(cursor, end, &buf[idx]);
}

static void log_signal_fault(int signo, int code, uint64_t fault_addr, const ucontext_t *uc) {
    char buf[1024];
    char *cursor = buf;
    char *end = buf + sizeof(buf) - 1;

    append_cstr(&cursor, end, "fault signo=");
    append_dec_i32(&cursor, end, signo);
    append_cstr(&cursor, end, " code=");
    append_dec_i32(&cursor, end, code);
    append_cstr(&cursor, end, " addr=");
    append_hex_u64(&cursor, end, fault_addr);
    append_cstr(&cursor, end, " pc=");
    append_hex_u64(&cursor, end, uc->uc_mcontext.pc);
    append_cstr(&cursor, end, " sp=");
    append_hex_u64(&cursor, end, uc->uc_mcontext.sp);
    append_cstr(&cursor, end, " x0=");
    append_hex_u64(&cursor, end, uc->uc_mcontext.regs[0]);
    append_cstr(&cursor, end, " x1=");
    append_hex_u64(&cursor, end, uc->uc_mcontext.regs[1]);
    append_cstr(&cursor, end, " x19=");
    append_hex_u64(&cursor, end, uc->uc_mcontext.regs[19]);
    append_cstr(&cursor, end, " x21=");
    append_hex_u64(&cursor, end, uc->uc_mcontext.regs[21]);
    append_cstr(&cursor, end, " x30=");
    append_hex_u64(&cursor, end, uc->uc_mcontext.regs[30]);
    *cursor++ = '\n';
    *cursor = '\0';

    (void)!write(STDERR_FILENO, buf, (size_t)(cursor - buf));
}

static int perms_to_prot(const char *perms) {
    int prot = 0;

    if (perms[0] == 'r') {
        prot |= PROT_READ;
    }
    if (perms[1] == 'w') {
        prot |= PROT_WRITE;
    }
    if (perms[2] == 'x') {
        prot |= PROT_EXEC;
    }
    return prot;
}

static const struct ReplayRegion *find_region(uint64_t addr) {
    for (size_t i = 0; i < g_region_count; ++i) {
        const struct ReplayRegion *region = &g_regions[i];
        if (addr >= region->base && addr < region->base + region->size) {
            return region;
        }
    }
    return NULL;
}

static struct ReplayRegion *find_region_mut(uint64_t addr) {
    for (size_t i = 0; i < g_region_count; ++i) {
        struct ReplayRegion *region = &g_regions[i];
        if (addr >= region->base && addr < region->base + region->size) {
            return region;
        }
    }
    return NULL;
}

static int read_regions(const char *regions_path) {
    FILE *fp = fopen(regions_path, "r");
    char line[1024];
    size_t cap = 0;

    if (fp == NULL) {
        fprintf(stderr, "failed to open regions file %s: %s\n", regions_path, strerror(errno));
        return -1;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        char kind_buf[32];
        char base_buf[32];
        char size_buf[32];
        char perms_buf[8];
        char eager_buf[8];
        char path_buf[512];
        struct ReplayRegion *region = NULL;
        unsigned long long base = 0;
        unsigned long long size = 0;
        int eager = 0;
        int fields = 0;

        if (line[0] == '#' || line[0] == '\n') {
            continue;
        }

        fields = sscanf(
            line,
            "%31s %31s %31s %7s %7s %511s",
            kind_buf,
            base_buf,
            size_buf,
            perms_buf,
            eager_buf,
            path_buf
        );
        if (fields != 6) {
            fprintf(stderr, "malformed regions line: %s\n", line);
            fclose(fp);
            return -1;
        }

        errno = 0;
        base = strtoull(base_buf, NULL, 0);
        size = strtoull(size_buf, NULL, 0);
        eager = (int)strtol(eager_buf, NULL, 0);
        if (errno != 0) {
            fprintf(stderr, "failed to parse numeric fields in: %s\n", line);
            fclose(fp);
            return -1;
        }

        if (g_region_count == cap) {
            size_t new_cap = cap == 0 ? 16 : cap * 2;
            void *new_regions = realloc(g_regions, new_cap * sizeof(*g_regions));
            if (new_regions == NULL) {
                fprintf(stderr, "realloc failed for %zu regions\n", new_cap);
                fclose(fp);
                return -1;
            }
            g_regions = new_regions;
            cap = new_cap;
        }

        region = &g_regions[g_region_count++];
        memset(region, 0, sizeof(*region));
        region->kind = strcmp(kind_buf, kKindLive) == 0 ? REGION_LIVE : REGION_FILE;
        region->base = (uint64_t)base;
        region->size = (uint64_t)size;
        region->prot = perms_to_prot(perms_buf);
        region->eager = eager;
        region->mapped = 0;
        if (strcmp(path_buf, "-") != 0) {
            snprintf(region->path, sizeof(region->path), "%s", path_buf);
        }
    }

    fclose(fp);
    return 0;
}

static int join_path(char *out, size_t out_size, const char *dir, const char *rel) {
    int written = snprintf(out, out_size, "%s/%s", dir, rel);
    if (written < 0 || (size_t)written >= out_size) {
        return -1;
    }
    return 0;
}

static int map_file_region(struct ReplayRegion *region) {
    int fd = -1;
    char full_path[1024];
    uint8_t *dst = NULL;
    size_t remaining = (size_t)region->size;
    off_t offset = 0;
    void *mapped = MAP_FAILED;

    if (region->mapped) {
        return 0;
    }
    if (region->kind != REGION_FILE) {
        return -1;
    }
    if (region->path[0] == '\0') {
        fprintf(stderr, "region 0x%016" PRIx64 " missing file path\n", region->base);
        return -1;
    }
    if (join_path(full_path, sizeof(full_path), g_snapshot_dir, region->path) != 0) {
        fprintf(stderr, "snapshot path too long: %s + %s\n", g_snapshot_dir, region->path);
        return -1;
    }

    mapped = mmap(
        (void *)(uintptr_t)region->base,
        (size_t)region->size,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
        -1,
        0
    );
    if (mapped == MAP_FAILED) {
        fprintf(stderr,
                "mmap failed for %s region 0x%016" PRIx64 " len=0x%016" PRIx64 ": %s\n",
                full_path,
                region->base,
                region->size,
                strerror(errno));
        return -1;
    }

    fd = open(full_path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        fprintf(stderr, "open failed for %s: %s\n", full_path, strerror(errno));
        munmap(mapped, (size_t)region->size);
        return -1;
    }

    dst = (uint8_t *)(uintptr_t)region->base;
    while (remaining > 0) {
        ssize_t chunk = read(fd, dst + offset, remaining);
        if (chunk < 0) {
            if (errno == EINTR) {
                continue;
            }
            fprintf(stderr, "read failed for %s: %s\n", full_path, strerror(errno));
            close(fd);
            munmap(mapped, (size_t)region->size);
            return -1;
        }
        if (chunk == 0) {
            break;
        }
        remaining -= (size_t)chunk;
        offset += chunk;
    }

    close(fd);

    if (mprotect((void *)(uintptr_t)region->base, (size_t)region->size, region->prot) != 0) {
        fprintf(stderr,
                "mprotect failed for 0x%016" PRIx64 " len=0x%016" PRIx64 ": %s\n",
                region->base,
                region->size,
                strerror(errno));
        munmap(mapped, (size_t)region->size);
        return -1;
    }

    region->mapped = 1;
    fprintf(stderr,
            "mapped %-4s base=0x%016" PRIx64 " size=0x%016" PRIx64 " prot=%d path=%s\n",
            kind_name(region->kind),
            region->base,
            region->size,
            region->prot,
            region->path);
    return 0;
}

static ssize_t live_read_remote(void *dst, uint64_t remote_addr, size_t size) {
    struct iovec local_iov = { .iov_base = dst, .iov_len = size };
    struct iovec remote_iov = { .iov_base = (void *)(uintptr_t)remote_addr, .iov_len = size };
    ssize_t nread = -1;

    if (g_live_pid > 0) {
        errno = 0;
        nread = (ssize_t)syscall(
            __NR_process_vm_readv,
            g_live_pid,
            &local_iov,
            1,
            &remote_iov,
            1,
            0
        );
        if (nread == (ssize_t)size) {
            return nread;
        }
    }

    if (g_live_mem_fd >= 0) {
        nread = pread(g_live_mem_fd, dst, size, (off_t)remote_addr);
        if (nread == (ssize_t)size) {
            return nread;
        }
    }

    return nread;
}

static int map_live_page(const struct ReplayRegion *region, uint64_t fault_addr) {
    uint64_t page_base = fault_addr & ~((uint64_t)g_page_size - 1U);
    void *mapped = MAP_FAILED;
    ssize_t nread = -1;

    if (region == NULL || region->kind != REGION_LIVE) {
        return -1;
    }

    mapped = mmap(
        (void *)(uintptr_t)page_base,
        (size_t)g_page_size,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
        -1,
        0
    );
    if (mapped == MAP_FAILED) {
        if (errno == EEXIST) {
            return 0;
        }
        return -1;
    }

    nread = live_read_remote(mapped, page_base, (size_t)g_page_size);
    if (nread != (ssize_t)g_page_size) {
        munmap(mapped, (size_t)g_page_size);
        return -1;
    }

    if (mprotect(mapped, (size_t)g_page_size, region->prot) != 0) {
        munmap(mapped, (size_t)g_page_size);
        return -1;
    }

    return 0;
}

static void handle_fault(int signo, siginfo_t *info, void *ucontext_void) {
    ucontext_t *uc = (ucontext_t *)ucontext_void;
    uint64_t fault_addr = (uint64_t)(uintptr_t)info->si_addr;
    struct ReplayRegion *region = find_region_mut(fault_addr);

    if ((signo == SIGSEGV || signo == SIGBUS) && region != NULL && region->kind == REGION_LIVE) {
        if (map_live_page(region, fault_addr) == 0) {
            return;
        }
    }

    log_signal_fault(signo, info->si_code, fault_addr, uc);
    _exit(128 + signo);
}

static int install_signal_handlers(void) {
    stack_t ss;
    struct sigaction sa;
    void *alt = mmap(NULL, 1U << 20, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (alt == MAP_FAILED) {
        fprintf(stderr, "sigaltstack mmap failed: %s\n", strerror(errno));
        return -1;
    }

    memset(&ss, 0, sizeof(ss));
    ss.ss_sp = alt;
    ss.ss_size = 1U << 20;
    ss.ss_flags = 0;
    if (sigaltstack(&ss, NULL) != 0) {
        fprintf(stderr, "sigaltstack failed: %s\n", strerror(errno));
        return -1;
    }

    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = handle_fault;
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
    sigemptyset(&sa.sa_mask);

    if (sigaction(SIGSEGV, &sa, NULL) != 0 ||
        sigaction(SIGBUS, &sa, NULL) != 0 ||
        sigaction(SIGILL, &sa, NULL) != 0) {
        fprintf(stderr, "sigaction failed: %s\n", strerror(errno));
        return -1;
    }
    return 0;
}

static int open_live_mem_if_needed(pid_t live_pid) {
    char proc_path[128];

    if (live_pid <= 0) {
        return 0;
    }

    g_live_pid = live_pid;
    snprintf(proc_path, sizeof(proc_path), "/proc/%d/mem", (int)live_pid);
    g_live_mem_fd = open(proc_path, O_RDONLY | O_CLOEXEC);
    if (g_live_mem_fd < 0) {
        fprintf(stderr,
                "warning: open(%s) failed: %s; process_vm_readv fallback only\n",
                proc_path,
                strerror(errno));
    } else {
        fprintf(stderr, "opened live memory source %s\n", proc_path);
    }

    return 0;
}

static int seed_live_page(uint64_t page_base) {
    const struct ReplayRegion *region = find_region(page_base);
    if (region == NULL || region->kind != REGION_LIVE) {
        return -1;
    }
    return map_live_page(region, page_base);
}

#include "generated/replay_regs.h"

static int seed_live_pages(void) {
    for (size_t i = 0; i < kSeedLivePageCount; ++i) {
        if (seed_live_page(kSeedLivePages[i].page_base) == 0) {
            fprintf(stderr, "seeded live page 0x%016" PRIx64 "\n", kSeedLivePages[i].page_base);
        }
    }
    return 0;
}

int main(int argc, char **argv) {
    const char *snapshot_dir = NULL;
    const char *regions_path = NULL;
    pid_t live_pid = -1;

    if (argc < 3) {
        fprintf(stderr, "usage: %s <snapshot_dir> <regions_tsv> [live_pid]\n", argv[0]);
        return 2;
    }

    snapshot_dir = argv[1];
    regions_path = argv[2];
    if (argc >= 4) {
        live_pid = (pid_t)strtol(argv[3], NULL, 0);
    }

    g_page_size = sysconf(_SC_PAGESIZE);
    snprintf(g_snapshot_dir, sizeof(g_snapshot_dir), "%s", snapshot_dir);

    (void)prctl(PR_SET_TAGGED_ADDR_CTRL, PR_TAGGED_ADDR_ENABLE, 0, 0, 0);

    if (read_regions(regions_path) != 0) {
        return 1;
    }

    if (open_live_mem_if_needed(live_pid) != 0) {
        return 1;
    }

    for (size_t i = 0; i < g_region_count; ++i) {
        if (g_regions[i].kind == REGION_FILE && g_regions[i].eager) {
            if (map_file_region(&g_regions[i]) != 0) {
                return 1;
            }
        }
    }

    seed_live_pages();

    if (install_signal_handlers() != 0) {
        return 1;
    }

    fprintf(stderr,
            "jumping to pc=0x%016" PRIx64 " sp=0x%016" PRIx64 " with %zu regions live_pid=%d\n",
            kReplayRegs.pc,
            kReplayRegs.sp,
            g_region_count,
            (int)g_live_pid);

    replay_jump(&kReplayRegs);
    fprintf(stderr, "unexpected return from replay_jump\n");
    return 0;
}

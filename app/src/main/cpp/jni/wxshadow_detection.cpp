#include <jni.h>
#include <android/log.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <pthread.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <dirent.h>
#include <link.h>
#include <dlfcn.h>
#include <inttypes.h>
#include "utils/time_util.h"

#define LOG_TAG "WxShadowNative"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// ==================== 通用工具函数 ====================

static uint64_t read_minflt(void) {
    FILE *fp = fopen("/proc/self/stat", "r");
    if (!fp) return 0;
    uint64_t minflt = 0;
    // pid comm state ppid pgrp session tty_nr tpgid flags minflt cminflt majflt cmajflt
    fscanf(fp, "%*d %*s %*c %*d %*d %*d %*d %*d %*u %llu", (unsigned long long*)&minflt);
    fclose(fp);
    return minflt;
}

static inline uint64_t nanos(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

// ==================== 1. WXShadow: 自读代码页 Page Fault ====================

// 这段代码的关键：它读取自己所在的页
// 如果该页被 wxshadow shadow (--x)，读取会触发 page fault
__attribute__((noinline))
static void self_read_probe(void) {
    void *page = (void*)((uintptr_t)&self_read_probe & ~0xFFF);
    volatile uint32_t val = *(volatile uint32_t*)page;
    (void)val;
}

extern "C" JNIEXPORT jstring JNICALL
Java_qpdb_env_check_utils_WxShadowDetectionUtil_nativeCheckWxShadowPageFault(
        JNIEnv* env, jclass clazz) {
    uint64_t before = read_minflt();

    // 多次调用以放大信号
    for (int i = 0; i < 100; i++) {
        self_read_probe();
    }

    uint64_t after = read_minflt();
    uint64_t delta = after - before;

    char result[256];
    snprintf(result, sizeof(result), "delta=%lu|threshold=50", (unsigned long)delta);
    return env->NewStringUTF(result);
}

// ==================== 2. WXShadow: BRK 时延指纹 ====================

__attribute__((noinline))
static int target_canary(void) {
    return 0x12345678;
}

extern "C" JNIEXPORT jstring JNICALL
Java_qpdb_env_check_utils_WxShadowDetectionUtil_nativeCheckWxShadowTiming(
        JNIEnv* env, jclass clazz) {
    // 预热缓存
    for (int i = 0; i < 100; i++) target_canary();

    uint64_t start = nanos();
    for (int i = 0; i < 10000; i++) {
        target_canary();
    }
    uint64_t total = nanos() - start;
    uint64_t avg_ns = total / 10000;

    // 测量参考函数 getpid
    uint64_t start2 = nanos();
    for (int i = 0; i < 10000; i++) {
        syscall(__NR_getpid);
    }
    uint64_t total2 = nanos() - start2;
    uint64_t avg_ref = total2 / 10000;

    uint64_t ratio = avg_ns / (avg_ref + 1);

    char result[256];
    snprintf(result, sizeof(result),
             "avg_ns=%lu|avg_ref=%lu|ratio=%lu|threshold=10",
             (unsigned long)avg_ns, (unsigned long)avg_ref, (unsigned long)ratio);
    return env->NewStringUTF(result);
}

// ==================== 3. WXShadow: prctl 探测 ====================

extern "C" JNIEXPORT jstring JNICALL
Java_qpdb_env_check_utils_WxShadowDetectionUtil_nativeCheckPrctlProbe(
        JNIEnv* env, jclass clazz) {
    // wxshadow 使用 0x57580001 - 0x57580008
    // 如果模块未加载，非法选项返回 -1, errno=EINVAL
    // 如果模块已加载，返回模块内部错误码

    errno = 0;
    int ret = prctl(0x57580001, 0, 0, 0, 0);
    int saved_errno = errno;

    char result[256];
    snprintf(result, sizeof(result), "ret=%d|errno=%d", ret, saved_errno);
    return env->NewStringUTF(result);
}

// ==================== 3.5 WXShadow: prctl 高精度时间侧信道探测 ====================

#ifdef __aarch64__

static inline uint64_t read_cntvct_el0_wx(void) {
    uint64_t val;
    __asm__ __volatile__ ("isb; mrs %0, cntvct_el0; isb" : "=r" (val));
    return val;
}

#else

static inline uint64_t read_cntvct_el0_wx(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

#endif

static int compare_u64_wx(const void* a, const void* b) {
    uint64_t av = *(const uint64_t*)a;
    uint64_t bv = *(const uint64_t*)b;
    if (av < bv) return -1;
    if (av > bv) return 1;
    return 0;
}

static uint64_t median_prctl_time(int option, int samples) {
    uint64_t* times = (uint64_t*)malloc(samples * sizeof(uint64_t));
    if (!times) return 0;

    for (int i = 0; i < samples; i++) {
        uint64_t start = read_cntvct_el0_wx();
        prctl(option, 0, 0, 0, 0);
        uint64_t end = read_cntvct_el0_wx();
        times[i] = end - start;
    }

    qsort(times, samples, sizeof(uint64_t), compare_u64_wx);
    uint64_t median = times[samples / 2];
    free(times);
    return median;
}

extern "C" JNIEXPORT jstring JNICALL
Java_qpdb_env_check_utils_WxShadowDetectionUtil_nativeCheckPrctlTimingSideChannel(
        JNIEnv* env, jclass clazz) {
    const int NUM_SAMPLES = 2000;
    const int NUM_WX_OPTS = 8;
    const uint32_t WX_OPTS[NUM_WX_OPTS] = {
        0x57580001, 0x57580002, 0x57580003, 0x57580004,
        0x57580005, 0x57580006, 0x57580007, 0x57580008
    };
    const uint32_t BASELINE_OPT = 0xfacebeef;
    const double THRESHOLD_RATIO = 2.0;

    // 预热缓存
    for (int i = 0; i < 50; i++) {
        prctl(BASELINE_OPT, 0, 0, 0, 0);
        prctl(WX_OPTS[0], 0, 0, 0, 0);
    }

    // 测量 baseline（不存在的选项）
    uint64_t baseline = median_prctl_time((int)BASELINE_OPT, NUM_SAMPLES);

    // 测量每个 WXShadow 选项
    uint64_t wx_times[NUM_WX_OPTS];
    for (int i = 0; i < NUM_WX_OPTS; i++) {
        wx_times[i] = median_prctl_time((int)WX_OPTS[i], NUM_SAMPLES);
    }

    // 统计异常：WXShadow 选项耗时显著不同于 baseline
    int anomaly_count = 0;
    uint64_t max_wx = 0;
    uint64_t min_wx = UINT64_MAX;
    uint64_t sum_wx = 0;
    for (int i = 0; i < NUM_WX_OPTS; i++) {
        if (wx_times[i] > max_wx) max_wx = wx_times[i];
        if (wx_times[i] < min_wx) min_wx = wx_times[i];
        sum_wx += wx_times[i];

        double ratio = (baseline > 0) ? (double)wx_times[i] / (double)baseline : 0.0;
        if (ratio > THRESHOLD_RATIO || ratio < (1.0 / THRESHOLD_RATIO)) {
            anomaly_count++;
        }
    }
    uint64_t avg_wx = sum_wx / NUM_WX_OPTS;

    double max_ratio = (baseline > 0) ? (double)max_wx / (double)baseline : 0.0;

    char result[512];
    snprintf(result, sizeof(result),
             "baseline=%llu|wx_avg=%llu|wx_min=%llu|wx_max=%llu|max_ratio=%.2f|anomaly=%d|threshold=%.1f",
             (unsigned long long)baseline,
             (unsigned long long)avg_wx,
             (unsigned long long)min_wx,
             (unsigned long long)max_wx,
             max_ratio,
             anomaly_count,
             THRESHOLD_RATIO);
    return env->NewStringUTF(result);
}

// ==================== 4. Anti-Detect: faccessat vs openat 不一致性 ====================

extern "C" JNIEXPORT jstring JNICALL
Java_qpdb_env_check_utils_WxShadowDetectionUtil_nativeCheckSyscallInconsistency(
        JNIEnv* env, jclass clazz) {
    // 使用 faccessat (libc wrapper 可能被 hook)
    int ret1 = faccessat(AT_FDCWD, "/dev/goldfish_pipe", F_OK, 0);
    int err1 = errno;

    // 直接 syscall openat (可能未被 hook)
    int fd = syscall(__NR_openat, AT_FDCWD, "/dev/goldfish_pipe", O_RDONLY);
    int has_open = (fd >= 0);
    if (has_open) close(fd);

    int inconsistent = (ret1 == -1 && err1 == ENOENT && has_open);

    char result[256];
    snprintf(result, sizeof(result),
             "inconsistent=%d|faccessat_ret=%d|faccessat_errno=%d|openat_ok=%d",
             inconsistent, ret1, err1, has_open);
    return env->NewStringUTF(result);
}

// ==================== 6. Anti-Detect: Kallsyms 扫描 ====================

extern "C" JNIEXPORT jstring JNICALL
Java_qpdb_env_check_utils_WxShadowDetectionUtil_nativeCheckKallsyms(
        JNIEnv* env, jclass clazz) {
    FILE *fp = fopen("/proc/kallsyms", "r");
    if (!fp) {
        return env->NewStringUTF("error=cannot_open");
    }

    char line[512];
    int anti_detect = 0;
    int kp_hooks = 0;
    int kp_modules = 0;

    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "anti_detect") ||
            strstr(line, "before_stat_syscall") ||
            strstr(line, "after_getdents64") ||
            strstr(line, "supercall_guard")) {
            anti_detect++;
        }
        if (strstr(line, "hook_chain") ||
            strstr(line, "hook_wrap") ||
            strstr(line, "hook_syscalln")) {
            kp_hooks++;
        }
        if (strstr(line, "kpm_") || strstr(line, "kernelpatch")) {
            kp_modules++;
        }
    }
    fclose(fp);

    char result[256];
    snprintf(result, sizeof(result),
             "anti_detect=%d|kp_hooks=%d|kp_modules=%d",
             anti_detect, kp_hooks, kp_modules);
    return env->NewStringUTF(result);
}

// ==================== 7. Hide-Maps: dl_iterate_phdr vs /proc/self/maps ====================

#define MAX_LIBS 256

static uintptr_t linker_bases[MAX_LIBS];
static char linker_names[MAX_LIBS][256];
static int linker_count = 0;

static int collect_linker_cb(struct dl_phdr_info *info, size_t size, void *data) {
    (void)size;
    (void)data;
    if (info->dlpi_addr != 0 && linker_count < MAX_LIBS) {
        linker_bases[linker_count] = info->dlpi_addr;
        strncpy(linker_names[linker_count], info->dlpi_name, 255);
        linker_names[linker_count][255] = 0;
        linker_count++;
    }
    return 0;
}

extern "C" JNIEXPORT jstring JNICALL
Java_qpdb_env_check_utils_WxShadowDetectionUtil_nativeCheckHiddenMaps(
        JNIEnv* env, jclass clazz) {
    linker_count = 0;
    dl_iterate_phdr(collect_linker_cb, NULL);

    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) {
        return env->NewStringUTF("hidden=0|total=0|error=cannot_open");
    }

    char line[512];
    int hidden = 0;

    for (int i = 0; i < linker_count; i++) {
        int found = 0;
        fseek(fp, 0, SEEK_SET);
        while (fgets(line, sizeof(line), fp)) {
            uintptr_t start, end;
            if (sscanf(line, "%" PRIxPTR "-%" PRIxPTR, &start, &end) == 2) {
                if (start == linker_bases[i]) {
                    found = 1;
                    break;
                }
            }
        }
        if (!found) {
            hidden++;
        }
    }
    fclose(fp);

    char result[256];
    snprintf(result, sizeof(result),
             "hidden=%d|total=%d", hidden, linker_count);
    return env->NewStringUTF(result);
}

// ==================== 8. Hide-Maps: smaps vs maps 行数对比 ====================

extern "C" JNIEXPORT jstring JNICALL
Java_qpdb_env_check_utils_WxShadowDetectionUtil_nativeCheckSmapsVsMaps(
        JNIEnv* env, jclass clazz) {
    // 统计 /proc/self/maps 行数
    int maps_lines = 0;
    FILE *fp_maps = fopen("/proc/self/maps", "r");
    if (fp_maps) {
        char line[512];
        while (fgets(line, sizeof(line), fp_maps)) {
            maps_lines++;
        }
        fclose(fp_maps);
    }

    // 统计 /proc/self/smaps 的 VMA 段数（按空行分隔）
    int smaps_regions = 0;
    FILE *fp_smaps = fopen("/proc/self/smaps", "r");
    if (fp_smaps) {
        char line[512];
        int in_region = 0;
        while (fgets(line, sizeof(line), fp_smaps)) {
            // maps 行格式: address-perms offset dev inode pathname
            if (strchr(line, '-') && strchr(line, ' ')) {
                if (!in_region) {
                    smaps_regions++;
                    in_region = 1;
                }
            } else if (line[0] == '\n' || line[0] == 0) {
                in_region = 0;
            }
        }
        fclose(fp_smaps);
    }

    int diff = smaps_regions - maps_lines;

    char result[256];
    snprintf(result, sizeof(result),
             "maps_lines=%d|smaps_regions=%d|diff=%d",
             maps_lines, smaps_regions, diff);
    return env->NewStringUTF(result);
}

// ==================== 9. Hide-Maps: mincore 扫描 ====================

extern "C" JNIEXPORT jstring JNICALL
Java_qpdb_env_check_utils_WxShadowDetectionUtil_nativeCheckMincoreScan(
        JNIEnv* env, jclass clazz) {
    // 扫描典型库加载区域，查找有物理映射但在 maps 中未报告的页
    // 简化版本：扫描并统计有映射的页数
    unsigned char vec;
    int mapped_count = 0;

#ifdef __aarch64__
    // Android 64bit 典型库加载区域
    for (uint64_t addr = 0x7000000000ULL; addr < 0x8000000000ULL; addr += 4096) {
        if (mincore((void*)addr, 4096, &vec) == 0) {
            mapped_count++;
        }
    }
#else
    // 32位：扫描典型共享库加载区域
    for (uintptr_t addr = 0x70000000; addr < 0xC0000000; addr += 4096) {
        if (mincore((void*)addr, 4096, &vec) == 0) {
            mapped_count++;
        }
    }
#endif

    char result[256];
    snprintf(result, sizeof(result), "mapped_pages=%d", mapped_count);
    return env->NewStringUTF(result);
}

// ==================== 10. Hide-Maps: ELF Magic 扫描 ====================

extern "C" JNIEXPORT jstring JNICALL
Java_qpdb_env_check_utils_WxShadowDetectionUtil_nativeCheckElfMagic(
        JNIEnv* env, jclass clazz) {
    // 简化版本：使用 process_vm_readv 扫描 ELF magic
    // 注意：此功能需要 API 23+ 且可能受 SELinux 限制
    // 这里改用 /proc/self/maps 遍历 + mem 读取的方式

    int elf_count = 0;

    // 通过 dl_iterate_phdr 获取的基地址列表已经在上面的函数中收集
    // 这里我们只是简单报告 dl_iterate_phdr 发现的库数量
    // 更复杂的 ELF magic 扫描需要 root 或特殊权限

    linker_count = 0;
    dl_iterate_phdr(collect_linker_cb, NULL);

    // 尝试直接读取每个已知基地址的前 4 字节
    for (int i = 0; i < linker_count; i++) {
        unsigned char buf[4];
        int fd = open("/proc/self/mem", O_RDONLY);
        if (fd < 0) break;

        off_t offset = (off_t)linker_bases[i];
        if (lseek(fd, offset, SEEK_SET) == offset) {
            if (read(fd, buf, 4) == 4) {
                if (buf[0] == 0x7f && buf[1] == 'E' && buf[2] == 'L' && buf[3] == 'F') {
                    elf_count++;
                }
            }
        }
        close(fd);
    }

    char result[256];
    snprintf(result, sizeof(result),
             "elf_count=%d|total_libs=%d", elf_count, linker_count);
    return env->NewStringUTF(result);
}

// ==================== 11. /proc/modules 检测 KernelPatch ====================

extern "C" JNIEXPORT jstring JNICALL
Java_qpdb_env_check_utils_WxShadowDetectionUtil_nativeCheckProcModules(
        JNIEnv* env, jclass clazz) {
    FILE *fp = fopen("/proc/modules", "r");
    if (!fp) {
        return env->NewStringUTF("kernelpatch=0|error=cannot_open");
    }

    char line[256];
    int kp = 0;

    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "kernelpatch") || strstr(line, "kp_")) {
            kp++;
        }
    }
    fclose(fp);

    char result[256];
    snprintf(result, sizeof(result), "kernelpatch=%d", kp);
    return env->NewStringUTF(result);
}

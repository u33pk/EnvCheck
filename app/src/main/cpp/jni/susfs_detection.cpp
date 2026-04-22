#include <jni.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <sys/mman.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <time.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <android/log.h>
#include "utils/time_util.h"

// memfd_create 在 NDK 中可能不可用，使用 syscall 直接调用
#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif

#define LOG_TAG "SusfsNative"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// ================== prctl 返回值检测 ==================

/**
 * Layer 1: prctl(0xDEADBEEF) 返回值侧信道
 *
 * 原理：KSU 的 ksu_handle_prctl() 对 option == 0xDEADBEEF 有专门处理。
 * 普通 app 调用时，即使不是 root，也会进入 KSU handler 并返回 0；
 * 而无 KSU 的内核不认识 0xDEADBEEF，返回 EINVAL。
 *
 * @return 0=无KSU, 1=有KSU(SUSFS前提条件), -1=异常
 */
extern "C" JNIEXPORT jint JNICALL
Java_qpdb_env_check_utils_SusfsDetectionUtil_nativeCheckPrctlReturn(
        JNIEnv* env, jclass clazz) {
    // 清除 errno
    errno = 0;
    // prctl(0xDEADBEEF, CMD_SUSFS_ADD_SUS_PATH=0x55555, ...)
    int ret = prctl(0xDEADBEEF, 0x55555, NULL, NULL, NULL);
    if (ret == 0) {
        return 1; // KSU 存在
    } else if (errno == EINVAL) {
        return 0; // 无 KSU
    }
    return -1; // 异常
}

// ================== prctl 执行路径长度侧信道 ==================

/**
 * Layer 2: prctl 执行路径长度侧信道
 *
 * 原理：有 KSU 时，prctl(0xDEADBEEF) 需进入 ksu_handle_prctl() 执行多个分支判断；
 * 无 KSU 时直接返回 EINVAL。通过测量平均延迟区分。
 *
 * @param iterations 循环次数
 * @return 总耗时（纳秒）
 */
extern "C" JNIEXPORT jlong JNICALL
Java_qpdb_env_check_utils_SusfsDetectionUtil_nativeCheckPrctlTiming(
        JNIEnv* env, jclass clazz, jint iterations) {
    // 预热
    for (int i = 0; i < 50; i++) {
        prctl(0xDEADBEEF, 0x55555, NULL, NULL, NULL);
    }
    long start = get_time_ns();
    for (int i = 0; i < iterations; i++) {
        prctl(0xDEADBEEF, 0x55555, NULL, NULL, NULL);
    }
    long end = get_time_ns();
    return (jlong)(end - start);
}

// ================== faccessat kmalloc 侧信道 ==================

/**
 * Layer 2: faccessat 隐藏路径 kmalloc 侧信道
 *
 * 原理：susfs_sus_path_by_path() 对隐藏路径执行
 * kmalloc(PAGE_SIZE) + d_path() + list_for_each_entry_safe() + kfree()。
 * 对隐藏路径调用 faccessat 会触发额外的 slab 分配器开销。
 *
 * @param path 要检测的路径
 * @param iterations 循环次数
 * @return 总耗时（纳秒）
 */
extern "C" JNIEXPORT jlong JNICALL
Java_qpdb_env_check_utils_SusfsDetectionUtil_nativeCheckFaccessatTiming(
        JNIEnv* env, jclass clazz, jstring path, jint iterations) {
    const char* cpath = env->GetStringUTFChars(path, nullptr);
    if (!cpath) return -1;

    // 预热
    for (int i = 0; i < 100; i++) {
        syscall(__NR_faccessat, AT_FDCWD, cpath, F_OK, 0);
    }

    long start = get_time_ns();
    for (int i = 0; i < iterations; i++) {
        syscall(__NR_faccessat, AT_FDCWD, cpath, F_OK, 0);
    }
    long end = get_time_ns();

    env->ReleaseStringUTFChars(path, cpath);
    return (jlong)(end - start);
}

// ================== /proc/self/maps 读取时延侧信道 ==================

/**
 * Layer 2: /proc/self/maps 读取时延侧信道
 *
 * 原理：show_map_vma() 中调用 susfs_sus_maps()，
 * 需要 kmalloc(SUSFS_MAX_LEN_PATHNAME) + 遍历 LH_SUS_MAPS_SPOOFER。
 *
 * @param iterations 循环次数
 * @return 总耗时（纳秒）
 */
extern "C" JNIEXPORT jlong JNICALL
Java_qpdb_env_check_utils_SusfsDetectionUtil_nativeCheckMapsReadTiming(
        JNIEnv* env, jclass clazz, jint iterations) {
    char buf[4096];

    // 预热
    for (int i = 0; i < 20; i++) {
        int fd = open("/proc/self/maps", O_RDONLY | O_CLOEXEC);
        if (fd >= 0) {
            while (read(fd, buf, sizeof(buf)) > 0);
            close(fd);
        }
    }

    long start = get_time_ns();
    for (int i = 0; i < iterations; i++) {
        int fd = open("/proc/self/maps", O_RDONLY | O_CLOEXEC);
        if (fd >= 0) {
            while (read(fd, buf, sizeof(buf)) > 0);
            close(fd);
        }
    }
    long end = get_time_ns();
    return (jlong)(end - start);
}

// ================== linkat 错误码异常检测 ==================

/**
 * Layer 3: linkat 错误码异常检测
 *
 * 源码级漏洞：susfs_change_error_no_by_pathname() 对 /data/ 路径的 linkat 操作
 * 返回 ENOENT 而非 EEXIST。
 * 正常系统行为：对已存在的文件执行 linkat(newname) 应返回 EEXIST。
 * SUSFS 行为：返回 ENOENT。
 *
 * @return 0=正常(EEXIST), 1=SUSFS异常(ENOENT), -1=其他错误
 */
extern "C" JNIEXPORT jint JNICALL
Java_qpdb_env_check_utils_SusfsDetectionUtil_nativeCheckLinkatErrno(
        JNIEnv* env, jclass clazz, jstring testDir) {
    const char* dir = env->GetStringUTFChars(testDir, nullptr);
    if (!dir) return -1;

    char existing[512], newlink[512];
    snprintf(existing, sizeof(existing), "%s/.susfs_probe", dir);
    snprintf(newlink, sizeof(newlink), "%s/.susfs_probe_link", dir);

    // 创建测试文件
    int fd = open(existing, O_CREAT | O_RDWR | O_CLOEXEC, 0644);
    if (fd < 0) {
        env->ReleaseStringUTFChars(testDir, dir);
        return -1;
    }
    close(fd);

    // 尝试对已存在的文件创建硬链接
    errno = 0;
    int ret = linkat(AT_FDCWD, existing, AT_FDCWD, newlink, 0);
    int saved_errno = errno;

    // 清理
    unlink(existing);
    unlink(newlink);
    env->ReleaseStringUTFChars(testDir, dir);

    if (ret == -1) {
        if (saved_errno == ENOENT) {
            return 1; // SUSFS 错误码漏洞命中
        } else if (saved_errno == EEXIST) {
            return 0; // 正常行为
        }
        return -1; // 其他错误（如 EPERM）
    }
    return 0; // 成功创建（正常系统允许硬链接）
}

// ================== memfd_create EFAULT 异常检测 ==================

/**
 * Layer 3: memfd_create EFAULT 异常检测
 *
 * SUSFS 的 sus_memfd 功能对特定命名模式的 memfd 故意返回 EFAULT。
 * 正常系统：memfd_create 应返回有效 fd 或 EINVAL/ENOSYS。
 *
 * @return 0=正常, 1=SUSFS异常(EFAULT), -1=其他
 */
extern "C" JNIEXPORT jint JNICALL
Java_qpdb_env_check_utils_SusfsDetectionUtil_nativeCheckMemfdErrno(
        JNIEnv* env, jclass clazz) {
    // 测试多个可能触发 SUSFS sus_memfd 的命名模式
    const char* test_names[] = {
            "memfd:/jit-cache",
            "memfd:/jit-zygote-cache",
            "memfd:/dex-cache",
            NULL
    };

    for (int i = 0; test_names[i] != NULL; i++) {
        errno = 0;
        int fd = syscall(__NR_memfd_create, test_names[i], MFD_CLOEXEC);
        int saved_errno = errno;

        if (fd == -1 && saved_errno == EFAULT) {
            return 1; // SUSFS sus_memfd 命中
        }
        if (fd >= 0) {
            close(fd);
        }
    }
    return 0; // 正常
}

// ================== mnt_id 连续性异常检测 ==================

/**
 * Layer 3: mountinfo mnt_id 连续性异常检测
 *
 * 原理：mnt_id_reorder 功能会将 mount ID 重新编号为从第一个 mount ID 开始的
 * 严格连续整数（1, 2, 3...）。正常系统的 mount ID 是内核全局递增的，通常不连续。
 *
 * @return 0=正常(不连续), 1=SUSFS异常(严格连续), -1=读取失败
 */
extern "C" JNIEXPORT jint JNICALL
Java_qpdb_env_check_utils_SusfsDetectionUtil_nativeCheckMntIdReorder(
        JNIEnv* env, jclass clazz) {
    FILE* fp = fopen("/proc/self/mountinfo", "r");
    if (!fp) return -1;

    int prev_id = -1;
    int count = 0;
    int consecutive = 0;
    char line[512];

    while (fgets(line, sizeof(line), fp)) {
        int mnt_id;
        if (sscanf(line, "%d", &mnt_id) != 1) break;

        if (prev_id != -1) {
            if (mnt_id == prev_id + 1) {
                consecutive++;
            }
        }
        prev_id = mnt_id;
        count++;
        if (count >= 20) break; // 只检查前 20 条
    }
    fclose(fp);

    // 如果前 20 条 mount ID 全部严格连续，极可疑
    if (count >= 10 && consecutive >= 10) {
        return 1; // SUSFS mnt_id_reorder 嫌疑
    }
    return 0; // 正常
}

// ================== uname 与 /proc/version 不一致检测 ==================

/**
 * Layer 3: uname 与 /proc/version 不一致检测
 *
 * 原理：spoof_uname 功能伪造 uname 返回的内核版本号，
 * 但 /proc/version 通常不受影响。
 *
 * @return 0=一致, 1=不一致(spoof_uname), -1=读取失败
 */
extern "C" JNIEXPORT jint JNICALL
Java_qpdb_env_check_utils_SusfsDetectionUtil_nativeCheckUnameInconsistency(
        JNIEnv* env, jclass clazz) {
    struct utsname u;
    if (uname(&u) != 0) return -1;

    FILE* fp = fopen("/proc/version", "r");
    if (!fp) return -1;

    char version[512];
    if (!fgets(version, sizeof(version), fp)) {
        fclose(fp);
        return -1;
    }
    fclose(fp);

    // 检查 /proc/version 中是否包含 uname.release
    if (strstr(version, u.release) == NULL) {
        LOGI("uname.release=%s, /proc/version=%s", u.release, version);
        return 1; // 不一致，spoof_uname 嫌疑
    }
    return 0; // 一致
}

// ================== CNTVCT_EL0 高精度侧信道 ==================

#ifdef __aarch64__

static inline uint64_t read_cntvct_el0(void) {
    uint64_t val;
    __asm__ __volatile__ ("isb; mrs %0, cntvct_el0; isb" : "=r" (val));
    return val;
}

static int compare_u64(const void* a, const void* b) {
    uint64_t av = *(const uint64_t*)a;
    uint64_t bv = *(const uint64_t*)b;
    if (av < bv) return -1;
    if (av > bv) return 1;
    return 0;
}

/**
 * Layer 2: CNTVCT_EL0 高精度 prctl 侧信道
 *
 * 原理：KSU 的 ksu_handle_prctl() 在 syscall 入口处拦截所有 prctl 调用，
 * 检查 option == 0xDEADBEEF。
 *
 * 有 KSU 时：
 *   prctl(0xDEADBEEF) → hook 匹配 → KSU handler → 返回 0（较慢，因为进入 handler）
 *   prctl(0xDEADBEEA) → hook 检查 → 不匹配 → 正常 prctl → EINVAL（较快，只做比较）
 *
 * 无 KSU 时：
 *   两者都 → 正常 prctl → EINVAL（速度相同）
 *
 * 因此，有 KSU 时 DEADBEEF 应该比 DEADBEEA 慢（handler 开销）。
 * 无 KSU 时两者速度相同。
 *
 * @return 格式：deadbeef_median=xxx|deadbeea_median=xxx|anomaly=xxx
 */
extern "C" JNIEXPORT jstring JNICALL
Java_qpdb_env_check_utils_SusfsDetectionUtil_nativeCheckPrctlCntvct(
        JNIEnv* env, jclass clazz) {
    const int NUM_SAMPLES = 10000;
    uint64_t* beef_samples = (uint64_t*)malloc(NUM_SAMPLES * sizeof(uint64_t));
    uint64_t* beea_samples = (uint64_t*)malloc(NUM_SAMPLES * sizeof(uint64_t));
    if (!beef_samples || !beea_samples) {
        free(beef_samples);
        free(beea_samples);
        return env->NewStringUTF("alloc_failed");
    }

    // 预热缓存 - 交替调用两种 prctl
    for (int i = 0; i < 200; i++) {
        prctl(0xDEADBEEF, 0x55555, NULL, NULL, NULL);
        prctl(0xDEADBEEA, 0x55555, NULL, NULL, NULL);
    }

    // 收集 DEADBEEF 样本（KSU handler 路径）
    for (int i = 0; i < NUM_SAMPLES; i++) {
        uint64_t start = read_cntvct_el0();
        prctl(0xDEADBEEF, 0x55555, NULL, NULL, NULL);
        uint64_t end = read_cntvct_el0();
        beef_samples[i] = end - start;
    }

    // 收集 DEADBEEA 样本（非 KSU 路径，基线）
    for (int i = 0; i < NUM_SAMPLES; i++) {
        uint64_t start = read_cntvct_el0();
        prctl(0xDEADBEEA, 0x55555, NULL, NULL, NULL);
        uint64_t end = read_cntvct_el0();
        beea_samples[i] = end - start;
    }

    // 排序
    qsort(beef_samples, NUM_SAMPLES, sizeof(uint64_t), compare_u64);
    qsort(beea_samples, NUM_SAMPLES, sizeof(uint64_t), compare_u64);

    // 计算中位数
    uint64_t beef_median = beef_samples[NUM_SAMPLES / 2];
    uint64_t beea_median = beea_samples[NUM_SAMPLES / 2];

    // 对位比较：DEADBEEF > DEADBEEA 的次数
    // 有 KSU 时 DEADBEEF 应该更慢（进入 handler），anomaly 应该 > 5000
    // 无 KSU 时两者相同，anomaly 应该 ~5000
    uint32_t anomaly = 0;
    for (int i = 0; i < NUM_SAMPLES; i++) {
        if (beef_samples[i] > beea_samples[i]) {
            anomaly++;
        }
    }

    free(beef_samples);
    free(beea_samples);

    char result[256];
    snprintf(result, sizeof(result),
             "deadbeef_median=%llu|deadbeea_median=%llu|anomaly=%u",
             (unsigned long long)beef_median,
             (unsigned long long)beea_median,
             anomaly);
    return env->NewStringUTF(result);
}

/**
 * Layer 2: CNTVCT_EL0 高精度 prctl vs getpid 对比
 *
 * 原理：有 KSU 时，prctl(0xDEADBEEF) 走 hook 路径；
 * getpid() 不被 hook，作为基线。
 * 比较两者的时延差异。
 *
 * @return 格式：prctl_median=xxx|getpid_median=xxx|anomaly=xxx
 */
extern "C" JNIEXPORT jstring JNICALL
Java_qpdb_env_check_utils_SusfsDetectionUtil_nativeCheckPrctlVsGetpid(
        JNIEnv* env, jclass clazz) {
    const int NUM_SAMPLES = 10000;
    uint64_t* prctl_samples = (uint64_t*)malloc(NUM_SAMPLES * sizeof(uint64_t));
    uint64_t* getpid_samples = (uint64_t*)malloc(NUM_SAMPLES * sizeof(uint64_t));
    if (!prctl_samples || !getpid_samples) {
        free(prctl_samples);
        free(getpid_samples);
        return env->NewStringUTF("alloc_failed");
    }

    // 预热
    for (int i = 0; i < 200; i++) {
        prctl(0xDEADBEEF, 0x55555, NULL, NULL, NULL);
        syscall(__NR_getpid);
    }

    // 收集 prctl 样本
    for (int i = 0; i < NUM_SAMPLES; i++) {
        uint64_t start = read_cntvct_el0();
        prctl(0xDEADBEEF, 0x55555, NULL, NULL, NULL);
        uint64_t end = read_cntvct_el0();
        prctl_samples[i] = end - start;
    }

    // 收集 getpid 样本
    for (int i = 0; i < NUM_SAMPLES; i++) {
        uint64_t start = read_cntvct_el0();
        syscall(__NR_getpid);
        uint64_t end = read_cntvct_el0();
        getpid_samples[i] = end - start;
    }

    qsort(prctl_samples, NUM_SAMPLES, sizeof(uint64_t), compare_u64);
    qsort(getpid_samples, NUM_SAMPLES, sizeof(uint64_t), compare_u64);

    uint64_t prctl_median = prctl_samples[NUM_SAMPLES / 2];
    uint64_t getpid_median = getpid_samples[NUM_SAMPLES / 2];

    // 对位比较
    uint32_t anomaly = 0;
    for (int i = 0; i < NUM_SAMPLES; i++) {
        if (prctl_samples[i] > getpid_samples[i]) {
            anomaly++;
        }
    }

    free(prctl_samples);
    free(getpid_samples);

    char result[256];
    snprintf(result, sizeof(result),
             "prctl_median=%llu|getpid_median=%llu|anomaly=%u",
             (unsigned long long)prctl_median,
             (unsigned long long)getpid_median,
             anomaly);
    return env->NewStringUTF(result);
}

/**
 * Layer 2: CNTVCT_EL0 高精度 faccessat 侧信道
 *
 * 原理：SUSFS 的 sus_path 对隐藏路径执行 kmalloc(PAGE_SIZE) + d_path() + 链表遍历。
 * 利用 ARM64 cntvct_el0 虚拟计数器，测量隐藏路径 vs 正常路径的 faccessat 延迟差异。
 * 排序后对位比较，异常次数超过阈值则判定存在 SUSFS。
 *
 * @param hiddenPath 可能被隐藏的路径
 * @param normalPath 确定存在的正常路径
 * @return 格式：anomaly=xxx|hidden_median=xxx|normal_median=xxx
 */
extern "C" JNIEXPORT jstring JNICALL
Java_qpdb_env_check_utils_SusfsDetectionUtil_nativeCheckFaccessatCntvct(
        JNIEnv* env, jclass clazz, jstring hiddenPath, jstring normalPath) {
    const char* hpath = env->GetStringUTFChars(hiddenPath, nullptr);
    const char* npath = env->GetStringUTFChars(normalPath, nullptr);
    if (!hpath || !npath) {
        if (hpath) env->ReleaseStringUTFChars(hiddenPath, hpath);
        if (npath) env->ReleaseStringUTFChars(normalPath, npath);
        return env->NewStringUTF("invalid_args");
    }

    const int NUM_SAMPLES = 10000;
    uint64_t* hidden_samples = (uint64_t*)malloc(NUM_SAMPLES * sizeof(uint64_t));
    uint64_t* normal_samples = (uint64_t*)malloc(NUM_SAMPLES * sizeof(uint64_t));
    if (!hidden_samples || !normal_samples) {
        free(hidden_samples);
        free(normal_samples);
        env->ReleaseStringUTFChars(hiddenPath, hpath);
        env->ReleaseStringUTFChars(normalPath, npath);
        return env->NewStringUTF("alloc_failed");
    }

    // 预热缓存
    for (int i = 0; i < 200; i++) {
        syscall(__NR_faccessat, AT_FDCWD, hpath, F_OK, 0);
        syscall(__NR_faccessat, AT_FDCWD, npath, F_OK, 0);
    }

    // 收集隐藏路径样本
    for (int i = 0; i < NUM_SAMPLES; i++) {
        uint64_t start = read_cntvct_el0();
        syscall(__NR_faccessat, AT_FDCWD, hpath, F_OK, 0);
        uint64_t end = read_cntvct_el0();
        hidden_samples[i] = end - start;
    }

    // 收集正常路径基线样本
    for (int i = 0; i < NUM_SAMPLES; i++) {
        uint64_t start = read_cntvct_el0();
        syscall(__NR_faccessat, AT_FDCWD, npath, F_OK, 0);
        uint64_t end = read_cntvct_el0();
        normal_samples[i] = end - start;
    }

    env->ReleaseStringUTFChars(hiddenPath, hpath);
    env->ReleaseStringUTFChars(normalPath, npath);

    // 排序，消除离群值
    qsort(hidden_samples, NUM_SAMPLES, sizeof(uint64_t), compare_u64);
    qsort(normal_samples, NUM_SAMPLES, sizeof(uint64_t), compare_u64);

    // 计算中位数
    uint64_t hidden_median = hidden_samples[NUM_SAMPLES / 2];
    uint64_t normal_median = normal_samples[NUM_SAMPLES / 2];

    // 对位比较异常计数：hidden[i] > normal[i] 的次数
    uint32_t anomaly = 0;
    for (int i = 0; i < NUM_SAMPLES; i++) {
        if (hidden_samples[i] > normal_samples[i]) {
            anomaly++;
        }
    }

    free(hidden_samples);
    free(normal_samples);

    char result[256];
    snprintf(result, sizeof(result),
             "anomaly=%u|hidden_median=%llu|normal_median=%llu",
             anomaly,
             (unsigned long long)hidden_median,
             (unsigned long long)normal_median);
    return env->NewStringUTF(result);
}

/**
 * Layer 2: stat 系统调用双路径 CNTVCT 侧信道
 *
 * 原理：stat() 在内核中触发 vfs_getattr() -> susfs_sus_path_by_path()（路径匹配）
 * -> cp_new_stat() -> susfs_sus_kstat()（inode 匹配）。
 * 对隐藏文件调用 stat() 走 sus_path 拦截路径（kmalloc + 链表遍历）。
 *
 * @param hiddenPath 可能被隐藏的路径
 * @param normalPath 确定存在的正常路径
 * @return 格式：anomaly=xxx|hidden_median=xxx|normal_median=xxx
 */
extern "C" JNIEXPORT jstring JNICALL
Java_qpdb_env_check_utils_SusfsDetectionUtil_nativeCheckStatCntvct(
        JNIEnv* env, jclass clazz, jstring hiddenPath, jstring normalPath) {
    const char* hpath = env->GetStringUTFChars(hiddenPath, nullptr);
    const char* npath = env->GetStringUTFChars(normalPath, nullptr);
    if (!hpath || !npath) {
        if (hpath) env->ReleaseStringUTFChars(hiddenPath, hpath);
        if (npath) env->ReleaseStringUTFChars(normalPath, npath);
        return env->NewStringUTF("invalid_args");
    }

    const int NUM_SAMPLES = 10000;
    uint64_t* hidden_samples = (uint64_t*)malloc(NUM_SAMPLES * sizeof(uint64_t));
    uint64_t* normal_samples = (uint64_t*)malloc(NUM_SAMPLES * sizeof(uint64_t));
    if (!hidden_samples || !normal_samples) {
        free(hidden_samples);
        free(normal_samples);
        env->ReleaseStringUTFChars(hiddenPath, hpath);
        env->ReleaseStringUTFChars(normalPath, npath);
        return env->NewStringUTF("alloc_failed");
    }

    struct stat st;

    // 预热
    for (int i = 0; i < 200; i++) {
        stat(hpath, &st);
        stat(npath, &st);
    }

    // 收集隐藏路径样本
    for (int i = 0; i < NUM_SAMPLES; i++) {
        uint64_t start = read_cntvct_el0();
        stat(hpath, &st);
        uint64_t end = read_cntvct_el0();
        hidden_samples[i] = end - start;
    }

    // 收集正常路径基线样本
    for (int i = 0; i < NUM_SAMPLES; i++) {
        uint64_t start = read_cntvct_el0();
        stat(npath, &st);
        uint64_t end = read_cntvct_el0();
        normal_samples[i] = end - start;
    }

    env->ReleaseStringUTFChars(hiddenPath, hpath);
    env->ReleaseStringUTFChars(normalPath, npath);

    qsort(hidden_samples, NUM_SAMPLES, sizeof(uint64_t), compare_u64);
    qsort(normal_samples, NUM_SAMPLES, sizeof(uint64_t), compare_u64);

    uint64_t hidden_median = hidden_samples[NUM_SAMPLES / 2];
    uint64_t normal_median = normal_samples[NUM_SAMPLES / 2];

    uint32_t anomaly = 0;
    for (int i = 0; i < NUM_SAMPLES; i++) {
        if (hidden_samples[i] > normal_samples[i]) {
            anomaly++;
        }
    }

    free(hidden_samples);
    free(normal_samples);

    char result[256];
    snprintf(result, sizeof(result),
             "anomaly=%u|hidden_median=%llu|normal_median=%llu",
             anomaly,
             (unsigned long long)hidden_median,
             (unsigned long long)normal_median);
    return env->NewStringUTF(result);
}

#else

extern "C" JNIEXPORT jstring JNICALL
Java_qpdb_env_check_utils_SusfsDetectionUtil_nativeCheckPrctlCntvct(
        JNIEnv* env, jclass clazz) {
    return env->NewStringUTF("unsupported_arch");
}

extern "C" JNIEXPORT jstring JNICALL
Java_qpdb_env_check_utils_SusfsDetectionUtil_nativeCheckPrctlVsGetpid(
        JNIEnv* env, jclass clazz) {
    return env->NewStringUTF("unsupported_arch");
}

extern "C" JNIEXPORT jstring JNICALL
Java_qpdb_env_check_utils_SusfsDetectionUtil_nativeCheckFaccessatCntvct(
        JNIEnv* env, jclass clazz, jstring hiddenPath, jstring normalPath) {
    return env->NewStringUTF("unsupported_arch");
}

extern "C" JNIEXPORT jstring JNICALL
Java_qpdb_env_check_utils_SusfsDetectionUtil_nativeCheckStatCntvct(
        JNIEnv* env, jclass clazz, jstring hiddenPath, jstring normalPath) {
    return env->NewStringUTF("unsupported_arch");
}

#endif

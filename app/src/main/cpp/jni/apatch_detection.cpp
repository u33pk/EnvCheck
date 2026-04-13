#include <jni.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <android/log.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sched.h>
#include "utils/time_util.h"

#define LOG_TAG "ApatchNative"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// ================== APatch 侧信道检测 JNI 方法 ==================

/**
 * 调用 syscall(45) 并返回其结果
 * 用于检测 APatch 的 SuperCall 返回值异常
 */
extern "C" JNIEXPORT jint JNICALL
Java_qpdb_env_check_utils_ApatchDetectionUtil_nativeCheckSyscall45Return(
        JNIEnv* env,
        jclass clazz,
        jlong cmd) {
    long ret = syscall(45, "", cmd);
    return (jint)ret;
}

/**
 * 调用 getpid() 并返回结果（作为基线对照）
 */
extern "C" JNIEXPORT jint JNICALL
Java_qpdb_env_check_utils_ApatchDetectionUtil_nativeCheckGetpidReturn(
        JNIEnv* env,
        jclass clazz) {
    return (jint)syscall(__NR_getpid);
}

/**
 * 测量 syscall(45) 的总耗时（纳秒）
 */
extern "C" JNIEXPORT jlong JNICALL
Java_qpdb_env_check_utils_ApatchDetectionUtil_nativeCheckSyscall45Timing(
        JNIEnv* env,
        jclass clazz,
        jlong cmd,
        jint iterations) {
    long start = get_time_ns();
    for (int i = 0; i < iterations; i++) {
        syscall(45, "", cmd);
    }
    long end = get_time_ns();
    return (jlong)(end - start);
}

/**
 * 测量相邻合法 syscall（ftruncate，非法参数 -1）的总耗时（纳秒，作为基线对照）
 *
 * 选择 __NR_ftruncate 的原因：
 * - 与 45 号相邻（在 ARM 上为 46），KernelPatch 明确没有 hook
 * - 传入非法 fd (-1) 会走完整 syscall 入口路径后快速失败
 * - 与 syscall(45) 的入口路径（seccomp → 内核入口 → sys_call_table 查找 → handler）完全对称
 * - 避免了 getpid() 无参数、以及不存在 syscall 早退带来的系统误差
 */
extern "C" JNIEXPORT jlong JNICALL
Java_qpdb_env_check_utils_ApatchDetectionUtil_nativeCheckBaselineTiming(
        JNIEnv* env,
        jclass clazz,
        jint iterations) {
    long start = get_time_ns();
    for (int i = 0; i < iterations; i++) {
        syscall(__NR_ftruncate, -1, 0L);
    }
    long end = get_time_ns();
    return (jlong)(end - start);
}

// ================== CNTVCT_EL0 高精度侧信道检测 ==================

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
 * 基于 CNTVCT_EL0 的高精度 syscall(45) 侧信道检测
 *
 * 原理：测量 syscall(45, "", 0x1) 与基线 syscall(__NR_ftruncate, -1, 0) 各 10000 次，
 * 排序后对位比较。若 syscall(45)[i] > baseline[i] + 1 的异常次数超过阈值，
 * 则判定 45 号系统调用被 hook（APatch / KernelPatch 指纹）。
 * 使用 ftruncate(-1) 作为基线：它是已实现的合法 syscall，会走完整入口路径后
 * 快速失败，与 syscall(45) 的入口路径完全对称，且不会被 KernelPatch hook。
 */
extern "C" JNIEXPORT jstring JNICALL
Java_qpdb_env_check_utils_ApatchDetectionUtil_nativeCheckSupercallTiming(
        JNIEnv* env, jclass clazz) {
    const int NUM_SAMPLES = 10000;
    uint64_t* test_samples = (uint64_t*)malloc(NUM_SAMPLES * sizeof(uint64_t));
    uint64_t* base_samples = (uint64_t*)malloc(NUM_SAMPLES * sizeof(uint64_t));
    if (!test_samples || !base_samples) {
        free(test_samples);
        free(base_samples);
        return env->NewStringUTF("alloc_failed");
    }

    // 预热缓存
    for (int i = 0; i < 50; i++) {
        syscall(45, "", 0x1L);
        syscall(__NR_ftruncate, -1, 0L);
    }

    // 收集 syscall(45, "", 0x1) 测试样本（cmd 无效，但会进入 hook 跳板）
    for (int i = 0; i < NUM_SAMPLES; i++) {
        uint64_t start = read_cntvct_el0();
        syscall(45, "", 0x1L);
        uint64_t end = read_cntvct_el0();
        test_samples[i] = end - start;
    }

    // 收集 ftruncate(-1) 基线样本（已实现的合法 syscall，非法参数快速失败）
    for (int i = 0; i < NUM_SAMPLES; i++) {
        uint64_t start = read_cntvct_el0();
        syscall(__NR_ftruncate, -1, 0L);
        uint64_t end = read_cntvct_el0();
        base_samples[i] = end - start;
    }

    // 排序，消除离群值影响
    qsort(test_samples, NUM_SAMPLES, sizeof(uint64_t), compare_u64);
    qsort(base_samples, NUM_SAMPLES, sizeof(uint64_t), compare_u64);

    // 计算中位数
    uint64_t test_median = test_samples[NUM_SAMPLES / 2];
    uint64_t base_median = base_samples[NUM_SAMPLES / 2];

    // 对位比较异常计数
    uint32_t anomaly = 0;
    for (int i = 0; i < NUM_SAMPLES; i++) {
        if (test_samples[i] > base_samples[i] + 1) {
            anomaly++;
        }
    }

    free(test_samples);
    free(base_samples);

    char result[256];
    snprintf(result, sizeof(result),
             "anomaly=%u|threshold=7000|test_median=%llu|base_median=%llu",
             anomaly,
             (unsigned long long)test_median,
             (unsigned long long)base_median);
    return env->NewStringUTF(result);
}

/**
 * CNTVCT_EL0 高精度侧信道检测：有效 cmd vs 无效 cmd
 *
 * 原理：测量 syscall(45, "", 0x1000) 与 syscall(45, "", 0x1) 各 10000 次。
 * 在 APatch 设备上，0x1000 会触发 compat_strncpy_from_user + auth_superkey()，
 * 路径更长；0x1 会在 before 函数前几行快速返回。
 * 通过对比两者的耗时差异，可以进一步确认是 KernelPatch/APatch 而非单纯劫持。
 */
extern "C" JNIEXPORT jstring JNICALL
Java_qpdb_env_check_utils_ApatchDetectionUtil_nativeCheckSupercallValidVsInvalid(
        JNIEnv* env, jclass clazz) {
    const int NUM_SAMPLES = 10000;
    uint64_t* valid_samples = (uint64_t*)malloc(NUM_SAMPLES * sizeof(uint64_t));
    uint64_t* invalid_samples = (uint64_t*)malloc(NUM_SAMPLES * sizeof(uint64_t));
    if (!valid_samples || !invalid_samples) {
        free(valid_samples);
        free(invalid_samples);
        return env->NewStringUTF("alloc_failed");
    }

    // 预热
    for (int i = 0; i < 50; i++) {
        syscall(45, "", 0x1000L); // SUPERCALL_HELLO
        syscall(45, "", 0x1L);    // 无效 cmd
    }

    // 收集有效 cmd 样本
    for (int i = 0; i < NUM_SAMPLES; i++) {
        uint64_t start = read_cntvct_el0();
        syscall(45, "", 0x1000L);
        uint64_t end = read_cntvct_el0();
        valid_samples[i] = end - start;
    }

    // 收集无效 cmd 样本
    for (int i = 0; i < NUM_SAMPLES; i++) {
        uint64_t start = read_cntvct_el0();
        syscall(45, "", 0x1L);
        uint64_t end = read_cntvct_el0();
        invalid_samples[i] = end - start;
    }

    qsort(valid_samples, NUM_SAMPLES, sizeof(uint64_t), compare_u64);
    qsort(invalid_samples, NUM_SAMPLES, sizeof(uint64_t), compare_u64);

    uint64_t valid_median = valid_samples[NUM_SAMPLES / 2];
    uint64_t invalid_median = invalid_samples[NUM_SAMPLES / 2];

    uint32_t anomaly = 0;
    for (int i = 0; i < NUM_SAMPLES; i++) {
        if (valid_samples[i] > invalid_samples[i] + 1) {
            anomaly++;
        }
    }

    free(valid_samples);
    free(invalid_samples);

    char result[256];
    snprintf(result, sizeof(result),
             "anomaly=%u|threshold=7000|valid_median=%llu|invalid_median=%llu",
             anomaly,
             (unsigned long long)valid_median,
             (unsigned long long)invalid_median);
    return env->NewStringUTF(result);
}

/**
 * 绑定到高性能大核（研究性侧信道需要尽可能稳定的计时环境）
 */
static void bind_big_core() {
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(0, &cpuset);  // 文档示例绑定 CPU 4，通常为大核
    sched_setaffinity(0, sizeof(cpuset), &cpuset);
}

/**
 * SuperKey 长度时间侧信道检测（研究性）
 *
 * 基于 doc/supercall_key_length_timing_sidechannel.md 的实验方案：
 * - 基线：syscall(45, fake_key_64, 0x1)   — cmd 无效，before 钩子直接 return
 * - 测试：syscall(45, fake_key_64, 0x1000) — cmd 有效，完整执行 strncpy + auth_superkey
 * - 通过大样本 CNTVCT_EL0 高精度计时，取中位数后计算差分 delta。
 *
 * 注意：该侧信道在理论上成立，但 Android 调度噪声较大，结果仅供研究参考。
 */
extern "C" JNIEXPORT jstring JNICALL
Java_qpdb_env_check_utils_ApatchDetectionUtil_nativeCheckSuperkeyLengthSideChannel(
        JNIEnv* env, jclass clazz) {
    const int NUM_SAMPLES = 100000;
    const char fake_key[65] =
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    uint64_t* baseline_samples = (uint64_t*)malloc(NUM_SAMPLES * sizeof(uint64_t));
    uint64_t* test_samples = (uint64_t*)malloc(NUM_SAMPLES * sizeof(uint64_t));
    if (!baseline_samples || !test_samples) {
        free(baseline_samples);
        free(test_samples);
        return env->NewStringUTF("alloc_failed");
    }

    bind_big_core();
    volatile long dummy = 0;

    // 预热，避免缓存冷启动影响
    for (int i = 0; i < 50; i++) {
        dummy += syscall(45, fake_key, 0x1L);
        dummy += syscall(45, fake_key, 0x1000L);
    }

    // 基线样本：cmd 无效，不执行 strncpy_from_user 和 auth_superkey
    for (int i = 0; i < NUM_SAMPLES; i++) {
        uint64_t start = read_cntvct_el0();
        dummy += syscall(45, fake_key, 0x1L);
        uint64_t end = read_cntvct_el0();
        baseline_samples[i] = end - start;
    }

    // 测试样本：cmd 有效，触发完整路径（含 strncpy + auth_superkey）
    for (int i = 0; i < NUM_SAMPLES; i++) {
        uint64_t start = read_cntvct_el0();
        dummy += syscall(45, fake_key, 0x1000L);
        uint64_t end = read_cntvct_el0();
        test_samples[i] = end - start;
    }

    qsort(baseline_samples, NUM_SAMPLES, sizeof(uint64_t), compare_u64);
    qsort(test_samples, NUM_SAMPLES, sizeof(uint64_t), compare_u64);

    uint64_t baseline_median = baseline_samples[NUM_SAMPLES / 2];
    uint64_t test_median = test_samples[NUM_SAMPLES / 2];
    int64_t delta = (int64_t)test_median - (int64_t)baseline_median;

    free(baseline_samples);
    free(test_samples);

    char result[256];
    snprintf(result, sizeof(result),
             "delta=%lld|baseline=%llu|test=%llu|samples=%d",
             (long long)delta,
             (unsigned long long)baseline_median,
             (unsigned long long)test_median,
             NUM_SAMPLES);
    return env->NewStringUTF(result);
}

#else

extern "C" JNIEXPORT jstring JNICALL
Java_qpdb_env_check_utils_ApatchDetectionUtil_nativeCheckSupercallTiming(
        JNIEnv* env, jclass clazz) {
    return env->NewStringUTF("unsupported_arch");
}

extern "C" JNIEXPORT jstring JNICALL
Java_qpdb_env_check_utils_ApatchDetectionUtil_nativeCheckSupercallValidVsInvalid(
        JNIEnv* env, jclass clazz) {
    return env->NewStringUTF("unsupported_arch");
}

extern "C" JNIEXPORT jstring JNICALL
Java_qpdb_env_check_utils_ApatchDetectionUtil_nativeCheckSuperkeyLengthSideChannel(
        JNIEnv* env, jclass clazz) {
    return env->NewStringUTF("unsupported_arch");
}

#endif // __aarch64__

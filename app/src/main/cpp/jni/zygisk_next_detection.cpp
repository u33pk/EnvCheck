#include <jni.h>
#include <android/log.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/wait.h>
#include <math.h>
#include <sched.h>
#include "utils/time_util.h"

#define LOG_TAG "ZygiskNextNative"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

static int compare_long(const void* a, const void* b) {
    long av = *(const long*)a;
    long bv = *(const long*)b;
    if (av < bv) return -1;
    if (av > bv) return 1;
    return 0;
}

// ================== Zygote fork 时间侧信道检测 ==================

/**
 * Zygote fork 时间侧信道检测
 *
 * 测量 fork + exec("/system/bin/sh", "-c", "exit 0") 的总耗时。
 * Zygisk Next 注入后，zygote 进程的 fork 路径被 hook：
 * - fork_pre() 遍历 /proc/self/fd 记录 fd（~50-500 us）
 * - app_specialize_pre() 加载执行模块（~1-20 ms/模块）
 * - sanitize_fds() 两次遍历 /proc/self/fd 并 close（~70-600 us）
 *
 * 正常设备：中位数 ~500-2000 us
 * 有 Zygisk Next：中位数 ~2000-10000+ us
 */
extern "C" JNIEXPORT jstring JNICALL
Java_qpdb_env_check_utils_ZygiskNextUtil_nativeCheckZygoteForkTiming(
        JNIEnv* env, jclass clazz) {
    const int NUM_SAMPLES = 30;
    long samples[NUM_SAMPLES];

    // 预热：丢弃前几次 fork 的冷启动惩罚
    for (int i = 0; i < 5; i++) {
        pid_t pid = fork();
        if (pid == 0) {
//            execl("/system/bin/sh", "sh", "-c", "exit 0", (char*)nullptr);
            _exit(1);
        } else if (pid > 0) {
            int status;
            waitpid(pid, &status, 0);
        } else {
            return env->NewStringUTF("fork_failed");
        }
    }

    // 正式采样
    for (int i = 0; i < NUM_SAMPLES; i++) {
        pid_t pid = fork();
        if (pid == 0) {
//            execl("/system/bin/sh", "sh", "-c", "exit 0", (char*)nullptr);
            _exit(1);
        } else if (pid > 0) {
            long start = get_time_ns();
            int status;
            waitpid(pid, &status, 0);
            long end = get_time_ns();
            samples[i] = (end - start) / 1000; // 转为微秒
        } else {
            return env->NewStringUTF("fork_failed");
        }
        usleep(10000); // 10ms 间隔，避免缓存影响
    }

    qsort(samples, NUM_SAMPLES, sizeof(long), compare_long);

    long median = samples[NUM_SAMPLES / 2];
    long p90 = samples[(int)(NUM_SAMPLES * 0.9)];
    long min_val = samples[0];
    long max_val = samples[NUM_SAMPLES - 1];

    long sum = 0;
    for (int i = 0; i < NUM_SAMPLES; i++) sum += samples[i];
    long mean = sum / NUM_SAMPLES;

    double sq_diff_sum = 0.0;
    for (int i = 0; i < NUM_SAMPLES; i++) {
        double diff = (double)samples[i] - (double)mean;
        sq_diff_sum += diff * diff;
    }
    long stddev = (long)sqrt(sq_diff_sum / NUM_SAMPLES);

    char result[256];
    snprintf(result, sizeof(result),
             "median_us=%ld|mean_us=%ld|stddev_us=%ld|min_us=%ld|max_us=%ld|p90_us=%ld",
             median, mean, stddev, min_val, max_val, p90);
    return env->NewStringUTF(result);
}

// ================== 方案 A：双进程对比侧信道 ==================

/**
 * 双进程对比侧信道（简化版）
 *
 * 对比 fork+exec（正常路径，含 Zygisk hook）与 fork+exit（最小路径）的耗时差异。
 * 若 Zygisk hook 了 execve 或 specialize 路径，fork+exec 会显著慢于 fork+exit。
 *
 * 文档分析：isolated 进程不会完全绕过 Zygisk，但跳过了 fd sanitization（~70-600 us）。
 * 本实现采用等效思路：exec 路径包含完整的 specialize 后逻辑，exit 路径跳过这些逻辑。
 */
extern "C" JNIEXPORT jstring JNICALL
Java_qpdb_env_check_utils_ZygiskNextUtil_nativeCheckForkExecVsExit(
        JNIEnv* env, jclass clazz) {
    const int NUM_SAMPLES = 30;
    long exec_samples[NUM_SAMPLES];
    long exit_samples[NUM_SAMPLES];

    // 预热
    for (int i = 0; i < 5; i++) {
        pid_t pid = fork();
        if (pid == 0) {
            execl("/system/bin/sh", "sh", "-c", "exit 0", (char*)nullptr);
            _exit(1);
        } else if (pid > 0) {
            int status;
            waitpid(pid, &status, 0);
        }
    }

    // 测试组：fork + exec
    for (int i = 0; i < NUM_SAMPLES; i++) {
        pid_t pid = fork();
        if (pid == 0) {
            execl("/system/bin/sh", "sh", "-c", "exit 0", (char*)nullptr);
            _exit(1);
        } else if (pid > 0) {
            long start = get_time_ns();
            int status;
            waitpid(pid, &status, 0);
            long end = get_time_ns();
            exec_samples[i] = (end - start) / 1000;
        } else {
            return env->NewStringUTF("fork_failed");
        }
        usleep(5000);
    }

    // 基线组：fork + exit（最小路径）
    for (int i = 0; i < NUM_SAMPLES; i++) {
        pid_t pid = fork();
        if (pid == 0) {
            _exit(0);
        } else if (pid > 0) {
            long start = get_time_ns();
            int status;
            waitpid(pid, &status, 0);
            long end = get_time_ns();
            exit_samples[i] = (end - start) / 1000;
        } else {
            return env->NewStringUTF("fork_failed");
        }
        usleep(5000);
    }

    qsort(exec_samples, NUM_SAMPLES, sizeof(long), compare_long);
    qsort(exit_samples, NUM_SAMPLES, sizeof(long), compare_long);

    long exec_median = exec_samples[NUM_SAMPLES / 2];
    long exit_median = exit_samples[NUM_SAMPLES / 2];
    long diff = exec_median - exit_median;
    if (diff < 0) diff = 0;

    char result[256];
    snprintf(result, sizeof(result),
             "exec_median_us=%ld|exit_median_us=%ld|diff_us=%ld|exec_samples=%d",
             exec_median, exit_median, diff, NUM_SAMPLES);
    return env->NewStringUTF(result);
}

// ================== 方案 B：多阶段时序（App 启动空白期） ==================

/**
 * 读取 /proc/self/stat 的 starttime，计算进程从内核创建到当前时刻的"空白期"。
 *
 * /proc/[pid]/stat 格式：
 * pid (comm) state ppid ... starttime ...
 * 第 22 个字段是 starttime（自系统启动以来的时钟滴答数）
 */
extern "C" JNIEXPORT jstring JNICALL
Java_qpdb_env_check_utils_ZygiskNextUtil_nativeCheckAppStartup(
        JNIEnv* env, jclass clazz) {
    FILE* fp = fopen("/proc/self/stat", "r");
    if (!fp) {
        return env->NewStringUTF("open_failed");
    }

    char line[1024];
    if (!fgets(line, sizeof(line), fp)) {
        fclose(fp);
        return env->NewStringUTF("read_failed");
    }
    fclose(fp);

    // comm 字段可能包含空格和括号，需要从最后一个 ')' 之后开始解析
    char* p = strrchr(line, ')');
    if (!p) {
        return env->NewStringUTF("parse_failed");
    }
    p += 2; // 跳过 ") "

    // 跳过前 19 个字段（state 开始后的 19 个字段到达 starttime）
    // state 是 p 指向的第一个字符，然后跳过 19 个空格分隔的字段
    for (int i = 0; i < 19; i++) {
        p = strchr(p, ' ');
        if (!p) {
            return env->NewStringUTF("parse_failed");
        }
        p++;
        // 跳过连续空格
        while (*p == ' ') p++;
    }

    long starttime = strtol(p, nullptr, 10);
    long clk_tck = sysconf(_SC_CLK_TCK);
    if (clk_tck <= 0) clk_tck = 100;

    long starttime_ms = starttime * 1000L / clk_tck;

    char result[128];
    snprintf(result, sizeof(result), "starttime_ms=%ld|clk_tck=%ld", starttime_ms, clk_tck);
    return env->NewStringUTF(result);
}

// ================== 方案 C：统计分布分析 ==================

/**
 * fork 统计分布分析
 *
 * 采集 30 次 fork+exec 样本，计算统计特征：
 * - 均值、标准差、变异系数（CV）
 * - 双峰分布检测：以 5ms 为阈值分割快/慢路径
 *
 * Zygisk 引入的模块加载时间不稳定，会导致 CV 增大和双峰分布。
 */
extern "C" JNIEXPORT jstring JNICALL
Java_qpdb_env_check_utils_ZygiskNextUtil_nativeCheckForkDistribution(
        JNIEnv* env, jclass clazz) {
    const int NUM_SAMPLES = 30;
    long samples[NUM_SAMPLES];

    // 预热
    for (int i = 0; i < 5; i++) {
        pid_t pid = fork();
        if (pid == 0) {
            execl("/system/bin/sh", "sh", "-c", "exit 0", (char*)nullptr);
            _exit(1);
        } else if (pid > 0) {
            int status;
            waitpid(pid, &status, 0);
        }
    }

    // 采集样本
    for (int i = 0; i < NUM_SAMPLES; i++) {
        pid_t pid = fork();
        if (pid == 0) {
            execl("/system/bin/sh", "sh", "-c", "exit 0", (char*)nullptr);
            _exit(1);
        } else if (pid > 0) {
            long start = get_time_ns();
            int status;
            waitpid(pid, &status, 0);
            long end = get_time_ns();
            samples[i] = (end - start) / 1000; // 微秒
        } else {
            return env->NewStringUTF("fork_failed");
        }
        usleep(10000); // 10ms 间隔
    }

    // 计算均值
    double sum = 0.0;
    for (int i = 0; i < NUM_SAMPLES; i++) sum += samples[i];
    double mean = sum / NUM_SAMPLES;

    // 计算标准差
    double sq_diff_sum = 0.0;
    for (int i = 0; i < NUM_SAMPLES; i++) {
        double diff = (double)samples[i] - mean;
        sq_diff_sum += diff * diff;
    }
    double stddev = sqrt(sq_diff_sum / NUM_SAMPLES);

    // 变异系数
    double cv = (mean > 0.0) ? stddev / mean : 0.0;

    // 双峰分布检测：以 5000 us (5ms) 为阈值
    int fast_count = 0;
    int slow_count = 0;
    for (int i = 0; i < NUM_SAMPLES; i++) {
        if (samples[i] < 5000) fast_count++;
        else slow_count++;
    }

    char result[256];
    snprintf(result, sizeof(result),
             "mean_us=%ld|stddev_us=%ld|cv=%.4f|fast_count=%d|slow_count=%d|samples=%d",
             (long)mean, (long)stddev, cv, fast_count, slow_count, NUM_SAMPLES);
    return env->NewStringUTF(result);
}

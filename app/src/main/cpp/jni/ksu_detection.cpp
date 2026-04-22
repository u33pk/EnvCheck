#include <jni.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <time.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <android/log.h>
#include <stdlib.h>
#include "utils/time_util.h"

#define LOG_TAG "KsuNative"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// ================== KernelSU 侧信道检测 JNI 方法 ==================

/**
 * 测量 faccessat 系统调用耗时（纳秒）
 */
extern "C" JNIEXPORT jlong JNICALL
Java_qpdb_env_check_utils_KsuDetectionUtil_nativeCheckAccessTiming(
        JNIEnv* env,
        jclass clazz,
        jstring path,
        jint iterations) {
    const char* cpath = env->GetStringUTFChars(path, nullptr);
    if (!cpath) return -1;
    long start = get_time_ns();
    for (int i = 0; i < iterations; i++) {
        syscall(__NR_faccessat, AT_FDCWD, cpath, F_OK, 0);
    }
    long end = get_time_ns();
    env->ReleaseStringUTFChars(path, cpath);
    return (jlong)(end - start);
}

/**
 * 测量 getpid 系统调用循环耗时（纳秒）
 * 用于检测 tracepoint 标记带来的 syscall 开销
 */
extern "C" JNIEXPORT jlong JNICALL
Java_qpdb_env_check_utils_KsuDetectionUtil_nativeCheckSyscallLoop(
        JNIEnv* env,
        jclass clazz,
        jint iterations) {
    long start = get_time_ns();
    for (int i = 0; i < iterations; i++) {
        syscall(__NR_getpid);
    }
    long end = get_time_ns();
    return (jlong)(end - start);
}

/**
 * 检测 init.rc 的 stat 大小与实际读取大小是否一致
 * KernelSU 的 fstat hook 会虚增 init.rc 的 st_size
 */
extern "C" JNIEXPORT jstring JNICALL
Java_qpdb_env_check_utils_KsuDetectionUtil_nativeCheckInitRcStat(
        JNIEnv* env,
        jclass clazz) {
    const char* path = "/system/etc/init/hw/init.rc";
    struct stat st;
    if (stat(path, &st) != 0) {
        // 尝试备用路径
        const char* alt_path = "/init.rc";
        if (stat(alt_path, &st) != 0) {
            return env->NewStringUTF("stat_failed");
        }
        path = alt_path;
    }

    off_t stat_size = st.st_size;

    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return env->NewStringUTF("open_failed");
    }

    char buf[4096];
    ssize_t total_read = 0;
    ssize_t n;
    while ((n = read(fd, buf, sizeof(buf))) > 0) {
        total_read += n;
    }
    close(fd);

    char result[256];
    snprintf(result, sizeof(result), "stat=%ld|read=%ld", (long)stat_size, (long)total_read);
    return env->NewStringUTF(result);
}

/**
 * 检测 access("/system/bin/su", F_OK) 的返回值
 * 如果 su 不存在但 access 返回 0，说明可能被 sucompat 重定向
 */
extern "C" JNIEXPORT jint JNICALL
Java_qpdb_env_check_utils_KsuDetectionUtil_nativeCheckAccessSu(
        JNIEnv* env,
        jclass clazz) {
    int ret = access("/system/bin/su", F_OK);
    return (jint)(ret == 0 ? 1 : 0);
}

/**
 * 读取当前进程的 Seccomp 状态
 * KernelSU grant_root 后会将 seccomp 从 2 变为 0
 */
extern "C" JNIEXPORT jint JNICALL
Java_qpdb_env_check_utils_KsuDetectionUtil_nativeCheckSeccompStatus(
        JNIEnv* env,
        jclass clazz) {
    FILE* fp = fopen("/proc/self/status", "r");
    if (!fp) return -1;

    char line[256];
    int seccomp = -1;
    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "Seccomp:", 8) == 0) {
            sscanf(line + 8, "%d", &seccomp);
            break;
        }
    }
    fclose(fp);
    return (jint)seccomp;
}

/**
 * 扫描 /proc/self/fd/ 中是否存在 [ksu_driver] 或 [ksu_fdwrapper] 匿名 inode fd
 */
extern "C" JNIEXPORT jboolean JNICALL
Java_qpdb_env_check_utils_KsuDetectionUtil_nativeCheckKsuFd(
        JNIEnv* env,
        jclass clazz) {
    DIR* dir = opendir("/proc/self/fd");
    if (!dir) return JNI_FALSE;

    struct dirent* entry;
    char path[256];
    char target[256];
    ssize_t len;
    jboolean found = JNI_FALSE;

    while ((entry = readdir(dir)) != nullptr) {
        if (entry->d_name[0] == '.') continue;
        snprintf(path, sizeof(path), "/proc/self/fd/%s", entry->d_name);
        len = readlink(path, target, sizeof(target) - 1);
        if (len > 0) {
            target[len] = '\0';
            if (strstr(target, "[ksu_driver]") != nullptr || strstr(target, "[ksu_fdwrapper]") != nullptr) {
                found = JNI_TRUE;
                break;
            }
        }
    }
    closedir(dir);
    return found;
}

/**
 * 测量 execve("/system/bin/su") 与 execve("/system/bin/sh") 的延迟差异
 * 返回格式：su_avg=xxx|sh_avg=xxx（微秒）
 */
extern "C" JNIEXPORT jstring JNICALL
Java_qpdb_env_check_utils_KsuDetectionUtil_nativeCheckExecveTiming(
        JNIEnv* env,
        jclass clazz) {
    const int iterations = 10;

    // 测量 execve("/system/bin/su", ...)
    long su_total = 0;
    for (int i = 0; i < iterations; i++) {
        pid_t pid = fork();
        if (pid == 0) {
            // child: 执行 su -c exit
            execl("/system/bin/su", "su", "-c", "exit", (char*)nullptr);
            _exit(errno);
        } else if (pid > 0) {
            long start = get_time_ns();
            int status;
            waitpid(pid, &status, 0);
            long end = get_time_ns();
            su_total += (end - start);
        } else {
            return env->NewStringUTF("fork_failed");
        }
    }

    // 测量 execve("/system/bin/sh", ...)
    long sh_total = 0;
    for (int i = 0; i < iterations; i++) {
        pid_t pid = fork();
        if (pid == 0) {
            // child: 执行 sh -c exit
            execl("/system/bin/sh", "sh", "-c", "exit", (char*)nullptr);
            _exit(errno);
        } else if (pid > 0) {
            long start = get_time_ns();
            int status;
            waitpid(pid, &status, 0);
            long end = get_time_ns();
            sh_total += (end - start);
        } else {
            return env->NewStringUTF("fork_failed");
        }
    }

    char result[256];
    // 返回微秒值
    snprintf(result, sizeof(result), "su_avg=%ld|sh_avg=%ld",
             su_total / iterations / 1000,
             sh_total / iterations / 1000);
    return env->NewStringUTF(result);
}

/**
 * 测量 setresuid 系统调用耗时（纳秒）
 * 普通 App 调用会返回 EPERM，但 syscall 已进入内核并被 ksu_handle_setresuid hook
 */
extern "C" JNIEXPORT jlong JNICALL
Java_qpdb_env_check_utils_KsuDetectionUtil_nativeCheckSetresuidTiming(
        JNIEnv* env, jclass clazz, jint iterations) {
    uid_t uid = getuid();
    long start = get_time_ns();
    for (int i = 0; i < iterations; i++) {
        syscall(__NR_setresuid, uid, uid, uid);
    }
    long end = get_time_ns();
    return (jlong)(end - start);
}

// ================== CNTVCT_EL0 高精度侧信道检测 ==================

#ifdef __aarch64__

static inline uint64_t read_cntvct_el0(void) {
    uint64_t val;
    __asm__ __volatile__ ("isb; mrs %0, cntvct_el0; isb" : "=r" (val)); // isb 确保指令执行顺序 防止 CPU 乱序执行导致时间测量误差
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
 * 基于 CNTVCT_EL0 的高精度 syscall 侧信道检测
 *
 * 原理：测量 faccessat("/system/bin/su") 与基线 fchownat 各 10000 次，
 * 排序后对位比较。若 faccessat[i] > fchownat[i] + 1 的异常次数超过阈值，
 * 则判定存在 sucompat hook。
 *
 * 参考：doc/ksu_侧信道检测.md
 */
extern "C" JNIEXPORT jstring JNICALL
Java_qpdb_env_check_utils_KsuDetectionUtil_nativeCheckTimingSideChannel(
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
        // int faccessat(int dirfd, const char *pathname, int mode, int flags);
        // 当前工作目录 文件路径 访问模式 标志位
        syscall(__NR_faccessat, AT_FDCWD, "/system/bin/su", F_OK, 0);
        // int fchownat(int dirfd, const char *pathname, uid_t owner, gid_t group, int flags);
        // 当前工作目录 文件路径 新所有者UID   新组GID  标志位
        syscall(__NR_fchownat, AT_FDCWD, "/system/bin/sh", 0, 0, 0);
    }

    // 收集 faccessat 测试样本
    for (int i = 0; i < NUM_SAMPLES; i++) {
        uint64_t start = read_cntvct_el0();
        syscall(__NR_faccessat, AT_FDCWD, "/system/bin/su", F_OK, 0);
        uint64_t end = read_cntvct_el0();
        test_samples[i] = end - start;
    }

    // 收集 fchownat 基线样本（不会被 KSU hook 的稳定 syscall）
    for (int i = 0; i < NUM_SAMPLES; i++) {
        uint64_t start = read_cntvct_el0();
        syscall(__NR_fchownat, AT_FDCWD, "/system/bin/sh", 0, 0, 0);
        uint64_t end = read_cntvct_el0();
        base_samples[i] = end - start;
    }

    // 排序，消除离群值
    qsort(test_samples, NUM_SAMPLES, sizeof(uint64_t), compare_u64);
    qsort(base_samples, NUM_SAMPLES, sizeof(uint64_t), compare_u64);

    // 计算中位数（用于信息展示）
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

#else

extern "C" JNIEXPORT jstring JNICALL
Java_qpdb_env_check_utils_KsuDetectionUtil_nativeCheckTimingSideChannel(
        JNIEnv* env, jclass clazz) {
    return env->NewStringUTF("unsupported_arch");
}

#endif

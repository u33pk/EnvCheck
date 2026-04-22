#include <jni.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <sched.h>
#include <errno.h>
#include <android/log.h>

#define LOG_TAG "SoCDetection"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)

#ifdef __aarch64__

/**
 * 将当前线程绑定到指定 CPU 核心
 * @return 0 成功, -1 失败
 */
static int bind_to_cpu(int cpu_index) {
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(cpu_index, &cpuset);

    int ret = sched_setaffinity(0, sizeof(cpu_set_t), &cpuset);
    if (ret != 0) {
        LOGD("Failed to bind to CPU %d: %s", cpu_index, strerror(errno));
        return -1;
    }

    // 让出 CPU 确保线程调度到目标核心
    sched_yield();
    return 0;
}

/**
 * 通过汇编指令读取 MIDR_EL1 寄存器
 * MIDR_EL1 (Main ID Register) 包含处理器型号信息
 */
static inline uint64_t read_midr_el1_asm() {
    uint64_t val;
    __asm__ __volatile__(
        "isb\n\t"
        "mrs %0, midr_el1\n\t"
        "isb"
        : "=r" (val)
        :
        : "memory"
    );
    return val;
}

/**
 * 绑定到指定核心后读取 MIDR_EL1
 */
static uint64_t read_midr_el1_asm_on_cpu(int cpu_index) {
    // 保存原始亲和性
    cpu_set_t old_cpuset;
    sched_getaffinity(0, sizeof(cpu_set_t), &old_cpuset);

    // 绑定到目标核心
    if (bind_to_cpu(cpu_index) != 0) {
        return 0xFFFFFFFFFFFFFFFFULL;
    }

    // 在目标核心上读取 MIDR_EL1
    uint64_t val = read_midr_el1_asm();

    // 恢复原始亲和性
    sched_setaffinity(0, sizeof(cpu_set_t), &old_cpuset);

    return val;
}

#else

static inline uint64_t read_midr_el1_asm() {
    return 0xFFFFFFFFFFFFFFFFULL; // 不支持的架构
}

static uint64_t read_midr_el1_asm_on_cpu(int cpu_index) {
    return 0xFFFFFFFFFFFFFFFFULL;
}

#endif

/**
 * 通过 sysfs 读取指定 CPU 核心的 MIDR_EL1
 * 路径: /sys/devices/system/cpu/cpuX/regs/identification/midr_el1
 */
static uint64_t read_midr_el1_sysfs(int cpu_index) {
    char path[256];
    snprintf(path, sizeof(path),
             "/sys/devices/system/cpu/cpu%d/regs/identification/midr_el1",
             cpu_index);

    FILE* fp = fopen(path, "r");
    if (!fp) {
        LOGD("Failed to open %s", path);
        return 0xFFFFFFFFFFFFFFFFULL;
    }

    char buf[32] = {0};
    if (!fgets(buf, sizeof(buf), fp)) {
        fclose(fp);
        return 0xFFFFFFFFFFFFFFFFULL;
    }
    fclose(fp);

    // 解析十六进制值
    uint64_t val = strtoull(buf, nullptr, 16);
    return val;
}

/**
 * 获取系统 CPU 核心数量
 */
static int get_cpu_core_count() {
    return sysconf(_SC_NPROCESSORS_ONLN);
}

extern "C" {

JNIEXPORT jlong JNICALL
Java_qpdb_env_check_utils_SoCDetectionUtil_nativeReadMidrByAsm(
        JNIEnv* env, jclass clazz, jint cpuIndex) {
#ifdef __aarch64__
    uint64_t val = read_midr_el1_asm_on_cpu((int)cpuIndex);
    LOGD("MIDR_EL1 (asm cpu%d): 0x%016llx", (int)cpuIndex, (unsigned long long)val);
    return (jlong)val;
#else
    return -1;
#endif
}

JNIEXPORT jlong JNICALL
Java_qpdb_env_check_utils_SoCDetectionUtil_nativeReadMidrBySysfs(
        JNIEnv* env, jclass clazz, jint cpuIndex) {
    uint64_t val = read_midr_el1_sysfs((int)cpuIndex);
    LOGD("MIDR_EL1 (sysfs cpu%d): 0x%016llx", (int)cpuIndex, (unsigned long long)val);
    return (jlong)val;
}

JNIEXPORT jint JNICALL
Java_qpdb_env_check_utils_SoCDetectionUtil_nativeGetCpuCoreCount(
        JNIEnv* env, jclass clazz) {
    int count = get_cpu_core_count();
    LOGD("CPU core count: %d", count);
    return (jint)count;
}

} // extern "C"

#include <jni.h>
#include <android/log.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <math.h>
#include <pthread.h>
#include <sched.h>
#include <unistd.h>

#define LOG_TAG "TrickyStoreNative"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

#ifdef __aarch64__

static inline uint64_t read_cntvct_el0(void) {
    uint64_t val;
    __asm__ __volatile__ ("isb; mrs %0, cntvct_el0; isb" : "=r" (val));
    return val;
}

static inline uint64_t read_cntfrq_el0(void) {
    uint64_t freq;
    __asm__ __volatile__ ("mrs %0, cntfrq_el0" : "=r" (freq));
    return freq;
}

static uint64_t g_cntfrq = 0;

static uint64_t cntvct_to_ns(uint64_t cntvct) {
    if (g_cntfrq == 0) {
        g_cntfrq = read_cntfrq_el0();
        if (g_cntfrq == 0) g_cntfrq = 19200000;
    }
    uint64_t sec = cntvct / g_cntfrq;
    uint64_t rem = cntvct % g_cntfrq;
    return sec * 1000000000ULL + (rem * 1000000000ULL) / g_cntfrq;
}

static int compare_u64(const void* a, const void* b) {
    uint64_t av = *(const uint64_t*)a;
    uint64_t bv = *(const uint64_t*)b;
    if (av < bv) return -1;
    if (av > bv) return 1;
    return 0;
}

static volatile int cpu_burn_running = 0;

static void* cpu_burn_thread(void* arg) {
    (void)arg;
    cpu_burn_running = 1;
    volatile double dummy = 1.0;
    while (cpu_burn_running) {
        for (int i = 0; i < 500000; i++) {
            dummy = dummy * 1.00001 + 0.00001;
        }
    }
    return (void*)(uintptr_t)dummy;
}

static jboolean call_generate_keypair(JNIEnv* env, jboolean useStrongBox) {
    jclass clazz = env->FindClass("qpdb/env/check/utils/KeyAttestationUtil");
    if (!clazz) return JNI_FALSE;
    jmethodID method = env->GetStaticMethodID(clazz, "nativeTimingGenerateKeyPair", "(Z)Z");
    if (!method) return JNI_FALSE;
    jboolean ret = env->CallStaticBooleanMethod(clazz, method, useStrongBox);
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        return JNI_FALSE;
    }
    return ret;
}

static jboolean call_sign_data(JNIEnv* env, jstring alias, jbyteArray data) {
    jclass clazz = env->FindClass("qpdb/env/check/utils/KeyAttestationUtil");
    if (!clazz) return JNI_FALSE;
    jmethodID method = env->GetStaticMethodID(clazz, "nativeTimingSignData", "(Ljava/lang/String;[B)Z");
    if (!method) return JNI_FALSE;
    jboolean ret = env->CallStaticBooleanMethod(clazz, method, alias, data);
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        return JNI_FALSE;
    }
    return ret;
}

static void call_cleanup(JNIEnv* env) {
    jclass clazz = env->FindClass("qpdb/env/check/utils/KeyAttestationUtil");
    if (!clazz) return;
    jmethodID method = env->GetStaticMethodID(clazz, "nativeTimingCleanup", "()V");
    if (!method) return;
    env->CallStaticVoidMethod(clazz, method);
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
    }
}

static jboolean call_software_sign_data(JNIEnv* env, jbyteArray data) {
    jclass clazz = env->FindClass("qpdb/env/check/utils/KeyAttestationUtil");
    if (!clazz) return JNI_FALSE;
    jmethodID method = env->GetStaticMethodID(clazz, "nativeTimingSoftwareSignData", "([B)[B");
    if (!method) return JNI_FALSE;
    jbyteArray result = (jbyteArray)env->CallStaticObjectMethod(clazz, method, data);
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        return JNI_FALSE;
    }
    if (result) {
        env->DeleteLocalRef(result);
    } else {
        return JNI_FALSE;
    }
    return JNI_TRUE;
}

static void call_software_cleanup(JNIEnv* env) {
    jclass clazz = env->FindClass("qpdb/env/check/utils/KeyAttestationUtil");
    if (!clazz) return;
    jmethodID method = env->GetStaticMethodID(clazz, "nativeTimingSoftwareCleanup", "()V");
    if (!method) return;
    env->CallStaticVoidMethod(clazz, method);
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
    }
}

static int collect_sign_samples(JNIEnv* env, jstring alias, jbyteArray data,
                                 uint64_t* samples, int num_samples, const char* tag) {
    for (int i = 0; i < num_samples; i++) {
        uint64_t start = read_cntvct_el0();
        jboolean success = call_sign_data(env, alias, data);
        uint64_t end = read_cntvct_el0();
        if (!success) {
            LOGE("[%s] sign operation failed at sample %d", tag, i);
            return -1;
        }
        samples[i] = end - start;
    }
    return 0;
}

static void compute_stats(uint64_t* samples, int n,
                          uint64_t* out_mean, uint64_t* out_median,
                          uint64_t* out_std, uint64_t* out_min, uint64_t* out_max,
                          uint64_t* out_cv) {
    qsort(samples, n, sizeof(uint64_t), compare_u64);

    *out_min = samples[0];
    *out_max = samples[n - 1];
    *out_median = samples[n / 2];

    uint64_t sum = 0;
    for (int i = 0; i < n; i++) {
        sum += samples[i];
    }
    *out_mean = sum / n;

    double variance_sum = 0.0;
    for (int i = 0; i < n; i++) {
        double diff = (double)(int64_t)samples[i] - (double)(int64_t)*out_mean;
        variance_sum += diff * diff;
    }
    *out_std = (uint64_t)sqrt(variance_sum / n);

    // CV = std / mean * 100 (%), based on CNTVCT (same ratio in ns)
    *out_cv = (*out_mean > 0) ? ((*out_std * 100) / *out_mean) : 0;
}

extern "C" JNIEXPORT jstring JNICALL
Java_qpdb_env_check_utils_TrickyStoreUtil_nativeCheckTimingAttestation(
        JNIEnv* env, jclass clazz, jboolean useStrongBox) {
    (void)clazz;

    const int NUM_SAMPLES = 30;
    LOGI("[START] StrongBox=%d samples=%d", useStrongBox, NUM_SAMPLES);

    uint64_t* samples_idle = (uint64_t*)malloc(NUM_SAMPLES * sizeof(uint64_t));
    uint64_t* samples_load = (uint64_t*)malloc(NUM_SAMPLES * sizeof(uint64_t));
    if (!samples_idle || !samples_load) {
        LOGE("malloc failed");
        free(samples_idle);
        free(samples_load);
        return env->NewStringUTF("error=alloc_failed");
    }

    g_cntfrq = read_cntfrq_el0();
    if (g_cntfrq == 0) g_cntfrq = 19200000;

    // 1. 生成密钥对（计时）
    uint64_t gen_start = read_cntvct_el0();
    jboolean gen_ok = call_generate_keypair(env, useStrongBox);
    uint64_t gen_end = read_cntvct_el0();

    if (!gen_ok) {
        free(samples_idle);
        free(samples_load);
        return env->NewStringUTF("error=keygen_failed");
    }
    uint64_t gen_duration = gen_end - gen_start;

    // 2. 准备签名数据
    jstring alias = env->NewStringUTF("envcheck_timing");
    jbyteArray data = env->NewByteArray(32);
    if (!data) {
        free(samples_idle);
        free(samples_load);
        env->DeleteLocalRef(alias);
        call_cleanup(env);
        return env->NewStringUTF("error=alloc_data");
    }
    jbyte nonce[32] = {0};
    env->SetByteArrayRegion(data, 0, 32, nonce);

    // 预热：执行几次让缓存和 TEE 预热
    for (int i = 0; i < 5; i++) {
        if (!call_sign_data(env, alias, data)) {
            break;
        }
    }

    // 3. 空闲状态采集签名样本
    if (collect_sign_samples(env, alias, data, samples_idle, NUM_SAMPLES, "IDLE") < 0) {
        free(samples_idle);
        free(samples_load);
        env->DeleteLocalRef(alias);
        env->DeleteLocalRef(data);
        call_cleanup(env);
        return env->NewStringUTF("error=sign_idle_failed");
    }

    // 4. 启动 CPU 负载线程
    cpu_burn_running = 0;
    pthread_t burn_tid;
    pthread_create(&burn_tid, NULL, cpu_burn_thread, NULL);
    while (!cpu_burn_running) {
        sched_yield();
    }
    usleep(200000); // 让负载稳定运行 200ms

    // 5. CPU 负载下采集签名样本
    if (collect_sign_samples(env, alias, data, samples_load, NUM_SAMPLES, "LOAD") < 0) {
        cpu_burn_running = 0;
        pthread_join(burn_tid, NULL);
        free(samples_idle);
        free(samples_load);
        env->DeleteLocalRef(alias);
        env->DeleteLocalRef(data);
        call_cleanup(env);
        return env->NewStringUTF("error=sign_load_failed");
    }

    // 停止负载
    cpu_burn_running = 0;
    pthread_join(burn_tid, NULL);

    // 6. 计算统计特征
    uint64_t idle_mean, idle_median, idle_std, idle_min, idle_max, idle_cv;
    uint64_t load_mean, load_median, load_std, load_min, load_max, load_cv;

    compute_stats(samples_idle, NUM_SAMPLES, &idle_mean, &idle_median, &idle_std, &idle_min, &idle_max, &idle_cv);
    compute_stats(samples_load, NUM_SAMPLES, &load_mean, &load_median, &load_std, &load_min, &load_max, &load_cv);

    // 转换为纳秒 (CV 是百分比，CNTVCT 和 ns 相同)
    uint64_t gen_ns         = cntvct_to_ns(gen_duration);
    uint64_t idle_mean_ns   = cntvct_to_ns(idle_mean);
    uint64_t idle_median_ns = cntvct_to_ns(idle_median);
    uint64_t idle_std_ns    = cntvct_to_ns(idle_std);
    uint64_t idle_min_ns    = cntvct_to_ns(idle_min);
    uint64_t idle_max_ns    = cntvct_to_ns(idle_max);
    uint64_t load_mean_ns   = cntvct_to_ns(load_mean);
    uint64_t load_median_ns = cntvct_to_ns(load_median);
    uint64_t load_std_ns    = cntvct_to_ns(load_std);
    uint64_t load_min_ns    = cntvct_to_ns(load_min);
    uint64_t load_max_ns    = cntvct_to_ns(load_max);
    uint64_t idle_cv_pct    = idle_cv;
    uint64_t load_cv_pct    = load_cv;

    LOGI("[STATS] gen=%lluns idle=(mean=%llu med=%llu std=%llu min=%llu max=%llu cv=%llu%%) load=(mean=%llu med=%llu std=%llu min=%llu max=%llu cv=%llu%%)",
         (unsigned long long)gen_ns,
         (unsigned long long)idle_mean_ns, (unsigned long long)idle_median_ns,
         (unsigned long long)idle_std_ns, (unsigned long long)idle_min_ns,
         (unsigned long long)idle_max_ns, (unsigned long long)idle_cv_pct,
         (unsigned long long)load_mean_ns, (unsigned long long)load_median_ns,
         (unsigned long long)load_std_ns, (unsigned long long)load_min_ns,
         (unsigned long long)load_max_ns, (unsigned long long)load_cv_pct);

    // === BC 软件签名对照（双 provider 对比）===
    // 用系统默认纯软件签名作为标尺，与 KeyStore 签名对比
    // 真实 TEE/StrongBox：KeyStore 签名与软件签名不成比例
    // TEESimulator：KeyStore 签名 ≈ 软件签名（本质上都是软件实现）
    uint64_t* samples_bc = (uint64_t*)malloc(NUM_SAMPLES * sizeof(uint64_t));
    if (samples_bc) {
        for (int i = 0; i < NUM_SAMPLES; i++) {
            uint64_t start = read_cntvct_el0();
            jboolean success = call_software_sign_data(env, data);
            uint64_t end = read_cntvct_el0();
            if (!success) {
                LOGE("[BC] sign failed at sample %d", i);
                break;
            }
            samples_bc[i] = end - start;
        }
    }

    uint64_t bc_mean = 0, bc_median = 0, bc_std = 0, bc_min = 0, bc_max = 0, bc_cv = 0;
    if (samples_bc) {
        compute_stats(samples_bc, NUM_SAMPLES, &bc_mean, &bc_median, &bc_std, &bc_min, &bc_max, &bc_cv);
    }
    uint64_t bc_mean_ns = cntvct_to_ns(bc_mean);
    uint64_t bc_median_ns = cntvct_to_ns(bc_median);
    uint64_t bc_std_ns    = cntvct_to_ns(bc_std);
    uint64_t bc_min_ns    = cntvct_to_ns(bc_min);
    uint64_t bc_max_ns    = cntvct_to_ns(bc_max);
    uint64_t bc_cv_pct    = bc_cv;

    // 计算 KeyStore 签名 / BC 软件签名 比例
    double ks_bc_ratio = (bc_mean_ns > 0) ? ((double)idle_mean_ns / (double)bc_mean_ns) : 0.0;
    LOGI("[BC] mean=%lluns cv=%llu%% ks_bc_ratio=%.1f",
         (unsigned long long)bc_mean_ns, (unsigned long long)bc_cv_pct, ks_bc_ratio);

    // 7. 判别逻辑
    // 真实 TEE/StrongBox：独立运行环境，方差小，负载前后差异小，耗时稳定
    // 软件模拟（Tricky Store）：运行在 REE 中，方差大，绝对耗时快得多
    int suspicious = 0;

    // 指标 1：变异系数过大
    // 真实 StrongBox（eSE）CV 通常 < 3%，真实 TEE 受 Binder 调度影响可能达到 10-15%
    // Tricky Store 软件模拟 CV 通常 > 30%
    uint64_t idle_cv_threshold = useStrongBox ? 10 : 25;
    if (idle_cv_pct > idle_cv_threshold) {
        suspicious++;
        LOGI("[EVAL-1] TRIGGERED: idle_cv=%llu%% > %llu%%",
             (unsigned long long)idle_cv_pct, (unsigned long long)idle_cv_threshold);
    }

    // 指标 2：负载下方差相对于空闲状态显著增大
    // 真实 TEE 受 keystore service / Binder 调度影响，jitter_ratio 可能达到 200-250%
    // 真实 StrongBox（eSE）与主 CPU 隔离，抖动通常 < 150%
    // Tricky Store 软件模拟在 CPU 负载下抖动极大，通常 > 400%
    uint64_t jitter_ratio = (idle_std_ns > 0) ? ((load_std_ns * 100) / idle_std_ns) : 0;
    uint64_t jitter_threshold = useStrongBox ? 250 : 350;
    if (jitter_ratio > jitter_threshold) {
        suspicious++;
        LOGI("[EVAL-2] TRIGGERED: jitter_ratio=%llu%% > %llu%%",
             (unsigned long long)jitter_ratio, (unsigned long long)jitter_threshold);
    }

    // 指标 3：负载下均值显著增加（> 3ms）
    uint64_t mean_diff = (load_mean_ns > idle_mean_ns) ? (load_mean_ns - idle_mean_ns) : 0;
    if (mean_diff > 3000000) {
        suspicious++;
        LOGI("[EVAL-3] TRIGGERED: mean_diff=%lluns > 3ms", (unsigned long long)mean_diff);
    }

    // 指标 4：空闲时最大最小比过大
    // 真实 StrongBox 通常 < 120%，真实 TEE 受调度影响可能达到 150-180%
    uint64_t spread_ratio = (idle_min_ns > 0) ? ((idle_max_ns * 100) / idle_min_ns) : 0;
    uint64_t spread_threshold = useStrongBox ? 150 : 200;
    if (spread_ratio > spread_threshold) {
        suspicious++;
        LOGI("[EVAL-4] TRIGGERED: spread_ratio=%llu%% > %llu%%",
             (unsigned long long)spread_ratio, (unsigned long long)spread_threshold);
    }

    // 指标 5：中位数与均值偏离过大（> 15%）
    uint64_t median_mean_ratio = (idle_mean_ns > 0) ? ((idle_median_ns * 100) / idle_mean_ns) : 0;
    if (median_mean_ratio < 85 || median_mean_ratio > 115) {
        suspicious++;
        LOGI("[EVAL-5] TRIGGERED: median_mean_ratio=%llu%% out of [85,115]", (unsigned long long)median_mean_ratio);
    }

    // 指标 6：绝对签名耗时过快
    uint64_t sign_speed_threshold_ns = useStrongBox ? 50000000 : 5000000;
    if (idle_mean_ns < sign_speed_threshold_ns) {
        suspicious += 2;
        LOGI("[EVAL-6] TRIGGERED: idle_mean=%lluns < %lluns (%s)",
             (unsigned long long)idle_mean_ns,
             (unsigned long long)sign_speed_threshold_ns,
             useStrongBox ? "StrongBox" : "TEE");
    }

    // 指标 7：密钥生成耗时过快
    if (gen_ns < 15000000) {
        suspicious += 2;
        LOGI("[EVAL-7] TRIGGERED: gen_ns=%lluns < 15ms", (unsigned long long)gen_ns);
    }

    // 指标 8：密钥生成 / 签名耗时比例异常
    // 真实 TEE 签名很快（< 20ms），生成相对较慢，比例通常 > 300%
    // 真实 StrongBox 签名也很慢（eSE 通信开销，> 100ms），比例可能 < 250%，属于正常
    // 对 TEE 保持 250%，对 StrongBox 放宽到 150%
    uint64_t gen_sign_ratio = (idle_mean_ns > 0) ? ((gen_ns * 100) / idle_mean_ns) : 0;
    uint64_t gen_sign_threshold = useStrongBox ? 150 : 250;
    if (!useStrongBox && gen_sign_ratio > 0 && gen_sign_ratio < gen_sign_threshold) {
        suspicious += 2;
        LOGI("[EVAL-8] TRIGGERED: gen_sign_ratio=%llu%% < %llu%% (TEE)",
             (unsigned long long)gen_sign_ratio, (unsigned long long)gen_sign_threshold);
    }

    // 指标 9：负载下反而更快（负漂移）
    // 使用相对阈值：负漂移超过 idle_mean 的一定比例且绝对值 > 1ms 才判定异常
    // StrongBox 阈值 5%（慢速操作噪声小），TEE 阈值 15%（Binder 调度波动更大）
    uint64_t negative_drift = (idle_mean_ns > load_mean_ns) ? (idle_mean_ns - load_mean_ns) : 0;
    uint64_t negative_drift_pct = (idle_mean_ns > 0) ? (negative_drift * 100 / idle_mean_ns) : 0;
    uint64_t negative_drift_pct_threshold = useStrongBox ? 5 : 15;
    if (negative_drift > 1000000 && negative_drift_pct > negative_drift_pct_threshold) {
        suspicious++;
        LOGI("[EVAL-9] TRIGGERED: negative_drift=%lluns (%llu%%) (load faster than idle)",
             (unsigned long long)negative_drift, (unsigned long long)negative_drift_pct);
    }

    // 指标 10：KeyStore/BC 软件签名比例异常
    // 真实 StrongBox（eSE）签名极慢，比例通常 > 500
    // 真实 TEE 因设备实现差异大，比例范围约 10-100；伪装 TEE（软件模拟）比例接近 1-3
    // 将 TEE 阈值从 35 放宽到 15，避免对较慢 TEE 实现（如小米 14 的 ~26x）误报
    uint64_t ks_bc_ratio_threshold = useStrongBox ? 200 : 15;
    if (ks_bc_ratio > 0.01 && ks_bc_ratio < ks_bc_ratio_threshold) {
        suspicious += 2;
        LOGI("[EVAL-10] TRIGGERED: ks_bc_ratio=%.1f < %llu", ks_bc_ratio, (unsigned long long)ks_bc_ratio_threshold);
    }

    // 指标 11：idle 变异系数异常高于 load 变异系数
    uint64_t cv_diff = (idle_cv_pct > load_cv_pct) ? (idle_cv_pct - load_cv_pct) : 0;
    if (cv_diff > 5) {
        suspicious++;
        LOGI("[EVAL-11] TRIGGERED: cv_diff=%llu%% (idle_cv=%llu%% > load_cv=%llu%%)",
             (unsigned long long)cv_diff,
             (unsigned long long)idle_cv_pct,
             (unsigned long long)load_cv_pct);
    }

    // 8. 清理密钥
    call_cleanup(env);
    call_software_cleanup(env);

    char result[2048];
    snprintf(result, sizeof(result),
             "suspicious=%d|gen_ns=%llu"
             "|idle_mean=%llu|idle_median=%llu|idle_std=%llu|idle_min=%llu|idle_max=%llu|idle_cv=%llu"
             "|load_mean=%llu|load_median=%llu|load_std=%llu|load_min=%llu|load_max=%llu|load_cv=%llu"
             "|jitter_ratio=%llu|mean_diff=%llu|spread_ratio=%llu|median_mean_ratio=%llu"
             "|gen_sign_ratio=%llu|negative_drift=%llu"
             "|bc_mean=%llu|bc_median=%llu|bc_std=%llu|bc_min=%llu|bc_max=%llu|bc_cv=%llu"
             "|ks_bc_ratio=%d|cv_diff=%llu",
             suspicious,
             (unsigned long long)gen_ns,
             (unsigned long long)idle_mean_ns,
             (unsigned long long)idle_median_ns,
             (unsigned long long)idle_std_ns,
             (unsigned long long)idle_min_ns,
             (unsigned long long)idle_max_ns,
             (unsigned long long)idle_cv_pct,
             (unsigned long long)load_mean_ns,
             (unsigned long long)load_median_ns,
             (unsigned long long)load_std_ns,
             (unsigned long long)load_min_ns,
             (unsigned long long)load_max_ns,
             (unsigned long long)load_cv_pct,
             (unsigned long long)jitter_ratio,
             (unsigned long long)mean_diff,
             (unsigned long long)spread_ratio,
             (unsigned long long)median_mean_ratio,
             (unsigned long long)gen_sign_ratio,
             (unsigned long long)negative_drift,
             (unsigned long long)bc_mean_ns,
             (unsigned long long)bc_median_ns,
             (unsigned long long)bc_std_ns,
             (unsigned long long)bc_min_ns,
             (unsigned long long)bc_max_ns,
             (unsigned long long)bc_cv_pct,
             (int)(ks_bc_ratio * 1000),
             (unsigned long long)cv_diff);

    LOGI("[END] score=%d %s", suspicious, result);

    free(samples_idle);
    free(samples_load);
    free(samples_bc);
    env->DeleteLocalRef(alias);
    env->DeleteLocalRef(data);

    return env->NewStringUTF(result);
}

#else // !__aarch64__

extern "C" JNIEXPORT jstring JNICALL
Java_qpdb_env_check_utils_TrickyStoreUtil_nativeCheckTimingAttestation(
        JNIEnv* env, jclass clazz, jboolean useStrongBox) {
    (void)clazz;
    (void)useStrongBox;
    return env->NewStringUTF("error=unsupported_arch");
}

#endif // __aarch64__

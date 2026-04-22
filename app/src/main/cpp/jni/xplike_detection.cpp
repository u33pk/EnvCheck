#include <jni.h>
#include <android/log.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define LOG_TAG "XPLikeNative"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// XPLike (Vector/LSPosed) 在 /proc/self/maps 中的特征字符串
static const char* XP_MAPS_KEYWORDS[] = {
    "liboat_hook.so",
    "liboat_hook_memfd",
    "Vector_",
    "Dobby",
    "xposed/dummy/XResourcesSuperClass",
    "xposed/dummy/XTypedArraySuperClass",
    "InMemoryDexClassLoader",
    "org.matrix.vector",
    "de.robv.android.xposed",
    nullptr
};

/**
 * 读取 /proc/self/maps，查找 XPLike 框架相关的内存映射特征。
 *
 * 文档列出的特征：
 * - liboat_hook.so / liboat_hook_memfd（dex2oat hook 库）
 * - Vector_（ART 动态生成的类前缀）
 * - Dobby（inline hook 引擎标识）
 * - xposed/dummy/XResourcesSuperClass（资源 hook 虚拟类）
 * - InMemoryDexClassLoader（内存 DEX 加载器）
 * - org.matrix.vector / de.robv.android.xposed（包名路径）
 */
extern "C" JNIEXPORT jstring JNICALL
Java_qpdb_env_check_utils_XPLikeUtil_nativeCheckMaps(
        JNIEnv* env, jclass clazz) {
    const char* maps_path = "/proc/self/maps";
    FILE* fp = fopen(maps_path, "r");
    if (!fp) {
        LOGE("无法打开 %s", maps_path);
        return env->NewStringUTF("");
    }

    char line[512];
    char result[1024] = {0};
    size_t result_len = 0;

    while (fgets(line, sizeof(line), fp)) {
        const char** keyword = XP_MAPS_KEYWORDS;
        while (*keyword != nullptr) {
            if (strstr(line, *keyword) != nullptr) {
                line[strcspn(line, "\n")] = 0;
                if (result_len > 0) {
                    strncat(result, ", ", sizeof(result) - result_len - 1);
                    result_len += 2;
                }
                // 只记录特征关键词，避免结果过长
                strncat(result, *keyword, sizeof(result) - result_len - 1);
                result_len += strlen(*keyword);
                if (result_len >= sizeof(result) - 64) {
                    fclose(fp);
                    return env->NewStringUTF(result);
                }
                break; // 一行只记录一个特征
            }
            keyword++;
        }
    }
    fclose(fp);

    return env->NewStringUTF(result);
}

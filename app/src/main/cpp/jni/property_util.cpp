#include <jni.h>
#include <string>
#include "properties/system_properties.h"

#define PROP_VALUE_MAX 92

/**
 * 获取系统属性值
 */
extern "C" JNIEXPORT jstring JNICALL
Java_qpdb_env_check_utils_PropertyUtil_nativeGetProp(
        JNIEnv* env,
        jclass clazz,
        jstring propName) {
    const char* prop_name = env->GetStringUTFChars(propName, nullptr);
    char buffer[PROP_VALUE_MAX] = {0};

    int result = native_getprop(prop_name, buffer, sizeof(buffer));

    env->ReleaseStringUTFChars(propName, prop_name);

    if (result == 0) {
        return env->NewStringUTF(buffer);
    } else {
        return env->NewStringUTF("");
    }
}

/**
 * 设置系统属性值
 */
extern "C" JNIEXPORT jboolean JNICALL
Java_qpdb_env_check_utils_PropertyUtil_nativeSetProp(
        JNIEnv* env,
        jclass clazz,
        jstring propName,
        jstring propValue) {
    const char* prop_name = env->GetStringUTFChars(propName, nullptr);
    const char* prop_value = env->GetStringUTFChars(propValue, nullptr);

    int result = native_setprop(prop_name, prop_value);

    env->ReleaseStringUTFChars(propName, prop_name);
    env->ReleaseStringUTFChars(propValue, prop_value);

    return (result == 0) ? JNI_TRUE : JNI_FALSE;
}

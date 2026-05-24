#include <jni.h>
#include <string>
#include <cstdlib>

extern "C" char *native_getallprop(size_t *out_len);

extern "C" JNIEXPORT jstring JNICALL
Java_qpdb_env_check_MainActivity_stringFromJNI(
        JNIEnv* env,
        jobject /* this */) {
    std::string hello = "Hello from C++";
    return env->NewStringUTF(hello.c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_qpdb_env_check_utils_PropertyUtil_nativeGetAllProp(
        JNIEnv* env,
        jclass /* clazz */) {
    size_t len = 0;
    char *buffer = native_getallprop(&len);
    if (buffer == NULL) {
        return env->NewStringUTF("");
    }
    jstring result = env->NewStringUTF(buffer);
    free(buffer);
    return result;
}

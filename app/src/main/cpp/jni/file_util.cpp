#include <jni.h>
#include <sys/stat.h>
#include <errno.h>

/**
 * 检查文件是否存在 (使用 stat 函数)
 * 特性：只需要对目录有搜索权限，不需要对文件本身有读写权限
 *
 * 注意：当父目录无搜索权限时（EACCES），此方法会返回 true，这可能导致误报。
 * 对于需要精确区分的场景（如判断 /data/adb/ 下的 root 特征文件），
 * 请使用 nativeCheckFileStatus()。
 */
extern "C" JNIEXPORT jboolean JNICALL
Java_qpdb_env_check_utils_FileUtil_fileExists(
        JNIEnv* env,
        jclass clazz,
        jstring filePath) {
    const char* path = env->GetStringUTFChars(filePath, nullptr);
    struct stat st;
    jboolean exists = false;
    int ret = stat(path, &st);
    if(ret == 0){
        exists = true;
    } else {
        if(errno == ENOENT)
            exists = false;
        else if(errno == EACCES)
            exists = true;
    }
    env->ReleaseStringUTFChars(filePath, path);
    return exists;
}

/**
 * 精确检查文件状态
 * 返回值： 1 = 文件存在
 *         0 = 文件不存在（ENOENT）
 *        -1 = 权限不足或其他错误（无法判断）
 */
extern "C" JNIEXPORT jint JNICALL
Java_qpdb_env_check_utils_FileUtil_nativeCheckFileStatus(
        JNIEnv* env,
        jclass clazz,
        jstring filePath) {
    const char* path = env->GetStringUTFChars(filePath, nullptr);
    struct stat st;
    int ret = stat(path, &st);
    jint result;
    if (ret == 0) {
        result = 1; // 存在
    } else {
        if (errno == ENOENT) {
            result = 0; // 不存在
        } else if (errno == EACCES || errno == EPERM) {
            result = -1; // 权限不足，无法判断
        } else {
            result = -1; // 其他错误也视为无法判断
        }
    }
    env->ReleaseStringUTFChars(filePath, path);
    return result;
}

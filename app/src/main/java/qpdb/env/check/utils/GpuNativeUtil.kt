package qpdb.env.check.utils

/**
 * GPU 相关 JNI Native 方法封装
 */
object GpuNativeUtil {
    init {
        System.loadLibrary("check")
    }

    @JvmStatic
    external fun nativeGetVulkanInfo(): String

    @JvmStatic
    external fun nativeGetVulkanExtensions(): String

    @JvmStatic
    external fun nativeIsSoLoaded(soName: String): Boolean
}

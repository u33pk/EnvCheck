package qpdb.env.check.utils

/**
 * XPLike (Vector/LSPosed) 检测工具类
 * 提供 JNI native 方法进行内存映射检测
 */
object XPLikeUtil {
    init {
        System.loadLibrary("check")
    }

    /**
     * 读取 /proc/self/maps，查找 XPLike 框架相关的内存映射特征
     * @return 匹配到的特征列表，逗号分隔；空字符串表示未找到
     */
    @JvmStatic
    external fun nativeCheckMaps(): String
}

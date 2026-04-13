package qpdb.env.check.utils

/**
 * 属性工具类 (使用 JNI native 方法)
 * 直接读取系统属性，不需要执行 shell 命令
 */
object PropertyUtil {
    init {
        System.loadLibrary("check")
    }

    /**
     * 获取系统属性值
     *
     * @param name 属性名称
     * @return 属性值，如果获取失败返回空字符串
     */
    @JvmStatic
    external fun nativeGetProp(name: String): String

    /**
     * 设置系统属性值
     *
     * @param name 属性名称
     * @param value 属性值
     * @return true 表示成功，false 表示失败
     */
    @JvmStatic
    external fun nativeSetProp(name: String, value: String): Boolean

    /**
     * 获取系统属性值 (Kotlin 风格包装)
     *
     * @param name 属性名称
     * @return 属性值，如果获取失败返回 null
     */
    @JvmStatic
    fun getProp(name: String): String? {
        val result = nativeGetProp(name)
        return if (result.isNotEmpty()) result else null
    }

    /**
     * 设置系统属性值 (Kotlin 风格包装)
     *
     * @param name 属性名称
     * @param value 属性值
     * @return true 表示成功，false 表示失败
     */
    @JvmStatic
    fun setProp(name: String, value: String): Boolean {
        return nativeSetProp(name, value)
    }
}

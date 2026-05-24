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
     * 获取所有系统属性（JNI 原生方法）
     *
     * @return 所有可读的属性字符串，格式为每行 "key=value"
     */
    @JvmStatic
    external fun nativeGetAllProp(): String

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

    /**
     * 获取所有系统属性 (Kotlin 风格包装)
     *
     * @return 所有可读属性的 Map<name, value>，失败返回空 Map
     */
    @JvmStatic
    fun getAllProp(): Map<String, String> {
        val result = mutableMapOf<String, String>()
        val allProps = nativeGetAllProp()
        if (allProps.isEmpty()) {
            return result
        }
        allProps.lineSequence().forEach { line ->
            val idx = line.indexOf('=')
            if (idx > 0) {
                val key = line.substring(0, idx)
                val value = line.substring(idx + 1)
                result[key] = value
            }
        }
        return result
    }
}

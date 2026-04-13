package qpdb.env.check.utils

import android.util.Log
import qpdb.env.check.utils.PropertyUtil.getProp

/**
 * 系统属性获取工具类
 * 优先使用 JNI native 方法，失败时回退到 shell 命令
 */
object SystemPropertyUtil {
    private const val TAG = "SystemPropertyUtil"

    /**
     * 获取系统属性值
     * 优先使用 native 方法，失败时使用 shell 命令
     * @param property 属性名称
     * @return 属性值，如果获取失败返回空字符串
     */
    fun getSystemProperty(property: String): String {
        val nativeResult = getProp(property)
        if (nativeResult != null) {
            return nativeResult
        }

        return try {
            val process = Runtime.getRuntime().exec("getprop $property")
            val reader = java.io.BufferedReader(java.io.InputStreamReader(process.inputStream))
            val value = reader.readLine()?.trim() ?: ""
            reader.close()
            value
        } catch (e: Exception) {
            Log.e(TAG, "getSystemProperty($property) 出错: ${e.message}")
            ""
        }
    }
}

package qpdb.env.check.utils

/**
 * 文件工具类 (使用 JNI native 方法)
 * 使用 stat 函数检查文件是否存在，不需要对文件本身拥有权限
 */
object FileUtil {
    init {
        System.loadLibrary("check")
    }

    /**
     * 检查文件是否存在
     * 使用 stat 函数，只需要对目录有搜索权限即可
     *
     * @param filePath 文件路径
     * @return true 表示文件存在，false 表示文件不存在或无法访问
     */
    @JvmStatic
    external fun fileExists(filePath: String): Boolean

    /**
     * 精确检查文件状态
     * 返回值： 1 = 文件存在
     *         0 = 文件不存在
     *        -1 = 权限不足或其他错误，无法判断
     *
     * @param filePath 文件路径
     */
    @JvmStatic
    external fun nativeCheckFileStatus(filePath: String): Int
}

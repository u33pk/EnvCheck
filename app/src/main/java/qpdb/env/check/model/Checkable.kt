package qpdb.env.check.model

/**
 * 可检测接口
 * 所有检测类需要实现此接口
 */
interface Checkable {
    /**
     * 获取分类名称
     */
    val categoryName: String

    /**
     * 获取检测列表
     * @return 检测项列表
     */
    fun checkList(): List<CheckItem>

    /**
     * 执行检测（可选）
     * 可以在这里实现自动检测逻辑
     */
    fun runCheck(): List<CheckItem> {
        return checkList()
    }

    /**
     * 执行检测并实时回调每个检测项的结果
     * 默认实现先执行 runCheck()，然后一次性回调所有结果
     */
    suspend fun runCheckWithProgress(onProgress: suspend (CheckItem) -> Unit): List<CheckItem> {
        val results = runCheck()
        results.forEach { onProgress(it) }
        return results
    }
}

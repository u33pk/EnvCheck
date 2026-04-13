package qpdb.env.check.model

/**
 * 分类数据类
 * 由 Checkable 接口实现类动态生成
 */
data class Category(
    val id: String = java.util.UUID.randomUUID().toString(),
    val name: String,
    var isExpanded: Boolean = true,
    val items: MutableList<CheckItem> = mutableListOf()
) {
    fun getPassedCount(): Int = items.count { it.status == CheckStatus.PASS }

    fun getInfoCount(): Int = items.count { it.status == CheckStatus.INFO }

    fun getFailedCount(): Int = items.count { it.status == CheckStatus.FAIL }

    fun getTotalCount(): Int = items.size

    fun getProgress(): Int = if (items.isEmpty()) 0 else (getPassedCount() * 100 / getTotalCount())

    fun updateItemStatus(itemId: String, status: CheckStatus) {
        items.find { it.id == itemId }?.status = status
    }

    fun updateItemChecked(itemId: String, checked: Boolean) {
        items.find { it.id == itemId }?.isChecked = checked
    }
}

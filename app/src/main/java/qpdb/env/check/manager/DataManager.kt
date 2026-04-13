package qpdb.env.check.manager

import android.util.Log
import qpdb.env.check.adapter.CategoryAdapter
import qpdb.env.check.model.Category

/**
 * 数据管理器
 * 负责管理应用数据和适配器
 */
object DataManager {

    private const val TAG = "DataManager"

    /**
     * 更新分类数据到适配器
     */
    fun updateCategories(adapter: CategoryAdapter, categories: List<Category>) {
        Log.d(TAG, "更新分类数据到适配器，共 ${categories.size} 个分类")
        adapter.setCategories(categories)
    }

    /**
     * 获取分类统计信息
     */
    fun getCategoryStatistics(categories: List<Category>): CategoryStats {
        val totalCategories = categories.size
        val totalItems = categories.sumOf { it.items.size }
        val passedItems = categories.sumOf { it.getPassedCount() }
        val progress = if (totalItems == 0) 0 else (passedItems * 100 / totalItems)

        return CategoryStats(
            totalCategories = totalCategories,
            totalItems = totalItems,
            passedItems = passedItems,
            progress = progress
        )
    }

    /**
     * 更新单个分类的状态
     */
    fun updateCategoryStatus(adapter: CategoryAdapter, category: Category) {
        Log.d(TAG, "更新分类状态：${category.name}")
        adapter.updateCategory(category)
    }

    /**
     * 展开/折叠分类
     */
    fun toggleCategoryExpansion(adapter: CategoryAdapter, category: Category, position: Int) {
        category.isExpanded = !category.isExpanded
        adapter.notifyItemChanged(position)
        Log.d(TAG, "切换分类展开状态：${category.name}, isExpanded=${category.isExpanded}")
    }

    /**
     * 获取分类数据快照
     */
    fun getCategorySnapshot(categories: List<Category>): List<Category> {
        return categories.map { category ->
            Category(
                id = category.id,
                name = category.name,
                isExpanded = category.isExpanded,
                items = category.items.map { it.copy() }.toMutableList()
            )
        }
    }
}

/**
 * 分类统计信息
 */
data class CategoryStats(
    val totalCategories: Int,
    val totalItems: Int,
    val passedItems: Int,
    val progress: Int
)

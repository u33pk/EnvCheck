package qpdb.env.check.manager

import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import qpdb.env.check.model.Category
import qpdb.env.check.model.CheckItem
import qpdb.env.check.model.Checkable
import qpdb.env.check.model.CheckerRegistry

/**
 * 检测器管理器
 * 负责检测器的注册、管理和执行检测
 */
object CheckerManager {

    private const val TAG = "CheckerManager"

    /**
     * 初始化并注册所有检测器
     */
    fun initialize() {
        Log.d(TAG, "初始化检测器管理器")
        CheckerRegistry.clear()
        registerDefaultCheckers()
        Log.d(TAG, "已注册 ${CheckerRegistry.size()} 个检测器")
    }

    /**
     * 注册默认检测器
     */
    private fun registerDefaultCheckers() {
        // 使用反射或手动注册检测器
        // 这里采用手动注册方式
        CheckerRegistry.registerAll(
//            qpdb.env.check.checkers.BootloaderLockChecker(),
//            qpdb.env.check.checkers.BatteryChecker(),      // 电池信息检测
//            qpdb.env.check.checkers.DeveloperChecker(),  // 开发者模式和 ADB 检测
//            qpdb.env.check.checkers.SimCardChecker(),    // SIM 卡信息检测
//            qpdb.env.check.checkers.WebViewFingerPrintChecker(),  // WebView 指纹检测
//            qpdb.env.check.checkers.InputDeviceChecker(),  // 输入设备检测
//            qpdb.env.check.checkers.NetworkChecker(),    // 网络环境检测
//            qpdb.env.check.checkers.GpuChecker(),        // GPU 信息检测
//            qpdb.env.check.checkers.KernelSUChecker(),   // KernelSU 检测
            qpdb.env.check.checkers.APatchChecker(),     // APatch 检测
//            qpdb.env.check.checkers.KernelInfoChecker(), // 内核信息检测
        )
    }

    /**
     * 注册单个检测器
     */
    fun registerChecker(checker: Checkable) {
        CheckerRegistry.register(checker)
        Log.d(TAG, "注册检测器：${checker.categoryName}")
    }

    /**
     * 注册多个检测器
     */
    fun registerCheckers(vararg checkers: Checkable) {
        CheckerRegistry.registerAll(*checkers)
        Log.d(TAG, "批量注册 ${checkers.size} 个检测器")
    }

    /**
     * 加载所有分类（不执行实际检测）
     */
    fun loadCategories(): List<Category> {
        Log.d(TAG, "加载检测分类")
        val categories = mutableListOf<Category>()

        CheckerRegistry.getAllCheckers().forEach { checker ->
            val category = Category(name = checker.categoryName, isExpanded = false)
            val checkItems = checker.checkList().map { item ->
                CheckItem(
                    name = item.name,
                    checkPoint = item.checkPoint,
                    description = item.description,
                    status = item.status
                )
            }.toMutableList()
            category.items.addAll(checkItems)
            categories.add(category)
        }

        Log.d(TAG, "加载了 ${categories.size} 个分类，共 ${categories.sumOf { it.items.size }} 个检测项")
        return categories
    }

    /**
     * 执行所有检测（在后台线程执行）
     */
    suspend fun runAllChecks(): List<Category> = withContext(Dispatchers.IO) {
        Log.d(TAG, "开始执行所有检测")
        val categories = mutableListOf<Category>()

        CheckerRegistry.getAllCheckers().forEach { checker ->
            try {
                Log.d(TAG, "执行检测器：${checker.categoryName}")
                val category = Category(name = checker.categoryName, isExpanded = true)
                    val checkItems = checker.runCheck().toMutableList()

                Log.d(TAG, "检测器 ${checker.categoryName} 返回 ${checkItems.size} 个检测项")
                checkItems.forEach { item ->
                    Log.d(TAG, "  - ${item.name}: status=${item.status}")
                }

                category.items.addAll(checkItems)
                categories.add(category)
            } catch (e: Exception) {
                Log.e(TAG, "执行检测器 ${checker.categoryName} 失败：${e.message}", e)
            }
        }

        val passedCount = categories.sumOf { it.getPassedCount() }
        val totalCount = categories.sumOf { it.getTotalCount() }
        Log.d(TAG, "检测完成：$passedCount/$totalCount 通过")

        categories
    }

    /**
     * 获取已注册检测器数量
     */
    fun getCheckerCount(): Int = CheckerRegistry.size()

    /**
     * 获取所有已注册检测器
     */
    fun getAllCheckers(): List<Checkable> = CheckerRegistry.getAllCheckers()

    /**
     * 清除所有检测器
     */
    fun clear() {
        CheckerRegistry.clear()
        Log.d(TAG, "已清除所有检测器")
    }
}

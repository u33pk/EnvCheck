package qpdb.env.check

import android.os.Bundle
import android.util.Log
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.updatePadding
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import kotlinx.coroutines.launch
import qpdb.env.check.adapter.CategoryAdapter
import qpdb.env.check.databinding.ActivityMainBinding
import qpdb.env.check.manager.CheckerManager
import qpdb.env.check.manager.DataManager
import qpdb.env.check.manager.UIManager
import qpdb.env.check.utils.PermissionUtil
import android.content.Intent

/**
 * 主活动
 * 负责 UI 初始化和用户交互处理
 */
class MainActivity : AppCompatActivity() {

    companion object {
        private const val TAG = "MainActivity"
    }

    private lateinit var binding: ActivityMainBinding
    private lateinit var adapter: CategoryAdapter

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // 初始化视图绑定
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        // 设置沉浸式适配
        setupEdgeToEdge()

        // 初始化 UI 组件
        initViews()

        // 初始化检测器
        initCheckers()

        // 加载检测分类
        loadCategories()
    }

    /**
     * 设置沉浸式适配
     */
    private fun setupEdgeToEdge() {
        // 设置状态栏颜色为深紫色，文字为白色
        window.statusBarColor = getColor(R.color.purple_700)
        
        ViewCompat.setOnApplyWindowInsetsListener(binding.root) { view, windowInsets ->
            val insets = windowInsets.getInsets(WindowInsetsCompat.Type.systemBars())
            // 为根布局设置 padding，避免内容被状态栏和导航栏遮挡
            view.updatePadding(
                left = insets.left,
                top = insets.top,
                right = insets.right,
                bottom = insets.bottom
            )
            WindowInsetsCompat.CONSUMED
        }
    }

    /**
     * 初始化 UI 组件
     */
    private fun initViews() {
        Log.d(TAG, "初始化 UI 组件")

        // 设置工具栏
        setSupportActionBar(binding.toolbar)
        supportActionBar?.title = getString(R.string.app_name)

        // 设置 RecyclerView
        adapter = CategoryAdapter(
            onCategoryExpanded = { category, isExpanded ->
                onCategoryExpanded(category, isExpanded)
            }
        )
        binding.rvCategories.layoutManager = LinearLayoutManager(this)
        binding.rvCategories.adapter = adapter

        // 设置运行检测按钮
        binding.fabRunCheck.setOnClickListener {
            runAllChecks()
        }

        // 设置行为分析按钮
        binding.btnBehaviorAnalysis.setOnClickListener {
            navigateToBehavioraActivity()
        }
    }

    /**
     * 初始化检测器
     */
    private fun initCheckers() {
        Log.d(TAG, "初始化检测器")
        CheckerManager.initialize()
    }

    /**
     * 加载检测分类
     */
    private fun loadCategories() {
        Log.d(TAG, "加载检测分类")
        val categories = CheckerManager.loadCategories()
        DataManager.updateCategories(adapter, categories)

        // 显示加载完成提示
        val stats = DataManager.getCategoryStatistics(categories)
        UIManager.showLoadedMessage(binding.root, stats.totalCategories, stats.totalItems)
    }

    /**
     * 分类展开/折叠回调
     */
    private fun onCategoryExpanded(category: qpdb.env.check.model.Category, isExpanded: Boolean) {
        Log.d(TAG, "分类 ${category.name} ${if (isExpanded) "展开" else "折叠"}")
        // 可以在这里添加额外逻辑
    }

    /**
     * 跳转到行为分析页面
     */
    private fun navigateToBehavioraActivity() {
        Log.d(TAG, "跳转到行为分析页面")
        val intent = Intent(this, BehavioraActivity::class.java)
        startActivity(intent)
    }

    /**
     * 运行所有检测（支持实时进度更新）
     */
    private fun runAllChecks() {
        Log.d(TAG, "用户触发运行检测")

        // 显示检测运行中提示
        UIManager.showCheckingMessage(binding.root)

        lifecycleScope.launch {
            // 先加载初始分类（状态为等待检测）
            val categories = CheckerManager.loadCategories()
            categories.forEach { cat ->
                cat.items.forEach { it.description = "检测中..." }
            }
            DataManager.updateCategories(adapter, categories)

            // 执行检测，实时更新每个 item 的结果
            CheckerManager.runChecksWithProgress(categories) { category ->
                DataManager.updateCategoryStatus(adapter, category)
            }

            // 显示最终结果
            val stats = DataManager.getCategoryStatistics(categories)
            UIManager.showCheckResult(binding.root, stats.passedItems, stats.totalItems)
        }
    }
}

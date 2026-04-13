package qpdb.env.check

import android.os.Bundle
import android.util.Log
import android.view.MotionEvent
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.updatePadding
import qpdb.env.check.data.RegistrationData
import qpdb.env.check.databinding.ActivityBehavioraBinding
import qpdb.env.check.tracker.JsonLineWriter
import qpdb.env.check.tracker.TouchTrajectory
import qpdb.env.check.ui.behaviora.RegistrationSuccessFragment
import qpdb.env.check.ui.behaviora.WelcomeFragment

/**
 * 行为分析测试页面
 * 使用单 Activity + 多 Fragment 架构
 * 记录所有触摸操作轨迹到 JSON Lines 文件
 */
class BehavioraActivity : AppCompatActivity() {

    companion object {
        private const val TAG = "BehavioraActivity"
    }

    private lateinit var binding: ActivityBehavioraBinding
    private lateinit var jsonLineWriter: JsonLineWriter

    // 当前正在追踪的轨迹（每个手指一个轨迹）
    private val activeTrajectories = mutableMapOf<Int, TouchTrajectory>()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // 初始化视图绑定
        binding = ActivityBehavioraBinding.inflate(layoutInflater)
        setContentView(binding.root)

        Log.d(TAG, "行为分析页面已启动")

        // 初始化数据记录器
        initTracker()

        // 设置沉浸式适配
        setupEdgeToEdge()

        // 初始化 UI
        initViews()

        // 加载默认 Fragment
        if (savedInstanceState == null) {
            loadWelcomeFragment()
        }
    }

    /**
     * 拦截所有触摸事件并记录
     * 将单次操作（DOWN -> MOVE* -> UP）作为完整轨迹记录
     */
    override fun dispatchTouchEvent(ev: MotionEvent): Boolean {
        // 记录触摸轨迹
        recordTouchTrajectory(ev)

        // 调用父类方法，让事件正常传递下去
        return super.dispatchTouchEvent(ev)
    }

    /**
     * 记录触摸轨迹
     * 一个完整的操作（DOWN 到 UP）作为一条 JSON 记录
     */
    private fun recordTouchTrajectory(event: MotionEvent) {
        if (!::jsonLineWriter.isInitialized) return

        val timestamp = System.currentTimeMillis()
        val action = event.actionMasked

        when (action) {
            MotionEvent.ACTION_DOWN -> {
                // 为每个按下的手指创建新的轨迹
                for (i in 0 until event.pointerCount) {
                    val pointerId = event.getPointerId(i)
                    val trajectory = TouchTrajectory(
                        pointerId = pointerId,
                        startTime = timestamp
                    )
                    trajectory.addPoint(
                        eventType = "DOWN",
                        x = event.getX(i),
                        y = event.getY(i),
                        timestamp = timestamp,
                        pressure = event.getPressure(i)
                    )
                    activeTrajectories[pointerId] = trajectory
                }
                Log.v(TAG, "轨迹开始: pointers=${event.pointerCount}")
            }

            MotionEvent.ACTION_POINTER_DOWN -> {
                val index = event.actionIndex
                val pointerId = event.getPointerId(index)
                val trajectory = TouchTrajectory(
                    pointerId = pointerId,
                    startTime = timestamp
                )
                trajectory.addPoint(
                    eventType = "DOWN",
                    x = event.getX(index),
                    y = event.getY(index),
                    timestamp = timestamp,
                    pressure = event.getPressure(index)
                )
                activeTrajectories[pointerId] = trajectory
                Log.v(TAG, "轨迹开始(多指): pointerId=$pointerId")
            }

            MotionEvent.ACTION_MOVE -> {
                // 为所有手指添加移动点
                for (i in 0 until event.pointerCount) {
                    val pointerId = event.getPointerId(i)
                    activeTrajectories[pointerId]?.addPoint(
                        eventType = "MOVE",
                        x = event.getX(i),
                        y = event.getY(i),
                        timestamp = timestamp,
                        pressure = event.getPressure(i)
                    )
                }
            }

            MotionEvent.ACTION_UP -> {
                val index = event.actionIndex
                val pointerId = event.getPointerId(index)
                activeTrajectories[pointerId]?.let { trajectory ->
                    trajectory.addPoint(
                        eventType = "UP",
                        x = event.getX(index),
                        y = event.getY(index),
                        timestamp = timestamp,
                        pressure = event.getPressure(index)
                    )
                    trajectory.end(timestamp)
                    // 写入完整的轨迹
                    saveTrajectory(trajectory)
                    activeTrajectories.remove(pointerId)
                }
                Log.v(TAG, "轨迹结束: pointerId=$pointerId")
            }

            MotionEvent.ACTION_POINTER_UP -> {
                val index = event.actionIndex
                val pointerId = event.getPointerId(index)
                activeTrajectories[pointerId]?.let { trajectory ->
                    trajectory.addPoint(
                        eventType = "UP",
                        x = event.getX(index),
                        y = event.getY(index),
                        timestamp = timestamp,
                        pressure = event.getPressure(index)
                    )
                    trajectory.end(timestamp)
                    saveTrajectory(trajectory)
                    activeTrajectories.remove(pointerId)
                }
                Log.v(TAG, "轨迹结束(多指): pointerId=$pointerId")
            }

            MotionEvent.ACTION_CANCEL -> {
                val index = event.actionIndex
                val pointerId = event.getPointerId(index)
                activeTrajectories[pointerId]?.let { trajectory ->
                    trajectory.addPoint(
                        eventType = "CANCEL",
                        x = event.getX(index),
                        y = event.getY(index),
                        timestamp = timestamp,
                        pressure = event.getPressure(index)
                    )
                    trajectory.end(timestamp)
                    saveTrajectory(trajectory)
                    activeTrajectories.remove(pointerId)
                }
                Log.v(TAG, "轨迹取消: pointerId=$pointerId")
            }
        }
    }

    /**
     * 保存轨迹到文件
     */
    private fun saveTrajectory(trajectory: TouchTrajectory) {
        jsonLineWriter.writeJsonLine(trajectory.toJson())
        Log.d(TAG, "保存轨迹: ${trajectory.trajectoryId}, 类型=${trajectory.getOperationType()}, 点数=${trajectory.getPointCount()}, 持续时间=${trajectory.getDuration()}ms")
    }

    /**
     * 初始化数据记录器
     */
    private fun initTracker() {
        jsonLineWriter = JsonLineWriter(this)
        Log.d(TAG, "数据记录器已初始化")
        Log.d(TAG, "数据文件路径: ${jsonLineWriter.getDataFilePath()}")
    }

    /**
     * 设置沉浸式适配
     */
    private fun setupEdgeToEdge() {
        window.statusBarColor = getColor(R.color.purple_700)

        ViewCompat.setOnApplyWindowInsetsListener(binding.root) { view, windowInsets ->
            val insets = windowInsets.getInsets(WindowInsetsCompat.Type.systemBars())
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
        setSupportActionBar(binding.toolbar)
        supportActionBar?.setDisplayHomeAsUpEnabled(true)
        supportActionBar?.title = "行为分析测试"

        binding.toolbar.setNavigationOnClickListener {
            onBackPressed()
        }
    }

    /**
     * 加载欢迎界面 Fragment
     */
    private fun loadWelcomeFragment() {
        Log.d(TAG, "加载欢迎界面")
        supportFragmentManager.beginTransaction()
            .replace(R.id.fragmentContainer, WelcomeFragment.newInstance())
            .commit()
    }

    /**
     * 切换 Fragment
     */
    fun navigateToFragment(fragment: androidx.fragment.app.Fragment, addToBackStack: Boolean = true) {
        Log.d(TAG, "切换到 Fragment: ${fragment.javaClass.simpleName}")
        val transaction = supportFragmentManager.beginTransaction()
            .replace(R.id.fragmentContainer, fragment)

        if (addToBackStack) {
            transaction.addToBackStack(null)
        }

        transaction.commit()
    }

    /**
     * 获取数据文件路径
     */
    fun getDataFilePath(): String {
        return jsonLineWriter.getDataFilePath()
    }

    /**
     * 读取所有记录（调试用）
     */
    fun readAllRecords(): List<String> {
        return jsonLineWriter.readAllRecords()
    }

    override fun onDestroy() {
        super.onDestroy()
        // 保存所有未完成的轨迹
        val timestamp = System.currentTimeMillis()
        activeTrajectories.values.forEach { trajectory ->
            trajectory.end(timestamp)
            saveTrajectory(trajectory)
        }
        activeTrajectories.clear()

        RegistrationData.clear()
        Log.d(TAG, "BehavioraActivity 已销毁")
    }
}

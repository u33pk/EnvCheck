package qpdb.env.check.ui.behaviora.gl

import android.content.Context
import android.opengl.GLSurfaceView
import android.view.MotionEvent
import android.view.ScaleGestureDetector

/**
 * OpenGL ES 轨迹可视化视图
 */
class TrajectoryGLView(context: Context) : GLSurfaceView(context) {

    private val renderer: TrajectoryRenderer
    private var previousX: Float = 0f
    private var previousY: Float = 0f

    // 缩放手势检测
    private val scaleDetector = ScaleGestureDetector(context,
        object : ScaleGestureDetector.SimpleOnScaleGestureListener() {
            override fun onScale(detector: ScaleGestureDetector): Boolean {
                renderer.scale *= detector.scaleFactor
                renderer.scale = renderer.scale.coerceIn(0.1f, 5f)
                requestRender()
                return true
            }
        }
    )

    init {
        // 创建OpenGL ES 2.0上下文
        setEGLContextClientVersion(2)

        // 创建渲染器
        renderer = TrajectoryRenderer(context)

        // 设置渲染器
        setRenderer(renderer)

        // 设置渲染模式为按需渲染（节省电量）
        renderMode = RENDERMODE_WHEN_DIRTY
    }

    /**
     * 刷新数据并重新渲染
     */
    fun refreshData() {
        onResume()
        requestRender()
    }

    override fun onTouchEvent(event: MotionEvent): Boolean {
        // 处理缩放手势
        scaleDetector.onTouchEvent(event)

        val x = event.x
        val y = event.y

        when (event.action) {
            MotionEvent.ACTION_DOWN -> {
                previousX = x
                previousY = y
            }

            MotionEvent.ACTION_MOVE -> {
                if (!scaleDetector.isInProgress) {
                    // 计算滑动距离
                    val dx = x - previousX
                    val dy = y - previousY

                    // 更新旋转角度
                    renderer.rotationY += dx * 0.5f
                    renderer.rotationX += dy * 0.5f

                    // 限制X轴旋转范围（防止翻转）
                    renderer.rotationX = renderer.rotationX.coerceIn(-80f, 10f)

                    requestRender()
                }

                previousX = x
                previousY = y
            }
        }

        return true
    }
}

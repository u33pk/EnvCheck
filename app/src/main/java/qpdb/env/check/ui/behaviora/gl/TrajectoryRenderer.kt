package qpdb.env.check.ui.behaviora.gl

import android.content.Context
import android.opengl.GLES20
import android.opengl.GLSurfaceView
import android.opengl.Matrix
import android.util.Log
import org.json.JSONArray
import org.json.JSONObject
import qpdb.env.check.tracker.JsonLineWriter
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.FloatBuffer
import javax.microedition.khronos.egl.EGLConfig
import javax.microedition.khronos.opengles.GL10

/**
 * OpenGL ES 2.0 渲染器
 * 渲染3D轨迹，时间作为Z轴向上
 */
class TrajectoryRenderer(private val context: Context) : GLSurfaceView.Renderer {

    companion object {
        private const val TAG = "TrajectoryRenderer"
        private const val COORDS_PER_VERTEX = 3
        private const val VERTEX_STRIDE = COORDS_PER_VERTEX * 4 // 4 bytes per float

        // 顶点着色器
        private const val VERTEX_SHADER_CODE = """
            uniform mat4 uMVPMatrix;
            attribute vec4 vPosition;
            void main() {
                gl_Position = uMVPMatrix * vPosition;
                gl_PointSize = 5.0;
            }
        """

        // 片段着色器
        private const val FRAGMENT_SHADER_CODE = """
            precision mediump float;
            uniform vec4 vColor;
            void main() {
                gl_FragColor = vColor;
            }
        """
    }

    // OpenGL程序
    private var program: Int = 0
    private var positionHandle: Int = 0
    private var colorHandle: Int = 0
    private var mvpMatrixHandle: Int = 0

    // 矩阵
    private val projectionMatrix = FloatArray(16)
    private val viewMatrix = FloatArray(16)
    private val mvpMatrix = FloatArray(16)
    private val rotationMatrix = FloatArray(16)

    // 轨迹数据
    private var trajectories: List<Trajectory3D> = emptyList()
    private var maxZ: Float = 1f
    private var minZ: Float = 0f

    // 视角旋转
    var rotationX = -30f  // 绕X轴旋转（俯视角度）
    var rotationY = 0f    // 绕Y轴旋转
    var scale = 1f        // 缩放

    // 顶点缓冲区
    private var vertexBuffer: FloatBuffer? = null

    override fun onSurfaceCreated(unused: GL10, config: EGLConfig) {
        // 设置背景色（深灰色）
        GLES20.glClearColor(0.1f, 0.1f, 0.15f, 1.0f)
        GLES20.glEnable(GLES20.GL_DEPTH_TEST)

        // 编译着色器
        val vertexShader = loadShader(GLES20.GL_VERTEX_SHADER, VERTEX_SHADER_CODE)
        val fragmentShader = loadShader(GLES20.GL_FRAGMENT_SHADER, FRAGMENT_SHADER_CODE)

        // 创建OpenGL程序
        program = GLES20.glCreateProgram().apply {
            GLES20.glAttachShader(this, vertexShader)
            GLES20.glAttachShader(this, fragmentShader)
            GLES20.glLinkProgram(this)
        }

        // 加载轨迹数据（在后台线程）
        Thread { loadTrajectoryData() }.start()
    }

    override fun onSurfaceChanged(unused: GL10, width: Int, height: Int) {
        GLES20.glViewport(0, 0, width, height)

        val ratio: Float = width.toFloat() / height.toFloat()

        // 设置透视投影
        Matrix.frustumM(projectionMatrix, 0, -ratio, ratio, -1f, 1f, 2f, 100f)
    }

    override fun onDrawFrame(unused: GL10) {
        // 清除颜色和深度缓冲区
        GLES20.glClear(GLES20.GL_COLOR_BUFFER_BIT or GLES20.GL_DEPTH_BUFFER_BIT)

        // 设置相机位置
        Matrix.setLookAtM(viewMatrix, 0,
            0f, 0f, -5f,  // 相机位置
            0f, 0f, 0f,   // 观察点
            0f, 1f, 0f    // 上方向
        )

        // 应用旋转
        Matrix.setIdentityM(rotationMatrix, 0)
        Matrix.rotateM(rotationMatrix, 0, rotationX, 1f, 0f, 0f)
        Matrix.rotateM(rotationMatrix, 0, rotationY, 0f, 1f, 0f)
        Matrix.scaleM(rotationMatrix, 0, scale, scale, scale)

        // 计算MVP矩阵
        Matrix.multiplyMM(mvpMatrix, 0, projectionMatrix, 0, viewMatrix, 0)
        Matrix.multiplyMM(mvpMatrix, 0, mvpMatrix, 0, rotationMatrix, 0)

        // 绘制所有轨迹
        drawTrajectories()
    }

    /**
     * 绘制所有轨迹
     */
    private fun drawTrajectories() {
        if (trajectories.isEmpty()) return

        // 使用程序
        GLES20.glUseProgram(program)

        // 获取着色器变量句柄
        positionHandle = GLES20.glGetAttribLocation(program, "vPosition")
        colorHandle = GLES20.glGetUniformLocation(program, "vColor")
        mvpMatrixHandle = GLES20.glGetUniformLocation(program, "uMVPMatrix")

        // 设置MVP矩阵
        GLES20.glUniformMatrix4fv(mvpMatrixHandle, 1, false, mvpMatrix, 0)

        // 绘制每条轨迹
        trajectories.forEachIndexed { index, trajectory ->
            drawTrajectory(trajectory, index)
        }

        // 禁用顶点属性
        GLES20.glDisableVertexAttribArray(positionHandle)
    }

    /**
     * 绘制单条轨迹
     */
    private fun drawTrajectory(trajectory: Trajectory3D, index: Int) {
        val points = trajectory.points
        if (points.size < 2) return

        // 准备顶点数据
        val coords = FloatArray(points.size * 3)
        points.forEachIndexed { i, point ->
            // 归一化坐标到 [-1, 1] 范围
            coords[i * 3] = (point.x / 1080f) * 2f - 1f  // 假设屏幕宽度1080
            coords[i * 3 + 1] = -(point.y / 2400f) * 2f + 1f  // 假设屏幕高度2400，Y轴翻转
            coords[i * 3 + 2] = (point.z - minZ) / (maxZ - minZ + 1f) * 2f - 1f  // Z轴归一化
        }

        // 创建顶点缓冲区
        val buffer = ByteBuffer.allocateDirect(coords.size * 4).run {
            order(ByteOrder.nativeOrder())
            asFloatBuffer().apply {
                put(coords)
                position(0)
            }
        }

        // 设置顶点数据
        GLES20.glEnableVertexAttribArray(positionHandle)
        GLES20.glVertexAttribPointer(
            positionHandle,
            COORDS_PER_VERTEX,
            GLES20.GL_FLOAT,
            false,
            VERTEX_STRIDE,
            buffer
        )

        // 设置颜色（不同轨迹用不同颜色）
        val colors = arrayOf(
            floatArrayOf(1f, 0f, 0f, 1f),  // 红色
            floatArrayOf(0f, 1f, 0f, 1f),  // 绿色
            floatArrayOf(0f, 0f, 1f, 1f),  // 蓝色
            floatArrayOf(1f, 1f, 0f, 1f),  // 黄色
            floatArrayOf(1f, 0f, 1f, 1f),  // 紫色
            floatArrayOf(0f, 1f, 1f, 1f),  // 青色
            floatArrayOf(1f, 0.5f, 0f, 1f), // 橙色
            floatArrayOf(0.5f, 0f, 1f, 1f)  // 紫罗兰
        )
        val color = colors[index % colors.size]
        GLES20.glUniform4fv(colorHandle, 1, color, 0)

        // 绘制线条
        GLES20.glDrawArrays(GLES20.GL_LINE_STRIP, 0, points.size)

        // 绘制点（起点和终点）
        GLES20.glDrawArrays(GLES20.GL_POINTS, 0, 1)  // 起点
        GLES20.glDrawArrays(GLES20.GL_POINTS, points.size - 1, 1)  // 终点
    }

    /**
     * 加载着色器
     */
    private fun loadShader(type: Int, shaderCode: String): Int {
        return GLES20.glCreateShader(type).also { shader ->
            GLES20.glShaderSource(shader, shaderCode)
            GLES20.glCompileShader(shader)
        }
    }

    /**
     * 加载轨迹数据
     */
    private fun loadTrajectoryData() {
        try {
            val jsonLineWriter = JsonLineWriter(context)
            val records = jsonLineWriter.readAllRecords()

            Log.d(TAG, "读取到 ${records.size} 条记录")

            val loadedTrajectories = mutableListOf<Trajectory3D>()
            var globalMinTime = Long.MAX_VALUE
            var globalMaxTime = Long.MIN_VALUE

            records.forEach { json ->
                try {
                    val trajectory = parseTrajectoryJson(json)
                    if (trajectory.points.isNotEmpty()) {
                        loadedTrajectories.add(trajectory)
                        if (trajectory.startTime < globalMinTime) globalMinTime = trajectory.startTime
                        if (trajectory.endTime > globalMaxTime) globalMaxTime = trajectory.endTime
                        Log.d(TAG, "解析轨迹: ${trajectory.id}, 点数: ${trajectory.points.size}")
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "解析轨迹失败: $json", e)
                }
            }

            // 转换时间为相对Z坐标
            if (loadedTrajectories.isNotEmpty() && globalMaxTime > globalMinTime) {
                val timeRange = (globalMaxTime - globalMinTime).toFloat().coerceAtLeast(1f)
                trajectories = loadedTrajectories.map { traj ->
                    traj.copy(points = traj.points.map { point ->
                        point.copy(z = (point.z - globalMinTime) / timeRange * 5f)  // Z轴范围0-5
                    })
                }
                minZ = 0f
                maxZ = 5f
            } else {
                trajectories = loadedTrajectories
            }

            Log.d(TAG, "加载完成，共 ${trajectories.size} 条轨迹")

        } catch (e: Exception) {
            Log.e(TAG, "加载轨迹数据失败", e)
        }
    }

    /**
     * 解析JSON轨迹（使用 org.json）
     */
    private fun parseTrajectoryJson(json: String): Trajectory3D {
        val obj = JSONObject(json)
        val id = obj.optString("trajectoryId", "")
        val startTime = obj.optLong("startTime", 0)
        val endTime = obj.optLong("endTime", 0)

        val points = mutableListOf<TrajectoryPoint3D>()

        val pointsArray = obj.optJSONArray("points")
        pointsArray?.let { array ->
            for (i in 0 until array.length()) {
                val pointObj = array.getJSONObject(i)
                val x = pointObj.optDouble("x", 0.0).toFloat()
                val y = pointObj.optDouble("y", 0.0).toFloat()
                val timestamp = pointObj.optLong("timestamp", 0)
                val eventType = pointObj.optString("eventType", "")
                val pressure = pointObj.optDouble("pressure", 1.0).toFloat()
                points.add(TrajectoryPoint3D(x, y, timestamp.toFloat(), eventType, pressure))
            }
        }

        return Trajectory3D(id, points, startTime = startTime, endTime = endTime)
    }
}

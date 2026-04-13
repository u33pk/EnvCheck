package qpdb.env.check.ui.behaviora.gl

/**
 * 3D轨迹点数据
 * X: 屏幕水平位置
 * Y: 屏幕垂直位置
 * Z: 时间（向上）
 */
data class TrajectoryPoint3D(
    val x: Float,
    val y: Float,
    val z: Float,
    val eventType: String,  // DOWN, MOVE, UP
    val pressure: Float
)

/**
 * 3D轨迹数据
 */
data class Trajectory3D(
    val id: String,
    val points: List<TrajectoryPoint3D>,
    val color: FloatArray = floatArrayOf(1f, 0f, 0f, 1f), // RGBA
    val startTime: Long,
    val endTime: Long
) {
    /**
     * 获取轨迹持续时间
     */
    fun getDuration(): Long = endTime - startTime
}

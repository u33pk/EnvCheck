package qpdb.env.check.tracker

/**
 * 触摸事件数据类（单条事件）
 * @deprecated 请使用 TouchTrajectory 记录完整轨迹
 */
@Deprecated("使用 TouchTrajectory 替代")
data class TouchData(
    val eventType: String,
    val x: Float,
    val y: Float,
    val timestamp: Long,
    val pointerId: Int = 0,
    val pressure: Float = 1.0f,
    val action: String = ""
) {
    fun toJson(): String {
        return """{"eventType":"$eventType","x":$x,"y":$y,"timestamp":$timestamp,"pointerId":$pointerId,"pressure":$pressure}"""
    }
}

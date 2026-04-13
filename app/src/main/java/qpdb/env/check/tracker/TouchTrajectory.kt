package qpdb.env.check.tracker

import java.util.UUID

/**
 * 触摸轨迹数据类
 * 记录一次完整的触摸操作（DOWN -> MOVE* -> UP）
 */
data class TouchTrajectory(
    val trajectoryId: String = UUID.randomUUID().toString(),
    val pointerId: Int,
    val startTime: Long,
    var endTime: Long? = null,
    val points: MutableList<TouchPoint> = mutableListOf()
) {
    /**
     * 轨迹点数据
     */
    data class TouchPoint(
        val eventType: String,      // DOWN, MOVE, UP
        val x: Float,
        val y: Float,
        val timestamp: Long,
        val pressure: Float
    )

    /**
     * 添加轨迹点
     */
    fun addPoint(eventType: String, x: Float, y: Float, timestamp: Long, pressure: Float) {
        points.add(TouchPoint(eventType, x, y, timestamp, pressure))
    }

    /**
     * 结束轨迹
     */
    fun end(endTime: Long) {
        this.endTime = endTime
    }

    /**
     * 获取轨迹持续时间（毫秒）
     */
    fun getDuration(): Long {
        return (endTime ?: System.currentTimeMillis()) - startTime
    }

    /**
     * 获取轨迹点数量
     */
    fun getPointCount(): Int = points.size

    /**
     * 判断是否为点击（移动距离小于阈值）
     */
    fun isClick(threshold: Float = 20f): Boolean {
        if (points.size < 2) return true
        
        val startPoint = points.first()
        val endPoint = points.last()
        val distance = kotlin.math.hypot(
            endPoint.x - startPoint.x,
            endPoint.y - startPoint.y
        )
        return distance < threshold && getDuration() < 500
    }

    /**
     * 获取操作类型描述
     */
    fun getOperationType(): String {
        return if (isClick()) "CLICK" else "SWIPE"
    }

    /**
     * 转换为 JSON 字符串
     */
    fun toJson(): String {
        val pointsJson = points.joinToString(",") { point ->
            """{"eventType":"${point.eventType}","x":${point.x},"y":${point.y},"timestamp":${point.timestamp},"pressure":${point.pressure}}"""
        }
        
        return """{"trajectoryId":"$trajectoryId","pointerId":$pointerId,"startTime":$startTime,"endTime":$endTime,"duration":${getDuration()},"pointCount":${getPointCount()},"operationType":"${getOperationType()}","points":[$pointsJson]}"""
    }
}

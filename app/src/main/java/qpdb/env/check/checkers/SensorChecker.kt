package qpdb.env.check.checkers

import android.content.Context
import android.hardware.Sensor
import android.hardware.SensorManager
import android.util.Log
import qpdb.env.check.EnvCheckApp
import qpdb.env.check.model.CheckItem
import qpdb.env.check.model.CheckResult
import qpdb.env.check.model.CheckStatus
import qpdb.env.check.model.Checkable

/**
 * 传感器信息检测
 * 检测所有传感器的数量、详细信息（制造商、分辨率、功耗等）
 * 判定规则：
 *   - 传感器总数 < 25 → 不通过
 *   - 任一传感器信息中包含 cvd/AOSP/cuttlefish/qemu/virtual 关键字 → 不通过
 */
class SensorChecker : Checkable {

    companion object {
        private const val TAG = "SensorChecker"
        private const val MIN_SENSOR_COUNT = 25
        private val EMULATOR_KEYWORDS = listOf(
            "cvd", "aosp", "cuttlefish", "qemu", "virtual"
        )
    }

    override val categoryName: String = "传感器信息"

    override fun checkList(): List<CheckItem> {
        return listOf(
            CheckItem(
                name = "传感器数量",
                checkPoint = "sensor_count",
                description = "等待检测..."
            ),
            CheckItem(
                name = "模拟器关键字检测",
                checkPoint = "sensor_keyword_check",
                description = "等待检测..."
            ),
            CheckItem(
                name = "传感器详情",
                checkPoint = "sensor_details",
                description = "等待检测..."
            ),
            CheckItem(
                name = "传感器数据注入检测",
                checkPoint = "sensor_injection_check",
                description = "等待检测..."
            )
        )
    }

    override fun runCheck(): List<CheckItem> {
        Log.i(TAG, "runCheck() 被调用")
        val items = checkList().toMutableList()
        val context = EnvCheckApp.getContext()

        try {
            val sensorManager = context.getSystemService(Context.SENSOR_SERVICE) as SensorManager
            val allSensors = sensorManager.getSensorList(Sensor.TYPE_ALL)

            // 检测传感器数量
            val countResult = checkSensorCount(allSensors.size)
            Log.i(TAG, "传感器数量: ${countResult.description}")
            items.find { it.checkPoint == "sensor_count" }?.let {
                it.status = countResult.status
                it.description = countResult.description
            }

            // 传感器详细信息 + 模拟器关键字检测
            val (detailsResult, keywordResult) = checkSensorDetails(allSensors)
            items.find { it.checkPoint == "sensor_details" }?.let {
                it.status = detailsResult.status
                it.description = detailsResult.description
            }
            items.find { it.checkPoint == "sensor_keyword_check" }?.let {
                it.status = keywordResult.status
                it.description = keywordResult.description
            }

            // 传感器数据注入检测
            val injectionResult = checkSensorInjection(allSensors)
            items.find { it.checkPoint == "sensor_injection_check" }?.let {
                it.status = injectionResult.status
                it.description = injectionResult.description
            }

        } catch (e: Exception) {
            Log.e(TAG, "检测过程出错: ${e.message}", e)
            items.forEach { item ->
                if (item.description == "等待检测...") {
                    item.status = CheckStatus.FAIL
                    item.description = "检测失败: ${e.message}"
                }
            }
        }

        return items
    }

    /**
     * 检测传感器总数
     */
    private fun checkSensorCount(count: Int): CheckResult {
        return if (count >= MIN_SENSOR_COUNT) {
            CheckResult(CheckStatus.PASS, "共 $count 个传感器 (≥ $MIN_SENSOR_COUNT)")
        } else {
            CheckResult(CheckStatus.FAIL, "仅 $count 个传感器 (< $MIN_SENSOR_COUNT)")
        }
    }

    /**
     * 检测传感器是否支持数据注入 (SENSOR_FLAG_BITS_DATA_INJECTION)
     * 通过反射调用 isDataInjectionSupported，兼容 API < 34 的情况
     */
    private fun checkSensorInjection(sensors: List<Sensor>): CheckResult {
        val injectionSensors = mutableListOf<String>()
        for ((index, sensor) in sensors.withIndex()) {
            if (isDataInjectionSupported(sensor)) {
                injectionSensors.add("[${index + 1}] ${sensor.name ?: "unknown"}")
            }
        }
        return if (injectionSensors.isNotEmpty()) {
            CheckResult(
                CheckStatus.FAIL,
                "检测到 ${injectionSensors.size} 个传感器支持数据注入:\n${injectionSensors.joinToString("\n")}"
            )
        } else {
            CheckResult(CheckStatus.PASS, "所有传感器均不支持数据注入")
        }
    }

    /**
     * 反射获取 Sensor.isDataInjectionSupported()
     */
    private fun isDataInjectionSupported(sensor: Sensor): Boolean {
        return try {
            val method = Sensor::class.java.getMethod("isDataInjectionSupported")
            method.invoke(sensor) as? Boolean ?: false
        } catch (e: Exception) {
            false
        }
    }

    /**
     * 检测传感器详细信息并扫描模拟器关键字
     */
    private fun checkSensorDetails(sensors: List<Sensor>): Pair<CheckResult, CheckResult> {
        val details = mutableListOf<String>()
        val keywordHits = mutableListOf<String>()
        val typeGroup = sensors.groupBy { it.stringType ?: "unknown" }

        for ((index, sensor) in sensors.withIndex()) {
            val sensorIndex = index + 1
            val name = sensor.name ?: "unknown"
            val vendor = sensor.vendor ?: "unknown"
            val type = sensor.stringType ?: "unknown"
            val resolution = sensor.resolution
            val power = sensor.power
            val maxRange = sensor.maximumRange
            val minDelay = sensor.minDelay
            val maxDelay = sensor.maxDelay
            val fifoReserved = sensor.fifoReservedEventCount
            val fifoMax = sensor.fifoMaxEventCount
            val version = sensor.version

            // 扫描模拟器关键字（检查 name、vendor、type）
            val scanTargets = listOf(name, vendor, type)
            for (target in scanTargets) {
                for (keyword in EMULATOR_KEYWORDS) {
                    if (target.contains(keyword, ignoreCase = true)) {
                        val hit = "传感器$sensorIndex [$name]: \"$target\" 包含关键字 \"$keyword\""
                        if (!keywordHits.contains(hit)) {
                            keywordHits.add(hit)
                        }
                    }
                }
            }

            val detail = buildString {
                append("[$sensorIndex] $name")
                append("\n  制造商: $vendor")
                append("\n  类型: $type")
                append("\n  版本: $version")
                append("\n  分辨率: $resolution")
                append("\n  最大量程: $maxRange")
                append("\n  功耗: ${power}mA")
                append("\n  最小采样间隔: ${minDelay}μs")
                append("\n  最大采样间隔: ${maxDelay}μs")
                append("\n  FIFO保留事件数: $fifoReserved")
                append("\n  FIFO最大事件数: $fifoMax")
            }
            details.add(detail)
        }

        // 按类型分组统计摘要
        val typeSummary = typeGroup.entries.joinToString("\n") { (type, list) ->
            "  $type: ${list.size}个"
        }

        val fullDescription = buildString {
            append("共 ${sensors.size} 个传感器，按类型统计:\n$typeSummary\n\n")
            append(details.joinToString("\n\n"))
        }

        val detailsResult = CheckResult(CheckStatus.PASS, fullDescription)

        val keywordResult = if (keywordHits.isNotEmpty()) {
            CheckResult(CheckStatus.FAIL, "检测到模拟器关键字:\n${keywordHits.joinToString("\n")}")
        } else {
            CheckResult(CheckStatus.PASS, "未检测到模拟器关键字")
        }

        return Pair(detailsResult, keywordResult)
    }
}

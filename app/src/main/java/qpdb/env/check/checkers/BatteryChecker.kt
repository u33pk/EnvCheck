package qpdb.env.check.checkers

import android.annotation.SuppressLint
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.BatteryManager
import android.os.Build
import android.util.Log
import qpdb.env.check.EnvCheckApp
import qpdb.env.check.model.CheckItem
import qpdb.env.check.model.CheckResult
import qpdb.env.check.model.CheckStatus
import qpdb.env.check.model.Checkable
import qpdb.env.check.utils.FileUtil.fileExists

/**
 * 电池信息检测
 * 检测电池容量、电量、电压、温度、健康状态等信息
 * 容量为 1000mAh 则判定为虚拟电池（不通过），其他只显示信息
 */
class BatteryChecker : Checkable {

    companion object {
        private const val TAG = "BatteryChecker"

        // 虚拟电池容量阈值 (mAh)
        private const val VIRTUAL_BATTERY_CAPACITY = 1000
    }

    override val categoryName: String = "电池信息"

    override fun checkList(): List<CheckItem> {
        Log.i(TAG, "checkList() 被调用")
        return listOf(
            // 电池容量检测（关键检测项）
            CheckItem(
                name = "电池容量",
                checkPoint = "battery_capacity",
                description = "等待检测..."
            ),
            // 当前电量百分比
            CheckItem(
                name = "当前电量",
                checkPoint = "battery_level",
                description = "等待检测..."
            ),
            // 电池电压
            CheckItem(
                name = "电池电压",
                checkPoint = "battery_voltage",
                description = "等待检测..."
            ),
            // 电池温度
            CheckItem(
                name = "电池温度",
                checkPoint = "battery_temperature",
                description = "等待检测..."
            ),
            // 电池健康状态
            CheckItem(
                name = "健康状态",
                checkPoint = "battery_health",
                description = "等待检测..."
            ),
            // 充电状态
            CheckItem(
                name = "充电状态",
                checkPoint = "battery_status",
                description = "等待检测..."
            ),
            // 充电方式
            CheckItem(
                name = "充电方式",
                checkPoint = "battery_plugged",
                description = "等待检测..."
            ),
            // 电池技术类型
            CheckItem(
                name = "电池技术",
                checkPoint = "battery_technology",
                description = "等待检测..."
            ),
            // 电池温度检测
            CheckItem(
                name = "温度合理性",
                checkPoint = "temperature_check",
                description = "等待检测..."
            ),
            // Goldfish 电池模块检测（模拟器特征）
            CheckItem(
                name = "Goldfish 电池模块",
                checkPoint = "goldfish_battery",
                description = "等待检测..."
            )
        )
    }

    /**
     * 执行实际检测
     */
    override fun runCheck(): List<CheckItem> {
        Log.i(TAG, "runCheck() 被调用")

        val items = checkList().toMutableList()
        val context = EnvCheckApp.getContext()

        try {
            // 获取电池信息
            val batteryInfo = getBatteryInfo(context)

            // 检测电池容量（关键项：1000mAh 视为虚拟电池）
            val capacityResult = checkBatteryCapacity(batteryInfo)
            Log.i(TAG, "电池容量: ${capacityResult.description}")
            items.find { it.checkPoint == "battery_capacity" }?.let {
                it.status = capacityResult.status
                it.description = capacityResult.description
            }

            // 显示当前电量
            val levelResult = checkBatteryLevel(batteryInfo)
            Log.i(TAG, "当前电量: ${levelResult.description}")
            items.find { it.checkPoint == "battery_level" }?.let {
                it.status = levelResult.status
                it.description = levelResult.description
            }

            // 显示电池电压
            val voltageResult = checkBatteryVoltage(batteryInfo)
            Log.i(TAG, "电池电压: ${voltageResult.description}")
            items.find { it.checkPoint == "battery_voltage" }?.let {
                it.status = voltageResult.status
                it.description = voltageResult.description
            }

            // 显示电池温度
            val temperatureResult = checkBatteryTemperature(batteryInfo)
            Log.i(TAG, "电池温度: ${temperatureResult.description}")
            items.find { it.checkPoint == "battery_temperature" }?.let {
                it.status = temperatureResult.status
                it.description = temperatureResult.description
            }

            // 显示健康状态
            val healthResult = checkBatteryHealth(batteryInfo)
            Log.i(TAG, "健康状态: ${healthResult.description}")
            items.find { it.checkPoint == "battery_health" }?.let {
                it.status = healthResult.status
                it.description = healthResult.description
            }

            // 显示充电状态
            val statusResult = checkBatteryStatus(batteryInfo)
            Log.i(TAG, "充电状态: ${statusResult.description}")
            items.find { it.checkPoint == "battery_status" }?.let {
                it.status = statusResult.status
                it.description = statusResult.description
            }

            // 显示充电方式
            val pluggedResult = checkBatteryPlugged(batteryInfo)
            Log.i(TAG, "充电方式: ${pluggedResult.description}")
            items.find { it.checkPoint == "battery_plugged" }?.let {
                it.status = pluggedResult.status
                it.description = pluggedResult.description
            }

            // 显示电池技术类型
            val technologyResult = checkBatteryTechnology(batteryInfo)
            Log.i(TAG, "电池技术: ${technologyResult.description}")
            items.find { it.checkPoint == "battery_technology" }?.let {
                it.status = technologyResult.status
                it.description = technologyResult.description
            }

            // 检测温度合理性
            val tempCheckResult = checkTemperatureReasonable(batteryInfo)
            Log.i(TAG, "温度合理性: ${tempCheckResult.description}")
            items.find { it.checkPoint == "temperature_check" }?.let {
                it.status = tempCheckResult.status
                it.description = tempCheckResult.description
            }

            // 检测 Goldfish 电池模块（模拟器特征）
            val goldfishResult = checkGoldfishBatteryModule()
            Log.i(TAG, "Goldfish 电池模块: ${goldfishResult.description}")
            items.find { it.checkPoint == "goldfish_battery" }?.let {
                it.status = goldfishResult.status
                it.description = goldfishResult.description
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
     * 获取电池信息
     */
    private fun getBatteryInfo(context: Context): BatteryInfo {
        val intentFilter = IntentFilter(Intent.ACTION_BATTERY_CHANGED)
        val batteryIntent = context.registerReceiver(null, intentFilter)
            ?: return BatteryInfo()

        return BatteryInfo.fromIntent(context, batteryIntent)
    }

    /**
     * 检测电池容量
     * 关键检测项：1000mAh 判定为虚拟电池（不通过）
     */
    private fun checkBatteryCapacity(batteryInfo: BatteryInfo): CheckResult {
        return when {
            batteryInfo.capacity <= 0 -> {
                CheckResult(CheckStatus.INFO, "无法获取电池容量")
            }
            batteryInfo.capacity == VIRTUAL_BATTERY_CAPACITY -> {
                CheckResult(CheckStatus.FAIL, "${batteryInfo.capacity}mAh (疑似虚拟电池)")
            }
            else -> {
                CheckResult(CheckStatus.PASS, "${batteryInfo.capacity}mAh")
            }
        }
    }

    /**
     * 检测当前电量百分比
     */
    private fun checkBatteryLevel(batteryInfo: BatteryInfo): CheckResult {
        return if (batteryInfo.level >= 0 && batteryInfo.scale > 0) {
            val percentage = (batteryInfo.level * 100) / batteryInfo.scale
            CheckResult(CheckStatus.INFO, "$percentage% (${batteryInfo.level}/${batteryInfo.scale})")
        } else {
            CheckResult(CheckStatus.INFO, "无法获取电量信息")
        }
    }

    /**
     * 检测电池电压
     */
    private fun checkBatteryVoltage(batteryInfo: BatteryInfo): CheckResult {
        return if (batteryInfo.voltage > 0) {
            // voltage 单位为毫伏(mV)，转换为伏(V)显示
            val voltageV = batteryInfo.voltage / 1000.0
            CheckResult(CheckStatus.INFO, "${batteryInfo.voltage}mV (${String.format("%.2f", voltageV)}V)")
        } else {
            CheckResult(CheckStatus.INFO, "无法获取电压信息")
        }
    }

    /**
     * 检测电池温度
     */
    private fun checkBatteryTemperature(batteryInfo: BatteryInfo): CheckResult {
        return if (batteryInfo.temperature != 0) {
            // temperature 单位为 0.1摄氏度，转换为摄氏度
            val tempC = batteryInfo.temperature / 10.0
            CheckResult(CheckStatus.INFO, "${String.format("%.1f", tempC)}°C")
        } else {
            CheckResult(CheckStatus.INFO, "无法获取温度信息")
        }
    }

    /**
     * 检测温度合理性
     */
    private fun checkTemperatureReasonable(batteryInfo: BatteryInfo): CheckResult {
        return if (batteryInfo.temperature != 0) {
            val tempC = batteryInfo.temperature / 10.0
            when {
                tempC < -20 -> CheckResult(CheckStatus.FAIL, "温度过低 (${String.format("%.1f", tempC)}°C)")
                tempC > 60 -> CheckResult(CheckStatus.FAIL, "温度过高 (${String.format("%.1f", tempC)}°C)")
                else -> CheckResult(CheckStatus.PASS, "温度正常 (${String.format("%.1f", tempC)}°C)")
            }
        } else {
            CheckResult(CheckStatus.INFO, "无法检测温度")
        }
    }

    /**
     * 检测电池健康状态
     */
    private fun checkBatteryHealth(batteryInfo: BatteryInfo): CheckResult {
        val healthDescription = when (batteryInfo.health) {
            BatteryManager.BATTERY_HEALTH_GOOD -> "良好"
            BatteryManager.BATTERY_HEALTH_OVERHEAT -> "过热"
            BatteryManager.BATTERY_HEALTH_DEAD -> "损坏"
            BatteryManager.BATTERY_HEALTH_OVER_VOLTAGE -> "过压"
            BatteryManager.BATTERY_HEALTH_UNSPECIFIED_FAILURE -> "未知故障"
            BatteryManager.BATTERY_HEALTH_COLD -> "过冷"
            BatteryManager.BATTERY_HEALTH_UNKNOWN -> "未知"
            else -> "未知状态 (${batteryInfo.health})"
        }

        val isHealthy = batteryInfo.health == BatteryManager.BATTERY_HEALTH_GOOD
        return CheckResult(
            if (isHealthy) CheckStatus.PASS else CheckStatus.FAIL,
            healthDescription
        )
    }

    /**
     * 检测电池充电状态
     */
    private fun checkBatteryStatus(batteryInfo: BatteryInfo): CheckResult {
        val statusDescription = when (batteryInfo.status) {
            BatteryManager.BATTERY_STATUS_CHARGING -> "充电中"
            BatteryManager.BATTERY_STATUS_DISCHARGING -> "放电中"
            BatteryManager.BATTERY_STATUS_FULL -> "已充满"
            BatteryManager.BATTERY_STATUS_NOT_CHARGING -> "未充电"
            BatteryManager.BATTERY_STATUS_UNKNOWN -> "未知"
            else -> "未知状态 (${batteryInfo.status})"
        }

        return CheckResult(CheckStatus.INFO, statusDescription)
    }

    /**
     * 检测充电方式
     */
    private fun checkBatteryPlugged(batteryInfo: BatteryInfo): CheckResult {
        val pluggedDescription = when (batteryInfo.plugged) {
            BatteryManager.BATTERY_PLUGGED_AC -> "AC电源"
            BatteryManager.BATTERY_PLUGGED_USB -> "USB"
            BatteryManager.BATTERY_PLUGGED_WIRELESS -> "无线充电"
            0 -> "未连接"
            else -> "未知方式 (${batteryInfo.plugged})"
        }

        return CheckResult(CheckStatus.INFO, pluggedDescription)
    }

    /**
     * 检测电池技术类型
     */
    private fun checkBatteryTechnology(batteryInfo: BatteryInfo): CheckResult {
        return if (batteryInfo.technology.isNotEmpty()) {
            CheckResult(CheckStatus.INFO, batteryInfo.technology)
        } else {
            CheckResult(CheckStatus.INFO, "未知")
        }
    }

    /**
     * 检测 Goldfish 电池模块
     * 该文件是 Android 模拟器的特征文件
     * @return CheckResult 如果文件存在则返回 FAIL（表示检测到模拟器）
     */
    private fun checkGoldfishBatteryModule(): CheckResult {
        return try {
            val goldfishPath = "/vendor/lib/modules/goldfish_battery.ko"
            val exists = fileExists(goldfishPath)
            if (exists) {
                CheckResult(CheckStatus.FAIL, "检测到模拟器电池模块: $goldfishPath")
            } else {
                CheckResult(CheckStatus.PASS, "未检测到模拟器电池模块")
            }
        } catch (e: Exception) {
            Log.e(TAG, "检测 Goldfish 电池模块出错: ${e.message}")
            CheckResult(CheckStatus.INFO, "检测失败: ${e.message}")
        }
    }

    /**
     * 电池信息数据类
     */
    private data class BatteryInfo(
        val level: Int = -1,           // 当前电量 (0-100 或 0-scale)
        val scale: Int = -1,           // 电量最大值
        val voltage: Int = -1,         // 电压 (mV)
        val temperature: Int = 0,      // 温度 (0.1摄氏度)
        val health: Int = BatteryManager.BATTERY_HEALTH_UNKNOWN,
        val status: Int = BatteryManager.BATTERY_STATUS_UNKNOWN,
        val plugged: Int = 0,          // 充电方式
        val technology: String = "",   // 电池技术类型 (Li-ion, Li-poly 等)
        val capacity: Int = -1         // 电池容量 (mAh)
    ) {
        companion object {
            fun fromIntent(context: Context, intent: Intent): BatteryInfo {
                val level = intent.getIntExtra(BatteryManager.EXTRA_LEVEL, -1)
                val scale = intent.getIntExtra(BatteryManager.EXTRA_SCALE, -1)
                val voltage = intent.getIntExtra(BatteryManager.EXTRA_VOLTAGE, -1)
                val temperature = intent.getIntExtra(BatteryManager.EXTRA_TEMPERATURE, 0)
                val health = intent.getIntExtra(BatteryManager.EXTRA_HEALTH, BatteryManager.BATTERY_HEALTH_UNKNOWN)
                val status = intent.getIntExtra(BatteryManager.EXTRA_STATUS, BatteryManager.BATTERY_STATUS_UNKNOWN)
                val plugged = intent.getIntExtra(BatteryManager.EXTRA_PLUGGED, 0)
                val technology = intent.getStringExtra(BatteryManager.EXTRA_TECHNOLOGY) ?: ""

                // 获取电池容量
                val capacity = getBatteryCapacity(context)

                return BatteryInfo(
                    level = level,
                    scale = scale,
                    voltage = voltage,
                    temperature = temperature,
                    health = health,
                    status = status,
                    plugged = plugged,
                    technology = technology,
                    capacity = capacity
                )
            }

            /**
             * 获取电池容量 (mAh)
             */
            private fun getBatteryCapacity(context: Context): Int {
                return try {
                    when {
                        Build.VERSION.SDK_INT >= Build.VERSION_CODES.P -> {
                            // Android 9+ (API 28+) 使用 BatteryManager
                            val batteryManager = context.getSystemService(Context.BATTERY_SERVICE) as BatteryManager
                            val chargeCounter = batteryManager.getIntProperty(BatteryManager.BATTERY_PROPERTY_CHARGE_COUNTER)
                            val capacity = batteryManager.getIntProperty(BatteryManager.BATTERY_PROPERTY_CAPACITY)

                            if (chargeCounter > 0 && capacity > 0) {
                                // 计算容量: chargeCounter (uAh) / capacity (%) * 100 = capacity (uAh)
                                // 转换为 mAh
                                (chargeCounter / capacity) * 100 / 1000
                            } else {
                                getBatteryCapacityFromPowerProfile(context)
                            }
                        }
                        else -> {
                            getBatteryCapacityFromPowerProfile(context)
                        }
                    }
                } catch (e: Exception) {
                    Log.w(TAG, "获取电池容量失败: ${e.message}")
                    -1
                }
            }

            /**
             * 从 PowerProfile 获取电池容量
             */
            @SuppressLint("PrivateApi")
            private fun getBatteryCapacityFromPowerProfile(context: Context): Int {
                return try {
                    // 通过反射获取 com.android.internal.os.PowerProfile
                    val powerProfileClass = Class.forName("com.android.internal.os.PowerProfile")
                    val constructor = powerProfileClass.getConstructor(Context::class.java)
                    val powerProfile = constructor.newInstance(context)
                    val method = powerProfileClass.getMethod("getBatteryCapacity")
                    val capacity = method.invoke(powerProfile) as Double
                    capacity.toInt()
                } catch (e: Exception) {
                    Log.w(TAG, "从 PowerProfile 获取容量失败: ${e.message}")
                    -1
                }
            }
        }
    }
}

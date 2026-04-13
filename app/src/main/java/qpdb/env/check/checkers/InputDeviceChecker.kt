package qpdb.env.check.checkers

import android.content.Context
import android.hardware.input.InputManager
import android.os.Build
import android.util.Log
import android.view.InputDevice
import android.view.InputDevice.MotionRange
import android.view.MotionEvent
import qpdb.env.check.EnvCheckApp
import qpdb.env.check.model.CheckItem
import qpdb.env.check.model.CheckResult
import qpdb.env.check.model.CheckStatus
import qpdb.env.check.model.Checkable

/**
 * 输入设备检测
 * 检测输入设备列表，识别模拟器/虚拟环境特征
 * 检测设备功能支持：压力事件、触摸大小、分辨率等
 * 对获取的数据进行合理性检测
 * 如果设备名称中包含 AOSP、crosvm、cuttlefish 等关键词则判定为不通过
 */
class InputDeviceChecker : Checkable {

    companion object {
        private const val TAG = "InputDeviceChecker"
        
        // 模拟器/虚拟环境关键词列表
        private val SUSPICIOUS_KEYWORDS = listOf(
            "AOSP",           // Android Open Source Project 默认设备
            "crosvm",         // Chrome OS 虚拟机
            "cuttlefish",     // Android 虚拟设备
            "goldfish",       // Android 模拟器内核
            "ranchu",         // Android 模拟器
            "qemu",           // QEMU 模拟器
            "virtio",         // 虚拟化 I/O
            "virtual",        // 虚拟设备
            "vbox",           // VirtualBox
            "vmware",         // VMware
            "hyperv",         // Hyper-V
            "kvm",            // KVM 虚拟化
            "xen",            // Xen 虚拟化
            "bochs",          // Bochs 模拟器
            "docker",         // Docker 容器
            "container",      // 容器环境
            "waydroid",       // Waydroid 容器
            "anbox",          // Anbox 容器
            "blissos",        // Bliss OS
            "android_x86",    // Android x86 项目
            "remixos",        // Remix OS
            "phoenixos",      // Phoenix OS
            "primeos",        // Prime OS
            "genymotion",     // Genymotion 模拟器
            "nox",            // 夜神模拟器
            "bluestacks",     // BlueStacks 模拟器
            "ldplayer",       // 雷电模拟器
            "mumu",           // 网易 MuMu 模拟器
            "memu",           // 逍遥模拟器
            "tiantian",       // 天天模拟器
            "xiaoyao",        // 逍遥模拟器
            "droid4x",        // 海马模拟器
            "koplayer",       //  Koplayer 模拟器
            "leapdroid",      // LeapDroid 模拟器
            "smartgaga",      // SmartGaGa 模拟器
            "andy",           // Andy 模拟器
            "windroy",        // Windroy 模拟器
            "youwave",        // YouWave 模拟器
            "amiduos",        // AMI DuOS 模拟器
            "microvirt",      // 微模拟器框架
            "vphone"          // 虚拟手机
        )
        
        // 压力值合理范围
        const val PRESSURE_MIN = 0.0f
        const val PRESSURE_MAX = 1.0f
        const val PRESSURE_REASONABLE_MIN = 0.0f
        const val PRESSURE_REASONABLE_MAX = 1.0f
        
        // 触摸大小合理范围
        const val SIZE_MIN = 0.0f
        const val SIZE_MAX = 1.0f
        const val SIZE_REASONABLE_MAX = 1.0f
        
        // 触摸屏分辨率合理范围 (像素)
        const val RESOLUTION_MIN = 1.0f
        const val RESOLUTION_MAX = 10000.0f
        const val RESOLUTION_REASONABLE_MIN = 100.0f
        
        // 坐标范围合理值
        const val AXIS_RANGE_MIN = 0.0f
        const val AXIS_RANGE_MAX = 100000.0f
    }

    override val categoryName: String = "输入设备"

    override fun checkList(): List<CheckItem> {
        Log.i(TAG, "checkList() 被调用")
        return listOf(
            // 输入设备总数量
            CheckItem(
                name = "输入设备数量",
                checkPoint = "input_device_count",
                description = "等待检测..."
            ),
            // 可疑设备检测
            CheckItem(
                name = "可疑设备检测",
                checkPoint = "suspicious_devices",
                description = "等待检测..."
            ),
            // 设备列表详情
            CheckItem(
                name = "输入设备列表",
                checkPoint = "input_device_list",
                description = "等待检测..."
            ),
            // 键盘设备
            CheckItem(
                name = "键盘设备",
                checkPoint = "keyboard_devices",
                description = "等待检测..."
            ),
            // 鼠标/触摸板设备
            CheckItem(
                name = "鼠标/触摸板设备",
                checkPoint = "mouse_devices",
                description = "等待检测..."
            ),
            // 触摸屏设备
            CheckItem(
                name = "触摸屏设备",
                checkPoint = "touchscreen_devices",
                description = "等待检测..."
            ),
            // 压力事件支持
            CheckItem(
                name = "压力事件支持",
                checkPoint = "pressure_support",
                description = "等待检测..."
            ),
            // 触摸大小支持
            CheckItem(
                name = "触摸大小支持",
                checkPoint = "touch_size_support",
                description = "等待检测..."
            ),
            // 触摸分辨率
            CheckItem(
                name = "触摸分辨率/精度",
                checkPoint = "touch_resolution",
                description = "等待检测..."
            ),
            // 坐标范围检测
            CheckItem(
                name = "坐标范围合理性",
                checkPoint = "axis_range_check",
                description = "等待检测..."
            ),
            // 设备功能综合评估
            CheckItem(
                name = "触摸功能完整性",
                checkPoint = "touch_function_integrity",
                description = "等待检测..."
            ),
            // 游戏手柄/摇杆
            CheckItem(
                name = "游戏手柄/摇杆",
                checkPoint = "gamepad_devices",
                description = "等待检测..."
            ),
            // 综合安全检测
            CheckItem(
                name = "输入设备安全性",
                checkPoint = "input_security",
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
            // 获取所有输入设备信息
            val devices = getInputDevices(context)
            Log.i(TAG, "检测到 ${devices.size} 个输入设备")

            // 获取触摸屏设备（用于功能检测）
            val touchDevices = devices.filter { it.isTouchscreen }

            // 检测输入设备数量
            val countResult = checkDeviceCount(devices)
            Log.i(TAG, "输入设备数量: ${countResult.description}")
            items.find { it.checkPoint == "input_device_count" }?.let {
                it.status = countResult.status
                it.description = countResult.description
            }

            // 检测可疑设备
            val suspiciousResult = checkSuspiciousDevices(devices)
            Log.i(TAG, "可疑设备检测: ${suspiciousResult.description}")
            items.find { it.checkPoint == "suspicious_devices" }?.let {
                it.status = suspiciousResult.status
                it.description = suspiciousResult.description
            }

            // 获取设备列表
            val listResult = checkDeviceList(devices)
            Log.i(TAG, "设备列表: ${listResult.description}")
            items.find { it.checkPoint == "input_device_list" }?.let {
                it.status = listResult.status
                it.description = listResult.description
            }

            // 检测键盘设备
            val keyboardResult = checkKeyboardDevices(devices)
            Log.i(TAG, "键盘设备: ${keyboardResult.description}")
            items.find { it.checkPoint == "keyboard_devices" }?.let {
                it.status = keyboardResult.status
                it.description = keyboardResult.description
            }

            // 检测鼠标设备
            val mouseResult = checkMouseDevices(devices)
            Log.i(TAG, "鼠标设备: ${mouseResult.description}")
            items.find { it.checkPoint == "mouse_devices" }?.let {
                it.status = mouseResult.status
                it.description = mouseResult.description
            }

            // 检测触摸屏设备
            val touchscreenResult = checkTouchscreenDevices(devices)
            Log.i(TAG, "触摸屏设备: ${touchscreenResult.description}")
            items.find { it.checkPoint == "touchscreen_devices" }?.let {
                it.status = touchscreenResult.status
                it.description = touchscreenResult.description
            }

            // 检测压力事件支持
            val pressureResult = checkPressureSupport(touchDevices)
            Log.i(TAG, "压力事件支持: ${pressureResult.description}")
            items.find { it.checkPoint == "pressure_support" }?.let {
                it.status = pressureResult.status
                it.description = pressureResult.description
            }

            // 检测触摸大小支持
            val sizeResult = checkTouchSizeSupport(touchDevices)
            Log.i(TAG, "触摸大小支持: ${sizeResult.description}")
            items.find { it.checkPoint == "touch_size_support" }?.let {
                it.status = sizeResult.status
                it.description = sizeResult.description
            }

            // 检测触摸分辨率
            val resolutionResult = checkTouchResolution(touchDevices)
            Log.i(TAG, "触摸分辨率: ${resolutionResult.description}")
            items.find { it.checkPoint == "touch_resolution" }?.let {
                it.status = resolutionResult.status
                it.description = resolutionResult.description
            }

            // 检测坐标范围合理性
            val axisRangeResult = checkAxisRange(touchDevices)
            Log.i(TAG, "坐标范围: ${axisRangeResult.description}")
            items.find { it.checkPoint == "axis_range_check" }?.let {
                it.status = axisRangeResult.status
                it.description = axisRangeResult.description
            }

            // 触摸功能完整性评估
            val integrityResult = checkTouchFunctionIntegrity(
                touchDevices, pressureResult, sizeResult, resolutionResult, axisRangeResult
            )
            Log.i(TAG, "触摸功能完整性: ${integrityResult.description}")
            items.find { it.checkPoint == "touch_function_integrity" }?.let {
                it.status = integrityResult.status
                it.description = integrityResult.description
            }

            // 检测游戏手柄
            val gamepadResult = checkGamepadDevices(devices)
            Log.i(TAG, "游戏手柄: ${gamepadResult.description}")
            items.find { it.checkPoint == "gamepad_devices" }?.let {
                it.status = gamepadResult.status
                it.description = gamepadResult.description
            }

            // 综合安全检测
            val securityResult = checkInputSecurity(
                countResult, suspiciousResult, devices, integrityResult
            )
            Log.i(TAG, "输入设备安全性: ${securityResult.description}")
            items.find { it.checkPoint == "input_security" }?.let {
                it.status = securityResult.status
                it.description = securityResult.description
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
     * 获取所有输入设备信息
     */
    private fun getInputDevices(context: Context): List<InputDeviceInfo> {
        val devices = mutableListOf<InputDeviceInfo>()
        
        try {
            val inputManager = context.getSystemService(Context.INPUT_SERVICE) as InputManager
            val deviceIds = inputManager.inputDeviceIds
            
            for (deviceId in deviceIds) {
                try {
                    val device = inputManager.getInputDevice(deviceId)
                    if (device != null) {
                        devices.add(InputDeviceInfo.fromDevice(device))
                    }
                } catch (e: Exception) {
                    Log.w(TAG, "获取设备 $deviceId 信息失败: ${e.message}")
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "获取输入设备列表失败: ${e.message}")
        }
        
        return devices
    }

    /**
     * 检测输入设备数量
     */
    private fun checkDeviceCount(devices: List<InputDeviceInfo>): CheckResult {
        val count = devices.size

        return when {
            count == 0 -> CheckResult(CheckStatus.FAIL, "未检测到任何输入设备 (异常)")
            count < 2 -> CheckResult(CheckStatus.FAIL, "只检测到 $count 个输入设备 (过少)")
            count > 20 -> CheckResult(CheckStatus.FAIL, "检测到 $count 个输入设备 (过多，可能异常)")
            else -> CheckResult(CheckStatus.PASS, "检测到 $count 个输入设备")
        }
    }

    /**
     * 检测可疑设备
     */
    private fun checkSuspiciousDevices(devices: List<InputDeviceInfo>): CheckResult {
        val suspiciousDevices = mutableListOf<Pair<String, String>>()

        for (device in devices) {
            for (keyword in SUSPICIOUS_KEYWORDS) {
                if (device.name.contains(keyword, ignoreCase = true)) {
                    suspiciousDevices.add(Pair(device.name, keyword))
                    Log.w(TAG, "发现可疑设备: ${device.name} (匹配关键词: $keyword)")
                    break
                }
            }
        }

        return if (suspiciousDevices.isNotEmpty()) {
            val deviceNames = suspiciousDevices.map { it.first }.distinct().take(3).joinToString(", ")
            val keywordStr = suspiciousDevices.map { it.second }.distinct().take(3).joinToString(", ")
            CheckResult(
                CheckStatus.FAIL,
                "发现 ${suspiciousDevices.size} 个可疑设备: $deviceNames (关键词: $keywordStr)"
            )
        } else {
            CheckResult(CheckStatus.PASS, "未发现可疑输入设备")
        }
    }

    /**
     * 检测设备列表
     */
    private fun checkDeviceList(devices: List<InputDeviceInfo>): CheckResult {
        if (devices.isEmpty()) {
            return CheckResult(CheckStatus.FAIL, "无设备")
        }

        val deviceNames = devices.map { it.name }
        val displayNames = if (deviceNames.size <= 5) {
            deviceNames.joinToString(", ")
        } else {
            deviceNames.take(5).joinToString(", ") + " 等共 ${devices.size} 个"
        }

        return CheckResult(CheckStatus.PASS, displayNames)
    }

    /**
     * 检测键盘设备
     */
    private fun checkKeyboardDevices(devices: List<InputDeviceInfo>): CheckResult {
        val keyboards = devices.filter {
            (it.sources and InputDevice.SOURCE_KEYBOARD) == InputDevice.SOURCE_KEYBOARD ||
            it.keyboardType != InputDevice.KEYBOARD_TYPE_NONE
        }

        return if (keyboards.isNotEmpty()) {
            val names = keyboards.map { it.name }.distinct().take(3).joinToString(", ")
            CheckResult(CheckStatus.PASS, "${keyboards.size} 个: $names")
        } else {
            CheckResult(CheckStatus.FAIL, "未检测到键盘设备")
        }
    }

    /**
     * 检测鼠标/触摸板设备
     */
    private fun checkMouseDevices(devices: List<InputDeviceInfo>): CheckResult {
        val mice = devices.filter {
            (it.sources and InputDevice.SOURCE_MOUSE) == InputDevice.SOURCE_MOUSE ||
            (it.sources and InputDevice.SOURCE_TOUCHPAD) == InputDevice.SOURCE_TOUCHPAD
        }

        return if (mice.isNotEmpty()) {
            val names = mice.map { it.name }.distinct().take(3).joinToString(", ")
            CheckResult(CheckStatus.PASS, "${mice.size} 个: $names")
        } else {
            // 移动设备可能没有鼠标，不判定为失败
            CheckResult(CheckStatus.PASS, "未检测到鼠标 (正常)")
        }
    }

    /**
     * 检测触摸屏设备
     */
    private fun checkTouchscreenDevices(devices: List<InputDeviceInfo>): CheckResult {
        val touchscreens = devices.filter { it.isTouchscreen }

        return if (touchscreens.isNotEmpty()) {
            val names = touchscreens.map { it.name }.distinct().take(3).joinToString(", ")
            CheckResult(CheckStatus.PASS, "${touchscreens.size} 个: $names")
        } else {
            // 检查是否为电视/机顶盒等无触摸屏设备
            val hasTouch = devices.any {
                it.name.contains("touch", ignoreCase = true) ||
                it.name.contains("screen", ignoreCase = true)
            }
            if (hasTouch) {
                CheckResult(CheckStatus.PASS, "可能支持触摸但未识别到专用触摸屏设备")
            } else {
                CheckResult(CheckStatus.FAIL, "未检测到触摸屏设备")
            }
        }
    }

    /**
     * 检测压力事件支持
     */
    private fun checkPressureSupport(devices: List<InputDeviceInfo>): CheckResult {
        if (devices.isEmpty()) {
            return CheckResult(CheckStatus.FAIL, "无触摸屏设备")
        }

        val pressureSupported = devices.filter { it.hasPressure }

        if (pressureSupported.isEmpty()) {
            return CheckResult(CheckStatus.FAIL, "触摸屏不支持压力检测")
        }

        // 检查压力范围的合理性
        val pressureRanges = pressureSupported.map { device ->
            device.getRange(MotionEvent.AXIS_PRESSURE)
        }.filterNotNull()

        if (pressureRanges.isEmpty()) {
            return CheckResult(CheckStatus.PASS, "${pressureSupported.size} 个设备支持压力检测 (范围未知)")
        }

        // 验证压力范围的合理性
        val allReasonable = pressureRanges.all { range ->
            range.min >= PRESSURE_MIN &&
            range.max <= PRESSURE_MAX &&
            range.max > range.min
        }

        val rangeStr = pressureRanges.firstOrNull()?.let {
            "${it.min}~${it.max}"
        } ?: "unknown"

        return if (allReasonable) {
            CheckResult(CheckStatus.PASS, "${pressureSupported.size} 个设备支持压力检测 (范围: $rangeStr) ✓")
        } else {
            CheckResult(CheckStatus.FAIL, "压力范围异常: $rangeStr (期望值: $PRESSURE_MIN~$PRESSURE_MAX)")
        }
    }

    /**
     * 检测触摸大小支持
     */
    private fun checkTouchSizeSupport(devices: List<InputDeviceInfo>): CheckResult {
        if (devices.isEmpty()) {
            return CheckResult(CheckStatus.FAIL, "无触摸屏设备")
        }

        val sizeSupported = devices.filter { it.hasSize }

        if (sizeSupported.isEmpty()) {
            return CheckResult(CheckStatus.FAIL, "触摸屏不支持触摸大小检测")
        }

        // 检查触摸大小范围的合理性
        val sizeRanges = sizeSupported.map { device ->
            device.getRange(MotionEvent.AXIS_SIZE)
        }.filterNotNull()

        if (sizeRanges.isEmpty()) {
            return CheckResult(CheckStatus.PASS, "${sizeSupported.size} 个设备支持触摸大小检测 (范围未知)")
        }

        // 验证触摸大小范围的合理性
        val allReasonable = sizeRanges.all { range ->
            range.min >= SIZE_MIN &&
            range.max <= SIZE_MAX &&
            range.max > range.min
        }

        val rangeStr = sizeRanges.firstOrNull()?.let {
            "${it.min}~${it.max}"
        } ?: "unknown"

        return if (allReasonable) {
            CheckResult(CheckStatus.PASS, "${sizeSupported.size} 个设备支持触摸大小 (范围: $rangeStr) ✓")
        } else {
            CheckResult(CheckStatus.FAIL, "触摸大小范围异常: $rangeStr (期望值: $SIZE_MIN~$SIZE_MAX)")
        }
    }

    /**
     * 检测触摸分辨率/精度
     */
    private fun checkTouchResolution(devices: List<InputDeviceInfo>): CheckResult {
        if (devices.isEmpty()) {
            return CheckResult(CheckStatus.FAIL, "无触摸屏设备")
        }

        // 获取 X 和 Y 轴的分辨率
        val xResolutions = mutableListOf<Pair<String, Float>>()
        val yResolutions = mutableListOf<Pair<String, Float>>()

        for (device in devices) {
            device.getRange(MotionEvent.AXIS_X)?.let { range ->
                if (range.resolution > 0) {
                    xResolutions.add(Pair(device.name, range.resolution))
                }
            }
            device.getRange(MotionEvent.AXIS_Y)?.let { range ->
                if (range.resolution > 0) {
                    yResolutions.add(Pair(device.name, range.resolution))
                }
            }
        }

        if (xResolutions.isEmpty() && yResolutions.isEmpty()) {
            // 某些设备可能不报告分辨率，这不一定是异常
            return CheckResult(CheckStatus.PASS, "未获取到分辨率信息 (可能未报告)")
        }

        // 检查分辨率的合理性
        val allXReasonable = xResolutions.all {
            it.second in RESOLUTION_MIN..RESOLUTION_MAX
        }
        val allYReasonable = yResolutions.all {
            it.second in RESOLUTION_MIN..RESOLUTION_MAX
        }

        val xAvg = if (xResolutions.isNotEmpty()) {
            xResolutions.map { it.second }.average()
        } else null
        val yAvg = if (yResolutions.isNotEmpty()) {
            yResolutions.map { it.second }.average()
        } else null

        val resStr = when {
            xAvg != null && yAvg != null -> "X=${String.format("%.2f", xAvg)}, Y=${String.format("%.2f", yAvg)}"
            xAvg != null -> "X=${String.format("%.2f", xAvg)}"
            yAvg != null -> "Y=${String.format("%.2f", yAvg)}"
            else -> "unknown"
        }

        return if (allXReasonable && allYReasonable) {
            CheckResult(CheckStatus.PASS, "分辨率: $resStr dpi ✓")
        } else {
            val abnormal = mutableListOf<String>()
            xResolutions.filter { it.second !in RESOLUTION_MIN..RESOLUTION_MAX }.forEach {
                abnormal.add("${it.first}: X=${it.second}")
            }
            yResolutions.filter { it.second !in RESOLUTION_MIN..RESOLUTION_MAX }.forEach {
                abnormal.add("${it.first}: Y=${it.second}")
            }
            CheckResult(CheckStatus.FAIL, "分辨率异常: ${abnormal.take(2).joinToString(", ")}")
        }
    }

    /**
     * 检测坐标范围合理性
     */
    private fun checkAxisRange(devices: List<InputDeviceInfo>): CheckResult {
        if (devices.isEmpty()) {
            return CheckResult(CheckStatus.FAIL, "无触摸屏设备")
        }

        val xRanges = mutableListOf<RangeInfo>()
        val yRanges = mutableListOf<RangeInfo>()

        for (device in devices) {
            device.getRange(MotionEvent.AXIS_X)?.let { range ->
                xRanges.add(RangeInfo(device.name, range.min, range.max))
            }
            device.getRange(MotionEvent.AXIS_Y)?.let { range ->
                yRanges.add(RangeInfo(device.name, range.min, range.max))
            }
        }

        if (xRanges.isEmpty() || yRanges.isEmpty()) {
            return CheckResult(CheckStatus.FAIL, "无法获取坐标范围")
        }

        // 检查范围的合理性
        val xAllReasonable = xRanges.all {
            it.max > it.min &&
            it.max in AXIS_RANGE_MIN..AXIS_RANGE_MAX &&
            it.min >= AXIS_RANGE_MIN
        }
        val yAllReasonable = yRanges.all {
            it.max > it.min &&
            it.max in AXIS_RANGE_MIN..AXIS_RANGE_MAX &&
            it.min >= AXIS_RANGE_MIN
        }

        // 获取最大范围
        val maxX = xRanges.maxByOrNull { it.max }?.max ?: 0f
        val maxY = yRanges.maxByOrNull { it.max }?.max ?: 0f

        return if (xAllReasonable && yAllReasonable) {
            CheckResult(CheckStatus.PASS, "坐标范围: ${maxX.toInt()}x${maxY.toInt()} ✓")
        } else {
            val abnormal = mutableListOf<String>()
            xRanges.filter { it.max !in AXIS_RANGE_MIN..AXIS_RANGE_MAX }.forEach {
                abnormal.add("${it.deviceName}: X max=${it.max}")
            }
            yRanges.filter { it.max !in AXIS_RANGE_MIN..AXIS_RANGE_MAX }.forEach {
                abnormal.add("${it.deviceName}: Y max=${it.max}")
            }
            CheckResult(CheckStatus.FAIL, "坐标范围异常: ${abnormal.take(2).joinToString(", ")}")
        }
    }

    /**
     * 检测触摸功能完整性
     */
    private fun checkTouchFunctionIntegrity(
        devices: List<InputDeviceInfo>,
        pressureResult: CheckResult,
        sizeResult: CheckResult,
        resolutionResult: CheckResult,
        axisRangeResult: CheckResult
    ): CheckResult {
        if (devices.isEmpty()) {
            return CheckResult(CheckStatus.FAIL, "无触摸屏设备")
        }

        val checks = listOf(pressureResult, sizeResult, resolutionResult, axisRangeResult)
        val passedCount = checks.count { it.status == CheckStatus.PASS }
        val totalCount = checks.size

        return when {
            passedCount == totalCount ->
                CheckResult(CheckStatus.PASS, "触摸功能完整 (${passedCount}/${totalCount})")
            passedCount >= totalCount / 2 ->
                CheckResult(CheckStatus.PASS, "触摸功能基本完整 (${passedCount}/${totalCount})")
            passedCount >= 1 ->
                CheckResult(CheckStatus.FAIL, "触摸功能不完整 (${passedCount}/${totalCount})")
            else ->
                CheckResult(CheckStatus.FAIL, "触摸功能缺失 (${passedCount}/${totalCount})")
        }
    }

    /**
     * 检测游戏手柄/摇杆设备
     */
    private fun checkGamepadDevices(devices: List<InputDeviceInfo>): CheckResult {
        val gamepads = devices.filter {
            (it.sources and InputDevice.SOURCE_GAMEPAD) == InputDevice.SOURCE_GAMEPAD ||
            (it.sources and InputDevice.SOURCE_JOYSTICK) == InputDevice.SOURCE_JOYSTICK ||
            it.name.contains("gamepad", ignoreCase = true) ||
            it.name.contains("joystick", ignoreCase = true) ||
            it.name.contains("controller", ignoreCase = true)
        }

        return if (gamepads.isNotEmpty()) {
            val names = gamepads.map { it.name }.distinct().take(3).joinToString(", ")
            CheckResult(CheckStatus.PASS, "${gamepads.size} 个: $names")
        } else {
            // 没有游戏手柄是正常情况
            CheckResult(CheckStatus.PASS, "未检测到游戏手柄")
        }
    }

    /**
     * 综合安全检测
     */
    private fun checkInputSecurity(
        countResult: CheckResult,
        suspiciousResult: CheckResult,
        devices: List<InputDeviceInfo>,
        touchIntegrityResult: CheckResult
    ): CheckResult {
        // 如果检测到可疑设备，直接判定为不安全
        if (suspiciousResult.status != CheckStatus.PASS) {
            return CheckResult(CheckStatus.FAIL, "检测到模拟器/虚拟环境特征: ${suspiciousResult.description}")
        }

        // 检查设备数量是否异常
        if (countResult.status != CheckStatus.PASS) {
            return CheckResult(CheckStatus.FAIL, "输入设备数量异常: ${countResult.description}")
        }

        // 检查是否只有虚拟输入设备
        val virtualOnly = devices.all { device ->
            SUSPICIOUS_KEYWORDS.any {
                device.name.contains(it, ignoreCase = true)
            }
        }
        if (virtualOnly && devices.isNotEmpty()) {
            return CheckResult(CheckStatus.FAIL, "所有输入设备均为虚拟设备")
        }

        // 检查触摸功能完整性（针对有触摸屏的设备）
        val touchDevices = devices.filter { it.isTouchscreen }
        if (touchDevices.isNotEmpty() && touchIntegrityResult.status != CheckStatus.PASS) {
            return CheckResult(CheckStatus.FAIL, "触摸屏功能异常: ${touchIntegrityResult.description}")
        }

        // 检查是否有真实物理设备特征
        val hasPhysicalDevice = devices.any { device ->
            device.isExternal ||
            device.name.contains("usb", ignoreCase = true) ||
            device.name.contains("bluetooth", ignoreCase = true) ||
            device.name.contains("hid", ignoreCase = true)
        }

        // 检查是否具有合理的触摸功能
        val hasReasonableTouch = touchDevices.isEmpty() ||
            (touchDevices.any { it.hasPressure || it.hasSize })

        return if ((hasPhysicalDevice || devices.size >= 3) && hasReasonableTouch) {
            CheckResult(CheckStatus.PASS, "输入设备检测通过 (${devices.size} 个设备)")
        } else if (hasReasonableTouch) {
            CheckResult(CheckStatus.PASS, "输入设备正常 (${devices.size} 个设备，功能完整)")
        } else {
            CheckResult(CheckStatus.FAIL, "输入设备可能为虚拟设备 (缺乏物理触摸特征)")
        }
    }

    /**
     * 坐标范围信息
     */
    private data class RangeInfo(
        val deviceName: String,
        val min: Float,
        val max: Float
    )

    /**
     * 输入设备信息数据类
     */
    private data class InputDeviceInfo(
        val id: Int,
        val name: String,
        val descriptor: String,
        val sources: Int,
        val keyboardType: Int,
        val isExternal: Boolean,
        private val motionRanges: Map<Int, MotionRangeData>
    ) {
        /**
         * 是否为触摸屏设备
         */
        val isTouchscreen: Boolean
            get() = (sources and InputDevice.SOURCE_TOUCHSCREEN) == InputDevice.SOURCE_TOUCHSCREEN ||
                    (sources and InputDevice.SOURCE_STYLUS) == InputDevice.SOURCE_STYLUS

        /**
         * 是否支持压力检测
         */
        val hasPressure: Boolean
            get() = motionRanges.containsKey(MotionEvent.AXIS_PRESSURE)

        /**
         * 是否支持触摸面积
         */
        val hasSize: Boolean
            get() = motionRanges.containsKey(MotionEvent.AXIS_SIZE) ||
                    motionRanges.containsKey(MotionEvent.AXIS_TOUCH_MAJOR) ||
                    motionRanges.containsKey(MotionEvent.AXIS_TOUCH_MINOR)

        /**
         * 获取指定轴的范围
         */
        fun getRange(axis: Int): MotionRangeData? = motionRanges[axis]

        companion object {
            fun fromDevice(device: InputDevice): InputDeviceInfo {
                val ranges = mutableMapOf<Int, MotionRangeData>()
                
                // 获取所有 MotionRange
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR1) {
                    try {
                        device.getMotionRanges().forEach { range ->
                            ranges[range.axis] = MotionRangeData.fromRange(range)
                        }
                    } catch (e: Exception) {
                        Log.w(TAG, "获取 MotionRanges 失败: ${e.message}")
                    }
                } else {
                    // 低版本手动获取常用轴
                    try {
                        val axes = intArrayOf(
                            MotionEvent.AXIS_X,
                            MotionEvent.AXIS_Y,
                            MotionEvent.AXIS_PRESSURE,
                            MotionEvent.AXIS_SIZE,
                            MotionEvent.AXIS_TOUCH_MAJOR,
                            MotionEvent.AXIS_TOUCH_MINOR,
                            MotionEvent.AXIS_TOOL_MAJOR,
                            MotionEvent.AXIS_TOOL_MINOR,
                            MotionEvent.AXIS_ORIENTATION
                        )
                        axes.forEach { axis ->
                            device.getMotionRange(axis)?.let { range ->
                                ranges[axis] = MotionRangeData.fromRange(range)
                            }
                        }
                    } catch (e: Exception) {
                        Log.w(TAG, "获取 MotionRange 失败: ${e.message}")
                    }
                }
                
                return InputDeviceInfo(
                    id = device.id,
                    name = device.name ?: "Unknown",
                    descriptor = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                        device.descriptor ?: "Unknown"
                    } else {
                        "Unknown"
                    },
                    sources = device.sources,
                    keyboardType = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN) {
                        device.keyboardType
                    } else {
                        InputDevice.KEYBOARD_TYPE_NONE
                    },
                    isExternal = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN) {
                        try {
                            val method = InputDevice::class.java.getMethod("isExternal")
                            method.invoke(device) as? Boolean ?: false
                        } catch (e: Exception) {
                            false
                        }
                    } else {
                        false
                    },
                    motionRanges = ranges
                )
            }
        }
    }

    /**
     * MotionRange 数据封装
     */
    private data class MotionRangeData(
        val axis: Int,
        val min: Float,
        val max: Float,
        val flat: Float,
        val fuzz: Float,
        val resolution: Float
    ) {
        companion object {
            fun fromRange(range: MotionRange): MotionRangeData {
                return MotionRangeData(
                    axis = range.axis,
                    min = range.min,
                    max = range.max,
                    flat = range.flat,
                    fuzz = range.fuzz,
                    resolution = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR1) {
                        range.resolution
                    } else {
                        0f
                    }
                )
            }
        }
    }
}

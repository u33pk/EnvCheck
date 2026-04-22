package qpdb.env.check.checkers

import android.content.Context
import android.graphics.ImageFormat
import android.hardware.camera2.CameraAccessException
import android.hardware.camera2.CameraCharacteristics
import android.hardware.camera2.CameraManager
import android.os.Build
import android.util.Log
import qpdb.env.check.EnvCheckApp
import qpdb.env.check.model.CheckItem
import qpdb.env.check.model.CheckResult
import qpdb.env.check.model.CheckStatus
import qpdb.env.check.model.Checkable
import qpdb.env.check.utils.FileUtil
import qpdb.env.check.utils.PropertyUtil

class CameraChecker : Checkable {

    companion object {
        private const val TAG = "CameraChecker"
        private const val MIN_MP_BACK = 10.0  // 后置摄像头最低像素 (MP)
        private const val MIN_MP_FRONT = 5.0   // 前置摄像头最低像素 (MP)
        private const val MIN_MP_OTHER = 2.0   // 其他摄像头最低像素 (MP)
    }

    override val categoryName: String = "摄像头信息"

    override fun checkList(): List<CheckItem> {
        return listOf(
            CheckItem(
                name = "摄像头信息",
                checkPoint = "camera_info",
                description = "等待检测..."
            ),
            CheckItem(
                name = "摄像头像素检测",
                checkPoint = "camera_pixel_check",
                description = "等待检测..."
            ),
            CheckItem(
                name = "模拟器摄像头配置检测",
                checkPoint = "emulator_camera_config",
                description = "等待检测..."
            ),
            CheckItem(
                name = "模拟器相机 HAL 检测",
                checkPoint = "emulator_camera_hal",
                description = "等待检测..."
            ),
            CheckItem(
                name = "模拟器相机属性检测",
                checkPoint = "emulator_camera_prop",
                description = "等待检测..."
            ),
            CheckItem(
                name = "模拟器相机服务属性检测",
                checkPoint = "emulator_camera_service_prop",
                description = "等待检测..."
            )
        )
    }

    override fun runCheck(): List<CheckItem> {
        val items = checkList().toMutableList()
        val context = EnvCheckApp.getContext()

        try {
            val (infoResult, pixelResults) = getCameraInfo(context)
            items.find { it.checkPoint == "camera_info" }?.let {
                it.status = infoResult.status
                it.description = infoResult.description
            }
            items.find { it.checkPoint == "camera_pixel_check" }?.let {
                it.status = pixelResults.status
                it.description = pixelResults.description
            }

            // 模拟器摄像头配置检测
            val emulatorResult = checkEmulatorCameraConfig()
            items.find { it.checkPoint == "emulator_camera_config" }?.let {
                it.status = emulatorResult.status
                it.description = emulatorResult.description
            }

            // 模拟器相机 HAL 检测
            val halResult = checkEmulatorCameraHal()
            items.find { it.checkPoint == "emulator_camera_hal" }?.let {
                it.status = halResult.status
                it.description = halResult.description
            }

            // 模拟器相机属性检测
            val propResult = checkEmulatorCameraProp()
            items.find { it.checkPoint == "emulator_camera_prop" }?.let {
                it.status = propResult.status
                it.description = propResult.description
            }

            // 模拟器相机服务属性检测
            val servicePropResult = checkEmulatorCameraServiceProps()
            items.find { it.checkPoint == "emulator_camera_service_prop" }?.let {
                it.status = servicePropResult.status
                it.description = servicePropResult.description
            }
        } catch (e: Exception) {
            Log.e(TAG, "检测失败: ${e.message}", e)
            items.forEach { item ->
                if (item.description == "等待检测...") {
                    item.status = CheckStatus.FAIL
                    item.description = "检测失败: ${e.message}"
                }
            }
        }

        return items
    }

    private fun getCameraInfo(context: Context): Pair<CheckResult, CheckResult> {
        val cameraManager = context.getSystemService(Context.CAMERA_SERVICE) as CameraManager
        val cameraDetails = mutableListOf<String>()
        val lowPixelCameras = mutableListOf<Triple<String, Double, Double>>() // (cameraId, mp, minMp)

        try {
            val logicalMap = getAllPhysicalCameras(cameraManager)
            val processedPhysicalIds = mutableSetOf<String>()

            for ((logicalId, physicalIds) in logicalMap) {
                val logicalCharacteristics = cameraManager.getCameraCharacteristics(logicalId)
                val isLogical = physicalIds.size > 1 || !physicalIds.contains(logicalId)

                val logicalFacing = getFacingName(logicalCharacteristics)

                val detail = buildString {
                    if (isLogical) {
                        append("逻辑摄像头 ID:$logicalId ($logicalFacing)")
                        append("\n包含 ${physicalIds.size} 个物理摄像头")
                    }

                    // 展示每个物理摄像头的详细信息
                    for (physicalId in physicalIds) {
                        // 去重：避免物理摄像头被重复检测
                        if (!processedPhysicalIds.add(physicalId)) continue

                        append("\n")
                        if (isLogical) {
                            append("\n--- 物理摄像头 ID:$physicalId ---")
                        } else {
                            append("摄像头 ID:$physicalId ($logicalFacing)")
                        }

                        try {
                            val phyChars = getPhysicalCharacteristics(cameraManager, physicalId)
                            if (phyChars != null) {
                                val facing = getFacingName(phyChars)
                                append("\n  方向: $facing")
                                append("\n  硬件级别: ${getHardwareLevel(phyChars)}")

                                // 传感器信息
                                val sensorSize = phyChars.get(CameraCharacteristics.SENSOR_INFO_PHYSICAL_SIZE)
                                val activeArray = phyChars.get(CameraCharacteristics.SENSOR_INFO_ACTIVE_ARRAY_SIZE)
                                val pixelArray = phyChars.get(CameraCharacteristics.SENSOR_INFO_PIXEL_ARRAY_SIZE)
                                if (sensorSize != null) {
                                    append("\n  传感器: ${String.format("%.2f", sensorSize.width)}mm x ${String.format("%.2f", sensorSize.height)}mm")
                                }

                                // 计算传感器像素（活跃阵列优先）
                                val sensorPixels = if (activeArray != null) {
                                    activeArray.width() * activeArray.height()
                                } else if (pixelArray != null) {
                                    pixelArray.width * pixelArray.height
                                } else {
                                    0
                                }

                                // 从支持的流配置中获取最大输出像素和尺寸
                                val map = phyChars.get(CameraCharacteristics.SCALER_STREAM_CONFIGURATION_MAP)
                                var maxJpegPixels = 0
                                var maxJpegSize: android.util.Size? = null
                                var maxOutputPixels = 0
                                var maxOutputSize: android.util.Size? = null
                                if (map != null) {
                                    val formats = listOf(ImageFormat.JPEG, ImageFormat.YUV_420_888, ImageFormat.RAW_SENSOR)
                                    for (format in formats) {
                                        val sizes = map.getOutputSizes(format)
                                        if (sizes != null) {
                                            for (size in sizes) {
                                                val pixels = size.width * size.height
                                                if (pixels > maxOutputPixels) {
                                                    maxOutputPixels = pixels
                                                    maxOutputSize = size
                                                }
                                                if (format == ImageFormat.JPEG && pixels > maxJpegPixels) {
                                                    maxJpegPixels = pixels
                                                    maxJpegSize = size
                                                }
                                            }
                                        }
                                    }
                                }

                                // 取传感器像素和最大输出像素的较大者作为摄像头像素能力
                                // 高像素传感器（如50MP/200MP）通常以合并模式暴露传感器尺寸，
                                // 但实际支持更高的输出分辨率，因此必须参考 SCALER_STREAM_CONFIGURATION_MAP
                                val pixelCount = maxOf(sensorPixels, maxOutputPixels)
                                if (pixelCount > 0) {
                                    val mp = pixelCount / 1_000_000.0
                                    val mpStr = String.format("%.1f", mp)
                                    append(" | ${mpStr}MP")

                                    // 如果流配置的最大输出大于传感器报告尺寸，标注实际最大输出分辨率
                                    if (maxOutputPixels > sensorPixels && maxOutputSize != null) {
                                        append(" (最大输出 ${maxOutputSize.width}x${maxOutputSize.height})")
                                    }

                                    // 根据朝向确定阈值并记录低像素摄像头
                                    val minMp = when (facing) {
                                        "后置" -> MIN_MP_BACK
                                        "前置" -> MIN_MP_FRONT
                                        else -> MIN_MP_OTHER
                                    }
                                    if (mp < minMp) {
                                        lowPixelCameras.add(Triple(physicalId, mp, minMp))
                                    }
                                }

                                // 焦距和光圈
                                val focalLengths = phyChars.get(CameraCharacteristics.LENS_INFO_AVAILABLE_FOCAL_LENGTHS)
                                val apertures = phyChars.get(CameraCharacteristics.LENS_INFO_AVAILABLE_APERTURES)
                                if (focalLengths != null && focalLengths.isNotEmpty()) {
                                    append("\n  焦距: ${focalLengths.joinToString(", ") { "${it}mm" }}")
                                }
                                if (apertures != null && apertures.isNotEmpty()) {
                                    append(" | 光圈: ${apertures.joinToString(", ") { "f/$it" }}")
                                }

                                // 对焦能力
                                val afModes = phyChars.get(CameraCharacteristics.CONTROL_AF_AVAILABLE_MODES)
                                val hasAutoFocus = afModes?.any { it != CameraCharacteristics.CONTROL_AF_MODE_OFF } == true
                                append("\n  自动对焦: ${if (hasAutoFocus) "支持" else "不支持"}")

                                // OIS
                                val ois = phyChars.get(CameraCharacteristics.LENS_INFO_AVAILABLE_OPTICAL_STABILIZATION)
                                val hasOis = ois?.any { it == CameraCharacteristics.LENS_OPTICAL_STABILIZATION_MODE_ON } == true
                                append(" | OIS: ${if (hasOis) "支持" else "不支持"}")

                                // 闪光灯
                                val flash = phyChars.get(CameraCharacteristics.FLASH_INFO_AVAILABLE) ?: false
                                append(" | 闪光灯: ${if (flash) "支持" else "不支持"}")

                                // ISO范围
                                val isoRange = phyChars.get(CameraCharacteristics.SENSOR_INFO_SENSITIVITY_RANGE)
                                if (isoRange != null) {
                                    append("\n  ISO: ${isoRange.lower}-${isoRange.upper}")
                                }

                                // 最大帧率 / 最大分辨率（基于 JPEG 最大尺寸）
                                if (map != null && maxJpegSize != null) {
                                    try {
                                        val minDuration = map.getOutputMinFrameDuration(ImageFormat.JPEG, maxJpegSize)
                                        if (minDuration > 0) {
                                            val fps = 1_000_000_000L / minDuration
                                            append(" | 最大帧率: ${fps}fps@${maxJpegSize.width}x${maxJpegSize.height}")
                                        } else {
                                            append(" | 最大分辨率: ${maxJpegSize.width}x${maxJpegSize.height}")
                                        }
                                    } catch (e: Exception) {
                                        append(" | 最大分辨率: ${maxJpegSize.width}x${maxJpegSize.height}")
                                    }
                                }
                            } else {
                                append("\n  (无法获取详细信息)")
                            }
                        } catch (e: Exception) {
                            append("\n  (获取失败: ${e.message})")
                        }
                    }
                }

                cameraDetails.add(detail)
            }

            val totalPhysical = logicalMap.values.sumOf { it.size }
            val logicalCount = logicalMap.count { it.value.size > 1 || !it.value.contains(it.key) }
            val summary = "共 ${logicalMap.size} 个摄像头 (逻辑: $logicalCount, 物理: $totalPhysical)"
            val fullDescription = "$summary\n\n${cameraDetails.joinToString("\n\n")}"

            val infoResult = CheckResult(CheckStatus.PASS, fullDescription)

            // 像素检测结果
            val pixelResult = if (lowPixelCameras.isEmpty()) {
                CheckResult(CheckStatus.PASS, "所有摄像头像素均满足最低要求")
            } else {
                val desc = lowPixelCameras.joinToString(", ") {
                    "ID:${it.first} (${String.format("%.1f", it.second)}MP, 要求 ${String.format("%.1f", it.third)}MP)"
                }
                CheckResult(CheckStatus.FAIL, "像素异常: $desc")
            }

            return Pair(infoResult, pixelResult)

        } catch (e: CameraAccessException) {
            Log.e(TAG, "获取摄像头信息失败: ${e.message}")
            val failResult = CheckResult(CheckStatus.FAIL, "获取失败: ${e.message}")
            return Pair(failResult, failResult)
        }
    }

    private fun getPhysicalCharacteristics(
        manager: CameraManager,
        physicalId: String
    ): CameraCharacteristics? {
        return try {
            manager.getCameraCharacteristics(physicalId)
        } catch (e: Exception) {
            Log.w(TAG, "获取物理摄像头 $physicalId 特性失败: ${e.message}")
            null
        }
    }

    private fun getFacingName(characteristics: CameraCharacteristics): String {
        return when (characteristics.get(CameraCharacteristics.LENS_FACING)) {
            CameraCharacteristics.LENS_FACING_BACK -> "后置"
            CameraCharacteristics.LENS_FACING_FRONT -> "前置"
            CameraCharacteristics.LENS_FACING_EXTERNAL -> "外部"
            else -> "未知"
        }
    }

    private fun getHardwareLevel(characteristics: CameraCharacteristics): String {
        return when (characteristics.get(CameraCharacteristics.INFO_SUPPORTED_HARDWARE_LEVEL)) {
            CameraCharacteristics.INFO_SUPPORTED_HARDWARE_LEVEL_LIMITED -> "LIMITED"
            CameraCharacteristics.INFO_SUPPORTED_HARDWARE_LEVEL_FULL -> "FULL"
            CameraCharacteristics.INFO_SUPPORTED_HARDWARE_LEVEL_LEGACY -> "LEGACY"
            CameraCharacteristics.INFO_SUPPORTED_HARDWARE_LEVEL_3 -> "LEVEL_3"
            else -> "未知"
        }
    }

    private fun getAllPhysicalCameras(manager: CameraManager): Map<String, Set<String>> {
        val result = mutableMapOf<String, Set<String>>()

        try {
            for (cameraId in manager.cameraIdList) {
                val characteristics = manager.getCameraCharacteristics(cameraId)

                val capabilities = characteristics.get(
                    CameraCharacteristics.REQUEST_AVAILABLE_CAPABILITIES
                ) ?: intArrayOf()

                val isLogical = capabilities.contains(
                    CameraCharacteristics.REQUEST_AVAILABLE_CAPABILITIES_LOGICAL_MULTI_CAMERA
                )

                if (isLogical) {
                    val physicalIds = characteristics.physicalCameraIds
                    result[cameraId] = physicalIds.toSet()
                    Log.d(TAG, "逻辑摄像头 $cameraId 包含物理摄像头: $physicalIds")
                } else {
                    result[cameraId] = setOf(cameraId)
                    Log.d(TAG, "物理摄像头 $cameraId")
                }
            }
        } catch (e: CameraAccessException) {
            Log.e(TAG, "获取摄像头失败: ${e.message}")
        }

        return result
    }

    private fun checkEmulatorCameraConfig(): CheckResult {
        val configFileDir = "/vendor/etc/config/"
        val emulatorFiles = listOf(
            "emu_camera_back.json",
            "emu_camera_depth.json",
            "emu_camera_front.json"
        )

        val foundFiles = mutableListOf<String>()

        for (fileName in emulatorFiles) {
            val filePath = configFileDir + fileName
            if (FileUtil.fileExists(filePath)) {
                foundFiles.add(fileName)
                Log.w(TAG, "发现模拟器摄像头配置文件: $filePath")
            }
        }

        return if (foundFiles.isNotEmpty()) {
            CheckResult(CheckStatus.FAIL, "检测到模拟器摄像头配置: ${foundFiles.joinToString(", ")}")
        } else {
            CheckResult(CheckStatus.PASS, "未检测到模拟器摄像头配置")
        }
    }

    private fun checkEmulatorCameraHal(): CheckResult {
        val halPath = "/apex/com.google.emulated.camera.provider.hal"

        return if (FileUtil.fileExists(halPath)) {
            Log.w(TAG, "发现模拟器相机 HAL 路径: $halPath")
            CheckResult(CheckStatus.FAIL, "检测到模拟器相机 HAL: $halPath")
        } else {
            CheckResult(CheckStatus.PASS, "未检测到模拟器相机 HAL")
        }
    }

    private fun checkEmulatorCameraProp(): CheckResult {
        val propName = "ro.boot.vendor.apex.com.google.emulated.camera.provider.hal"
        val propValue = PropertyUtil.getProp(propName)

        return if (propValue != null && propValue.contains("emulated", ignoreCase = true)) {
            Log.w(TAG, "发现模拟器相机属性: $propName = $propValue")
            CheckResult(CheckStatus.FAIL, "属性值: $propValue")
        } else {
            CheckResult(CheckStatus.PASS, "属性值: $propValue")
        }
    }

    private fun checkEmulatorCameraServiceProps(): CheckResult {
        val propPrefixes = listOf(
            "init.svc.vendor.camera-provider-",
            "init.svc_debug_pid.vendor.camera-provider-",
            "ro.boottime.vendor.camera-provider-"
        )

        val foundProps = mutableListOf<String>()
        var checkedCount = 0

        for (prefix in propPrefixes) {
            for (major in 0..3) {
                for (minor in 0..9) {
                    if (major == 0 && minor < 1) continue
                    if (major == 3 && minor > 0) continue

                    val version = "$major-$minor"
                    val propName = "$prefix$version"
                    val propValue = PropertyUtil.getProp(propName)
                    checkedCount++

                    if (propValue != null) {
                        foundProps.add("$propName = $propValue")
                        Log.d(TAG, "找到属性: $propName = $propValue")
                    }
                }
            }
        }

        return if (foundProps.isNotEmpty()) {
            val desc = buildString {
                append("命中 ${foundProps.size} 个属性:")
                for (prop in foundProps) {
                    append("\n  $prop")
                }
            }
            CheckResult(CheckStatus.FAIL, desc)
        } else {
            CheckResult(CheckStatus.PASS, "所有属性均为 null (共检测 $checkedCount 个)")
        }
    }
}

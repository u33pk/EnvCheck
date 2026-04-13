package qpdb.env.check.checkers

import android.util.Log
import qpdb.env.check.model.CheckItem
import qpdb.env.check.model.CheckResult
import qpdb.env.check.model.CheckStatus
import qpdb.env.check.model.Checkable
import qpdb.env.check.utils.EmulatorDetector
import qpdb.env.check.utils.GpuInfoUtil

/**
 * GPU 信息检测
 * 从 Vulkan 和 OpenGL 两个角度检测 GPU 属性
 *
 * 判定规则：
 * - 真实手机通常使用 Mali/Adreno/PowerVR 等移动 GPU。
 * - 若出现 NVIDIA/AMD/Intel 等 PC 显卡厂商名称，说明是模拟器在利用 PC 硬件加速，并非真实手机，判定为 FAIL。
 * - 若出现 AOSP/ANGLE/QEMU/virto/SwiftShader/llvmpipe 等字样，同样判定为 FAIL（模拟器特征）。
 *
 * 实现说明：
 * - OpenGL 信息通过 EGL14 创建 Pbuffer 上下文，在后台线程安全调用 GLES API 获取
 * - Vulkan 信息通过 C++ 原生代码调用 Vulkan API 获取
 * - 同时通过 dl_iterate_phdr 检测模拟器相关 SO 是否被加载
 * - 枚举 Vulkan/OpenGL 扩展，检测是否包含真实厂商特有前缀
 */
class GpuChecker : Checkable {

    companion object {
        private const val TAG = "GpuChecker"
    }

    override val categoryName: String = "GPU信息"

    override fun checkList(): List<CheckItem> {
        Log.i(TAG, "checkList() 被调用")
        return listOf(
            CheckItem(
                name = "OpenGL 渲染器",
                checkPoint = "opengl_renderer",
                description = "等待检测..."
            ),
            CheckItem(
                name = "OpenGL 版本",
                checkPoint = "opengl_version",
                description = "等待检测..."
            ),
            CheckItem(
                name = "OpenGL 厂商",
                checkPoint = "opengl_vendor",
                description = "等待检测..."
            ),
            CheckItem(
                name = "OpenGL 扩展厂商特征",
                checkPoint = "opengl_extensions_vendor",
                description = "等待检测..."
            ),
            CheckItem(
                name = "Vulkan GPU 信息",
                checkPoint = "vulkan_gpu",
                description = "等待检测..."
            ),
            CheckItem(
                name = "Vulkan 扩展厂商特征",
                checkPoint = "vulkan_extensions_vendor",
                description = "等待检测..."
            ),
            CheckItem(
                name = "模拟器 SO 加载检测",
                checkPoint = "emulator_so",
                description = "等待检测..."
            ),
            CheckItem(
                name = "GPU 硬件属性",
                checkPoint = "gpu_hardware",
                description = "等待检测..."
            ),
            CheckItem(
                name = "GPU 运算性能测试",
                checkPoint = "gpu_compute",
                description = "等待检测..."
            ),
            CheckItem(
                name = "模拟器特征综合判定",
                checkPoint = "emulator_check",
                description = "等待检测..."
            )
        )
    }

    override fun runCheck(): List<CheckItem> {
        Log.i(TAG, "runCheck() 被调用")

        val items = checkList().toMutableList()
        val detectedKeywords = mutableListOf<String>()

        try {
            // 1. OpenGL 信息（通过 EGL14 创建上下文获取）
            val openGlInfo = GpuInfoUtil.getOpenGlInfoWithEGL()

            // OpenGL 渲染器
            val rendererMatched = EmulatorDetector.findEmulatorKeywords(openGlInfo.renderer)
            val rendererResult = if (rendererMatched.isNotEmpty()) {
                detectedKeywords.add("OpenGL渲染器: ${openGlInfo.renderer}")
                CheckResult(CheckStatus.FAIL, "${openGlInfo.renderer} (模拟器特征: ${rendererMatched.joinToString(", ")})")
            } else {
                CheckResult(CheckStatus.PASS, openGlInfo.renderer)
            }
            items.find { it.checkPoint == "opengl_renderer" }?.let {
                it.status = rendererResult.status
                it.description = rendererResult.description
            }

            // OpenGL 版本
            val versionMatched = EmulatorDetector.findEmulatorKeywords(openGlInfo.version)
            val versionResult = if (versionMatched.isNotEmpty()) {
                detectedKeywords.add("OpenGL版本: ${openGlInfo.version}")
                CheckResult(CheckStatus.FAIL, "${openGlInfo.version} (模拟器特征: ${versionMatched.joinToString(", ")})")
            } else {
                CheckResult(CheckStatus.PASS, openGlInfo.version)
            }
            items.find { it.checkPoint == "opengl_version" }?.let {
                it.status = versionResult.status
                it.description = versionResult.description
            }

            // OpenGL 厂商
            val vendorMatched = EmulatorDetector.findEmulatorKeywords(openGlInfo.vendor)
            val vendorResult = if (vendorMatched.isNotEmpty()) {
                detectedKeywords.add("OpenGL厂商: ${openGlInfo.vendor}")
                CheckResult(CheckStatus.FAIL, "${openGlInfo.vendor} (模拟器特征: ${vendorMatched.joinToString(", ")})")
            } else {
                CheckResult(CheckStatus.PASS, openGlInfo.vendor)
            }
            items.find { it.checkPoint == "opengl_vendor" }?.let {
                it.status = vendorResult.status
                it.description = vendorResult.description
            }

            // OpenGL 扩展厂商特征
            val glVendorExts = openGlInfo.extensions.split(" ").filter { it.isNotEmpty() }
            Log.i(TAG, "runCheck: ${EmulatorDetector.GL_VENDOR_PREFIXES}")
            val glMatchedVendorExts = glVendorExts.filter { ext ->
                Log.i(TAG, "runCheck: $ext")
                EmulatorDetector.GL_VENDOR_PREFIXES.any { prefix -> ext.startsWith(prefix, ignoreCase = true) }
            }
            val glExtResult = if (glMatchedVendorExts.isNotEmpty()) {
                CheckResult(CheckStatus.FAIL, "发现 ${glMatchedVendorExts.size} 个厂商扩展: ${glMatchedVendorExts.take(5).joinToString(", ")}${if (glMatchedVendorExts.size > 5) "..." else ""}")
            } else {
                detectedKeywords.add("OpenGL无厂商扩展(共${glVendorExts.size}个)")
                CheckResult(CheckStatus.FAIL, "未检测到厂商特有扩展 (共 ${glVendorExts.size} 个扩展)")
            }
            items.find { it.checkPoint == "opengl_extensions_vendor" }?.let {
                it.status = glExtResult.status
                it.description = glExtResult.description
            }

            // 2. Vulkan GPU 信息
            val vulkanResult = EmulatorDetector.checkVulkanGpu()
            Log.i(TAG, "Vulkan GPU: ${vulkanResult.description}")
            items.find { it.checkPoint == "vulkan_gpu" }?.let {
                it.status = vulkanResult.status
                it.description = vulkanResult.description
            }
            if (vulkanResult.status == CheckStatus.FAIL) {
                detectedKeywords.add("Vulkan: ${vulkanResult.description}")
            }

            // 3. Vulkan 扩展厂商特征
            val vulkanExtResult = EmulatorDetector.checkVulkanExtensions()
            Log.i(TAG, "Vulkan 扩展: ${vulkanExtResult.description}")
            items.find { it.checkPoint == "vulkan_extensions_vendor" }?.let {
                it.status = vulkanExtResult.status
                it.description = vulkanExtResult.description
            }
            if (vulkanExtResult.status == CheckStatus.FAIL) {
                detectedKeywords.add("Vulkan扩展: ${vulkanExtResult.description}")
            }

            // 4. 模拟器 SO 加载检测
            val soResult = EmulatorDetector.checkEmulatorSoLoaded()
            Log.i(TAG, "模拟器 SO: ${soResult.description}")
            items.find { it.checkPoint == "emulator_so" }?.let {
                it.status = soResult.status
                it.description = soResult.description
            }
            if (soResult.status == CheckStatus.FAIL) {
                detectedKeywords.add(soResult.description)
            }

            // 5. GPU 硬件属性
            val hardwareResult = EmulatorDetector.checkGpuHardware()
            Log.i(TAG, "GPU 硬件属性: ${hardwareResult.description}")
            items.find { it.checkPoint == "gpu_hardware" }?.let {
                it.status = hardwareResult.status
                it.description = hardwareResult.description
            }
            if (hardwareResult.status == CheckStatus.FAIL) {
                detectedKeywords.add("GPU硬件: ${hardwareResult.description}")
            }

            // 6. GPU 运算性能测试（仅显示信息，不参与判定）
            val computeResult = GpuInfoUtil.measureGpuCompute()
            Log.i(TAG, "GPU 运算性能: ${computeResult.description}")
            items.find { it.checkPoint == "gpu_compute" }?.let {
                it.status = computeResult.status
                it.description = computeResult.description
            }

            // 7. 综合模拟器判定
            val emulatorResult = EmulatorDetector.checkEmulatorSignature(detectedKeywords)
            Log.i(TAG, "模拟器特征综合判定: ${emulatorResult.description}")
            items.find { it.checkPoint == "emulator_check" }?.let {
                it.status = emulatorResult.status
                it.description = emulatorResult.description
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
}

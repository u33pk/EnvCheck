package qpdb.env.check.utils

import android.app.ActivityManager
import android.util.Log
import qpdb.env.check.EnvCheckApp
import qpdb.env.check.model.CheckResult
import qpdb.env.check.model.CheckStatus

/**
 * 模拟器检测工具类
 * 提供 GPU/系统层面的模拟器特征检测能力
 */
object EmulatorDetector {
    private const val TAG = "EmulatorDetector"

    // 模拟器/可疑特征关键词（不区分大小写）
    // 注意：NVIDIA/AMD/Intel 属于 PC 端显卡厂商，真实 Android 手机不会出现，
    // 若检测到说明当前环境为模拟器或虚拟机使用了硬件加速。
    val EMULATOR_KEYWORDS = listOf(
        "aosp", "nvidia", "amd", "intel", "angle", "qemu", "virto", "virtio",
        "swiftshader", "llvmpipe", "softpipe", "emulation",
        "goldfish", "ranchu", "gvm", "vmware", "virtualbox",
        "bochs", "kvm", "hyperv", "parallels", "fusion",
        "gallium", "mesa", "android sdk", "google"
    )

    // 模拟器相关 SO 库
    private val EMULATOR_SO_LIST = listOf(
        "libEGL_emulation.so",
        "libGLESv1_CM_emulation.so",
        "libGLESv2_emulation.so",
        "libgoldfish.so",
        "libqemud.so",
        "libvmwgfx.so",
        "libvulkan_enc.so",
        "libEGL_angle.so",
        "libGLESv1_CM_angle.so",
        "libGLESv2_angle.so",
    )

    // OpenGL 厂商特有扩展前缀
    val GL_VENDOR_PREFIXES = listOf(
        "GL_NV_", "GL_NVX_", "GL_AMD_", "GL_ATI_", "GL_INTEL_", "ANDROID_EMU_"
    )

    // Vulkan 厂商特有扩展前缀
    val VK_VENDOR_PREFIXES = listOf(
        "VK_NV_", "VK_NVX_", "VK_AMD_", "VK_INTEL_", "VK_GOOGLE_"
    )

    /**
     * 在文本中查找模拟器特征关键词
     */
    fun findEmulatorKeywords(text: String): List<String> {
        val lowerText = text.lowercase()
        return EMULATOR_KEYWORDS.filter { keyword ->
            lowerText.contains(keyword.lowercase())
        }.distinct()
    }

    /**
     * 检测 Vulkan GPU 信息
     */
    fun checkVulkanGpu(): CheckResult {
        return try {
            val vulkanInfo = GpuNativeUtil.nativeGetVulkanInfo()
            if (vulkanInfo.isEmpty()) {
                CheckResult(CheckStatus.INFO, "未获取到 Vulkan 信息（设备可能不支持 Vulkan）")
            } else {
                val matched = findEmulatorKeywords(vulkanInfo)
                if (matched.isNotEmpty()) {
                    CheckResult(CheckStatus.FAIL, "$vulkanInfo (模拟器特征: ${matched.joinToString(", ")})")
                } else {
                    CheckResult(CheckStatus.PASS, vulkanInfo)
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "检测 Vulkan GPU 失败: ${e.message}")
            CheckResult(CheckStatus.INFO, "检测失败: ${e.message}")
        }
    }

    /**
     * 检测 Vulkan 扩展厂商特征
     */
    fun checkVulkanExtensions(): CheckResult {
        return try {
            val extStr = GpuNativeUtil.nativeGetVulkanExtensions()
            if (extStr.isEmpty()) {
                CheckResult(CheckStatus.INFO, "未获取到 Vulkan 扩展信息")
            } else {
                // 解析扩展字符串，格式: [GPU0] ext1 ext2 ext3 | [GPU1] ext4 ext5
                val allExts = mutableListOf<String>()
                extStr.split(" | ").forEach { gpuPart ->
                    val parts = gpuPart.split("] ", limit = 2)
                    if (parts.size == 2) {
                        allExts.addAll(parts[1].split(" ").filter { it.isNotEmpty() })
                    }
                }

                val matchedExts = allExts.filter { ext ->
                    Log.i(TAG, "checkVulkanExtensions: $ext")
                    VK_VENDOR_PREFIXES.any { prefix -> ext.startsWith(prefix, ignoreCase = true) }
                }

                if (matchedExts.isNotEmpty()) {
                    CheckResult(CheckStatus.PASS, "发现 ${matchedExts.size} 个厂商扩展: ${matchedExts.take(5).joinToString(", ")}${if (matchedExts.size > 5) "..." else ""}")
                } else {
                    CheckResult(CheckStatus.FAIL, "未检测到厂商特有 Vulkan 扩展 (共 ${allExts.size} 个扩展)")
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "检测 Vulkan 扩展失败: ${e.message}")
            CheckResult(CheckStatus.INFO, "检测失败: ${e.message}")
        }
    }

    /**
     * 检测模拟器相关 SO 是否被加载
     */
    fun checkEmulatorSoLoaded(): CheckResult {
        return try {
            val loadedSos = EMULATOR_SO_LIST.filter { soName ->
                GpuNativeUtil.nativeIsSoLoaded(soName)
            }

            if (loadedSos.isNotEmpty()) {
                CheckResult(CheckStatus.FAIL, "检测到模拟器 SO: ${loadedSos.joinToString(", ")}")
            } else {
                CheckResult(CheckStatus.PASS, "未检测到模拟器相关 SO")
            }
        } catch (e: Exception) {
            Log.e(TAG, "检测 SO 加载失败: ${e.message}")
            CheckResult(CheckStatus.INFO, "检测失败: ${e.message}")
        }
    }

    /**
     * 检测 GPU 硬件属性（系统属性补充）
     */
    fun checkGpuHardware(): CheckResult {
        return try {
            val gpuProps = listOf(
                "ro.hardware.egl",
                "ro.opengles.version",
                "ro.product.gpu",
                "ro.hardware.gpu",
                "ro.board.platform",
                "ro.hardware",
                "ro.hardware.vulkan"
            )

            val results = mutableListOf<String>()
            var hasEmulatorSign = false

            gpuProps.forEach { prop ->
                val value = SystemPropertyUtil.getSystemProperty(prop)
                if (value.isNotEmpty()) {
                    results.add("$prop=$value")
                    val matched = findEmulatorKeywords(value)
                    if (matched.isNotEmpty()) {
                        hasEmulatorSign = true
                        results.add("(模拟器特征: ${matched.joinToString(", ")})")
                    }
                }
            }

            // ActivityManager 中的 GL ES 版本要求
            val context = EnvCheckApp.getContext()
            val activityManager = context.getSystemService(android.content.Context.ACTIVITY_SERVICE) as ActivityManager
            val configInfo = activityManager.deviceConfigurationInfo
            configInfo?.let {
                results.add("reqGlEsVersion=${it.reqGlEsVersion}")
            }

            if (results.isEmpty()) {
                CheckResult(CheckStatus.INFO, "未获取到 GPU 硬件属性")
            } else if (hasEmulatorSign) {
                CheckResult(CheckStatus.FAIL, results.joinToString("; "))
            } else {
                CheckResult(CheckStatus.PASS, results.joinToString("; "))
            }
        } catch (e: Exception) {
            Log.e(TAG, "检测 GPU 硬件属性失败: ${e.message}")
            CheckResult(CheckStatus.INFO, "检测失败: ${e.message}")
        }
    }

    /**
     * 综合模拟器特征判定
     */
    fun checkEmulatorSignature(detectedKeywords: List<String>): CheckResult {
        return if (detectedKeywords.isNotEmpty()) {
            CheckResult(
                CheckStatus.FAIL,
                "检测到 ${detectedKeywords.size} 项模拟器 GPU 特征"
            )
        } else {
            CheckResult(CheckStatus.PASS, "未检测到模拟器 GPU 特征")
        }
    }
}

package qpdb.env.check.checkers

import android.annotation.SuppressLint
import android.content.Context
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.util.Log
import android.webkit.JavascriptInterface
import android.webkit.WebSettings
import android.webkit.WebView
import android.webkit.WebViewClient
import qpdb.env.check.EnvCheckApp
import qpdb.env.check.model.CheckItem
import qpdb.env.check.model.CheckResult
import qpdb.env.check.model.CheckStatus
import qpdb.env.check.model.Checkable
import java.io.BufferedReader
import java.io.IOException
import java.io.InputStreamReader
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * WebView 指纹检测
 * 检测 Canvas WebGL、Canvas 2D、User Agent、WebView 版本、字体、AudioContext 等指纹信息
 */
class WebViewFingerPrintChecker : Checkable {

    companion object {
        private const val TAG = "WebViewFingerPrintChecker"
        private const val JS_TIMEOUT_MS = 10000L // 10秒超时
        private const val ASSETS_HTML_PATH = "file:///android_asset/fingerprint/fingerprint.html"
    }

    override val categoryName: String = "WebView指纹"

    // 存储 JavaScript 返回的指纹数据
    private var fingerprintData = mutableMapOf<String, String>()
    private var jsExecutionComplete = false

    override fun checkList(): List<CheckItem> {
        Log.i(TAG, "checkList() 被调用")
        return listOf(
            // User Agent
            CheckItem(
                name = "User Agent",
                checkPoint = "user_agent",
                description = "等待检测..."
            ),
            // WebView 版本
            CheckItem(
                name = "WebView 版本",
                checkPoint = "webview_version",
                description = "等待检测..."
            ),
            // Android/Chromium 版本对照
            CheckItem(
                name = "Android/Chromium 版本对照",
                checkPoint = "android_chromium_version",
                description = "等待检测..."
            ),
            // Canvas 2D 指纹
            CheckItem(
                name = "Canvas 2D 指纹",
                checkPoint = "canvas_2d",
                description = "等待检测..."
            ),
            // WebGL 指纹
            CheckItem(
                name = "WebGL 指纹",
                checkPoint = "webgl",
                description = "等待检测..."
            ),
            // WebGL Vendor & Renderer
            CheckItem(
                name = "WebGL 厂商/渲染器",
                checkPoint = "webgl_vendor_renderer",
                description = "等待检测..."
            ),
            // 字体指纹
            CheckItem(
                name = "字体指纹",
                checkPoint = "font",
                description = "等待检测..."
            ),
            // AudioContext 指纹
            CheckItem(
                name = "AudioContext 指纹",
                checkPoint = "audio_context",
                description = "等待检测..."
            ),
            // 屏幕信息
            CheckItem(
                name = "屏幕/视口信息",
                checkPoint = "screen_info",
                description = "等待检测..."
            ),
            // 时区信息
            CheckItem(
                name = "时区/语言",
                checkPoint = "timezone_language",
                description = "等待检测..."
            ),
            // 硬件并发数
            CheckItem(
                name = "硬件并发数",
                checkPoint = "hardware_concurrency",
                description = "等待检测..."
            ),
            // 设备内存
            CheckItem(
                name = "设备内存",
                checkPoint = "device_memory",
                description = "等待检测..."
            ),
            // 触摸支持
            CheckItem(
                name = "触摸支持",
                checkPoint = "touch_support",
                description = "等待检测..."
            )
        )
    }

    /**
     * 执行实际检测
     */
    @SuppressLint("SetJavaScriptEnabled")
    override fun runCheck(): List<CheckItem> {
        Log.i(TAG, "runCheck() 被调用")

        val items = checkList().toMutableList()
        val context = EnvCheckApp.getContext()

        // 检查资源文件是否存在
        if (!isAssetsFileExists(context, "fingerprint/fingerprint.html") ||
            !isAssetsFileExists(context, "fingerprint/fingerprint.js")) {
            Log.e(TAG, "资源文件不存在")
            items.forEach { item ->
                item.status = CheckStatus.FAIL
                item.description = "资源文件缺失"
            }
            return items
        }

        // 在主线程中创建和使用 WebView
        val latch = CountDownLatch(1)
        val handler = Handler(Looper.getMainLooper())

        handler.post {
            try {
                collectFingerprintsViaWebView(context) { success ->
                    if (success) {
                        Log.i(TAG, "指纹收集成功")
                    } else {
                        Log.w(TAG, "指纹收集失败或超时")
                    }
                    latch.countDown()
                }
            } catch (e: Exception) {
                Log.e(TAG, "WebView 初始化失败: ${e.message}", e)
                latch.countDown()
            }
        }

        // 等待 JavaScript 执行完成
        try {
            latch.await(JS_TIMEOUT_MS, TimeUnit.MILLISECONDS)
        } catch (e: InterruptedException) {
            Log.e(TAG, "等待 JavaScript 执行被中断", e)
        }

        // 更新检测项结果
        try {
            // User Agent
            val uaResult = checkUserAgent()
            Log.i(TAG, "User Agent: ${uaResult.description}")
            items.find { it.checkPoint == "user_agent" }?.let {
                it.status = uaResult.status
                it.description = uaResult.description
            }

            // WebView 版本
            val versionResult = checkWebViewVersion()
            Log.i(TAG, "WebView 版本: ${versionResult.description}")
            items.find { it.checkPoint == "webview_version" }?.let {
                it.status = versionResult.status
                it.description = versionResult.description
            }

            // Android/Chromium 版本对照
            val androidChromiumResult = checkAndroidChromiumVersion()
            Log.i(TAG, "Android/Chromium 版本对照: ${androidChromiumResult.description}")
            items.find { it.checkPoint == "android_chromium_version" }?.let {
                it.status = androidChromiumResult.status
                it.description = androidChromiumResult.description
            }

            // Canvas 2D
            val canvas2dResult = checkCanvas2D()
            Log.i(TAG, "Canvas 2D: ${canvas2dResult.description}")
            items.find { it.checkPoint == "canvas_2d" }?.let {
                it.status = canvas2dResult.status
                it.description = canvas2dResult.description
            }

            // WebGL
            val webglResult = checkWebGL()
            Log.i(TAG, "WebGL: ${webglResult.description}")
            items.find { it.checkPoint == "webgl" }?.let {
                it.status = webglResult.status
                it.description = webglResult.description
            }

            // WebGL Vendor & Renderer
            val webglVendorResult = checkWebGLVendorRenderer()
            Log.i(TAG, "WebGL Vendor/Renderer: ${webglVendorResult.description}")
            items.find { it.checkPoint == "webgl_vendor_renderer" }?.let {
                it.status = webglVendorResult.status
                it.description = webglVendorResult.description
            }

            // 字体指纹
            val fontResult = checkFontFingerprint()
            Log.i(TAG, "字体指纹: ${fontResult.description}")
            items.find { it.checkPoint == "font" }?.let {
                it.status = fontResult.status
                it.description = fontResult.description
            }

            // AudioContext
            val audioResult = checkAudioContext()
            Log.i(TAG, "AudioContext: ${audioResult.description}")
            items.find { it.checkPoint == "audio_context" }?.let {
                it.status = audioResult.status
                it.description = audioResult.description
            }

            // 屏幕信息
            val screenResult = checkScreenInfo()
            Log.i(TAG, "屏幕信息: ${screenResult.description}")
            items.find { it.checkPoint == "screen_info" }?.let {
                it.status = screenResult.status
                it.description = screenResult.description
            }

            // 时区/语言
            val timezoneResult = checkTimezoneLanguage()
            Log.i(TAG, "时区/语言: ${timezoneResult.description}")
            items.find { it.checkPoint == "timezone_language" }?.let {
                it.status = timezoneResult.status
                it.description = timezoneResult.description
            }

            // 硬件并发数
            val concurrencyResult = checkHardwareConcurrency()
            Log.i(TAG, "硬件并发数: ${concurrencyResult.description}")
            items.find { it.checkPoint == "hardware_concurrency" }?.let {
                it.status = concurrencyResult.status
                it.description = concurrencyResult.description
            }

            // 设备内存
            val memoryResult = checkDeviceMemory()
            Log.i(TAG, "设备内存: ${memoryResult.description}")
            items.find { it.checkPoint == "device_memory" }?.let {
                it.status = memoryResult.status
                it.description = memoryResult.description
            }

            // 触摸支持
            val touchResult = checkTouchSupport()
            Log.i(TAG, "触摸支持: ${touchResult.description}")
            items.find { it.checkPoint == "touch_support" }?.let {
                it.status = touchResult.status
                it.description = touchResult.description
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
     * 检查 assets 文件是否存在
     */
    private fun isAssetsFileExists(context: Context, filePath: String): Boolean {
        return try {
            context.assets.open(filePath).close()
            true
        } catch (e: IOException) {
            false
        }
    }

    /**
     * 使用 WebView 收集指纹信息
     */
    @SuppressLint("SetJavaScriptEnabled", "AddJavascriptInterface")
    private fun collectFingerprintsViaWebView(context: Context, callback: (Boolean) -> Unit) {
        var webView: WebView? = null

        try {
            webView = WebView(context)
            val settings = webView.settings

            // 启用 JavaScript
            settings.javaScriptEnabled = true
            settings.domStorageEnabled = true
            settings.cacheMode = WebSettings.LOAD_NO_CACHE

            // 添加 JavaScript 接口
            webView.addJavascriptInterface(FingerprintJSInterface { key, value ->
                fingerprintData[key] = value
                Log.d(TAG, "JS 返回: $key = ${value.take(50)}...")
                
                // 检测是否完成
                if (key == "fingerprintComplete") {
                    jsExecutionComplete = true
                    callback(fingerprintData.isNotEmpty())
                    destroyWebView(webView!!)
                }
            }, "FingerprintBridge")

            // 设置 WebViewClient
            webView.webViewClient = object : WebViewClient() {
                override fun onPageFinished(view: WebView?, url: String?) {
                    super.onPageFinished(view, url)
                    Log.i(TAG, "页面加载完成: $url")
                }
            }

            // 从 assets 加载 HTML 文件
            webView.loadUrl(ASSETS_HTML_PATH)

            // 设置超时回调
            Handler(Looper.getMainLooper()).postDelayed({
                if (!jsExecutionComplete) {
                    jsExecutionComplete = true
                    callback(fingerprintData.isNotEmpty())
                    destroyWebView(webView)
                }
            }, 5000)

        } catch (e: Exception) {
            Log.e(TAG, "WebView 执行失败: ${e.message}", e)
            jsExecutionComplete = true
            callback(false)
            webView?.let { destroyWebView(it) }
        }
    }

    /**
     * 销毁 WebView，释放资源
     */
    private fun destroyWebView(webView: WebView) {
        try {
            webView.stopLoading()
            webView.loadUrl("about:blank")
            webView.removeAllViews()
            webView.destroy()
        } catch (e: Exception) {
            Log.w(TAG, "销毁 WebView 时出错: ${e.message}")
        }
    }

    /**
     * JavaScript 接口，用于接收 WebView 中的指纹数据
     */
    private inner class FingerprintJSInterface(private val callback: (String, String) -> Unit) {
        @JavascriptInterface
        fun onFingerprintData(key: String, value: String) {
            callback(key, value)
        }
    }

    // ==================== 各项检测方法 ====================

    private fun checkUserAgent(): CheckResult {
        val ua = fingerprintData["userAgent"] ?: getDefaultUserAgent()
        return if (ua != "unknown") {
            CheckResult(CheckStatus.PASS, ua)
        } else {
            CheckResult(CheckStatus.FAIL, "无法获取 User Agent")
        }
    }

    private fun checkWebViewVersion(): CheckResult {
        val version = fingerprintData["webviewVersion"] ?: "unknown"
        val appVersion = fingerprintData["appVersion"] ?: "unknown"
        val platform = fingerprintData["platform"] ?: "unknown"

        return if (version != "unknown") {
            CheckResult(CheckStatus.PASS, "${version} | 平台: ${platform}")
        } else {
            CheckResult(CheckStatus.FAIL, "无法获取 WebView 版本")
        }
    }

    private fun checkCanvas2D(): CheckResult {
        val hash = fingerprintData["canvas2dHash"] ?: "unknown"
        val length = fingerprintData["canvas2dLength"] ?: "0"

        return when {
            hash.startsWith("error") -> CheckResult(CheckStatus.FAIL, "Canvas 2D 错误: ${hash.substring(7)}")
            hash == "unknown" -> CheckResult(CheckStatus.FAIL, "无法获取 Canvas 2D 指纹")
            else -> CheckResult(CheckStatus.PASS, "指纹: ${hash} (数据长度: ${length})")
        }
    }

    private fun checkWebGL(): CheckResult {
        val hash = fingerprintData["webglHash"] ?: "unknown"

        return when {
            hash == "0" || hash == "unknown" -> CheckResult(CheckStatus.FAIL, "WebGL 不支持或已禁用")
            else -> CheckResult(CheckStatus.PASS, "指纹: ${hash}")
        }
    }

    private fun checkWebGLVendorRenderer(): CheckResult {
        val vendor = fingerprintData["webglVendor"] ?: "unknown"
        val renderer = fingerprintData["webglRenderer"] ?: "unknown"

        return when {
            vendor == "not supported" -> CheckResult(CheckStatus.FAIL, "WebGL 不支持")
            vendor.startsWith("error") -> CheckResult(CheckStatus.FAIL, "WebGL 错误")
            vendor == "restricted" -> CheckResult(CheckStatus.FAIL, "WebGL 信息被限制")
            else -> CheckResult(CheckStatus.PASS, "${vendor} | ${renderer}")
        }
    }

    private fun checkFontFingerprint(): CheckResult {
        val fonts = fingerprintData["detectedFonts"] ?: "unknown"
        val count = fingerprintData["fontCount"] ?: "0"

        return when {
            fonts.startsWith("error") -> CheckResult(CheckStatus.FAIL, "字体检测错误")
            fonts == "unknown" -> CheckResult(CheckStatus.FAIL, "无法检测字体")
            else -> CheckResult(CheckStatus.PASS, "检测到 ${count} 种字体")
        }
    }

    private fun checkAudioContext(): CheckResult {
        val hash = fingerprintData["audioHash"] ?: "unknown"
        val sampleRate = fingerprintData["audioSampleRate"] ?: "0"
        val baseLatency = fingerprintData["audioBaseLatency"] ?: "unknown"

        return when {
            hash == "not supported" -> CheckResult(CheckStatus.FAIL, "AudioContext 不支持")
            hash.startsWith("error") -> CheckResult(CheckStatus.FAIL, "AudioContext 错误")
            hash == "unknown" -> CheckResult(CheckStatus.FAIL, "无法获取 AudioContext 指纹")
            else -> CheckResult(CheckStatus.PASS, "指纹: ${hash} (采样率: ${sampleRate}Hz)")
        }
    }

    private fun checkScreenInfo(): CheckResult {
        val width = fingerprintData["screenWidth"] ?: "0"
        val height = fingerprintData["screenHeight"] ?: "0"
        val colorDepth = fingerprintData["screenColorDepth"] ?: "0"
        val pixelRatio = fingerprintData["screenPixelRatio"] ?: "1"
        val vpWidth = fingerprintData["viewportWidth"] ?: "0"
        val vpHeight = fingerprintData["viewportHeight"] ?: "0"

        return CheckResult(
            CheckStatus.PASS,
            "屏幕: ${width}x${height} (${colorDepth}bit) DPR: ${pixelRatio} | 视口: ${vpWidth}x${vpHeight}"
        )
    }

    private fun checkTimezoneLanguage(): CheckResult {
        val timezone = fingerprintData["timezone"] ?: "unknown"
        val offset = fingerprintData["timezoneOffset"] ?: "0"
        val language = fingerprintData["language"] ?: "unknown"
        val languages = fingerprintData["languages"] ?: language

        val offsetHours = offset.toIntOrNull()?.let {
            val sign = if (it <= 0) "+" else "-"
            "${sign}${kotlin.math.abs(it / 60)}"
        } ?: "?"

        return if (timezone != "unknown") {
            CheckResult(CheckStatus.PASS, "${timezone} (UTC${offsetHours}) | 语言: ${languages}")
        } else {
            CheckResult(CheckStatus.FAIL, "无法获取时区信息")
        }
    }

    private fun checkHardwareConcurrency(): CheckResult {
        val cores = fingerprintData["hardwareConcurrency"] ?: "unknown"

        return if (cores != "unknown") {
            CheckResult(CheckStatus.PASS, "${cores} 核心")
        } else {
            CheckResult(CheckStatus.FAIL, "无法获取硬件并发数")
        }
    }

    private fun checkDeviceMemory(): CheckResult {
        val memory = fingerprintData["deviceMemory"] ?: "unknown"

        return if (memory != "unknown") {
            CheckResult(CheckStatus.PASS, "${memory} GB")
        } else {
            CheckResult(CheckStatus.FAIL, "无法获取设备内存 (可能受限)")
        }
    }

    private fun checkTouchSupport(): CheckResult {
        val maxTouchPoints = fingerprintData["maxTouchPoints"] ?: "0"
        val touchEvent = fingerprintData["touchEvent"] ?: "no"

        val hasTouch = maxTouchPoints.toIntOrNull()?.let { it > 0 } ?: false
        val touchEnabled = hasTouch || touchEvent == "yes"

        return CheckResult(
            CheckStatus.PASS,
            if (touchEnabled) "支持 (最多 ${maxTouchPoints} 点触摸)" else "不支持触摸"
        )
    }

    /**
     * 检查 Android 版本与 Chromium 版本对照
     * 对照规则：
     * - Android 13 -> Chromium >= 105
     * - Android 14 -> Chromium >= 117
     * - Android 15 -> Chromium >= 120
     * - Android 16 -> Chromium >= 130
     */
    private fun checkAndroidChromiumVersion(): CheckResult {
        val ua = fingerprintData["userAgent"] ?: getDefaultUserAgent()

        // 从 User Agent 提取 Chromium 版本
        val chromiumVersion = extractChromiumVersion(ua)

        // 获取 Android 版本
        val androidVersion = Build.VERSION.RELEASE
        val androidApiLevel = Build.VERSION.SDK_INT

        if (chromiumVersion == null) {
            return CheckResult(CheckStatus.FAIL, "无法从 UA 提取 Chromium 版本")
        }

        // 定义版本对照表
        val versionRequirements = mapOf(
            33 to 105,  // Android 13 (API 33)
            34 to 117,  // Android 14 (API 34)
            35 to 120,  // Android 15 (API 35)
            36 to 130   // Android 16 (API 36)
        )

        // 查找当前 Android 版本的要求
        val requiredChromium = versionRequirements[androidApiLevel]

        return if (requiredChromium != null) {
            if (chromiumVersion >= requiredChromium) {
                CheckResult(
                    CheckStatus.PASS,
                    "Android ${androidVersion} (API ${androidApiLevel}) 对应 Chromium ${chromiumVersion} >= ${requiredChromium} ✓"
                )
            } else {
                CheckResult(
                    CheckStatus.FAIL,
                    "Android ${androidVersion} (API ${androidApiLevel}) 要求 Chromium >= ${requiredChromium}, 实际 ${chromiumVersion} ✗"
                )
            }
        } else {
            // 对于不在对照表中的版本，只记录信息不判定失败
            if (androidApiLevel < 33) {
                CheckResult(CheckStatus.PASS, "Android ${androidVersion} (API ${androidApiLevel}) 低于 Android 13, Chromium ${chromiumVersion}")
            } else {
                CheckResult(CheckStatus.PASS, "Android ${androidVersion} (API ${androidApiLevel}) 版本对照表未定义, Chromium ${chromiumVersion}")
            }
        }
    }

    /**
     * 从 User Agent 提取 Chromium 版本号
     * @return 版本号数字（如 120），提取失败返回 null
     */
    private fun extractChromiumVersion(userAgent: String): Int? {
        // 尝试匹配 Chrome/Chromium 版本: Chrome/120.0.0.0 或 Chromium/120.0.0.0
        val patterns = listOf(
            "Chrome/(\\d+)".toRegex(),
            "Chromium/(\\d+)".toRegex(),
            "CrMo/(\\d+)".toRegex(),
            "CriOS/(\\d+)".toRegex()  // iOS Chrome
        )
        
        for (pattern in patterns) {
            val match = pattern.find(userAgent)
            if (match != null) {
                return match.groupValues[1].toIntOrNull()
            }
        }
        
        return null
    }

    /**
     * 获取默认 User Agent（作为备选）
     */
    private fun getDefaultUserAgent(): String {
        return try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR1) {
                WebSettings.getDefaultUserAgent(EnvCheckApp.getContext())
            } else {
                "unknown"
            }
        } catch (e: Exception) {
            "unknown"
        }
    }
}

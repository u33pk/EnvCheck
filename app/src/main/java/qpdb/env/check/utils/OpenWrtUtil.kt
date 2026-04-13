package qpdb.env.check.utils

import android.content.Context
import android.util.Log

/**
 * OpenWrt 网关检测工具类
 * 专门用于检测网关是否为 OpenWrt 以及是否存在未授权访问
 */
object OpenWrtUtil {

    private const val TAG = "OpenWrtUtil"
    private const val CONNECT_TIMEOUT = 5000
    private const val READ_TIMEOUT = 5000
    private const val MAX_REDIRECTS = 3  // 最大重定向次数

    /**
     * OpenWrt 检测结果数据类
     */
    data class OpenWrtCheckResult(
        val gatewayIp: String?,
        val isOpenWrt: Boolean,
        val isVulnerable: Boolean,  // 是否无需密码可访问
        val loginUrl: String?,
        val finalUrl: String?,  // 最终跳转后的 URL
        val redirectCount: Int,  // 重定向次数
        val responseCode: Int,
        val responseHeaders: Map<String, String>,
        val analysis: String,
        val details: List<String>
    ) {
        fun getFullDescription(): String {
            return buildString {
                append(analysis)
                if (details.isNotEmpty()) {
                    append(" | ")
                    append(details.joinToString("; "))
                }
            }
        }
    }

    /**
     * 检测网关是否为 OpenWrt 且存在未授权访问
     * 遍历所有网关，优先返回存在漏洞的结果
     *
     * @param context 应用上下文
     * @return OpenWrtCheckResult 检测结果
     */
    @JvmStatic
    fun detectOpenWrtGateway(context: Context): OpenWrtCheckResult {
        val details = mutableListOf<String>()

        // 1. 获取所有网关 IP（只处理 IPv4）
        val gatewayIps = NetworkUtil.getGatewayIps(context).filter { NetworkUtil.isIpv4Address(it) }
        
        if (gatewayIps.isEmpty()) {
            return OpenWrtCheckResult(
                gatewayIp = null,
                isOpenWrt = false,
                isVulnerable = false,
                loginUrl = null,
                finalUrl = null,
                redirectCount = 0,
                responseCode = -1,
                responseHeaders = emptyMap(),
                analysis = "无法获取网关地址",
                details = listOf("请检查网络连接")
            )
        }

        details.add("网关: ${gatewayIps.joinToString(", ")}")

        // 2. 遍历所有网关，检查是否有任何一个存在 OpenWrt
        var finalResult: OpenWrtCheckResult? = null

        for (gatewayIp in gatewayIps) {
            val checkResult = checkSingleGateway(gatewayIp)

            // 如果找到 OpenWrt，优先记录存在漏洞的
            if (checkResult.isOpenWrt) {
                if (checkResult.isVulnerable) {
                    // 发现漏洞，立即返回
                    finalResult = checkResult
                    details.addAll(checkResult.details)
                    break
                } else if (finalResult == null) {
                    // 记录第一个发现的 OpenWrt
                    finalResult = checkResult
                }
            }
        }

        // 3. 如果没有发现任何 OpenWrt
        val checkResult = finalResult ?: OpenWrtCheckResult(
            gatewayIp = gatewayIps.firstOrNull(),
            isOpenWrt = false,
            isVulnerable = false,
            loginUrl = null,
            finalUrl = null,
            redirectCount = 0,
            responseCode = -1,
            responseHeaders = emptyMap(),
            analysis = "",
            details = emptyList()
        )

        details.addAll(checkResult.details)

        // 4. 分析结果
        val analysis = when {
            checkResult.isVulnerable -> 
                "检测到 OpenWrt 网关(${checkResult.gatewayIp})未设置密码，存在严重安全风险"
            checkResult.isOpenWrt -> 
                "检测到 OpenWrt 网关(${checkResult.gatewayIp})，已设置密码"
            checkResult.responseCode > 0 -> 
                "网关未识别为 OpenWrt (HTTP ${checkResult.responseCode})"
            else -> "无法访问网关管理页面"
        }

        return OpenWrtCheckResult(
            gatewayIp = checkResult.gatewayIp,
            isOpenWrt = checkResult.isOpenWrt,
            isVulnerable = checkResult.isVulnerable,
            loginUrl = checkResult.loginUrl,
            finalUrl = checkResult.finalUrl,
            redirectCount = checkResult.redirectCount,
            responseCode = checkResult.responseCode,
            responseHeaders = checkResult.responseHeaders,
            analysis = analysis,
            details = details
        )
    }

    /**
     * 检查单个网关是否为 OpenWrt
     */
    private fun checkSingleGateway(gatewayIp: String): OpenWrtCheckResult {
        val urlsToTry = listOf(
            "http://$gatewayIp",
            "https://$gatewayIp",
            "http://$gatewayIp:80/",
            "http://$gatewayIp:8080/",
            "http://$gatewayIp/cgi-bin/luci",
            "http://$gatewayIp/cgi-bin/luci/admin",
            "http://$gatewayIp/index.html"
        )

        for (url in urlsToTry) {
            val result = tryAccessOpenWrt(url)
            if (result.isOpenWrt) {
                return result.copy(gatewayIp = gatewayIp)
            }
        }

        // 都未识别为 OpenWrt，返回最后一次尝试的结果
        return tryAccessOpenWrt("http://$gatewayIp").copy(gatewayIp = gatewayIp)
    }

    /**
     * 尝试访问 OpenWrt 页面
     * 使用 HttpUtil.httpGetWithDetails 处理请求和重定向
     */
    private fun tryAccessOpenWrt(urlString: String): OpenWrtCheckResult {
        val details = mutableListOf<String>()

        // 使用 HttpUtil 进行 HTTP 请求（自动处理重定向）
        val response = HttpUtil.httpGetWithDetails(
            urlString = urlString,
            timeoutMs = CONNECT_TIMEOUT,
            userAgent = "Mozilla/5.0 (Linux; Android)",
            maxRedirects = MAX_REDIRECTS
        )

        if (!response.success && response.statusCode == -1) {
            // 请求失败
            return OpenWrtCheckResult(
                gatewayIp = null,
                isOpenWrt = false,
                isVulnerable = false,
                loginUrl = null,
                finalUrl = response.finalUrl,
                redirectCount = response.redirectCount,
                responseCode = response.statusCode,
                responseHeaders = response.headers,
                analysis = "",
                details = listOf("访问失败: ${response.error}")
            )
        }

        // 判断是否为 OpenWrt
        val isOpenWrt = detectOpenWrt(response.headers, response.body, response.finalUrl)

        if (isOpenWrt) {
            details.add("访问地址: $urlString")
            if (response.redirectCount > 0) {
                details.add("重定向次数: ${response.redirectCount}")
                details.add("最终地址: ${response.finalUrl}")
            }

            // 判断是否无需密码
            val isVulnerable = checkIfVulnerable(
                response.statusCode,
                response.body,
                response.headers
            )

            if (isVulnerable) {
                details.add("风险: 无需密码即可访问管理界面")
            }

            return OpenWrtCheckResult(
                gatewayIp = null,
                isOpenWrt = true,
                isVulnerable = isVulnerable,
                loginUrl = urlString,
                finalUrl = response.finalUrl,
                redirectCount = response.redirectCount,
                responseCode = response.statusCode,
                responseHeaders = response.headers,
                analysis = "",
                details = details
            )
        }

        // 未识别为 OpenWrt
        return OpenWrtCheckResult(
            gatewayIp = null,
            isOpenWrt = false,
            isVulnerable = false,
            loginUrl = null,
            finalUrl = response.finalUrl,
            redirectCount = response.redirectCount,
            responseCode = response.statusCode,
            responseHeaders = response.headers,
            analysis = "",
            details = details
        )
    }

    /**
     * 检查是否无需密码即可访问（存在漏洞）
     */
    private fun checkIfVulnerable(
        responseCode: Int,
        responseBody: String,
        headers: Map<String, String>
    ): Boolean {
        val bodyLower = responseBody.lowercase()

        return when {
            // 401/403 表示需要认证
            responseCode == 401 || responseCode == 403 -> false

            // 200 OK 且包含 luci，可能是已登录或无密码
            responseCode == 200 && bodyLower.contains("luci") -> {
                // 检查是否包含登录相关关键词
                val hasLoginForm = bodyLower.contains("<input") &&
                        (bodyLower.contains("password") || bodyLower.contains("pass"))
                val hasLoginKeyword = bodyLower.contains("login") ||
                        bodyLower.contains("登录") ||
                        bodyLower.contains("username")
                val hasLogout = bodyLower.contains("logout") || bodyLower.contains("退出")
                val hasAdminPanel = bodyLower.contains("system") &&
                        bodyLower.contains("network") &&
                        bodyLower.contains("admin")

                // 如果没有登录表单但有管理面板，说明无需密码
                (!hasLoginForm && hasAdminPanel) ||
                        hasLogout ||
                        (bodyLower.contains("admin") && !bodyLower.contains("password"))
            }

            // 其他情况默认不标记为漏洞
            else -> false
        }
    }

    /**
     * 根据响应头和内容判断是否为 OpenWrt
     */
    private fun detectOpenWrt(
        headers: Map<String, String>,
        body: String,
        url: String
    ): Boolean {
        val bodyLower = body.lowercase()
        val server = headers["Server"]?.lowercase() ?: ""

        // 1. 检查 Server 头
        if (server.contains("uhttpd") || server.contains("luci") || server.contains("openwrt")) {
            return true
        }

        // 2. 检查页面内容中的 OpenWrt 特征
        val openWrtIndicators = listOf(
            // 核心标识
            "luci.js",
            "luci-static",
            "/cgi-bin/luci",
            "luci-theme",
            // 页面标题
            "luCI - Lua Configuration Interface",
            "openwrt",
            // 常见路径
            "/admin/system",
            "/admin/network",
            "/admin/status",
            // CSS/JS 文件
            "luci-base",
            "luci-mod",
            // 特定元素
            "data-path=\"admin\"",
            "class=\"cbi-",
            // LEDE（OpenWrt 分支）
            "lede"
        )

        val indicatorCount = openWrtIndicators.count { indicator ->
            bodyLower.contains(indicator.lowercase())
        }

        // 匹配多个特征，认为是 OpenWrt
        if (indicatorCount >= 2) {
            return true
        }

        // 3. 检查 URL 路径
        if (url.contains("/cgi-bin/luci") || url.contains("luci-static")) {
            return true
        }

        // 4. 检查特定的 HTTP 头组合
        if (headers.containsKey("X-Frame-Options") &&
            headers.containsKey("X-XSS-Protection") &&
            (bodyLower.contains("luci") || bodyLower.contains("openwrt"))
        ) {
            return true
        }

        return false
    }

    /**
     * 测试指定 URL 是否为 OpenWrt（用于外部调用）
     */
    @JvmStatic
    fun testUrl(urlString: String): OpenWrtCheckResult {
        return tryAccessOpenWrt(urlString).copy(analysis = "手动测试")
    }
}

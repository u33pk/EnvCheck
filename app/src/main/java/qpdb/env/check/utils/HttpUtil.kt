package qpdb.env.check.utils

import android.util.Log
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.HttpURLConnection
import java.net.URL
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/**
 * HTTP 工具类
 * 提供网络请求和 IP 查询相关功能
 */
object HttpUtil {

    private const val TAG = "HttpUtil"
    private const val DEFAULT_TIMEOUT_MS = 8000

    /**
     * IP 查询服务数据类
     */
    data class IpService(
        val name: String,
        val url: String
    )

    /**
     * 默认的 IP 查询服务列表
     */
    val DEFAULT_IP_SERVICES = listOf(
        IpService("ipinfo.io", "https://ipinfo.io/ip"),
        IpService("cip.cc", "https://cip.cc"),
        IpService("ip.sb", "https://api.ip.sb/ip"),
        IpService("ifconfig.me", "https://ifconfig.me/ip")
    )

    /**
     * 从多个服务获取出口 IP，并进行交叉验证
     *
     * @param services IP 查询服务列表，默认使用 DEFAULT_IP_SERVICES
     * @param timeoutMs 超时时间（毫秒）
     * @return IpCheckResult 包含各服务的查询结果和分析结果
     */
    @JvmStatic
    fun fetchAndValidateExitIp(
        services: List<IpService> = DEFAULT_IP_SERVICES,
        timeoutMs: Int = DEFAULT_TIMEOUT_MS
    ): IpCheckResult {
        val executor = Executors.newFixedThreadPool(services.size)
        val futures = mutableMapOf<String, java.util.concurrent.Future<String?>>()

        // 并行发起请求
        services.forEach { service ->
            val future = executor.submit(Callable {
                fetchIpFromService(service, timeoutMs)
            })
            futures[service.name] = future
        }

        // 收集结果
        val results = mutableMapOf<String, String?>()
        futures.forEach { (name, future) ->
            try {
                results[name] = future.get(timeoutMs.toLong(), TimeUnit.MILLISECONDS)
            } catch (e: Exception) {
                Log.w(TAG, "从 $name 获取IP超时或失败: ${e.message}")
                results[name] = null
            }
        }

        executor.shutdown()

        return analyzeIpResults(results)
    }

    /**
     * 从指定服务获取 IP 地址
     *
     * @param service IP 查询服务
     * @param timeoutMs 超时时间（毫秒）
     * @return IP 地址，获取失败返回 null
     */
    @JvmStatic
    fun fetchIpFromService(service: IpService, timeoutMs: Int = DEFAULT_TIMEOUT_MS): String? {
        return try {
            val url = URL(service.url)
            val connection = url.openConnection() as HttpURLConnection
            connection.apply {
                connectTimeout = timeoutMs
                readTimeout = timeoutMs
                requestMethod = "GET"
                setRequestProperty("User-Agent", "Mozilla/5.0 (Linux; Android)")
            }

            val responseCode = connection.responseCode
            if (responseCode == HttpURLConnection.HTTP_OK) {
                val ip = connection.inputStream.bufferedReader().use { it.readText() }.trim()
                extractIpAddress(ip)
            } else {
                null
            }
        } catch (e: Exception) {
            Log.w(TAG, "获取IP失败 ${service.name}: ${e.message}")
            null
        }
    }

    /**
     * 执行简单的 HTTP GET 请求
     *
     * @param urlString URL 地址
     * @param timeoutMs 超时时间（毫秒）
     * @param userAgent User-Agent 字符串
     * @return 响应内容，请求失败返回 null
     */
    @JvmStatic
    fun httpGet(
        urlString: String,
        timeoutMs: Int = DEFAULT_TIMEOUT_MS,
        userAgent: String = "Mozilla/5.0 (Linux; Android)"
    ): String? {
        return try {
            val url = URL(urlString)
            val connection = url.openConnection() as HttpURLConnection
            connection.apply {
                connectTimeout = timeoutMs
                readTimeout = timeoutMs
                requestMethod = "GET"
                setRequestProperty("User-Agent", userAgent)
            }

            val responseCode = connection.responseCode
            if (responseCode == HttpURLConnection.HTTP_OK) {
                connection.inputStream.bufferedReader().use { it.readText() }
            } else {
                null
            }
        } catch (e: Exception) {
            Log.w(TAG, "HTTP GET 失败: $urlString, ${e.message}")
            null
        }
    }

    /**
     * HTTP 响应结果数据类
     */
    data class HttpResponse(
        val url: String,                    // 原始请求 URL
        val finalUrl: String,               // 最终 URL（跟随重定向后）
        val statusCode: Int,                // HTTP 状态码
        val headers: Map<String, String>,   // 响应头
        val body: String,                   // 响应体
        val redirectCount: Int,             // 重定向次数
        val success: Boolean,               // 是否成功
        val error: String? = null           // 错误信息
    ) {
        /**
         * 获取 Server 头
         */
        fun getServer(): String? = headers["Server"] ?: headers["server"]

        /**
         * 获取 Content-Type
         */
        fun getContentType(): String? = headers["Content-Type"] ?: headers["content-type"]
    }

    /**
     * 执行 HTTP GET 请求，返回完整响应信息（支持自动重定向）
     *
     * @param urlString URL 地址
     * @param timeoutMs 超时时间（毫秒）
     * @param userAgent User-Agent 字符串
     * @param maxRedirects 最大重定向次数
     * @return HttpResponse 完整的响应信息
     */
    @JvmStatic
    fun httpGetWithDetails(
        urlString: String,
        timeoutMs: Int = DEFAULT_TIMEOUT_MS,
        userAgent: String = "Mozilla/5.0 (Linux; Android)",
        maxRedirects: Int = 5
    ): HttpResponse {
        var currentUrl = urlString
        var redirectCount = 0
        val visitedUrls = mutableSetOf<String>()  // 防止循环重定向

        while (redirectCount <= maxRedirects) {
            // 检查循环重定向
            if (currentUrl in visitedUrls) {
                return HttpResponse(
                    url = urlString,
                    finalUrl = currentUrl,
                    statusCode = -1,
                    headers = emptyMap(),
                    body = "",
                    redirectCount = redirectCount,
                    success = false,
                    error = "检测到循环重定向"
                )
            }
            visitedUrls.add(currentUrl)

            try {
                val url = URL(currentUrl)
                val connection = url.openConnection() as HttpURLConnection
                connection.apply {
                    connectTimeout = timeoutMs
                    readTimeout = timeoutMs
                    requestMethod = "GET"
                    setRequestProperty("User-Agent", userAgent)
                    // 启用自动重定向（对于同一协议）
                    instanceFollowRedirects = true
                }

                val responseCode = connection.responseCode

                // 收集响应头
                val headers = connection.headerFields
                    ?.filter { it.key != null }
                    ?.mapKeys { it.key }
                    ?.mapValues { it.value?.firstOrNull() ?: "" }
                    ?: emptyMap()

                // 处理重定向 (301, 302, 303, 307, 308)
                if (responseCode in 300..399) {
                    val location = connection.getHeaderField("Location")
                    if (!location.isNullOrEmpty()) {
                        connection.disconnect()

                        // 构建新的 URL
                        currentUrl = if (location.startsWith("http")) {
                            location
                        } else if (location.startsWith("/")) {
                            "${url.protocol}://${url.host}$location"
                        } else {
                            // 相对路径
                            val base = currentUrl.trimEnd('/')
                            "$base/$location"
                        }

                        Log.d(TAG, "重定向 $redirectCount: $responseCode -> $currentUrl")
                        redirectCount++
                        continue  // 继续循环，访问新地址
                    }
                }

                // 读取响应体
                val body = try {
                    connection.inputStream?.bufferedReader()?.use {
                        it.readText().take(5000)  // 限制大小
                    } ?: ""
                } catch (e: Exception) {
                    connection.errorStream?.bufferedReader()?.use {
                        it.readText().take(5000)
                    } ?: ""
                }

                connection.disconnect()

                return HttpResponse(
                    url = urlString,
                    finalUrl = currentUrl,
                    statusCode = responseCode,
                    headers = headers,
                    body = body,
                    redirectCount = redirectCount,
                    success = responseCode in 200..299
                )

            } catch (e: Exception) {
                Log.w(TAG, "HTTP 请求失败: $currentUrl, $e ${e.message}")
                return HttpResponse(
                    url = urlString,
                    finalUrl = currentUrl,
                    statusCode = -1,
                    headers = emptyMap(),
                    body = "",
                    redirectCount = redirectCount,
                    success = false,
                    error = e.message
                )
            }
        }

        // 超过最大重定向次数
        return HttpResponse(
            url = urlString,
            finalUrl = currentUrl,
            statusCode = -1,
            headers = emptyMap(),
            body = "",
            redirectCount = redirectCount,
            success = false,
            error = "超过最大重定向次数 $maxRedirects"
        )
    }

    /**
     * 从文本中提取 IPv4 地址
     *
     * @param text 包含 IP 的文本
     * @return IPv4 地址，未找到返回 null
     */
    @JvmStatic
    fun extractIpAddress(text: String): String? {
        // 移除 HTML 标签
        var cleaned = text.replace(Regex("<[^>]*>"), "")
        // 移除多余的空白字符
        cleaned = cleaned.trim()
        // 提取 IPv4 地址
        val ipv4Pattern = Regex("""(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""")
        val match = ipv4Pattern.find(cleaned)
        return match?.value
    }

    /**
     * 分析 IP 查询结果
     */
    private fun analyzeIpResults(results: Map<String, String?>): IpCheckResult {
        val validIps = results.values.filterNotNull()

        if (validIps.isEmpty()) {
            return IpCheckResult(
                success = false,
                consistent = false,
                ipResults = results,
                message = "无法从任何服务获取出口IP"
            )
        }

        val uniqueIps = validIps.toSet()
        val successServices = results.filter { it.value != null }.keys.joinToString(", ")

        return when {
            uniqueIps.size == 1 -> {
                IpCheckResult(
                    success = true,
                    consistent = true,
                    ipAddress = uniqueIps.first(),
                    ipResults = results,
                    message = "出口IP一致: ${uniqueIps.first()} (来源: $successServices)"
                )
            }
            validIps.size >= 2 -> {
                IpCheckResult(
                    success = true,
                    consistent = false,
                    ipResults = results,
                    message = "出口IP不一致，可能存在代理/VPN"
                )
            }
            else -> {
                IpCheckResult(
                    success = true,
                    consistent = true,
                    ipAddress = validIps.first(),
                    ipResults = results,
                    message = "仅部分服务返回IP: ${validIps.first()}"
                )
            }
        }
    }

    /**
     * IP 检测结果数据类
     */
    data class IpCheckResult(
        val success: Boolean,
        val consistent: Boolean,
        val ipAddress: String? = null,
        val ipResults: Map<String, String?>,
        val message: String
    ) {
        /**
         * 获取详细的 IP 对比信息
         */
        fun getDetailInfo(): String {
            return ipResults.filter { it.value != null }
                .map { "${it.key}=${it.value}" }
                .joinToString(", ")
        }
    }

    /**
     * RTT 测量结果数据类
     */
    data class RttResult(
        val url: String,
        val rttMs: Long,
        val success: Boolean,
        val error: String? = null
    )

    /**
     * 测量到指定 URL 的 RTT（往返时延）
     *
     * @param urlString 目标 URL
     * @param timeoutMs 超时时间（毫秒）
     * @return RttResult RTT 测量结果
     */
    @JvmStatic
    fun measureRtt(urlString: String, timeoutMs: Int = DEFAULT_TIMEOUT_MS): RttResult {
        val startTime = System.currentTimeMillis()
        
        return try {
            val url = URL(urlString)
            val connection = url.openConnection() as HttpURLConnection
            connection.apply {
                connectTimeout = timeoutMs
                readTimeout = timeoutMs
                requestMethod = "HEAD"  // 使用 HEAD 请求减少数据传输
                setRequestProperty("User-Agent", "Mozilla/5.0 (Linux; Android)")
                // 禁用重定向，减少额外跳转带来的误差
                instanceFollowRedirects = false
            }

            val responseCode = connection.responseCode
            val endTime = System.currentTimeMillis()
            val rtt = endTime - startTime

            if (responseCode in 200..399) {
                RttResult(urlString, rtt, true)
            } else {
                // 即使返回非 200，只要能连上也算成功
                RttResult(urlString, rtt, true, "HTTP $responseCode")
            }
        } catch (e: Exception) {
            RttResult(urlString, -1, false, e.message)
        }
    }

    /**
     * 批量测量多个 URL 的 RTT
     *
     * @param urls URL 列表
     * @param timeoutMs 超时时间（毫秒）
     * @return List<RttResult> 测量结果列表
     */
    @JvmStatic
    fun measureRttMultiple(urls: List<String>, timeoutMs: Int = DEFAULT_TIMEOUT_MS): List<RttResult> {
        return urls.map { measureRtt(it, timeoutMs) }
    }

    /**
     * 测量 IP 查询服务的 RTT（并行执行）
     *
     * @param services IP 查询服务列表
     * @param timeoutMs 超时时间（毫秒）
     * @return Map<服务名, RttResult>
     */
    @JvmStatic
    fun measureIpServicesRtt(
        services: List<IpService> = DEFAULT_IP_SERVICES,
        timeoutMs: Int = DEFAULT_TIMEOUT_MS
    ): Map<String, RttResult> {
        val executor = Executors.newFixedThreadPool(services.size)
        val results = mutableMapOf<String, RttResult>()

        try {
            val futures = services.associate { service ->
                service.name to executor.submit(java.util.concurrent.Callable {
                    measureRtt(service.url, timeoutMs)
                })
            }

            futures.forEach { (name, future) ->
                try {
                    results[name] = future.get(timeoutMs.toLong(), TimeUnit.MILLISECONDS)
                } catch (e: Exception) {
                    results[name] = RttResult(name, -1, false, e.message)
                }
            }
        } finally {
            executor.shutdown()
        }

        return results
    }
}

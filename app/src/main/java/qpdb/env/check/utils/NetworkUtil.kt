package qpdb.env.check.utils

import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.NetworkCapabilities
import android.net.wifi.WifiManager
import android.os.Build
import android.provider.Settings
import android.util.Log
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.NetworkInterface
import java.util.Collections

/**
 * 网络工具类
 * 提供网络接口、VPN、代理等网络状态检测功能
 */
object NetworkUtil {

    private const val TAG = "NetworkUtil"

    // ========== 网络接口相关 ==========

    /**
     * 网络接口信息数据类
     */
    data class NetworkInterfaceInfo(
        val name: String,
        val displayName: String,
        val isUp: Boolean,
        val isVirtual: Boolean,
        val hardwareAddress: String?,
        val inetAddresses: List<String>
    )

    /**
     * 获取所有网络接口信息
     *
     * @return 网络接口列表
     */
    @JvmStatic
    fun getNetworkInterfaces(): List<NetworkInterfaceInfo> {
        return try {
            Collections.list(NetworkInterface.getNetworkInterfaces()).map { intf ->
                NetworkInterfaceInfo(
                    name = intf.name,
                    displayName = intf.displayName,
                    isUp = intf.isUp,
                    isVirtual = intf.isVirtual,
                    hardwareAddress = intf.hardwareAddress?.joinToString(":") {
                        String.format("%02X", it)
                    },
                    inetAddresses = Collections.list(intf.inetAddresses).map { it.hostAddress }
                )
            }
        } catch (e: Exception) {
            Log.e(TAG, "获取网络接口失败: ${e.message}")
            emptyList()
        }
    }

    /**
     * 获取指定类型的网络接口名称列表
     *
     * @param prefix 接口名称前缀（如 "eth", "tun", "wlan" 等）
     * @return 匹配的接口名称列表
     */
    @JvmStatic
    fun getInterfacesByPrefix(prefix: String): List<String> {
        return try {
            Collections.list(NetworkInterface.getNetworkInterfaces())
                .filter { it.name.startsWith(prefix, ignoreCase = true) }
                .map { it.name }
        } catch (e: Exception) {
            Log.e(TAG, "获取网络接口失败: ${e.message}")
            emptyList()
        }
    }

    /**
     * 检查是否存在指定类型的网络接口
     *
     * @param prefix 接口名称前缀
     * @return 是否存在
     */
    @JvmStatic
    fun hasInterfaceWithPrefix(prefix: String): Boolean {
        return getInterfacesByPrefix(prefix).isNotEmpty()
    }

    /**
     * 获取网卡信息摘要
     *
     * @return NetworkInterfaceSummary 包含各类网卡的统计信息
     */
    @JvmStatic
    fun getNetworkInterfaceSummary(): NetworkInterfaceSummary {
        val interfaces = try {
            Collections.list(NetworkInterface.getNetworkInterfaces())
        } catch (e: Exception) {
            Log.e(TAG, "获取网络接口失败: ${e.message}")
            return NetworkInterfaceSummary(emptyList())
        }

        val ethInterfaces = mutableListOf<String>()
        val tunInterfaces = mutableListOf<String>()
        val wlanInterfaces = mutableListOf<String>()
        val pppInterfaces = mutableListOf<String>()
        val otherInterfaces = mutableListOf<String>()

        interfaces.forEach { intf ->
            val name = intf.name
            when {
                name.startsWith("eth", ignoreCase = true) -> ethInterfaces.add(name)
                name.startsWith("tun", ignoreCase = true) -> tunInterfaces.add(name)
                name.startsWith("wlan", ignoreCase = true) -> wlanInterfaces.add(name)
                name.startsWith("ppp", ignoreCase = true) -> pppInterfaces.add(name)
                else -> otherInterfaces.add(name)
            }
        }

        return NetworkInterfaceSummary(
            allInterfaces = interfaces.map { it.name },
            ethInterfaces = ethInterfaces,
            tunInterfaces = tunInterfaces,
            wlanInterfaces = wlanInterfaces,
            pppInterfaces = pppInterfaces,
            otherInterfaces = otherInterfaces
        )
    }

    /**
     * 网卡信息摘要数据类
     */
    data class NetworkInterfaceSummary(
        val allInterfaces: List<String>,
        val ethInterfaces: List<String> = emptyList(),
        val tunInterfaces: List<String> = emptyList(),
        val wlanInterfaces: List<String> = emptyList(),
        val pppInterfaces: List<String> = emptyList(),
        val otherInterfaces: List<String> = emptyList()
    ) {
        fun hasEth(): Boolean = ethInterfaces.isNotEmpty()
        fun hasTun(): Boolean = tunInterfaces.isNotEmpty()
        fun hasWlan(): Boolean = wlanInterfaces.isNotEmpty()
        fun hasPpp(): Boolean = pppInterfaces.isNotEmpty()

        fun getDescription(): String {
            return buildString {
                if (ethInterfaces.isNotEmpty()) append("ETH: ${ethInterfaces.joinToString(",")}; ")
                if (tunInterfaces.isNotEmpty()) append("TUN: ${tunInterfaces.joinToString(",")}; ")
                if (wlanInterfaces.isNotEmpty()) append("WLAN: ${wlanInterfaces.joinToString(",")}; ")
                if (pppInterfaces.isNotEmpty()) append("PPP: ${pppInterfaces.joinToString(",")}; ")
                append("总计: ${allInterfaces.size}")
            }
        }
    }

    // ========== VPN 检测相关 ==========

    /**
     * VPN 状态信息数据类
     */
    data class VpnStatus(
        val isActive: Boolean,
        val details: List<String> = emptyList()
    ) {
        fun getDetailString(): String = details.joinToString("; ")
    }

    /**
     * 检测 VPN 状态（综合多种方法）
     *
     * @param context 应用上下文
     * @return VpnStatus VPN 状态信息
     */
    @JvmStatic
    fun checkVpnStatus(context: Context): VpnStatus {
        val details = mutableListOf<String>()
        var isActive = false

        // 方法1: 使用 NetworkCapabilities 检测 (Android 6.0+)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            try {
                val connectivityManager = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
                val activeNetwork = connectivityManager.activeNetwork
                val capabilities = activeNetwork?.let { connectivityManager.getNetworkCapabilities(it) }

                if (capabilities != null && capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
                    isActive = true
                    details.add("检测到VPN传输")
                }
            } catch (e: Exception) {
                Log.w(TAG, "通过 NetworkCapabilities 检测 VPN 失败: ${e.message}")
            }
        }

        // 方法2: 使用 NetworkInterface 检测 TUN/PPP 接口
        if (hasInterfaceWithPrefix("tun") || hasInterfaceWithPrefix("ppp")) {
            isActive = true
            val tunList = getInterfacesByPrefix("tun")
            val pppList = getInterfacesByPrefix("ppp")
            if (tunList.isNotEmpty()) details.add("TUN接口: ${tunList.joinToString(",")}")
            if (pppList.isNotEmpty()) details.add("PPP接口: ${pppList.joinToString(",")}")
        }

        // 方法3: 检查默认路由
        if (checkDefaultRouteViaVpn()) {
            isActive = true
            details.add("默认路由经过VPN")
        }

        // 方法4: 检查系统属性
        val vpnProps = checkVpnProperties()
        if (vpnProps.isNotEmpty()) {
            isActive = true
            details.addAll(vpnProps)
        }

        return VpnStatus(isActive, details)
    }

    /**
     * 检查默认路由是否经过 VPN
     */
    @JvmStatic
    fun checkDefaultRouteViaVpn(): Boolean {
        return try {
            val process = Runtime.getRuntime().exec("ip route")
            val reader = BufferedReader(InputStreamReader(process.inputStream))
            var line: String?
            var hasVpnRoute = false

            while (reader.readLine().also { line = it } != null) {
                val currentLine = line ?: continue
                // 检查默认路由是否指向 tun/ppp 接口或常见的 VPN 网段
                if (currentLine.contains("default") &&
                    (currentLine.contains("tun") ||
                            currentLine.contains("ppp") ||
                            currentLine.contains("10.") ||
                            currentLine.contains("172.16.") ||
                            currentLine.contains("192.168."))
                ) {
                    hasVpnRoute = true
                    break
                }
            }
            reader.close()
            hasVpnRoute
        } catch (e: Exception) {
            false
        }
    }

    /**
     * 检查 VPN 相关的系统属性
     */
    @JvmStatic
    fun checkVpnProperties(): List<String> {
        val vpnProps = mutableListOf<String>()

        val propsToCheck = listOf(
            "vpn.status",
            "persist.vpn.enabled",
            "net.vpn.status",
            "service.vpn.active",
            "persist.sys.vpn",
            "net.tun.vpn"
        )

        propsToCheck.forEach { prop ->
            val value = getPropValue(prop)
            if (!value.isNullOrEmpty() && value != "0" && value != "null") {
                vpnProps.add("$prop=$value")
            }
        }

        return vpnProps
    }

    // ========== 代理检测相关 ==========

    /**
     * 代理信息数据类
     */
    data class ProxyInfo(
        val host: String?,
        val port: Int,
        val source: String
    ) {
        fun isSet(): Boolean = !host.isNullOrEmpty() && port > 0
        override fun toString(): String = if (isSet()) "$host:$port" else "未设置"
    }

    /**
     * 代理检测结果数据类
     */
    data class ProxyStatus(
        val wifiProxy: ProxyInfo?,
        val envProxies: Map<String, String>,
        val systemProxies: Map<String, String>
    ) {
        fun hasAnyProxy(): Boolean {
            return wifiProxy?.isSet() == true ||
                    envProxies.isNotEmpty() ||
                    systemProxies.isNotEmpty()
        }
    }

    /**
     * 获取 WiFi/系统代理设置
     *
     * @param context 应用上下文
     * @return ProxyInfo? 代理信息
     */
    @JvmStatic
    fun getWifiProxy(context: Context): ProxyInfo? {
        // 方法1: 通过 ConnectivityManager 获取 (Android 6.0+)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            try {
                val connectivityManager = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
                val activeNetwork = connectivityManager.activeNetwork
                val linkProperties = activeNetwork?.let { connectivityManager.getLinkProperties(it) }
                val httpProxy = linkProperties?.httpProxy

                if (httpProxy != null && !httpProxy.host.isNullOrEmpty()) {
                    return ProxyInfo(
                        host = httpProxy.host,
                        port = httpProxy.port,
                        source = "LinkProperties"
                    )
                }
            } catch (e: Exception) {
                Log.w(TAG, "通过 LinkProperties 获取代理失败: ${e.message}")
            }
        }

        // 方法2: 通过系统设置获取
        try {
            val proxyHost = Settings.Global.getString(context.contentResolver, "http_proxy")
            if (!proxyHost.isNullOrEmpty() && proxyHost != ":0") {
                // 格式可能是 "host:port" 或仅 "host"
                val parts = proxyHost.split(":")
                return ProxyInfo(
                    host = parts[0],
                    port = parts.getOrNull(1)?.toIntOrNull() ?: 8080,
                    source = "Settings.Global"
                )
            }
        } catch (e: Exception) {
            Log.w(TAG, "通过 Settings 获取代理失败: ${e.message}")
        }

        return null
    }

    /**
     * 获取环境变量中的代理设置
     *
     * @return Map<变量名, 值>
     */
    @JvmStatic
    fun getEnvProxies(): Map<String, String> {
        val proxyVars = listOf(
            "http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY",
            "ftp_proxy", "FTP_PROXY", "all_proxy", "ALL_PROXY",
            "no_proxy", "NO_PROXY", "socks_proxy", "SOCKS_PROXY"
        )

        val result = mutableMapOf<String, String>()

        // 方法1: 直接读取环境变量
        proxyVars.forEach { varName ->
            val value = System.getenv(varName)
            if (!value.isNullOrEmpty()) {
                result[varName] = value
            }
        }

        // 方法2: 通过 shell 命令获取
        try {
            val process = Runtime.getRuntime().exec("env")
            val reader = BufferedReader(InputStreamReader(process.inputStream))
            var line: String?

            while (reader.readLine().also { line = it } != null) {
                val currentLine = line ?: continue
                proxyVars.forEach { varName ->
                    if (currentLine.startsWith("$varName=")) {
                        val value = currentLine.substringAfter("=").trim()
                        if (value.isNotEmpty() && !result.containsKey(varName)) {
                            result[varName] = value
                        }
                    }
                }
            }
            reader.close()
        } catch (e: Exception) {
            Log.w(TAG, "通过 shell 获取环境变量失败: ${e.message}")
        }

        return result
    }

    /**
     * 获取系统属性中的代理设置
     *
     * @return Map<属性名, 值>
     */
    @JvmStatic
    fun getSystemProxyProperties(): Map<String, String> {
        val result = mutableMapOf<String, String>()

        val proxyProps = listOf(
            "net.gprs.http-proxy",
            "net.wifi.http-proxy",
            "persist.sys.proxy",
            "sys.proxy.hostname",
            "sys.proxy.port",
            "global_http_proxy_host",
            "global_http_proxy_port",
            "net.rmnet0.http-proxy",
            "net.eth0.http-proxy"
        )

        proxyProps.forEach { prop ->
            val value = getPropValue(prop)
            if (!value.isNullOrEmpty() && value != "0" && value != "null" && value != ":0") {
                result[prop] = value
            }
        }

        return result
    }

    /**
     * 获取所有代理状态
     *
     * @param context 应用上下文
     * @return ProxyStatus 代理状态汇总
     */
    @JvmStatic
    fun getAllProxyStatus(context: Context): ProxyStatus {
        return ProxyStatus(
            wifiProxy = getWifiProxy(context),
            envProxies = getEnvProxies(),
            systemProxies = getSystemProxyProperties()
        )
    }

    // ========== 网络连接状态 ==========

    /**
     * 检查网络是否可用
     *
     * @param context 应用上下文
     * @return 是否可用
     */
    @JvmStatic
    fun isNetworkAvailable(context: Context): Boolean {
        val connectivityManager = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            val network = connectivityManager.activeNetwork
            val capabilities = network?.let { connectivityManager.getNetworkCapabilities(it) }
            capabilities?.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) == true
        } else {
            @Suppress("DEPRECATION")
            val networkInfo = connectivityManager.activeNetworkInfo
            networkInfo?.isConnected == true
        }
    }

    /**
     * 获取当前网络类型
     *
     * @param context 应用上下文
     * @return 网络类型描述
     */
    @JvmStatic
    fun getNetworkType(context: Context): String {
        val connectivityManager = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager

        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            val network = connectivityManager.activeNetwork
            val capabilities = network?.let { connectivityManager.getNetworkCapabilities(it) }

            when {
                capabilities?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true -> "WiFi"
                capabilities?.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) == true -> "移动数据"
                capabilities?.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) == true -> "以太网"
                capabilities?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true -> "VPN"
                capabilities?.hasTransport(NetworkCapabilities.TRANSPORT_BLUETOOTH) == true -> "蓝牙"
                else -> "未知"
            }
        } else {
            @Suppress("DEPRECATION")
            when (connectivityManager.activeNetworkInfo?.type) {
                ConnectivityManager.TYPE_WIFI -> "WiFi"
                ConnectivityManager.TYPE_MOBILE -> "移动数据"
                ConnectivityManager.TYPE_ETHERNET -> "以太网"
                ConnectivityManager.TYPE_VPN -> "VPN"
                ConnectivityManager.TYPE_BLUETOOTH -> "蓝牙"
                else -> "未知"
            }
        }
    }

    // ========== 网络地址/子网掩码检测相关 ==========

    /**
     * 网络地址信息数据类
     */
    data class NetworkAddressInfo(
        val localIp: String?,
        val gatewayIp: String?,
        val netmask: String?,
        val prefixLength: Int?,  // 如 24、30 等
        val networkAddress: String?,  // 网络地址，如 192.168.1.0
        val broadcastAddress: String?,  // 广播地址
        val hostCount: Int?,  // 可容纳主机数
        val isStandardNetmask: Boolean,
        val isSuspiciousSmallNetwork: Boolean
    ) {
        fun getNetmaskDescription(): String {
            return when (prefixLength) {
                null -> "未知"
                8 -> "/8 (A类网络)"
                16 -> "/16 (B类网络)"
                24 -> "/24 (标准家庭网络)"
                22 -> "/22 (中等企业网络)"
                30 -> "/30 (仅2台主机 - 可疑)"
                31 -> "/31 (仅2台主机 - 可疑)"
                32 -> "/32 (单主机)"
                else -> "/$prefixLength"
            }
        }
    }

    /**
     * 网络地址检测结果数据类
     */
    data class NetworkAddressResult(
        val addressInfo: NetworkAddressInfo,
        val suspicious: Boolean,
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
     * 检测网络地址配置
     * 检查子网掩码是否为异常的小网络（如 Cuttlefish 的 /30）
     *
     * @param context 应用上下文
     * @return NetworkAddressResult 检测结果
     */
    @JvmStatic
    fun checkNetworkAddress(context: Context): NetworkAddressResult {
        val details = mutableListOf<String>()
        
        // 1. 获取本地 IP
        val localIp = getLocalIpAddress()
        if (localIp != null) {
            details.add("本机IP: $localIp")
        }
        
        // 2. 获取所有网关
        val gatewayIps = getGatewayIps(context)
        if (gatewayIps.isNotEmpty()) {
            details.add("网关: ${gatewayIps.joinToString(", ")}")
        }
        
        // 3. 获取子网掩码和前缀长度
        val netmaskInfo = getNetmaskInfo(context)
        val netmask = netmaskInfo?.first
        val prefixLength = netmaskInfo?.second
        
        if (netmask != null) {
            details.add("子网掩码: $netmask")
        }
        if (prefixLength != null) {
            details.add("前缀长度: /$prefixLength")
        }
        
        // 4. 计算网络信息
        val networkAddress = if (localIp != null && netmask != null) {
            calculateNetworkAddress(localIp, netmask)
        } else null
        
        val broadcastAddress = if (localIp != null && netmask != null) {
            calculateBroadcastAddress(localIp, netmask)
        } else null
        
        val hostCount = prefixLength?.let { calculateHostCount(it) }
        
        if (networkAddress != null) {
            details.add("网络地址: $networkAddress")
        }
        if (broadcastAddress != null) {
            details.add("广播地址: $broadcastAddress")
        }
        if (hostCount != null) {
            details.add("可用主机数: $hostCount")
        }
        
        // 5. 判断是否为异常网络
        val isStandardNetmask = prefixLength?.let { it <= 24 } ?: false
        val isSuspiciousSmall = prefixLength?.let { it >= 29 } ?: false  // /29、/30、/31、/32 都很可疑
        
        // 6. 生成分析结果
        val analysis = when {
            prefixLength == null -> "无法获取子网掩码信息"
            isSuspiciousSmall -> {
                when (prefixLength) {
                    30 -> "检测到极小子网 /30 (Cuttlefish/模拟器特征)"
                    31 -> "检测到极小子网 /31"
                    29 -> "检测到小子网 /29"
                    32 -> "检测到单主机网络 /32"
                    else -> "检测到小子网 /$prefixLength"
                }
            }
            prefixLength == 24 -> "标准家庭网络 /24"
            prefixLength == 22 -> "标准企业网络 /22"
            prefixLength == 16 -> "大型网络 /16"
            prefixLength < 24 -> "较大网络 /$prefixLength"
            else -> "非标准网络 /$prefixLength"
        }
        
        val addressInfo = NetworkAddressInfo(
            localIp = localIp,
            gatewayIp = gatewayIps.firstOrNull(),
            netmask = netmask,
            prefixLength = prefixLength,
            networkAddress = networkAddress,
            broadcastAddress = broadcastAddress,
            hostCount = hostCount,
            isStandardNetmask = isStandardNetmask,
            isSuspiciousSmallNetwork = isSuspiciousSmall
        )
        
        return NetworkAddressResult(
            addressInfo = addressInfo,
            suspicious = isSuspiciousSmall,
            analysis = analysis,
            details = details
        )
    }

    /**
     * 获取子网掩码信息
     * @return Pair<掩码字符串, 前缀长度> 如 ("255.255.255.0", 24)
     */
    @JvmStatic
    fun getNetmaskInfo(context: Context): Pair<String, Int>? {
        // 方法1: 从 WifiManager 获取
        try {
            val wifiManager = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager?
            val dhcpInfo = wifiManager?.dhcpInfo
            val netmaskInt = dhcpInfo?.netmask
            
            if (netmaskInt != null && netmaskInt != 0) {
                val netmask = ipIntToString(netmaskInt)
                val prefixLength = netmaskToPrefixLength(netmask)
                if (prefixLength != null) {
                    return Pair(netmask, prefixLength)
                }
            }
        } catch (e: Exception) {
            Log.w(TAG, "从 WifiManager 获取子网掩码失败: ${e.message}")
        }
        
        // 方法2: 从 LinkProperties 获取 (Android 9+)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            try {
                val connectivityManager = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
                val activeNetwork = connectivityManager.activeNetwork
                val linkProperties = activeNetwork?.let { connectivityManager.getLinkProperties(it) }
                
                // 获取本地地址和前缀长度
                linkProperties?.linkAddresses?.forEach { linkAddress ->
                    val prefix = linkAddress.prefixLength
                    val address = linkAddress.address.hostAddress
                    if (prefix in 1..32 && address?.contains('.') == true) {
                        val netmask = prefixLengthToNetmask(prefix)
                        return Pair(netmask, prefix)
                    }
                }
            } catch (e: Exception) {
                Log.w(TAG, "从 LinkProperties 获取子网掩码失败: ${e.message}")
            }
        }
        
        // 方法3: 尝试从系统属性获取
        val netmaskProps = listOf("net.mask", "net.wlan0.mask", "net.eth0.mask")
        for (prop in netmaskProps) {
            try {
                getPropValue(prop)?.let { netmask ->
                    if (netmask.isNotEmpty() && netmask.contains('.')) {
                        val prefixLength = netmaskToPrefixLength(netmask)
                        if (prefixLength != null) {
                            return Pair(netmask, prefixLength)
                        }
                    }
                }
            } catch (e: Exception) {
                // 忽略
            }
        }
        
        return null
    }

    /**
     * 将子网掩码转换为前缀长度
     */
    @JvmStatic
    fun netmaskToPrefixLength(netmask: String): Int? {
        return try {
            val parts = netmask.split(".").map { it.toIntOrNull() ?: 0 }
            if (parts.size != 4) return null
            
            var prefix = 0
            for (part in parts) {
                prefix += when (part) {
                    255 -> 8
                    254 -> 7
                    252 -> 6
                    248 -> 5
                    240 -> 4
                    224 -> 3
                    192 -> 2
                    128 -> 1
                    0 -> 0
                    else -> return null  // 无效的掩码
                }
            }
            prefix
        } catch (e: Exception) {
            null
        }
    }

    /**
     * 将前缀长度转换为子网掩码
     */
    @JvmStatic
    fun prefixLengthToNetmask(prefixLength: Int): String {
        val mask = 0xffffffff shl (32 - prefixLength)
        return String.format(
            "%d.%d.%d.%d",
            (mask shr 24) and 0xff,
            (mask shr 16) and 0xff,
            (mask shr 8) and 0xff,
            mask and 0xff
        )
    }

    /**
     * 计算网络地址
     */
    @JvmStatic
    fun calculateNetworkAddress(ip: String, netmask: String): String? {
        return try {
            val ipParts = ip.split(".").map { it.toInt() }
            val maskParts = netmask.split(".").map { it.toInt() }
            
            if (ipParts.size != 4 || maskParts.size != 4) return null
            
            String.format(
                "%d.%d.%d.%d",
                ipParts[0] and maskParts[0],
                ipParts[1] and maskParts[1],
                ipParts[2] and maskParts[2],
                ipParts[3] and maskParts[3]
            )
        } catch (e: Exception) {
            null
        }
    }

    /**
     * 计算广播地址
     */
    @JvmStatic
    fun calculateBroadcastAddress(ip: String, netmask: String): String? {
        return try {
            val ipParts = ip.split(".").map { it.toInt() }
            val maskParts = netmask.split(".").map { it.toInt() }
            
            if (ipParts.size != 4 || maskParts.size != 4) return null
            
            String.format(
                "%d.%d.%d.%d",
                ipParts[0] or (maskParts[0] xor 255),
                ipParts[1] or (maskParts[1] xor 255),
                ipParts[2] or (maskParts[2] xor 255),
                ipParts[3] or (maskParts[3] xor 255)
            )
        } catch (e: Exception) {
            null
        }
    }

    /**
     * 计算可容纳的主机数
     */
    @JvmStatic
    fun calculateHostCount(prefixLength: Int): Int {
        return if (prefixLength >= 31) {
            0  // /31 和 /32 没有可用主机地址
        } else {
            (1 shl (32 - prefixLength)) - 2  // 减去网络地址和广播地址
        }
    }

    // ========== 旁路由检测相关 ==========

    /**
     * 旁路由检测结果数据类
     */
    data class BypassRouterResult(
        val gatewayIp: String?,
        val subnetPrefix: String?,  // 网段前缀，如 192.168.1
        val expectedGateway: String?,  // 预期的网关地址（.1）
        val isBypassRouter: Boolean,
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
     * 检测是否为旁路由环境
     * 判断网关是否为网段的.1地址，如果不是则可能是旁路由
     *
     * @param context 应用上下文
     * @return BypassRouterResult 检测结果
     */
    @JvmStatic
    fun detectBypassRouter(context: Context): BypassRouterResult {
        val details = mutableListOf<String>()
        
        // 1. 获取所有网关
        val gatewayIps = getGatewayIps(context)
        
        if (gatewayIps.isEmpty()) {
            return BypassRouterResult(
                gatewayIp = null,
                subnetPrefix = null,
                expectedGateway = null,
                isBypassRouter = false,
                analysis = "无法获取网关信息",
                details = listOf("请检查网络连接")
            )
        }
        
        details.add("当前网关: ${gatewayIps.joinToString(", ")}")
        
        // 2. 遍历所有网关，检查是否有任何一个存在旁路由特征
        var hasBypassRouter = false
        val allBypassIndicators = mutableListOf<String>()
        var mainGatewayIp: String? = null
        var mainSubnetPrefix: String? = null
        var mainExpectedGateway: String? = null
        
        for (gatewayIp in gatewayIps) {
            // 只处理 IPv4 网关
            if (!isIpv4Address(gatewayIp)) continue
            
            val networkInfo = parseNetworkInfo(gatewayIp)
            if (networkInfo == null) continue
            
            val (subnetPrefix, hostPart) = networkInfo
            val expectedGateway = "$subnetPrefix.1"
            
            // 记录第一个有效网关的信息
            if (mainGatewayIp == null) {
                mainGatewayIp = gatewayIp
                mainSubnetPrefix = subnetPrefix
                mainExpectedGateway = expectedGateway
                details.add("网段: $subnetPrefix.0/24")
                details.add("预期网关: $expectedGateway")
            }
            
            // 3. 判断是否为旁路由
            val isStandardGateway = hostPart == 1
            val bypassIndicators = mutableListOf<String>()
            
            if (!isStandardGateway) {
                bypassIndicators.add("网关$gatewayIp 不是$subnetPrefix.1")
                
                // 检查网关是否为常见旁路由地址
                if (hostPart in listOf(2, 100, 200, 254)) {
                    bypassIndicators.add("网关$gatewayIp 为常见旁路由地址($hostPart)")
                }
                
                // 检查当前设备IP与网关是否在同一网段
                val localIp = getLocalIpAddress()
                if (localIp != null) {
                    details.add("本机IP: $localIp")
                    val localNetwork = parseNetworkInfo(localIp)
                    if (localNetwork != null && localNetwork.first == subnetPrefix) {
                        bypassIndicators.add("网关$gatewayIp 与本机处于同一层级")
                    }
                }
            }
            
            if (bypassIndicators.isNotEmpty()) {
                hasBypassRouter = true
                allBypassIndicators.addAll(bypassIndicators)
            }
        }
        
        // 4. 生成分析结果
        val analysis = when {
            !hasBypassRouter -> "网关配置标准（${mainExpectedGateway ?: "N/A"}）"
            allBypassIndicators.isNotEmpty() -> "检测到旁路由特征: ${allBypassIndicators.take(3).joinToString(", ")}"
            else -> "网关配置非标准，但未发现明确旁路由特征"
        }
        
        return BypassRouterResult(
            gatewayIp = mainGatewayIp,
            subnetPrefix = mainSubnetPrefix,
            expectedGateway = mainExpectedGateway,
            isBypassRouter = hasBypassRouter,
            analysis = analysis,
            details = details
        )
    }

    /**
     * 解析网络信息
     * @return Pair<网段前缀, 主机位> 如 ("192.168.1", 100)
     */
    private fun parseNetworkInfo(ip: String): Pair<String, Int>? {
        return try {
            val parts = ip.split(".")
            if (parts.size != 4) return null
            
            val subnetPrefix = "${parts[0]}.${parts[1]}.${parts[2]}"
            val hostPart = parts[3].toIntOrNull() ?: return null
            
            Pair(subnetPrefix, hostPart)
        } catch (e: Exception) {
            null
        }
    }

    /**
     * 获取本机 IP 地址
     */
    @JvmStatic
    fun getLocalIpAddress(): String? {
        return try {
            val interfaces = Collections.list(NetworkInterface.getNetworkInterfaces())
            for (intf in interfaces) {
                val addresses = Collections.list(intf.inetAddresses)
                for (addr in addresses) {
                    if (!addr.isLoopbackAddress && addr is java.net.Inet4Address) {
                        return addr.hostAddress
                    }
                }
            }
            null
        } catch (e: Exception) {
            Log.w(TAG, "获取本机IP失败: ${e.message}")
            null
        }
    }

    // ========== DNS 检测相关 ==========

    /**
     * DNS 服务器信息数据类
     */
    data class DnsServerInfo(
        val ip: String,
        val source: String,  // 来源：DHCP、Property、LinkProperties 等
        val isGateway: Boolean = false,
        val isPrivateNetwork: Boolean = false,
        val isPublicDns: Boolean = false,
        val subnet: String? = null
    ) {
        fun isSuspicious(gatewayIp: String?): Boolean {
            // 如果既不是网关，也不是公网 DNS，且不是内网地址，则可疑
            if (isGateway) return false  // 网关做 DNS 是正常的
            if (isPublicDns) return false  // 公网 DNS 是正常的
            if (!isPrivateNetwork) return true  // 非公网非公网的地址可疑
            return false
        }
    }

    /**
     * DNS 检测结果数据类
     */
    data class DnsCheckResult(
        val dnsServers: List<DnsServerInfo>,
        val gatewayIp: String?,
        val suspicious: Boolean,
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
     * 已知公网 DNS 服务器列表
     */
    val PUBLIC_DNS_SERVERS = setOf(
        // Google
        "8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844",
        // Cloudflare
        "1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001",
        // Quad9
        "9.9.9.9", "149.112.112.112",
        // OpenDNS
        "208.67.222.222", "208.67.220.220",
        // 国内
        "114.114.114.114", "114.114.115.115",  // 114 DNS
        "223.5.5.5", "223.6.6.6",  // 阿里 DNS
        "180.76.76.76",  // 百度 DNS
        "119.29.29.29", "182.254.116.116",  // DNSPod
        "101.226.4.6", "218.30.118.6",  // DNS派
        "123.125.81.6", "140.207.198.6",  // DNS派
        "1.2.4.8", "210.2.4.8",  // CNNIC SDNS
        "168.95.1.1", "168.95.192.1",  // 台湾 Hinet
        "203.80.96.10",  // 香港
        // 运营商
        "202.96.128.86", "202.96.128.166",  // 电信
        "221.5.88.88", "221.6.4.66",  // 联通
        "211.136.112.50", "211.136.150.66"  // 移动
    )

    /**
     * 检测 DNS 配置
     * 检查 DNS 服务器是否为网关、公网 DNS 或其他可疑地址
     *
     * @param context 应用上下文
     * @return DnsCheckResult DNS 检测结果
     */
    @JvmStatic
    fun checkDnsConfiguration(context: Context): DnsCheckResult {
        val details = mutableListOf<String>()
        
        // 1. 获取所有网关 IP
        val gatewayIps = getGatewayIps(context)
        if (gatewayIps.isNotEmpty()) {
            details.add("网关: ${gatewayIps.joinToString(", ")}")
        }

        // 2. 获取所有 DNS 服务器
        val dnsServers = getDetailedDnsServers(context, gatewayIps.firstOrNull())
        
        // 3. 分析每个 DNS 服务器（检查是否匹配任一网关）
        val dnsInfoList = dnsServers.map { (ip, source) ->
            analyzeDnsServer(ip, source, gatewayIps)
        }

        dnsInfoList.forEach { dns ->
            val type = when {
                dns.isGateway -> "网关"
                dns.isPublicDns -> "公网"
                dns.isPrivateNetwork -> "内网"
                else -> "未知"
            }
            details.add("DNS[${dns.source}]: ${dns.ip} ($type)")
        }

        // 4. 判断是否存在可疑 DNS（任一网关下都可疑则判定为可疑）
        val suspiciousDns = dnsInfoList.filter { dns ->
            // 检查该 DNS 是否在所有网关下都可疑（不匹配任一网关）
            !dns.isGateway && !dns.isPublicDns
        }
        val isSuspicious = suspiciousDns.isNotEmpty()

        // 5. 生成分析结果
        val analysis = when {
            dnsInfoList.isEmpty() -> "无法获取 DNS 配置"
            isSuspicious -> "检测到可疑 DNS 服务器: ${suspiciousDns.map { it.ip }.take(3).joinToString(", ")}"
            dnsInfoList.all { it.isGateway } -> "DNS 均为网关（正常）"
            dnsInfoList.all { it.isPublicDns } -> "DNS 均为公网（正常）"
            else -> "DNS 配置正常"
        }

        return DnsCheckResult(
            dnsServers = dnsInfoList,
            gatewayIp = gatewayIps.firstOrNull(),
            suspicious = isSuspicious,
            analysis = analysis,
            details = details
        )
    }

    /**
     * 获取详细的 DNS 服务器信息
     */
    @JvmStatic
    fun getDetailedDnsServers(context: Context, gatewayIp: String? = null): List<Pair<String, String>> {
        val dnsList = mutableListOf<Pair<String, String>>()

        // 方法1: 从 LinkProperties 获取 (Android 6.0+)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            try {
                val connectivityManager = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
                val activeNetwork = connectivityManager.activeNetwork
                val linkProperties = activeNetwork?.let { connectivityManager.getLinkProperties(it) }
                val servers = linkProperties?.dnsServers
                
                servers?.forEach { address ->
                    val ip = address.hostAddress
                    if (!ip.isNullOrEmpty() && !dnsList.any { it.first == ip }) {
                        dnsList.add(ip to "LinkProperties")
                    }
                }
            } catch (e: Exception) {
                Log.w(TAG, "从 LinkProperties 获取 DNS 失败: ${e.message}")
            }
        }

        // 方法2: 从 WifiManager 获取 DHCP 信息
        try {
            val wifiManager = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager?
            val dhcpInfo = wifiManager?.dhcpInfo
            
            dhcpInfo?.dns1?.let { 
                val ip = ipIntToString(it)
                if (ip.isNotEmpty() && ip != "0.0.0.0" && !dnsList.any { it.first == ip }) {
                    dnsList.add(ip to "DHCP")
                }
            }
            
            dhcpInfo?.dns2?.let { 
                val ip = ipIntToString(it)
                if (ip.isNotEmpty() && ip != "0.0.0.0" && !dnsList.any { it.first == ip }) {
                    dnsList.add(ip to "DHCP2")
                }
            }
        } catch (e: Exception) {
            Log.w(TAG, "从 WifiManager 获取 DNS 失败: ${e.message}")
        }

        // 方法3: 从系统属性获取
        val propDns = listOf("net.dns1", "net.dns2", "net.dns3", "net.dns4",
                             "net.rmnet0.dns1", "net.rmnet0.dns2",
                             "net.eth0.dns1", "net.eth0.dns2",
                             "net.wlan0.dns1", "net.wlan0.dns2")
        
        propDns.forEach { prop ->
            try {
                getPropValue(prop)?.let { ip ->
                    if (ip.isNotEmpty() && ip != "0.0.0.0" && !dnsList.any { it.first == ip }) {
                        dnsList.add(ip to "Property:$prop")
                    }
                }
            } catch (e: Exception) {
                // 忽略
            }
        }

        return dnsList
    }

    /**
     * 分析 DNS 服务器信息
     * @param gatewayIps 网关列表，用于判断 DNS 是否为网关
     */
    private fun analyzeDnsServer(ip: String, source: String, gatewayIps: List<String>): DnsServerInfo {
        val isGateway = gatewayIps.any { it == ip }
        val isPublicDns = PUBLIC_DNS_SERVERS.contains(ip) || isPublicDnsServer(ip)
        val isPrivate = isPrivateNetwork(ip)
        val subnet = if (!isPublicDns) getSubnet(ip) else null

        return DnsServerInfo(
            ip = ip,
            source = source,
            isGateway = isGateway,
            isPrivateNetwork = isPrivate,
            isPublicDns = isPublicDns,
            subnet = subnet
        )
    }

    /**
     * 判断是否为公网 DNS 服务器
     * 除已知列表外，检查是否为公网 IP 且端口 53 可连接
     */
    private fun isPublicDnsServer(ip: String): Boolean {
        // 检查是否为公网 IP
        if (!isPublicIp(ip)) return false
        
        // 检查是否为保留的 DNS 端口（这里只做 IP 判断，不实际连接）
        // 额外的检查可以包括端口连通性测试
        return true
    }

    /**
     * 判断是否为公网 IP
     */
    private fun isPublicIp(ip: String): Boolean {
        return try {
            // IPv4 检查
            if (ip.contains('.')) {
                val parts = ip.split(".").map { it.toIntOrNull() ?: 0 }
                if (parts.size != 4) return false

                // 检查内网/保留地址
                return when {
                    parts[0] == 10 -> false  // 10.0.0.0/8
                    parts[0] == 172 && parts[1] in 16..31 -> false  // 172.16.0.0/12
                    parts[0] == 192 && parts[1] == 168 -> false  // 192.168.0.0/16
                    parts[0] == 127 -> false  // 127.0.0.0/8
                    parts[0] == 169 && parts[1] == 254 -> false  // 169.254.0.0/16
                    parts[0] in 224..255 -> false  // 多播/保留/实验
                    else -> true
                }
            }
            // IPv6 简化检查
            else if (ip.contains(':')) {
                return when {
                    ip.startsWith("fe80:", ignoreCase = true) -> false  // 链路本地
                    ip.startsWith("fc", ignoreCase = true) || 
                    ip.startsWith("fd", ignoreCase = true) -> false  // 私有地址
                    ip == "::1" -> false  // 本地回环
                    else -> true
                }
            }
            false
        } catch (e: Exception) {
            false
        }
    }

    /**
     * 判断是否为内网地址
     */
    private fun isPrivateNetwork(ip: String): Boolean {
        return !isPublicIp(ip) && ip != "0.0.0.0"
    }

    /**
     * 获取 IP 所属子网
     */
    private fun getSubnet(ip: String): String? {
        return try {
            if (ip.contains('.')) {
                val parts = ip.split(".")
                if (parts.size == 4) {
                    "${parts[0]}.${parts[1]}.${parts[2]}.0/24"
                } else null
            } else null
        } catch (e: Exception) {
            null
        }
    }

    // ========== 透明代理检测 ==========

    /**
     * 协议类型
     */
    enum class ProtocolType {
        ICMP, TCP, UDP
    }

    /**
     * 协议 RTT 结果
     */
    data class ProtocolRttResult(
        val protocol: ProtocolType,
        val rttMs: Long,
        val success: Boolean,
        val error: String? = null
    )

    /**
     * 目标主机 RTT 测量结果
     */
    data class TargetRttResult(
        val host: String,
        val icmpRtt: Long?,
        val tcpRtt: Long?,
        val udpRtt: Long?
    ) {
        fun hasAnyResult(): Boolean = icmpRtt != null || tcpRtt != null || udpRtt != null
        
        fun getSuccessfulProtocols(): List<Pair<ProtocolType, Long>> {
            return listOfNotNull(
                icmpRtt?.let { ProtocolType.ICMP to it },
                tcpRtt?.let { ProtocolType.TCP to it },
                udpRtt?.let { ProtocolType.UDP to it }
            )
        }
    }

    /**
     * 透明代理检测结果数据类
     */
    data class TransparentProxyResult(
        val suspicious: Boolean,
        val targetResults: List<TargetRttResult>,
        val analysis: String,
        val details: List<String>
    ) {
        /**
         * 获取详细描述
         */
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
     * 检测透明代理
     * 通过对多个目标 IP 进行 ICMP/TCP/UDP 三条路径的 RTT 对比
     * 如果同目标不同协议间差距过大，则表明可能存在透明代理
     *
     * @param context 应用上下文
     * @param targetHosts 用于检测的目标主机列表（IP 或域名）
     * @return TransparentProxyResult 检测结果
     */
    @JvmStatic
    fun detectTransparentProxy(
        context: Context,
        targetHosts: List<String> = listOf(
            "1.1.1.1",           // Cloudflare DNS
            "223.5.5.5",         // 阿里 DNS
            "114.114.114.114"    // 114 DNS
        )
    ): TransparentProxyResult {
        val details = mutableListOf<String>()

        // 对多个目标进行 RTT 测量
        val targetResults = mutableListOf<TargetRttResult>()
        val summaryList = mutableListOf<String>()

        for (host in targetHosts) {
            // 1. ICMP RTT 测试
            val icmpRtt = measureIcmpRtt(host)
            
            // 2. TCP RTT 测试（使用 DNS 端口 53，失败则试 443）
            val tcpRtt = measureTcpRtt(host, 53, 2000) ?: measureTcpRtt(host, 443, 2000)
            
            // 3. UDP RTT 测试（使用 DNS 查询）
            val udpRtt = measureUdpRtt(host, 53)

            targetResults.add(TargetRttResult(host, icmpRtt, tcpRtt, udpRtt))
            
            // 精简显示：只显示每个目标各协议的平均值
            val results = listOfNotNull(icmpRtt, tcpRtt, udpRtt)
            if (results.isNotEmpty()) {
                val avg = results.average().toLong()
                val resultStr = buildString {
                    append(host)
                    append("=")
                    append("I:${icmpRtt?.toString() ?: "X"}")
                    append("/")
                    append("T:${tcpRtt?.toString() ?: "X"}")
                    append("/")
                    append("U:${udpRtt?.toString() ?: "X"}")
                    append("(avg:${avg}ms)")
                }
                summaryList.add(resultStr)
            }
        }

        // 汇总显示所有目标的 RTT 数据
        if (summaryList.isNotEmpty()) {
            details.add(summaryList.joinToString("; "))
        }

        // 分析所有目标的 RTT 差异
        val analysis = analyzeMultiTargetRttDifferences(targetResults)
        
        // 判断是否可疑
        val suspicious = isProxySuspiciousByMultiTargetDiff(targetResults, analysis)

        return TransparentProxyResult(
            suspicious = suspicious,
            targetResults = targetResults,
            analysis = analysis.description,
            details = details + analysis.details
        )
    }

    /**
     * 测量 ICMP RTT
     */
    private fun measureIcmpRtt(host: String): Long? {
        return pingHost(host, 3)
    }

    /**
     * 测量 UDP RTT（通过 DNS 查询）
     */
    private fun measureUdpRtt(dnsServer: String, port: Int = 53): Long? {
        return try {
            val startTime = System.currentTimeMillis()
            
            // 使用 DNS 查询测量 UDP RTT
            val socket = java.net.DatagramSocket()
            socket.soTimeout = 3000
            
            // 构建简单的 DNS 查询包
            val query = buildDnsQuery()
            val address = java.net.InetAddress.getByName(dnsServer)
            val packet = java.net.DatagramPacket(query, query.size, address, port)
            
            socket.send(packet)
            
            val buffer = ByteArray(512)
            val response = java.net.DatagramPacket(buffer, buffer.size)
            socket.receive(response)
            
            val rtt = System.currentTimeMillis() - startTime
            socket.close()
            
            if (rtt > 0) rtt else null
        } catch (e: Exception) {
            Log.w(TAG, "UDP RTT 测量失败 ($dnsServer:$port): ${e.message}")
            null
        }
    }

    /**
     * 构建简单的 DNS 查询包（查询 google.com）
     */
    private fun buildDnsQuery(): ByteArray {
        // 简单的 DNS 查询包
        return byteArrayOf(
            // Transaction ID
            0x00, 0x01,
            // Flags: Standard query
            0x01, 0x00,
            // Questions: 1
            0x00, 0x01,
            // Answer RRs: 0
            0x00, 0x00,
            // Authority RRs: 0
            0x00, 0x00,
            // Additional RRs: 0
            0x00, 0x00,
            // Query: google.com
            0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, // "google"
            0x03, 0x63, 0x6f, 0x6d, // "com"
            0x00, // End of name
            // Type: A
            0x00, 0x01,
            // Class: IN
            0x00, 0x01
        )
    }

    /**
     * 多目标 RTT 分析结果
     */
    data class MultiTargetRttAnalysis(
        val description: String,
        val details: List<String>
    )

    /**
     * 分析多目标的 RTT 差异
     * 检测同目标不同协议间的 RTT 差异是否异常
     */
    private fun analyzeMultiTargetRttDifferences(
        targetResults: List<TargetRttResult>
    ): MultiTargetRttAnalysis {
        val details = mutableListOf<String>()
        
        val successfulTargets = targetResults.filter { it.hasAnyResult() }
        
        if (successfulTargets.isEmpty()) {
            return MultiTargetRttAnalysis(
                "无法获取 RTT 数据",
                listOf("所有目标均不可用")
            )
        }

        // 统计所有成功的协议 RTT
        var totalRttSum = 0L
        var totalRttCount = 0
        val allProtocolDiffs = mutableListOf<Long>()
        val suspiciousTargets = mutableListOf<String>()

        for (target in successfulTargets) {
            val protocols = target.getSuccessfulProtocols()
            if (protocols.size >= 2) {
                val rtts = protocols.map { it.second }
                val minRtt = rtts.minOrNull() ?: 0
                val maxRtt = rtts.maxOrNull() ?: 0
                val diff = maxRtt - minRtt
                allProtocolDiffs.add(diff)
                
                totalRttSum += rtts.sum()
                totalRttCount += rtts.size
                
                // 检测该目标是否可疑（同目标协议间差异过大）
                if (diff > 50 || (minRtt > 0 && maxRtt > minRtt * 3)) {
                    suspiciousTargets.add("${target.host}(差${diff}ms)")
                }
            }
        }

        if (totalRttCount > 0) {
            val avgRtt = totalRttSum / totalRttCount
            details.add("平均RTT: ${avgRtt}ms")
        }

        // 检测异常情况
        return when {
            // 发现可疑目标
            suspiciousTargets.isNotEmpty() -> {
                details.add("可疑: ${suspiciousTargets.joinToString(", ")}")
                MultiTargetRttAnalysis("检测到协议 RTT 差异异常", details)
            }
            
            // 所有目标都正常
            allProtocolDiffs.isNotEmpty() -> {
                val avgDiff = allProtocolDiffs.average().toLong()
                details.add("平均协议差: ${avgDiff}ms")
                MultiTargetRttAnalysis("RTT 正常", details)
            }
            
            else -> {
                MultiTargetRttAnalysis("RTT 分析完成", details)
            }
        }
    }

    /**
     * 根据多目标 RTT 差异判断是否可能存在代理
     */
    private fun isProxySuspiciousByMultiTargetDiff(
        targetResults: List<TargetRttResult>,
        analysis: MultiTargetRttAnalysis
    ): Boolean {
        // 根据分析结果判断
        if (analysis.description.contains("异常") || analysis.description.contains("可疑")) {
            return true
        }

        // 检查各目标的协议 RTT 差异
        for (target in targetResults) {
            val protocols = target.getSuccessfulProtocols()
            if (protocols.size >= 2) {
                val rtts = protocols.map { it.second }
                val minRtt = rtts.minOrNull() ?: 0
                val maxRtt = rtts.maxOrNull() ?: 0
                val diff = maxRtt - minRtt
                
                // 同目标协议间差异过大（>50ms 或 3 倍以上）
                if (diff > 50 || (minRtt > 0 && maxRtt > minRtt * 3)) {
                    return true
                }
                
                // 检查是否有协议的 RTT 异常低（可能本地代理）
                val tcpRtt = protocols.find { it.first == ProtocolType.TCP }?.second
                if (tcpRtt != null && tcpRtt < 5) {
                    return true
                }
            }
        }

        return false
    }

    /**
     * 使用 ICMP ping 测量 RTT
     */
    @JvmStatic
    fun pingHost(host: String, count: Int = 3): Long? {
        return try {
            val process = Runtime.getRuntime().exec("ping -c $count -W 2 $host")
            val reader = BufferedReader(InputStreamReader(process.inputStream))
            var line: String?
            var avgRtt: Long? = null

            while (reader.readLine().also { line = it } != null) {
                val currentLine = line ?: continue
                // 解析类似 "rtt min/avg/max/mdev = 0.456/0.523/0.612/0.058 ms" 的行
                if (currentLine.contains("rtt") && currentLine.contains("avg")) {
                    val regex = Regex("""avg/(\d+\.?\d*)""")
                    val match = regex.find(currentLine)
                    if (match != null) {
                        avgRtt = (match.groupValues[1].toDouble()).toLong()
                    }
                }
                // Android 某些版本的格式可能不同
                if (currentLine.contains("time=") && avgRtt == null) {
                    val regex = Regex("""time=(\d+\.?\d*)""")
                    val matches = regex.findAll(currentLine).toList()
                    if (matches.isNotEmpty()) {
                        val times = matches.map { it.groupValues[1].toDouble() }
                        avgRtt = (times.average()).toLong()
                    }
                }
            }

            reader.close()
            process.waitFor()

            if (process.exitValue() == 0) avgRtt else null
        } catch (e: Exception) {
            Log.w(TAG, "ping $host 失败: ${e.message}")
            null
        }
    }

    /**
     * 测量 TCP 连接的 RTT
     */
    @JvmStatic
    fun measureTcpRtt(host: String, port: Int, timeoutMs: Int): Long? {
        return try {
            val startTime = System.currentTimeMillis()
            val socket = java.net.Socket()
            socket.connect(java.net.InetSocketAddress(host, port), timeoutMs)
            val rtt = System.currentTimeMillis() - startTime
            socket.close()
            rtt
        } catch (e: Exception) {
            null
        }
    }

    /**
     * 获取所有网关 IP 地址列表 (优先 IPv4)
     * 优先使用 LinkProperties (Android M+)，更准确
     * 旧版本使用 WifiManager
     * 
     * @return 网关地址列表，可能包含多个网关（如 IPv4 和 IPv6）
     */
    @JvmStatic
    fun getGatewayIps(context: Context): List<String> {
        val gateways = mutableListOf<String>()
        
        // 方法1: 使用 LinkProperties 获取所有默认路由的网关 (Android M+)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            try {
                val connectivityManager = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
                val network = connectivityManager.activeNetwork ?: return emptyList()
                val linkProperties = connectivityManager.getLinkProperties(network) ?: return emptyList()
                
                val ipv4Gateways = mutableListOf<String>()
                val ipv6Gateways = mutableListOf<String>()
                
                // 收集所有默认路由的网关
                for (route in linkProperties.routes) {
                    if (route.isDefaultRoute) {
                        val gateway = route.gateway?.hostAddress
                        if (!gateway.isNullOrEmpty() && !gateways.contains(gateway)) {
                            if (isIpv4Address(gateway)) {
                                ipv4Gateways.add(gateway)
                            } else if (isIpv6Address(gateway)) {
                                ipv6Gateways.add(gateway)
                            }
                        }
                    }
                }
                
                // IPv4 优先
                gateways.addAll(ipv4Gateways)
                gateways.addAll(ipv6Gateways)
                
                if (gateways.isNotEmpty()) {
                    Log.d(TAG, "从 LinkProperties 获取网关: $gateways")
                    return gateways
                }
            } catch (e: Exception) {
                Log.w(TAG, "从 LinkProperties 获取网关失败: ${e.message}")
            }
        }
        
        // 方法2: 使用 WifiManager (旧版本兼容，只返回 IPv4)
        try {
            val wifiManager = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager?
            val dhcpInfo = wifiManager?.dhcpInfo
            val gateway = dhcpInfo?.gateway?.let { ipIntToString(it) }
            if (!gateway.isNullOrEmpty() && gateway != "0.0.0.0") {
                Log.d(TAG, "从 WifiManager 获取网关: $gateway")
                return listOf(gateway)
            }
        } catch (e: Exception) {
            Log.w(TAG, "从 WifiManager 获取网关失败: ${e.message}")
        }
        
        return gateways
    }

    /**
     * 获取主网关 IP 地址 (兼容旧代码)
     * 返回第一个网关（通常是 IPv4）
     */
    @JvmStatic
    @Deprecated("使用 getGatewayIps 获取所有网关", ReplaceWith("getGatewayIps(context).firstOrNull()"))
    fun getGatewayIp(context: Context): String? {
        return getGatewayIps(context).firstOrNull()
    }

    /**
     * 判断是否为 IPv4 地址
     */
    @JvmStatic
    fun isIpv4Address(ip: String): Boolean {
        return ip.contains('.') && !ip.contains(':')
    }

    /**
     * 判断是否为 IPv6 地址
     */
    @JvmStatic
    fun isIpv6Address(ip: String): Boolean {
        return ip.contains(':')
    }

    /**
     * 将整数 IP 转换为字符串 (用于 WifiManager.dhcpInfo)
     * 注意：Android 的整数 IP 是小端序存储的
     */
    @JvmStatic
    fun intToIp(ip: Int): String {
        return String.format(
            "%d.%d.%d.%d",
            ip and 0xff,
            ip shr 8 and 0xff,
            ip shr 16 and 0xff,
            ip shr 24 and 0xff
        )
    }

    /**
     * 获取 DNS 服务器列表
     */
    @JvmStatic
    fun getDnsServers(context: Context): List<String> {
        val dnsList = mutableListOf<String>()

        // 方法1: 从 WifiManager 获取
        try {
            val wifiManager = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager?
            val dhcpInfo = wifiManager?.dhcpInfo
            dhcpInfo?.dns1?.let { dnsList.add(ipIntToString(it)) }
            dhcpInfo?.dns2?.let { if (it != 0) dnsList.add(ipIntToString(it)) }
        } catch (e: Exception) {
            Log.w(TAG, "从 WifiManager 获取 DNS 失败: ${e.message}")
        }

        // 方法2: 从 ConnectivityManager 获取 (Android 9+)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            try {
                val connectivityManager = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
                val activeNetwork = connectivityManager.activeNetwork
                val linkProperties = activeNetwork?.let { connectivityManager.getLinkProperties(it) }
                val servers = linkProperties?.dnsServers?.map { it.hostAddress }
                if (!servers.isNullOrEmpty()) {
                    dnsList.addAll(servers.filter { !dnsList.contains(it) })
                }
            } catch (e: Exception) {
                Log.w(TAG, "从 LinkProperties 获取 DNS 失败: ${e.message}")
            }
        }

        // 方法3: 读取系统属性
        try {
            val propDns = arrayOf("net.dns1", "net.dns2", "net.dns3", "net.dns4")
            propDns.forEach { prop ->
                getPropValue(prop)?.let { ip ->
                    if (ip.isNotEmpty() && !dnsList.contains(ip)) {
                        dnsList.add(ip)
                    }
                }
            }
        } catch (e: Exception) {
            Log.w(TAG, "从属性获取 DNS 失败: ${e.message}")
        }

        return dnsList
    }

    /**
     * 将整数 IP 转换为字符串
     * 调用 intToIp 保持统一实现
     */
    @JvmStatic
    fun ipIntToString(ipInt: Int): String {
        return intToIp(ipInt)
    }

    // ========== 私有辅助方法 ==========

    /**
     * 获取系统属性值
     */
    private fun getPropValue(prop: String): String? {
        return try {
            // 优先使用 PropertyUtil
            PropertyUtil.getProp(prop)
        } catch (e: Exception) {
            // 降级使用 shell 命令
            try {
                val process = Runtime.getRuntime().exec("getprop $prop")
                val reader = BufferedReader(InputStreamReader(process.inputStream))
                val value = reader.readLine()?.trim()
                reader.close()
                value?.takeIf { it.isNotEmpty() }
            } catch (e: Exception) {
                null
            }
        }
    }
}

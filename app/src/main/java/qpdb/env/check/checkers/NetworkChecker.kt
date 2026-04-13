package qpdb.env.check.checkers

import android.content.Context
import android.util.Log
import qpdb.env.check.EnvCheckApp
import qpdb.env.check.model.CheckItem
import qpdb.env.check.model.CheckResult
import qpdb.env.check.model.CheckStatus
import qpdb.env.check.model.Checkable
import qpdb.env.check.utils.HttpUtil
import qpdb.env.check.utils.KeyStoreUtil
import qpdb.env.check.utils.NetworkUtil
import qpdb.env.check.utils.OpenWrtUtil

/**
 * 网络环境检测
 * 检测出口IP、网卡信息、VPN状态、代理设置等
 */
class NetworkChecker : Checkable {

    companion object {
        private const val TAG = "NetworkChecker"
    }

    override val categoryName: String = "网络环境"

    override fun checkList(): List<CheckItem> {
        Log.i(TAG, "checkList() 被调用")
        return listOf(
            CheckItem(
                name = "出口IP验证",
                checkPoint = "exit_ip",
                description = "等待检测..."
            ),
            CheckItem(
                name = "网卡信息",
                checkPoint = "network_interfaces",
                description = "等待检测..."
            ),
            CheckItem(
                name = "VPN状态",
                checkPoint = "vpn_status",
                description = "等待检测..."
            ),
            CheckItem(
                name = "WiFi代理",
                checkPoint = "wifi_proxy",
                description = "等待检测..."
            ),
            CheckItem(
                name = "环境变量代理",
                checkPoint = "env_proxy",
                description = "等待检测..."
            ),
            CheckItem(
                name = "透明代理检测",
                checkPoint = "transparent_proxy",
                description = "等待检测..."
            ),
            CheckItem(
                name = "DNS配置检测",
                checkPoint = "dns_config",
                description = "等待检测..."
            ),
            CheckItem(
                name = "旁路由检测",
                checkPoint = "bypass_router",
                description = "等待检测..."
            ),
            CheckItem(
                name = "网络地址检测",
                checkPoint = "network_address",
                description = "等待检测..."
            ),
            CheckItem(
                name = "OpenWrt网关检测",
                checkPoint = "openwrt_gateway",
                description = "等待检测..."
            ),
            CheckItem(
                name = "系统证书检测",
                checkPoint = "system_certificates",
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
            // 检测出口IP
            val exitIpResult = checkExitIp()
            Log.i(TAG, "出口IP：${exitIpResult.description}")
            items.find { it.checkPoint == "exit_ip" }?.let {
                it.status = exitIpResult.status
                it.description = exitIpResult.description
            }

            // 检测网卡信息
            val networkInterfaceResult = checkNetworkInterfaces()
            Log.i(TAG, "网卡信息：${networkInterfaceResult.description}")
            items.find { it.checkPoint == "network_interfaces" }?.let {
                it.status = networkInterfaceResult.status
                it.description = networkInterfaceResult.description
            }

            // 检测VPN状态
            val vpnResult = checkVpnStatus(context)
            Log.i(TAG, "VPN状态：${vpnResult.description}")
            items.find { it.checkPoint == "vpn_status" }?.let {
                it.status = vpnResult.status
                it.description = vpnResult.description
            }

            // 检测WiFi代理
            val wifiProxyResult = checkWifiProxy(context)
            Log.i(TAG, "WiFi代理：${wifiProxyResult.description}")
            items.find { it.checkPoint == "wifi_proxy" }?.let {
                it.status = wifiProxyResult.status
                it.description = wifiProxyResult.description
            }

            // 检测环境变量代理
            val envProxyResult = checkEnvProxy()
            Log.i(TAG, "环境变量代理：${envProxyResult.description}")
            items.find { it.checkPoint == "env_proxy" }?.let {
                it.status = envProxyResult.status
                it.description = envProxyResult.description
            }

            // 检测透明代理
            val transparentProxyResult = checkTransparentProxy(context)
            Log.i(TAG, "透明代理：${transparentProxyResult.description}")
            items.find { it.checkPoint == "transparent_proxy" }?.let {
                it.status = transparentProxyResult.status
                it.description = transparentProxyResult.description
            }

            // 检测 DNS 配置
            val dnsResult = checkDnsConfiguration(context)
            Log.i(TAG, "DNS配置：${dnsResult.description}")
            items.find { it.checkPoint == "dns_config" }?.let {
                it.status = dnsResult.status
                it.description = dnsResult.description
            }

            // 检测旁路由
            val bypassRouterResult = checkBypassRouter(context)
            Log.i(TAG, "旁路由：${bypassRouterResult.description}")
            items.find { it.checkPoint == "bypass_router" }?.let {
                it.status = bypassRouterResult.status
                it.description = bypassRouterResult.description
            }

            // 检测网络地址/子网掩码
            val networkAddressResult = checkNetworkAddress(context)
            Log.i(TAG, "网络地址：${networkAddressResult.description}")
            items.find { it.checkPoint == "network_address" }?.let {
                it.status = networkAddressResult.status
                it.description = networkAddressResult.description
            }

            // 检测 OpenWrt 网关
            val openWrtResult = checkOpenWrtGateway(context)
            Log.i(TAG, "OpenWrt网关：${openWrtResult.description}")
            items.find { it.checkPoint == "openwrt_gateway" }?.let {
                it.status = openWrtResult.status
                it.description = openWrtResult.description
            }

            // 检测系统证书
            val certificateResult = checkSystemCertificates()
            Log.i(TAG, "系统证书：${certificateResult.description}")
            items.find { it.checkPoint == "system_certificates" }?.let {
                it.status = certificateResult.status
                it.description = certificateResult.description
            }

        } catch (e: Exception) {
            Log.e(TAG, "检测过程出错：${e.message}", e)
            items.forEach { item ->
                if (item.description == "等待检测...") {
                    item.status = CheckStatus.FAIL
                    item.description = "检测失败：${e.message}"
                }
            }
        }

        return items
    }

    /**
     * 检测出口IP
     */
    private fun checkExitIp(): CheckResult {
        return try {
            val result = HttpUtil.fetchAndValidateExitIp()

            when {
                !result.success -> {
                    CheckResult(CheckStatus.FAIL, "无法从任何服务获取出口IP")
                }
                result.consistent -> {
                    CheckResult(CheckStatus.PASS, result.message)
                }
                else -> {
                    // IP 不一致，可能存在代理/VPN
                    CheckResult(CheckStatus.FAIL, "出口IP不一致: ${result.getDetailInfo()}")
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "checkExitIp 出错：${e.message}")
            CheckResult(CheckStatus.FAIL, "检测失败：${e.message}")
        }
    }

    /**
     * 检测网卡信息
     */
    private fun checkNetworkInterfaces(): CheckResult {
        return try {
            val summary = NetworkUtil.getNetworkInterfaceSummary()
            val description = summary.getDescription()

            // 如果存在TUN网卡，可能是VPN
            val status = when {
                summary.hasTun() -> CheckStatus.FAIL
                summary.hasEth() -> CheckStatus.INFO
                else -> CheckStatus.PASS
            }

            CheckResult(status, description)
        } catch (e: Exception) {
            Log.e(TAG, "checkNetworkInterfaces 出错：${e.message}")
            CheckResult(CheckStatus.FAIL, "检测失败：${e.message}")
        }
    }

    /**
     * 检测VPN状态
     */
    private fun checkVpnStatus(context: Context): CheckResult {
        return try {
            val vpnStatus = NetworkUtil.checkVpnStatus(context)

            return if (vpnStatus.isActive) {
                CheckResult(CheckStatus.FAIL, "VPN已开启: ${vpnStatus.getDetailString()}")
            } else {
                CheckResult(CheckStatus.PASS, "未检测到VPN")
            }
        } catch (e: Exception) {
            Log.e(TAG, "checkVpnStatus 出错：${e.message}")
            CheckResult(CheckStatus.FAIL, "检测失败：${e.message}")
        }
    }

    /**
     * 检测WiFi代理设置
     */
    private fun checkWifiProxy(context: Context): CheckResult {
        return try {
            val proxyInfo = NetworkUtil.getWifiProxy(context)

            return if (proxyInfo?.isSet() == true) {
                CheckResult(CheckStatus.FAIL, "WiFi代理已设置: $proxyInfo (来源: ${proxyInfo.source})")
            } else {
                CheckResult(CheckStatus.PASS, "未设置WiFi代理")
            }
        } catch (e: Exception) {
            Log.e(TAG, "checkWifiProxy 出错：${e.message}")
            CheckResult(CheckStatus.FAIL, "检测失败：${e.message}")
        }
    }

    /**
     * 检测环境变量代理设置
     */
    private fun checkEnvProxy(): CheckResult {
        return try {
            val proxyStatus = NetworkUtil.getAllProxyStatus(EnvCheckApp.getContext())

            return if (proxyStatus.hasAnyProxy()) {
                val details = buildString {
                    if (proxyStatus.envProxies.isNotEmpty()) {
                        append("环境变量: ${proxyStatus.envProxies.map { "${it.key}=${it.value}" }.joinToString(", ")}; ")
                    }
                    if (proxyStatus.systemProxies.isNotEmpty()) {
                        append("系统属性: ${proxyStatus.systemProxies.map { "${it.key}=${it.value}" }.joinToString(", ")}")
                    }
                }
                CheckResult(CheckStatus.FAIL, "检测到代理设置: $details")
            } else {
                CheckResult(CheckStatus.PASS, "未检测到代理环境变量")
            }
        } catch (e: Exception) {
            Log.e(TAG, "checkEnvProxy 出错：${e.message}")
            CheckResult(CheckStatus.FAIL, "检测失败：${e.message}")
        }
    }

    /**
     * 检测透明代理
     * 通过 RTT 分析判断流量是否被本地拦截处理
     */
    private fun checkTransparentProxy(context: Context): CheckResult {
        return try {
            val result = NetworkUtil.detectTransparentProxy(context)

            return if (result.suspicious) {
                CheckResult(CheckStatus.FAIL, result.getFullDescription())
            } else {
                CheckResult(CheckStatus.PASS, result.getFullDescription())
            }
        } catch (e: Exception) {
            Log.e(TAG, "checkTransparentProxy 出错：${e.message}")
            CheckResult(CheckStatus.FAIL, "检测失败：${e.message}")
        }
    }

    /**
     * 检测 DNS 配置
     * 检查 DNS 服务器是否为网关、公网 DNS 或其他可疑地址
     */
    private fun checkDnsConfiguration(context: Context): CheckResult {
        return try {
            val result = NetworkUtil.checkDnsConfiguration(context)

            return if (result.suspicious) {
                CheckResult(CheckStatus.FAIL, result.getFullDescription())
            } else {
                CheckResult(CheckStatus.PASS, result.getFullDescription())
            }
        } catch (e: Exception) {
            Log.e(TAG, "checkDnsConfiguration 出错：${e.message}")
            CheckResult(CheckStatus.FAIL, "检测失败：${e.message}")
        }
    }

    /**
     * 检测旁路由
     * 判断网关是否为网段的.1地址，如果不是则可能是旁路由
     */
    private fun checkBypassRouter(context: Context): CheckResult {
        return try {
            val result = NetworkUtil.detectBypassRouter(context)

            return if (result.isBypassRouter) {
                CheckResult(CheckStatus.FAIL, result.getFullDescription())
            } else {
                CheckResult(CheckStatus.PASS, result.getFullDescription())
            }
        } catch (e: Exception) {
            Log.e(TAG, "checkBypassRouter 出错：${e.message}")
            CheckResult(CheckStatus.FAIL, "检测失败：${e.message}")
        }
    }

    /**
     * 检测网络地址配置
     * 检查子网掩码是否为异常的小网络（如 Cuttlefish 的 /30）
     */
    private fun checkNetworkAddress(context: Context): CheckResult {
        return try {
            val result = NetworkUtil.checkNetworkAddress(context)

            return if (result.suspicious) {
                CheckResult(CheckStatus.FAIL, result.getFullDescription())
            } else {
                CheckResult(CheckStatus.PASS, result.getFullDescription())
            }
        } catch (e: Exception) {
            Log.e(TAG, "checkNetworkAddress 出错：${e.message}")
            CheckResult(CheckStatus.FAIL, "检测失败：${e.message}")
        }
    }

    /**
     * 检测 OpenWrt 网关
     * 尝试访问网关默认页面，检查是否为 OpenWrt 且无需密码可访问
     */
    private fun checkOpenWrtGateway(context: Context): CheckResult {
        return try {
            val result = OpenWrtUtil.detectOpenWrtGateway(context)

            return when {
                result.isVulnerable -> {
                    // 无需密码可访问，严重问题
                    CheckResult(CheckStatus.FAIL, result.getFullDescription())
                }
                result.isOpenWrt -> {
                    // 是 OpenWrt 但已设置密码，正常
                    CheckResult(CheckStatus.PASS, result.getFullDescription())
                }
                else -> {
                    // 不是 OpenWrt 或无法访问
                    CheckResult(CheckStatus.PASS, result.getFullDescription())
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "checkOpenWrtGateway 出错：${e.message}")
            CheckResult(CheckStatus.FAIL, "检测失败：${e.message}")
        }
    }

    /**
     * 检测系统证书
     * 枚举系统证书库，检查是否存在抓包工具植入的根证书
     */
    private fun checkSystemCertificates(): CheckResult {
        return try {
            val result = KeyStoreUtil.enumerateSystemCertificates()

            return when {
                result.proxyToolCertificates.isNotEmpty() -> {
                    // 发现抓包工具证书，严重问题
                    val proxyNames = result.proxyToolCertificates
                        .map { it.matchedProxyName }
                        .distinct()
                        .joinToString(", ")
                    CheckResult(
                        CheckStatus.FAIL,
                        "${result.analysis} (工具: $proxyNames) | ${result.details.take(3).joinToString("; ")}"
                    )
                }
                result.userCertificates.isNotEmpty() -> {
                    // 发现用户证书，提示检查
                    CheckResult(
                        CheckStatus.INFO,
                        "${result.analysis} | ${result.details.take(2).joinToString("; ")}"
                    )
                }
                else -> {
                    // 未发现可疑证书
                    CheckResult(CheckStatus.PASS, result.analysis)
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "checkSystemCertificates 出错：${e.message}")
            CheckResult(CheckStatus.FAIL, "检测失败：${e.message}")
        }
    }
}

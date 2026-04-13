package qpdb.env.check.checkers

import android.content.Context
import android.provider.Settings
import android.util.Log
import qpdb.env.check.EnvCheckApp
import qpdb.env.check.model.CheckItem
import qpdb.env.check.model.CheckResult
import qpdb.env.check.model.CheckStatus
import qpdb.env.check.model.Checkable
import qpdb.env.check.utils.FileUtil.fileExists
import qpdb.env.check.utils.PropertyUtil.getProp
import java.io.BufferedReader
import java.io.IOException
import java.io.InputStreamReader
import java.net.BindException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket

/**
 * 开发者模式和 ADB 状态检测
 * 检测是否开启了开发者模式、ADB 调试、WiFi ADB
 * 注意：开启这些功能视为未通过检测（安全角度）
 */
class DeveloperChecker : Checkable {

    companion object {
        private const val TAG = "DeveloperChecker"
    }

    override val categoryName: String = "开发者状态"

    override fun checkList(): List<CheckItem> {
        Log.i(TAG, "checkList() 被调用")
        return listOf(
            // 开发者模式检测
            CheckItem(
                name = "开发者模式",
                checkPoint = "developer_mode",
                description = "等待检测..."
            ),
            // ADB 相关检测
            CheckItem(
                name = "ADB 进程检测",
                checkPoint = "adb_process",
                description = "等待检测..."
            ),
            CheckItem(
                name = "ADB 属性检测",
                checkPoint = "adb_prop",
                description = "等待检测..."
            ),
            CheckItem(
                name = "ADB Socket 检测",
                checkPoint = "adb_socket",
                description = "等待检测..."
            ),
            CheckItem(
                name = "ADB 调试",
                checkPoint = "adb_settings",
                description = "等待检测..."
            ),
            CheckItem(
                name = "Dev ContentProvider",
                checkPoint = "dev_content_provider",
                description = "等待检测..."
            ),
            // WiFi ADB 检测
            CheckItem(
                name = "WiFi ADB 端口",
                checkPoint = "wifi_adb_port",
                description = "等待检测..."
            ),
            CheckItem(
                name = "WiFi ADB 设置",
                checkPoint = "wifi_adb_settings",
                description = "等待检测..."
            ),
            // USB 相关检测
            CheckItem(
                name = "USB 安装",
                checkPoint = "usb_install",
                description = "等待检测..."
            )
        )
    }

    /**
     * 执行实际检测
     * 通过读取系统属性来判断开发者模式和 ADB 状态
     * 返回 true 表示未开启（安全），false 表示已开启（不安全）
     */
    override fun runCheck(): List<CheckItem> {
        Log.i(TAG, "runCheck() 被调用")

        val items = checkList().toMutableList()

        try {
            // 检测开发者模式
            val devModeResult = checkDeveloperMode()
            Log.i(TAG, "开发者模式：${devModeResult.description}")
            items.find { it.checkPoint == "developer_mode" }?.let {
                it.status = devModeResult.status
                it.description = devModeResult.description
            }

            // 检测 ADB 进程
            val adbProcessResult = checkAdbProcess()
            Log.i(TAG, "ADB 进程：${adbProcessResult.description}")
            items.find { it.checkPoint == "adb_process" }?.let {
                it.status = adbProcessResult.status
                it.description = adbProcessResult.description
            }

            // 检测 ADB 属性
            val adbPropResult = checkAdbProperties()
            Log.i(TAG, "ADB 属性：${adbPropResult.description}")
            items.find { it.checkPoint == "adb_prop" }?.let {
                it.status = adbPropResult.status
                it.description = adbPropResult.description
            }

            // 检测 ADB Socket
            val adbSocketResult = checkAdbSocket()
            Log.i(TAG, "ADB Socket: ${adbSocketResult.description}")
            items.find { it.checkPoint == "adb_socket" }?.let {
                it.status = adbSocketResult.status
                it.description = adbSocketResult.description
            }

            // 检测 ADB 设置
            val adbSettingsResult = checkAdbSettings()
            Log.i(TAG, "ADB 设置：${adbSettingsResult.description}")
            items.find { it.checkPoint == "adb_settings" }?.let {
                it.status = adbSettingsResult.status
                it.description = adbSettingsResult.description
            }

            // 检测 Dev ContentProvider
            val devProviderResult = checkDevContentProvider()
            Log.i(TAG, "Dev ContentProvider: ${devProviderResult.description}")
            items.find { it.checkPoint == "dev_content_provider" }?.let {
                it.status = devProviderResult.status
                it.description = devProviderResult.description
            }

            // 检测 WiFi ADB 端口
            val wifiAdbPortResult = checkWifiAdbPort()
            Log.i(TAG, "WiFi ADB 端口：${wifiAdbPortResult.description}")
            items.find { it.checkPoint == "wifi_adb_port" }?.let {
                it.status = wifiAdbPortResult.status
                it.description = wifiAdbPortResult.description
            }

            // 检测 WiFi ADB 设置
            val wifiAdbSettingsResult = checkWifiAdbSettings()
            Log.i(TAG, "WiFi ADB 设置：${wifiAdbSettingsResult.description}")
            items.find { it.checkPoint == "wifi_adb_settings" }?.let {
                it.status = wifiAdbSettingsResult.status
                it.description = wifiAdbSettingsResult.description
            }

            // 检测 USB 安装
            val usbInstallResult = checkUsbInstall()
            Log.i(TAG, "USB 安装：${usbInstallResult.description}")
            items.find { it.checkPoint == "usb_install" }?.let {
                it.status = usbInstallResult.status
                it.description = usbInstallResult.description
            }

        } catch (e: Exception) {
            Log.e(TAG, "检测过程出错：${e.message}", e)
        }

        return items
    }

    /**
     * 检查开发者模式
     * @return CheckResult 包含检测结果和描述
     */
    private fun checkDeveloperMode(): CheckResult {
        return try {
            val context = EnvCheckApp.getContext()
            val resolver = context.contentResolver

            // 方法 1: 使用官方 API (Settings.Secure)
            val devModeSecure = Settings.Secure.getInt(
                resolver,
                Settings.Global.DEVELOPMENT_SETTINGS_ENABLED,
                0
            ) > 0
            if (devModeSecure) {
                return CheckResult(CheckStatus.FAIL, "Settings.Secure 检测到开发者模式已开启")
            }

            // 方法 2: 通过 Settings.Global 检查 Settings 数据库
            val contentProviderResult = isDeveloperModeVia()
            if (contentProviderResult) {
                return CheckResult(CheckStatus.FAIL, "通过 ContentProvider 检测到开发者模式已开启")
            }

            // 方法 3: 检查系统调试属性
            val debuggable = getSystemProperty("ro.debuggable")
            if (debuggable == "1") {
                return CheckResult(CheckStatus.FAIL, "ro.debuggable=1，开发者模式已开启")
            }

            // 方法 4: 检查 settings 数据库 (命令行)
            val settingsResult = getSettingsValue("global", "development_settings_enabled")
            if (settingsResult == "1") {
                return CheckResult(CheckStatus.FAIL, "development_settings_enabled=1，开发者模式已开启")
            }

            CheckResult(CheckStatus.PASS, "未检测到开发者模式")
        } catch (e: Exception) {
            Log.e(TAG, "checkDeveloperMode 出错：${e.message}")
            CheckResult(CheckStatus.FAIL, "检测失败：${e.message}")
        }
    }

    /**
     * 检查 ADB 进程
     * @return CheckResult 包含检测结果和描述
     */
    private fun checkAdbProcess(): CheckResult {
        return try {
            val hasAdbProcess = hasProcess("adbd")
            if (hasAdbProcess) {
                return CheckResult(CheckStatus.FAIL, "检测到 adbd 进程运行")
            }
            CheckResult(CheckStatus.PASS, "未检测到 adbd 进程")
        } catch (e: Exception) {
            Log.e(TAG, "checkAdbProcess 出错：${e.message}")
            CheckResult(CheckStatus.FAIL, "检测失败：${e.message}")
        }
    }

    /**
     * ADB 相关属性检查规则
     * 每个规则包含：属性名、检查函数
     */
    private data class PropCheckRule(
        val propName: String,
        val check: (String) -> Boolean
    )

    /**
     * 检查 ADB 相关系统属性
     * 使用配置化的检查规则，避免多个 if-return 语句
     * @return CheckResult 包含检测结果和描述
     */
    private fun checkAdbProperties(): CheckResult {
        return try {
            // 定义检查规则
            val rules = listOf(
                // 服务运行状态
                PropCheckRule("init.svc.adb_root") { it == "running" },
                PropCheckRule("init.svc.adbd") { it == "running" },
                PropCheckRule("ro.boottime.adb_root") { it.isNotEmpty() },
                PropCheckRule("ro.boottime.adbd") { it.isNotEmpty() },

                
                // ADB 配置
                PropCheckRule("persist.service.adb.enable") { it == "1" },
                PropCheckRule("persist.adb.tls_server.enable") { it == "1" },
                PropCheckRule("persist.adb.wifi.guid") { it.isNotEmpty() },

                // USB 配置 (包含 adb)
                PropCheckRule("persist.sys.usb.config") { it.contains("adb") },
                PropCheckRule("persist.vendor.usb.config") { it.contains("adb") },
                PropCheckRule("sys.usb.config") { it.contains("adb") },
                PropCheckRule("vendor.usb.config") { it.contains("adb") },
                
                // ADB 禁用状态 (0 表示未禁用，即开启)
                PropCheckRule("sys.usb.adb.disabled") { it == "0" },
                PropCheckRule("vendor.sys.usb.adb.disabled") { it == "0" }
            )

            // 执行检查，返回第一个失败的规则
            val failedRule = rules.firstOrNull { rule ->
                val value = getSystemProperty(rule.propName)
                value.isNotEmpty() && rule.check(value)
            }

            // 如果有规则失败，返回失败结果
            if (failedRule != null) {
                val value = getSystemProperty(failedRule.propName)
                CheckResult(CheckStatus.FAIL, "${failedRule.propName} = [$value]")
            } else {
                CheckResult(CheckStatus.PASS, "未检测到 ADB 相关属性")
            }
        } catch (e: Exception) {
            Log.e(TAG, "checkAdbProperties 出错：${e.message}")
            CheckResult(CheckStatus.FAIL, "检测失败：${e.message}")
        }
    }

    /**
     * 检查 ADB Socket 文件
     * 使用 native stat 函数，不需要对文件本身拥有权限
     * @return CheckResult 包含检测结果和描述
     */
    private fun checkAdbSocket(): CheckResult {
        return try {
            // 检查 ADB socket 文件 /data/local/debug/adb
            if (fileExists("/data/local/debug/adbd")) {
                return CheckResult(CheckStatus.FAIL, "检测到 ADB socket: /data/local/debug/adb")
            }

            // 检查 ADB socket 文件 /dev/socket/adb
            if (fileExists("/dev/socket/adbd")) {
                return CheckResult(CheckStatus.FAIL, "检测到 ADB socket: /dev/socket/adb")
            }

            CheckResult(CheckStatus.PASS, "未检测到 ADB socket 文件")
        } catch (e: Exception) {
            Log.e(TAG, "checkAdbSocket 出错：${e.message}")
            CheckResult(CheckStatus.FAIL, "检测失败：${e.message}")
        }
    }

    /**
     * 检查 ADB 设置（通过 ContentProvider）
     * @return CheckResult 包含检测结果和描述
     */
    private fun checkAdbSettings(): CheckResult {
        return try {
            val context = EnvCheckApp.getContext()
            val resolver = context.contentResolver

            // 检查 adb_enabled
            val adbEnabled = Settings.Global.getInt(resolver, "adb_enabled", 0)
            if (adbEnabled == 1) {
                return CheckResult(CheckStatus.FAIL, "Settings.Global adb_enabled=1")
            }

            CheckResult(CheckStatus.PASS, "ADB 设置未启用")
        } catch (e: Exception) {
            Log.e(TAG, "checkAdbSettings 出错：${e.message}")
            CheckResult(CheckStatus.FAIL, "检测失败：${e.message}")
        }
    }

    /**
     * 检查 Dev ContentProvider
     * @return CheckResult 包含检测结果和描述
     */
    private fun checkDevContentProvider(): CheckResult {
        return try {
            val providerResult = isDebugViaContentProviderQuery()
            if (providerResult) {
                return CheckResult(CheckStatus.FAIL, "ContentProvider 查询到调试相关设置")
            }
            CheckResult(CheckStatus.PASS, "ContentProvider 未检测到异常")
        } catch (e: Exception) {
            Log.e(TAG, "checkDevContentProvider 出错：${e.message}")
            CheckResult(CheckStatus.FAIL, "检测失败：${e.message}")
        }
    }

    /**
     * 检查 WiFi ADB 端口
     * @return CheckResult 包含检测结果和描述
     */
    private fun checkWifiAdbPort(): CheckResult {
        try{
            val rules = listOf<PropCheckRule>(
                PropCheckRule("service.adb.tls.port") { it.isNotEmpty() && it != "0" },
                PropCheckRule("persist.adb.tcp.port") { it.isNotEmpty() && it != "0" },
                PropCheckRule("service.adb.tcp.port") { it.isNotEmpty() && it != "0" },
            )
            // 执行检查，返回第一个失败的规则
            val failedRule = rules.firstOrNull { rule ->
                val value = getSystemProperty(rule.propName)
                value.isNotEmpty() && rule.check(value)
            }

            // 如果有规则失败，返回失败结果
            if (failedRule != null) {
                val value = getSystemProperty(failedRule.propName)
                return CheckResult(CheckStatus.FAIL, "${failedRule.propName} = [$value]")
            }

            val checkPorts = listOf<Int>(27042, 23946, 5555, 5554, 5037, 12345, 1234)
            checkPorts.forEach { port ->
                val listen = checkListeningPort(port)
                if (listen) {
                    return CheckResult(CheckStatus.FAIL, "检测到 $port 端口监听")
                }
            }


            return CheckResult(CheckStatus.PASS, "未检测到 WiFi ADB 端口")

        } catch (e: Exception){
            Log.e(TAG, "checkWifiAdbPort 出错：${e.message}")
            return CheckResult(true, "检测失败：${e.message}")
        }

    }

    /**
     * 检查 WiFi ADB 设置
     * @return CheckResult 包含检测结果和描述
     */
    private fun checkWifiAdbSettings(): CheckResult {
        return try {
            val context = EnvCheckApp.getContext()
            val resolver = context.contentResolver

            // 检查 adb_wifi
            val adbWifi = Settings.Global.getInt(resolver, "adb_wifi", 0)
            if (adbWifi == 1) {
                return CheckResult(CheckStatus.FAIL, "Settings.Global adb_wifi=1")
            }

            // 检查 adb_tcp_port
            val tcpPort = Settings.Global.getInt(resolver, "adb_tcp_port", 0)
            if (tcpPort > 0) {
                return CheckResult(CheckStatus.FAIL, "Settings.Global adb_tcp_port=$tcpPort")
            }

//            val adbTLSPort =

            CheckResult(CheckStatus.PASS, "WiFi ADB 设置未启用")
        } catch (e: Exception) {
            Log.e(TAG, "checkWifiAdbSettings 出错：${e.message}")
            CheckResult(CheckStatus.FAIL, "检测失败：${e.message}")
        }
    }

    /**
     * 检查 USB 安装
     * @return CheckResult 包含检测结果和描述
     */
    private fun checkUsbInstall(): CheckResult {
        return try {
            val context = EnvCheckApp.getContext()
            val resolver = context.contentResolver

            // 检查 USB 安装设置
            val usbInstall = Settings.Global.getInt(resolver, "usb_install_enabled", 0)
            if (usbInstall == 1) {
                return CheckResult(CheckStatus.FAIL, "Settings.Global usb_install_enabled=1")
            }

            val usbInstallProp = getSystemProperty("persist.security.adbinstall")
            if(usbInstallProp == "1"){
                return CheckResult(CheckStatus.FAIL, "persist.security.adbinstall=1")
            }

            // 检查包验证器用户同意设置
            val packageVerifier = Settings.Global.getInt(resolver, "package_verifier_user_consent", 1)
            if (packageVerifier == 0) {
                return CheckResult(CheckStatus.FAIL, "package_verifier_user_consent=0")
            }



            CheckResult(CheckStatus.PASS, "USB 安装未启用")
        } catch (e: Exception) {
            Log.e(TAG, "checkUsbInstall 出错：${e.message}")
            CheckResult(CheckStatus.FAIL, "检测失败：${e.message}")
        }
    }

    /**
     * 通过 ContentProvider 检查开发者模式是否开启
     * @return true 表示已开启，false 表示未开启
     */
    private fun isDeveloperModeVia(): Boolean {
        return try {
            val context = EnvCheckApp.getContext()
            val resolver = context.contentResolver

            // 通过 Settings.Global 读取开发者模式状态
            val devMode = Settings.Global.getInt(resolver, "development_settings_enabled", 0)
            Log.i(TAG, "Settings.Global development_settings_enabled = $devMode")
            if (devMode == 1) {
                return true
            }

            false
        } catch (e: Exception) {
            Log.e(TAG, "isDeveloperModeVia 出错：${e.message}")
            false
        }
    }

    /**
     * 通过直接查询 ContentProvider 遍历设置项来检测调试状态
     * @return true 表示检测到调试相关设置已开启
     */
    private fun isDebugViaContentProviderQuery(): Boolean {
        return try {
            val context = EnvCheckApp.getContext()
            val contentResolver = context.contentResolver

            // 查询 settings/global 的 ContentProvider
            val uri = android.net.Uri.parse("content://settings/global")
            val cursor = contentResolver.query(uri, null, null, null, null)

            cursor?.use { cur ->
                val nameIndex = cur.getColumnIndexOrThrow("name")
                val valueIndex = cur.getColumnIndexOrThrow("value")

                while (cur.moveToNext()) {
                    val name = cur.getString(nameIndex)
                    val value = cur.getString(valueIndex)

                    // 检查开发者模式相关设置
                    when (name) {
                        "adb_enabled" -> {
                            Log.i(TAG, "ContentProvider: adb_enabled = $value")
                            if (value == "1") return true
                        }
                        "adb_wifi" -> {
                            Log.i(TAG, "ContentProvider: adb_wifi = $value")
                            if (value == "1") return true
                        }
                        "adb_tcp_port" -> {
                            Log.i(TAG, "ContentProvider: adb_tcp_port = $value")
                            if (value.toIntOrNull() ?: 0 > 0) return true
                        }
                        "usb_install_enabled" -> {
                            Log.i(TAG, "ContentProvider: usb_install_enabled = $value")
                            if (value == "1") return true
                        }
                        "development_settings_enabled" -> {
                            Log.i(TAG, "ContentProvider: development_settings_enabled = $value")
                            if (value == "1") return true
                        }
                    }
                }
            }

            false
        } catch (e: Exception) {
            Log.e(TAG, "isDebugViaContentProviderQuery 出错：${e.message}")
            false
        }
    }

    /**
     * 获取系统属性值
     * 优先使用 native 方法，失败时使用 shell 命令
     * @param property 属性名称
     * @return 属性值，如果获取失败返回空字符串
     */
    private fun getSystemProperty(property: String): String {
        // 优先使用 native 方法
        val nativeResult = getProp(property)
        if (nativeResult != null) {
            Log.i(TAG, "getProp (native): $property=$nativeResult")
            return nativeResult
        }
        
        // native 方法失败时使用 shell 命令
        return try {
            val process = Runtime.getRuntime().exec("getprop $property")
            val reader = BufferedReader(InputStreamReader(process.inputStream))
            val value = reader.readLine()?.trim() ?: ""
            reader.close()
            Log.i(TAG, "getProp (shell): $property=$value")
            value
        } catch (e: Exception) {
            Log.e(TAG, "getSystemProperty($property) 出错：${e.message}")
            ""
        }
    }

    /**
     * 从 settings 数据库获取设置值
     * @param table 表名 (system|secure|global)
     * @param key 设置键
     * @return 设置值，如果获取失败返回空字符串
     */
    private fun getSettingsValue(table: String, key: String): String {
        return try {
            val process = Runtime.getRuntime().exec("settings get $table $key")
            val reader = BufferedReader(InputStreamReader(process.inputStream))
            val value = reader.readLine()?.trim() ?: ""
            reader.close()
            value
        } catch (e: Exception) {
            Log.e(TAG, "getSettingsValue($table, $key) 出错：${e.message}")
            ""
        }
    }

    /**
     * 检查是否存在指定进程
     * @param processName 进程名
     * @return true 表示存在，false 表示不存在
     */
    private fun hasProcess(processName: String): Boolean {
        return try {
            val process = Runtime.getRuntime().exec("ps -A")
            val reader = BufferedReader(InputStreamReader(process.inputStream))
            var found = false
            var line: String?
            while (reader.readLine().also { line = it } != null) {
                if (line!!.contains(processName)) {
                    found = true
                    break
                }
            }
            reader.close()
            found
        } catch (e: Exception) {
            Log.e(TAG, "hasProcess($processName) 出错：${e.message}")
            false
        }
    }

    /**
     * 检查指定端口是否在监听
     * @param port 端口号
     * @return true 表示在监听，false 表示不在监听
     */
    private fun checkListeningPort(port: Int): Boolean {
        return isPortInUseForAddress("127.0.0.1", port) ||
                isPortInUseForAddress("::1", port)
    }

    /**
     * 检测指定地址和端口是否可绑定
     * @param host 主机地址 (IPv4 或 IPv6)
     * @param port 端口号
     * @return true 如果绑定失败（端口被占用）；false 如果绑定成功（端口空闲）
     */
    private fun isPortInUseForAddress(host: String, port: Int): Boolean {
        var serverSocket: ServerSocket? = null
        return try {
            val inetAddress = InetAddress.getByName(host)
            serverSocket = ServerSocket()
            // 设置重用地址为 false 以确保检测准确性
            serverSocket.reuseAddress = false
            serverSocket.bind(InetSocketAddress(inetAddress, port))
            // 绑定成功，端口未被占用
            false
        } catch (e: BindException) {
            // 端口已被占用
            true
        } catch (e: IOException) {
            // 其他 I/O 错误，默认视为已被占用或不可用
            Log.e(TAG, "检查 $host:$port 时发生异常: ${e.message}")
            true
        } finally {
            // 确保关闭 ServerSocket
            try {
                serverSocket?.close()
            } catch (e: IOException) {
                // 忽略关闭时的异常
            }
        }
    }
}

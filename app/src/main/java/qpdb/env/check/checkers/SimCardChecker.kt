package qpdb.env.check.checkers

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.telephony.SubscriptionInfo
import android.telephony.SubscriptionManager
import android.telephony.TelephonyManager
import android.util.Log
import androidx.annotation.RequiresPermission
import androidx.core.content.ContextCompat
import qpdb.env.check.EnvCheckApp
import qpdb.env.check.model.CheckItem
import qpdb.env.check.model.CheckResult
import qpdb.env.check.model.CheckStatus
import qpdb.env.check.model.Checkable

/**
 * SIM 卡信息检测
 * 检测 SIM 卡状态、运营商信息、MCC/MNC、ICCID 等
 */
class SimCardChecker : Checkable {

    companion object {
        private const val TAG = "SimCardChecker"
    }

    override val categoryName: String = "SIM卡信息"

    override fun checkList(): List<CheckItem> {
        Log.i(TAG, "checkList() 被调用")
        return listOf(
            // SIM 卡状态检测
            CheckItem(
                name = "SIM 卡状态",
                checkPoint = "sim_state",
                description = "等待检测..."
            ),
            // 运营商信息
            CheckItem(
                name = "运营商名称",
                checkPoint = "operator_name",
                description = "等待检测..."
            ),
            // MCC 检测
            CheckItem(
                name = "MCC (移动国家码)",
                checkPoint = "mcc",
                description = "等待检测..."
            ),
            // MNC 检测
            CheckItem(
                name = "MNC (移动网络码)",
                checkPoint = "mnc",
                description = "等待检测..."
            ),
            // ICCID 检测
            CheckItem(
                name = "ICCID (SIM卡标识)",
                checkPoint = "iccid",
                description = "等待检测..."
            ),
            // IMSI 检测
            CheckItem(
                name = "IMSI",
                checkPoint = "imsi",
                description = "等待检测..."
            ),
            // 电话号码检测
            CheckItem(
                name = "电话号码",
                checkPoint = "phone_number",
                description = "等待检测..."
            ),
            // 设备 ID 检测
            CheckItem(
                name = "设备 ID (IMEI/MEID)",
                checkPoint = "device_id",
                description = "等待检测..."
            ),
            // 网络类型检测
            CheckItem(
                name = "网络类型",
                checkPoint = "network_type",
                description = "等待检测..."
            ),
            // SIM 卡综合检测
            CheckItem(
                name = "SIM 卡信息完整度",
                checkPoint = "sim_integrity",
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
            // 检查权限
            val hasPhoneStatePermission = ContextCompat.checkSelfPermission(
                context, Manifest.permission.READ_PHONE_STATE
            ) == PackageManager.PERMISSION_GRANTED

            if (!hasPhoneStatePermission) {
                items.forEach { item ->
                    item.status = CheckStatus.FAIL
                    item.description = "缺少 READ_PHONE_STATE 权限"
                }
                return items
            }

            // 获取 TelephonyManager
            val telephonyManager = context.getSystemService(Context.TELEPHONY_SERVICE) as TelephonyManager

            // 检测 SIM 卡状态
            val simStateResult = checkSimState(telephonyManager)
            Log.i(TAG, "SIM 卡状态：${simStateResult.description}")
            items.find { it.checkPoint == "sim_state" }?.let {
                it.status = simStateResult.status
                it.description = simStateResult.description
            }

            // 检测运营商名称
            val operatorNameResult = checkOperatorName(telephonyManager)
            Log.i(TAG, "运营商名称：${operatorNameResult.description}")
            items.find { it.checkPoint == "operator_name" }?.let {
                it.status = operatorNameResult.status
                it.description = operatorNameResult.description
            }

            // 检测 MCC
            val mccResult = checkMcc(telephonyManager)
            Log.i(TAG, "MCC：${mccResult.description}")
            items.find { it.checkPoint == "mcc" }?.let {
                it.status = mccResult.status
                it.description = mccResult.description
            }

            // 检测 MNC
            val mncResult = checkMnc(telephonyManager)
            Log.i(TAG, "MNC：${mncResult.description}")
            items.find { it.checkPoint == "mnc" }?.let {
                it.status = mncResult.status
                it.description = mncResult.description
            }

            // 检测 ICCID
            val iccidResult = checkIccid(context, telephonyManager)
            Log.i(TAG, "ICCID：${iccidResult.description}")
            items.find { it.checkPoint == "iccid" }?.let {
                it.status = iccidResult.status
                it.description = iccidResult.description
            }

            // 检测 IMSI
            val imsiResult = checkImsi(telephonyManager)
            Log.i(TAG, "IMSI：${imsiResult.description}")
            items.find { it.checkPoint == "imsi" }?.let {
                it.status = imsiResult.status
                it.description = imsiResult.description
            }

            // 检测电话号码
            val phoneNumberResult = checkPhoneNumber(telephonyManager)
            Log.i(TAG, "电话号码：${phoneNumberResult.description}")
            items.find { it.checkPoint == "phone_number" }?.let {
                it.status = phoneNumberResult.status
                it.description = phoneNumberResult.description
            }

            // 检测设备 ID
            val deviceIdResult = checkDeviceId(telephonyManager)
            Log.i(TAG, "设备 ID：${deviceIdResult.description}")
            items.find { it.checkPoint == "device_id" }?.let {
                it.status = deviceIdResult.status
                it.description = deviceIdResult.description
            }

            // 检测网络类型
            val networkTypeResult = checkNetworkType(telephonyManager)
            Log.i(TAG, "网络类型：${networkTypeResult.description}")
            items.find { it.checkPoint == "network_type" }?.let {
                it.status = networkTypeResult.status
                it.description = networkTypeResult.description
            }

            // SIM 卡信息完整度综合检测
            val integrityResult = checkSimIntegrity(
                simStateResult, operatorNameResult, mccResult, mncResult, iccidResult
            )
            Log.i(TAG, "SIM 信息完整度：${integrityResult.description}")
            items.find { it.checkPoint == "sim_integrity" }?.let {
                it.status = integrityResult.status
                it.description = integrityResult.description
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
     * 检测 SIM 卡状态
     * @return CheckResult 包含检测结果和描述
     */
    private fun checkSimState(telephonyManager: TelephonyManager): CheckResult {
        return try {
            val simState = telephonyManager.simState
            val stateDescription = when (simState) {
                TelephonyManager.SIM_STATE_ABSENT -> "无 SIM 卡"
                TelephonyManager.SIM_STATE_PIN_REQUIRED -> "需要 PIN 码解锁"
                TelephonyManager.SIM_STATE_PUK_REQUIRED -> "需要 PUK 码解锁"
                TelephonyManager.SIM_STATE_NETWORK_LOCKED -> "网络锁定"
                TelephonyManager.SIM_STATE_READY -> "SIM 卡就绪"
                TelephonyManager.SIM_STATE_NOT_READY -> "SIM 卡未就绪"
                TelephonyManager.SIM_STATE_PERM_DISABLED -> "SIM 卡被永久禁用"
                TelephonyManager.SIM_STATE_CARD_IO_ERROR -> "SIM 卡 IO 错误"
                TelephonyManager.SIM_STATE_CARD_RESTRICTED -> "SIM 卡受限"
                10 -> "SIM 卡已加载"  // SIM_STATE_LOADED (API 29+)
                11 -> "SIM 卡存在"    // SIM_STATE_PRESENT (API 29+)
                TelephonyManager.SIM_STATE_UNKNOWN -> "状态未知"
                else -> "未知状态 ($simState)"
            }

            val isNormal = simState == TelephonyManager.SIM_STATE_READY ||
                          simState == 10  // SIM_STATE_LOADED

            CheckResult(isNormal, "状态: $stateDescription")
        } catch (e: Exception) {
            Log.e(TAG, "checkSimState 出错：${e.message}")
            CheckResult(false, "检测失败：${e.message}")
        }
    }

    /**
     * 检测运营商名称
     * @return CheckResult 包含检测结果和描述
     */
    private fun checkOperatorName(telephonyManager: TelephonyManager): CheckResult {
        return try {
            // 获取网络运营商名称
            val networkOperatorName = telephonyManager.networkOperatorName
            // 获取 SIM 卡运营商名称
            val simOperatorName = telephonyManager.simOperatorName

            val displayName = when {
                !networkOperatorName.isNullOrEmpty() && networkOperatorName != "UNKNOWN" -> 
                    networkOperatorName
                !simOperatorName.isNullOrEmpty() && simOperatorName != "UNKNOWN" -> 
                    simOperatorName
                else -> null
            }

            if (displayName == null) {
                return CheckResult(CheckStatus.FAIL, "无法获取运营商名称")
            }

            // 检测是否为模拟器/虚拟运营商
            val virtualOperators = listOf(
                "Android Virtual Operator",
                "android virtual operator",
                "Android",
                "Virtual",
                "Simulator",
                " Emulator",  // 常见模拟器特征
                "Genymotion",
                "Nox",
                "BlueStacks",
                "LDPlayer",
                "MuMu",
                "MEmu"
            )

            val isVirtualOperator = virtualOperators.any {
                displayName.contains(it, ignoreCase = true)
            }

            return if (isVirtualOperator) {
                CheckResult(CheckStatus.FAIL, "检测到虚拟运营商: $displayName")
            } else {
                CheckResult(CheckStatus.PASS, "运营商: $displayName")
            }
        } catch (e: Exception) {
            Log.e(TAG, "checkOperatorName 出错：${e.message}")
            CheckResult(CheckStatus.FAIL, "检测失败：${e.message}")
        }
    }

    /**
     * 检测 MCC (移动国家码)
     * @return CheckResult 包含检测结果和描述
     */
    private fun checkMcc(telephonyManager: TelephonyManager): CheckResult {
        return try {
            // 从网络运营商获取 MCC+MNC
            val networkOperator = telephonyManager.networkOperator
            // 从 SIM 卡获取 MCC+MNC
            val simOperator = telephonyManager.simOperator

            val mcc = when {
                !networkOperator.isNullOrEmpty() && networkOperator.length >= 3 -> 
                    networkOperator.substring(0, 3)
                !simOperator.isNullOrEmpty() && simOperator.length >= 3 -> 
                    simOperator.substring(0, 3)
                else -> null
            }

            if (mcc != null) {
                val countryName = getCountryNameFromMcc(mcc)
                CheckResult(CheckStatus.PASS, "MCC: $mcc ($countryName)")
            } else {
                CheckResult(CheckStatus.FAIL, "无法获取 MCC")
            }
        } catch (e: Exception) {
            Log.e(TAG, "checkMcc 出错：${e.message}")
            CheckResult(CheckStatus.FAIL, "检测失败：${e.message}")
        }
    }

    /**
     * 检测 MNC (移动网络码)
     * @return CheckResult 包含检测结果和描述
     */
    private fun checkMnc(telephonyManager: TelephonyManager): CheckResult {
        return try {
            // 从网络运营商获取 MCC+MNC
            val networkOperator = telephonyManager.networkOperator
            // 从 SIM 卡获取 MCC+MNC
            val simOperator = telephonyManager.simOperator

            val mnc = when {
                !networkOperator.isNullOrEmpty() && networkOperator.length >= 5 -> 
                    networkOperator.substring(3)
                !simOperator.isNullOrEmpty() && simOperator.length >= 5 -> 
                    simOperator.substring(3)
                else -> null
            }

            if (mnc != null) {
                CheckResult(CheckStatus.PASS, "MNC: $mnc")
            } else {
                CheckResult(CheckStatus.FAIL, "无法获取 MNC")
            }
        } catch (e: Exception) {
            Log.e(TAG, "checkMnc 出错：${e.message}")
            CheckResult(CheckStatus.FAIL, "检测失败：${e.message}")
        }
    }

    /**
     * 检测 ICCID (SIM卡唯一标识)
     * @return CheckResult 包含检测结果和描述
     */
    private fun checkIccid(context: Context, telephonyManager: TelephonyManager): CheckResult {
        return try {
            var iccid: String? = null
            
            // 方法 1: 尝试从 SubscriptionManager 获取 (Android 5.1+)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP_MR1) {
                try {
                    val subscriptionManager = context.getSystemService(Context.TELEPHONY_SUBSCRIPTION_SERVICE) as SubscriptionManager
                    if (ContextCompat.checkSelfPermission(context, Manifest.permission.READ_PHONE_STATE) == PackageManager.PERMISSION_GRANTED) {
                        val activeSubscriptionInfoList = subscriptionManager.activeSubscriptionInfoList
                        if (!activeSubscriptionInfoList.isNullOrEmpty()) {
                            val subscriptionInfo = activeSubscriptionInfoList[0]
                            iccid = subscriptionInfo.iccId
                            if (iccid.isNullOrEmpty() && Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                                // Android 10+ 可能使用 getIccId() 方法
                                try {
                                    val method = SubscriptionInfo::class.java.getMethod("getIccId")
                                    iccid = method.invoke(subscriptionInfo) as? String
                                } catch (e: Exception) {
                                    Log.w(TAG, "通过反射获取 ICCID 失败: ${e.message}")
                                }
                            }
                        }
                    }
                } catch (e: Exception) {
                    Log.w(TAG, "从 SubscriptionManager 获取 ICCID 失败: ${e.message}")
                }
            }

            // 方法 2: 尝试使用反射获取 (可能受限)
            if (iccid.isNullOrEmpty()) {
                try {
                    val method = TelephonyManager::class.java.getDeclaredMethod("getSimSerialNumber")
                    iccid = method.invoke(telephonyManager) as? String
                } catch (e: Exception) {
                    Log.w(TAG, "通过反射获取 ICCID 失败: ${e.message}")
                }
            }

            if (!iccid.isNullOrEmpty() && iccid != "null") {
                // 脱敏显示，只显示前6位和后4位
                val maskedIccid = if (iccid.length > 10) {
                    "${iccid.take(6)}****${iccid.takeLast(4)}"
                } else {
                    "****"
                }
                CheckResult(CheckStatus.PASS, "ICCID: $maskedIccid (长度: ${iccid.length})")
            } else {
                // Android 10+ 开始，非系统应用无法获取 ICCID
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    CheckResult(CheckStatus.FAIL, "无法获取 ICCID (Android 10+ 限制)")
                } else {
                    CheckResult(CheckStatus.FAIL, "无法获取 ICCID")
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "checkIccid 出错：${e.message}")
            CheckResult(CheckStatus.FAIL, "检测失败：${e.message}")
        }
    }

    /**
     * 检测 IMSI (国际移动用户识别码)
     * @return CheckResult 包含检测结果和描述
     */
    private fun checkImsi(telephonyManager: TelephonyManager): CheckResult {
        return try {
            val imsi = telephonyManager.subscriberId

            if (!imsi.isNullOrEmpty()) {
                // 脱敏显示，只显示前5位和后2位
                val maskedImsi = if (imsi.length > 7) {
                    "${imsi.take(5)}****${imsi.takeLast(2)}"
                } else {
                    "****"
                }
                CheckResult(CheckStatus.PASS, "IMSI: $maskedImsi (长度: ${imsi.length})")
            } else {
                CheckResult(CheckStatus.FAIL, "无法获取 IMSI")
            }
        } catch (e: SecurityException) {
            Log.e(TAG, "checkImsi 安全异常：${e.message}")
            CheckResult(CheckStatus.FAIL, "权限受限，无法获取 IMSI")
        } catch (e: Exception) {
            Log.e(TAG, "checkImsi 出错：${e.message}")
            CheckResult(CheckStatus.FAIL, "检测失败：${e.message}")
        }
    }

    /**
     * 检测电话号码
     * @return CheckResult 包含检测结果和描述
     */
    @RequiresPermission(allOf = [Manifest.permission.READ_SMS, Manifest.permission.READ_PHONE_NUMBERS, Manifest.permission.READ_PHONE_STATE])
    private fun checkPhoneNumber(telephonyManager: TelephonyManager): CheckResult {
        return try {
            val phoneNumber = telephonyManager.line1Number

            if (!phoneNumber.isNullOrEmpty() && phoneNumber != "null") {
                // 脱敏显示，只显示前3位和后4位
                val maskedNumber = if (phoneNumber.length > 7) {
                    "${phoneNumber.take(3)}****${phoneNumber.takeLast(4)}"
                } else {
                    "****"
                }
                CheckResult(CheckStatus.PASS, "号码: $maskedNumber")
            } else {
                CheckResult(CheckStatus.FAIL, "无法获取电话号码 (可能未存储在 SIM 卡中)")
            }
        } catch (e: Exception) {
            Log.e(TAG, "checkPhoneNumber 出错：${e.message}")
            CheckResult(CheckStatus.FAIL, "检测失败：${e.message}")
        }
    }

    /**
     * 检测设备 ID (IMEI/MEID)
     * @return CheckResult 包含检测结果和描述
     */
    private fun checkDeviceId(telephonyManager: TelephonyManager): CheckResult {
        return try {
            var deviceId: String? = null
            var idType = ""

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                // Android 10+ 非系统应用无法获取 IMEI
                return CheckResult(CheckStatus.FAIL, "无法获取设备 ID (Android 10+ 限制)")
            } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                // Android 8-9
                try {
                    deviceId = telephonyManager.imei
                    idType = "IMEI"
                } catch (e: Exception) {
                    Log.w(TAG, "获取 IMEI 失败: ${e.message}")
                }
                
                if (deviceId.isNullOrEmpty()) {
                    try {
                        deviceId = telephonyManager.meid
                        idType = "MEID"
                    } catch (e: Exception) {
                        Log.w(TAG, "获取 MEID 失败: ${e.message}")
                    }
                }
            } else {
                // Android 7.1 及以下
                @Suppress("DEPRECATION")
                deviceId = telephonyManager.deviceId
                idType = if (deviceId?.length == 14) "MEID" else "IMEI"
            }

            if (!deviceId.isNullOrEmpty() && deviceId != "null") {
                // 脱敏显示
                val maskedId = if (deviceId.length > 4) {
                    "${deviceId.take(4)}****${deviceId.takeLast(4)}"
                } else {
                    "****"
                }
                CheckResult(CheckStatus.PASS, "$idType: $maskedId")
            } else {
                CheckResult(CheckStatus.FAIL, "无法获取设备 ID")
            }
        } catch (e: SecurityException) {
            Log.e(TAG, "checkDeviceId 安全异常：${e.message}")
            CheckResult(CheckStatus.FAIL, "权限受限，无法获取设备 ID")
        } catch (e: Exception) {
            Log.e(TAG, "checkDeviceId 出错：${e.message}")
            CheckResult(CheckStatus.FAIL, "检测失败：${e.message}")
        }
    }

    /**
     * 检测网络类型
     * @return CheckResult 包含检测结果和描述
     */
    @RequiresPermission(Manifest.permission.READ_PHONE_STATE)
    private fun checkNetworkType(telephonyManager: TelephonyManager): CheckResult {
        return try {
            val networkType = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                telephonyManager.dataNetworkType
            } else {
                @Suppress("DEPRECATION")
                telephonyManager.networkType
            }

            val networkTypeName = getNetworkTypeName(networkType)
            val isNormal = networkType != TelephonyManager.NETWORK_TYPE_UNKNOWN

            CheckResult(isNormal, "网络类型: $networkTypeName")
        } catch (e: Exception) {
            Log.e(TAG, "checkNetworkType 出错：${e.message}")
            CheckResult(false, "检测失败：${e.message}")
        }
    }

    /**
     * SIM 卡信息完整度综合检测
     * @return CheckResult 包含检测结果和描述
     */
    private fun checkSimIntegrity(
        simStateResult: CheckResult,
        operatorNameResult: CheckResult,
        mccResult: CheckResult,
        mncResult: CheckResult,
        iccidResult: CheckResult
    ): CheckResult {
        return try {
            val results = listOf(simStateResult, operatorNameResult, mccResult, mncResult)
            val passedCount = results.count { it.status == CheckStatus.PASS }
            val totalCount = results.size

            when {
                simStateResult.status != CheckStatus.PASS ->
                    CheckResult(CheckStatus.FAIL, "SIM 卡状态异常，无法完成检测")
                passedCount == totalCount ->
                    CheckResult(CheckStatus.PASS, "SIM 卡信息完整 ($passedCount/$totalCount)")
                passedCount >= totalCount / 2 ->
                    CheckResult(CheckStatus.FAIL, "SIM 卡信息基本完整 ($passedCount/$totalCount)")
                else ->
                    CheckResult(CheckStatus.FAIL, "SIM 卡信息不完整 ($passedCount/$totalCount)")
            }
        } catch (e: Exception) {
            Log.e(TAG, "checkSimIntegrity 出错：${e.message}")
            CheckResult(CheckStatus.FAIL, "检测失败：${e.message}")
        }
    }

    /**
     * 根据 MCC 获取国家名称
     */
    private fun getCountryNameFromMcc(mcc: String): String {
        val mccMap = mapOf(
            "460" to "中国",
            "461" to "中国",
            "454" to "中国香港",
            "455" to "中国澳门",
            "466" to "中国台湾",
            "310" to "美国",
            "311" to "美国",
            "312" to "美国",
            "313" to "美国",
            "314" to "美国",
            "315" to "美国",
            "316" to "美国",
            "440" to "日本",
            "441" to "日本",
            "234" to "英国",
            "235" to "英国",
            "208" to "法国",
            "262" to "德国",
            "222" to "意大利",
            "214" to "西班牙",
            "250" to "俄罗斯",
            "502" to "马来西亚",
            "525" to "新加坡",
            "520" to "泰国",
            "510" to "印度尼西亚",
            "515" to "菲律宾",
            "505" to "澳大利亚",
            "530" to "新西兰",
            "404" to "印度",
            "405" to "印度",
            "286" to "土耳其",
            "424" to "阿联酋",
            "426" to "巴林",
            "427" to "卡塔尔",
            "430" to "阿联酋",
            "431" to "阿联酋",
            "432" to "伊朗",
            "434" to "乌兹别克斯坦",
            "436" to "塔吉克斯坦",
            "437" to "吉尔吉斯斯坦",
            "438" to "土库曼斯坦",
            "440" to "日本",
            "450" to "韩国",
            "452" to "越南",
            "456" to "柬埔寨",
            "457" to "老挝",
            "502" to "马来西亚",
            "525" to "新加坡",
            "530" to "新西兰"
        )
        return mccMap[mcc] ?: "未知国家"
    }

    /**
     * 获取网络类型名称
     */
    private fun getNetworkTypeName(networkType: Int): String {
        return when (networkType) {
            TelephonyManager.NETWORK_TYPE_GPRS -> "GPRS (2G)"
            TelephonyManager.NETWORK_TYPE_EDGE -> "EDGE (2.5G)"
            TelephonyManager.NETWORK_TYPE_CDMA -> "CDMA (2G)"
            TelephonyManager.NETWORK_TYPE_1xRTT -> "1xRTT (2G)"
            TelephonyManager.NETWORK_TYPE_IDEN -> "iDEN (2G)"
            TelephonyManager.NETWORK_TYPE_GSM -> "GSM (2G)"
            TelephonyManager.NETWORK_TYPE_UMTS -> "UMTS (3G)"
            TelephonyManager.NETWORK_TYPE_EVDO_0 -> "EVDO_0 (3G)"
            TelephonyManager.NETWORK_TYPE_EVDO_A -> "EVDO_A (3G)"
            TelephonyManager.NETWORK_TYPE_EVDO_B -> "EVDO_B (3G)"
            TelephonyManager.NETWORK_TYPE_HSDPA -> "HSDPA (3G)"
            TelephonyManager.NETWORK_TYPE_HSUPA -> "HSUPA (3G)"
            TelephonyManager.NETWORK_TYPE_HSPA -> "HSPA (3G)"
            TelephonyManager.NETWORK_TYPE_HSPAP -> "HSPA+ (3.5G)"
            TelephonyManager.NETWORK_TYPE_EHRPD -> "eHRPD (3G)"
            TelephonyManager.NETWORK_TYPE_TD_SCDMA -> "TD-SCDMA (3G)"
            TelephonyManager.NETWORK_TYPE_LTE -> "LTE (4G)"
            TelephonyManager.NETWORK_TYPE_IWLAN -> "IWLAN"
            TelephonyManager.NETWORK_TYPE_NR -> "NR (5G)"
            TelephonyManager.NETWORK_TYPE_UNKNOWN -> "未知"
            else -> "未知类型 ($networkType)"
        }
    }
}

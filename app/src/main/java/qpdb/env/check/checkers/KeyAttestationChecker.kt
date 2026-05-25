package qpdb.env.check.checkers

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.util.Log
import qpdb.env.check.model.CheckItem
import qpdb.env.check.model.CheckResult
import qpdb.env.check.model.CheckStatus
import qpdb.env.check.model.Checkable
import qpdb.env.check.attestation.Attestation
import qpdb.env.check.attestation.RootOfTrust
import qpdb.env.check.utils.KeyAttestationUtil
import qpdb.env.check.utils.KeyAttestationRevocationUtil
import qpdb.env.check.utils.SystemPropertyUtil
import qpdb.env.check.utils.TrickyStoreUtil
import org.bouncycastle.util.encoders.Hex

/**
 * KeyAttestation 检测器
 *
 * 通过 Android KeyStore 硬件密钥认证机制，检测设备的引导状态和安全配置。
 *
 * 检测项：
 * 1. TEE 认证可用性 - 能否成功生成 TEE 认证密钥
 * 2. StrongBox 认证可用性 - 能否成功生成 StrongBox 认证密钥
 * 3. 认证版本与安全级别 - Keymaster/KeyMint 版本号 + Software/TEE/StrongBox
 * 4. Bootloader 与 Verified Boot - deviceLocked + verifiedBootState + 交叉验证
 * 5. 回滚防护与系统版本 - rollbackResistance + osVersion/osPatchLevel
 * 6. 证书吊销状态 - 证书链是否在 Google 官方吊销列表中
 * 7. Tricky Store 时序检测 (TEE)
 * 8. Tricky Store 时序检测 (StrongBox)
 */
class KeyAttestationChecker : Checkable {

    companion object {
        private const val TAG = "KeyAttestationChecker"
    }

    override val categoryName: String = "密钥认证检测"

    override fun checkList(): List<CheckItem> {
        return listOf(
            CheckItem(
                name = "TEE 认证可用性",
                checkPoint = "tee_attestation",
                description = "等待检测..."
            ),
            CheckItem(
                name = "StrongBox 认证可用性",
                checkPoint = "strongbox_attestation",
                description = "等待检测..."
            ),
            CheckItem(
                name = "认证版本与安全级别",
                checkPoint = "version_and_security",
                description = "等待检测..."
            ),
            CheckItem(
                name = "Bootloader 与 Verified Boot",
                checkPoint = "bootloader_and_vb",
                description = "等待检测..."
            ),
            CheckItem(
                name = "回滚防护与系统版本",
                checkPoint = "rollback_and_patch",
                description = "等待检测..."
            ),
            CheckItem(
                name = "证书吊销状态",
                checkPoint = "cert_revocation_status",
                description = "等待检测..."
            ),
            CheckItem(
                name = "Tricky Store 时序检测 (TEE)",
                checkPoint = "tricky_store_timing_tee",
                description = "等待检测..."
            ),
            CheckItem(
                name = "Tricky Store 时序检测 (StrongBox)",
                checkPoint = "tricky_store_timing_sb",
                description = "等待检测..."
            )
        )
    }

    override fun runCheck(): List<CheckItem> {
        return kotlinx.coroutines.runBlocking { runCheckBlocking() }
    }

    override suspend fun runCheckWithProgress(onProgress: suspend (CheckItem) -> Unit): List<CheckItem> {
        return runCheckBlocking(onProgress)
    }

    private suspend fun runCheckBlocking(
        onProgress: suspend (CheckItem) -> Unit = {}
    ): List<CheckItem> {
        val items = checkList().toMutableList()

        suspend fun emit(checkPoint: String) {
            items.find { it.checkPoint == checkPoint }?.let { onProgress(it) }
        }

        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.N) {
            items.forEach {
                it.status = CheckStatus.INFO
                it.description = "需要 Android 7.0+"
                emit(it.checkPoint)
            }
            return items
        }

        val pm = qpdb.env.check.EnvCheckApp.getContext().packageManager
        val hasStrongBox = KeyAttestationUtil.hasStrongBox(pm)

        // ===== 1. TEE 认证 =====
        val teeResult = KeyAttestationUtil.performAttestation(useStrongBox = false, forceReset = true)
        val teeAttestation = teeResult.attestation

        items.find { it.checkPoint == "tee_attestation" }?.let {
            if (teeResult.success && teeAttestation != null) {
                it.status = CheckStatus.PASS
                it.description = "TEE 认证成功，证书链 ${teeResult.certChain.size} 张"
            } else {
                it.status = CheckStatus.FAIL
                it.description = "TEE 认证失败: ${teeResult.error}"
            }
        }
        emit("tee_attestation")

        // ===== 2. StrongBox 认证 =====
        val sbResult = if (hasStrongBox) {
            KeyAttestationUtil.performAttestation(useStrongBox = true, forceReset = true)
        } else null

        items.find { it.checkPoint == "strongbox_attestation" }?.let {
            if (!hasStrongBox) {
                it.status = CheckStatus.INFO
                it.description = "设备不支持 StrongBox"
            } else if (sbResult?.success == true && sbResult.attestation != null) {
                it.status = CheckStatus.PASS
                it.description = "StrongBox 认证成功"
            } else {
                it.status = CheckStatus.FAIL
                it.description = "StrongBox 认证失败: ${sbResult?.error}"
            }
        }
        emit("strongbox_attestation")

        // 使用 TEE 结果作为主要分析对象（如果 TEE 失败则用 StrongBox）
        val primaryResult = if (teeResult.success) teeResult else sbResult
        val attestation = primaryResult?.attestation

        if (attestation == null) {
            // 认证完全失败，剩余项标记为不可用
            listOf(
                "version_and_security",
                "bootloader_and_vb",
                "rollback_and_patch",
                "cert_revocation_status"
            ).forEach { cp ->
                items.find { it.checkPoint == cp }?.let {
                    it.status = CheckStatus.INFO
                    it.description = "认证不可用"
                    emit(cp)
                }
            }
            return items
        }

        val rootOfTrust = attestation.getRootOfTrust()
        val teeAuth = attestation.teeEnforced
        val swAuth = attestation.softwareEnforced

        // ===== 3. 认证版本与安全级别 =====
        items.find { it.checkPoint == "version_and_security" }?.let {
            val attLevel = attestation.attestationSecurityLevel
            val kmLevel = attestation.keymasterSecurityLevel
            val attVersion = Attestation.attestationVersionToString(attestation.attestationVersion)
            val kmVersion = Attestation.keymasterVersionToString(attestation.keymasterVersion)

            val levelDesc = "Attestation: ${Attestation.securityLevelToString(attLevel)}\n" +
                    "Keymaster: ${Attestation.securityLevelToString(kmLevel)}\n" +
                    "Version: $attVersion / $kmVersion"

            it.status = when {
                attLevel == Attestation.KM_SECURITY_LEVEL_STRONG_BOX ||
                        attLevel == Attestation.KM_SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> CheckStatus.PASS
                else -> CheckStatus.FAIL
            }
            it.description = levelDesc
        }
        emit("version_and_security")

        // ===== 4. Bootloader 与 Verified Boot（含交叉验证） =====
        val propChecks = checkBootloaderProps()
        items.find { it.checkPoint == "bootloader_and_vb" }?.let {
            val kaLocked = rootOfTrust?.deviceLocked
            val propLocked = inferLockedFromProps(propChecks)
            val finalLocked = when {
                kaLocked == true && propLocked != false -> true
                kaLocked == false && propLocked != true -> false
                propLocked == true -> true
                propLocked == false -> false
                else -> kaLocked // fallback
            }

            val desc = StringBuilder()
            // Bootloader 锁定状态
            desc.append("=== Bootloader 锁定 ===\n")
            desc.append("KeyAttestation deviceLocked: ${kaLocked ?: "N/A"}\n")
            desc.append("属性交叉验证: ${when (propLocked) { true -> "锁定" false -> "解锁" else -> "无法推断" }}\n")
            desc.append("综合判定: ${when (finalLocked) { true -> "锁定" false -> "解锁" else -> "未知" }}\n\n")
            desc.append("=== 系统属性 ===\n")
            propChecks.forEach { (k, v) ->
                desc.append("$k: ${if (v.isEmpty()) "(null)" else v}\n")
            }

            // Verified Boot 状态
            desc.append("\n=== Verified Boot ===\n")
            if (rootOfTrust != null) {
                desc.append("verifiedBootState: ${RootOfTrust.verifiedBootStateToString(rootOfTrust.verifiedBootState)}\n")
                desc.append("verifiedBootKey: ${Hex.toHexString(rootOfTrust.verifiedBootKey)}\n")
                rootOfTrust.verifiedBootHash?.let {
                    desc.append("verifiedBootHash: ${Hex.toHexString(it)}\n")
                } ?: desc.append("verifiedBootHash: (none)\n")
            } else {
                desc.append("未获取到 RootOfTrust\n")
            }

            // 综合状态：任一异常即 FAIL
            val vbStatus = when (rootOfTrust?.verifiedBootState) {
                RootOfTrust.KM_VERIFIED_BOOT_VERIFIED -> CheckStatus.PASS
                RootOfTrust.KM_VERIFIED_BOOT_SELF_SIGNED -> CheckStatus.INFO
                else -> CheckStatus.FAIL
            }
            val blStatus = when (finalLocked) {
                true -> CheckStatus.PASS
                false -> CheckStatus.FAIL
                null -> CheckStatus.INFO
            }
            it.status = when {
                blStatus == CheckStatus.FAIL || vbStatus == CheckStatus.FAIL -> CheckStatus.FAIL
                blStatus == CheckStatus.INFO || vbStatus == CheckStatus.INFO -> CheckStatus.INFO
                else -> CheckStatus.PASS
            }
            it.description = desc.toString().trim()
        }
        emit("bootloader_and_vb")

        // ===== 5. 回滚防护与系统版本 =====
        items.find { it.checkPoint == "rollback_and_patch" }?.let {
            val teeRR = teeAuth.rollbackResistance ?: teeAuth.rollbackResistant
            val swRR = swAuth.rollbackResistance ?: swAuth.rollbackResistant
            val hasRR = teeRR == true || swRR == true

            val osVer = teeAuth.osVersion ?: swAuth.osVersion
            val osPatch = teeAuth.osPatchLevel ?: swAuth.osPatchLevel
            val vendorPatch = teeAuth.vendorPatchLevel ?: swAuth.vendorPatchLevel
            val bootPatch = teeAuth.bootPatchLevel ?: swAuth.bootPatchLevel

            val parts = mutableListOf<String>()
            parts.add("=== 回滚防护 ===")
            parts.add(
                if (hasRR) {
                    val source = when {
                        teeRR == true -> "TEE"
                        swRR == true -> "Software"
                        else -> "Unknown"
                    }
                    "支持 ($source)"
                } else {
                    "不支持"
                }
            )
            parts.add("")
            parts.add("=== 系统版本 ===")
            parts.add("OS: ${KeyAttestationUtil.formatOsVersion(osVer)}")
            parts.add("Patch: ${KeyAttestationUtil.formatPatchLevel(osPatch)}")
            if (vendorPatch != null) parts.add("Vendor: ${KeyAttestationUtil.formatPatchLevel(vendorPatch)}")
            if (bootPatch != null) parts.add("Boot: ${KeyAttestationUtil.formatPatchLevel(bootPatch)}")

            it.status = CheckStatus.INFO
            it.description = parts.joinToString("\n")
        }
        emit("rollback_and_patch")

        // ===== 6. 证书吊销状态（Google 官方吊销列表） =====
        items.find { it.checkPoint == "cert_revocation_status" }?.let {
            val certs = primaryResult.certChain
            if (certs.isEmpty()) {
                it.status = CheckStatus.INFO
                it.description = "无证书链可供检查"
            } else {
                val result = KeyAttestationRevocationUtil.checkCertificateChain(certs)
                if (result.error != null) {
                    it.status = CheckStatus.INFO
                    it.description = "检查失败: ${result.error}"
                } else if (result.revoked) {
                    it.status = CheckStatus.FAIL
                    it.description = "发现已吊销证书\n" +
                            "Serial: ${result.serialNumber}\n" +
                            "原因: ${result.reason ?: "UNKNOWN"}\n" +
                            "证书链共 ${certs.size} 张"
                } else {
                    it.status = CheckStatus.PASS
                    it.description = "证书链未在 Google 吊销列表中（共检查 ${certs.size} 张）"
                }
            }
        }
        emit("cert_revocation_status")

        // ===== 7-8. Tricky Store 时序检测 =====
        val teeTimingResult = checkTrickyStoreTiming(useStrongBox = false)
        items.find { it.checkPoint == "tricky_store_timing_tee" }?.let {
            it.status = teeTimingResult.status
            it.description = teeTimingResult.description
        }
        emit("tricky_store_timing_tee")

        if (hasStrongBox) {
            val sbTimingResult = checkTrickyStoreTiming(useStrongBox = true)
            items.find { it.checkPoint == "tricky_store_timing_sb" }?.let {
                it.status = sbTimingResult.status
                it.description = sbTimingResult.description
            }
            emit("tricky_store_timing_sb")
        } else {
            items.find { it.checkPoint == "tricky_store_timing_sb" }?.let {
                it.status = CheckStatus.INFO
                it.description = "设备不支持 StrongBox"
            }
            emit("tricky_store_timing_sb")
        }

        return items
    }

    // ==================== Bootloader 交叉验证辅助方法 ====================

    /**
     * 读取多个与 Bootloader 锁定相关的系统属性
     */
    private fun checkBootloaderProps(): Map<String, String> {
        val props = listOf(
            "ro.boot.verifiedbootstate",
            "ro.boot.vbmeta.device_state",
            "ro.boot.vbmeta.digest",
            "ro.boot.flash.locked",
            "ro.meizu.bl_unlock",
            "persist.fastboot.unlock",
            "persist.sys.oem_unlock_allowed",
            "persist.sys.unlock.enable",
            "ro.secureboot.devicelock",
            "ro.secureboot.lockstate",
            "ro.boot.secureboot.lockstate",
            "vendor.boot.verifiedbootstate",
            "ro.boot.selinux",
            "ro.build.selinux"
        )
        val result = LinkedHashMap<String, String>()
        props.forEach {
            result[it] = SystemPropertyUtil.getSystemProperty(it)
        }
        return result
    }

    /**
     * 从系统属性推断 Bootloader 锁定状态
     * @return true=锁定, false=解锁, null=无法推断
     */
    private fun inferLockedFromProps(props: Map<String, String>): Boolean? {
        // 明确的锁定指标
        val lockedIndicators = listOf(
            "ro.boot.flash.locked" to "1",
            "ro.boot.vbmeta.device_state" to "locked",
            "persist.fastboot.unlock" to "0",
            "ro.secureboot.devicelock" to "1",
            "ro.secureboot.lockstate" to "locked",
            "ro.boot.secureboot.lockstate" to "locked",
            "persist.sys.oem_unlock_allowed" to "0",
            "persist.sys.unlock.enable" to "0",
            "ro.meizu.bl_unlock" to "0"
        )

        // 明确的解锁指标
        val unlockedIndicators = listOf(
            "ro.boot.flash.locked" to "0",
            "ro.boot.vbmeta.device_state" to "unlocked",
            "persist.fastboot.unlock" to "1",
            "ro.secureboot.devicelock" to "0",
            "ro.secureboot.lockstate" to "unlocked",
            "ro.boot.secureboot.lockstate" to "unlocked",
            "persist.sys.oem_unlock_allowed" to "1",
            "persist.sys.unlock.enable" to "1",
            "ro.meizu.bl_unlock" to "1",
            "ro.boot.verifiedbootstate" to "orange"
        )

        var lockedVotes = 0
        var unlockedVotes = 0

        lockedIndicators.forEach { (key, expected) ->
            if (props[key] == expected) lockedVotes++
        }
        unlockedIndicators.forEach { (key, expected) ->
            if (props[key] == expected) unlockedVotes++
        }

        return when {
            unlockedVotes > lockedVotes -> false
            lockedVotes > unlockedVotes -> true
            lockedVotes == 0 && unlockedVotes == 0 -> null
            else -> null // 平局，无法确定
        }
    }

    // ==================== Tricky Store 时序检测 ====================

    /**
     * Tricky Store 时序侧信道检测
     *
     * 原理：真实 TEE/StrongBox 处于独立运行环境，密码学操作耗时稳定、方差小，
     * 不受主系统 CPU 负载影响；软件模拟（Tricky Store）运行在 REE 中，
     * 耗时会随 CPU 调度产生明显抖动，在 CPU 负载下方差显著增大。
     *
     * 检测流程：
     * 1. 生成 EC P-256 硬件密钥对
     * 2. 空闲状态下连续签名 30 次，收集耗时样本
     * 3. 启动 CPU 负载线程，压力状态下再签名 30 次
     * 4. 计算统计特征并对比抖动差异
     */
    private fun checkTrickyStoreTiming(useStrongBox: Boolean): CheckResult {
        return try {
            val result = TrickyStoreUtil.nativeCheckTimingAttestation(useStrongBox)
            Log.i(TAG, "TrickyStore timing (StrongBox=$useStrongBox): $result")

            if (result.startsWith("error=")) {
                val err = result.substringAfter("error=")
                return when (err) {
                    "unsupported_arch" -> CheckResult(CheckStatus.INFO, "仅支持 ARM64 设备")
                    "keygen_failed" -> CheckResult(CheckStatus.INFO, "密钥生成失败（可能设备不支持硬件认证）")
                    else -> CheckResult(CheckStatus.INFO, "检测失败: $err")
                }
            }

            val suspicious = parseIntValue(result, "suspicious") ?: 0
            val genNs = parseLongValue(result, "gen_ns")
            val idleMean = parseLongValue(result, "idle_mean")
            val idleMedian = parseLongValue(result, "idle_median")
            val idleStd = parseLongValue(result, "idle_std")
            val idleMin = parseLongValue(result, "idle_min")
            val idleMax = parseLongValue(result, "idle_max")
            val loadMean = parseLongValue(result, "load_mean")
            val loadMedian = parseLongValue(result, "load_median")
            val loadStd = parseLongValue(result, "load_std")
            val loadMin = parseLongValue(result, "load_min")
            val loadMax = parseLongValue(result, "load_max")
            val idleCv = parseLongValue(result, "idle_cv")
            val loadCv = parseLongValue(result, "load_cv")
            val jitterRatio = parseLongValue(result, "jitter_ratio")
            val meanDiff = parseLongValue(result, "mean_diff")
            val spreadRatio = parseLongValue(result, "spread_ratio")
            val medianMeanRatio = parseLongValue(result, "median_mean_ratio")
            val genSignRatio = parseLongValue(result, "gen_sign_ratio")
            val negativeDrift = parseLongValue(result, "negative_drift")
            val bcMean = parseLongValue(result, "bc_mean")
            val bcStd = parseLongValue(result, "bc_std")
            val bcCv = parseLongValue(result, "bc_cv")
            val ksBcRatio = parseLongValue(result, "ks_bc_ratio")
            val cvDiff = parseLongValue(result, "cv_diff")

            val sbLabel = if (useStrongBox) "StrongBox" else "TEE"

            Log.i(TAG, "[TrickyStore-$sbLabel] parsed: suspicious=$suspicious" +
                " genNs=$genNs idleMean=$idleMean idleMedian=$idleMedian idleStd=$idleStd" +
                " idleMin=$idleMin idleMax=$idleMax idleCv=$idleCv" +
                " loadMean=$loadMean loadMedian=$loadMedian loadStd=$loadStd" +
                " loadMin=$loadMin loadMax=$loadMax loadCv=$loadCv" +
                " jitterRatio=$jitterRatio meanDiff=$meanDiff spreadRatio=$spreadRatio" +
                " medianMeanRatio=$medianMeanRatio genSignRatio=$genSignRatio negativeDrift=$negativeDrift" +
                " bcMean=$bcMean bcStd=$bcStd bcCv=$bcCv ksBcRatio=${ksBcRatio?.let { it / 1000.0 }} cvDiff=$cvDiff")

            when {
                suspicious >= 6 -> {
                    CheckResult(
                        CheckStatus.FAIL,
                        "[$sbLabel] 检测到高度可疑的软件模拟特征 (score=$suspicious):\n" +
                        "- 空闲均值: ${idleMean}ns, 标准差: ${idleStd}ns, CV: ${idleCv}%\n" +
                        "- 负载均值: ${loadMean}ns, 标准差: ${loadStd}ns, CV: ${loadCv}%\n" +
                        "- 抖动比: ${jitterRatio}%, 离散比: ${spreadRatio}%\n" +
                        "- 均值差: ${meanDiff}ns, 负漂移: ${negativeDrift}ns\n" +
                        "- 中位均值比: ${medianMeanRatio}%, 生成签名比: ${genSignRatio}%\n" +
                        "- BC 软件签名均值: ${bcMean}ns, BC-CV: ${bcCv}%\n" +
                        "- KeyStore/BC 比例: ${ksBcRatio?.let { it / 1000.0 }}\n" +
                        "- CV 差值 (idle-load): ${cvDiff}%\n" +
                        "- 密钥生成耗时: ${genNs}ns\n" +
                        "结论: Tricky Store 等 Keybox 伪装工具可能性极高"
                    )
                }
                suspicious >= 3 -> {
                    CheckResult(
                        CheckStatus.FAIL,
                        "[$sbLabel] 存在明显时序异常 (score=$suspicious), 疑似软件模拟:\n" +
                        "- 空闲均值: ${idleMean}ns, 标准差: ${idleStd}ns, CV: ${idleCv}%\n" +
                        "- 负载均值: ${loadMean}ns, 标准差: ${loadStd}ns, CV: ${loadCv}%\n" +
                        "- 抖动比: ${jitterRatio}%, 离散比: ${spreadRatio}%\n" +
                        "- 负漂移: ${negativeDrift}ns, 生成签名比: ${genSignRatio}%\n" +
                        "- BC 软件签名均值: ${bcMean}ns, KeyStore/BC 比例: ${ksBcRatio?.let { it / 1000.0 }}\n" +
                        "- CV 差值 (idle-load): ${cvDiff}%\n" +
                        "- 密钥生成耗时: ${genNs}ns\n" +
                        "结论: 建议结合其他检测项综合判断"
                    )
                }
                suspicious >= 1 -> {
                    CheckResult(
                        CheckStatus.INFO,
                        "[$sbLabel] 存在轻微时序异常 (score=$suspicious):\n" +
                        "- 空闲均值: ${idleMean}ns, 标准差: ${idleStd}ns, CV: ${idleCv}%\n" +
                        "- 负载均值: ${loadMean}ns, 标准差: ${loadStd}ns, CV: ${loadCv}%\n" +
                        "- 抖动比: ${jitterRatio}%, 离散比: ${spreadRatio}%\n" +
                        "- 负漂移: ${negativeDrift}ns, 生成签名比: ${genSignRatio}%\n" +
                        "- BC 软件签名均值: ${bcMean}ns, KeyStore/BC 比例: ${ksBcRatio?.let { it / 1000.0 }}\n" +
                        "- CV 差值 (idle-load): ${cvDiff}%\n" +
                        "- 密钥生成耗时: ${genNs}ns\n" +
                        "结论: 时序特征基本正常，但存在个别异常指标"
                    )
                }
                else -> {
                    CheckResult(
                        CheckStatus.PASS,
                        "[$sbLabel] 时序特征符合硬件执行:\n" +
                        "- 空闲均值: ${idleMean}ns, 标准差: ${idleStd}ns, CV: ${idleCv}%\n" +
                        "- 负载均值: ${loadMean}ns, 标准差: ${loadStd}ns, CV: ${loadCv}%\n" +
                        "- 抖动比: ${jitterRatio}%, 离散比: ${spreadRatio}%\n" +
                        "- 负漂移: ${negativeDrift}ns, 生成签名比: ${genSignRatio}%\n" +
                        "- BC 软件签名均值: ${bcMean}ns, KeyStore/BC 比例: ${ksBcRatio?.let { it / 1000.0 }}\n" +
                        "- CV 差值 (idle-load): ${cvDiff}%\n" +
                        "- 密钥生成耗时: ${genNs}ns\n" +
                        "结论: 未检测到 Tricky Store 伪装迹象"
                    )
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "checkTrickyStoreTiming 出错: ${e.message}", e)
            CheckResult(CheckStatus.INFO, "检测异常: ${e.message}")
        }
    }

    // ==================== 工具函数 ====================

    /**
     * 从 "key=value|key2=value2" 格式字符串中解析 int 值
     */
    private fun parseIntValue(result: String, key: String): Int? {
        val pattern = "$key=(-?\\d+)".toRegex()
        val match = pattern.find(result)
        return match?.groupValues?.get(1)?.toIntOrNull()
    }

    /**
     * 从 "key=value|key2=value2" 格式字符串中解析 long 值
     */
    private fun parseLongValue(result: String, key: String): Long? {
        val pattern = "$key=(-?\\d+)".toRegex()
        val match = pattern.find(result)
        return match?.groupValues?.get(1)?.toLongOrNull()
    }
}

package qpdb.env.check.checkers

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.util.Log
import java.security.cert.X509Certificate
import qpdb.env.check.model.CheckItem
import qpdb.env.check.model.CheckResult
import qpdb.env.check.model.CheckStatus
import qpdb.env.check.model.Checkable
import qpdb.env.check.attestation.Attestation
import qpdb.env.check.attestation.RootOfTrust
import qpdb.env.check.utils.KeyAttestationUtil
import qpdb.env.check.utils.KeyAttestationRevocationUtil
import qpdb.env.check.utils.KeyAttestationRootChecker
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
 * 7. 证书来源真实性 - 根证书公钥是否匹配 Google/AOSP/Knox 已知根
 * 8. 证书硬件绑定一致性 - 证书中的 brand/device/model 与当前设备是否一致
 * 9. 证书链完整性 - 父证书公钥验证子证书签名 + 有效期检查
 * 10. Tricky Store 时序检测 (TEE)
 * 11. Tricky Store 时序检测 (StrongBox)
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
                name = "证书来源真实性",
                checkPoint = "cert_root_authenticity",
                description = "等待检测..."
            ),
            CheckItem(
                name = "证书硬件绑定一致性",
                checkPoint = "cert_hardware_binding",
                description = "等待检测..."
            ),
            CheckItem(
                name = "证书链完整性",
                checkPoint = "cert_chain_integrity",
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
                "cert_revocation_status",
                "cert_root_authenticity",
                "cert_hardware_binding",
                "cert_chain_integrity"
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

        // ===== 7. 证书来源真实性（根公钥比对） =====
        items.find { it.checkPoint == "cert_root_authenticity" }?.let {
            val certs = primaryResult.certChain
            it.status = CheckStatus.INFO
            if (certs.isEmpty()) {
                it.description = "无证书链可供检查"
            } else {
                val result = KeyAttestationRootChecker.checkRootCertificate(certs)
                val sourceName = when (result.status) {
                    KeyAttestationRootChecker.RootStatus.GOOGLE -> "Google 官方"
                    KeyAttestationRootChecker.RootStatus.AOSP -> "AOSP 默认"
                    KeyAttestationRootChecker.RootStatus.KNOX -> "Samsung Knox"
                    KeyAttestationRootChecker.RootStatus.OEM -> "OEM 厂商"
                    KeyAttestationRootChecker.RootStatus.UNKNOWN -> "未知"
                }
                val builder = StringBuilder()
                builder.append("根证书来源: $sourceName\n")
                builder.append("Subject: ${result.rootSubject ?: "N/A"}\n")
                builder.append("\n说明:\n")
                builder.append(when (result.status) {
                    KeyAttestationRootChecker.RootStatus.GOOGLE -> "该根证书属于 Google 官方硬件认证根证书，通常用于 Pixel 及通过 GMS 认证的设备。"
                    KeyAttestationRootChecker.RootStatus.AOSP -> "该根证书为 AOSP 默认证书，常见于模拟器、未 provision 或自定义 ROM 设备。"
                    KeyAttestationRootChecker.RootStatus.KNOX -> "该根证书属于 Samsung Knox 认证体系，用于三星设备的企业安全认证。"
                    KeyAttestationRootChecker.RootStatus.OEM -> "该根证书为 OEM 厂商自定义证书，部分厂商会使用自己的根证书替代 Google 根证书。"
                    KeyAttestationRootChecker.RootStatus.UNKNOWN -> "该根证书不在已知公钥列表中，可能为自签名、伪造或 Tricky Store 等工具注入的证书。"
                })
                builder.append("\n\n证书链深度: ${certs.size} 张")
                it.description = builder.toString()
            }
        }
        emit("cert_root_authenticity")

        // ===== 8. 证书硬件绑定一致性 =====
        items.find { it.checkPoint == "cert_hardware_binding" }?.let {
            val auth = attestation.teeEnforced
            val swAuth = attestation.softwareEnforced

            // 收集证书中的硬件信息（优先 TEE，其次 Software）
            val certBrand = auth.brand ?: swAuth.brand
            val certDevice = auth.device ?: swAuth.device
            val certProduct = auth.product ?: swAuth.product
            val certManufacturer = auth.manufacturer ?: swAuth.manufacturer
            val certModel = auth.model ?: swAuth.model
            val certSerial = auth.serialNumber ?: swAuth.serialNumber
            val certImei = auth.imei ?: swAuth.imei
            val certMeid = auth.meid ?: swAuth.meid

            val hasAnyId = certBrand != null || certDevice != null || certProduct != null ||
                    certManufacturer != null || certModel != null || certSerial != null ||
                    certImei != null || certMeid != null

            if (!hasAnyId) {
                it.status = CheckStatus.INFO
                it.description = "证书中未包含硬件绑定信息（Attestation ID）\n" +
                        "可能原因：旧版 Keymaster、未启用设备标识符绑定、或 AOSP 模拟器证书"
            } else {
                val mismatches = mutableListOf<String>()

                // 交叉比对
                certBrand?.let { cb ->
                    if (!cb.equals(android.os.Build.BRAND, ignoreCase = true)) {
                        mismatches.add("Brand: 证书='$cb' vs 设备='${android.os.Build.BRAND}'")
                    }
                }
                certDevice?.let { cd ->
                    if (!cd.equals(android.os.Build.DEVICE, ignoreCase = true)) {
                        mismatches.add("Device: 证书='$cd' vs 设备='${android.os.Build.DEVICE}'")
                    }
                }
                certProduct?.let { cp ->
                    if (!cp.equals(android.os.Build.PRODUCT, ignoreCase = true)) {
                        mismatches.add("Product: 证书='$cp' vs 设备='${android.os.Build.PRODUCT}'")
                    }
                }
                certManufacturer?.let { cm ->
                    if (!cm.equals(android.os.Build.MANUFACTURER, ignoreCase = true)) {
                        mismatches.add("Manufacturer: 证书='$cm' vs 设备='${android.os.Build.MANUFACTURER}'")
                    }
                }
                certModel?.let { cmo ->
                    if (!cmo.equals(android.os.Build.MODEL, ignoreCase = true)) {
                        mismatches.add("Model: 证书='$cmo' vs 设备='${android.os.Build.MODEL}'")
                    }
                }

                val desc = StringBuilder()
                desc.append("=== 证书中的硬件信息 ===\n")
                certBrand?.let { desc.append("Brand: $it\n") }
                certDevice?.let { desc.append("Device: $it\n") }
                certProduct?.let { desc.append("Product: $it\n") }
                certManufacturer?.let { desc.append("Manufacturer: $it\n") }
                certModel?.let { desc.append("Model: $it\n") }
                certSerial?.let { desc.append("Serial: $it\n") }
                certImei?.let { desc.append("IMEI: $it\n") }
                certMeid?.let { desc.append("MEID: $it\n") }

                desc.append("\n=== 当前设备信息 ===\n")
                desc.append("Brand: ${android.os.Build.BRAND}\n")
                desc.append("Device: ${android.os.Build.DEVICE}\n")
                desc.append("Product: ${android.os.Build.PRODUCT}\n")
                desc.append("Manufacturer: ${android.os.Build.MANUFACTURER}\n")
                desc.append("Model: ${android.os.Build.MODEL}")

                if (mismatches.isNotEmpty()) {
                    it.status = CheckStatus.FAIL
                    desc.append("\n\n=== 不一致项 ===\n")
                    mismatches.forEach { m -> desc.append("❌ $m\n") }
                    desc.append("\n结论: 证书硬件绑定信息与当前设备不匹配，疑似异地 keybox/Tricky Store 注入")
                } else {
                    it.status = CheckStatus.PASS
                    desc.append("\n\n结论: 证书硬件绑定信息与当前设备一致")
                }
                it.description = desc.toString().trim()
            }
        }
        emit("cert_hardware_binding")

        // ===== 9. 证书链完整性（签名验证 + 有效期） =====
        items.find { it.checkPoint == "cert_chain_integrity" }?.let {
            val certs = primaryResult.certChain
            if (certs.isEmpty()) {
                it.status = CheckStatus.INFO
                it.description = "无证书链可供验证"
            } else {
                val (valid, desc) = verifyCertificateChain(certs)
                it.status = if (valid) CheckStatus.PASS else CheckStatus.FAIL
                it.description = desc
            }
        }
        emit("cert_chain_integrity")

        // ===== 10-11. Tricky Store 时序检测 =====
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

    // ==================== 证书链完整性验证 ====================

    /**
     * 验证证书链的完整性和有效性
     *
     * 参考 KeyAttestation (vvb2060) 的 CertificateInfo.checkStatus 实现：
     * 1. 用父证书公钥验证每个子证书的签名（从根到叶子）
     * 2. 检查每张证书是否在有效期内
     *
     * @param certs 证书链（叶子证书在前，根证书在后）
     * @return Pair<是否全部通过, 详细描述>
     */
    private fun verifyCertificateChain(certs: List<X509Certificate>): Pair<Boolean, String> {
        if (certs.isEmpty()) {
            return false to "证书链为空"
        }
        if (certs.size < 2) {
            return true to "证书链仅 ${certs.size} 张，无需链式验证"
        }

        val errors = mutableListOf<String>()
        val details = mutableListOf<String>()

        // 从根证书开始，往前遍历到叶子证书
        // 参考 CertificateInfo.parse(): parent 初始为根证书，逐步更新
        var parent = certs.last()

        for (i in certs.size - 1 downTo 0) {
            val cert = certs[i]
            val subject = cert.subjectX500Principal.name
            val issuer = cert.issuerX500Principal.name

            // 1. 签名验证：用父证书公钥验证当前证书签名
            try {
                cert.verify(parent.publicKey)
                details.add("[证书 $i] 签名验证通过 ($subject)")
            } catch (e: Exception) {
                errors.add("[证书 $i] 签名验证失败: ${e.message} ($subject)")
            }

            // 2. 有效期验证
            try {
                cert.checkValidity()
                details.add("[证书 $i] 有效期正常 (NotBefore=${cert.notBefore}, NotAfter=${cert.notAfter})")
            } catch (e: Exception) {
                errors.add("[证书 $i] 有效期异常: ${e.message} (NotBefore=${cert.notBefore}, NotAfter=${cert.notAfter})")
            }

            // 3. 根证书额外检查：Issuer 是否等于 Subject（自签名）
            if (i == certs.size - 1) {
                if (subject != issuer) {
                    errors.add("[根证书] 非自签名证书: Subject='$subject' != Issuer='$issuer'")
                } else {
                    details.add("[根证书] 自签名验证通过")
                }
            }

            // 更新 parent 为当前证书，用于验证下一个（更靠近叶子的）证书
            if (i > 0) {
                parent = cert
            }
        }

        val desc = StringBuilder()
        desc.append("证书链深度: ${certs.size} 张\n\n")
        if (details.isNotEmpty()) {
            desc.append("=== 通过项 ===\n")
            details.forEach { desc.append("✅ $it\n") }
        }
        if (errors.isNotEmpty()) {
            desc.append("\n=== 异常项 ===\n")
            errors.forEach { desc.append("❌ $it\n") }
            desc.append("\n结论: 证书链完整性验证失败，存在伪造或篡改风险")
            return false to desc.toString().trim()
        }

        desc.append("\n结论: 证书链完整，所有签名和有效期均正常")
        return true to desc.toString().trim()
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
    /**
     * Tricky Store 时序侧信道检测（多轮波动分析版）
     *
     * 核心思路：真实 TEE/StrongBox 的时序特征在多轮检测中是稳定的；
     * 而 TEESimulator 等工具由于存在拦截/注入层，每轮执行路径不同，
     * 轮间波动显著更大。通过分析多轮结果的稳定性来提高检测概率。
     */
    private fun checkTrickyStoreTiming(useStrongBox: Boolean): CheckResult {
        return try {
            val rounds = 3
            val results = mutableListOf<String>()
            val sbLabel = if (useStrongBox) "StrongBox" else "TEE"

            repeat(rounds) { round ->
                val result = TrickyStoreUtil.nativeCheckTimingAttestation(useStrongBox)
                Log.i(TAG, "TrickyStore timing round ${round + 1}/$rounds (StrongBox=$useStrongBox): $result")
                results.add(result)

                // 轮间间隔 300ms，让系统状态恢复
                if (round < rounds - 1) {
                    Thread.sleep(300)
                }
            }

            // 解析每轮数据
            data class RoundData(
                val suspicious: Int, val genNs: Long, val idleMean: Long, val idleStd: Long,
                val idleCv: Long, val loadMean: Long, val loadStd: Long, val loadCv: Long,
                val jitterRatio: Long, val meanDiff: Long, val spreadRatio: Long,
                val genSignRatio: Long, val negativeDrift: Long, val bcMean: Long,
                val bcCv: Long, val ksBcRatio: Long, val cvDiff: Long, val loadCvIdleMult: Long
            )

            val roundData = results.map { r ->
                if (r.startsWith("error=")) {
                    return CheckResult(CheckStatus.INFO, "第 ${results.indexOf(r) + 1} 轮检测失败: ${r.substringAfter("error=")}")
                }
                RoundData(
                    suspicious = parseIntValue(r, "suspicious") ?: 0,
                    genNs = parseLongValue(r, "gen_ns") ?: 0,
                    idleMean = parseLongValue(r, "idle_mean") ?: 0,
                    idleStd = parseLongValue(r, "idle_std") ?: 0,
                    idleCv = parseLongValue(r, "idle_cv") ?: 0,
                    loadMean = parseLongValue(r, "load_mean") ?: 0,
                    loadStd = parseLongValue(r, "load_std") ?: 0,
                    loadCv = parseLongValue(r, "load_cv") ?: 0,
                    jitterRatio = parseLongValue(r, "jitter_ratio") ?: 0,
                    meanDiff = parseLongValue(r, "mean_diff") ?: 0,
                    spreadRatio = parseLongValue(r, "spread_ratio") ?: 0,
                    genSignRatio = parseLongValue(r, "gen_sign_ratio") ?: 0,
                    negativeDrift = parseLongValue(r, "negative_drift") ?: 0,
                    bcMean = parseLongValue(r, "bc_mean") ?: 0,
                    bcCv = parseLongValue(r, "bc_cv") ?: 0,
                    ksBcRatio = parseLongValue(r, "ks_bc_ratio") ?: 0,
                    cvDiff = parseLongValue(r, "cv_diff") ?: 0,
                    loadCvIdleMult = parseLongValue(r, "load_cv_idle_mult") ?: 0
                )
            }

            // ========== 单轮分数汇总 ==========
            val singleRoundSum = roundData.sumOf { it.suspicious }
            val highScoreRounds = roundData.count { it.suspicious >= 3 }

            // ========== 轮间波动分析 ==========
            val jitterRatios = roundData.map { it.jitterRatio }
            val idleMeans = roundData.map { it.idleMean }
            val meanDiffs = roundData.map { it.meanDiff }
            val loadCvs = roundData.map { it.loadCv }

            val jitterRange = jitterRatios.maxOrNull()!! - jitterRatios.minOrNull()!!
            val idleMeanCv = computeCv(idleMeans)
            val meanDiffLargeCount = meanDiffs.count { it > 2_000_000 }
            val loadCvRange = loadCvs.maxOrNull()!! - loadCvs.minOrNull()!!

            var interRoundSuspicious = 0
            val interRoundTriggers = mutableListOf<String>()

            // 指标 R1：jitter_ratio 轮间极差过大（> 150%）
            // 真实 TEE 每轮 jitter 稳定，TEESimulator 每轮差异大
            if (jitterRange > 150) {
                interRoundSuspicious += 2
                interRoundTriggers.add("jitter_range=${jitterRange}%")
            }

            // 指标 R2：idle_mean 轮间变异系数过大（> 25%）
            // 真实 TEE 签名速度稳定，TEESimulator 受系统状态影响大
            if (idleMeanCv > 25) {
                interRoundSuspicious += 2
                interRoundTriggers.add("idle_mean_cv=${idleMeanCv}%")
            }

            // 指标 R3：多轮 mean_diff 出现大值（>= 2 轮 > 2ms）
            // 真实 TEE 负载下均值几乎不变，TEESimulator 偶尔波动大
            if (meanDiffLargeCount >= 2) {
                interRoundSuspicious += 2
                interRoundTriggers.add("mean_diff_large=${meanDiffLargeCount}轮")
            }

            // 指标 R4：load_cv 轮间极差过大（> 20%）
            if (loadCvRange > 20) {
                interRoundSuspicious += 1
                interRoundTriggers.add("load_cv_range=${loadCvRange}%")
            }

            // 指标 R5：存在单轮高得分（>=3）
            if (highScoreRounds >= 1) {
                interRoundSuspicious += 1
                interRoundTriggers.add("high_score_rounds=${highScoreRounds}")
            }

            val totalSuspicious = singleRoundSum + interRoundSuspicious

            Log.i(TAG, "[TrickyStore-$sbLabel-Multi] singleSum=$singleRoundSum inter=$interRoundSuspicious total=$totalSuspicious " +
                "jitterRange=$jitterRange idleMeanCv=$idleMeanCv meanDiffLarge=$meanDiffLargeCount loadCvRange=$loadCvRange")

            // ========== 生成详细描述 ==========
            val desc = StringBuilder()
            desc.append("[$sbLabel] 多轮时序检测 (${rounds}轮):\n\n")

            desc.append("=== 单轮结果 ===\n")
            roundData.forEachIndexed { idx, d ->
                desc.append("轮次 ${idx + 1}: score=${d.suspicious}, jitter=${d.jitterRatio}%, idle_mean=${d.idleMean}ns, mean_diff=${d.meanDiff}ns\n")
            }
            desc.append("单轮总分: $singleRoundSum\n\n")

            desc.append("=== 轮间波动分析 ===\n")
            desc.append("jitter_ratio 极差: ${jitterRange}% (范围: ${jitterRatios.minOrNull()}% ~ ${jitterRatios.maxOrNull()}%)\n")
            desc.append("idle_mean 轮间CV: ${idleMeanCv}% (值: ${idleMeans.map { it / 1_000_000.0 }.joinToString(", ") { "%.1f".format(it) }} ms)\n")
            desc.append("mean_diff >=2ms 轮数: ${meanDiffLargeCount}/$rounds\n")
            desc.append("load_cv 极差: ${loadCvRange}%\n")
            desc.append("高得分轮数: ${highScoreRounds}/$rounds\n")
            if (interRoundTriggers.isNotEmpty()) {
                desc.append("触发项: ${interRoundTriggers.joinToString(", ")}\n")
            }
            desc.append("轮间得分: $interRoundSuspicious\n\n")

            desc.append("=== 综合指标 ===\n")
            val avgIdleMean = idleMeans.average().toLong()
            val avgLoadMean = roundData.map { it.loadMean }.average().toLong()
            val avgBcMean = roundData.map { it.bcMean }.average().toLong()
            val avgKsBcRatio = roundData.map { it.ksBcRatio }.average() / 1000.0
            desc.append("平均空闲均值: ${avgIdleMean}ns, 平均负载均值: ${avgLoadMean}ns\n")
            desc.append("平均 BC 软件签名: ${avgBcMean}ns\n")
            desc.append("平均 KeyStore/BC 比例: %.1f\n".format(avgKsBcRatio))
            desc.append("总得分: $totalSuspicious (单轮 $singleRoundSum + 轮间 $interRoundSuspicious)\n\n")

            // ========== 状态判定 ==========
            when {
                totalSuspicious >= 6 -> {
                    desc.append("结论: 检测到高度可疑的时序不稳定特征，TEESimulator/Tricky Store 等工具可能性极高")
                    CheckResult(CheckStatus.FAIL, desc.toString().trim())
                }
                totalSuspicious >= 3 -> {
                    desc.append("结论: 存在明显的时序不稳定特征，疑似存在拦截/注入层")
                    CheckResult(CheckStatus.FAIL, desc.toString().trim())
                }
                totalSuspicious >= 1 -> {
                    desc.append("结论: 存在轻微的时序异常或不稳定特征")
                    CheckResult(CheckStatus.INFO, desc.toString().trim())
                }
                else -> {
                    desc.append("结论: 多轮时序特征稳定，符合硬件执行环境")
                    CheckResult(CheckStatus.PASS, desc.toString().trim())
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

    /**
     * 计算一组数值的变异系数 (CV = std / mean * 100)
     */
    private fun computeCv(values: List<Long>): Long {
        if (values.isEmpty() || values.all { it == 0L }) return 0
        val mean = values.average()
        if (mean == 0.0) return 0
        val variance = values.map { (it - mean) * (it - mean) }.average()
        val std = kotlin.math.sqrt(variance)
        return ((std / mean) * 100).toLong()
    }
}

package qpdb.env.check.checkers

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import android.util.Log
import qpdb.env.check.EnvCheckApp
import qpdb.env.check.model.CheckItem
import qpdb.env.check.model.CheckResult
import qpdb.env.check.model.CheckStatus
import qpdb.env.check.model.Checkable
import qpdb.env.check.oem.OEMServiceProbe
import qpdb.env.check.utils.PropertyUtil
import java.io.BufferedReader
import java.io.InputStreamReader

/**
 * OEM 服务与应用一致性检测器
 *
 * 检测原理：不同品牌/型号的设备通常预装特定的系统服务和应用。
 * 如果设备声称是某品牌（如 Xiaomi、Samsung），但缺少该品牌标志性的系统服务或预装应用，
 * 则高度疑似模拟器、云手机、改机工具或 ROM 被篡改。
 *
 * 采用多维度交叉验证策略：
 * 1. 主动服务探针（调用 OEMServiceProbe 主动探测品牌标志性组件）
 * 2. 系统应用包检测（PackageManager + shell pm list 多源合并）
 * 3. 品牌标志性应用存在性检测
 * 4. 多源属性一致性校验（Build.BRAND vs ro.product.brand vs ro.product.manufacturer）
 * 5. 模拟器特征检测
 */
class OEMChecker : Checkable {

    companion object {
        private const val TAG = "OEMChecker"

        // ========== OEM 品牌特征库 ==========
        private val OEM_SIGNATURES = mapOf(
            "xiaomi" to OEMProfile(
                brandNames = listOf("xiaomi", "redmi", "poco", "mi"),
                expectedPackages = listOf(
                    "com.miui.home",
                    "com.android.settings",
                    "com.miui.securitycenter",
                    "com.xiaomi.market",
                    "com.xiaomi.payment",
                    "com.miui.cloudservice",
                    "com.miui.msa.global",
                ),
                propertyHints = listOf(
                    "ro.miui.ui.version",
                    "ro.product.mod_device",
                )
            ),
            "samsung" to OEMProfile(
                brandNames = listOf("samsung"),
                expectedPackages = listOf(
                    "com.samsung.android.launcher",
                    "com.sec.android.app.launcher",
                    "com.samsung.android.app.settings.bixby",
                    "com.samsung.android.knox.containeragent",
                    "com.sec.android.app.samsungapps",
                    "com.samsung.android.messaging",
                    "com.samsung.android.dialer",
                ),
                propertyHints = listOf(
                    "ro.build.changelist",
                    "ro.build.PDA",
                )
            ),
            "oppo" to OEMProfile(
                brandNames = listOf("oppo", "realme", "oneplus"),
                expectedPackages = listOf(
                    "com.coloros.launcher",
                    "com.oppo.launcher",
                    "com.coloros.safecenter",
                    "com.heytap.market",
                    "com.coloros.ocrscanner",
                    "com.oplus.games",
                ),
                propertyHints = listOf(
                    "ro.build.version.opporom",
                    "ro.build.version.realmeui",
                    "ro.build.version.ota",
                )
            ),
            "vivo" to OEMProfile(
                brandNames = listOf("vivo", "iqoo"),
                expectedPackages = listOf(
                    "com.vivo.launcher",
                    "com.bbk.launcher2",
                    "com.vivo.game",
                    "com.bbk.appstore",
                    "com.vivo.dream.clock",
                    "com.iqoo.daemon",
                ),
                propertyHints = listOf(
                    "ro.vivo.os.version",
                    "ro.vivo.os.build.display.id",
                    "ro.product.model.bbk",
                )
            ),
            "huawei" to OEMProfile(
                brandNames = listOf("huawei", "honor"),
                expectedPackages = listOf(
                    "com.huawei.android.launcher",
                    "com.hihonor.android.launcher",
                    "com.huawei.systemmanager",
                    "com.huawei.appmarket",
                    "com.huawei.health",
                    "com.hihonor.id",
                ),
                propertyHints = listOf(
                    "ro.build.version.emui",
                    "ro.build.version.magic",
                    "ro.product.hardwareversion",
                )
            ),
            "google" to OEMProfile(
                brandNames = listOf("google"),
                expectedPackages = listOf(
                    "com.google.android.apps.nexuslauncher",
                    "com.google.android.apps.wallpaper",
                    "com.google.android.dialer",
                    "com.google.android.apps.messaging",
                    "com.google.android.apps.photos",
                ),
                propertyHints = listOf(
                    "ro.com.google.clientidbase",
                )
            ),
            "motorola" to OEMProfile(
                brandNames = listOf("motorola", "moto"),
                expectedPackages = listOf(
                    "com.motorola.launcher3",
                    "com.motorola.moto",
                    "com.motorola.camera2",
                    "com.motorola.actions",
                ),
                propertyHints = listOf(
                    "ro.mot.build.customerid",
                    "ro.mot.product",
                )
            ),
            "sony" to OEMProfile(
                brandNames = listOf("sony"),
                expectedPackages = listOf(
                    "com.sonyericsson.home",
                    "com.sonymobile.launcher",
                    "com.sonyericsson.android.socialphonebook",
                ),
                propertyHints = listOf(
                    "ro.semc.version",
                    "ro.somc.customerid",
                )
            ),
            "asus" to OEMProfile(
                brandNames = listOf("asus"),
                expectedPackages = listOf(
                    "com.asus.launcher",
                    "com.asus.mobilemanager",
                ),
                propertyHints = listOf(
                    "ro.build.asus.sku",
                    "ro.build.asus.version",
                )
            ),
            "lenovo" to OEMProfile(
                brandNames = listOf("lenovo", "zuk"),
                expectedPackages = listOf(
                    "com.lenovo.launcher",
                    "com.zui.launcher",
                ),
                propertyHints = listOf(
                    "ro.lenovo.series",
                )
            ),
            "meizu" to OEMProfile(
                brandNames = listOf("meizu"),
                expectedPackages = listOf(
                    "com.meizu.flyme.launcher",
                    "com.meizu.cloud",
                ),
                propertyHints = listOf(
                    "ro.build.flyme.version",
                )
            ),
        )
    }

    override val categoryName: String = "OEM 一致性检测"

    override fun checkList(): List<CheckItem> = listOf(
        CheckItem(name = "品牌属性一致性", checkPoint = "oem_brand_consistency", description = "等待检测..."),
        CheckItem(name = "主动服务探针", checkPoint = "oem_service_probe", description = "等待检测..."),
        CheckItem(name = "系统应用包检测", checkPoint = "oem_system_packages", description = "等待检测..."),
        CheckItem(name = "OEM 属性存在性", checkPoint = "oem_property_hints", description = "等待检测..."),
        CheckItem(name = "模拟器特征检测", checkPoint = "oem_emulator_hints", description = "等待检测..."),
        CheckItem(name = "综合评估", checkPoint = "oem_summary", description = "等待检测...")
    )

    override fun runCheck(): List<CheckItem> {
        Log.i(TAG, "runCheck() 开始执行 OEM 一致性检测")
        val items = checkList().toMutableList()

        fun applyResult(checkPoint: String, result: CheckResult) {
            items.find { it.checkPoint == checkPoint }?.let {
                it.status = result.status
                it.description = result.description
            }
            Log.i(TAG, "[$checkPoint] ${result.status}: ${result.description}")
        }

        try {
            val context = EnvCheckApp.getContext()
            val brand = detectBrand()
            Log.i(TAG, "检测到的品牌: $brand")

            // 1. 品牌属性一致性检测
            val brandResult = checkBrandConsistency(brand)
            applyResult("oem_brand_consistency", brandResult)

            // 2. 主动服务探针
            val probeResult = checkServiceProbes(context, brand)
            applyResult("oem_service_probe", probeResult)

            // 3. 系统应用包检测
            val packagesResult = checkSystemPackages(context, brand)
            applyResult("oem_system_packages", packagesResult)

            // 4. OEM 属性存在性
            val propsResult = checkOEMProperties(brand)
            applyResult("oem_property_hints", propsResult)

            // 5. 模拟器特征检测
            val emuResult = checkEmulatorHints(context, brand)
            applyResult("oem_emulator_hints", emuResult)

            // 6. 综合评估
            applyResult("oem_summary", evaluateSummary(items, brand))

        } catch (e: Exception) {
            Log.e(TAG, "检测过程异常", e)
            applyResult("oem_brand_consistency", CheckResult(CheckStatus.INFO, "检测异常: ${e.message}"))
            applyResult("oem_service_probe", CheckResult(CheckStatus.INFO, "检测异常: ${e.message}"))
            applyResult("oem_system_packages", CheckResult(CheckStatus.INFO, "检测异常: ${e.message}"))
            applyResult("oem_property_hints", CheckResult(CheckStatus.INFO, "检测异常: ${e.message}"))
            applyResult("oem_emulator_hints", CheckResult(CheckStatus.INFO, "检测异常: ${e.message}"))
            applyResult("oem_summary", CheckResult(CheckStatus.INFO, "检测失败: ${e.message}"))
        }

        return items
    }

    // ==================== 品牌识别 ====================

    private fun detectBrand(): String {
        val candidates = mutableListOf<String>()
        candidates.add(Build.BRAND.lowercase())
        candidates.add(Build.MANUFACTURER.lowercase())
        candidates.add(getProp("ro.product.brand").lowercase())
        candidates.add(getProp("ro.product.manufacturer").lowercase())
        candidates.add(getProp("ro.product.vendor.brand").lowercase())
        candidates.add(getProp("ro.product.vendor.manufacturer").lowercase())

        val voteMap = mutableMapOf<String, Int>()
        for (c in candidates) {
            if (c.isBlank() || c == "unknown") continue
            voteMap[c] = (voteMap[c] ?: 0) + 1
        }

        return if (voteMap.isNotEmpty()) {
            voteMap.maxByOrNull { it.value }!!.key
        } else {
            Build.BRAND.lowercase()
        }
    }

    // ==================== 检测项 1: 品牌属性一致性 ====================

    private fun checkBrandConsistency(brand: String): CheckResult {
        val brandFromBuild = Build.BRAND.lowercase()
        val manufacturerFromBuild = Build.MANUFACTURER.lowercase()
        val brandFromProp = getProp("ro.product.brand").lowercase()
        val manufacturerFromProp = getProp("ro.product.manufacturer").lowercase()
        val vendorBrand = getProp("ro.product.vendor.brand").lowercase()
        val vendorManufacturer = getProp("ro.product.vendor.manufacturer").lowercase()

        val inconsistencies = mutableListOf<String>()

        if (brandFromBuild.isNotBlank() && brandFromProp.isNotBlank()
            && brandFromBuild != brandFromProp
        ) {
            inconsistencies.add("Build.BRAND($brandFromBuild) ≠ ro.product.brand($brandFromProp)")
        }

        if (manufacturerFromBuild.isNotBlank() && manufacturerFromProp.isNotBlank()
            && manufacturerFromBuild != manufacturerFromProp
        ) {
            inconsistencies.add("Build.MANUFACTURER($manufacturerFromBuild) ≠ ro.product.manufacturer($manufacturerFromProp)")
        }

        if (brandFromBuild.isNotBlank() && manufacturerFromBuild.isNotBlank()
            && brandFromBuild != manufacturerFromBuild
            && !areRelatedBrands(brandFromBuild, manufacturerFromBuild)
        ) {
            inconsistencies.add("BRAND($brandFromBuild) 与 MANUFACTURER($manufacturerFromBuild) 不相关")
        }

        if (vendorBrand.isNotBlank() && brandFromBuild.isNotBlank()
            && vendorBrand != brandFromBuild
            && !areRelatedBrands(vendorBrand, brandFromBuild)
        ) {
            inconsistencies.add("vendor.brand($vendorBrand) ≠ Build.BRAND($brandFromBuild)")
        }

        val matchedOEM = findMatchedOEM(brand)
        val isGeneric = brandFromBuild == "generic" || brandFromBuild == "google"
                || manufacturerFromBuild == "unknown"

        return when {
            inconsistencies.isNotEmpty() -> {
                CheckResult(
                    CheckStatus.FAIL,
                    "品牌属性不一致 (${inconsistencies.size}处): ${inconsistencies.joinToString("; ")}"
                )
            }
            isGeneric -> {
                CheckResult(
                    CheckStatus.FAIL,
                    "品牌属性为通用值: BRAND=$brandFromBuild, MANUFACTURER=$manufacturerFromBuild"
                )
            }
            matchedOEM == null -> {
                CheckResult(
                    CheckStatus.INFO,
                    "品牌 '$brand' 不在已知 OEM 库中，无法验证一致性 (BRAND=$brandFromBuild, MANUFACTURER=$manufacturerFromBuild)"
                )
            }
            else -> {
                CheckResult(
                    CheckStatus.PASS,
                    "品牌属性一致: $brand (BRAND=$brandFromBuild, MANUFACTURER=$manufacturerFromBuild)"
                )
            }
        }
    }

    // ==================== 检测项 2: 主动服务探针 ====================

    private fun checkServiceProbes(context: Context, brand: String): CheckResult {
        val outcomes = OEMServiceProbe.probeByBrand(context, brand)

        val hits = outcomes.count { it.result == OEMServiceProbe.ProbeResult.HIT }
        val misses = outcomes.count { it.result == OEMServiceProbe.ProbeResult.MISS }
        val errors = outcomes.count { it.result == OEMServiceProbe.ProbeResult.ERROR }

        val hitDetails = outcomes
            .filter { it.result == OEMServiceProbe.ProbeResult.HIT }
            .map { it.detail }
        val missDetails = outcomes
            .filter { it.result == OEMServiceProbe.ProbeResult.MISS }
            .map { it.detail }

        Log.d(TAG, "服务探针结果: HIT=$hits, MISS=$misses, ERROR=$errors")

        val matchedOEM = findMatchedOEM(brand)

        return when {
            hits >= 2 -> {
                CheckResult(
                    CheckStatus.PASS,
                    "主动探针命中 ${hits} 项: ${hitDetails.joinToString("; ")}"
                )
            }
            hits == 1 && matchedOEM != null -> {
                CheckResult(
                    CheckStatus.INFO,
                    "仅命中 1 项品牌服务: ${hitDetails.first()} (共探测 ${outcomes.size} 项)"
                )
            }
            matchedOEM != null && hits == 0 -> {
                CheckResult(
                    CheckStatus.FAIL,
                    "品牌标志性服务探针全部未命中 (${misses}项失败)，疑似非原厂设备: ${missDetails.firstOrNull() ?: "无响应"}"
                )
            }
            else -> {
                CheckResult(
                    CheckStatus.INFO,
                    "未知品牌 '$brand'，探针结果: 命中=$hits, 未命中=$misses, 错误=$errors"
                )
            }
        }
    }

    // ==================== 检测项 3: 系统应用包检测 ====================

    private fun checkSystemPackages(context: Context, brand: String): CheckResult {
        val pm = context.packageManager

        // 多方案获取应用列表
        val allPackages = mutableSetOf<String>()

        try {
            val installed = pm.getInstalledPackages(0)
            allPackages.addAll(installed.map { it.packageName })
        } catch (e: Exception) {
            Log.w(TAG, "getInstalledPackages 失败: ${e.message}")
        }

        try {
            val apps = pm.getInstalledApplications(PackageManager.GET_META_DATA)
            allPackages.addAll(apps.map { it.packageName })
        } catch (e: Exception) {
            Log.w(TAG, "getInstalledApplications 失败: ${e.message}")
        }

        try {
            val shellOutput = executeShell("pm list packages")
            val shellPackages = shellOutput.lines()
                .map { it.trim() }
                .filter { it.startsWith("package:") }
                .map { it.removePrefix("package:") }
            allPackages.addAll(shellPackages)
        } catch (e: Exception) {
            Log.w(TAG, "shell pm list 失败: ${e.message}")
        }

        Log.d(TAG, "总应用包数 (多源合并): ${allPackages.size}")

        val matchedOEM = findMatchedOEM(brand)

        var oemPackageHits = 0
        val matchedOEMPackages = mutableListOf<String>()
        val missingOEMPackages = mutableListOf<String>()
        if (matchedOEM != null) {
            for (pkg in matchedOEM.expectedPackages) {
                if (allPackages.contains(pkg)) {
                    oemPackageHits++
                    if (matchedOEMPackages.size < 5) {
                        matchedOEMPackages.add(pkg.substringAfterLast("."))
                    }
                } else {
                    if (missingOEMPackages.size < 5) {
                        missingOEMPackages.add(pkg.substringAfterLast("."))
                    }
                }
            }
        }

        // 检测系统应用比例异常
        val systemApps = allPackages.count { pkgName ->
            try {
                val info = pm.getPackageInfo(pkgName, 0)
                info?.applicationInfo?.flags?.and(ApplicationInfo.FLAG_SYSTEM) != 0
            } catch (e: Exception) {
                false
            }
        }
        val systemAppRatio = if (allPackages.isNotEmpty()) systemApps.toFloat() / allPackages.size else 0f
        val isLowSystemRatio = systemAppRatio < 0.15f && allPackages.size > 50

        return when {
            matchedOEM != null && oemPackageHits == 0 -> {
                CheckResult(
                    CheckStatus.FAIL,
                    "未找到 ${matchedOEM.brandNames.first()} 标志性应用 (${matchedOEM.expectedPackages.size}个期望包全部缺失)"
                )
            }
            matchedOEM != null && oemPackageHits < matchedOEM.expectedPackages.size / 3 -> {
                CheckResult(
                    CheckStatus.FAIL,
                    "${matchedOEM.brandNames.first()} 标志性应用缺失过多 (仅 ${oemPackageHits}/${matchedOEM.expectedPackages.size})，缺失: ${missingOEMPackages.joinToString(", ")}"
                )
            }
            isLowSystemRatio -> {
                CheckResult(
                    CheckStatus.FAIL,
                    "系统应用比例异常低 (${String.format("%.1f", systemAppRatio * 100)}%)，疑似 GSI/模拟器"
                )
            }
            matchedOEM != null -> {
                CheckResult(
                    CheckStatus.PASS,
                    "${matchedOEM.brandNames.first()} 应用检测通过 (${oemPackageHits}/${matchedOEM.expectedPackages.size}): ${matchedOEMPackages.joinToString(", ")}"
                )
            }
            else -> {
                CheckResult(
                    CheckStatus.INFO,
                    "未知品牌 '$brand'，共扫描到 ${allPackages.size} 个应用包"
                )
            }
        }
    }

    // ==================== 检测项 4: OEM 属性存在性 ====================

    private fun checkOEMProperties(brand: String): CheckResult {
        val matchedOEM = findMatchedOEM(brand)

        if (matchedOEM == null) {
            return CheckResult(
                CheckStatus.INFO,
                "品牌 '$brand' 不在已知 OEM 库中，跳过属性检测"
            )
        }

        val foundProps = mutableListOf<String>()
        val missingProps = mutableListOf<String>()

        for (prop in matchedOEM.propertyHints) {
            val value = getProp(prop)
            if (value.isNotBlank() && value != "unknown") {
                foundProps.add("$prop=$value")
            } else {
                missingProps.add(prop)
            }
        }

        return when {
            foundProps.isEmpty() && missingProps.isNotEmpty() -> {
                CheckResult(
                    CheckStatus.FAIL,
                    "${matchedOEM.brandNames.first()} 标志性属性全部缺失 (${missingProps.size}个)，疑似非原厂 ROM/模拟器"
                )
            }
            foundProps.isEmpty() -> {
                CheckResult(
                    CheckStatus.INFO,
                    "未找到 ${matchedOEM.brandNames.first()} 标志性属性"
                )
            }
            else -> {
                CheckResult(
                    CheckStatus.PASS,
                    "发现 ${matchedOEM.brandNames.first()} 属性 ${foundProps.size} 个: ${foundProps.joinToString(", ")}"
                )
            }
        }
    }

    // ==================== 检测项 5: 模拟器特征检测 ====================

    private fun checkEmulatorHints(context: Context, brand: String): CheckResult {
        val hints = mutableListOf<String>()

        // 1. 通用品牌名
        if (Build.BRAND.lowercase() == "generic" || Build.BRAND.lowercase() == "google") {
            hints.add("Build.BRAND='${Build.BRAND}'")
        }
        if (Build.MANUFACTURER.lowercase() == "unknown") {
            hints.add("Build.MANUFACTURER='${Build.MANUFACTURER}'")
        }

        // 2. 设备型号包含模拟器关键词
        val model = Build.MODEL.lowercase()
        val emulatorModels = listOf("sdk", "emulator", "simulator", "virtual", "ranchu", "goldfish")
        for (em in emulatorModels) {
            if (model.contains(em)) {
                hints.add("MODEL='$model' 包含 '$em'")
                break
            }
        }

        // 3. 硬件名包含模拟器关键词
        val hardware = Build.HARDWARE.lowercase()
        val emulatorHardware = listOf("goldfish", "ranchu", "vbox86", "ttvm", "nox", "ldplayer", "memu", "bluestacks")
        for (eh in emulatorHardware) {
            if (hardware.contains(eh)) {
                hints.add("HARDWARE='$hardware' 包含 '$eh'")
                break
            }
        }

        // 4. 指纹包含可疑关键词
        val fingerprint = Build.FINGERPRINT.lowercase()
        val emulatorFingerprints = listOf("generic", "test-keys", "sdk", "emulator")
        for (ef in emulatorFingerprints) {
            if (fingerprint.contains(ef)) {
                hints.add("FINGERPRINT 包含 '$ef'")
                break
            }
        }

        // 5. ro.kernel.qemu
        val qemu = getProp("ro.kernel.qemu")
        if (qemu == "1") {
            hints.add("ro.kernel.qemu=1")
        }

        // 6. 检查是否存在 QEMU 属性
        val qemuProps = listOf("ro.hardware.vm", "ro.boot.vm")
        for (prop in qemuProps) {
            val value = getProp(prop)
            if (value.isNotBlank() && value != "unknown") {
                hints.add("$prop=$value")
            }
        }

        return when {
            hints.size >= 2 -> {
                CheckResult(
                    CheckStatus.FAIL,
                    "发现 ${hints.size} 项模拟器/云手机特征: ${hints.joinToString("; ")}"
                )
            }
            hints.size == 1 -> {
                CheckResult(
                    CheckStatus.INFO,
                    "发现 1 项可疑特征: ${hints.first()}"
                )
            }
            else -> {
                CheckResult(
                    CheckStatus.PASS,
                    "未发现明显的模拟器/云手机特征"
                )
            }
        }
    }

    // ==================== 综合评估 ====================

    private fun evaluateSummary(items: List<CheckItem>, brand: String): CheckResult {
        val failPoints = items.filter {
            it.checkPoint != "oem_summary" && it.status == CheckStatus.FAIL
        }
        val failNames = failPoints.map { it.name }

        val matchedOEM = findMatchedOEM(brand)
        val oemName = matchedOEM?.brandNames?.first() ?: brand

        return when {
            failPoints.size >= 3 -> {
                CheckResult(
                    CheckStatus.FAIL,
                    "高度疑似模拟器/云手机/改机 (${failPoints.size}项异常: ${failNames.joinToString(", ")})"
                )
            }
            failPoints.size >= 2 -> {
                CheckResult(
                    CheckStatus.FAIL,
                    "疑似非原厂设备 (${failPoints.size}项异常: ${failNames.joinToString(", ")})"
                )
            }
            failPoints.size == 1 -> {
                CheckResult(
                    CheckStatus.INFO,
                    "发现 1 项 OEM 一致性异常: ${failNames.first()}"
                )
            }
            matchedOEM == null -> {
                CheckResult(
                    CheckStatus.INFO,
                    "品牌 '$brand' 不在已知 OEM 库中，无法完整验证"
                )
            }
            else -> {
                CheckResult(
                    CheckStatus.PASS,
                    "${oemName} OEM 一致性检测通过"
                )
            }
        }
    }

    // ==================== 辅助方法 ====================

    private fun findMatchedOEM(brand: String): OEMProfile? {
        val lowerBrand = brand.lowercase()
        for ((key, profile) in OEM_SIGNATURES) {
            for (name in profile.brandNames) {
                if (lowerBrand.contains(name) || name.contains(lowerBrand)) {
                    return profile
                }
            }
        }
        return null
    }

    private fun areRelatedBrands(a: String, b: String): Boolean {
        val relatedGroups = listOf(
            setOf("xiaomi", "redmi", "poco", "mi"),
            setOf("oppo", "realme", "oneplus", "oplus"),
            setOf("vivo", "iqoo", "bbk"),
            setOf("huawei", "honor", "hihonor"),
            setOf("google", "generic"),
            setOf("motorola", "moto", "lenovo"),
            setOf("sony", "sonymobile", "sonyericsson"),
        )
        val la = a.lowercase()
        val lb = b.lowercase()
        for (group in relatedGroups) {
            val inA = group.any { la.contains(it) || it.contains(la) }
            val inB = group.any { lb.contains(it) || it.contains(lb) }
            if (inA && inB) return true
        }
        return false
    }

    private fun getProp(property: String): String {
        return PropertyUtil.nativeGetProp(property)
    }

    private fun executeShell(command: String): String {
        return try {
            val process = Runtime.getRuntime().exec(command)
            val reader = BufferedReader(InputStreamReader(process.inputStream))
            val output = reader.readText()
            reader.close()
            output
        } catch (e: Exception) {
            ""
        }
    }

    private data class OEMProfile(
        val brandNames: List<String>,
        val expectedPackages: List<String>,
        val propertyHints: List<String>
    )
}

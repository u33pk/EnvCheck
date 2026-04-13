package qpdb.env.check.checkers

import android.util.Log
import qpdb.env.check.model.CheckItem
import qpdb.env.check.model.CheckResult
import qpdb.env.check.model.CheckStatus
import qpdb.env.check.model.Checkable
import qpdb.env.check.utils.PropertyUtil.getProp
import java.io.BufferedReader
import java.io.InputStreamReader

/**
 * 内核信息检测器
 * 检测内核版本信息的一致性、GKI 格式合规性
 */
class KernelInfoChecker : Checkable {

    companion object {
        private const val TAG = "KernelInfoChecker"

        // GKI 格式的正则表达式
        // 示例: 5.15.119-android13-8-gdae8b7f03305-ab1764128685
        // 示例: 5.15.119-android13-8-gdae8b7f03305-4k
        private val GKI_PATTERN = Regex(
            """^\d+\.\d+\.\d+-android\d+-\d+-g[0-9a-f]+-.*""",
            RegexOption.IGNORE_CASE
        )
    }

    override val categoryName: String = "内核信息检测"

    override fun checkList(): List<CheckItem> {
        Log.i(TAG, "checkList() 被调用")
        return listOf(
            // uname 获取的内核版本
            CheckItem(
                name = "内核版本 (uname)",
                checkPoint = "kernel_uname",
                description = "等待检测..."
            ),
            // getprop 获取的内核版本
            CheckItem(
                name = "内核版本 (getprop)",
                checkPoint = "kernel_prop",
                description = "等待检测..."
            ),
            // 版本一致性检测
            CheckItem(
                name = "版本一致性",
                checkPoint = "kernel_version_consistency",
                description = "等待检测..."
            ),
            // GKI 格式合规检测（5.10+ 内核必须合规）
            CheckItem(
                name = "GKI 格式合规",
                checkPoint = "kernel_gki_compliance",
                description = "等待检测..."
            ),
            // 综合评估
            CheckItem(
                name = "综合评估",
                checkPoint = "kernel_overall",
                description = "等待检测..."
            )
        )
    }

    override fun runCheck(): List<CheckItem> {
        Log.i(TAG, "runCheck() 被调用")

        val items = checkList().toMutableList()

        try {
            // 1. 获取 uname 内核版本
            val unameResult = getKernelVersionFromUname()
            Log.i(TAG, "uname 内核版本：${unameResult.description}")
            items.find { it.checkPoint == "kernel_uname" }?.let {
                it.status = unameResult.status
                it.description = unameResult.description
            }
            val unameVersion = if (unameResult.status == CheckStatus.PASS ||
                                   unameResult.status == CheckStatus.INFO) {
                extractVersionString(unameResult.description)
            } else ""

            // 2. 获取 getprop 内核版本
            val propResult = getKernelVersionFromProp()
            Log.i(TAG, "getprop 内核版本：${propResult.description}")
            items.find { it.checkPoint == "kernel_prop" }?.let {
                it.status = propResult.status
                it.description = propResult.description
            }
            val propVersion = if (propResult.status == CheckStatus.PASS ||
                                 propResult.status == CheckStatus.INFO) {
                extractVersionString(propResult.description)
            } else ""

            // 3. 版本一致性检测
            val consistencyResult = checkVersionConsistency(unameVersion, propVersion)
            Log.i(TAG, "版本一致性：${consistencyResult.description}")
            items.find { it.checkPoint == "kernel_version_consistency" }?.let {
                it.status = consistencyResult.status
                it.description = consistencyResult.description
            }

            // 4. GKI 格式合规检测（以 uname 版本为准）
            val gkiResult = checkGkiCompliance(unameVersion)
            Log.i(TAG, "GKI 合规检测：${gkiResult.description}")
            items.find { it.checkPoint == "kernel_gki_compliance" }?.let {
                it.status = gkiResult.status
                it.description = gkiResult.description
            }

            // 5. 综合评估
            val overallResult = evaluateOverall(
                consistencyResult.status,
                gkiResult.status
            )
            items.find { it.checkPoint == "kernel_overall" }?.let {
                it.status = overallResult.status
                it.description = overallResult.description
            }

        } catch (e: Exception) {
            Log.e(TAG, "检测过程出错：${e.message}", e)
        }

        return items
    }

    /**
     * 从检测结果描述中提取版本字符串
     * 如果描述本身就是版本号则直接返回
     */
    private fun extractVersionString(description: String): String {
        return description
    }

    /**
     * 通过 uname -r 获取内核版本
     */
    private fun getKernelVersionFromUname(): CheckResult {
        return try {
            val process = Runtime.getRuntime().exec("uname -r")
            val reader = BufferedReader(InputStreamReader(process.inputStream))
            val version = reader.readLine()?.trim() ?: ""
            reader.close()
            process.waitFor()

            if (version.isNotEmpty()) {
                CheckResult(CheckStatus.INFO, version)
            } else {
                CheckResult(CheckStatus.FAIL, "无法获取 uname 内核版本")
            }
        } catch (e: Exception) {
            Log.e(TAG, "getKernelVersionFromUname 出错：${e.message}")
            CheckResult(CheckStatus.FAIL, "检测失败：${e.message}")
        }
    }

    /**
     * 通过 getprop 获取 ro.kernel.version
     */
    private fun getKernelVersionFromProp(): CheckResult {
        return try {
            // 尝试多个可能的属性名
            val propNames = listOf(
                "ro.kernel.version",
                "ro.build.kernel.version",
                "ro.boot.kernel.version",
                "ro.os_kernel.version"
            )

            for (propName in propNames) {
                val value = getProp(propName)
                if (!value.isNullOrEmpty()) {
                    return CheckResult(CheckStatus.INFO, value)
                }
            }

            // 如果 JNI 方法失败，尝试 shell 命令
            val process = Runtime.getRuntime().exec("getprop ro.kernel.version")
            val reader = BufferedReader(InputStreamReader(process.inputStream))
            val version = reader.readLine()?.trim() ?: ""
            reader.close()
            process.waitFor()

            if (version.isNotEmpty()) {
                CheckResult(CheckStatus.INFO, version)
            } else {
                CheckResult(CheckStatus.INFO, "未设置 ro.kernel.version")
            }
        } catch (e: Exception) {
            Log.e(TAG, "getKernelVersionFromProp 出错：${e.message}")
            CheckResult(CheckStatus.FAIL, "检测失败：${e.message}")
        }
    }

    /**
     * 检查 uname 和 getprop 获取的版本是否一致
     */
    private fun checkVersionConsistency(unameVersion: String, propVersion: String): CheckResult {
        // 如果任一版本为空，无法比较
        if (unameVersion.isEmpty() || propVersion.isEmpty()) {
            return CheckResult(CheckStatus.INFO, "无法比较：缺少版本信息")
        }

        // 完全匹配
        if (unameVersion == propVersion) {
            return CheckResult(CheckStatus.PASS, "版本一致：$unameVersion")
        }

        // 部分匹配检查（处理版本号包含关系）
        val unameNormalized = unameVersion.lowercase().replace("-", "").replace("_", "")
        val propNormalized = propVersion.lowercase().replace("-", "").replace("_", "")

        return if (unameNormalized == propNormalized ||
                   unameVersion.contains(propVersion) ||
                   propVersion.contains(unameVersion)) {
            CheckResult(CheckStatus.INFO, "版本部分匹配：uname=$unameVersion, prop=$propVersion")
        } else {
            CheckResult(CheckStatus.FAIL, "版本不一致：uname=$unameVersion, prop=$propVersion")
        }
    }

    /**
     * 解析内核版本号的主版本和次版本
     * 返回 Pair(主版本, 次版本)，解析失败返回 null
     */
    private fun parseKernelVersion(version: String): Pair<Int, Int>? {
        return try {
            // 匹配版本号开头，如 "5.15.119" 或 "6.1.25"
            val versionPattern = Regex("""^(\d+)\.(\d+)""")
            val match = versionPattern.find(version)
            if (match != null) {
                val major = match.groupValues[1].toInt()
                val minor = match.groupValues[2].toInt()
                Pair(major, minor)
            } else {
                null
            }
        } catch (e: Exception) {
            null
        }
    }

    /**
     * 检查 GKI 合规性
     * - 5.10 及以上内核：必须符合 GKI_PATTERN 格式，否则 FAIL
     * - 5.10 以下内核：显示原始值，INFO 类型
     */
    private fun checkGkiCompliance(version: String): CheckResult {
        if (version.isEmpty()) {
            return CheckResult(CheckStatus.INFO, "无法检测：缺少版本信息")
        }

        val versionPair = parseKernelVersion(version)
            ?: return CheckResult(CheckStatus.INFO, "无法解析版本号：$version")

        val (major, minor) = versionPair
        val versionFloat = major + minor / 100.0

        // 5.10 及以上内核必须合规
        return if (versionFloat >= 5.10) {
            val isGkiCompliant = GKI_PATTERN.matches(version)
            if (isGkiCompliant) {
                CheckResult(
                    CheckStatus.PASS,
                    "符合 GKI 标准：$version"
                )
            } else {
                CheckResult(
                    CheckStatus.FAIL,
                    "不符合 GKI 标准（内核 $major.$minor+ 必须合规）：$version"
                )
            }
        } else {
            // 5.10 以下版本，仅显示信息
            CheckResult(
                CheckStatus.INFO,
                "内核版本 $major.$minor（低于 5.10，无需 GKI 合规）：$version"
            )
        }
    }

    /**
     * 综合评估内核状态
     */
    private fun evaluateOverall(
        consistencyStatus: CheckStatus,
        gkiStatus: CheckStatus
    ): CheckResult {
        // 如果 GKI 不合规，直接判定为 FAIL
        if (gkiStatus == CheckStatus.FAIL) {
            return CheckResult(
                CheckStatus.FAIL,
                "内核不符合 GKI 标准（可能被修改）"
            )
        }

        // 如果版本不一致，判定为 FAIL
        if (consistencyStatus == CheckStatus.FAIL) {
            return CheckResult(
                CheckStatus.FAIL,
                "内核信息异常（版本不一致）"
            )
        }

        // 如果都是 PASS，判定为正常
        if (consistencyStatus == CheckStatus.PASS && gkiStatus == CheckStatus.PASS) {
            return CheckResult(
                CheckStatus.PASS,
                "内核信息正常"
            )
        }

        // 其他情况（部分为 INFO）
        return CheckResult(
            CheckStatus.INFO,
            "内核信息检测完成"
        )
    }
}

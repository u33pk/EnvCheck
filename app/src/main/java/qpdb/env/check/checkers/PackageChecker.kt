package qpdb.env.check.checkers

import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.util.Log
import qpdb.env.check.EnvCheckApp
import qpdb.env.check.model.CheckItem
import qpdb.env.check.model.CheckResult
import qpdb.env.check.model.CheckStatus
import qpdb.env.check.model.Checkable
import qpdb.env.check.utils.PackageUtil

/**
 * 已安装包名列表检测器
 *
 * 通过多 API 交叉验证获取包名列表，检测以下风险：
 * 1. 不同来源的包名集合不一致（可能存在包名隐藏/过滤）
 * 2. 检测到已知的 Root/越狱工具包名
 */
class PackageChecker : Checkable {

    companion object {
        private const val TAG = "PackageChecker"
    }

    override val categoryName: String = "包名列表检测"

    override fun checkList(): List<CheckItem> = listOf(
        CheckItem(name = "包名交集（多源一致）", checkPoint = "pkg_intersection", description = "等待检测..."),
        CheckItem(name = "包名并集（全量覆盖）", checkPoint = "pkg_union", description = "等待检测..."),
        CheckItem(name = "多源一致性校验", checkPoint = "pkg_consistency", description = "等待检测..."),
        CheckItem(name = "风险包名检测", checkPoint = "pkg_risk", description = "等待检测...")
    )

    override fun runCheck(): List<CheckItem> {
        Log.i(TAG, "runCheck() 开始执行包名列表检测")
        val items = checkList().toMutableList()

        fun applyResult(checkPoint: String, result: CheckResult) {
            items.find { it.checkPoint == checkPoint }?.let {
                it.status = result.status
                it.description = result.description
            }
            Log.i(TAG, "[$checkPoint] ${result.status}: ${result.description}")
        }

        try {
            val intersection = PackageUtil.getIntersectionPackages()
            val union = PackageUtil.getUnionPackages()
            val riskInIntersection = PackageUtil.getMatchedRiskPackages(intersection)
            val riskInUnion = PackageUtil.getMatchedRiskPackages(union)

            applyResult("pkg_intersection", checkIntersection(intersection))
            applyResult("pkg_union", checkUnion(union))
            applyResult("pkg_consistency", checkConsistency(intersection, union))
            applyResult("pkg_risk", checkRiskPackages(riskInIntersection, riskInUnion))
        } catch (e: Exception) {
            Log.e(TAG, "包名检测过程异常", e)
            items.forEach { it.status = CheckStatus.FAIL; it.description = "检测异常：${e.message}" }
        }

        return items
    }

    // ==================== 子检测逻辑 ====================

    private fun checkIntersection(intersection: Set<String>): CheckResult {
        return try {
            when {
                intersection.isEmpty() -> CheckResult(
                    CheckStatus.INFO,
                    "交集为空，未能从任何途径获取包名"
                )
                else -> CheckResult(
                    CheckStatus.PASS,
                    "交集包含 ${intersection.size} 个包名"
                )
            }
        } catch (e: Exception) {
            CheckResult(CheckStatus.INFO, "交集检测异常：${e.message}")
        }
    }

    private fun checkUnion(union: Set<String>): CheckResult {
        return try {
            when {
                union.isEmpty() -> CheckResult(
                    CheckStatus.INFO,
                    "并集为空，未能从任何途径获取包名"
                )
                else -> CheckResult(
                    CheckStatus.PASS,
                    "并集包含 ${union.size} 个包名"
                )
            }
        } catch (e: Exception) {
            CheckResult(CheckStatus.INFO, "并集检测异常：${e.message}")
        }
    }

    /**
     * 多源一致性校验
     * 交集 == 并集 说明各 API 返回结果完全一致，无隐藏迹象
     * 交集 != 并集 说明存在来源差异，可能存在包名过滤/隐藏
     */
    private fun checkConsistency(intersection: Set<String>, union: Set<String>): CheckResult {
        diagnose()
        return try {
            val diff = union - intersection
            when {
                union.isEmpty() && intersection.isEmpty() -> CheckResult(
                    CheckStatus.INFO,
                    "无法获取包名数据，无法判定一致性"
                )
                diff.isEmpty() -> CheckResult(
                    CheckStatus.PASS,
                    "各来源包名列表完全一致（交集=并集=${union.size}）"
                )
                else -> CheckResult(
                    CheckStatus.FAIL,
                    "包名列表不一致：并集比交集多 ${diff.size} 个包（${diff.take(5).joinToString(", ")}${if (diff.size > 5) "..." else ""}），可能存在包名隐藏/过滤"
                )
            }
        } catch (e: Exception) {
            CheckResult(CheckStatus.INFO, "一致性校验异常：${e.message}")
        }
    }
    fun diagnose() {
        val pm = EnvCheckApp.getContext().packageManager

        // 1. 包是否存在
        try {
            val info = pm.getPackageInfo("com.xiaomi.market", 0)
            Log.i("DIAG", "✅ 包存在: ${info.packageName}, version=${info.versionName}")
        } catch (e: Exception) {
            Log.e("DIAG", "❌ 包不存在: ${e.message}")
        }

        // 2. 全局 query
        val intent =
            Intent(Intent.ACTION_VIEW, Uri.parse("market://details?id=com.android.settings"))
        val all = pm.queryIntentActivities(intent, PackageManager.MATCH_ALL)
        Log.i("DIAG", "全局匹配: ${all.size} 个")
        all.forEach { Log.i("DIAG", "   -> ${it.activityInfo.packageName}/${it.activityInfo.name}") }

        // 3. 定向 query
        intent.`package` = "com.xiaomi.market"
        val targeted = pm.queryIntentActivities(intent, PackageManager.MATCH_ALL)
        Log.i("DIAG", "定向匹配: ${targeted.size} 个")
        targeted.forEach { Log.i("DIAG", "   -> ${it.activityInfo.name}") }

        // 4. resolveActivity
        val resolve = pm.resolveActivity(intent, PackageManager.MATCH_DEFAULT_ONLY)
        Log.i("DIAG", "resolveActivity: ${resolve?.activityInfo?.name ?: "null"}")
    }

    /**
     * 风险包名检测
     * 若交集或并集中发现风险包名，均视为不通过
     */
    private fun checkRiskPackages(
        riskInIntersection: Set<String>,
        riskInUnion: Set<String>
    ): CheckResult {
        return try {
            val allRisk = riskInIntersection + riskInUnion
            when {
                allRisk.isEmpty() -> CheckResult(
                    CheckStatus.PASS,
                    "未发现已知风险包名"
                )
                else -> CheckResult(
                    CheckStatus.FAIL,
                    "检测到风险包名（${allRisk.size} 个）：${allRisk.joinToString(", ")}"
                )
            }
        } catch (e: Exception) {
            CheckResult(CheckStatus.INFO, "风险包名检测异常：${e.message}")
        }
    }
}

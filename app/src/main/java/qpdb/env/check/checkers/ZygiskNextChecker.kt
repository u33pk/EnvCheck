package qpdb.env.check.checkers

import android.util.Log
import qpdb.env.check.model.CheckItem
import qpdb.env.check.model.CheckResult
import qpdb.env.check.model.CheckStatus
import qpdb.env.check.model.Checkable
import qpdb.env.check.utils.ZygiskNextUtil

/**
 * Zygisk Next 检测器（v2）
 *
 * 基于 doc/timing_detection_schemes_analysis.md 实现的时间侧信道检测方案。
 * 删除了所有无效检测（SO 加载、maps、mountinfo、env、mprotect、selinux），
 * 专注于高可靠性的时间侧信道检测。
 *
 * 检测维度：
 * 1. 基础 fork 时间测量（zn_fork_timing）
 * 2. 双进程对比（zn_fork_exec_vs_exit）— 方案 A 简化版
 * 3. App 启动空白期（zn_app_startup）— 方案 B
 * 4. fork 统计分布分析（zn_fork_distribution）— 方案 C
 * 5. 综合评估（zn_summary）
 */
class ZygiskNextChecker : Checkable {

    companion object {
        private const val TAG = "ZygiskNextChecker"
    }

    override val categoryName: String = "Zygisk Next 检测"

    override fun checkList(): List<CheckItem> = listOf(
        CheckItem(name = "Zygote fork 时间侧信道", checkPoint = "zn_fork_timing", description = "等待检测..."),
        CheckItem(name = "双进程对比侧信道", checkPoint = "zn_fork_exec_vs_exit", description = "等待检测..."),
        CheckItem(name = "App 启动空白期", checkPoint = "zn_app_startup", description = "等待检测..."),
        CheckItem(name = "fork 统计分布分析", checkPoint = "zn_fork_distribution", description = "等待检测..."),
        CheckItem(name = "综合评估", checkPoint = "zn_summary", description = "等待检测...")
    )

    override fun runCheck(): List<CheckItem> {
        Log.i(TAG, "runCheck() 开始执行 Zygisk Next 时间侧信道检测")
        val items = checkList().toMutableList()

        fun applyResult(checkPoint: String, result: CheckResult) {
            items.find { it.checkPoint == checkPoint }?.let {
                it.status = result.status
                it.description = result.description
            }
            Log.i(TAG, "[$checkPoint] ${result.status}: ${result.description}")
        }

        try {
            applyResult("zn_fork_timing", checkZygoteForkTiming())
            applyResult("zn_fork_exec_vs_exit", checkForkExecVsExit())
            applyResult("zn_app_startup", checkAppStartup())
            applyResult("zn_fork_distribution", checkForkDistribution())
            applyResult("zn_summary", checkSummary(items))
        } catch (e: Exception) {
            Log.e(TAG, "检测过程异常", e)
        }

        return items
    }

    // ==================== 基础 fork 时间测量 ====================

    /**
     * Zygote fork 时间侧信道检测
     *
     * 基于 doc/zygote_timing_analysis.md 实现：
     * 测量 fork + exec("/system/bin/sh", "-c", "exit 0") 的总耗时。
     * Zygisk Next 注入后，zygote 进程的 App 孵化时间会显著变长：
     * - 正常设备：中位数 ~500-2000 us
     * - 有 Zygisk Next：中位数 ~2000-10000+ us
     */
    private fun checkZygoteForkTiming(): CheckResult {
        return try {
            val result = ZygiskNextUtil.nativeCheckZygoteForkTiming()
            if (result == "fork_failed") {
                return CheckResult(CheckStatus.INFO, "fork 失败，无法测量 fork 延迟")
            }

            val medianUs = result.substringAfter("median_us=").substringBefore("|").toLongOrNull() ?: -1
            val meanUs = result.substringAfter("mean_us=").substringBefore("|").toLongOrNull() ?: -1
            val p90Us = result.substringAfter("p90_us=").toLongOrNull() ?: -1

            Log.d(TAG, "zygote fork timing median=${medianUs}us mean=${meanUs}us p90=${p90Us}us")

            if (medianUs < 0) {
                return CheckResult(CheckStatus.INFO, "数据解析异常: $result")
            }

            when {
                medianUs > 3000 -> CheckResult(
                    CheckStatus.FAIL,
                    "fork-exec 延迟显著偏高（中位数 ${medianUs} us，均值 ${meanUs} us），存在 Zygisk Next 注入迹象"
                )
                medianUs > 2000 -> CheckResult(
                    CheckStatus.INFO,
                    "fork-exec 延迟偏高（中位数 ${medianUs} us），建议结合其他维度判断"
                )
                else -> CheckResult(
                    CheckStatus.PASS,
                    "fork-exec 延迟正常（中位数 ${medianUs} us，P90 ${p90Us} us）"
                )
            }
        } catch (e: Exception) {
            CheckResult(CheckStatus.INFO, "zygote fork 时间侧信道异常: ${e.message}")
        }
    }

    // ==================== 方案 A：双进程对比侧信道 ====================

    /**
     * 双进程对比侧信道（方案 A 简化版）
     *
     * 文档分析：isolated 进程不会完全绕过 Zygisk，但确实减少了部分开销
     * （跳过 fd sanitization，~70-600 us）。
     *
     * 由于用户态 App 无法直接创建 Android isolatedProcess，
     * 本实现采用等效对比思路：
     * - 测试路径：fork + exec（完整 App 启动路径，含 Zygisk 的 execve/specialize hook）
     * - 基线路径：fork + _exit(0)（最小路径，跳过 exec 和 post-specialize）
     * - 若 Zygisk  hook 了 execve 或 specialize 路径，测试路径会显著慢于基线
     *
     * 可行性：中。差异存在但可能较小，适合作为辅助参照。
     */
    private fun checkForkExecVsExit(): CheckResult {
        return try {
            val result = ZygiskNextUtil.nativeCheckForkExecVsExit()
            if (result == "fork_failed") {
                return CheckResult(CheckStatus.INFO, "fork 失败，无法执行对比检测")
            }

            val execMedian = result.substringAfter("exec_median_us=").substringBefore("|").toLongOrNull() ?: -1
            val exitMedian = result.substringAfter("exit_median_us=").substringBefore("|").toLongOrNull() ?: -1
            val diff = result.substringAfter("diff_us=").substringBefore("|").toLongOrNull() ?: -1

            Log.d(TAG, "fork exec vs exit exec=$execMedian exit=$exitMedian diff=$diff")

            if (diff < 0) {
                return CheckResult(CheckStatus.INFO, "数据解析异常: $result")
            }

            when {
                diff > 1000 -> CheckResult(
                    CheckStatus.FAIL,
                    "fork+exec 显著慢于 fork+exit（差 ${diff} us），exec/specialize 路径存在 hook 迹象"
                )
                diff > 500 -> CheckResult(
                    CheckStatus.INFO,
                    "fork+exec 略慢于 fork+exit（差 ${diff} us），建议结合其他维度判断"
                )
                else -> CheckResult(
                    CheckStatus.PASS,
                    "fork+exec 与 fork+exit 差异正常（差 ${diff} us）"
                )
            }
        } catch (e: Exception) {
            CheckResult(CheckStatus.INFO, "双进程对比检测异常: ${e.message}")
        }
    }

    // ==================== 方案 B：多阶段时序（App 启动空白期） ====================

    /**
     * App 启动空白期检测（方案 B）
     *
     * 文档分析：Zygisk 的核心注入路径（fork_pre → run_modules_pre → sanitize_fds →
     * run_modules_post）全部发生在 fork 返回后到 ActivityThread 初始化前的"空白期"。
     *
     * 测量方法：
     * 1. 通过 EnvCheckApp.processStartupAgeMs 获取从进程创建到 Application.onCreate 的耗时
     * 2. 通过 JNI 读取 /proc/self/stat 的 starttime 作为内核视角的启动时间
     *
     * 可行性：高。直接测量 Zygisk 核心注入路径的延迟，信噪比最高。
     */
    private fun checkAppStartup(): CheckResult {
        return try {
            val startupMs = qpdb.env.check.EnvCheckApp.getInstance().processStartupAgeMs
            val nativeResult = ZygiskNextUtil.nativeCheckAppStartup()
            val starttimeMs = nativeResult.substringAfter("starttime_ms=").substringBefore("|").toLongOrNull() ?: -1

            Log.d(TAG, "app_startup startupMs=$startupMs starttimeMs=$starttimeMs")

            if (startupMs < 0) {
                return CheckResult(CheckStatus.INFO, "无法获取 App 启动时间")
            }

            when {
                startupMs > 3000 -> CheckResult(
                    CheckStatus.FAIL,
                    "App 启动空白期显著延长（${startupMs} ms），存在 Zygisk Next 注入导致的 specialize 延迟"
                )
                startupMs > 1500 -> CheckResult(
                    CheckStatus.INFO,
                    "App 启动空白期略长（${startupMs} ms），建议结合其他维度判断"
                )
                else -> CheckResult(
                    CheckStatus.PASS,
                    "App 启动空白期正常（${startupMs} ms）"
                )
            }
        } catch (e: Exception) {
            CheckResult(CheckStatus.INFO, "App 启动空白期检测异常: ${e.message}")
        }
    }

    // ==================== 方案 C：统计分布分析 ====================

    /**
     * fork 统计分布分析（方案 C）
     *
     * 文档分析：Zygisk 引入的时间延迟具有独特的统计特征：
     * 1. 均值偏移：有 Zygisk 时的均值都高于无 Zygisk
     * 2. 方差增大：模块加载时间不稳定（DlopenMem + onLoad + preAppSpecialize）
     * 3. 双峰/多峰分布：模块可能选择性加载，形成"快路径"和"慢路径"
     *
     * 检测方法：采集 30 次 fork+exec 样本，计算：
     * - 变异系数 CV = stddev / mean（正常 ~0.05-0.15，有 Zygisk ~0.1-0.8）
     * - 双峰分布检测：以 5ms 为阈值分割快/慢路径
     *
     * 可行性：高。统计特征是系统性的，难以伪造。
     */
    private fun checkForkDistribution(): CheckResult {
        return try {
            val result = ZygiskNextUtil.nativeCheckForkDistribution()
            if (result == "fork_failed") {
                return CheckResult(CheckStatus.INFO, "fork 失败，无法执行统计分布分析")
            }

            val meanUs = result.substringAfter("mean_us=").substringBefore("|").toLongOrNull() ?: -1
            val stddevUs = result.substringAfter("stddev_us=").substringBefore("|").toLongOrNull() ?: -1
            val cv = result.substringAfter("cv=").substringBefore("|").toDoubleOrNull() ?: -1.0
            val fastCount = result.substringAfter("fast_count=").substringBefore("|").toIntOrNull() ?: -1
            val slowCount = result.substringAfter("slow_count=").substringBefore("|").toIntOrNull() ?: -1

            Log.d(TAG, "fork distribution mean=$meanUs stddev=$stddevUs cv=$cv fast=$fastCount slow=$slowCount")

            if (meanUs < 0 || cv < 0) {
                return CheckResult(CheckStatus.INFO, "数据解析异常: $result")
            }

            val findings = mutableListOf<String>()
            if (meanUs > 5000) findings.add("均值异常高（${meanUs} us）")
            if (cv > 0.25) findings.add("变异系数大（CV=${"%.2f".format(cv)}）")
            if (slowCount > 3 && fastCount > 3) findings.add("双峰分布（快=$fastCount 慢=$slowCount）")

            when {
                findings.size >= 2 -> CheckResult(
                    CheckStatus.FAIL,
                    "统计分布强阳性：${findings.joinToString(", ")}，确认存在 Zygisk Next 时间指纹"
                )
                findings.isNotEmpty() -> CheckResult(
                    CheckStatus.INFO,
                    "统计分布可疑：${findings.first()}"
                )
                else -> CheckResult(
                    CheckStatus.PASS,
                    "fork 统计分布正常（均值 ${meanUs} us，CV=${"%.2f".format(cv)}）"
                )
            }
        } catch (e: Exception) {
            CheckResult(CheckStatus.INFO, "统计分布分析异常: ${e.message}")
        }
    }

    // ==================== 综合评估 ====================

    /**
     * 根据所有检测项的结果进行综合评估
     *
     * 核心可靠判据：
     * - fork 时间侧信道（直接测量核心路径）
     * - 统计分布分析（方差增大和双峰分布是强信号）
     * - App 启动空白期（信噪比最高）
     *
     * 辅助判据：
     * - 双进程对比（exec vs exit 差异，适合作为基线参照）
     */
    private fun checkSummary(items: List<CheckItem>): CheckResult {
        val failPoints = items.filter {
            it.checkPoint != "zn_summary" && it.status == CheckStatus.FAIL
        }.map { it.name }

        return when {
            failPoints.size >= 2 -> CheckResult(
                CheckStatus.FAIL,
                "高度疑似 Zygisk Next：${failPoints.joinToString(", ")}"
            )
            failPoints.isNotEmpty() -> CheckResult(
                CheckStatus.FAIL,
                "发现 Zygisk Next 可疑特征：${failPoints.first()}"
            )
            else -> CheckResult(CheckStatus.PASS, "未通过时间侧信道检测到 Zygisk Next 特征")
        }
    }
}

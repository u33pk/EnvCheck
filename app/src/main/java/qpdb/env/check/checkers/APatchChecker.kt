package qpdb.env.check.checkers

import android.util.Log
import qpdb.env.check.model.CheckItem
import qpdb.env.check.model.CheckResult
import qpdb.env.check.model.CheckStatus
import qpdb.env.check.model.Checkable
import qpdb.env.check.utils.ApatchDetectionUtil
import qpdb.env.check.utils.FileUtil.fileExists
import java.io.BufferedReader
import java.io.InputStreamReader

/**
 * APatch 检测器
 *
 * 基于 doc/detection_surface.md 实现的多维度联合检测方案。
 * APatch 的核心特征：
 * 1. 用户态文件系统痕迹（/data/adb/ap/ 等）
 * 2. 硬编码系统调用号 45（SuperCall）被劫持
 * 3. syscall(45) 返回值异常（返回 -EINVAL/-EPERM）
 * 4. syscall(45) 时间侧信道（hook 引入的额外开销）
 * 注意：使用 getpid() 作为基线对照，避免不存在的 syscall 触发 seccomp SIGSYS
 *
 * 检测策略：静态特征快速初筛 + 返回值侧信道核心确认 + 时间侧信道高对抗验证
 */
class APatchChecker : Checkable {

    companion object {
        private const val TAG = "APatchChecker"

        private const val EINVAL = -22
        private const val EPERM = -1
    }

    override val categoryName: String = "APatch 检测"

    override fun checkList(): List<CheckItem> = listOf(
        CheckItem(name = "APatch 文件痕迹", checkPoint = "apatch_files", description = "等待检测..."),
        CheckItem(name = "APD 进程检测", checkPoint = "apatch_process", description = "等待检测..."),
        CheckItem(name = "侧信道 - syscall(45) 返回值", checkPoint = "apatch_sc_return", description = "等待检测..."),
        CheckItem(name = "侧信道 - syscall(45) vs getpid 常规计时", checkPoint = "apatch_sc_timing", description = "等待检测..."),
        CheckItem(name = "侧信道 - CNTVCT syscall(45) vs 基线", checkPoint = "apatch_sc_cntvct_base", description = "等待检测..."),
        CheckItem(name = "侧信道 - CNTVCT 有效 vs 无效 cmd", checkPoint = "apatch_sc_cntvct_valid", description = "等待检测..."),
        CheckItem(name = "侧信道 - SuperKey 长度推断（研究性）", checkPoint = "apatch_sc_superkey_len", description = "等待检测..."),
        CheckItem(name = "综合评估", checkPoint = "apatch_summary", description = "等待检测...")
    )

    override fun runCheck(): List<CheckItem> {
        Log.i(TAG, "runCheck() 开始执行 APatch 检测")
        val items = checkList().toMutableList()

        fun applyResult(checkPoint: String, result: CheckResult) {
            items.find { it.checkPoint == checkPoint }?.let {
                it.status = result.status
                it.description = result.description
            }
            Log.i(TAG, "[$checkPoint] ${result.status}: ${result.description}")
        }

        try {
            applyResult("apatch_files", checkFileTraces())
            applyResult("apatch_process", checkApdProcess())
            applyResult("apatch_sc_return", checkSyscallReturn())
            applyResult("apatch_sc_timing", checkSyscallTiming())
            applyResult("apatch_sc_cntvct_base", checkCntvctBase())
            applyResult("apatch_sc_cntvct_valid", checkCntvctValidVsInvalid())
            applyResult("apatch_sc_superkey_len", checkSuperkeyLengthSideChannel())
            applyResult("apatch_summary", checkSummary(items))
        } catch (e: Exception) {
            Log.e(TAG, "检测过程异常", e)
        }

        return items
    }

    // ==================== 静态特征检测 ====================

    /**
     * 检测 APatch 在用户态留下的文件系统痕迹
     *
     * 注意：不再检测 /data/adb/ 下的内容。普通 App 通常无权限访问 /data/adb，
     * 无论目录内是否存在文件，stat() 都会因权限不足返回失败，导致误报/漏报。
     * 仅保留 /system/bin/su 等系统分区路径作为辅助参考。
     */
    private fun checkFileTraces(): CheckResult {
        return try {
            val traces = mutableListOf<String>()

            // 仅检测系统分区中常见的 su 路径（非 /data/adb 下）
            val suPaths = listOf("/system/bin/su")
            suPaths.forEach { path ->
                if (fileExists(path)) traces.add(path)
            }

            when {
                traces.isEmpty() -> CheckResult(CheckStatus.PASS, "未检测到系统分区 su 文件")
                else -> CheckResult(CheckStatus.INFO, "发现 su 文件：${traces.joinToString(", ")}（不能单独确认 APatch）")
            }
        } catch (e: Exception) {
            CheckResult(CheckStatus.INFO, "文件检测异常：${e.message}")
        }
    }

    /**
     * 扫描 APD 守护进程
     */
    private fun checkApdProcess(): CheckResult {
        return try {
            val hasApd = hasProcess("apd")
            when {
                hasApd -> CheckResult(CheckStatus.FAIL, "检测到 apd 守护进程运行")
                else -> CheckResult(CheckStatus.PASS, "未检测到 apd 进程")
            }
        } catch (e: Exception) {
            CheckResult(CheckStatus.INFO, "进程检测异常：${e.message}")
        }
    }

    // ==================== 返回值侧信道 ====================

    /**
     * 检测 syscall(45) 的返回值
     *
     * 根据最新文档分析：APatch 的 before 钩子在空 key / 错误 key 情况下不会设置
     * skip_origin，最终仍会调用原始系统调用处理函数并返回 -ENOSYS。
     * 因此，**仅通过返回值无法在不拥有 root 的情况下探测 APatch**。
     * 本项仅作为信息展示，不再参与 FAIL 判定。
     */
    private fun checkSyscallReturn(): CheckResult {
        return try {
            val retHello = ApatchDetectionUtil.nativeCheckSyscall45Return(0x1000L)
            val retInvalid = ApatchDetectionUtil.nativeCheckSyscall45Return(0x1L)
            val retBaseline = ApatchDetectionUtil.nativeCheckGetpidReturn()

            Log.d(TAG, "syscall return: hello=$retHello invalid=$retInvalid baseline(pid)=$retBaseline")

            if (retBaseline <= 0) {
                return CheckResult(CheckStatus.INFO, "基线 getpid() 返回值异常（$retBaseline），无法判定")
            }

            CheckResult(
                CheckStatus.INFO,
                "syscall(45) 返回值：hello=$retHello invalid=$retInvalid（返回值侧信道并不可行）"
            )
        } catch (e: Exception) {
            CheckResult(CheckStatus.INFO, "返回值检测异常：${e.message}")
        }
    }

    // ==================== 时间侧信道 ====================

    /**
     * 常规时间侧信道：syscall(45, "", 0x1) vs ftruncate(-1)
     *
     * 基线使用相邻且未被 hook 的合法 syscall（ftruncate，传入非法 fd -1），
     * 使其走完整的 syscall 入口路径后快速失败，与 45 号的入口路径完全对称。
     * 使用 clock_gettime(CLOCK_MONOTONIC) 测量，采样量较小（5000 次），
     * 作为 CNTVCT 检测的辅助和快速初筛。
     */
    private fun checkSyscallTiming(): CheckResult {
        return try {
            val iterations = 5000

            // 预热
            ApatchDetectionUtil.nativeCheckSyscall45Timing(0x1L, 100)
            ApatchDetectionUtil.nativeCheckBaselineTiming(100)

            // 各测 3 轮取中位数
            val testTimes = List(3) {
                ApatchDetectionUtil.nativeCheckSyscall45Timing(0x1L, iterations).toDouble()
            }
            val baseTimes = List(3) {
                ApatchDetectionUtil.nativeCheckBaselineTiming(iterations).toDouble()
            }

            val testMedian = testTimes.sorted()[1]
            val baseMedian = baseTimes.sorted()[1]

            val testAvgNs = testMedian / iterations
            val baseAvgNs = baseMedian / iterations
            val diffNs = testAvgNs - baseAvgNs

            Log.d(TAG, "syscall timing test_avg=${testAvgNs.toInt()}ns base_avg=${baseAvgNs.toInt()}ns diff=${diffNs.toInt()}ns")

            when {
                diffNs > 500 -> CheckResult(
                    CheckStatus.FAIL,
                    "syscall(45) 显著慢于基线（慢 ${diffNs.toInt()} ns/次），存在 hook 迹象"
                )
                diffNs > 150 -> CheckResult(
                    CheckStatus.INFO,
                    "syscall(45) 略慢于基线（慢 ${diffNs.toInt()} ns/次）"
                )
                else -> CheckResult(
                    CheckStatus.PASS,
                    "syscall(45) 计时正常（test=${testAvgNs.toInt()}ns base=${baseAvgNs.toInt()}ns）"
                )
            }
        } catch (e: Exception) {
            CheckResult(CheckStatus.INFO, "常规时间侧信道检测异常：${e.message}")
        }
    }

    /**
     * CNTVCT_EL0 高精度侧信道：syscall(45) vs ftruncate(-1)
     */
    private fun checkCntvctBase(): CheckResult {
        return try {
            val result = ApatchDetectionUtil.nativeCheckSupercallTiming()
            if (result == "alloc_failed") {
                return CheckResult(CheckStatus.INFO, "内存分配失败，无法执行 CNTVCT 检测")
            }
            if (result == "unsupported_arch") {
                return CheckResult(CheckStatus.INFO, "仅支持 ARM64 架构")
            }

            val anomaly = result.substringAfter("anomaly=").substringBefore("|").toIntOrNull() ?: -1
            val testMedian = result.substringAfter("test_median=").substringBefore("|").toLongOrNull() ?: -1
            val baseMedian = result.substringAfter("base_median=").toLongOrNull() ?: -1

            Log.d(TAG, "CNTVCT base anomaly=$anomaly test_median=$testMedian base_median=$baseMedian")

            if (anomaly < 0) {
                return CheckResult(CheckStatus.INFO, "CNTVCT 数据解析异常：$result")
            }

            when {
                anomaly > 7000 -> CheckResult(
                    CheckStatus.FAIL,
                    "CNTVCT 强阳性：syscall(45) 显著慢于基线（异常 $anomaly/10000），确认 45 号被 hook"
                )
                anomaly > 5000 -> CheckResult(
                    CheckStatus.INFO,
                    "CNTVCT 可疑：异常 $anomaly/10000，建议结合其他维度判断"
                )
                else -> CheckResult(
                    CheckStatus.PASS,
                    "CNTVCT 正常（异常 $anomaly/10000，test=$testMedian base=$baseMedian）"
                )
            }
        } catch (e: Exception) {
            CheckResult(CheckStatus.INFO, "CNTVCT 基线检测异常：${e.message}")
        }
    }

    /**
     * CNTVCT_EL0 高精度侧信道：有效 cmd vs 无效 cmd
     *
     * 用于区分"单纯被 hook 了 syscall 45"和"确实是 KernelPatch/APatch"。
     */
    private fun checkCntvctValidVsInvalid(): CheckResult {
        return try {
            val result = ApatchDetectionUtil.nativeCheckSupercallValidVsInvalid()
            if (result == "alloc_failed") {
                return CheckResult(CheckStatus.INFO, "内存分配失败")
            }
            if (result == "unsupported_arch") {
                return CheckResult(CheckStatus.INFO, "仅支持 ARM64 架构")
            }

            val anomaly = result.substringAfter("anomaly=").substringBefore("|").toIntOrNull() ?: -1
            val validMedian = result.substringAfter("valid_median=").substringBefore("|").toLongOrNull() ?: -1
            val invalidMedian = result.substringAfter("invalid_median=").toLongOrNull() ?: -1

            Log.d(TAG, "CNTVCT valid anomaly=$anomaly valid_median=$validMedian invalid_median=$invalidMedian")

            if (anomaly < 0) {
                return CheckResult(CheckStatus.INFO, "数据解析异常：$result")
            }

            when {
                anomaly > 7000 -> CheckResult(
                    CheckStatus.FAIL,
                    "CNTVCT 强阳性：有效 cmd 显著慢于无效 cmd（异常 $anomaly/10000），确认存在 APatch auth 逻辑"
                )
                anomaly > 5000 -> CheckResult(
                    CheckStatus.INFO,
                    "CNTVCT 可疑：异常 $anomaly/10000，建议综合判断"
                )
                else -> CheckResult(
                    CheckStatus.PASS,
                    "CNTVCT 正常（异常 $anomaly/10000，valid=$validMedian invalid=$invalidMedian）"
                )
            }
        } catch (e: Exception) {
            CheckResult(CheckStatus.INFO, "CNTVCT 有效/无效检测异常：${e.message}")
        }
    }

    /**
     * SuperKey 长度时间侧信道检测（研究性）
     *
     * 严格实现 doc/supercall_key_length_timing_sidechannel.md 的实验方案：
     * - 基线：syscall(45, fake_key_64, 0x1)  — cmd 无效，before 钩子直接 return
     * - 测试：syscall(45, fake_key_64, 0x1000) — cmd 有效，完整执行 strncpy + auth_superkey
     * - 通过大样本 CNTVCT_EL0 高精度计时并取中位数，计算差分 delta。
     *
     * 注意：该侧信道在理论上成立，但 Android 调度噪声较大，结果仅供研究参考，
     * 不参与常规 root 判定。
     */
    private fun checkSuperkeyLengthSideChannel(): CheckResult {
        return try {
            val result = ApatchDetectionUtil.nativeCheckSuperkeyLengthSideChannel()
            if (result == "alloc_failed") {
                return CheckResult(CheckStatus.INFO, "内存分配失败，无法执行检测")
            }
            if (result == "unsupported_arch") {
                return CheckResult(CheckStatus.INFO, "仅支持 ARM64 架构")
            }

            val delta = result.substringAfter("delta=").substringBefore("|").toLongOrNull()
            val baseline = result.substringAfter("baseline=").substringBefore("|").toLongOrNull()
            val test = result.substringAfter("test=").substringBefore("|").toLongOrNull()
            val samples = result.substringAfter("samples=").toIntOrNull()

            Log.d(TAG, "SuperKey length delta=$delta baseline=$baseline test=$test samples=$samples")

            if (delta == null || baseline == null || test == null || samples == null) {
                return CheckResult(CheckStatus.INFO, "数据解析异常：$result")
            }

            // 文档指出该信号非常微弱（auth_superkey 仅 1~3 ns/字符），
            // 且 Android 噪声大，因此统一作为 INFO 展示，不用于 FAIL 判定。
            when {
                delta > 5 -> CheckResult(
                    CheckStatus.INFO,
                    "检测到 auth_superkey 时间信号（delta=$delta CNTVCT counts），SuperKey 长度侧信道可能存在（研究性）"
                )
                delta > 3 -> CheckResult(
                    CheckStatus.INFO,
                    "存在微弱的 auth_superkey 时间信号（delta=$delta CNTVCT counts，仅供参考）"
                )
                else -> CheckResult(
                    CheckStatus.INFO,
                    "未检测到显著的 auth_superkey 时间信号（delta=$delta CNTVCT counts）"
                )
            }
        } catch (e: Exception) {
            CheckResult(CheckStatus.INFO, "SuperKey 长度侧信道检测异常：${e.message}")
        }
    }

    // ==================== 综合评估 ====================

    /**
     * 根据所有检测项的结果进行综合评估
     *
     * 核心可靠判据：CNTVCT 时间侧信道（syscall(45) 耗时异常）。
     * 文件痕迹与返回值侧信道已修正为不可靠/不可行，不再作为 FAIL 依据。
     * SuperKey 长度侧信道属于研究性手段，不参与 FAIL 判定。
     */
    private fun checkSummary(items: List<CheckItem>): CheckResult {
        val failPoints = items.filter {
            it.checkPoint != "apatch_summary" && it.status == CheckStatus.FAIL
        }.map { it.name }

        return when {
            failPoints.size >= 2 -> CheckResult(
                CheckStatus.FAIL,
                "高度疑似 APatch：${failPoints.joinToString(", ")}"
            )
            failPoints.isNotEmpty() -> CheckResult(
                CheckStatus.FAIL,
                "发现 APatch 可疑特征：${failPoints.first()}"
            )
            else -> CheckResult(CheckStatus.PASS, "未通过时间侧信道检测到 APatch 特征")
        }
    }

    // ==================== 工具方法 ====================

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
            false
        }
    }
}

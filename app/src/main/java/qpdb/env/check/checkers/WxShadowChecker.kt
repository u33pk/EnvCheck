package qpdb.env.check.checkers

import android.util.Log
import qpdb.env.check.model.CheckItem
import qpdb.env.check.model.CheckResult
import qpdb.env.check.model.CheckStatus
import qpdb.env.check.model.Checkable
import qpdb.env.check.utils.WxShadowDetectionUtil

/**
 * WXShadow / Anti-Detect / Hide-Maps 综合检测器
 *
 * 检测目标：
 * 1. WXShadow - 通过 Shadow Page 技术实现无痕 Hook 的内核模块
 * 2. Anti-Detect - 基于 Inline Hook 拦截 syscall 的防护模块
 * 3. Hide-Maps - 通过 Inline Hook 拦截 show_map_vma 隐藏内存映射的模块
 */
class WxShadowChecker : Checkable {

    companion object {
        private const val TAG = "WxShadowChecker"

        // 综合评分阈值
        private const val SCORE_HIGH_CONFIDENCE = 20
        private const val SCORE_SUSPICIOUS = 10
        private const val SCORE_WEAK = 5
    }

    override val categoryName: String = "WXShadow 关联检测"

    override fun checkList(): List<CheckItem> {
        Log.i(TAG, "checkList() 被调用")
        return listOf(
            // WXShadow 检测
            CheckItem(
                name = "WXShadow 自读页故障",
                checkPoint = "wxshadow_page_fault",
                description = "等待检测..."
            ),
            CheckItem(
                name = "WXShadow BRK时延指纹",
                checkPoint = "wxshadow_timing",
                description = "等待检测..."
            ),
            CheckItem(
                name = "WXShadow prctl探测",
                checkPoint = "wxshadow_prctl",
                description = "等待检测..."
            ),
            CheckItem(
                name = "WXShadow prctl时间侧信道",
                checkPoint = "wxshadow_prctl_timing",
                description = "等待检测..."
            ),
            // Anti-Detect 检测
            CheckItem(
                name = "Anti-Detect Hook不一致",
                checkPoint = "anti_detect_inconsistency",
                description = "等待检测..."
            ),
            CheckItem(
                name = "Anti-Detect Kallsyms扫描",
                checkPoint = "anti_detect_kallsyms",
                description = "等待检测..."
            ),
            // Hide-Maps 检测
            CheckItem(
                name = "Hide-Maps dl_iterate_phdr",
                checkPoint = "hide_maps_dl_vs_maps",
                description = "等待检测..."
            ),
            CheckItem(
                name = "Hide-Maps smaps对比",
                checkPoint = "hide_maps_smaps",
                description = "等待检测..."
            ),
            CheckItem(
                name = "Hide-Maps mincore扫描",
                checkPoint = "hide_maps_mincore",
                description = "等待检测..."
            ),
            CheckItem(
                name = "Hide-Maps ELF扫描",
                checkPoint = "hide_maps_elf",
                description = "等待检测..."
            ),
            // 内核日志/模块检测
            CheckItem(
                name = "/proc/modules KernelPatch",
                checkPoint = "proc_modules_kp",
                description = "等待检测..."
            ),
            // 综合评分
            CheckItem(
                name = "综合威胁评分",
                checkPoint = "overall_score",
                description = "等待检测..."
            )
        )
    }

    override fun runCheck(): List<CheckItem> {
        Log.i(TAG, "runCheck() 被调用")
        return kotlinx.coroutines.runBlocking { runCheckBlocking() }
    }

    override suspend fun runCheckWithProgress(onProgress: suspend (CheckItem) -> Unit): List<CheckItem> {
        Log.i(TAG, "runCheckWithProgress() 被调用")
        return runCheckBlocking(onProgress)
    }

    private suspend fun runCheckBlocking(onProgress: suspend (CheckItem) -> Unit = {}): List<CheckItem> {
        val items = checkList().toMutableList()
        var totalScore = 0

        suspend fun emit(checkPoint: String) {
            items.find { it.checkPoint == checkPoint }?.let { onProgress(it) }
        }

        try {
            // ===== WXShadow 检测 =====
            val pageFaultResult = checkWxShadowPageFault()
            items.find { it.checkPoint == "wxshadow_page_fault" }?.let {
                it.status = pageFaultResult.status
                it.description = pageFaultResult.description
            }
            emit("wxshadow_page_fault")
            if (pageFaultResult.status == CheckStatus.FAIL) totalScore += 10

            val timingResult = checkWxShadowTiming()
            items.find { it.checkPoint == "wxshadow_timing" }?.let {
                it.status = timingResult.status
                it.description = timingResult.description
            }
            emit("wxshadow_timing")
            if (timingResult.status == CheckStatus.FAIL) totalScore += 8

            val prctlResult = checkWxShadowPrctl()
            items.find { it.checkPoint == "wxshadow_prctl" }?.let {
                it.status = prctlResult.status
                it.description = prctlResult.description
            }
            emit("wxshadow_prctl")
            if (prctlResult.status == CheckStatus.FAIL) totalScore += 3

            val prctlTimingResult = checkWxShadowPrctlTiming()
            items.find { it.checkPoint == "wxshadow_prctl_timing" }?.let {
                it.status = prctlTimingResult.status
                it.description = prctlTimingResult.description
            }
            emit("wxshadow_prctl_timing")
            if (prctlTimingResult.status == CheckStatus.FAIL) totalScore += 6

            // ===== Anti-Detect 检测 =====
            val inconsistencyResult = checkSyscallInconsistency()
            items.find { it.checkPoint == "anti_detect_inconsistency" }?.let {
                it.status = inconsistencyResult.status
                it.description = inconsistencyResult.description
            }
            emit("anti_detect_inconsistency")
            if (inconsistencyResult.status == CheckStatus.FAIL) totalScore += 10

            val kallsymsResult = checkKallsyms()
            items.find { it.checkPoint == "anti_detect_kallsyms" }?.let {
                it.status = kallsymsResult.status
                it.description = kallsymsResult.description
            }
            emit("anti_detect_kallsyms")
            if (kallsymsResult.status == CheckStatus.FAIL) totalScore += 10

            // ===== Hide-Maps 检测 =====
            val hiddenMapsResult = checkHiddenMaps()
            items.find { it.checkPoint == "hide_maps_dl_vs_maps" }?.let {
                it.status = hiddenMapsResult.status
                it.description = hiddenMapsResult.description
            }
            emit("hide_maps_dl_vs_maps")
            if (hiddenMapsResult.status == CheckStatus.FAIL) totalScore += 10

            val smapsResult = checkSmapsVsMaps()
            items.find { it.checkPoint == "hide_maps_smaps" }?.let {
                it.status = smapsResult.status
                it.description = smapsResult.description
            }
            emit("hide_maps_smaps")
            if (smapsResult.status == CheckStatus.FAIL) totalScore += 5

            val mincoreResult = checkMincoreScan()
            items.find { it.checkPoint == "hide_maps_mincore" }?.let {
                it.status = mincoreResult.status
                it.description = mincoreResult.description
            }
            emit("hide_maps_mincore")
            if (mincoreResult.status == CheckStatus.FAIL) totalScore += 3

            val elfResult = checkElfMagic()
            items.find { it.checkPoint == "hide_maps_elf" }?.let {
                it.status = elfResult.status
                it.description = elfResult.description
            }
            emit("hide_maps_elf")
            if (elfResult.status == CheckStatus.FAIL) totalScore += 5

            // ===== 内核日志/模块检测 =====
            val procModulesResult = checkProcModules()
            items.find { it.checkPoint == "proc_modules_kp" }?.let {
                it.status = procModulesResult.status
                it.description = procModulesResult.description
            }
            emit("proc_modules_kp")
            if (procModulesResult.status == CheckStatus.FAIL) totalScore += 10

            // ===== 综合评分 =====
            val scoreResult = evaluateOverallScore(totalScore)
            items.find { it.checkPoint == "overall_score" }?.let {
                it.status = scoreResult.status
                it.description = scoreResult.description
            }
            emit("overall_score")

        } catch (e: Exception) {
            Log.e(TAG, "检测过程出错：${e.message}", e)
        }

        return items
    }

    // ==================== WXShadow 检测方法 ====================

    /**
     * 自读代码页 Page Fault 检测
     * 原理：正常代码页 r-x 自读不触发 page fault；wxshadow shadow 页 --x 自读触发 data abort
     */
    private fun checkWxShadowPageFault(): CheckResult {
        return try {
            val result = WxShadowDetectionUtil.nativeCheckWxShadowPageFault()
            Log.i(TAG, "WXShadow page fault: $result")

            val delta = parseLongValue(result, "delta")
            val threshold = parseLongValue(result, "threshold")

            if (delta != null && threshold != null && delta > threshold) {
                CheckResult(CheckStatus.FAIL, "检测到 page fault 异常增量: $delta (阈值: $threshold)")
            } else {
                CheckResult(CheckStatus.PASS, "page fault 正常: ${delta ?: "unknown"}")
            }
        } catch (e: Exception) {
            Log.e(TAG, "checkWxShadowPageFault 出错：${e.message}")
            CheckResult(CheckStatus.FAIL, "检测失败：${e.message}")
        }
    }

    /**
     * BRK + 单步时延指纹检测
     * 原理：wxshadow BRK 路径单次延迟约 5-20us，远高于普通函数调用
     */
    private fun checkWxShadowTiming(): CheckResult {
        return try {
            val result = WxShadowDetectionUtil.nativeCheckWxShadowTiming()
            Log.i(TAG, "WXShadow timing: $result")

            val ratio = parseLongValue(result, "ratio")
            val avgNs = parseLongValue(result, "avg_ns")
            val threshold = parseLongValue(result, "threshold")

            if (ratio != null && threshold != null && ratio > threshold) {
                CheckResult(CheckStatus.FAIL, "时延比值异常: $ratio (阈值: $threshold), 平均延迟: ${avgNs}ns")
            } else {
                CheckResult(CheckStatus.PASS, "时延正常: ratio=$ratio, avg=${avgNs}ns")
            }
        } catch (e: Exception) {
            Log.e(TAG, "checkWxShadowTiming 出错：${e.message}")
            CheckResult(CheckStatus.FAIL, "检测失败：${e.message}")
        }
    }

    /**
     * prctl 选项探测
     * 原理：wxshadow 注册了自定义 prctl 选项 0x57580001-0x57580008
     * 如果返回非 -EINVAL，说明模块已加载
     */
    private fun checkWxShadowPrctl(): CheckResult {
        return try {
            val result = WxShadowDetectionUtil.nativeCheckPrctlProbe()
            Log.i(TAG, "WXShadow prctl: $result")

            val ret = parseIntValue(result, "ret")
            val errno = parseIntValue(result, "errno")

            if (ret == -1 && errno == 22) { // EINVAL = 22
                CheckResult(CheckStatus.PASS, "prctl 返回 EINVAL，wxshadow 未加载")
            } else {
                CheckResult(CheckStatus.FAIL, "prctl 返回非 EINVAL: ret=$ret, errno=$errno (wxshadow 可能已加载)")
            }
        } catch (e: Exception) {
            Log.e(TAG, "checkWxShadowPrctl 出错：${e.message}")
            CheckResult(CheckStatus.FAIL, "检测失败：${e.message}")
        }
    }

    /**
     * prctl 高精度时间侧信道探测
     * 原理：对比 0x57580001-0x57580008 与不存在选项 0xfacebeef 的 prctl 耗时中位数
     * 使用 CNTVCT_EL0（aarch64）高精度计时，各采集 2000 个样本排序取中位数
     * 若 max_ratio > 2.0 或 anomaly >= 3，判定存在 WXShadow prctl hook
     */
    private fun checkWxShadowPrctlTiming(): CheckResult {
        return try {
            val result = WxShadowDetectionUtil.nativeCheckPrctlTimingSideChannel()
            Log.i(TAG, "WXShadow prctl timing: $result")

            val baseline = parseLongValue(result, "baseline")
            val wxAvg = parseLongValue(result, "wx_avg")
            val wxMin = parseLongValue(result, "wx_min")
            val wxMax = parseLongValue(result, "wx_max")
            val maxRatio = parseDoubleValue(result, "max_ratio")
            val anomaly = parseIntValue(result, "anomaly")
            val threshold = parseDoubleValue(result, "threshold")

            val desc = buildString {
                append("baseline=${baseline}cycles, ")
                append("wx_avg=${wxAvg}cycles, ")
                append("wx_min=${wxMin}cycles, ")
                append("wx_max=${wxMax}cycles, ")
                append("max_ratio=${String.format("%.2f", maxRatio)}, ")
                append("anomaly=${anomaly}/${8}")
            }

            if (maxRatio != null && threshold != null && maxRatio > threshold) {
                CheckResult(CheckStatus.FAIL, "检测到 prctl 时间侧信道异常: $desc")
            } else if (anomaly != null && anomaly >= 3) {
                CheckResult(CheckStatus.FAIL, "多个 prctl 选项耗时异常: $desc")
            } else {
                CheckResult(CheckStatus.PASS, "prctl 时间侧信道正常: $desc")
            }
        } catch (e: Exception) {
            Log.e(TAG, "checkWxShadowPrctlTiming 出错：${e.message}")
            CheckResult(CheckStatus.FAIL, "检测失败：${e.message}")
        }
    }

    // ==================== Anti-Detect 检测方法 ====================

    /**
     * faccessat vs openat 不一致性检测
     * 原理：anti-detect 可能 hook 了 faccessat 但未 hook openat
     */
    private fun checkSyscallInconsistency(): CheckResult {
        return try {
            val result = WxShadowDetectionUtil.nativeCheckSyscallInconsistency()
            Log.i(TAG, "Syscall inconsistency: $result")

            val inconsistent = parseIntValue(result, "inconsistent")

            if (inconsistent == 1) {
                CheckResult(CheckStatus.FAIL, "检测到 faccessat ENOENT 但 openat 成功 → syscall hook 确认")
            } else {
                CheckResult(CheckStatus.PASS, "faccessat 与 openat 结果一致")
            }
        } catch (e: Exception) {
            Log.e(TAG, "checkSyscallInconsistency 出错：${e.message}")
            CheckResult(CheckStatus.FAIL, "检测失败：${e.message}")
        }
    }

    /**
     * /proc/kallsyms 符号扫描
     */
    private fun checkKallsyms(): CheckResult {
        return try {
            val result = WxShadowDetectionUtil.nativeCheckKallsyms()
            Log.i(TAG, "Kallsyms: $result")

            val antiDetect = parseIntValue(result, "anti_detect") ?: 0
            val kpHooks = parseIntValue(result, "kp_hooks") ?: 0
            val kpModules = parseIntValue(result, "kp_modules") ?: 0

            if (antiDetect > 0 || kpHooks > 0 || kpModules > 0) {
                val parts = mutableListOf<String>()
                if (antiDetect > 0) parts.add("anti-detect符号: $antiDetect")
                if (kpHooks > 0) parts.add("KP hook符号: $kpHooks")
                if (kpModules > 0) parts.add("KP模块符号: $kpModules")
                CheckResult(CheckStatus.FAIL, parts.joinToString(", "))
            } else {
                CheckResult(CheckStatus.PASS, "未检测到 anti-detect 或 KernelPatch 符号")
            }
        } catch (e: Exception) {
            Log.e(TAG, "checkKallsyms 出错：${e.message}")
            CheckResult(CheckStatus.FAIL, "检测失败：${e.message}")
        }
    }

    // ==================== Hide-Maps 检测方法 ====================

    /**
     * dl_iterate_phdr 获取的 so 列表与 /proc/self/maps 做差集
     */
    private fun checkHiddenMaps(): CheckResult {
        return try {
            val result = WxShadowDetectionUtil.nativeCheckHiddenMaps()
            Log.i(TAG, "Hidden maps: $result")

            val hidden = parseIntValue(result, "hidden") ?: 0
            val total = parseIntValue(result, "total") ?: 0

            if (hidden > 0) {
                CheckResult(CheckStatus.FAIL, "发现 $hidden/$total 个库被隐藏在 /proc/self/maps 中")
            } else {
                CheckResult(CheckStatus.PASS, "dl_iterate_phdr 与 maps 一致: $total 个库")
            }
        } catch (e: Exception) {
            Log.e(TAG, "checkHiddenMaps 出错：${e.message}")
            CheckResult(CheckStatus.FAIL, "检测失败：${e.message}")
        }
    }

    /**
     * /proc/self/smaps 与 /proc/self/maps 行数对比
     */
    private fun checkSmapsVsMaps(): CheckResult {
        return try {
            val result = WxShadowDetectionUtil.nativeCheckSmapsVsMaps()
            Log.i(TAG, "Smaps vs maps: $result")

            val diff = parseIntValue(result, "diff") ?: 0
            val mapsLines = parseIntValue(result, "maps_lines") ?: 0
            val smapsRegions = parseIntValue(result, "smaps_regions") ?: 0

            if (diff > 2) {
                CheckResult(CheckStatus.FAIL, "smaps($smapsRegions) 与 maps($mapsLines) 差异: $diff")
            } else {
                CheckResult(CheckStatus.PASS, "smaps 与 maps 一致: $mapsLines 行")
            }
        } catch (e: Exception) {
            Log.e(TAG, "checkSmapsVsMaps 出错：${e.message}")
            CheckResult(CheckStatus.FAIL, "检测失败：${e.message}")
        }
    }

    /**
     * mincore 地址空间扫描
     */
    private fun checkMincoreScan(): CheckResult {
        return try {
            val result = WxShadowDetectionUtil.nativeCheckMincoreScan()
            Log.i(TAG, "Mincore scan: $result")

            val mappedPages = parseIntValue(result, "mapped_pages") ?: 0

            // mincore 扫描的映射页数如果显著大于 maps 报告的数量，可能表示有隐藏
            // 这里只做信息展示，因为需要与 maps 对比才能判断
            CheckResult(CheckStatus.INFO, "mincore 扫描到 $mappedPages 个有物理映射的页")
        } catch (e: Exception) {
            Log.e(TAG, "checkMincoreScan 出错：${e.message}")
            CheckResult(CheckStatus.FAIL, "检测失败：${e.message}")
        }
    }

    /**
     * ELF Magic 扫描
     */
    private fun checkElfMagic(): CheckResult {
        return try {
            val result = WxShadowDetectionUtil.nativeCheckElfMagic()
            Log.i(TAG, "ELF magic: $result")

            val elfCount = parseIntValue(result, "elf_count") ?: 0
            val totalLibs = parseIntValue(result, "total_libs") ?: 0

            if (totalLibs > 0 && elfCount < totalLibs / 2) {
                CheckResult(CheckStatus.FAIL, "ELF 扫描异常: $elfCount/$totalLibs (大量库无法通过 /proc/self/mem 读取)")
            } else {
                CheckResult(CheckStatus.PASS, "ELF 验证正常: $elfCount/$totalLibs")
            }
        } catch (e: Exception) {
            Log.e(TAG, "checkElfMagic 出错：${e.message}")
            CheckResult(CheckStatus.FAIL, "检测失败：${e.message}")
        }
    }

    // ==================== 内核日志/模块检测 ====================

    /**
     * /proc/modules 检测 KernelPatch 模块
     */
    private fun checkProcModules(): CheckResult {
        return try {
            val result = WxShadowDetectionUtil.nativeCheckProcModules()
            Log.i(TAG, "Proc modules: $result")

            val kp = parseIntValue(result, "kernelpatch") ?: 0

            if (kp > 0) {
                CheckResult(CheckStatus.FAIL, "/proc/modules 中发现 $kp 个 KernelPatch 相关模块")
            } else {
                CheckResult(CheckStatus.PASS, "/proc/modules 未检测到 KernelPatch")
            }
        } catch (e: Exception) {
            Log.e(TAG, "checkProcModules 出错：${e.message}")
            CheckResult(CheckStatus.FAIL, "检测失败：${e.message}")
        }
    }

    // ==================== 综合评分 ====================

    /**
     * 综合威胁评分
     */
    private fun evaluateOverallScore(score: Int): CheckResult {
        return when {
            score >= SCORE_HIGH_CONFIDENCE ->
                CheckResult(CheckStatus.FAIL, "综合评分: $score → 高置信度检测到 WXShadow/Anti-Detect/Hide-Maps 关联模块")
            score >= SCORE_SUSPICIOUS ->
                CheckResult(CheckStatus.FAIL, "综合评分: $score → 可疑，可能存在 WXShadow 或相关 Hook 模块")
            score >= SCORE_WEAK ->
                CheckResult(CheckStatus.INFO, "综合评分: $score → 弱信号，无法确定")
            else ->
                CheckResult(CheckStatus.PASS, "综合评分: $score → 未检测到 WXShadow 关联模块迹象")
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
     * 从 "key=value|key2=value2" 格式字符串中解析 double 值
     */
    private fun parseDoubleValue(result: String, key: String): Double? {
        val pattern = "$key=(-?\\d+\\.?\\d*)".toRegex()
        val match = pattern.find(result)
        return match?.groupValues?.get(1)?.toDoubleOrNull()
    }
}

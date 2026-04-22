package qpdb.env.check.checkers

import android.util.Log
import qpdb.env.check.model.CheckItem
import qpdb.env.check.model.CheckResult
import qpdb.env.check.model.CheckStatus
import qpdb.env.check.model.Checkable
import qpdb.env.check.utils.SusfsDetectionUtil
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader

/**
 * SUSFS 检测器
 *
 * 基于 doc/SUSFS_Detection_Report.md 实现的多层级检测框架。
 * SUSFS（SUperSU FileSystem）是 Android 内核层面的 root 隐藏框架，
 * 通过 KernelSU 的 prctl 隧道与用户态通信。
 *
 * 检测维度：
 * 1. Layer 1: 直接检测
 *    - prctl(0xDEADBEEF) 返回值侧信道
 *    - 文件系统痕迹扫描（ksu_susfs 二进制、module.prop）
 *    - 内核符号扫描（/proc/kallsyms susfs_* 符号）
 * 2. Layer 2: 高精度时间侧信道
 *    - prctl 执行路径长度侧信道
 *    - faccessat 隐藏路径 kmalloc 侧信道
 *    - CNTVCT_EL0 高精度 faccessat 侧信道
 *    - CNTVCT_EL0 高精度 stat 侧信道
 *    - /proc/self/maps 读取时延侧信道
 * 3. Layer 3: 一致性异常检测
 *    - linkat 错误码异常（ENOENT vs EEXIST）
 *    - memfd_create EFAULT 异常
 *    - mnt_id 连续性异常
 *    - uname 与 /proc/version 不一致
 * 4. Layer 4: 二进制与内存指纹
 *    - ksu_susfs 进程 cmdline 监控
 */
class SusfsChecker : Checkable {

    companion object {
        private const val TAG = "SusfsChecker"

        // 常见被 SUSFS 隐藏的路径
        private val HIDDEN_PATHS = listOf(
            "/system/addon.d",
            "/vendor/bin/install-recovery.sh",
            "/system/bin/install-recovery.sh",
            "/data/adbroot",
            "/system/bin/su",
            "/data/adb/ksu/bin/ksu_susfs"
        )

        // 确定存在的正常对照路径
        private const val NORMAL_PATH = "/system/bin/ls"
    }

    override val categoryName: String = "SUSFS 检测"

    override fun checkList(): List<CheckItem> = listOf(
        // Layer 1: 直接检测
        CheckItem(name = "prctl 返回值侧信道", checkPoint = "susfs_prctl_return", description = "等待检测..."),
        CheckItem(name = "文件系统痕迹", checkPoint = "susfs_filesystem", description = "等待检测..."),
        CheckItem(name = "内核符号 susfs_*", checkPoint = "susfs_kallsyms", description = "等待检测..."),
        // Layer 2: 时间侧信道
        CheckItem(name = "CNTVCT prctl DEADBEEF vs DEADBEEA", checkPoint = "susfs_cntvct_prctl", description = "等待检测..."),
        CheckItem(name = "CNTVCT prctl vs getpid", checkPoint = "susfs_prctl_vs_getpid", description = "等待检测..."),
        CheckItem(name = "faccessat 隐藏路径 kmalloc 时延", checkPoint = "susfs_faccessat_timing", description = "等待检测..."),
        CheckItem(name = "CNTVCT faccessat 高精度侧信道", checkPoint = "susfs_cntvct_faccessat", description = "等待检测..."),
        CheckItem(name = "CNTVCT stat 高精度侧信道", checkPoint = "susfs_cntvct_stat", description = "等待检测..."),
        CheckItem(name = "/proc/self/maps 读取时延", checkPoint = "susfs_maps_timing", description = "等待检测..."),
        // Layer 3: 一致性异常
        CheckItem(name = "linkat 错误码异常", checkPoint = "susfs_linkat_errno", description = "等待检测..."),
        CheckItem(name = "memfd_create EFAULT", checkPoint = "susfs_memfd", description = "等待检测..."),
        CheckItem(name = "mnt_id 连续性异常", checkPoint = "susfs_mnt_id", description = "等待检测..."),
        CheckItem(name = "uname 与 /proc/version 不一致", checkPoint = "susfs_uname", description = "等待检测..."),
        // Layer 4: 进程指纹
        CheckItem(name = "ksu_susfs 进程", checkPoint = "susfs_process", description = "等待检测...")
    )

    override fun runCheck(): List<CheckItem> {
        Log.i(TAG, "runCheck() 开始执行 SUSFS 检测")
        val items = checkList().toMutableList()

        fun applyResult(checkPoint: String, result: CheckResult) {
            items.find { it.checkPoint == checkPoint }?.let {
                it.status = result.status
                it.description = result.description
            }
            Log.i(TAG, "[$checkPoint] ${result.status}: ${result.description}")
        }

        try {
            // Layer 1
            applyResult("susfs_prctl_return", checkPrctlReturn())
            applyResult("susfs_filesystem", checkFilesystemTraces())
            applyResult("susfs_kallsyms", checkKernelSymbols())
            // Layer 2
            applyResult("susfs_cntvct_prctl", checkCntvctPrctl())
            applyResult("susfs_prctl_vs_getpid", checkPrctlVsGetpid())
            applyResult("susfs_faccessat_timing", checkFaccessatTiming())
            applyResult("susfs_cntvct_faccessat", checkCntvctFaccessat())
            applyResult("susfs_cntvct_stat", checkCntvctStat())
            applyResult("susfs_maps_timing", checkMapsTiming())
            // Layer 3
            applyResult("susfs_linkat_errno", checkLinkatErrno())
            applyResult("susfs_memfd", checkMemfdErrno())
            applyResult("susfs_mnt_id", checkMntIdReorder())
            applyResult("susfs_uname", checkUnameInconsistency())
            // Layer 4
            applyResult("susfs_process", checkSusfsProcess())
        } catch (e: Exception) {
            Log.e(TAG, "检测过程异常", e)
        }

        return items
    }

    // ==================== Layer 1: 直接检测 ====================

    /**
     * prctl(0xDEADBEEF) 返回值侧信道
     *
     * KSU 的 ksu_handle_prctl() 对 option == 0xDEADBEEF 有专门处理。
     * 普通 app 调用时，即使不是 root，也会进入 KSU handler 并返回 0；
     * 而无 KSU 的内核不认识 0xDEADBEEF，返回 EINVAL。
     */
    private fun checkPrctlReturn(): CheckResult {
        return try {
            val result = SusfsDetectionUtil.nativeCheckPrctlReturn()
            when (result) {
                1 -> CheckResult(
                    CheckStatus.FAIL,
                    "prctl(0xDEADBEEF) 返回 0，KSU 存在（SUSFS 的前提条件）"
                )
                0 -> CheckResult(
                    CheckStatus.PASS,
                    "prctl(0xDEADBEEF) 返回 EINVAL，未检测到 KSU"
                )
                else -> CheckResult(
                    CheckStatus.INFO,
                    "prctl 返回值异常（result=$result）"
                )
            }
        } catch (e: Exception) {
            CheckResult(CheckStatus.INFO, "prctl 检测异常：${e.message}")
        }
    }

    /**
     * 文件系统痕迹扫描
     *
     * 检测 SUSFS 安装后的文件系统残留：
     * - /data/adb/ksu/bin/ksu_susfs — 核心二进制
     * - /data/adb/ksu/modules/susfs4ksu/module.prop — 模块元数据
     */
    private fun checkFilesystemTraces(): CheckResult {
        return try {
            val traces = mutableListOf<String>()
            val paths = listOf(
                "/data/adb/ksu/bin/ksu_susfs" to "ksu_susfs 二进制",
                "/data/adb/ksu/modules/susfs4ksu/module.prop" to "susfs4ksu 模块配置"
            )

            for ((path, desc) in paths) {
                if (File(path).exists()) {
                    traces.add("$desc ($path)")
                }
            }

            when {
                traces.isNotEmpty() -> CheckResult(
                    CheckStatus.FAIL,
                    "发现 SUSFS 文件痕迹：${traces.joinToString(", ")}"
                )
                else -> CheckResult(
                    CheckStatus.PASS,
                    "未发现 SUSFS 文件系统痕迹"
                )
            }
        } catch (e: Exception) {
            CheckResult(CheckStatus.INFO, "文件系统痕迹检测异常：${e.message}")
        }
    }

    /**
     * 内核符号扫描
     *
     * 读取 /proc/kallsyms，搜索 susfs 相关符号。
     * 如果内核编译了 SUSFS，会暴露 susfs_* 或 LH_SUS_* 符号。
     */
    private fun checkKernelSymbols(): CheckResult {
        return try {
            val kallsyms = File("/proc/kallsyms")
            if (!kallsyms.canRead()) {
                return CheckResult(CheckStatus.INFO, "/proc/kallsyms 不可读（kptr_restrict 限制）")
            }

            var foundSymbols = mutableListOf<String>()
            kallsyms.forEachLine { line ->
                if (line.contains("susfs_") || line.contains("LH_SUS_") || line.contains("ksu_susfs")) {
                    // 提取符号名
                    val parts = line.split("\\s+".toRegex())
                    if (parts.size >= 4) {
                        foundSymbols.add(parts[3])
                    }
                }
            }

            when {
                foundSymbols.isNotEmpty() -> CheckResult(
                    CheckStatus.FAIL,
                    "发现 SUSFS 内核符号：${foundSymbols.take(5).joinToString(", ")}${if (foundSymbols.size > 5) " 等${foundSymbols.size}个" else ""}"
                )
                else -> CheckResult(
                    CheckStatus.PASS,
                    "未发现 SUSFS 相关内核符号"
                )
            }
        } catch (e: Exception) {
            CheckResult(CheckStatus.INFO, "内核符号扫描异常：${e.message}")
        }
    }

    // ==================== Layer 2: 时间侧信道 ====================

    /**
     * CNTVCT_EL0 高精度 prctl 侧信道
     *
     * 原理：KSU 的 ksu_handle_prctl() 在 syscall 入口处拦截所有 prctl 调用，
     * 检查 option == 0xDEADBEEF。
     *
     * 有 KSU 时：
     *   prctl(0xDEADBEEF) → hook 匹配 → KSU handler → 返回 0（较慢）
     *   prctl(0xDEADBEEA) → hook 检查 → 不匹配 → 正常 prctl → EINVAL（较快）
     *
     * 无 KSU 时：
     *   两者都 → 正常 prctl → EINVAL（速度相同）
     *
     * 因此 DEADBEEF 应该比 DEADBEEA 慢（handler 开销），anomaly > 5000 表示有 KSU。
     */
    private fun checkCntvctPrctl(): CheckResult {
        return try {
            val result = SusfsDetectionUtil.nativeCheckPrctlCntvct()

            if (result == "alloc_failed") {
                return CheckResult(CheckStatus.INFO, "内存分配失败，无法执行 CNTVCT prctl 检测")
            }
            if (result == "unsupported_arch") {
                return CheckResult(CheckStatus.INFO, "仅支持 ARM64 架构")
            }

            val beefMedian = result.substringAfter("deadbeef_median=").substringBefore("|").toLongOrNull() ?: -1
            val beeaMedian = result.substringAfter("deadbeea_median=").substringBefore("|").toLongOrNull() ?: -1
            val anomaly = result.substringAfter("anomaly=").toIntOrNull() ?: -1

            Log.d(TAG, "CNTVCT prctl DEADBEEF=$beefMedian DEADBEEA=$beeaMedian anomaly=$anomaly")

            if (anomaly < 0) {
                return CheckResult(CheckStatus.INFO, "CNTVCT prctl 数据解析异常：$result")
            }

            // 有 KSU 时 DEADBEEF > DEADBEEA，anomaly 应该 > 5000
            // 无 KSU 时两者相同，anomaly 应该 ~5000
            when {
                anomaly > 6500 -> CheckResult(
                    CheckStatus.FAIL,
                    "CNTVCT prctl 强阳性：DEADBEEF 显著慢于 DEADBEEA（anomaly=$anomaly/10000），" +
                            "确认存在 KSU prctl hook（SUSFS 前提条件）"
                )
                anomaly > 5500 -> CheckResult(
                    CheckStatus.INFO,
                    "CNTVCT prctl 可疑：anomaly=$anomaly/10000（DEADBEEF=$beefMedian DEADBEEA=$beeaMedian）"
                )
                else -> CheckResult(
                    CheckStatus.PASS,
                    "CNTVCT prctl 正常（anomaly=$anomaly/10000，无 KSU hook 迹象）"
                )
            }
        } catch (e: Exception) {
            CheckResult(CheckStatus.INFO, "CNTVCT prctl 检测异常：${e.message}")
        }
    }

    /**
     * CNTVCT_EL0 高精度 prctl vs getpid 对比
     *
     * 比较 prctl(0xDEADBEEF) 与 getpid() 的时延差异。
     * 有 KSU 时 prctl 走 hook 路径更慢，无 KSU 时两者相近。
     */
    private fun checkPrctlVsGetpid(): CheckResult {
        return try {
            val result = SusfsDetectionUtil.nativeCheckPrctlVsGetpid()

            if (result == "alloc_failed") {
                return CheckResult(CheckStatus.INFO, "内存分配失败，无法执行 prctl vs getpid 检测")
            }
            if (result == "unsupported_arch") {
                return CheckResult(CheckStatus.INFO, "仅支持 ARM64 架构")
            }

            val prctlMedian = result.substringAfter("prctl_median=").substringBefore("|").toLongOrNull() ?: -1
            val getpidMedian = result.substringAfter("getpid_median=").substringBefore("|").toLongOrNull() ?: -1
            val anomaly = result.substringAfter("anomaly=").toIntOrNull() ?: -1

            Log.d(TAG, "prctl vs getpid prctl=$prctlMedian getpid=$getpidMedian anomaly=$anomaly")

            if (anomaly < 0) {
                return CheckResult(CheckStatus.INFO, "prctl vs getpid 数据解析异常：$result")
            }

            // 有 KSU 时 prctl > getpid，anomaly 应该 > 5000
            when {
                anomaly > 6500 -> CheckResult(
                    CheckStatus.FAIL,
                    "prctl vs getpid 强阳性：prctl 显著慢于 getpid（anomaly=$anomaly/10000），" +
                            "确认存在 KSU prctl hook"
                )
                anomaly > 5500 -> CheckResult(
                    CheckStatus.INFO,
                    "prctl vs getpid 可疑：anomaly=$anomaly/10000（prctl=$prctlMedian getpid=$getpidMedian）"
                )
                else -> CheckResult(
                    CheckStatus.PASS,
                    "prctl vs getpid 正常（anomaly=$anomaly/10000）"
                )
            }
        } catch (e: Exception) {
            CheckResult(CheckStatus.INFO, "prctl vs getpid 检测异常：${e.message}")
        }
    }

    /**
     * faccessat 隐藏路径 kmalloc 侧信道
     *
     * SUSFS 的 susfs_sus_path_by_path() 对隐藏路径执行
     * kmalloc(PAGE_SIZE) + d_path() + list_for_each_entry_safe() + kfree()。
     * 对隐藏路径调用 faccessat 会触发额外的 slab 分配器慢路径开销。
     */
    private fun checkFaccessatTiming(): CheckResult {
        return try {
            val iterations = 5000
            val normalTimes = mutableListOf<Long>()
            val hiddenTimes = mutableListOf<Long>()

            // 测量正常路径
            SusfsDetectionUtil.nativeCheckFaccessatTiming(NORMAL_PATH, 200) // 预热
            repeat(3) {
                normalTimes.add(SusfsDetectionUtil.nativeCheckFaccessatTiming(NORMAL_PATH, iterations))
            }
            val normalMedian = normalTimes.sorted()[1] / iterations

            // 测量每个可能被隐藏的路径
            var maxRatio = 0.0
            var maxDiffNs = 0L
            var suspiciousPath = ""

            for (hiddenPath in HIDDEN_PATHS) {
                SusfsDetectionUtil.nativeCheckFaccessatTiming(hiddenPath, 200) // 预热
                val times = mutableListOf<Long>()
                repeat(3) {
                    times.add(SusfsDetectionUtil.nativeCheckFaccessatTiming(hiddenPath, iterations))
                }
                val hiddenMedian = times.sorted()[1] / iterations
                val ratio = if (normalMedian > 0) hiddenMedian.toDouble() / normalMedian else 0.0
                val diffNs = hiddenMedian - normalMedian

                Log.d(TAG, "faccessat [$hiddenPath] hidden=${hiddenMedian}ns normal=${normalMedian}ns ratio=${"%.2f".format(ratio)}")

                if (ratio > maxRatio) {
                    maxRatio = ratio
                    maxDiffNs = diffNs
                    suspiciousPath = hiddenPath
                }
            }

            when {
                maxRatio > 1.30 || maxDiffNs > 200 -> CheckResult(
                    CheckStatus.FAIL,
                    "faccessat 隐藏路径时延异常：$suspiciousPath 比正常路径慢 ${"%.0f".format(maxRatio * 100 - 100)}%（+${maxDiffNs}ns），" +
                            "暗示 SUSFS sus_path kmalloc 开销"
                )
                maxRatio > 1.15 -> CheckResult(
                    CheckStatus.INFO,
                    "faccessat 隐藏路径时延略高：$suspiciousPath 比正常路径慢 ${"%.0f".format(maxRatio * 100 - 100)}%"
                )
                else -> CheckResult(
                    CheckStatus.PASS,
                    "faccessat 隐藏路径时延正常（最大比值 ${"%.2f".format(maxRatio)}x）"
                )
            }
        } catch (e: Exception) {
            CheckResult(CheckStatus.INFO, "faccessat 时延检测异常：${e.message}")
        }
    }

    /**
     * CNTVCT_EL0 高精度 faccessat 侧信道
     *
     * 利用 ARM64 cntvct_el0 虚拟计数器，测量隐藏路径 vs 正常路径的 faccessat 延迟差异。
     * 排序后对位比较，异常次数超过阈值则判定存在 SUSFS。
     */
    private fun checkCntvctFaccessat(): CheckResult {
        return try {
            // 选择一个最可能被隐藏的路径
            val hiddenPath = "/system/addon.d"
            val result = SusfsDetectionUtil.nativeCheckFaccessatCntvct(hiddenPath, NORMAL_PATH)

            if (result == "alloc_failed") {
                return CheckResult(CheckStatus.INFO, "内存分配失败，无法执行 CNTVCT faccessat 检测")
            }
            if (result == "unsupported_arch") {
                return CheckResult(CheckStatus.INFO, "仅支持 ARM64 架构")
            }
            if (result == "invalid_args") {
                return CheckResult(CheckStatus.INFO, "参数无效")
            }

            val anomaly = result.substringAfter("anomaly=").substringBefore("|").toIntOrNull() ?: -1
            val hiddenMedian = result.substringAfter("hidden_median=").substringBefore("|").toLongOrNull() ?: -1
            val normalMedian = result.substringAfter("normal_median=").toLongOrNull() ?: -1

            Log.d(TAG, "CNTVCT faccessat anomaly=$anomaly hidden=$hiddenMedian normal=$normalMedian")

            if (anomaly < 0) {
                return CheckResult(CheckStatus.INFO, "CNTVCT faccessat 数据解析异常：$result")
            }

            when {
                anomaly > 7000 -> CheckResult(
                    CheckStatus.FAIL,
                    "CNTVCT faccessat 强阳性：隐藏路径 $hiddenPath 显著慢于正常路径（异常次数 $anomaly/10000），" +
                            "确认存在 SUSFS sus_path kmalloc 开销"
                )
                anomaly > 5500 -> CheckResult(
                    CheckStatus.INFO,
                    "CNTVCT faccessat 可疑：异常次数 $anomaly/10000（hidden=$hiddenMedian normal=$normalMedian）"
                )
                else -> CheckResult(
                    CheckStatus.PASS,
                    "CNTVCT faccessat 正常（异常次数 $anomaly/10000）"
                )
            }
        } catch (e: Exception) {
            CheckResult(CheckStatus.INFO, "CNTVCT faccessat 检测异常：${e.message}")
        }
    }

    /**
     * CNTVCT_EL0 高精度 stat 侧信道
     *
     * stat() 在内核中触发 vfs_getattr() -> susfs_sus_path_by_path()（路径匹配）
     * -> cp_new_stat() -> susfs_sus_kstat()（inode 匹配）。
     * 对隐藏文件调用 stat() 走 sus_path 拦截路径（kmalloc + 链表遍历）。
     */
    private fun checkCntvctStat(): CheckResult {
        return try {
            val hiddenPath = "/system/addon.d"
            val result = SusfsDetectionUtil.nativeCheckStatCntvct(hiddenPath, NORMAL_PATH)

            if (result == "alloc_failed") {
                return CheckResult(CheckStatus.INFO, "内存分配失败，无法执行 CNTVCT stat 检测")
            }
            if (result == "unsupported_arch") {
                return CheckResult(CheckStatus.INFO, "仅支持 ARM64 架构")
            }
            if (result == "invalid_args") {
                return CheckResult(CheckStatus.INFO, "参数无效")
            }

            val anomaly = result.substringAfter("anomaly=").substringBefore("|").toIntOrNull() ?: -1
            val hiddenMedian = result.substringAfter("hidden_median=").substringBefore("|").toLongOrNull() ?: -1
            val normalMedian = result.substringAfter("normal_median=").toLongOrNull() ?: -1

            Log.d(TAG, "CNTVCT stat anomaly=$anomaly hidden=$hiddenMedian normal=$normalMedian")

            if (anomaly < 0) {
                return CheckResult(CheckStatus.INFO, "CNTVCT stat 数据解析异常：$result")
            }

            when {
                anomaly > 7000 -> CheckResult(
                    CheckStatus.FAIL,
                    "CNTVCT stat 强阳性：隐藏路径显著慢于正常路径（异常次数 $anomaly/10000），" +
                            "确认存在 SUSFS sus_path/kstat 拦截开销"
                )
                anomaly > 5500 -> CheckResult(
                    CheckStatus.INFO,
                    "CNTVCT stat 可疑：异常次数 $anomaly/10000（hidden=$hiddenMedian normal=$normalMedian）"
                )
                else -> CheckResult(
                    CheckStatus.PASS,
                    "CNTVCT stat 正常（异常次数 $anomaly/10000）"
                )
            }
        } catch (e: Exception) {
            CheckResult(CheckStatus.INFO, "CNTVCT stat 检测异常：${e.message}")
        }
    }

    /**
     * /proc/self/maps 读取时延侧信道
     *
     * show_map_vma() 中调用 susfs_sus_maps()，
     * 需要 kmalloc(SUSFS_MAX_LEN_PATHNAME) + 遍历 LH_SUS_MAPS_SPOOFER。
     */
    private fun checkMapsTiming(): CheckResult {
        return try {
            val iterations = 500
            SusfsDetectionUtil.nativeCheckMapsReadTiming(20) // 预热

            val times = List(3) { SusfsDetectionUtil.nativeCheckMapsReadTiming(iterations).toDouble() }
            val medianNs = times.sorted()[1]
            val avgNs = medianNs / iterations

            Log.d(TAG, "maps_timing avg=${avgNs.toInt()}ns")

            // 正常系统读取 /proc/self/maps 约 50-200us，有 SUSFS sus_maps 时可能显著增加
            when {
                avgNs > 300000 -> CheckResult( // >300us/次
                    CheckStatus.FAIL,
                    "/proc/self/maps 读取时延显著偏高（${avgNs / 1000} us/次），存在 SUSFS sus_maps 拦截开销"
                )
                avgNs > 150000 -> CheckResult( // >150us/次
                    CheckStatus.INFO,
                    "/proc/self/maps 读取时延偏高（${avgNs / 1000} us/次）"
                )
                else -> CheckResult(
                    CheckStatus.PASS,
                    "/proc/self/maps 读取时延正常（${avgNs / 1000} us/次）"
                )
            }
        } catch (e: Exception) {
            CheckResult(CheckStatus.INFO, "/proc/self/maps 时延检测异常：${e.message}")
        }
    }

    // ==================== Layer 3: 一致性异常检测 ====================

    /**
     * linkat 错误码异常检测
     *
     * 源码级漏洞：susfs_change_error_no_by_pathname() 对 /data/ 路径的 linkat 操作
     * 返回 ENOENT 而非 EEXIST。正常系统：对已存在的文件执行 linkat(newname) 应返回 EEXIST。
     */
    private fun checkLinkatErrno(): CheckResult {
        return try {
            val testDir = "/data/data/${getPackageName()}/files"
            val dir = File(testDir)
            if (!dir.exists()) {
                dir.mkdirs()
            }

            val result = SusfsDetectionUtil.nativeCheckLinkatErrno(testDir)
            when (result) {
                1 -> CheckResult(
                    CheckStatus.FAIL,
                    "linkat 错误码异常：对已存在的 /data/ 路径文件创建硬链接返回 ENOENT（应为 EEXIST），" +
                            "确认命中 SUSFS 错误码替换漏洞"
                )
                0 -> CheckResult(
                    CheckStatus.PASS,
                    "linkat 错误码正常（返回 EEXIST）"
                )
                else -> CheckResult(
                    CheckStatus.INFO,
                    "linkat 检测异常（result=$result），可能权限不足"
                )
            }
        } catch (e: Exception) {
            CheckResult(CheckStatus.INFO, "linkat 错误码检测异常：${e.message}")
        }
    }

    /**
     * memfd_create EFAULT 异常检测
     *
     * SUSFS 的 sus_memfd 功能对特定命名模式（如 memfd:/jit-cache）的 memfd 故意返回 EFAULT。
     * 正常系统：memfd_create 应返回有效 fd 或 EINVAL/ENOSYS。
     */
    private fun checkMemfdErrno(): CheckResult {
        return try {
            val result = SusfsDetectionUtil.nativeCheckMemfdErrno()
            when (result) {
                1 -> CheckResult(
                    CheckStatus.FAIL,
                    "memfd_create('memfd:/jit-cache') 返回 EFAULT，确认命中 SUSFS sus_memfd 拦截"
                )
                0 -> CheckResult(
                    CheckStatus.PASS,
                    "memfd_create 行为正常（未返回 EFAULT）"
                )
                else -> CheckResult(
                    CheckStatus.INFO,
                    "memfd 检测异常（result=$result）"
                )
            }
        } catch (e: Exception) {
            CheckResult(CheckStatus.INFO, "memfd 检测异常：${e.message}")
        }
    }

    /**
     * mountinfo mnt_id 连续性异常检测
     *
     * mnt_id_reorder 功能会将 mount ID 重新编号为从第一个 mount ID 开始的严格连续整数（1, 2, 3...）。
     * 正常系统的 mount ID 是内核全局递增的，通常不连续。
     */
    private fun checkMntIdReorder(): CheckResult {
        return try {
            val result = SusfsDetectionUtil.nativeCheckMntIdReorder()
            when (result) {
                1 -> CheckResult(
                    CheckStatus.FAIL,
                    "mountinfo mnt_id 严格连续（前 10+ 条为 1,2,3...），" +
                            "疑似 SUSFS mnt_id_reorder 功能生效"
                )
                0 -> CheckResult(
                    CheckStatus.PASS,
                    "mountinfo mnt_id 正常（不连续）"
                )
                else -> CheckResult(
                    CheckStatus.INFO,
                    "mountinfo 读取失败（result=$result）"
                )
            }
        } catch (e: Exception) {
            CheckResult(CheckStatus.INFO, "mnt_id 检测异常：${e.message}")
        }
    }

    /**
     * uname 与 /proc/version 不一致检测
     *
     * spoof_uname 功能伪造 uname 返回的内核版本号，但 /proc/version 通常不受影响。
     */
    private fun checkUnameInconsistency(): CheckResult {
        return try {
            val result = SusfsDetectionUtil.nativeCheckUnameInconsistency()
            when (result) {
                1 -> CheckResult(
                    CheckStatus.FAIL,
                    "uname.release 与 /proc/version 不一致，疑似 SUSFS spoof_uname 功能生效"
                )
                0 -> CheckResult(
                    CheckStatus.PASS,
                    "uname 与 /proc/version 一致"
                )
                else -> CheckResult(
                    CheckStatus.INFO,
                    "uname 检测失败（result=$result）"
                )
            }
        } catch (e: Exception) {
            CheckResult(CheckStatus.INFO, "uname 检测异常：${e.message}")
        }
    }

    // ==================== Layer 4: 进程指纹 ====================

    /**
     * ksu_susfs 进程 cmdline 监控
     *
     * ksu_susfs 被调用时，/proc/<pid>/cmdline 会暴露完整参数。
     */
    private fun checkSusfsProcess(): CheckResult {
        return try {
            val hasProcess = hasProcess("ksu_susfs")
            if (hasProcess) {
                CheckResult(
                    CheckStatus.FAIL,
                    "检测到 ksu_susfs 进程运行"
                )
            } else {
                CheckResult(
                    CheckStatus.PASS,
                    "未检测到 ksu_susfs 进程"
                )
            }
        } catch (e: Exception) {
            CheckResult(CheckStatus.INFO, "进程检测异常：${e.message}")
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

    private fun getPackageName(): String {
        return try {
            // 通过 /proc/self/cmdline 获取包名
            val cmdline = File("/proc/self/cmdline").readText().trimEnd('\u0000')
            cmdline.ifEmpty { "qpdb.env.check" }
        } catch (e: Exception) {
            "qpdb.env.check"
        }
    }
}

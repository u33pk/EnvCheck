package qpdb.env.check.checkers

import android.util.Log
import qpdb.env.check.model.CheckItem
import qpdb.env.check.model.CheckResult
import qpdb.env.check.model.CheckStatus
import qpdb.env.check.model.Checkable
import qpdb.env.check.utils.FileUtil
import qpdb.env.check.utils.KsuDetectionUtil
import qpdb.env.check.utils.PropertyUtil.getProp
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader

/**
 * KernelSU 检测器（v2）
 *
 * 基于 doc/root_detection_attack_surface.md 实现的多维度联合检测方案。
 * 重点强化**侧信道检测**（时间侧信道 + 行为侧信道），与静态特征形成互补。
 *
 * 检测维度：
 * 1. 文件系统痕迹（stat）
 * 2. 进程痕迹（ksud 扫描）
 * 3. SELinux 上下文（self + proc 扫描）
 * 4. 系统属性
 * 5. 内核日志
 * 6. 侧信道 - faccessat 延迟差异
 * 7. 侧信道 - execve 延迟差异
 * 8. 侧信道 - syscall 循环开销（tracepoint）
 * 9. 侧信道 - init.rc stat 虚增
 * 10. 侧信道 - access("/system/bin/su") 返回值差异
 * 11. 侧信道 - seccomp 状态
 * 12. 侧信道 - [ksu_driver] fd 扫描
 * 13. 综合评估
 */
class KernelSUChecker : Checkable {

    companion object {
        private const val TAG = "KernelSUChecker"

        // KernelSU 相关系统属性
        private val KSU_PROPS = listOf(
            "ro.kernelsu.version",
            "persist.ksu.enabled",
            "persist.ksu.allowlist",
            "ro.boot.kernelsu",
            "ro.boot.kernelsu.version",
            "persist.ksu.manager"
        )
    }

    override val categoryName: String = "KernelSU 检测"

    override fun checkList(): List<CheckItem> = listOf(
        CheckItem(name = "KSU 守护进程", checkPoint = "ksu_process", description = "等待检测..."),
        CheckItem(name = "SELinux 上下文", checkPoint = "ksu_selinux", description = "等待检测..."),
        CheckItem(name = "KSU 系统属性", checkPoint = "ksu_props", description = "等待检测..."),
        CheckItem(name = "内核日志痕迹", checkPoint = "ksu_kmsg", description = "等待检测..."),
        CheckItem(name = "侧信道 - faccessat 延迟差异", checkPoint = "ksu_sc_faccessat", description = "等待检测..."),
        CheckItem(name = "侧信道 - execve 延迟差异", checkPoint = "ksu_sc_execve", description = "等待检测..."),
        CheckItem(name = "侧信道 - syscall 循环开销", checkPoint = "ksu_sc_syscall_loop", description = "等待检测..."),
        CheckItem(name = "侧信道 - init.rc stat 虚增", checkPoint = "ksu_sc_initrc", description = "等待检测..."),
        CheckItem(name = "侧信道 - access(su) 返回值差异", checkPoint = "ksu_sc_access_su", description = "等待检测..."),
        CheckItem(name = "侧信道 - seccomp 状态", checkPoint = "ksu_sc_seccomp", description = "等待检测..."),
        CheckItem(name = "侧信道 - [ksu_driver] fd 扫描", checkPoint = "ksu_sc_fd", description = "等待检测..."),
        CheckItem(name = "侧信道 - CNTVCT 高精度 syscall 计时", checkPoint = "ksu_sc_cntvct", description = "等待检测..."),
        CheckItem(name = "侧信道 - setresuid 耗时异常", checkPoint = "ksu_sc_setresuid", description = "等待检测..."),
        CheckItem(name = "侧信道 - App 冷启动延迟", checkPoint = "ksu_sc_startup", description = "等待检测...")
    )

    override fun runCheck(): List<CheckItem> {
        Log.i(TAG, "runCheck() 开始执行 KernelSU v2 检测")
        val items = checkList().toMutableList()

        val weights = mapOf(
            "ksu_process" to 2,
            "ksu_selinux" to 3,
            "ksu_props" to 1,
            "ksu_kmsg" to 1,
            "ksu_sc_faccessat" to 3,
            "ksu_sc_execve" to 3,
            "ksu_sc_syscall_loop" to 2,
            "ksu_sc_initrc" to 2,
            "ksu_sc_access_su" to 3,
            "ksu_sc_seccomp" to 1,
            "ksu_sc_fd" to 2,
            "ksu_sc_cntvct" to 0,
            "ksu_sc_setresuid" to 1,
            "ksu_sc_startup" to 1
        )

        fun applyResult(checkPoint: String, result: CheckResult) {
            items.find { it.checkPoint == checkPoint }?.let {
                it.status = result.status
                it.description = result.description
            }
            Log.i(TAG, "[$checkPoint] ${result.status}: ${result.description}")
        }

        try {
            applyResult("ksu_process", checkKsuProcess())
            applyResult("ksu_selinux", checkSelinuxContext())
            applyResult("ksu_props", checkKsuProperties())
            applyResult("ksu_kmsg", checkKernelLogs())
            applyResult("ksu_sc_faccessat", checkSideChannelFaccessat())
            applyResult("ksu_sc_execve", checkSideChannelExecve())
            applyResult("ksu_sc_syscall_loop", checkSideChannelSyscallLoop())
            applyResult("ksu_sc_initrc", checkSideChannelInitRc())
            applyResult("ksu_sc_access_su", checkSideChannelAccessSu())
            applyResult("ksu_sc_seccomp", checkSideChannelSeccomp())
            applyResult("ksu_sc_fd", checkSideChannelKsuFd())
            applyResult("ksu_sc_cntvct", checkSideChannelCntvctTiming())
            applyResult("ksu_sc_setresuid", checkSideChannelSetresuid())
            applyResult("ksu_sc_startup", checkSideChannelAppStartup())
        } catch (e: Exception) {
            Log.e(TAG, "检测过程异常", e)
        }

        return items
    }

    // ==================== 静态特征检测 ====================

    private fun checkKsuProcess(): CheckResult {
        return try {
            val hasKsud = hasProcess("ksud")
            when {
                hasKsud -> CheckResult(CheckStatus.FAIL, "检测到 ksud 守护进程运行")
                else -> CheckResult(CheckStatus.PASS, "未检测到 ksud 进程")
            }
        } catch (e: Exception) {
            CheckResult(CheckStatus.FAIL, "检测异常：${e.message}")
        }
    }

    private fun checkSelinuxContext(): CheckResult {
        return try {
            val selfContext = File("/proc/self/attr/current").readText().trim()
            if (selfContext.contains("ksu") || selfContext.contains("su:s0")) {
                return CheckResult(CheckStatus.FAIL, "当前进程 SELinux 上下文异常：$selfContext")
            }

            var ksuCount = 0
            val procDir = File("/proc")
            val pidDirs = procDir.listFiles { file ->
                file.isDirectory && file.name.matches(Regex("\\d+"))
            } ?: emptyArray()

            for (pidDir in pidDirs.take(80)) {
                try {
                    val ctx = File(pidDir, "attr/current").readText().trim()
                    if (ctx.contains("ksu") || ctx.contains("su:s0")) ksuCount++
                } catch (_: Exception) {
                }
            }

            when {
                ksuCount > 0 -> CheckResult(CheckStatus.FAIL, "发现 $ksuCount 个进程具有 KSU SELinux 上下文")
                else -> CheckResult(CheckStatus.PASS, "SELinux 上下文正常")
            }
        } catch (e: Exception) {
            CheckResult(CheckStatus.FAIL, "检测异常：${e.message}")
        }
    }

    private fun checkKsuProperties(): CheckResult {
        return try {
            val found = KSU_PROPS.mapNotNull { prop ->
                getProp(prop)?.let { "$prop=$it" }
            }
            if (found.isNotEmpty()) {
                CheckResult(CheckStatus.FAIL, "发现 KSU 属性：${found.joinToString(", ")}")
            } else {
                CheckResult(CheckStatus.PASS, "未检测到 KSU 相关属性")
            }
        } catch (e: Exception) {
            CheckResult(CheckStatus.FAIL, "检测异常：${e.message}")
        }
    }

    private fun checkKernelLogs(): CheckResult {
        return try {
            val process = Runtime.getRuntime().exec("dmesg")
            val reader = BufferedReader(InputStreamReader(process.inputStream))
            val keywords = listOf("KernelSU", "kernelsu", "ksu_manager", "ksud", "Crowning manager",
                "reboot kprobe registered", "hook_manager", "sys_call_table", "dispatcher installed")
            var count = 0
            var line: String?
            while (reader.readLine().also { line = it } != null) {
                val lower = line!!.lowercase()
                if (keywords.any { lower.contains(it.lowercase()) }) count++
            }
            reader.close()

            when {
                count >= 3 -> CheckResult(CheckStatus.FAIL, "内核日志中发现 $count 处 KernelSU 相关记录")
                count > 0 -> CheckResult(CheckStatus.INFO, "内核日志中发现 $count 处可疑记录")
                else -> CheckResult(CheckStatus.PASS, "内核日志未发现 KernelSU 痕迹")
            }
        } catch (e: Exception) {
            CheckResult(CheckStatus.INFO, "无法读取内核日志：${e.message}")
        }
    }

    // ==================== 侧信道检测（重中之重） ====================

    /**
     * 侧信道：faccessat("/system/bin/su") 与对照路径的延迟差异
     *
     * KernelSU 的 sucompat 对 allowlist App 会额外执行路径匹配和重定向，
     * 对非 allowlist App 也会执行 allowlist bitmap 查询，引入 ~10-200ns 的额外开销。
     * 通过高频调用并对比 su 路径与非 existent 路径的耗时差异来探测 hook。
     */
    private fun checkSideChannelFaccessat(): CheckResult {
        return try {
            val iterations = 5000
            val suPath = "/system/bin/su"
            val dummyPath = "/system/bin/xyz_nonexistent_${System.nanoTime()}"

            // 预热，避免缓存干扰
            KsuDetectionUtil.nativeCheckAccessTiming(suPath, 100)
            KsuDetectionUtil.nativeCheckAccessTiming(dummyPath, 100)

            // 各测 3 轮取中位数，减少抖动
            val suTimes = List(3) { KsuDetectionUtil.nativeCheckAccessTiming(suPath, iterations).toDouble() }
            val dummyTimes = List(3) { KsuDetectionUtil.nativeCheckAccessTiming(dummyPath, iterations).toDouble() }

            val suMedian = suTimes.sorted()[1]
            val dummyMedian = dummyTimes.sorted()[1]

            val suAvgNs = suMedian / iterations
            val dummyAvgNs = dummyMedian / iterations
            val diffNs = suAvgNs - dummyAvgNs

            Log.d(TAG, "faccessat su_avg=${suAvgNs.toInt()}ns dummy_avg=${dummyAvgNs.toInt()}ns diff=${diffNs.toInt()}ns")

            when {
                diffNs > 80 -> CheckResult(
                    CheckStatus.FAIL,
                    "faccessat('/system/bin/su') 显著慢于对照路径（慢 ${diffNs.toInt()} ns/次），存在 sucompat hook 迹象"
                )
                diffNs > 30 -> CheckResult(
                    CheckStatus.INFO,
                    "faccessat('/system/bin/su') 略慢于对照路径（慢 ${diffNs.toInt()} ns/次）"
                )
                else -> CheckResult(
                    CheckStatus.PASS,
                    "faccessat 延迟差异正常（su=${suAvgNs.toInt()}ns dummy=${dummyAvgNs.toInt()}ns）"
                )
            }
        } catch (e: Exception) {
            CheckResult(CheckStatus.INFO, "侧信道检测异常：${e.message}")
        }
    }

    /**
     * 侧信道：execve("/system/bin/su") 的延迟峰值
     *
     * KernelSU 的 sucompat 在 allowlist App 调用 execve("/system/bin/su") 时，
     * 会执行 escape_with_root_profile()（cred 重构、SELinux 切换、seccomp 关闭等），
     * 总耗时可达微秒到毫秒级，远超普通 execve。
     */
    private fun checkSideChannelExecve(): CheckResult {
        return try {
            val result = KsuDetectionUtil.nativeCheckExecveTiming()
            if (result == "fork_failed") {
                return CheckResult(CheckStatus.INFO, "fork 失败，无法测量 execve 延迟")
            }

            val suAvg = result.substringAfter("su_avg=").substringBefore("|").toLongOrNull() ?: -1
            val shAvg = result.substringAfter("sh_avg=").toLongOrNull() ?: -1

            Log.d(TAG, "execve su_avg=${suAvg}us sh_avg=${shAvg}us")

            if (suAvg < 0 || shAvg < 0) {
                return CheckResult(CheckStatus.INFO, "execve 计时数据异常：$result")
            }

            val ratio = if (shAvg > 0) suAvg.toDouble() / shAvg else 0.0
            val diffUs = suAvg - shAvg

            when {
                ratio > 5.0 && diffUs > 500 -> CheckResult(
                    CheckStatus.FAIL,
                    "execve('/system/bin/su') 出现显著延迟峰值（su=${suAvg}us sh=${shAvg}us 比值 ${"%.1f".format(ratio)}x），强烈暗示 sucompat hook"
                )
                ratio > 2.0 && diffUs > 200 -> CheckResult(
                    CheckStatus.INFO,
                    "execve('/system/bin/su') 延迟偏高（su=${suAvg}us sh=${shAvg}us 比值 ${"%.1f".format(ratio)}x）"
                )
                else -> CheckResult(
                    CheckStatus.PASS,
                    "execve 延迟正常（su=${suAvg}us sh=${shAvg}us 比值 ${"%.1f".format(ratio)}x）"
                )
            }
        } catch (e: Exception) {
            CheckResult(CheckStatus.INFO, "execve 侧信道检测异常：${e.message}")
        }
    }

    /**
     * 侧信道：tracepoint 标记导致的 syscall 全局延迟
     *
     * KernelSU 会对 allowlist 进程设置 TIF_SYSCALL_TRACEPOINT，
     * 导致每次系统调用进入时触发 ksu_sys_enter_handler。
     * 通过循环调用 getpid() 测量总耗时，异常高的值可能暗示被标记。
     */
    private fun checkSideChannelSyscallLoop(): CheckResult {
        return try {
            val iterations = 50000
            KsuDetectionUtil.nativeCheckSyscallLoop(1000) // 预热

            val times = List(3) { KsuDetectionUtil.nativeCheckSyscallLoop(iterations).toDouble() }
            val medianNs = times.sorted()[1]
            val avgNs = medianNs / iterations

            Log.d(TAG, "syscall_loop median=${medianNs.toInt()}ns avg_per_call=${avgNs.toInt()}ns")

            // 实测：各机型基线 130-200ns，在 Zygisk 注入场景下可能观察到明显差异
            when {
                avgNs > 250 -> CheckResult(
                    CheckStatus.FAIL,
                    "syscall 循环开销异常高（${avgNs.toInt()} ns/次），可能存在 tracepoint / Zygisk hook"
                )
                avgNs > 200 -> CheckResult(
                    CheckStatus.INFO,
                    "syscall 循环开销偏高（${avgNs.toInt()} ns/次）"
                )
                else -> CheckResult(
                    CheckStatus.PASS,
                    "syscall 循环开销正常（${avgNs.toInt()} ns/次）"
                )
            }
        } catch (e: Exception) {
            CheckResult(CheckStatus.INFO, "syscall 侧信道检测异常：${e.message}")
        }
    }

    /**
     * 侧信道：init.rc 的 stat 大小与实际读取大小不一致
     *
     * KernelSU 通过 read hook 向 init.rc 追加启动脚本，同时通过 fstat hook 虚增 st_size。
     * 对比 stat() 得到的 size 和实际 read() 到的字节数即可发现异常。
     */
    private fun checkSideChannelInitRc(): CheckResult {
        return try {
            val result = KsuDetectionUtil.nativeCheckInitRcStat()
            if (result == "stat_failed" || result == "open_failed") {
                return CheckResult(CheckStatus.INFO, "无法访问 init.rc（$result）")
            }

            val statSize = result.substringAfter("stat=").substringBefore("|").toLongOrNull() ?: -1
            val readSize = result.substringAfter("read=").toLongOrNull() ?: -1

            Log.d(TAG, "initRc stat=$statSize read=$readSize")

            if (statSize < 0 || readSize < 0) {
                return CheckResult(CheckStatus.INFO, "init.rc 数据解析异常：$result")
            }

            when {
                statSize > readSize -> CheckResult(
                    CheckStatus.FAIL,
                    "init.rc stat 大小($statSize) 大于实际读取大小($readSize)，存在 fstat/read hook 虚增迹象"
                )
                else -> CheckResult(
                    CheckStatus.PASS,
                    "init.rc 大小一致（stat=$statSize read=$readSize）"
                )
            }
        } catch (e: Exception) {
            CheckResult(CheckStatus.INFO, "init.rc 侧信道检测异常：${e.message}")
        }
    }

    /**
     * 侧信道：access("/system/bin/su") 的返回值差异
     *
     * 非 allowlist App 调用 access("/system/bin/su") 应返回失败（文件不存在）。
     * 如果 KernelSU sucompat 将路径重定向到 /system/bin/sh，则 access 会返回成功。
     * 结合 stat() 结果判断：stat 不存在但 access 成功 = 强侧信道信号。
     */
    private fun checkSideChannelAccessSu(): CheckResult {
        return try {
            val suExistsByStat = FileUtil.fileExists("/system/bin/su")
            val accessResult = KsuDetectionUtil.nativeCheckAccessSu() == 1

            Log.d(TAG, "accessSu stat=$suExistsByStat access=$accessResult")

            when {
                !suExistsByStat && accessResult -> CheckResult(
                    CheckStatus.FAIL,
                    "su 文件 stat 不存在但 access 返回成功，确认存在 sucompat 路径重定向"
                )
                suExistsByStat && accessResult -> CheckResult(
                    CheckStatus.INFO,
                    "/system/bin/su 真实存在且可访问（可能是其他 root 方案）"
                )
                else -> CheckResult(
                    CheckStatus.PASS,
                    "access('/system/bin/su') 行为正常（stat=$suExistsByStat access=$accessResult）"
                )
            }
        } catch (e: Exception) {
            CheckResult(CheckStatus.INFO, "access su 侧信道检测异常：${e.message}")
        }
    }

    /**
     * 侧信道：seccomp 状态
     *
     * 普通 App 通常为 Seccomp: 2（filter mode）。
     * KernelSU 的 escape_with_root_profile() 会将其置为 0。
     * 当前进程如果已经是 0，说明可能已被 root 或处于异常状态。
     */
    private fun checkSideChannelSeccomp(): CheckResult {
        return try {
            val seccomp = KsuDetectionUtil.nativeCheckSeccompStatus()
            when (seccomp) {
                0 -> CheckResult(CheckStatus.FAIL, "seccomp 状态为 0（已被关闭），这是 KernelSU grant_root 的典型指纹")
                2 -> CheckResult(CheckStatus.PASS, "seccomp 状态正常（filter mode: 2）")
                1 -> CheckResult(CheckStatus.INFO, "seccomp 状态为 strict mode: 1")
                else -> CheckResult(CheckStatus.INFO, "seccomp 状态未知（读取值=$seccomp）")
            }
        } catch (e: Exception) {
            CheckResult(CheckStatus.INFO, "seccomp 检测异常：${e.message}")
        }
    }

    /**
     * 侧信道：扫描 /proc/self/fd/ 中是否存在 [ksu_driver] 或 [ksu_fdwrapper]
     */
    private fun checkSideChannelKsuFd(): CheckResult {
        return try {
            val found = KsuDetectionUtil.nativeCheckKsuFd()
            if (found) {
                CheckResult(CheckStatus.FAIL, "在 /proc/self/fd 中发现 [ksu_driver] 或 [ksu_fdwrapper] 匿名 inode fd")
            } else {
                CheckResult(CheckStatus.PASS, "未在当前进程 fd 表中发现 KernelSU 特殊 fd")
            }
        } catch (e: Exception) {
            CheckResult(CheckStatus.INFO, "fd 扫描异常：${e.message}")
        }
    }

    /**
     * 侧信道：CNTVCT_EL0 高精度 syscall 计时
     *
     * 基于 doc/ksu_侧信道检测.md 实现：
     * 用 ARM64 虚拟计数器分别测量 faccessat("/system/bin/su") 与基线 fchownat
     * 各 10000 次，排序后对位比较。若 faccessat[i] > fchownat[i] + 1 的异常次数
     * 超过阈值（7000），则判定存在 sucompat hook。
     */
    private fun checkSideChannelCntvctTiming(): CheckResult {
        return try {
            val result = KsuDetectionUtil.nativeCheckTimingSideChannel()
            if (result == "alloc_failed") {
                return CheckResult(CheckStatus.INFO, "内存分配失败，无法执行 CNTVCT 侧信道检测")
            }
            if (result == "unsupported_arch") {
                return CheckResult(CheckStatus.INFO, "仅支持 ARM64 架构")
            }

            val anomaly = result.substringAfter("anomaly=").substringBefore("|").toIntOrNull() ?: -1
            val testMedian = result.substringAfter("test_median=").substringBefore("|").toLongOrNull() ?: -1
            val baseMedian = result.substringAfter("base_median=").toLongOrNull() ?: -1

            Log.d(TAG, "CNTVCT anomaly=$anomaly test_median=$testMedian base_median=$baseMedian")

            if (anomaly < 0) {
                return CheckResult(CheckStatus.INFO, "CNTVCT 数据解析异常：$result")
            }

            when {
                anomaly > 7000 -> CheckResult(
                    CheckStatus.FAIL,
                    "CNTVCT 侧信道强阳性：faccessat 显著慢于 fchownat（异常次数 $anomaly/10000），确认存在 sucompat hook"
                )
                anomaly > 5000 -> CheckResult(
                    CheckStatus.INFO,
                    "CNTVCT 侧信道可疑：异常次数 $anomaly/10000，建议结合其他维度判断"
                )
                else -> CheckResult(
                    CheckStatus.PASS,
                    "CNTVCT 侧信道正常（异常次数 $anomaly/10000，test=$testMedian base=$baseMedian）"
                )
            }
        } catch (e: Exception) {
            CheckResult(CheckStatus.INFO, "CNTVCT 侧信道检测异常：${e.message}")
        }
    }

    /**
     * 侧信道：setresuid 系统调用耗时
     *
     * KernelSU 的 ksu_handle_setresuid 会在权限检查前执行 kernel_umount，
     * 对非 allowlist App 遍历 mount_list 并 umount，导致 setresuid 耗时显著增加。
     */
    private fun checkSideChannelSetresuid(): CheckResult {
        return try {
            val iterations = 1000
            KsuDetectionUtil.nativeCheckSetresuidTiming(100) // 预热

            val times = List(3) { KsuDetectionUtil.nativeCheckSetresuidTiming(iterations).toDouble() }
            val medianNs = times.sorted()[1]
            val avgNs = medianNs / iterations

            Log.d(TAG, "setresuid avg=${avgNs.toInt()}ns")

            // 实测数据：KSU root 旗舰机 146ns、无root 252ns、低端机(Magisk) 1168ns
            // 该指标对 Zygisk 等方案可能呈现差异，保留阈值判定
            when {
                avgNs > 2000 -> CheckResult(
                    CheckStatus.FAIL,
                    "setresuid 系统调用耗时显著异常（${avgNs.toInt()} ns/次），存在 mount 遍历或 hook 迹象"
                )
                avgNs > 1000 -> CheckResult(
                    CheckStatus.INFO,
                    "setresuid 系统调用耗时偏高（${avgNs.toInt()} ns/次）"
                )
                else -> CheckResult(
                    CheckStatus.PASS,
                    "setresuid 系统调用耗时正常（${avgNs.toInt()} ns/次）"
                )
            }
        } catch (e: Exception) {
            CheckResult(CheckStatus.INFO, "setresuid 侧信道检测异常：${e.message}")
        }
    }

    /**
     * 侧信道：App 冷启动延迟
     *
     * 通过 /proc/self/stat 的 starttime 计算从进程 fork 到 Application.onCreate 的耗时。
     * 若 KernelSU 的 kernel_umount 遍历了较长的 mount_list，该值可能显著增大。
     */
    private fun checkSideChannelAppStartup(): CheckResult {
        return try {
            val startupMs = qpdb.env.check.EnvCheckApp.getInstance().processStartupAgeMs
            if (startupMs < 0) {
                return CheckResult(CheckStatus.INFO, "无法读取进程启动时间")
            }

            Log.d(TAG, "app_startup age=${startupMs}ms")

            // 保留阈值判定，在部分注入场景下可能观察到差异
            when {
                startupMs > 3000 -> CheckResult(
                    CheckStatus.FAIL,
                    "App 冷启动延迟显著偏高（${startupMs} ms），可能存在 Zygisk / kernel_umount 导致的启动开销"
                )
                startupMs > 1500 -> CheckResult(
                    CheckStatus.INFO,
                    "App 冷启动延迟偏高（${startupMs} ms）"
                )
                else -> CheckResult(
                    CheckStatus.PASS,
                    "App 冷启动延迟正常（${startupMs} ms）"
                )
            }
        } catch (e: Exception) {
            CheckResult(CheckStatus.INFO, "App 启动侧信道检测异常：${e.message}")
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

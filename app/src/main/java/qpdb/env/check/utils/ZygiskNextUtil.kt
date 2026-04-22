package qpdb.env.check.utils

/**
 * Zygisk Next 检测工具类
 * 专注于时间侧信道检测，基于 doc/timing_detection_schemes_analysis.md 实现
 */
object ZygiskNextUtil {
    init {
        System.loadLibrary("check")
    }

    /**
     * Zygote fork 时间侧信道检测
     * 测量 fork + exec("/system/bin/sh", "-c", "exit 0") 的总耗时。
     * Zygisk Next 注入后，每次 fork 都会经过 hook 的 fork_pre()、sanitize_fds() 等逻辑，
     * 导致 fork-exec 延迟显著增加（正常 0.5-2ms，有 Zygisk 2-10ms+）。
     * @return 格式：median_us=xxx|mean_us=xxx|stddev_us=xxx|min_us=xxx|max_us=xxx|p90_us=xxx
     *         或 fork_failed
     */
    @JvmStatic
    external fun nativeCheckZygoteForkTiming(): String

    /**
     * 双进程对比侧信道（方案 A 简化版）
     * 对比 fork+exec（正常路径，含 Zygisk hook）与 fork+exit（最小路径）的耗时差异。
     * 若 Zygisk  hook 了 execve 或 specialize 路径，fork+exec 会显著慢于 fork+exit。
     * @return 格式：exec_median_us=xxx|exit_median_us=xxx|diff_us=xxx|exec_samples=xxx
     *         或 fork_failed
     */
    @JvmStatic
    external fun nativeCheckForkExecVsExit(): String

    /**
     * 多阶段时序检测（方案 B）
     * 读取 /proc/self/stat 的 starttime，计算进程从内核创建到应用层首次执行的"空白期"。
     * @return 格式：starttime_ms=xxx|clk_tck=xxx
     */
    @JvmStatic
    external fun nativeCheckAppStartup(): String

    /**
     * 统计分布分析（方案 C）
     * 采集 30 次 fork+exec 样本，计算统计特征：
     * - 均值、标准差、变异系数（CV）
     * - 双峰分布检测（快路径 vs 慢路径）
     * Zygisk 引入的模块加载时间不稳定，会导致 CV 增大和双峰分布。
     * @return 格式：mean_us=xxx|stddev_us=xxx|cv=xxx|fast_count=xxx|slow_count=xxx|samples=xxx
     *         或 fork_failed
     */
    @JvmStatic
    external fun nativeCheckForkDistribution(): String
}

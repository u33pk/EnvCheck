package qpdb.env.check.utils

/**
 * SUSFS 检测工具类
 * 提供 JNI native 方法进行 SUSFS 深度检测
 *
 * 基于 doc/SUSFS_Detection_Report.md 实现的多层级检测框架：
 * - Layer 1: 直接检测（prctl 返回值、文件系统痕迹、内核符号）
 * - Layer 2: 高精度时间侧信道（faccessat kmalloc、stat、/proc/self/maps 时延）
 * - Layer 3: 一致性异常检测（linkat errno、memfd EFAULT、mnt_id 重排、uname 不一致）
 */
object SusfsDetectionUtil {
    init {
        System.loadLibrary("check")
    }

    // ================== Layer 1: 直接检测 ==================

    /**
     * prctl(0xDEADBEEF) 返回值侧信道
     * @return 0=无KSU, 1=有KSU(SUSFS前提条件), -1=异常
     */
    @JvmStatic
    external fun nativeCheckPrctlReturn(): Int

    // ================== Layer 2: 时间侧信道 ==================

    /**
     * prctl 执行路径长度侧信道
     * @param iterations 循环次数
     * @return 总耗时（纳秒）
     */
    @JvmStatic
    external fun nativeCheckPrctlTiming(iterations: Int): Long

    /**
     * faccessat 隐藏路径 kmalloc 侧信道
     * @param path 要检测的路径
     * @param iterations 循环次数
     * @return 总耗时（纳秒）
     */
    @JvmStatic
    external fun nativeCheckFaccessatTiming(path: String, iterations: Int): Long

    /**
     * /proc/self/maps 读取时延侧信道
     * @param iterations 循环次数
     * @return 总耗时（纳秒）
     */
    @JvmStatic
    external fun nativeCheckMapsReadTiming(iterations: Int): Long

    /**
     * CNTVCT_EL0 高精度 faccessat 侧信道
     * @param hiddenPath 可能被隐藏的路径
     * @param normalPath 确定存在的正常路径
     * @return 格式：anomaly=xxx|hidden_median=xxx|normal_median=xxx
     *         或 alloc_failed / unsupported_arch / invalid_args
     */
    @JvmStatic
    external fun nativeCheckFaccessatCntvct(hiddenPath: String, normalPath: String): String

    /**
     * CNTVCT_EL0 高精度 stat 侧信道
     * @param hiddenPath 可能被隐藏的路径
     * @param normalPath 确定存在的正常路径
     * @return 格式：anomaly=xxx|hidden_median=xxx|normal_median=xxx
     *         或 alloc_failed / unsupported_arch / invalid_args
     */
    @JvmStatic
    external fun nativeCheckStatCntvct(hiddenPath: String, normalPath: String): String

    /**
     * CNTVCT_EL0 高精度 prctl 侧信道
     *
     * 对比 prctl(0xDEADBEEF) vs prctl(0xDEADBEEA) 的时延差异。
     * 有 KSU 时 DEADBEEF 进入 handler 更慢，无 KSU 时两者相同。
     *
     * @return 格式：deadbeef_median=xxx|deadbeea_median=xxx|anomaly=xxx
     *         或 alloc_failed / unsupported_arch
     */
    @JvmStatic
    external fun nativeCheckPrctlCntvct(): String

    /**
     * CNTVCT_EL0 高精度 prctl vs getpid 对比
     *
     * 比较 prctl(0xDEADBEEF) 与 getpid() 的时延差异。
     * 有 KSU 时 prctl 走 hook 路径更慢。
     *
     * @return 格式：prctl_median=xxx|getpid_median=xxx|anomaly=xxx
     *         或 alloc_failed / unsupported_arch
     */
    @JvmStatic
    external fun nativeCheckPrctlVsGetpid(): String

    // ================== Layer 3: 一致性异常检测 ==================

    /**
     * linkat 错误码异常检测
     * @param testDir 测试目录路径（app 私有目录）
     * @return 0=正常(EEXIST), 1=SUSFS异常(ENOENT), -1=其他错误
     */
    @JvmStatic
    external fun nativeCheckLinkatErrno(testDir: String): Int

    /**
     * memfd_create EFAULT 异常检测
     * @return 0=正常, 1=SUSFS异常(EFAULT), -1=其他
     */
    @JvmStatic
    external fun nativeCheckMemfdErrno(): Int

    /**
     * mountinfo mnt_id 连续性异常检测
     * @return 0=正常(不连续), 1=SUSFS异常(严格连续), -1=读取失败
     */
    @JvmStatic
    external fun nativeCheckMntIdReorder(): Int

    /**
     * uname 与 /proc/version 不一致检测
     * @return 0=一致, 1=不一致(spoof_uname), -1=读取失败
     */
    @JvmStatic
    external fun nativeCheckUnameInconsistency(): Int
}

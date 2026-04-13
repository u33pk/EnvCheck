package qpdb.env.check.utils

/**
 * APatch / KernelPatch 侧信道检测工具类
 * 提供 JNI native 方法进行高精度系统调用计时和行为检测
 */
object ApatchDetectionUtil {
    init {
        System.loadLibrary("check")
    }

    /**
     * 调用 syscall(45) 并返回结果值
     * @param cmd 传递给系统调用的命令参数
     * @return 系统调用返回值
     */
    @JvmStatic
    external fun nativeCheckSyscall45Return(cmd: Long): Int

    /**
     * 调用 getpid() 并返回结果（基线对照）
     * @return 当前进程 PID
     */
    @JvmStatic
    external fun nativeCheckGetpidReturn(): Int

    /**
     * 测量 syscall(45) 的总耗时（纳秒）
     * @param cmd 传递给系统调用的命令参数
     * @param iterations 循环次数
     * @return 总耗时（纳秒）
     */
    @JvmStatic
    external fun nativeCheckSyscall45Timing(cmd: Long, iterations: Int): Long

    /**
     * 测量相邻合法 syscall（ftruncate，非法参数 -1）的总耗时（纳秒，基线对照）
     * @param iterations 循环次数
     * @return 总耗时（纳秒）
     */
    @JvmStatic
    external fun nativeCheckBaselineTiming(iterations: Int): Long

    /**
     * 基于 CNTVCT_EL0 的高精度 syscall(45) 侧信道检测
     * 测量 syscall(45, "", 0x1) 与基线 ftruncate(-1) 各 10000 次并排序对位比较。
     * @return 格式：anomaly=xxx|threshold=7000|test_median=xxx|base_median=xxx
     *         或 alloc_failed / unsupported_arch
     */
    @JvmStatic
    external fun nativeCheckSupercallTiming(): String

    /**
     * CNTVCT_EL0 高精度侧信道：有效 cmd vs 无效 cmd
     * 测量 syscall(45, "", 0x1000) 与 syscall(45, "", 0x1) 各 10000 次并排序对位比较。
     * @return 格式：anomaly=xxx|threshold=7000|valid_median=xxx|invalid_median=xxx
     *         或 alloc_failed / unsupported_arch
     */
    @JvmStatic
    external fun nativeCheckSupercallValidVsInvalid(): String

    /**
     * SuperKey 长度时间侧信道检测（研究性）
     * 测量 syscall(45, fake_key_64, 0x1000) 与 syscall(45, fake_key_64, 0x1)
     * 各 100000 次，通过中位数差分推断 auth_superkey() 的耗时信号。
     * @return 格式：delta=xxx|baseline=xxx|test=xxx|samples=xxx
     *         或 alloc_failed / unsupported_arch
     */
    @JvmStatic
    external fun nativeCheckSuperkeyLengthSideChannel(): String
}

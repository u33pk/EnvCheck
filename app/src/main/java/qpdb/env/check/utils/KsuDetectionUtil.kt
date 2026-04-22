package qpdb.env.check.utils

/**
 * KernelSU 侧信道检测工具类
 * 提供 JNI native 方法进行高精度系统调用计时和行为检测
 */
object KsuDetectionUtil {
    init {
        System.loadLibrary("check")
    }

    /**
     * 测量 faccessat 系统调用耗时（纳秒）
     * @param path 要检测的路径
     * @param iterations 循环次数
     * @return 总耗时（纳秒）
     */
    @JvmStatic
    external fun nativeCheckAccessTiming(path: String, iterations: Int): Long

    /**
     * 测量 getpid 系统调用循环耗时（纳秒）
     * 用于检测 tracepoint 标记带来的 syscall 开销
     * @param iterations 循环次数
     * @return 总耗时（纳秒）
     */
    @JvmStatic
    external fun nativeCheckSyscallLoop(iterations: Int): Long

    /**
     * 检测 init.rc 的 stat 大小与实际读取大小是否一致
     * @return 格式：stat=xxx|read=xxx 或错误信息
     */
    @JvmStatic
    external fun nativeCheckInitRcStat(): String

    /**
     * 检测 access("/system/bin/su", F_OK) 的返回值
     * @return 1 表示可访问（可能被重定向），0 表示不可访问
     */
    @JvmStatic
    external fun nativeCheckAccessSu(): Int

    /**
     * 读取当前进程的 Seccomp 状态
     * @return Seccomp 值，-1 表示读取失败
     */
    @JvmStatic
    external fun nativeCheckSeccompStatus(): Int

    /**
     * 扫描 /proc/self/fd/ 中是否存在 [ksu_driver] 或 [ksu_fdwrapper] 匿名 inode fd
     */
    @JvmStatic
    external fun nativeCheckKsuFd(): Boolean

    /**
     * 测量 execve("/system/bin/su") 与 execve("/system/bin/sh") 的延迟差异
     * @return 格式：su_avg=xxx|sh_avg=xxx（微秒）
     */
    @JvmStatic
    external fun nativeCheckExecveTiming(): String

    /**
     * 测量 setresuid 系统调用耗时（纳秒）
     * @param iterations 循环次数
     * @return 总耗时（纳秒）
     */
    @JvmStatic
    external fun nativeCheckSetresuidTiming(iterations: Int): Long

    /**
     * 基于 CNTVCT_EL0 的高精度 syscall 侧信道检测
     * 测量 faccessat("/system/bin/su") 与基线 fchownat 各 10000 次并排序对位比较。
     * @return 格式：anomaly=xxx|threshold=7000|test_median=xxx|base_median=xxx
     *         或 alloc_failed / unsupported_arch
     */
    @JvmStatic
    external fun nativeCheckTimingSideChannel(): String
}

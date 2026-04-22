package qpdb.env.check.utils

object SoCDetectionUtil {
    init {
        System.loadLibrary("check")
    }

    /**
     * 通过汇编指令读取 MIDR_EL1 寄存器
     * 会先将线程绑定到指定核心再执行 mrs 指令
     * @param cpuIndex CPU 核心编号
     * @return MIDR_EL1 的值，失败返回 -1
     */
    @JvmStatic
    external fun nativeReadMidrByAsm(cpuIndex: Int): Long

    /**
     * 通过 sysfs 读取指定 CPU 核心的 MIDR_EL1
     * @param cpuIndex CPU 核心编号
     * @return MIDR_EL1 的值，失败返回 -1
     */
    @JvmStatic
    external fun nativeReadMidrBySysfs(cpuIndex: Int): Long

    /**
     * 获取 CPU 核心数量
     */
    @JvmStatic
    external fun nativeGetCpuCoreCount(): Int
}

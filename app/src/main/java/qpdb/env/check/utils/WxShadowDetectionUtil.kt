package qpdb.env.check.utils

/**
 * WXShadow / Anti-Detect / Hide-Maps 综合检测 JNI 工具类
 * 提供原生层的高精度侧信道检测和文件系统扫描
 */
object WxShadowDetectionUtil {
    init {
        System.loadLibrary("check")
    }

    // ========== WXShadow 检测 ==========

    /**
     * 自读代码页 Page Fault 检测
     * 原理：正常代码页 r-x 自读不触发 page fault；wxshadow shadow 页 --x 自读触发 data abort
     * @return 格式：delta=xxx|threshold=50
     */
    @JvmStatic
    external fun nativeCheckWxShadowPageFault(): String

    /**
     * BRK + 单步时延指纹检测
     * 原理：wxshadow BRK 路径单次延迟约 5-20us，远高于普通函数调用
     * @return 格式：avg_ns=xxx|avg_ref=xxx|ratio=xxx|threshold=10
     */
    @JvmStatic
    external fun nativeCheckWxShadowTiming(): String

    /**
     * prctl 选项探测
     * 原理：wxshadow 注册了自定义 prctl 选项 0x57580001-0x57580008
     * @return 格式：ret=xxx|errno=xxx
     */
    @JvmStatic
    external fun nativeCheckPrctlProbe(): String

    // ========== Anti-Detect 检测 ==========

    /**
     * faccessat vs openat 不一致性检测
     * 原理：anti-detect 可能 hook 了 faccessat 但未 hook openat，导致结果矛盾
     * @return 格式：inconsistent=1/0|faccessat_ret=xxx|faccessat_errno=xxx|openat_ok=1/0
     */
    @JvmStatic
    external fun nativeCheckSyscallInconsistency(): String

    /**
     * /proc/kallsyms 符号扫描
     * 检测 anti-detect、KernelPatch hook 框架、KPM 模块相关符号
     * @return 格式：anti_detect=xxx|kp_hooks=xxx|kp_modules=xxx
     */
    @JvmStatic
    external fun nativeCheckKallsyms(): String

    // ========== Hide-Maps 检测 ==========

    /**
     * dl_iterate_phdr 获取的 so 列表与 /proc/self/maps 做差集
     * @return 格式：hidden=xxx|total=xxx
     */
    @JvmStatic
    external fun nativeCheckHiddenMaps(): String

    /**
     * /proc/self/smaps 与 /proc/self/maps 行数对比
     * @return 格式：maps_lines=xxx|smaps_regions=xxx|diff=xxx
     */
    @JvmStatic
    external fun nativeCheckSmapsVsMaps(): String

    /**
     * mincore 地址空间扫描
     * @return 格式：mapped_pages=xxx
     */
    @JvmStatic
    external fun nativeCheckMincoreScan(): String

    /**
     * ELF Magic 扫描验证
     * @return 格式：elf_count=xxx|total_libs=xxx
     */
    @JvmStatic
    external fun nativeCheckElfMagic(): String

    // ========== 内核日志/模块检测 ==========

    /**
     * /proc/modules 检测 KernelPatch 模块
     * @return 格式：kernelpatch=xxx
     */
    @JvmStatic
    external fun nativeCheckProcModules(): String
}

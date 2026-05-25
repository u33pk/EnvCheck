package qpdb.env.check.utils

/**
 * Tricky Store 时序检测 JNI 工具类
 *
 * 通过高精度 CNTVCT_EL0 计时器测量 KeyStore 操作的时序特征，
 * 利用行为与时序差异识别 Tricky Store 等 Keybox 伪装工具。
 *
 * 核心原理：真实 TEE/StrongBox 处于独立运行环境，密码学操作耗时稳定（方差小），
 * 不受主系统 CPU 负载影响；软件模拟运行在 REE 中，耗时会随 CPU 调度产生明显抖动。
 */
object TrickyStoreUtil {
    init {
        System.loadLibrary("check")
    }

    /**
     * 执行时序认证检测
     *
     * 流程：
     * 1. 生成 EC P-256 硬件密钥对（计时）
     * 2. 空闲状态下连续签名 30 次，收集耗时样本
     * 3. 启动 CPU 负载线程，在压力状态下再签名 30 次
     * 4. 计算统计特征（均值、中位数、标准差、最大最小值）
     * 5. 对比空闲/负载状态下的抖动差异
     *
     * @param useStrongBox 是否使用 StrongBox
     * @return 格式：suspicious=N|gen_ns=xxx|idle_mean=xxx|idle_std=xxx|...
     *         或 error=xxx
     */
    @JvmStatic
    external fun nativeCheckTimingAttestation(useStrongBox: Boolean): String
}

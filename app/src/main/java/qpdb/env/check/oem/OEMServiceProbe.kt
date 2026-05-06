package qpdb.env.check.oem

import android.content.Context

/**
 * OEM 服务探针统一入口
 *
 * 通过主动调用各品牌设备的标志性系统服务/组件来验证设备真实性。
 * 原理：模拟器/云手机/改机工具通常只修改了 Build 属性，但无法完整复刻各品牌
 * 复杂的系统服务架构。主动调用真实设备上必然存在的服务，根据响应判断环境真伪。
 *
 * 各品牌探针实现位于独立文件中：
 * - XiaomiProbe.kt  : Xiaomi / Redmi / POCO
 * - SamsungProbe.kt : Samsung
 * - OPPOProbe.kt    : OPPO / Realme / OnePlus
 * - VivoProbe.kt    : vivo / iQOO
 * - HuaweiProbe.kt  : Huawei / Honor
 * - GoogleProbe.kt  : Google / Pixel
 * - EmulatorProbe.kt: 通用模拟器特征探测
 *
 * 每个探针方法返回：
 * - ProbeResult.HIT: 服务存在且响应正常（强证据支持该品牌）
 * - ProbeResult.MISS: 服务不存在或调用失败（弱证据，可能服务被禁用）
 * - ProbeResult.ERROR: 调用异常（中性）
 */
object OEMServiceProbe {

    enum class ProbeResult {
        HIT,    // 命中：服务存在且正常响应
        MISS,   // 未命中：服务不存在或拒绝访问
        ERROR   // 错误：调用过程异常
    }

    data class ProbeOutcome(
        val result: ProbeResult,
        val detail: String
    )

    /**
     * 根据品牌执行对应的批量探针
     */
    fun probeByBrand(context: Context, brand: String): List<ProbeOutcome> {
        val lowerBrand = brand.lowercase()
        val results = mutableListOf<ProbeOutcome>()

        when {
            lowerBrand.contains("xiaomi") || lowerBrand.contains("redmi") || lowerBrand.contains("poco") || lowerBrand.contains("mi") -> {
                results.addAll(XiaomiProbe.probeAll(context))
            }
            lowerBrand.contains("samsung") || lowerBrand.contains("galaxy") -> {
                results.addAll(SamsungProbe.probeAll(context))
            }
            lowerBrand.contains("oppo") || lowerBrand.contains("realme") || lowerBrand.contains("oneplus") -> {
                results.addAll(OPPOProbe.probeAll(context))
            }
            lowerBrand.contains("vivo") || lowerBrand.contains("iqoo") -> {
                results.addAll(VivoProbe.probeAll(context))
            }
            lowerBrand.contains("huawei") || lowerBrand.contains("honor") -> {
                results.addAll(HuaweiProbe.probeAll(context))
            }
            lowerBrand.contains("google") || lowerBrand.contains("pixel") -> {
                results.addAll(GoogleProbe.probeAll(context))
            }
            else -> {
                results.add(ProbeOutcome(ProbeResult.ERROR, "品牌 '$brand' 暂无专用探针"))
            }
        }

        // 始终执行通用模拟器探测
        results.addAll(EmulatorProbe.probeAll(context))

        return results
    }
}

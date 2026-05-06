package qpdb.env.check.oem

import android.content.Context
import android.content.pm.PackageManager

/**
 * 通用模拟器/云手机特征探针
 */
object EmulatorProbe {

    /**
     * 探测是否存在模拟器常见组件和属性
     */
    fun probeAll(context: Context): List<OEMServiceProbe.ProbeOutcome> {
        val results = mutableListOf<OEMServiceProbe.ProbeOutcome>()

        // 1. 探测 QEMU 属性
        try {
            val process = Runtime.getRuntime().exec("getprop ro.kernel.qemu")
            val value = process.inputStream.bufferedReader().readLine()?.trim() ?: ""
            if (value == "1") {
                results.add(OEMServiceProbe.ProbeOutcome(OEMServiceProbe.ProbeResult.HIT, "ro.kernel.qemu=1 (QEMU标志)"))
            }
        } catch (e: Exception) {
            // ignore
        }

        // 2. 探测开发工具包
        val devTools = listOf(
            "com.android.development",
            "com.android.development_settings",
        )
        val pm = context.packageManager
        for (pkg in devTools) {
            try {
                pm.getPackageInfo(pkg, 0)
                results.add(OEMServiceProbe.ProbeOutcome(OEMServiceProbe.ProbeResult.HIT, "发现开发工具包: $pkg"))
            } catch (e: PackageManager.NameNotFoundException) {
                // 正常，不存在
            }
        }

        // 3. 探测模拟器专用硬件属性
        val hwProps = listOf("ro.hardware.vm", "ro.boot.vm")
        for (prop in hwProps) {
            try {
                val process = Runtime.getRuntime().exec("getprop $prop")
                val value = process.inputStream.bufferedReader().readLine()?.trim() ?: ""
                if (value.isNotBlank() && value != "unknown") {
                    results.add(OEMServiceProbe.ProbeOutcome(OEMServiceProbe.ProbeResult.HIT, "$prop=$value"))
                }
            } catch (e: Exception) {
                // ignore
            }
        }

        if (results.isEmpty()) {
            results.add(OEMServiceProbe.ProbeOutcome(OEMServiceProbe.ProbeResult.MISS, "未发现模拟器特征组件"))
        }

        return results
    }
}

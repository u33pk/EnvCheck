package qpdb.env.check.oem

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri

/**
 * OPPO / Realme / OnePlus 品牌服务探针
 */
object OPPOProbe {

    /**
     * 探测 ColorOS 安全中心
     */
    fun probeSecurityCenter(context: Context): OEMServiceProbe.ProbeOutcome {
        return try {
            val intent = Intent().apply {
                component = ComponentName(
                    "com.coloros.safecenter",
                    "com.coloros.safecenter.MainActivity"
                )
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
            val resolveInfo = context.packageManager.resolveActivity(intent, PackageManager.MATCH_DEFAULT_ONLY)
            if (resolveInfo != null) {
                OEMServiceProbe.ProbeOutcome(OEMServiceProbe.ProbeResult.HIT, "ColorOS 安全中心组件可解析")
            } else {
                OEMServiceProbe.ProbeOutcome(OEMServiceProbe.ProbeResult.MISS, "ColorOS 安全中心组件不可解析")
            }
        } catch (e: Exception) {
            OEMServiceProbe.ProbeOutcome(OEMServiceProbe.ProbeResult.ERROR, "探测异常: ${e.message}")
        }
    }

    /**
     * 探测 OPPO 软件商店 oppomarket 协议处理
     */
    fun probeAppStore(context: Context): OEMServiceProbe.ProbeOutcome {
        return try {
            val intent = Intent().apply {
                action = "android.intent.action.VIEW"
                data = Uri.parse("oppomarket://details?id=com.android.settings")
            }
            val resolveInfo = context.packageManager.resolveActivity(intent, PackageManager.MATCH_DEFAULT_ONLY)
            if (resolveInfo != null) {
                val pkg = resolveInfo.activityInfo.packageName
                if (pkg.contains("heytap") || pkg.contains("oppo") || pkg.contains("coloros")) {
                    OEMServiceProbe.ProbeOutcome(OEMServiceProbe.ProbeResult.HIT, "OPPO 软件商店可处理 oppomarket 协议: $pkg")
                } else {
                    OEMServiceProbe.ProbeOutcome(OEMServiceProbe.ProbeResult.MISS, "oppomarket 协议被非 OPPO 应用处理: $pkg")
                }
            } else {
                OEMServiceProbe.ProbeOutcome(OEMServiceProbe.ProbeResult.MISS, "无应用处理 oppomarket 协议")
            }
        } catch (e: Exception) {
            OEMServiceProbe.ProbeOutcome(OEMServiceProbe.ProbeResult.ERROR, "探测异常: ${e.message}")
        }
    }

    /**
     * 执行全部探针
     */
    fun probeAll(context: Context): List<OEMServiceProbe.ProbeOutcome> = listOf(
        probeSecurityCenter(context),
        probeAppStore(context)
    )
}

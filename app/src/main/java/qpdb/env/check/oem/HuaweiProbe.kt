package qpdb.env.check.oem

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri

/**
 * Huawei / Honor 品牌服务探针
 */
object HuaweiProbe {

    /**
     * 探测 Huawei 系统管家
     */
    fun probeSystemManager(context: Context): OEMServiceProbe.ProbeOutcome {
        return try {
            val intent = Intent().apply {
                component = ComponentName(
                    "com.huawei.systemmanager",
                    "com.huawei.systemmanager.mainscreen.MainScreenActivity"
                )
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
            val resolveInfo = context.packageManager.resolveActivity(intent, PackageManager.MATCH_DEFAULT_ONLY)
            if (resolveInfo != null) {
                OEMServiceProbe.ProbeOutcome(OEMServiceProbe.ProbeResult.HIT, "Huawei 系统管家组件可解析")
            } else {
                OEMServiceProbe.ProbeOutcome(OEMServiceProbe.ProbeResult.MISS, "Huawei 系统管家组件不可解析")
            }
        } catch (e: Exception) {
            OEMServiceProbe.ProbeOutcome(OEMServiceProbe.ProbeResult.ERROR, "探测异常: ${e.message}")
        }
    }

    /**
     * 探测 Huawei AppGallery appmarket 协议处理
     */
    fun probeAppGallery(context: Context): OEMServiceProbe.ProbeOutcome {
        return try {
            val intent = Intent().apply {
                action = "android.intent.action.VIEW"
                data = Uri.parse("appmarket://details?id=com.android.settings")
            }
            val resolveInfo = context.packageManager.resolveActivity(intent, PackageManager.MATCH_DEFAULT_ONLY)
            if (resolveInfo != null) {
                val pkg = resolveInfo.activityInfo.packageName
                if (pkg.contains("huawei") || pkg.contains("hihonor") || pkg.contains("appmarket")) {
                    OEMServiceProbe.ProbeOutcome(OEMServiceProbe.ProbeResult.HIT, "Huawei AppGallery 可处理 appmarket 协议: $pkg")
                } else {
                    OEMServiceProbe.ProbeOutcome(OEMServiceProbe.ProbeResult.MISS, "appmarket 协议被非 Huawei 应用处理: $pkg")
                }
            } else {
                OEMServiceProbe.ProbeOutcome(OEMServiceProbe.ProbeResult.MISS, "无应用处理 appmarket 协议")
            }
        } catch (e: Exception) {
            OEMServiceProbe.ProbeOutcome(OEMServiceProbe.ProbeResult.ERROR, "探测异常: ${e.message}")
        }
    }

    /**
     * 执行全部探针
     */
    fun probeAll(context: Context): List<OEMServiceProbe.ProbeOutcome> = listOf(
        probeSystemManager(context),
        probeAppGallery(context)
    )
}

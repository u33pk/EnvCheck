package qpdb.env.check.oem

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri

/**
 * Samsung 品牌服务探针
 */
object SamsungProbe {

    /**
     * 探测 Samsung Knox 安全容器
     */
    fun probeKnox(context: Context): OEMServiceProbe.ProbeOutcome {
        return try {
            val intent = Intent().apply {
                component = ComponentName(
                    "com.samsung.android.knox.containeragent",
                    "com.samsung.android.knox.containeragent.ui.launcher.KnoxLauncherActivity"
                )
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
            val resolveInfo = context.packageManager.resolveActivity(intent, PackageManager.MATCH_DEFAULT_ONLY)
            if (resolveInfo != null) {
                OEMServiceProbe.ProbeOutcome(OEMServiceProbe.ProbeResult.HIT, "Samsung Knox 组件可解析")
            } else {
                OEMServiceProbe.ProbeOutcome(OEMServiceProbe.ProbeResult.MISS, "Samsung Knox 组件不可解析")
            }
        } catch (e: Exception) {
            OEMServiceProbe.ProbeOutcome(OEMServiceProbe.ProbeResult.ERROR, "探测异常: ${e.message}")
        }
    }

    /**
     * 探测 Samsung Galaxy Store samsungapps 协议处理
     */
    fun probeGalaxyStore(context: Context): OEMServiceProbe.ProbeOutcome {
        return try {
            val intent = Intent().apply {
                action = "android.intent.action.VIEW"
                data = Uri.parse("samsungapps://ProductDetail/com.android.settings")
            }
            val resolveInfo = context.packageManager.resolveActivity(intent, PackageManager.MATCH_DEFAULT_ONLY)
            if (resolveInfo != null) {
                val pkg = resolveInfo.activityInfo.packageName
                if (pkg.contains("samsung") || pkg.contains("sec")) {
                    OEMServiceProbe.ProbeOutcome(OEMServiceProbe.ProbeResult.HIT, "Samsung Galaxy Store 可处理 samsungapps 协议: $pkg")
                } else {
                    OEMServiceProbe.ProbeOutcome(OEMServiceProbe.ProbeResult.MISS, "samsungapps 协议被非 Samsung 应用处理: $pkg")
                }
            } else {
                OEMServiceProbe.ProbeOutcome(OEMServiceProbe.ProbeResult.MISS, "无应用处理 samsungapps 协议")
            }
        } catch (e: Exception) {
            OEMServiceProbe.ProbeOutcome(OEMServiceProbe.ProbeResult.ERROR, "探测异常: ${e.message}")
        }
    }

    /**
     * 探测 Samsung Bixby
     */
    fun probeBixby(context: Context): OEMServiceProbe.ProbeOutcome {
        return try {
            val intent = Intent().apply {
                component = ComponentName(
                    "com.samsung.android.bixby.agent",
                    "com.samsung.android.bixby.agent.MainActivity"
                )
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
            val resolveInfo = context.packageManager.resolveActivity(intent, PackageManager.MATCH_DEFAULT_ONLY)
            if (resolveInfo != null) {
                OEMServiceProbe.ProbeOutcome(OEMServiceProbe.ProbeResult.HIT, "Samsung Bixby 组件可解析")
            } else {
                OEMServiceProbe.ProbeOutcome(OEMServiceProbe.ProbeResult.MISS, "Samsung Bixby 组件不可解析")
            }
        } catch (e: Exception) {
            OEMServiceProbe.ProbeOutcome(OEMServiceProbe.ProbeResult.ERROR, "探测异常: ${e.message}")
        }
    }

    /**
     * 执行全部探针
     */
    fun probeAll(context: Context): List<OEMServiceProbe.ProbeOutcome> = listOf(
        probeKnox(context),
        probeGalaxyStore(context),
        probeBixby(context)
    )
}

package qpdb.env.check.oem

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.util.Log

/**
 * Xiaomi / Redmi / POCO 品牌服务探针
 */
object XiaomiProbe {

    /**
     * 探测 MIUI/HyperOS 安全中心
     */
    fun probeSecurityCenter(context: Context): OEMServiceProbe.ProbeOutcome {
        return try {
            val intent = Intent().apply {
                component = ComponentName(
                    "com.miui.securitycenter",
                    "com.miui.securityscan.MainActivity"
                )
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
            val resolveInfo = context.packageManager.resolveActivity(intent, PackageManager.MATCH_DEFAULT_ONLY)
            if (resolveInfo != null) {
                OEMServiceProbe.ProbeOutcome(OEMServiceProbe.ProbeResult.HIT, "MIUI 安全中心组件可解析")
            } else {
                OEMServiceProbe.ProbeOutcome(OEMServiceProbe.ProbeResult.MISS, "MIUI 安全中心组件不可解析")
            }
        } catch (e: Exception) {
            OEMServiceProbe.ProbeOutcome(OEMServiceProbe.ProbeResult.ERROR, "探测异常: ${e.message}")
        }
    }

    /**
     * 探测小米应用商店 market 协议处理
     */
    fun probeAppStore(context: Context): OEMServiceProbe.ProbeOutcome {
        return try {
            val intent = Intent().apply {
                action = "android.intent.action.VIEW"
                data = Uri.parse("market://details?id=com.android.settings")
                `package` = "com.xiaomi.market"
            }
            val resolveInfo = context.packageManager.resolveActivity(intent, PackageManager.MATCH_DEFAULT_ONLY)
            if (resolveInfo != null) {
                Log.i("OEM", "小米应用商店可处理 market 协议")
                OEMServiceProbe.ProbeOutcome(OEMServiceProbe.ProbeResult.HIT, "小米应用商店可处理 market 协议")

            } else {
                Log.i("OEM", "小米应用商店无法处理 market 协议")
                OEMServiceProbe.ProbeOutcome(OEMServiceProbe.ProbeResult.MISS, "小米应用商店无法处理 market 协议")
            }
        } catch (e: Exception) {
            OEMServiceProbe.ProbeOutcome(OEMServiceProbe.ProbeResult.ERROR, "探测异常: ${e.message}")
        }
    }

    /**
     * 探测小米云服务
     */
    fun probeCloudAccount(context: Context): OEMServiceProbe.ProbeOutcome {
        return try {
            val intent = Intent().apply {
                component = ComponentName(
                    "com.miui.cloudservice",
                    "com.miui.cloudservice.ui.MiCloudDetailActivity"
                )
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
            val resolveInfo = context.packageManager.resolveActivity(intent, PackageManager.MATCH_DEFAULT_ONLY)
            if (resolveInfo != null) {
                OEMServiceProbe.ProbeOutcome(OEMServiceProbe.ProbeResult.HIT, "小米云服务组件可解析")
            } else {
                OEMServiceProbe.ProbeOutcome(OEMServiceProbe.ProbeResult.MISS, "小米云服务组件不可解析")
            }
        } catch (e: Exception) {
            OEMServiceProbe.ProbeOutcome(OEMServiceProbe.ProbeResult.ERROR, "探测异常: ${e.message}")
        }
    }

    /**
     * 探测默认 Launcher 是否为 MIUI/Xiaomi
     */
    fun probeLauncher(context: Context): OEMServiceProbe.ProbeOutcome {
        return try {
            val intent = Intent(Intent.ACTION_MAIN).apply {
                addCategory(Intent.CATEGORY_HOME)
            }
            val resolveInfo = context.packageManager.resolveActivity(intent, PackageManager.MATCH_DEFAULT_ONLY)
            val launcherPkg = resolveInfo?.activityInfo?.packageName ?: ""
            if (launcherPkg.contains("miui") || launcherPkg.contains("xiaomi")) {
                OEMServiceProbe.ProbeOutcome(OEMServiceProbe.ProbeResult.HIT, "默认 Launcher 为 Xiaomi: $launcherPkg")
            } else {
                OEMServiceProbe.ProbeOutcome(OEMServiceProbe.ProbeResult.MISS, "默认 Launcher 非 Xiaomi: $launcherPkg")
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
        probeAppStore(context),
        probeCloudAccount(context),
        probeLauncher(context)
    )
}

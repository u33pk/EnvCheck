package qpdb.env.check.oem

import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager

/**
 * Google / Pixel 品牌服务探针
 */
object GoogleProbe {

    /**
     * 探测默认 Launcher 是否为 Pixel Launcher
     */
    fun probeLauncher(context: Context): OEMServiceProbe.ProbeOutcome {
        return try {
            val intent = Intent(Intent.ACTION_MAIN).apply {
                addCategory(Intent.CATEGORY_HOME)
            }
            val resolveInfo = context.packageManager.resolveActivity(intent, PackageManager.MATCH_DEFAULT_ONLY)
            val launcherPkg = resolveInfo?.activityInfo?.packageName ?: ""
            if (launcherPkg.contains("nexuslauncher") || launcherPkg.contains("pixel")) {
                OEMServiceProbe.ProbeOutcome(OEMServiceProbe.ProbeResult.HIT, "默认 Launcher 为 Pixel: $launcherPkg")
            } else {
                OEMServiceProbe.ProbeOutcome(OEMServiceProbe.ProbeResult.MISS, "默认 Launcher 非 Pixel: $launcherPkg")
            }
        } catch (e: Exception) {
            OEMServiceProbe.ProbeOutcome(OEMServiceProbe.ProbeResult.ERROR, "探测异常: ${e.message}")
        }
    }

    /**
     * 探测默认拨号应用是否为 Google Dialer
     */
    fun probeDialer(context: Context): OEMServiceProbe.ProbeOutcome {
        return try {
            val intent = Intent(Intent.ACTION_DIAL)
            val resolveInfo = context.packageManager.resolveActivity(intent, PackageManager.MATCH_DEFAULT_ONLY)
            val pkg = resolveInfo?.activityInfo?.packageName ?: ""
            if (pkg.contains("google") && pkg.contains("dialer")) {
                OEMServiceProbe.ProbeOutcome(OEMServiceProbe.ProbeResult.HIT, "默认拨号应用为 Google Dialer: $pkg")
            } else {
                OEMServiceProbe.ProbeOutcome(OEMServiceProbe.ProbeResult.MISS, "默认拨号应用非 Google Dialer: $pkg")
            }
        } catch (e: Exception) {
            OEMServiceProbe.ProbeOutcome(OEMServiceProbe.ProbeResult.ERROR, "探测异常: ${e.message}")
        }
    }

    /**
     * 执行全部探针
     */
    fun probeAll(context: Context): List<OEMServiceProbe.ProbeOutcome> = listOf(
        probeLauncher(context),
        probeDialer(context)
    )
}

package qpdb.env.check.oem

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager

/**
 * vivo / iQOO 品牌服务探针
 */
object VivoProbe {

    /**
     * 探测 vivo/iQOO 守护组件 / 游戏中心
     */
    fun probeSecurity(context: Context): OEMServiceProbe.ProbeOutcome {
        return try {
            val intent = Intent().apply {
                component = ComponentName(
                    "com.iqoo.daemon",
                    "com.iqoo.daemon.MainActivity"
                )
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
            val pm = context.packageManager
            val resolveInfo = pm.resolveActivity(intent, PackageManager.MATCH_DEFAULT_ONLY)
            if (resolveInfo != null) {
                OEMServiceProbe.ProbeOutcome(OEMServiceProbe.ProbeResult.HIT, "vivo/iQOO 守护组件可解析")
            } else {
                // 尝试另一个 vivo 组件
                val intent2 = Intent().apply {
                    component = ComponentName(
                        "com.vivo.game",
                        "com.vivo.game.ui.GameMainActivity"
                    )
                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                }
                val resolveInfo2 = pm.resolveActivity(intent2, PackageManager.MATCH_DEFAULT_ONLY)
                if (resolveInfo2 != null) {
                    OEMServiceProbe.ProbeOutcome(OEMServiceProbe.ProbeResult.HIT, "vivo 游戏中心组件可解析")
                } else {
                    OEMServiceProbe.ProbeOutcome(OEMServiceProbe.ProbeResult.MISS, "vivo 标志性组件均不可解析")
                }
            }
        } catch (e: Exception) {
            OEMServiceProbe.ProbeOutcome(OEMServiceProbe.ProbeResult.ERROR, "探测异常: ${e.message}")
        }
    }

    /**
     * 执行全部探针
     */
    fun probeAll(context: Context): List<OEMServiceProbe.ProbeOutcome> = listOf(
        probeSecurity(context)
    )
}

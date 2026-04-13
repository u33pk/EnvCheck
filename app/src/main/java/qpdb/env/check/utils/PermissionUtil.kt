package qpdb.env.check.utils

import android.Manifest
import android.app.Activity
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import androidx.appcompat.app.AlertDialog
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat

/**
 * 权限管理工具类
 * 用于处理运行时权限申请
 */
object PermissionUtil {

    private const val REQUEST_CODE_PHONE_STATE = 1001

    /**
     * 检查是否已有 READ_PHONE_STATE 权限
     * @param context 上下文
     * @return true 表示已有权限
     */
    fun hasPhoneStatePermission(context: Context): Boolean {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            ContextCompat.checkSelfPermission(
                context, Manifest.permission.READ_PHONE_STATE
            ) == PackageManager.PERMISSION_GRANTED
        } else {
            true
        }
    }

    /**
     * 检查并申请 READ_PHONE_STATE 权限
     * @param activity 活动实例
     * @param onGranted 权限已授予的回调
     * @param onDenied 权限被拒绝的回调（可选，不设置则继续执行）
     */
    fun checkAndRequestPhoneStatePermission(
        activity: Activity,
        onGranted: () -> Unit,
        onDenied: (() -> Unit)? = null
    ) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            // Android 6.0 以下直接执行
            onGranted()
            return
        }

        when {
            hasPhoneStatePermission(activity) -> {
                // 已有权限
                onGranted()
            }
            ActivityCompat.shouldShowRequestPermissionRationale(
                activity, Manifest.permission.READ_PHONE_STATE
            ) -> {
                // 显示权限说明对话框
                showPermissionRationaleDialog(activity, onGranted, onDenied)
            }
            else -> {
                // 直接申请权限
                requestPhoneStatePermission(activity)
            }
        }
    }

    /**
     * 显示权限说明对话框
     */
    private fun showPermissionRationaleDialog(
        activity: Activity,
        onGranted: () -> Unit,
        onDenied: (() -> Unit)?
    ) {
        AlertDialog.Builder(activity)
            .setTitle("需要电话权限")
            .setMessage("SIM 卡信息检测需要读取电话状态权限，用于获取运营商、MCC/MNC 等信息。")
            .setPositiveButton("授权") { _, _ ->
                requestPhoneStatePermission(activity)
            }
            .setNegativeButton("取消") { _, _ ->
                onDenied?.invoke() ?: onGranted()
            }
            .setCancelable(false)
            .show()
    }

    /**
     * 申请 READ_PHONE_STATE 权限
     */
    fun requestPhoneStatePermission(activity: Activity) {
        ActivityCompat.requestPermissions(
            activity,
            arrayOf(Manifest.permission.READ_PHONE_STATE),
            REQUEST_CODE_PHONE_STATE
        )
    }

    /**
     * 处理权限申请结果
     * 在 Activity 的 onRequestPermissionsResult 中调用
     * @param requestCode 请求码
     * @param grantResults 授权结果
     * @param onGranted 权限已授予的回调
     * @param onDenied 权限被拒绝的回调（可选）
     * @return true 表示已处理该请求
     */
    fun handlePermissionResult(
        requestCode: Int,
        grantResults: IntArray,
        onGranted: () -> Unit,
        onDenied: (() -> Unit)? = null
    ): Boolean {
        if (requestCode != REQUEST_CODE_PHONE_STATE) {
            return false
        }

        if (grantResults.isNotEmpty() && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
            onGranted()
        } else {
            onDenied?.invoke() ?: onGranted()
        }
        return true
    }
}

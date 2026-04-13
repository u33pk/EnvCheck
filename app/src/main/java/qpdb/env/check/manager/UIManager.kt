package qpdb.env.check.manager

import android.content.Context
import android.util.Log
import com.google.android.material.snackbar.Snackbar
import qpdb.env.check.R
import qpdb.env.check.model.Category
import android.view.View

/**
 * UI 管理器
 * 负责 UI 相关的操作和显示
 */
object UIManager {

    private const val TAG = "UIManager"

    /**
     * 显示加载完成提示
     */
    fun showLoadedMessage(view: View, categoryCount: Int, itemCount: Int) {
        Log.d(TAG, "显示加载完成提示：$categoryCount 个分类，$itemCount 个检测项")
        Snackbar.make(
            view,
            "已加载 $categoryCount 个检测分类，共 $itemCount 个检测项",
            Snackbar.LENGTH_SHORT
        ).show()
    }

    /**
     * 显示检测运行中提示
     */
    fun showCheckingMessage(view: View) {
        Log.d(TAG, "显示检测运行中提示")
        Snackbar.make(
            view,
            R.string.check_running,
            Snackbar.LENGTH_SHORT
        ).show()
    }

    /**
     * 显示检测结果
     */
    fun showCheckResult(view: View, passedCount: Int, totalCount: Int) {
        Log.d(TAG, "显示检测结果：$passedCount/$totalCount 通过")
        Snackbar.make(
            view,
            "检测完成：$passedCount/$totalCount 通过",
            Snackbar.LENGTH_LONG
        ).show()
    }

    /**
     * 显示错误消息
     */
    fun showErrorMessage(view: View, message: String) {
        Log.e(TAG, "显示错误消息：$message")
        Snackbar.make(
            view,
            "错误：$message",
            Snackbar.LENGTH_LONG
        ).show()
    }

    /**
     * 显示通用消息
     */
    fun showMessage(view: View, message: String, duration: Int = Snackbar.LENGTH_SHORT) {
        Log.d(TAG, "显示消息：$message")
        Snackbar.make(view, message, duration).show()
    }
}

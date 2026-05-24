package qpdb.env.check.checkers

import android.content.Context
import android.graphics.Color
import android.view.View
import android.widget.LinearLayout
import qpdb.env.check.model.Checkable
import qpdb.env.check.model.CheckItem
import qpdb.env.check.model.DisplayMode
import qpdb.env.check.view.DiffPixelMapView
import qpdb.env.check.view.EntropyCurveView

/**
 * 属性检测器
 * 获取全部系统属性，与 assets/cvd.prop 对比，并绘制两个 Canvas：
 * 1. Diff Pixel Map — 差异像素矩阵
 * 2. Entropy Curve — 属性复杂度熵曲线 + 箱线图
 */
class PropertyChecker : Checkable {

    override val categoryName: String = "Property 对比"

    override val displayMode: DisplayMode = DisplayMode.CANVAS

    override fun checkList(): List<CheckItem> = emptyList()

    override fun createCanvasView(context: Context): View {
        val container = LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            )
            setBackgroundColor(Color.parseColor("#1A1A2E"))
        }

        val chartHeight = 380.dpToPx(context)

        // 差异像素图
        val diffMap = DiffPixelMapView(context).apply {
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                chartHeight
            )
        }
        container.addView(diffMap)

        // 熵曲线图
        val entropyCurve = EntropyCurveView(context).apply {
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                chartHeight
            )
        }
        container.addView(entropyCurve)

        return container
    }

    private fun Int.dpToPx(context: Context): Int {
        return (this * context.resources.displayMetrics.density).toInt()
    }
}

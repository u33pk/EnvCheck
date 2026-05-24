package qpdb.env.check.view

import android.content.Context
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.util.AttributeSet
import android.view.View
import qpdb.env.check.utils.PropertyUtil

/**
 * 属性差异像素图
 * 将当前系统属性与 assets/cvd.prop 逐 key 对比，
 * 差异度映射为像素颜色（绿=相同，红=差异大）。
 */
class DiffPixelMapView @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
    defStyleAttr: Int = 0
) : View(context, attrs, defStyleAttr) {

    private val paint = Paint(Paint.ANTI_ALIAS_FLAG)

    private val allKeys: List<String>
    private val diffs: FloatArray
    private val statTotal: Int
    private val statOnlyCurrent: Int
    private val statOnlyCvd: Int
    private val statCommon: Int

    init {
        setBackgroundColor(Color.parseColor("#1A1A2E"))

        val cvdProps = loadPropsFromAssets(context, "cvd.prop")
        val currentProps = PropertyUtil.getAllProp()

        allKeys = (cvdProps.keys + currentProps.keys).sorted()
        diffs = FloatArray(allKeys.size) { i ->
            val key = allKeys[i]
            when {
                key in cvdProps && key in currentProps ->
                    1.0f - similarity(cvdProps[key]!!, currentProps[key]!!)
                else -> 1.0f
            }
        }

        statTotal = allKeys.size
        statOnlyCurrent = currentProps.keys.minus(cvdProps.keys).size
        statOnlyCvd = cvdProps.keys.minus(currentProps.keys).size
        statCommon = cvdProps.keys.intersect(currentProps.keys).size
    }

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)

        val w = width.toFloat()
        val h = height.toFloat()
        val padding = 24f
        val topOffset = 110f
        val bottomOffset = 70f
        val legendHeight = 50f

        // 标题
        paint.color = Color.WHITE
        paint.textSize = 36f
        paint.textAlign = Paint.Align.CENTER
        paint.style = Paint.Style.FILL
        canvas.drawText("Config Diff Pixel Map", w / 2f, 55f, paint)

        // 统计信息
        paint.textSize = 22f
        paint.color = Color.parseColor("#A0A0A0")
        val statText = "Total=$statTotal  Common=$statCommon  OnlyCurrent=$statOnlyCurrent  OnlyCvd=$statOnlyCvd"
        canvas.drawText(statText, w / 2f, 90f, paint)

        // 像素矩阵绘制区域
        val drawLeft = padding
        val drawTop = topOffset
        val drawRight = w - padding
        val drawBottom = h - bottomOffset - legendHeight
        val drawWidth = drawRight - drawLeft
        val drawHeight = drawBottom - drawTop

        if (diffs.isEmpty() || drawWidth <= 0 || drawHeight <= 0) return

        // 计算每行像素数，根据宽高比自适应
        val pixelGap = 2f
        // 先估算：假设每行放 n 个，则每个大小 = (drawWidth - (n-1)*gap) / n
        // 总高度 = rows * (size + gap)，rows = ceil(total / n)
        // 我们希望 fill 整个区域，所以遍历 n 找最佳
        val bestN = (1..200).minByOrNull { n ->
            val cellW = (drawWidth - (n - 1) * pixelGap) / n
            val cellH = cellW
            val rows = kotlin.math.ceil(diffs.size.toFloat() / n).toInt()
            val neededH = rows * cellH + (rows - 1) * pixelGap
            kotlin.math.abs(neededH - drawHeight)
        } ?: 32

        val cellW = (drawWidth - (bestN - 1) * pixelGap) / bestN
        val cellH = cellW
        val rows = kotlin.math.ceil(diffs.size.toFloat() / bestN).toInt()

        // 居中偏移
        val actualWidth = bestN * cellW + (bestN - 1) * pixelGap
        val actualHeight = rows * cellH + (rows - 1) * pixelGap
        val offsetX = drawLeft + (drawWidth - actualWidth) / 2f
        val offsetY = drawTop + (drawHeight - actualHeight) / 2f

        diffs.forEachIndexed { index, diff ->
            val col = index % bestN
            val row = index / bestN
            val left = offsetX + col * (cellW + pixelGap)
            val top = offsetY + row * (cellH + pixelGap)
            paint.color = diffToColor(diff)
            paint.style = Paint.Style.FILL
            canvas.drawRect(left, top, left + cellW, top + cellH, paint)
        }

        // 填充多余的空白（NaN 颜色）
        val filledCount = diffs.size
        val totalCells = rows * bestN
        for (idx in filledCount until totalCells) {
            val col = idx % bestN
            val row = idx / bestN
            val left = offsetX + col * (cellW + pixelGap)
            val top = offsetY + row * (cellH + pixelGap)
            paint.color = Color.parseColor("#f0f0f0")
            canvas.drawRect(left, top, left + cellW, top + cellH, paint)
        }

        // Colorbar
        val barLeft = drawLeft
        val barTop = h - bottomOffset - legendHeight + 20f
        val barRight = drawRight
        val barHeight = 14f
        val segments = 128
        val segmentW = (barRight - barLeft) / segments
        for (i in 0 until segments) {
            val t = i / (segments - 1f)
            paint.color = diffToColor(t)
            canvas.drawRect(
                barLeft + i * segmentW, barTop,
                barLeft + (i + 1) * segmentW, barTop + barHeight, paint
            )
        }

        // Colorbar 标签
        paint.textSize = 18f
        paint.color = Color.parseColor("#A0A0A0")
        paint.textAlign = Paint.Align.LEFT
        canvas.drawText("0.0 (same)", barLeft, barTop + barHeight + 24f, paint)
        paint.textAlign = Paint.Align.RIGHT
        canvas.drawText("1.0 (diff)", barRight, barTop + barHeight + 24f, paint)
    }

    private fun loadPropsFromAssets(context: Context, fileName: String): Map<String, String> {
        val result = mutableMapOf<String, String>()
        try {
            context.assets.open(fileName).bufferedReader().useLines { lines ->
                lines.forEach { line ->
                    val trimmed = line.trim()
                    if (trimmed.isEmpty() || trimmed.startsWith("#")) return@forEach
                    val idx = trimmed.indexOf('=')
                    if (idx > 0) {
                        val key = trimmed.substring(0, idx).trim()
                        val value = trimmed.substring(idx + 1).trim()
                        result[key] = value
                    }
                }
            }
        } catch (_: Exception) {
        }
        return result
    }

    private fun similarity(v1: String, v2: String): Float {
        val n1 = v1.toDoubleOrNull()
        val n2 = v2.toDoubleOrNull()
        if (n1 != null && n2 != null) {
            val diff = kotlin.math.abs(n1 - n2)
            val denom = kotlin.math.abs(n1) + kotlin.math.abs(n2) + 1e-9
            return (1.0 - kotlin.math.min(diff / denom, 1.0)).toFloat()
        }
        val b1 = v1.lowercase()
        val b2 = v2.lowercase()
        if ((b1 == "true" || b1 == "false") && (b2 == "true" || b2 == "false")) {
            return if (b1 == b2) 1.0f else 0.0f
        }
        return levenshteinRatio(v1, v2)
    }

    private fun levenshteinRatio(s1: String, s2: String): Float {
        if (s1 == s2) return 1.0f
        val m = s1.length
        val n = s2.length
        if (m == 0) return 0.0f
        if (n == 0) return 0.0f
        var prev = IntArray(n + 1) { it }
        var curr = IntArray(n + 1)
        for (i in 1..m) {
            curr[0] = i
            for (j in 1..n) {
                val cost = if (s1[i - 1] == s2[j - 1]) 0 else 1
                curr[j] = kotlin.math.min(
                    kotlin.math.min(curr[j - 1] + 1, prev[j] + 1),
                    prev[j - 1] + cost
                )
            }
            val tmp = prev
            prev = curr
            curr = tmp
        }
        val dist = prev[n]
        val maxLen = kotlin.math.max(m, n)
        return 1.0f - (dist.toFloat() / maxLen).coerceIn(0f, 1f)
    }

    private fun diffToColor(diff: Float): Int {
        val t = diff.coerceIn(0f, 1f)
        return when {
            t <= 0.5f -> interpolateColor(0xFF16C79A.toInt(), 0xFFF4D03F.toInt(), t * 2f)
            else -> interpolateColor(0xFFF4D03F.toInt(), 0xFFE94560.toInt(), (t - 0.5f) * 2f)
        }
    }

    private fun interpolateColor(c1: Int, c2: Int, t: Float): Int {
        val tt = t.coerceIn(0f, 1f)
        val a1 = (c1 shr 24) and 0xFF
        val r1 = (c1 shr 16) and 0xFF
        val g1 = (c1 shr 8) and 0xFF
        val b1 = c1 and 0xFF
        val a2 = (c2 shr 24) and 0xFF
        val r2 = (c2 shr 16) and 0xFF
        val g2 = (c2 shr 8) and 0xFF
        val b2 = c2 and 0xFF
        val a = (a1 + (a2 - a1) * tt).toInt()
        val r = (r1 + (r2 - r1) * tt).toInt()
        val g = (g1 + (g2 - g1) * tt).toInt()
        val b = (b1 + (b2 - b1) * tt).toInt()
        return (a shl 24) or (r shl 16) or (g shl 8) or b
    }
}

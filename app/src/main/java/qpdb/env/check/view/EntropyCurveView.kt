package qpdb.env.check.view

import android.content.Context
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.graphics.Path
import android.util.AttributeSet
import android.view.View
import qpdb.env.check.utils.PropertyUtil

/**
 * 属性复杂度（熵）曲线图
 * 参考 doc/complexity_fit.py 实现：
 * - 主图：综合复杂度分箱拟合曲线
 * - 右侧：Value Entropy / Key Entropy / Depth 箱线图
 */
class EntropyCurveView @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
    defStyleAttr: Int = 0
) : View(context, attrs, defStyleAttr) {

    private val paint = Paint(Paint.ANTI_ALIAS_FLAG)
    private val path = Path()

    private val keys: List<String>
    private val scores: FloatArray
    private val vEnts: FloatArray
    private val kEnts: FloatArray
    private val depths: FloatArray

    private val xFine: FloatArray
    private val yFine: FloatArray
    private val xBin: FloatArray
    private val yBinRaw: FloatArray

    init {
        setBackgroundColor(Color.parseColor("#1A1A2E"))

        val props = PropertyUtil.getAllProp()
        keys = props.keys.sorted()
        val n = keys.size

        vEnts = FloatArray(n)
        kEnts = FloatArray(n)
        depths = FloatArray(n)
        scores = FloatArray(n)

        keys.forEachIndexed { i, key ->
            val value = props[key] ?: ""
            vEnts[i] = shannonEntropy(value).toFloat()
            kEnts[i] = shannonEntropy(key).toFloat()
            depths[i] = key.count { it == '.' }.toFloat()
            scores[i] = vEnts[i] + 0.3f * kEnts[i] + 0.5f * depths[i]
        }

        val result = binSmooth(scores, nBins = 80, smoothRounds = 3)
        xFine = result.xFine
        yFine = result.yFine
        xBin = result.xBin
        yBinRaw = result.yBinRaw
    }

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)

        val w = width.toFloat()
        val h = height.toFloat()

        val padding = 20f
        val topOffset = 60f
        val gap = 20f

        // 标题
        paint.color = Color.WHITE
        paint.textSize = 36f
        paint.textAlign = Paint.Align.CENTER
        paint.style = Paint.Style.FILL
        canvas.drawText("Complexity Trend (Fitted)", w / 2f, 45f, paint)

        // 主图占满整个宽度
        val mainLeft = padding
        val mainRight = w - padding
        val chartTop = topOffset + 10f
        val chartBottom = h - padding - 10f

        // ── 主图 ──
        val mainChartH = chartBottom - chartTop
        val scoreMin = scores.minOrNull() ?: 0f
        val scoreMax = scores.maxOrNull() ?: 1f
        val scoreRange = if (scoreMax > scoreMin) scoreMax - scoreMin else 1f

        // 散点（极淡）
        paint.color = Color.parseColor("#33CCCCCC")
        paint.style = Paint.Style.FILL
        val xScale = (mainRight - mainLeft) / 80f
        val yScale = mainChartH / (scoreRange * 1.1f)
        val yBase = chartBottom - scoreMin * yScale

        scores.forEachIndexed { i, score ->
            val x = mainLeft + (i.toFloat() / keys.size) * 80f * xScale
            val y = yBase - score * yScale
            canvas.drawCircle(x, y, 1.5f, paint)
        }

        // 拟合填充区域
        path.reset()
        val xStart = mainLeft + xFine[0] * xScale
        val yStart = yBase - yFine[0] * yScale
        path.moveTo(xStart, yStart)
        for (i in 1 until xFine.size) {
            val x = mainLeft + xFine[i] * xScale
            val y = yBase - yFine[i] * yScale
            path.lineTo(x, y)
        }
        path.lineTo(mainLeft + xFine.last() * xScale, chartBottom)
        path.lineTo(mainLeft + xFine[0] * xScale, chartBottom)
        path.close()
        paint.color = Color.parseColor("#40AB63FA")
        paint.style = Paint.Style.FILL
        canvas.drawPath(path, paint)

        // 拟合曲线
        path.reset()
        path.moveTo(xStart, yStart)
        for (i in 1 until xFine.size) {
            val x = mainLeft + xFine[i] * xScale
            val y = yBase - yFine[i] * yScale
            path.lineTo(x, y)
        }
        paint.color = Color.parseColor("#AB63FA")
        paint.style = Paint.Style.STROKE
        paint.strokeWidth = 3f
        paint.strokeCap = Paint.Cap.ROUND
        paint.strokeJoin = Paint.Join.ROUND
        canvas.drawPath(path, paint)

        // bin 点
        paint.style = Paint.Style.FILL
        for (i in xBin.indices) {
            val x = mainLeft + xBin[i] * xScale
            val y = yBase - yBinRaw[i] * yScale
            paint.color = binColor(yBinRaw[i], scoreMin, scoreMax)
            canvas.drawCircle(x, y, 4.5f, paint)
            paint.color = Color.WHITE
            paint.style = Paint.Style.STROKE
            paint.strokeWidth = 0.8f
            canvas.drawCircle(x, y, 4.5f, paint)
            paint.style = Paint.Style.FILL
        }

        // 主图坐标轴
        paint.color = Color.parseColor("#555577")
        paint.strokeWidth = 1f
        paint.style = Paint.Style.STROKE
        // Y 轴网格
        val gridCount = 5
        for (i in 0..gridCount) {
            val ratio = i / gridCount.toFloat()
            val y = chartBottom - mainChartH * ratio
            canvas.drawLine(mainLeft, y, mainRight, y, paint)
            paint.color = Color.parseColor("#A0A0A0")
            paint.textSize = 18f
            paint.textAlign = Paint.Align.RIGHT
            paint.style = Paint.Style.FILL
            val label = String.format("%.1f", scoreMin + scoreRange * ratio)
            canvas.drawText(label, mainLeft - 8f, y + 6f, paint)
            paint.color = Color.parseColor("#555577")
            paint.style = Paint.Style.STROKE
        }
        // 轴线
        paint.color = Color.parseColor("#8888AA")
        paint.strokeWidth = 2f
        canvas.drawLine(mainLeft, chartTop, mainLeft, chartBottom, paint)
        canvas.drawLine(mainLeft, chartBottom, mainRight, chartBottom, paint)

        // 统计文字
        paint.color = Color.parseColor("#808080")
        paint.textSize = 18f
        paint.textAlign = Paint.Align.RIGHT
        paint.style = Paint.Style.FILL
        canvas.drawText("n_keys=${keys.size}  bins=${xBin.size}", mainRight, chartTop + 6f, paint)
    }

    private fun shannonEntropy(s: String): Double {
        if (s.isEmpty()) return 0.0
        val freq = mutableMapOf<Char, Int>()
        for (ch in s) {
            freq[ch] = freq.getOrDefault(ch, 0) + 1
        }
        var entropy = 0.0
        val n = s.length.toDouble()
        for (count in freq.values) {
            val p = count / n
            entropy -= p * kotlin.math.log2(p)
        }
        return entropy
    }

    private data class BinResult(
        val xFine: FloatArray,
        val yFine: FloatArray,
        val xBin: FloatArray,
        val yBinRaw: FloatArray
    )

    private fun binSmooth(scores: FloatArray, nBins: Int = 80, smoothRounds: Int = 3): BinResult {
        val n = scores.size
        val binSize = n.toFloat() / nBins
        val xBin = FloatArray(nBins) { it.toFloat() }
        val yBinRaw = FloatArray(nBins)

        for (i in 0 until nBins) {
            val start = (i * binSize).toInt()
            val end = if (i < nBins - 1) ((i + 1) * binSize).toInt() else n
            var sum = 0f
            for (j in start until end) {
                sum += scores[j]
            }
            yBinRaw[i] = sum / (end - start).coerceAtLeast(1)
        }

        var ySmooth = yBinRaw.copyOf()
        for (_r in 0 until smoothRounds) {
            val smoothed = FloatArray(nBins)
            for (i in 0 until nBins) {
                val left = if (i > 0) ySmooth[i - 1] else ySmooth[i]
                val center = ySmooth[i]
                val right = if (i < nBins - 1) ySmooth[i + 1] else ySmooth[i]
                smoothed[i] = (left + center + right) / 3f
            }
            ySmooth = smoothed
        }

        val fineSize = 400
        val xFine = FloatArray(fineSize) { i -> i.toFloat() / (fineSize - 1) * (nBins - 1) }
        val yFine = FloatArray(fineSize) { i ->
            linearInterpolate(xFine[i], xBin, ySmooth)
        }

        return BinResult(xFine, yFine, xBin, yBinRaw)
    }

    private fun linearInterpolate(x: Float, xp: FloatArray, yp: FloatArray): Float {
        if (x <= xp.first()) return yp.first()
        if (x >= xp.last()) return yp.last()
        var i = 0
        while (i < xp.size - 1 && x > xp[i + 1]) i++
        val t = (x - xp[i]) / (xp[i + 1] - xp[i])
        return yp[i] + t * (yp[i + 1] - yp[i])
    }

    private fun binColor(value: Float, min: Float, max: Float): Int {
        val t = if (max > min) (value - min) / (max - min) else 0f
        val tt = t.coerceIn(0f, 1f)
        // plasma colormap 近似：暗紫 -> 橙红 -> 亮黄
        return when {
            tt < 0.25f -> interpolateColor(0xFF3B0F70.toInt(), 0xFF5D1898.toInt(), tt * 4f)
            tt < 0.5f -> interpolateColor(0xFF5D1898.toInt(), 0xFFAB63FA.toInt(), (tt - 0.25f) * 4f)
            tt < 0.75f -> interpolateColor(0xFFAB63FA.toInt(), 0xFFFFB56B.toInt(), (tt - 0.5f) * 4f)
            else -> interpolateColor(0xFFFFB56B.toInt(), 0xFFFFFFCC.toInt(), (tt - 0.75f) * 4f)
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

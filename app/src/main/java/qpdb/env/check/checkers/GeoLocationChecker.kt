package qpdb.env.check.checkers

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.location.Location
import android.location.LocationManager
import android.os.Build
import android.provider.Settings
import android.util.Log
import androidx.core.content.ContextCompat
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.runBlocking
import qpdb.env.check.EnvCheckApp
import qpdb.env.check.model.CheckItem
import qpdb.env.check.model.CheckResult
import qpdb.env.check.model.CheckStatus
import qpdb.env.check.model.Checkable
import qpdb.env.check.utils.GpsDetectionUtil
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * 地理位置检测
 *
 * 全面检测 GPS / GNSS 相关数据：
 * 1. 定位权限
 * 2. 定位提供器状态（GPS / 网络 / 被动）
 * 3. 最近定位与当前定位（尽力获取新 fix）
 * 4. 定位质量评估（精度 / 速度 / 方位 / fix 时效）
 * 5. GNSS 卫星数据（数量 / 星座分布 / 信号强度 / 卫星详情）
 * 6. NMEA 数据流（原始语句 / 类型统计 / GGA·RMC·GSA·GSV 解析）
 * 7. GNSS 硬件能力（硬件年份 / 型号 / 能力位）
 * 8. 模拟位置检测（Mock 标志 / 模拟器坐标 / 系统设置）
 * 9. 多源位置一致性（GPS vs 网络）
 * 10. 综合评估
 */
class GeoLocationChecker : Checkable {

    companion object {
        private const val TAG = "GeoLocationChecker"

        /** GNSS 卫星 / NMEA 采集窗口（10s，兼顾 GPS 锁定初期信号稳定与检测耗时） */
        private const val GNSS_WINDOW_MS = 10_000L

        /** 当前定位获取超时（15s：热启动 1~3s 可拿到 fix，温启动 10~15s） */
        private const val LOCATION_TIMEOUT_MS = 15_000L

        /** GPS 与网络位置相差超过该距离视为异常（米） */
        private const val CONSISTENCY_THRESHOLD_M = 100_000

        /** 一致性比对时位置最大可接受时效（毫秒，3 小时） */
        private const val CONSISTENCY_MAX_AGE_MS = 3 * 3600 * 1000L
    }

    override val categoryName: String = "地理位置检测"

    override fun checkList(): List<CheckItem> = listOf(
        CheckItem(
            name = "定位权限",
            checkPoint = "permission",
            description = "等待检测..."
        ),
        CheckItem(
            name = "定位提供器",
            checkPoint = "providers",
            description = "等待检测..."
        ),
        CheckItem(
            name = "GPS 定位状态",
            checkPoint = "gps_enabled",
            description = "等待检测..."
        ),
        CheckItem(
            name = "网络定位状态",
            checkPoint = "network_enabled",
            description = "等待检测..."
        ),
        CheckItem(
            name = "最近定位信息",
            checkPoint = "last_location",
            description = "等待检测..."
        ),
        CheckItem(
            name = "当前定位信息",
            checkPoint = "current_location",
            description = "等待检测..."
        ),
        CheckItem(
            name = "定位质量评估",
            checkPoint = "location_quality",
            description = "等待检测..."
        ),
        CheckItem(
            name = "卫星数量统计",
            checkPoint = "satellite_overview",
            description = "等待检测..."
        ),
        CheckItem(
            name = "卫星星座分布",
            checkPoint = "satellite_constellation",
            description = "等待检测..."
        ),
        CheckItem(
            name = "卫星信号强度",
            checkPoint = "satellite_signal",
            description = "等待检测..."
        ),
        CheckItem(
            name = "卫星列表详情",
            checkPoint = "satellite_details",
            description = "等待检测..."
        ),
        CheckItem(
            name = "NMEA 原始数据",
            checkPoint = "nmea_raw",
            description = "等待检测..."
        ),
        CheckItem(
            name = "NMEA 语句统计",
            checkPoint = "nmea_stats",
            description = "等待检测..."
        ),
        CheckItem(
            name = "NMEA 解析定位",
            checkPoint = "nmea_parsed",
            description = "等待检测..."
        ),
        CheckItem(
            name = "GNSS 硬件能力",
            checkPoint = "gnss_hardware",
            description = "等待检测..."
        ),
        CheckItem(
            name = "模拟位置检测",
            checkPoint = "mock_location",
            description = "等待检测..."
        ),
        CheckItem(
            name = "多源位置一致性",
            checkPoint = "location_consistency",
            description = "等待检测..."
        ),
        CheckItem(
            name = "综合评估",
            checkPoint = "overall",
            description = "等待检测..."
        )
    )

    override fun runCheck(): List<CheckItem> = runBlocking { runCheckBlocking() }

    override suspend fun runCheckWithProgress(
        onProgress: suspend (CheckItem) -> Unit
    ): List<CheckItem> = runCheckBlocking(onProgress)

    private suspend fun runCheckBlocking(
        onProgress: suspend (CheckItem) -> Unit = {}
    ): List<CheckItem> {
        val items = checkList().toMutableList()

        suspend fun emit(checkPoint: String) {
            items.find { it.checkPoint == checkPoint }?.let { onProgress(it) }
        }

        suspend fun setResult(checkPoint: String, result: CheckResult) {
            items.find { it.checkPoint == checkPoint }?.let {
                it.status = result.status
                it.description = result.description
            }
            emit(checkPoint)
        }

        val context = EnvCheckApp.getContext()
        val lm = context.getSystemService(Context.LOCATION_SERVICE) as? LocationManager
        if (lm == null) {
            setResult("permission", CheckResult(CheckStatus.FAIL, "无法获取定位服务"))
            items.forEach {
                if (it.checkPoint != "permission") {
                    it.status = CheckStatus.INFO
                    it.description = "定位服务不可用"
                }
            }
            return items
        }

        // ===== 1. 定位权限 =====
        val fineGranted = ContextCompat.checkSelfPermission(
            context, Manifest.permission.ACCESS_FINE_LOCATION
        ) == PackageManager.PERMISSION_GRANTED
        val coarseGranted = ContextCompat.checkSelfPermission(
            context, Manifest.permission.ACCESS_COARSE_LOCATION
        ) == PackageManager.PERMISSION_GRANTED

        when {
            fineGranted -> setResult(
                "permission",
                CheckResult(CheckStatus.PASS, "已授予精确定位权限 (ACCESS_FINE_LOCATION)")
            )
            coarseGranted -> setResult(
                "permission",
                CheckResult(
                    CheckStatus.INFO,
                    "仅授予粗略定位权限 (ACCESS_COARSE_LOCATION)\n" +
                            "卫星 / NMEA 等 GNSS 数据需要精确定位权限，将跳过相关检测"
                )
            )
            else -> {
                setResult(
                    "permission",
                    CheckResult(
                        CheckStatus.FAIL,
                        "缺少定位权限 (ACCESS_FINE_LOCATION / ACCESS_COARSE_LOCATION)\n" +
                                "请在系统设置中开启「精确位置」权限后重试"
                    )
                )
                items.forEach {
                    if (it.checkPoint != "permission") {
                        it.status = CheckStatus.INFO
                        it.description = "缺少定位权限，无法检测"
                    }
                }
                return items
            }
        }

        // 卫星 / NMEA / 当前定位需要精确定位权限
        val canUseGnss = fineGranted

        // ===== 2. 提供器状态 =====
        setResult("providers", buildProvidersResult(lm))

        val gpsEnabled = lm.isProviderEnabled(LocationManager.GPS_PROVIDER)
        setResult(
            "gps_enabled",
            if (gpsEnabled) {
                CheckResult(CheckStatus.PASS, "GPS 定位已开启")
            } else {
                CheckResult(CheckStatus.INFO, "GPS 定位未开启\n开启后卫星 / NMEA 数据才会产生")
            }
        )

        val networkEnabled = lm.isProviderEnabled(LocationManager.NETWORK_PROVIDER)
        setResult(
            "network_enabled",
            if (networkEnabled) {
                CheckResult(CheckStatus.PASS, "网络定位已开启")
            } else {
                CheckResult(CheckStatus.INFO, "网络定位未开启\n(Wi-Fi / 基站定位)")
            }
        )

        // ===== 3. 最近定位 =====
        val lastGps = safeLastKnownLocation(lm, LocationManager.GPS_PROVIDER)
        val lastNetwork = safeLastKnownLocation(lm, LocationManager.NETWORK_PROVIDER)
        val lastPassive = safeLastKnownLocation(lm, LocationManager.PASSIVE_PROVIDER)
        setResult("last_location", buildLastLocationResult(lastGps, lastNetwork, lastPassive))

        // ===== 4. 并行采集 GNSS 快照 + 当前定位 =====
        var snapshot: GpsDetectionUtil.GnssSnapshot? = null
        var currentLoc: Location? = null

        if (canUseGnss) {
            try {
                coroutineScope {
                    val s = async { GpsDetectionUtil.collectGnssSnapshot(lm, GNSS_WINDOW_MS) }
                    val c = async {
                        GpsDetectionUtil.requestCurrentLocation(
                            context, lm, LocationManager.GPS_PROVIDER, LOCATION_TIMEOUT_MS
                        )
                    }
                    snapshot = s.await()
                    currentLoc = c.await()
                }
            } catch (e: Exception) {
                Log.e(TAG, "GNSS 采集异常: ${e.message}", e)
                snapshot = GpsDetectionUtil.GnssSnapshot(emptyList(), emptyList(), -1)
            }
        }

        // ===== 5. 当前定位 / 定位质量 =====
        val bestLast = listOfNotNull(lastGps, lastNetwork, lastPassive)
            .maxByOrNull { it.time } ?: currentLoc
        val effectiveCurrent = currentLoc ?: bestLast

        setResult("current_location", buildCurrentLocationResult(currentLoc, bestLast))

        setResult(
            "location_quality",
            if (effectiveCurrent != null) {
                buildQualityResult(effectiveCurrent)
            } else {
                CheckResult(CheckStatus.INFO, "无可用定位数据")
            }
        )

        // ===== 6. 卫星数据 =====
        val sats = snapshot?.satellites ?: emptyList()
        if (!canUseGnss) {
            val msg = "需要精确定位权限"
            setResult("satellite_overview", CheckResult(CheckStatus.INFO, msg))
            setResult("satellite_constellation", CheckResult(CheckStatus.INFO, msg))
            setResult("satellite_signal", CheckResult(CheckStatus.INFO, msg))
            setResult("satellite_details", CheckResult(CheckStatus.INFO, msg))
            setResult("nmea_raw", CheckResult(CheckStatus.INFO, msg))
            setResult("nmea_stats", CheckResult(CheckStatus.INFO, msg))
            setResult("nmea_parsed", CheckResult(CheckStatus.INFO, msg))
        } else {
            setResult("satellite_overview", buildSatelliteOverview(sats, snapshot?.firstFixTimeMs))
            setResult("satellite_constellation", buildConstellationResult(sats))
            setResult("satellite_signal", buildSignalResult(sats))
            setResult("satellite_details", buildSatelliteDetails(sats))
            setResult("nmea_raw", buildNmeaRawResult(snapshot?.nmeaSentences))
            setResult("nmea_stats", buildNmeaStatsResult(snapshot?.nmeaSentences))
            setResult("nmea_parsed", buildNmeaParsedResult(snapshot?.nmeaSentences))
        }

        // ===== 7. GNSS 硬件能力 =====
        setResult("gnss_hardware", buildGnssHardwareResult(lm))

        // ===== 8. 模拟位置检测 =====
        setResult(
            "mock_location",
            buildMockLocationResult(context, currentLoc, lastGps, lastNetwork, lastPassive)
        )

        // ===== 9. 多源位置一致性 =====
        setResult(
            "location_consistency",
            buildConsistencyResult(currentLoc, lastGps, lastNetwork)
        )

        // ===== 10. 综合评估 =====
        setResult("overall", buildOverallResult(items, gpsEnabled, sats.isNotEmpty()))

        return items
    }

    // ==================== 检测项构建 ====================

    private fun buildProvidersResult(lm: LocationManager): CheckResult {
        return try {
            val allProviders = lm.allProviders
            val enabledProviders = lm.getProviders(true)
            val sb = StringBuilder()
            sb.append("已启用 (${enabledProviders.size}): ${enabledProviders.joinToString(", ")}\n")
            sb.append("全部提供器 (${allProviders.size}): ${allProviders.joinToString(", ")}")
            CheckResult(CheckStatus.INFO, sb.toString())
        } catch (e: Exception) {
            Log.e(TAG, "查询提供器失败: ${e.message}")
            CheckResult(CheckStatus.INFO, "查询失败: ${e.message}")
        }
    }

    private fun buildLastLocationResult(
        lastGps: Location?,
        lastNetwork: Location?,
        lastPassive: Location?
    ): CheckResult {
        val sb = StringBuilder()
        if (lastGps != null) {
            sb.append("GPS: ${GpsDetectionUtil.formatLatLng(lastGps.latitude, lastGps.longitude)}")
            sb.append("  (${formatAge(lastGps.time)})\n")
        } else {
            sb.append("GPS: 无记录\n")
        }
        if (lastNetwork != null) {
            sb.append("网络: ${GpsDetectionUtil.formatLatLng(lastNetwork.latitude, lastNetwork.longitude)}")
            sb.append("  (${formatAge(lastNetwork.time)})\n")
        } else {
            sb.append("网络: 无记录\n")
        }
        if (lastPassive != null) {
            sb.append("被动: ${GpsDetectionUtil.formatLatLng(lastPassive.latitude, lastPassive.longitude)}")
            sb.append("  (${formatAge(lastPassive.time)})")
        } else {
            sb.append("被动: 无记录")
        }
        return CheckResult(CheckStatus.INFO, sb.toString())
    }

    private fun buildCurrentLocationResult(currentLoc: Location?, bestLast: Location?): CheckResult {
        if (currentLoc != null) {
            return CheckResult(
                CheckStatus.PASS,
                "获取到新的定位 (GPS)\n${describeLocation(currentLoc)}"
            )
        }
        if (bestLast != null) {
            return CheckResult(
                CheckStatus.INFO,
                "未能在 ${LOCATION_TIMEOUT_MS / 1000}s 内获取新定位\n回退到最近一次定位:\n${describeLocation(bestLast)}"
            )
        }
        return CheckResult(CheckStatus.INFO, "无可用定位数据")
    }

    private fun buildQualityResult(loc: Location): CheckResult {
        val sb = StringBuilder()
        if (loc.hasAccuracy()) sb.append("水平精度: %.1f 米\n".format(loc.accuracy))
        if (loc.hasAltitude()) sb.append("海拔: %.1f 米\n".format(loc.altitude))
        if (loc.hasSpeed()) sb.append("速度: %.1f m/s (%.1f km/h)\n".format(loc.speed, loc.speed * 3.6))
        if (loc.hasBearing()) sb.append("方位: %.1f°\n".format(loc.bearing))
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            if (loc.hasVerticalAccuracy()) sb.append("垂直精度: %.1f 米\n".format(loc.verticalAccuracyMeters))
            if (loc.hasSpeedAccuracy()) sb.append("速度精度: %.1f m/s\n".format(loc.speedAccuracyMetersPerSecond))
            if (loc.hasBearingAccuracy()) sb.append("方位精度: %.1f°\n".format(loc.bearingAccuracyDegrees))
        }
        sb.append("fix 时效: ${formatAge(loc.time)}")

        // 精度异常提示（低于 3 米且无垂直精度，通常只有测量型设备可达）
        val suspiciousPrecision = loc.hasAccuracy() && loc.accuracy < 3f &&
                (!loc.hasVerticalAccuracy() || loc.verticalAccuracyMeters == 0f)
        return if (suspiciousPrecision) {
            CheckResult(
                CheckStatus.INFO,
                sb.toString() + "\n精度异常偏高，疑似模拟定位或测试模式"
            )
        } else {
            CheckResult(CheckStatus.INFO, sb.toString())
        }
    }

    private fun buildSatelliteOverview(sats: List<GpsDetectionUtil.SatInfo>, ttff: Int?): CheckResult {
        if (sats.isEmpty()) {
            return CheckResult(
                CheckStatus.INFO,
                "采集窗口内未捕获到卫星数据\n(GPS 未开启、室内或天线受阻)"
            )
        }
        val visible = sats.size
        val used = sats.count { it.usedInFix }
        val sb = StringBuilder()
        sb.append("可见卫星: $visible 颗\n")
        sb.append("参与定位解算: $used 颗\n")
        if (ttff != null && ttff >= 0) sb.append("首次定位 (TTFF): ${ttff}ms")
        return CheckResult(
            if (used > 0) CheckStatus.PASS else CheckStatus.INFO,
            sb.toString()
        )
    }

    private fun buildConstellationResult(sats: List<GpsDetectionUtil.SatInfo>): CheckResult {
        if (sats.isEmpty()) {
            return CheckResult(CheckStatus.INFO, "无卫星数据")
        }
        val byConstellation = sats.groupBy { it.constellationType }
        val sb = StringBuilder()
        byConstellation.entries
            .sortedByDescending { it.value.size }
            .forEach { (type, list) ->
                val used = list.count { it.usedInFix }
                sb.append("${GpsDetectionUtil.constellationName(type)}: ${list.size} 颗")
                sb.append(" (参与定位 $used)\n")
            }
        return CheckResult(CheckStatus.INFO, sb.toString().trim())
    }

    private fun buildSignalResult(sats: List<GpsDetectionUtil.SatInfo>): CheckResult {
        if (sats.isEmpty()) {
            return CheckResult(CheckStatus.INFO, "无卫星数据")
        }
        val cn0s = sats.map { it.cn0DbHz }.filter { it > 0f }
        val best = sats.maxByOrNull { it.cn0DbHz }
        val sb = StringBuilder()
        sb.append("最佳卫星: ${best?.let { "${GpsDetectionUtil.constellationName(it.constellationType)} SV${it.svid}" } ?: "-"}")
        sb.append("  信号 ${best?.cn0DbHz?.let { "%.1f".format(it) } ?: "-"} dB-Hz\n")
        if (cn0s.isNotEmpty()) {
            sb.append("平均信号: %.1f dB-Hz\n".format(cn0s.average()))
            sb.append("信号范围: %.1f ~ %.1f dB-Hz".format(cn0s.min(), cn0s.max()))
        }
        return CheckResult(CheckStatus.INFO, sb.toString())
    }

    private fun buildSatelliteDetails(sats: List<GpsDetectionUtil.SatInfo>): CheckResult {
        if (sats.isEmpty()) {
            return CheckResult(CheckStatus.INFO, "无卫星数据")
        }
        val sb = StringBuilder()
        sb.append("共 ${sats.size} 颗卫星（按信号强度排序）:\n")
        sats.sortedByDescending { it.cn0DbHz }
            .take(48)
            .forEach { sat ->
                val name = GpsDetectionUtil.constellationName(sat.constellationType)
                val freq = if (sat.hasCarrierFreq && sat.carrierFreqHz != null) {
                    "  %.2f MHz".format(sat.carrierFreqHz / 1_000_000f)
                } else ""
                val used = if (sat.usedInFix) "★" else " "
                sb.append("$used SV${sat.svid} [$name] ${"%.1f".format(sat.cn0DbHz)}dB-Hz")
                sb.append(" 仰角${"%.0f°".format(sat.elevationDeg)} 方位${"%.0f°".format(sat.azimuthDeg)}")
                sb.append("$freq\n")
            }
        return CheckResult(CheckStatus.INFO, sb.toString().trim())
    }

    private fun buildNmeaRawResult(sentences: List<String>?): CheckResult {
        if (sentences.isNullOrEmpty()) {
            return CheckResult(CheckStatus.INFO, "未捕获到 NMEA 数据\n(GPS 未开启或无信号)")
        }
        // NMEA 校验和统计：真实芯片语句普遍带 *XX 校验和，虚拟 GNSS 注入常缺失/错误
        val stats = GpsDetectionUtil.analyzeNmeaChecksums(sentences)
        val sb = StringBuilder()
        if (stats.isSuspicious) {
            sb.append("⚠ NMEA 校验和异常（无校验和/校验失败占比高），疑似虚拟 GNSS 注入\n")
        }
        sb.append("采集到 ${sentences.size} 条语句，显示最近 ${minOf(sentences.size, 15)} 条:\n")
        sb.append("校验和: 有效 ${stats.valid} / 错误 ${stats.invalid} / 缺失 ${stats.missing}\n")
        sentences.takeLast(15).forEach { line ->
            sb.append(if (line.length > 120) line.take(120) + "..." else line)
            sb.append("\n")
        }
        return if (stats.isSuspicious) {
            CheckResult(CheckStatus.FAIL, sb.toString().trim())
        } else {
            CheckResult(CheckStatus.INFO, sb.toString().trim())
        }
    }

    private fun buildNmeaStatsResult(sentences: List<String>?): CheckResult {
        if (sentences.isNullOrEmpty()) {
            return CheckResult(CheckStatus.INFO, "无 NMEA 数据")
        }
        val counts = LinkedHashMap<String, Int>()
        sentences.forEach { line ->
            val id = line.trim().substringAfter("$").substringBefore(",")
            val type = id.takeLast(3)
            counts[type] = (counts[type] ?: 0) + 1
        }
        val sb = StringBuilder()
        sb.append("语句总数: ${sentences.size}\n")
        counts.forEach { (type, count) ->
            sb.append("$type: $count\n")
        }
        return CheckResult(CheckStatus.INFO, sb.toString().trim())
    }

    private fun buildNmeaParsedResult(sentences: List<String>?): CheckResult {
        if (sentences.isNullOrEmpty()) {
            return CheckResult(CheckStatus.INFO, "无 NMEA 数据")
        }
        val infos = sentences.mapNotNull { GpsDetectionUtil.parseNmea(it) }
        val gga = infos.filter { it.type == "GGA" }.lastOrNull()
        val rmc = infos.filter { it.type == "RMC" }.lastOrNull()
        val gsa = infos.filter { it.type == "GSA" }.lastOrNull()
        val gsv = infos.filter { it.type == "GSV" }.lastOrNull()

        val sb = StringBuilder()
        if (gga != null) {
            sb.append("GGA: 质量=${gga.fixQuality?.let { GpsDetectionUtil.fixQualityName(it) } ?: "-"}")
            sb.append(" 卫星=${gga.satUsed ?: "-"}")
            sb.append(" HDOP=${gga.hdop?.let { "%.1f".format(it) } ?: "-"}\n")
            if (gga.latitude != null && gga.longitude != null) {
                sb.append("  坐标: ${GpsDetectionUtil.formatLatLng(gga.latitude, gga.longitude)}\n")
            }
            if (gga.altitudeMeters != null) {
                sb.append("  海拔: %.1f 米\n".format(gga.altitudeMeters))
            }
        }
        if (rmc != null) {
            val status = when (rmc.status) {
                'A' -> "有效"
                'V' -> "无效"
                else -> "-"
            }
            sb.append("RMC: 状态=${status}")
            if (rmc.latitude != null && rmc.longitude != null) {
                sb.append(" 坐标: ${GpsDetectionUtil.formatLatLng(rmc.latitude, rmc.longitude)}")
            }
            if (rmc.speedKnots != null) {
                sb.append(" 速度: %.1f km/h".format(rmc.speedKnots * 1.852))
            }
            sb.append("\n")
        }
        if (gsa != null) {
            val mode = when (gsa.fixMode) {
                2 -> "2D 定位"
                3 -> "3D 定位"
                else -> "未定位"
            }
            sb.append("GSA: $mode")
            sb.append(" PDOP=${gsa.pdop?.let { "%.1f".format(it) } ?: "-"}")
            sb.append(" HDOP=${gsa.hdop?.let { "%.1f".format(it) } ?: "-"}")
            sb.append(" VDOP=${gsa.vdop?.let { "%.1f".format(it) } ?: "-"}\n")
        }
        if (gsv != null) {
            sb.append("GSV: 可见卫星=${gsv.satsInView ?: "-"} 颗")
            if (gsv.gsvSats.isNotEmpty()) {
                val strong = gsv.gsvSats.count { (it.snr ?: 0.0) >= 30 }
                sb.append(" (信号≥30dB: $strong)")
            }
            sb.append("\n")
        }
        if (sb.isEmpty()) {
            return CheckResult(CheckStatus.INFO, "未解析出 GGA/RMC/GSA/GSV 语句")
        }
        return CheckResult(CheckStatus.INFO, sb.toString().trim())
    }

    private fun buildGnssHardwareResult(lm: LocationManager): CheckResult {
        val sb = StringBuilder()

        // ==================== 硬件信息展示 ====================

        // 硬件年份（API 28+，方法位于 LocationManager）
        var hardwareYear = 0
        try {
            hardwareYear = lm.gnssYearOfHardware
            sb.append("GNSS 硬件年份: ${if (hardwareYear == 0) "不可用" else "$hardwareYear 年"}\n")
        } catch (e: Exception) {
            sb.append("GNSS 硬件年份: 查询失败 (${e.message})\n")
        }

        // 硬件型号（API 31+）
        var hardwareModel: String? = null
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            try {
                hardwareModel = lm.gnssHardwareModelName
                sb.append("GNSS 硬件型号: ${hardwareModel?.ifEmpty { "不可用" } ?: "不可用"}\n")
            } catch (e: Exception) {
                sb.append("GNSS 硬件型号: 查询失败 (${e.message})\n")
            }
        } else {
            sb.append("GNSS 硬件型号: (API 31+ 提供)\n")
        }

        // GNSS 能力（基础能力 API 31+，扩展能力 API 34+）
        // 注意: hasMsb/hasMsa/hasSatellitePvt/hasMeasurementCorrelationVectors 等均为 API 34
        // 引入，Android 12/13 上调用会抛 NoSuchMethodError，必须用 UPSIDE_DOWN_CAKE 守卫。
        var hasMsbOrMsa = false
        var hasNavMessages = false
        var hasSatellitePvt = false
        var hasCorrVectors = false
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            try {
                val caps = lm.gnssCapabilities
                val capabilities = mutableListOf<String>()
                if (caps.hasMeasurements()) capabilities.add("原始测量值")
                if (caps.hasNavigationMessages()) {
                    capabilities.add("导航电文")
                    hasNavMessages = true
                }
                if (caps.hasAntennaInfo()) capabilities.add("天线信息")
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                    if (caps.hasSatellitePvt()) {
                        capabilities.add("卫星 PVT")
                        hasSatellitePvt = true
                    }
                    if (caps.hasMeasurementCorrelationVectors()) {
                        capabilities.add("相关向量")
                        hasCorrVectors = true
                    }
                    if (caps.hasMsb()) {
                        capabilities.add("MS-Based A-GNSS")
                        hasMsbOrMsa = true
                    }
                    if (caps.hasMsa()) {
                        capabilities.add("MS-Assisted A-GNSS")
                        hasMsbOrMsa = true
                    }
                    if (caps.hasGeofencing()) capabilities.add("地理围栏")
                    if (caps.hasLowPowerMode()) capabilities.add("低功耗模式")
                    if (caps.hasSingleShotFix()) capabilities.add("单次定位")
                    if (caps.hasOnDemandTime()) capabilities.add("按需授时")
                    if (caps.hasScheduling()) capabilities.add("调度能力")
                }
                sb.append("GNSS 能力 (${capabilities.size}): ${capabilities.joinToString(", ")}")
            } catch (e: Exception) {
                sb.append("GNSS 能力: 查询失败 (${e.message})")
            }
        } else {
            sb.append("GNSS 能力: (API 31+ 提供)")
        }

        // ==================== 虚拟 GNSS 特征判定 ====================

        // 1. 硬件型号含虚拟设备标识
        val suspiciousModel = try {
            hardwareModel?.let { GpsDetectionUtil.containsVirtualDeviceKeyword(it) } ?: false
        } catch (e: Exception) {
            false
        }

        // 2. 硬件年份异常（0 表示不可用不参与判定）
        val suspiciousYear = try {
            hardwareYear != 0 && hardwareYear < 2018
        } catch (e: Exception) {
            false
        }

        // 3. 能力组合异常：无 MSB/MSA/导航电文，却暴露卫星 PVT + 相关向量（仅 API 34+ 可判定）
        val suspiciousCaps = try {
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE &&
                !hasMsbOrMsa && !hasNavMessages && hasSatellitePvt && hasCorrVectors
        } catch (e: Exception) {
            false
        }

        // 4. 系统级虚拟设备特征（Build 属性）
        val buildFields = mapOf(
            "HARDWARE" to Build.HARDWARE,
            "PRODUCT" to Build.PRODUCT,
            "MODEL" to Build.MODEL,
            "DEVICE" to Build.DEVICE
        )
        val buildHits = buildFields.filter { (_, value) ->
            GpsDetectionUtil.containsVirtualDeviceKeyword(value)
        }

        // ==================== 汇总判定 ====================

        sb.append("\n--- 虚拟特征判定 ---\n")
        val signals = mutableListOf<String>()
        if (suspiciousModel) signals.add("GNSS 硬件型号含虚拟设备标识")
        if (suspiciousYear) signals.add("GNSS 硬件年份异常 (<2018)")
        if (suspiciousCaps) signals.add("GNSS 能力组合异常 (无 MSB/MSA/导航电文却暴露 PVT/相关向量)")
        if (buildHits.isNotEmpty()) {
            val desc = buildHits.entries.joinToString("; ") { "${it.key}=${it.value}" }
            signals.add("系统 Build 属性含虚拟设备标识 ($desc)")
        }

        if (signals.isEmpty()) {
            sb.append("未发现明显虚拟特征")
            return CheckResult(CheckStatus.INFO, sb.toString().trim())
        }
        signals.forEach { signal -> sb.append("⚠ $signal\n") }
        return CheckResult(CheckStatus.FAIL, sb.toString().trim())
    }

    private fun buildMockLocationResult(
        context: Context,
        currentLoc: Location?,
        lastGps: Location?,
        lastNetwork: Location?,
        lastPassive: Location?
    ): CheckResult {
        val locs = listOfNotNull(currentLoc, lastGps, lastNetwork, lastPassive)
        val mockLocs = locs.filter { GpsDetectionUtil.isMockLocation(it) }
        val emuLocs = locs.filter { GpsDetectionUtil.isKnownEmulatorCoordinate(it) }

        val allowMock = try {
            @Suppress("DEPRECATION")
            Settings.Secure.getInt(
                context.contentResolver, Settings.Secure.ALLOW_MOCK_LOCATION, 0
            ) == 1
        } catch (e: Exception) {
            false
        }

        val sb = StringBuilder()
        sb.append("检测位置源: ${locs.size} 个\n")
        if (locs.isNotEmpty()) {
            sb.append("Mock 标志位置源: ${mockLocs.size} 个\n")
            sb.append("已知模拟器坐标位置源: ${emuLocs.size} 个\n")
            sb.append("系统「允许模拟位置」: ${if (allowMock) "开启" else "关闭"}\n")
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                sb.append("(Android 12+ 该设置已被「选择模拟位置信息应用」取代，仅供参考)\n")
            }
        } else {
            sb.append("无可用位置数据，无法判定\n")
        }
        mockLocs.forEach { loc ->
            sb.append("⚠ Mock: ${loc.provider} ${GpsDetectionUtil.formatLatLng(loc.latitude, loc.longitude)}\n")
        }
        emuLocs.forEach { loc ->
            sb.append("⚠ 模拟器坐标: ${loc.provider} ${GpsDetectionUtil.formatLatLng(loc.latitude, loc.longitude)}\n")
        }

        return when {
            mockLocs.isNotEmpty() || emuLocs.isNotEmpty() -> CheckResult(CheckStatus.FAIL, sb.toString().trim())
            locs.isEmpty() -> CheckResult(CheckStatus.INFO, sb.toString().trim())
            else -> CheckResult(CheckStatus.PASS, sb.toString().trim())
        }
    }

    private fun buildConsistencyResult(
        currentLoc: Location?,
        lastGps: Location?,
        lastNetwork: Location?
    ): CheckResult {
        val gpsLoc = lastGps ?: currentLoc?.takeIf { it.provider == LocationManager.GPS_PROVIDER }
        val netLoc = lastNetwork ?: currentLoc?.takeIf { it.provider == LocationManager.NETWORK_PROVIDER }

        if (gpsLoc == null || netLoc == null) {
            return CheckResult(
                CheckStatus.INFO,
                "缺少 GPS 与网络两个位置源，无法比对一致性"
            )
        }

        val now = System.currentTimeMillis()
        val gpsFresh = now - gpsLoc.time <= CONSISTENCY_MAX_AGE_MS
        val netFresh = now - netLoc.time <= CONSISTENCY_MAX_AGE_MS
        val dist = GpsDetectionUtil.distanceMeters(
            gpsLoc.latitude, gpsLoc.longitude, netLoc.latitude, netLoc.longitude
        )

        val sb = StringBuilder()
        sb.append("GPS 位置: ${GpsDetectionUtil.formatLatLng(gpsLoc.latitude, gpsLoc.longitude)} (${formatAge(gpsLoc.time)})\n")
        sb.append("网络位置: ${GpsDetectionUtil.formatLatLng(netLoc.latitude, netLoc.longitude)} (${formatAge(netLoc.time)})\n")
        sb.append("两点距离: %.2f km\n".format(dist / 1000.0))

        return when {
            !gpsFresh || !netFresh -> CheckResult(
                CheckStatus.INFO,
                sb.toString() + "存在过期位置记录，比对结果仅供参考"
            )
            dist > CONSISTENCY_THRESHOLD_M -> CheckResult(
                CheckStatus.FAIL,
                sb.toString() + "GPS 与网络定位相距过远，疑似位置伪造 / 注入"
            )
            else -> CheckResult(
                CheckStatus.PASS,
                sb.toString() + "两源位置一致"
            )
        }
    }

    private fun buildOverallResult(
        items: List<CheckItem>,
        gpsEnabled: Boolean,
        hasSatelliteData: Boolean
    ): CheckResult {
        fun statusOf(checkPoint: String): CheckStatus =
            items.find { it.checkPoint == checkPoint }?.status ?: CheckStatus.INFO

        val mockFail = statusOf("mock_location") == CheckStatus.FAIL
        val consistencyFail = statusOf("location_consistency") == CheckStatus.FAIL
        val permissionFail = statusOf("permission") == CheckStatus.FAIL
        val virtualFail = statusOf("gnss_hardware") == CheckStatus.FAIL ||
            statusOf("nmea_raw") == CheckStatus.FAIL
        val hasFix = items.any {
            it.checkPoint == "current_location" && it.status == CheckStatus.PASS
        }

        val sb = StringBuilder()
        sb.append("定位权限: ${statusText(statusOf("permission"))}\n")
        sb.append("GPS 状态: ${if (gpsEnabled) "开启" else "关闭"}\n")
        sb.append("当前定位: ${if (hasFix) "已获取" else "未获取"}\n")
        sb.append("卫星数据: ${if (hasSatelliteData) "有" else "无"}\n")
        sb.append("模拟位置: ${statusText(statusOf("mock_location"))}\n")
        sb.append("位置一致性: ${statusText(statusOf("location_consistency"))}\n")
        sb.append("虚拟 GNSS 特征: ${statusText(statusOf("gnss_hardware"))}")

        return when {
            permissionFail -> CheckResult(CheckStatus.FAIL, sb.toString() + "\n结论: 缺少定位权限")
            mockFail || consistencyFail || virtualFail -> CheckResult(
                CheckStatus.FAIL,
                sb.toString() + "\n结论: 检测到位置或虚拟设备异常（位置伪造 / 模拟 / 虚拟 GNSS）"
            )
            hasFix -> CheckResult(
                CheckStatus.PASS,
                sb.toString() + "\n结论: 定位正常，未发现位置异常"
            )
            else -> CheckResult(
                CheckStatus.INFO,
                sb.toString() + "\n结论: 暂无有效定位（GPS 未开启或信号不佳）"
            )
        }
    }

    // ==================== 工具函数 ====================

    private fun safeLastKnownLocation(lm: LocationManager, provider: String): Location? {
        return try {
            @Suppress("DEPRECATION")
            lm.getLastKnownLocation(provider)
        } catch (e: SecurityException) {
            Log.w(TAG, "获取 $provider 最近定位失败: ${e.message}")
            null
        } catch (e: Exception) {
            Log.w(TAG, "获取 $provider 最近定位异常: ${e.message}")
            null
        }
    }

    private fun describeLocation(loc: Location): String {
        val sb = StringBuilder()
        sb.append("提供器: ${loc.provider}\n")
        sb.append("坐标: ${GpsDetectionUtil.formatLatLng(loc.latitude, loc.longitude)}\n")
        if (loc.hasAccuracy()) sb.append("精度: %.1f 米\n".format(loc.accuracy))
        if (loc.hasAltitude()) sb.append("海拔: %.1f 米\n".format(loc.altitude))
        if (loc.hasSpeed()) sb.append("速度: %.1f m/s (%.1f km/h)\n".format(loc.speed, loc.speed * 3.6))
        if (loc.hasBearing()) sb.append("方位: %.1f°\n".format(loc.bearing))
        sb.append("定位时间: ${formatTime(loc.time)} (${formatAge(loc.time)})")
        return sb.toString().trim()
    }

    private fun formatTime(time: Long): String =
        SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault()).format(Date(time))

    private fun formatAge(time: Long): String {
        val age = System.currentTimeMillis() - time
        return when {
            age < 0 -> "时间超前"
            age < 1000 -> "刚刚"
            age < 60_000 -> "${age / 1000} 秒前"
            age < 3_600_000 -> "${age / 60_000} 分钟前"
            age < 86_400_000 -> "${age / 3_600_000} 小时前"
            else -> "${age / 86_400_000} 天前"
        }
    }

    private fun statusText(status: CheckStatus): String = when (status) {
        CheckStatus.PASS -> "正常"
        CheckStatus.FAIL -> "异常"
        CheckStatus.INFO -> "未知/未检测"
    }
}

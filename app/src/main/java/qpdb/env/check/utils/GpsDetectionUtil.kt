package qpdb.env.check.utils

import android.content.Context
import android.location.GnssStatus
import android.location.Location
import android.location.LocationListener
import android.location.LocationManager
import android.location.OnNmeaMessageListener
import android.os.Build
import android.os.Bundle
import android.os.CancellationSignal
import android.os.Handler
import android.os.Looper
import android.util.Log
import androidx.core.content.ContextCompat
import kotlinx.coroutines.delay
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withTimeoutOrNull
import java.util.Collections
import java.util.concurrent.atomic.AtomicInteger
import kotlin.math.abs
import kotlin.math.asin
import kotlin.math.cos
import kotlin.math.sin
import kotlin.math.sqrt

/**
 * GPS / GNSS 检测工具类
 *
 * 提供：
 * 1. GNSS 卫星状态与 NMEA 数据流的窗口采集（异步）
 * 2. 当前定位的尽力获取（getCurrentLocation / requestSingleUpdate）
 * 3. NMEA 语句解析（GGA/RMC/GSA/GSV）
 * 4. 模拟位置 / 模拟器坐标判定
 * 5. 球面距离计算
 */
object GpsDetectionUtil {

    private const val TAG = "GpsDetectionUtil"

    /** NMEA 采集上限，防止内存膨胀 */
    private const val MAX_NMEA_CAPTURED = 200

    // ==================== 数据模型 ====================

    /**
     * 单颗卫星信息快照
     */
    data class SatInfo(
        val svid: Int,                  // 卫星编号 (PRN / SVID)
        val constellationType: Int,     // GnssStatus.CONSTELLATION_*
        val cn0DbHz: Float,             // 载噪比 (dB-Hz)
        val elevationDeg: Float,        // 仰角
        val azimuthDeg: Float,          // 方位角
        val usedInFix: Boolean,         // 是否参与定位解算
        val carrierFreqHz: Float?,      // 载波频率
        val hasCarrierFreq: Boolean
    )

    /**
     * 一个采集窗口内的 GNSS 快照
     */
    data class GnssSnapshot(
        val satellites: List<SatInfo>,
        val nmeaSentences: List<String>,
        val firstFixTimeMs: Int         // TTFF，-1 表示未定位
    )

    /**
     * GSV 语句中的单颗卫星
     */
    data class GsvSat(
        val prn: Int,
        val elevation: Double?,
        val azimuth: Double?,
        val snr: Double?
    )

    /**
     * 解析后的 NMEA 信息（各字段按语句类型部分填充）
     */
    data class NmeaInfo(
        val type: String,               // GGA / RMC / GSA / GSV
        val talker: String,             // GP / GL / GA / BD / GB / QZ ...
        val fixQuality: Int?,           // GGA: 定位质量
        val satUsed: Int?,              // GGA: 参与解算卫星数
        val altitudeMeters: Double?,    // GGA: 海拔
        val hdop: Double?,              // GGA/GSA: 水平精度因子
        val latitude: Double?,          // GGA/RMC: 纬度（十进制）
        val longitude: Double?,         // GGA/RMC: 经度（十进制）
        val status: Char?,              // RMC: 'A' 有效 / 'V' 无效
        val speedKnots: Double?,        // RMC: 速度（节）
        val trackDegrees: Double?,      // RMC: 航迹角
        val fixMode: Int?,              // GSA: 1=无, 2=2D, 3=3D
        val pdop: Double?,              // GSA: 位置精度因子
        val vdop: Double?,              // GSA: 垂直精度因子
        val satsInView: Int?,           // GSV: 可见卫星总数
        val gsvSats: List<GsvSat>,
        val raw: String
    )

    // ==================== GNSS 快照采集 ====================

    /**
     * 在 [windowMs] 毫秒窗口内采集卫星状态与 NMEA 数据。
     *
     * 注册 GnssStatus.Callback 与 NmeaListener（回调在主线程 Handler），
     * 数据收集到线程安全容器，窗口结束后统一反注册。
     *
     * @return 采集到的卫星快照与 NMEA 语句列表（可能为空）
     */
    suspend fun collectGnssSnapshot(lm: LocationManager, windowMs: Long): GnssSnapshot {
        val satList = Collections.synchronizedList(mutableListOf<SatInfo>())
        val nmeaList = Collections.synchronizedList(mutableListOf<String>())
        val firstFix = AtomicInteger(-1)
        val handler = Handler(Looper.getMainLooper())

        var callback: GnssStatus.Callback? = null
        var nmeaListener: OnNmeaMessageListener? = null

        try {
            callback = object : GnssStatus.Callback() {
                override fun onSatelliteStatusChanged(status: GnssStatus) {
                    val snapshot = mutableListOf<SatInfo>()
                    for (i in 0 until status.satelliteCount) {
                        val hasCarrier = Build.VERSION.SDK_INT >= Build.VERSION_CODES.O &&
                                status.hasCarrierFrequencyHz(i)
                        val carrierFreq = if (hasCarrier) status.getCarrierFrequencyHz(i) else null
                        snapshot.add(
                            SatInfo(
                                svid = status.getSvid(i),
                                constellationType = status.getConstellationType(i),
                                cn0DbHz = status.getCn0DbHz(i),
                                elevationDeg = status.getElevationDegrees(i),
                                azimuthDeg = status.getAzimuthDegrees(i),
                                usedInFix = status.usedInFix(i),
                                carrierFreqHz = carrierFreq,
                                hasCarrierFreq = hasCarrier
                            )
                        )
                    }
                    synchronized(satList) {
                        satList.clear()
                        satList.addAll(snapshot)
                    }
                }

                override fun onFirstFix(ttffMillis: Int) {
                    firstFix.set(ttffMillis)
                }
            }
            @Suppress("DEPRECATION")
            lm.registerGnssStatusCallback(callback, handler)

            nmeaListener = OnNmeaMessageListener { message, _ ->
                val trimmed = message.trim()
                if (trimmed.isEmpty()) return@OnNmeaMessageListener
                synchronized(nmeaList) {
                    if (nmeaList.size < MAX_NMEA_CAPTURED) {
                        // 去除完全重复的语句（GSV 每秒重复广播）
                        if (nmeaList.lastOrNull() != trimmed) {
                            nmeaList.add(trimmed)
                        }
                    }
                }
            }
            lm.addNmeaListener(nmeaListener, handler)

            delay(windowMs)
        } catch (e: Exception) {
            Log.w(TAG, "GNSS 采集异常: ${e.message}")
        } finally {
            try {
                if (callback != null) lm.unregisterGnssStatusCallback(callback)
            } catch (e: Exception) {
                Log.w(TAG, "反注册 GNSS 回调失败: ${e.message}")
            }
            try {
                if (nmeaListener != null) lm.removeNmeaListener(nmeaListener)
            } catch (e: Exception) {
                Log.w(TAG, "反注册 NMEA 监听失败: ${e.message}")
            }
        }

        return GnssSnapshot(
            satellites = synchronized(satList) { satList.toList() },
            nmeaSentences = synchronized(nmeaList) { nmeaList.toList() },
            firstFixTimeMs = firstFix.get()
        )
    }

    // ==================== 当前定位获取 ====================

    /**
     * 尽力获取一次当前定位。
     *
     * API 30+ 使用 [LocationManager.getCurrentLocation]（带 CancellationSignal），
     * 低版本回退到 [LocationManager.requestSingleUpdate]。
     * 超过 [timeoutMs] 仍未获得定位返回 null。
     *
     * @return 最新定位，失败或超时返回 null
     */
    suspend fun requestCurrentLocation(
        context: Context,
        lm: LocationManager,
        provider: String,
        timeoutMs: Long
    ): Location? {
        if (!lm.isProviderEnabled(provider)) return null
        return withTimeoutOrNull(timeoutMs) {
            suspendCancellableCoroutine { cont ->
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                    val signal = CancellationSignal()
                    cont.invokeOnCancellation { signal.cancel() }
                    try {
                        lm.getCurrentLocation(
                            provider, signal, ContextCompat.getMainExecutor(context)
                        ) { loc ->
                            if (cont.isActive) cont.resumeWith(Result.success(loc))
                        }
                    } catch (e: Exception) {
                        Log.w(TAG, "getCurrentLocation 失败: ${e.message}")
                        if (cont.isActive) cont.resumeWith(Result.success(null))
                    }
                } else {
                    @Suppress("DEPRECATION")
                    val listener = object : LocationListener {
                        override fun onLocationChanged(location: Location) {
                            if (!cont.isActive) return
                            @Suppress("DEPRECATION")
                            lm.removeUpdates(this)
                            cont.resumeWith(Result.success(location))
                        }

                        @Deprecated("Deprecated in Java")
                        override fun onStatusChanged(provider: String?, status: Int, extras: Bundle?) {}

                        override fun onProviderEnabled(provider: String) {}

                        override fun onProviderDisabled(provider: String) {}
                    }
                    cont.invokeOnCancellation {
                        @Suppress("DEPRECATION")
                        lm.removeUpdates(listener)
                    }
                    try {
                        @Suppress("DEPRECATION")
                        lm.requestSingleUpdate(provider, listener, Looper.getMainLooper())
                    } catch (e: Exception) {
                        Log.w(TAG, "requestSingleUpdate 失败: ${e.message}")
                        if (cont.isActive) cont.resumeWith(Result.success(null))
                    }
                }
            }
        }
    }

    // ==================== NMEA 解析 ====================

    /**
     * 解析单条 NMEA 语句。
     * 支持 GGA / RMC / GSA / GSV，其它类型返回 null。
     */
    fun parseNmea(sentence: String): NmeaInfo? {
        val trimmed = sentence.trim()
        if (!trimmed.startsWith("$")) return null
        val fields = trimmed.substring(1).split(",")
        if (fields.isEmpty() || fields[0].length < 5) return null
        val id = fields[0]
        val type = id.substring(id.length - 3)
        val talker = id.substring(0, id.length - 3)
        return when (type) {
            "GGA" -> parseGga(fields, talker, trimmed)
            "RMC" -> parseRmc(fields, talker, trimmed)
            "GSA" -> parseGsa(fields, talker, trimmed)
            "GSV" -> parseGsv(fields, talker, trimmed)
            else -> null
        }
    }

    private fun parseGga(fields: List<String>, talker: String, raw: String): NmeaInfo {
        return NmeaInfo(
            type = "GGA",
            talker = talker,
            fixQuality = cleanField(fields.getOrNull(6))?.toIntOrNull(),
            satUsed = cleanField(fields.getOrNull(7))?.toIntOrNull(),
            altitudeMeters = parseNmeaDouble(fields.getOrNull(9)),
            hdop = parseNmeaDouble(fields.getOrNull(8)),
            latitude = parseNmeaCoordinate(fields.getOrNull(2), fields.getOrNull(3), 2),
            longitude = parseNmeaCoordinate(fields.getOrNull(4), fields.getOrNull(5), 3),
            status = null,
            speedKnots = null,
            trackDegrees = null,
            fixMode = null,
            pdop = null,
            vdop = null,
            satsInView = null,
            gsvSats = emptyList(),
            raw = raw
        )
    }

    private fun parseRmc(fields: List<String>, talker: String, raw: String): NmeaInfo {
        return NmeaInfo(
            type = "RMC",
            talker = talker,
            fixQuality = null,
            satUsed = null,
            altitudeMeters = null,
            hdop = null,
            latitude = parseNmeaCoordinate(fields.getOrNull(3), fields.getOrNull(4), 2),
            longitude = parseNmeaCoordinate(fields.getOrNull(5), fields.getOrNull(6), 3),
            status = cleanField(fields.getOrNull(2))?.firstOrNull(),
            speedKnots = parseNmeaDouble(fields.getOrNull(7)),
            trackDegrees = parseNmeaDouble(fields.getOrNull(8)),
            fixMode = null,
            pdop = null,
            vdop = null,
            satsInView = null,
            gsvSats = emptyList(),
            raw = raw
        )
    }

    private fun parseGsa(fields: List<String>, talker: String, raw: String): NmeaInfo {
        return NmeaInfo(
            type = "GSA",
            talker = talker,
            fixQuality = null,
            satUsed = null,
            altitudeMeters = null,
            hdop = parseNmeaDouble(fields.getOrNull(16)),
            latitude = null,
            longitude = null,
            status = null,
            speedKnots = null,
            trackDegrees = null,
            fixMode = cleanField(fields.getOrNull(2))?.toIntOrNull(),
            pdop = parseNmeaDouble(fields.getOrNull(15)),
            vdop = parseNmeaDouble(fields.getOrNull(17)),
            satsInView = null,
            gsvSats = emptyList(),
            raw = raw
        )
    }

    private fun parseGsv(fields: List<String>, talker: String, raw: String): NmeaInfo {
        val satsInView = cleanField(fields.getOrNull(3))?.toIntOrNull()
        val sats = mutableListOf<GsvSat>()
        var i = 4
        while (i < fields.size) {
            val prn = cleanField(fields.getOrNull(i))?.toIntOrNull() ?: break
            val elevation = parseNmeaDouble(fields.getOrNull(i + 1))
            val azimuth = parseNmeaDouble(fields.getOrNull(i + 2))
            val snr = parseNmeaDouble(fields.getOrNull(i + 3))
            sats.add(GsvSat(prn, elevation, azimuth, snr))
            i += 4
        }
        return NmeaInfo(
            type = "GSV",
            talker = talker,
            fixQuality = null,
            satUsed = null,
            altitudeMeters = null,
            hdop = null,
            latitude = null,
            longitude = null,
            status = null,
            speedKnots = null,
            trackDegrees = null,
            fixMode = null,
            pdop = null,
            vdop = null,
            satsInView = satsInView,
            gsvSats = sats,
            raw = raw
        )
    }

    private fun cleanField(field: String?): String? {
        if (field.isNullOrEmpty()) return null
        val star = field.indexOf('*')
        return if (star >= 0) field.substring(0, star) else field
    }

    private fun parseNmeaDouble(field: String?): Double? = cleanField(field)?.toDoubleOrNull()

    /**
     * NMEA 坐标格式 (ddmm.mmmm / dddmm.mmmm) 转十进制。
     * @param coord 坐标字符串
     * @param hemi 半球字符 N/S/E/W
     * @param degDigits 度数位数：纬度 2，经度 3
     */
    private fun parseNmeaCoordinate(coord: String?, hemi: String?, degDigits: Int): Double? {
        val c = cleanField(coord) ?: return null
        if (c.length <= degDigits) return null
        val deg = c.substring(0, degDigits).toDoubleOrNull() ?: return null
        val min = c.substring(degDigits).toDoubleOrNull() ?: return null
        var value = deg + min / 60.0
        val h = cleanField(hemi)
        if (h == "S" || h == "W") value = -value
        return value
    }

    // ==================== NMEA 校验和 ====================

    /**
     * 校验 NMEA 语句的 *XX 校验和。
     * 校验和为 `$` 与 `*` 之间所有字符的按位异或，两位十六进制表示。
     * 无 `*` 或校验和不匹配返回 false。
     */
    fun nmeaChecksumValid(sentence: String): Boolean {
        val star = sentence.indexOf('*')
        if (star < 0) return false
        val startIdx = if (sentence.startsWith("$")) 1 else 0
        var checksum = 0
        for (i in startIdx until star) {
            checksum = checksum xor sentence[i].code
        }
        val expected = checksum.toString(16).uppercase().padStart(2, '0')
        val actual = sentence.substring(star + 1).trim().take(2).uppercase()
        return actual.isNotEmpty() && actual == expected
    }

    /**
     * NMEA 校验和统计结果
     */
    data class NmeaChecksumStats(
        val total: Int,
        val valid: Int,     // 带校验和且匹配
        val invalid: Int,   // 带校验和但错误
        val missing: Int,   // 无校验和
        val isSuspicious: Boolean
    )

    /**
     * 统计一批 NMEA 语句的校验和情况。
     *
     * 真实芯片 NMEA 语句普遍带校验和；虚拟 GNSS（如 Cuttlefish 注入的示例语句）
     * 常缺失校验和或校验错误。样本 ≥3 条时，存在校验错误或缺失占比 ≥60% 视为可疑。
     */
    fun analyzeNmeaChecksums(sentences: List<String>): NmeaChecksumStats {
        var valid = 0
        var invalid = 0
        var missing = 0
        sentences.forEach { line ->
            when {
                !line.contains("*") -> missing++
                nmeaChecksumValid(line) -> valid++
                else -> invalid++
            }
        }
        val total = sentences.size
        val isSuspicious = total >= 3 && (
            invalid > 0 ||
                missing.toDouble() / total >= 0.6
            )
        return NmeaChecksumStats(total, valid, invalid, missing, isSuspicious)
    }

    // ==================== 星座与坐标工具 ====================

    /**
     * 星座名称
     */
    fun constellationName(type: Int): String = when (type) {
        GnssStatus.CONSTELLATION_GPS -> "GPS"
        GnssStatus.CONSTELLATION_SBAS -> "SBAS"
        GnssStatus.CONSTELLATION_GLONASS -> "GLONASS"
        GnssStatus.CONSTELLATION_QZSS -> "QZSS"
        GnssStatus.CONSTELLATION_BEIDOU -> "北斗"
        GnssStatus.CONSTELLATION_GALILEO -> "Galileo"
        GnssStatus.CONSTELLATION_IRNSS -> "IRNSS"
        else -> "未知($type)"
    }

    /**
     * GGA 定位质量说明
     */
    fun fixQualityName(quality: Int): String = when (quality) {
        0 -> "无定位"
        1 -> "GPS 定位"
        2 -> "差分 GPS (DGPS)"
        3 -> "PPS 定位"
        4 -> "RTK 固定解"
        5 -> "RTK 浮点解"
        6 -> "航位推算"
        7 -> "手动输入"
        8 -> "模拟模式"
        else -> "未知($quality)"
    }

    /**
     * 格式化为 4 位小数的坐标
     */
    fun formatLatLng(latitude: Double, longitude: Double): String =
        "%.4f, %.4f".format(latitude, longitude)

    /**
     * 球面（Haversine）距离，单位米
     */
    fun distanceMeters(lat1: Double, lng1: Double, lat2: Double, lng2: Double): Double {
        val earthRadius = 6371000.0
        val dLat = Math.toRadians(lat2 - lat1)
        val dLng = Math.toRadians(lng2 - lng1)
        val a = sin(dLat / 2) * sin(dLat / 2) +
                cos(Math.toRadians(lat1)) * cos(Math.toRadians(lat2)) * sin(dLng / 2) * sin(dLng / 2)
        val c = 2 * asin(sqrt(a))
        return earthRadius * c
    }

    // ==================== 模拟位置判定 ====================

    /**
     * 判断定位是否来自 Mock 提供器。
     * API 31+ 使用 [Location.isMock]，低版本使用 isFromMockProvider()。
     */
    fun isMockLocation(loc: Location): Boolean = try {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            loc.isMock
        } else {
            @Suppress("DEPRECATION")
            loc.isFromMockProvider
        }
    } catch (e: Exception) {
        @Suppress("DEPRECATION")
        loc.isFromMockProvider
    }

    /**
     * 已知模拟器默认坐标（Android Studio 模拟器 / 常见模拟器工具）。
     * 在 ±0.01°（约 1km）范围内视为命中。
     */
    private val EMULATOR_COORDINATES = listOf(
        // Android Studio 模拟器默认 (Googleplex)
        37.4220 to -122.0841,
        // 山景城
        37.3861 to -122.0839,
        // 旧金山
        37.7749 to -122.4194,
        // 东京（部分模拟器配置）
        35.6762 to 139.6503,
        // 伦敦
        51.5074 to -0.1278,
        // 北京（0,0 之外常见配置）
        39.9042 to 116.4074
    )

    /**
     * 判断坐标是否命中已知模拟器默认位置。
     */
    fun isKnownEmulatorCoordinate(loc: Location): Boolean {
        return EMULATOR_COORDINATES.any { (lat, lng) ->
            abs(loc.latitude - lat) < 0.01 && abs(loc.longitude - lng) < 0.01
        }
    }

    // ==================== 虚拟设备特征 ====================

    /**
     * 虚拟设备 / 模拟器 Build 标识关键词。
     * 命中这些关键词基本可判定运行在虚拟设备上（真机几乎不会出现）。
     */
    private val VIRTUAL_DEVICE_KEYWORDS = listOf(
        "cuttlefish",   // Google Cuttlefish 虚拟设备
        "goldfish",     // 传统 Android 模拟器内核
        "ranchu",       // Android Emulator (API 26+)
        "vsoc",         // Cuttlefish hardware (vsoc_x86_64)
        "emulator",     // 通用模拟器标识
        "emu64",        // emulator device (emu64x)
        "sdk_gphone",   // AOSP SDK 模拟器 product
        "cf_",          // Cuttlefish product/device 前缀 (cf_phone 等)
        "generic",      // AOSP 通用 device (generic_x86)
        "aosp"          // AOSP 模拟器 product (aosp_arm64)
    )

    /**
     * 判断文本是否包含虚拟设备标识关键词（不区分大小写）。
     */
    fun containsVirtualDeviceKeyword(text: String): Boolean {
        return VIRTUAL_DEVICE_KEYWORDS.any { text.contains(it, ignoreCase = true) }
    }
}

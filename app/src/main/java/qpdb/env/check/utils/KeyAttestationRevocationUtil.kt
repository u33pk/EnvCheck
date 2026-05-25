package qpdb.env.check.utils

import android.util.Log
import org.json.JSONObject
import java.math.BigInteger
import java.security.cert.X509Certificate
import java.util.concurrent.TimeUnit

/**
 * Google Key Attestation 证书吊销列表工具类
 *
 * 从 https://android.googleapis.com/attestation/status 获取谷歌官方吊销的
 * Key Attestation 证书序列号列表，用于检测设备证书是否已被吊销。
 *
 * 吊销原因通常包括：
 * - KEY_COMPROMISE: 密钥泄露
 * - SOFTWARE_FLAW: 软件漏洞
 */
object KeyAttestationRevocationUtil {

    private const val TAG = "KeyAttestationRevocation"
    private const val REVOCATION_URL = "https://android.googleapis.com/attestation/status"
    private const val CACHE_VALID_MS = 60 * 60 * 1000L // 1小时缓存

    private var cachedEntries: Set<String>? = null
    private var cacheTimestamp: Long = 0

    /**
     * 证书吊销检查结果
     */
    data class RevocationCheckResult(
        val revoked: Boolean,
        val reason: String? = null,
        val serialNumber: String? = null,
        val error: String? = null
    )

    /**
     * 检查单张证书是否被吊销
     *
     * @param cert X509 证书
     * @return RevocationCheckResult
     */
    @JvmStatic
    fun checkCertificate(cert: X509Certificate): RevocationCheckResult {
        val entries = fetchRevocationList()
        if (entries == null) {
            return RevocationCheckResult(revoked = false, error = "无法获取吊销列表")
        }

        val serial = cert.serialNumber
        // Google 列表中的 key 同时支持十进制和十六进制（小写）两种格式
        val decimalKey = serial.toString()
        val hexKey = serial.toString(16).lowercase().trimStart('0').ifEmpty { "0" }

        // 先检查十进制
        if (entries.contains(decimalKey)) {
            return RevocationCheckResult(
                revoked = true,
                reason = getReasonFromJson(decimalKey),
                serialNumber = decimalKey
            )
        }
        // 再检查十六进制
        if (entries.contains(hexKey)) {
            return RevocationCheckResult(
                revoked = true,
                reason = getReasonFromJson(hexKey),
                serialNumber = hexKey
            )
        }

        return RevocationCheckResult(revoked = false, serialNumber = decimalKey)
    }

    /**
     * 检查证书链中是否有证书被吊销
     *
     * @param certs 证书链列表（通常叶子证书在前）
     * @return 第一个被吊销的证书结果，如果都正常返回未吊销结果
     */
    @JvmStatic
    fun checkCertificateChain(certs: List<X509Certificate>): RevocationCheckResult {
        if (certs.isEmpty()) {
            return RevocationCheckResult(revoked = false, error = "证书链为空")
        }

        val entries = fetchRevocationList()
        if (entries == null) {
            return RevocationCheckResult(revoked = false, error = "无法获取吊销列表")
        }

        certs.forEachIndexed { index, cert ->
            val serial = cert.serialNumber
            val decimalKey = serial.toString()
            val hexKey = serial.toString(16).lowercase().trimStart('0').ifEmpty { "0" }
            val subject = cert.subjectX500Principal.name

            val matchedKey = when {
                entries.contains(decimalKey) -> decimalKey
                entries.contains(hexKey) -> hexKey
                else -> null
            }

            if (matchedKey != null) {
                Log.w(TAG, "证书 #$index [$subject] 已被吊销 (serial=$matchedKey)")
                return RevocationCheckResult(
                    revoked = true,
                    reason = getReasonFromJson(matchedKey),
                    serialNumber = matchedKey
                )
            }
        }

        return RevocationCheckResult(revoked = false)
    }

    /**
     * 获取吊销列表中的条目数量（调试用）
     */
    @JvmStatic
    fun getRevokedCount(): Int {
        return fetchRevocationList()?.size ?: -1
    }

    // ==================== 私有方法 ====================

    /**
     * 获取已解析的吊销列表条目（带缓存）
     */
    private fun fetchRevocationList(): Set<String>? {
        val now = System.currentTimeMillis()
        val cached = cachedEntries
        if (cached != null && (now - cacheTimestamp) < CACHE_VALID_MS) {
            Log.d(TAG, "使用缓存的吊销列表，共 ${cached.size} 条")
            return cached
        }

        return try {
            val jsonStr = HttpUtil.httpGet(REVOCATION_URL, timeoutMs = 15000)
            if (jsonStr.isNullOrEmpty()) {
                Log.w(TAG, "吊销列表响应为空")
                return cached // 网络失败时回退到旧缓存（即使过期）
            }

            val json = JSONObject(jsonStr)
            val entriesObj = json.optJSONObject("entries")
            if (entriesObj == null) {
                Log.w(TAG, "吊销列表中无 entries 字段")
                return cached
            }

            val keys = entriesObj.keys().asSequence().toSet()
            cachedEntries = keys
            cacheTimestamp = now
            Log.i(TAG, "成功获取吊销列表，共 ${keys.size} 条")
            keys
        } catch (e: Exception) {
            Log.e(TAG, "获取吊销列表失败: ${e.message}", e)
            // 网络异常时，如果有过期缓存也优先使用（降级 graceful）
            cached ?: run {
                Log.w(TAG, "无可用缓存")
                null
            }
        }
    }

    private var reasonCache: Map<String, String>? = null

    /**
     * 从 JSON 中获取指定 serial 的吊销原因（调试用，不频繁调用）
     */
    private fun getReasonFromJson(serial: String): String? {
        return try {
            val cached = reasonCache
            if (cached != null) {
                return cached[serial]
            }

            val jsonStr = HttpUtil.httpGet(REVOCATION_URL, timeoutMs = 15000) ?: return null
            val json = JSONObject(jsonStr)
            val entries = json.optJSONObject("entries") ?: return null
            val map = mutableMapOf<String, String>()
            entries.keys().forEach { key ->
                val k = key ?: return@forEach
                val obj = entries.optJSONObject(k)
                val reason = obj?.optString("reason", "UNKNOWN") ?: "UNKNOWN"
                map[k] = reason
            }
            reasonCache = map
            map[serial]
        } catch (e: Exception) {
            null
        }
    }
}

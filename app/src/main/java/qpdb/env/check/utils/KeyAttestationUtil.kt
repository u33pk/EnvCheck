package qpdb.env.check.utils

import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import qpdb.env.check.attestation.Attestation
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.util.Date

/**
 * KeyAttestation 检测工具类
 * 封装密钥生成、证书获取和认证解析的核心逻辑
 */
object KeyAttestationUtil {

    private const val TAG = "KeyAttestationUtil"
    private const val ALIAS_PREFIX = "envcheck_attestation"
    private const val ALIAS_STRONGBOX = "${ALIAS_PREFIX}_strongbox"

    data class AttestationResult(
        val success: Boolean,
        val error: String? = null,
        val attestation: Attestation? = null,
        val certChain: List<X509Certificate> = emptyList(),
        val useStrongBox: Boolean = false
    )

    /**
     * 检查设备是否支持 StrongBox
     */
    fun hasStrongBox(pm: PackageManager): Boolean {
        return Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
                pm.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
    }

    /**
     * 检查设备是否支持 App Attest Key
     */
    fun hasAttestKey(pm: PackageManager): Boolean {
        return Build.VERSION.SDK_INT >= Build.VERSION_CODES.S &&
                pm.hasSystemFeature(PackageManager.FEATURE_KEYSTORE_APP_ATTEST_KEY)
    }

    /**
     * 生成带硬件认证的密钥对并解析认证数据
     * @param useStrongBox 是否使用 StrongBox
     * @param forceReset 是否强制删除已有密钥重新生成
     */
    fun performAttestation(useStrongBox: Boolean = false, forceReset: Boolean = true): AttestationResult {
        val alias = if (useStrongBox) ALIAS_STRONGBOX else ALIAS_PREFIX

        return try {
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.N) {
                return AttestationResult(false, "Requires Android 7.0+")
            }

            val keyStore = KeyStore.getInstance("AndroidKeyStore")
            keyStore.load(null)

            // 清理旧密钥
            if (forceReset && keyStore.containsAlias(alias)) {
                keyStore.deleteEntry(alias)
            }

            // 生成 EC 密钥对，启用认证
            val purposes = KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
            val builder = KeyGenParameterSpec.Builder(alias, purposes)
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setCertificateNotBefore(Date())
                .setAttestationChallenge("EnvCheckChallenge".toByteArray())

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && useStrongBox) {
                builder.setIsStrongBoxBacked(true)
            }

            val keyPairGenerator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore"
            )
            keyPairGenerator.initialize(builder.build())
            keyPairGenerator.generateKeyPair()

            // 获取证书链
            val chain = keyStore.getCertificateChain(alias)
                ?: return AttestationResult(false, "Certificate chain is null")

            val certs = chain.map { it as X509Certificate }
            if (certs.isEmpty()) {
                return AttestationResult(false, "Empty certificate chain")
            }

            // 解析认证扩展（第一个证书）
            val attestation = Attestation.loadFromCertificate(certs[0])

            // 清理生成的密钥
            try {
                keyStore.deleteEntry(alias)
            } catch (e: Exception) {
                Log.w(TAG, "Failed to delete entry: ${e.message}")
            }

            AttestationResult(
                success = true,
                attestation = attestation,
                certChain = certs,
                useStrongBox = useStrongBox
            )
        } catch (e: Exception) {
            Log.e(TAG, "Attestation failed", e)

            // 清理失败的密钥
            try {
                val keyStore = KeyStore.getInstance("AndroidKeyStore")
                keyStore.load(null)
                if (keyStore.containsAlias(alias)) {
                    keyStore.deleteEntry(alias)
                }
            } catch (cleanup: Exception) {
                Log.w(TAG, "Cleanup failed: ${cleanup.message}")
            }

            AttestationResult(false, e.message ?: "Unknown error")
        }
    }

    /**
     * 格式化 OS 版本号（YYYYMMDD 格式）
     */
    fun formatOsVersion(version: Int?): String {
        if (version == null || version == 0) return "Unknown"
        val year = version / 10000
        val month = (version % 10000) / 100
        val day = version % 100
        return String.format("%04d-%02d-%02d", year, month, day)
    }

    /**
     * 格式化补丁级别（YYYYMM 格式）
     */
    fun formatPatchLevel(level: Int?): String {
        if (level == null || level == 0) return "Unknown"
        val year = level / 100
        val month = level % 100
        return String.format("%04d-%02d", year, month)
    }

    // ==================== Tricky Store 时序检测 JNI 桥接 ====================

    private const val TIMING_ALIAS = "envcheck_timing"

    /**
     * 生成用于时序检测的密钥对（最小化开销，纯操作）
     */
    @JvmStatic
    fun nativeTimingGenerateKeyPair(useStrongBox: Boolean): Boolean {
        return try {
            val keyStore = KeyStore.getInstance("AndroidKeyStore")
            keyStore.load(null)
            if (keyStore.containsAlias(TIMING_ALIAS)) {
                keyStore.deleteEntry(TIMING_ALIAS)
            }
            val purposes = KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
            val builder = KeyGenParameterSpec.Builder(TIMING_ALIAS, purposes)
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setAttestationChallenge("TimingCheck".toByteArray())
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && useStrongBox) {
                builder.setIsStrongBoxBacked(true)
            }
            val kpg = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore"
            )
            kpg.initialize(builder.build())
            kpg.generateKeyPair()
            true
        } catch (e: Exception) {
            false
        }
    }

    /**
     * 执行签名操作（最小化开销，纯操作）
     */
    @JvmStatic
    fun nativeTimingSignData(alias: String, data: ByteArray): Boolean {
        return try {
            val keyStore = KeyStore.getInstance("AndroidKeyStore")
            keyStore.load(null)
            val entry = keyStore.getEntry(alias, null) as? KeyStore.PrivateKeyEntry
                ?: return false
            val sig = Signature.getInstance("SHA256withECDSA")
            sig.initSign(entry.privateKey)
            sig.update(data)
            sig.sign()
            true
        } catch (e: Exception) {
            false
        }
    }

    /**
     * 清理时序检测生成的密钥
     */
    @JvmStatic
    fun nativeTimingCleanup() {
        try {
            val keyStore = KeyStore.getInstance("AndroidKeyStore")
            keyStore.load(null)
            if (keyStore.containsAlias(TIMING_ALIAS)) {
                keyStore.deleteEntry(TIMING_ALIAS)
            }
        } catch (_: Exception) {
            // ignore cleanup errors
        }
    }

    // ==================== BC 软件签名对照（双 provider 对比） ====================

    private var cachedBcKeyPair: java.security.KeyPair? = null

    /**
     * 使用系统默认软件实现执行 EC P-256 签名，作为与 KeyStore 签名的对照。
     * 真实 TEE/StrongBox 的签名耗时与纯软件签名不成比例；
     * TEESimulator 等伪装模块本质上就是软件签名，两者比例接近。
     */
    @JvmStatic
    fun nativeTimingSoftwareSignData(data: ByteArray): ByteArray? {
        return try {
            // 复用已生成的密钥对，避免每次重新生成引入额外开销
            var keyPair = cachedBcKeyPair
            if (keyPair == null) {
                val keyGen = KeyPairGenerator.getInstance("EC")
                keyGen.initialize(ECGenParameterSpec("secp256r1"))
                keyPair = keyGen.generateKeyPair()
                cachedBcKeyPair = keyPair
            }
            val sig = Signature.getInstance("SHA256withECDSA")
            sig.initSign(keyPair.private)
            sig.update(data)
            sig.sign()
        } catch (e: Exception) {
            Log.e(TAG, "Software sign failed", e)
            null
        }
    }

    @JvmStatic
    fun nativeTimingSoftwareCleanup() {
        cachedBcKeyPair = null
    }
}

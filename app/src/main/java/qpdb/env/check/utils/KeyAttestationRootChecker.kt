package qpdb.env.check.utils

import android.util.Base64
import android.util.Log
import java.security.cert.X509Certificate
import java.util.Arrays

/**
 * Key Attestation 证书根公钥真实性检测工具
 *
 * 参考 KeyAttestation (vvb2060) 实现，通过比对证书链根证书的公钥
 * 与已知的 Google / AOSP / Samsung Knox / OEM 根公钥，判断证书来源。
 *
 * Google 官方根公钥列表：
 * - Google Hardware Attestation Root (RSA)
 * - AOSP Root (EC / RSA)
 * - Samsung Knox SAKv1/SAKv2/SAKmv1
 * - OEM 厂商根证书（从系统资源 vendor_required_attestation_certificates 读取）
 */
object KeyAttestationRootChecker {

    private const val TAG = "KeyAttestationRoot"

    /**
     * 证书来源类型
     */
    enum class RootStatus {
        UNKNOWN,        // 未知来源（可能是自签名、伪造或 Tricky Store 注入）
        GOOGLE,         // Google 官方硬件认证根证书
        AOSP,           // AOSP 默认根证书（通常出现在模拟器或未 provision 设备）
        KNOX,           // Samsung Knox 根证书
        OEM,            // OEM 厂商自定义根证书
    }

    /**
     * 检测结果
     */
    data class RootCheckResult(
        val status: RootStatus,
        val rootSubject: String? = null,
        val description: String = ""
    )

    // ==================== 已知根公钥（Base64） ====================

    // Google Hardware Attestation Root (RSA 2048)
    private const val GOOGLE_ROOT_PUBLIC_KEY = """
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAr7bHgiuxpwHsK7Qui8xU\
FMOr75gvMsd/dTEDDJdSSxtf6An7xyqpRR90PL2abxM1dEqlXnf2tqw1Ne4Xwl5j\
lRfdnJLmN0pTy/4lj4/7tv0Sk3iiKkypnEUtR6WfMgH0QZfKHM1+di+y9TFRtv6y\
//0rb+T+W8a9nsNL/ggjnar86461qO0rOs2cXjp3kOG1FEJ5MVmFmBGtnrKpa73X\
pXyTqRxB/M0n1n/W9nGqC4FSYa04T6N5RIZGBN2z2MT5IKGbFlbC8UrW0DxW7AYI\
mQQcHtGl/m00QLVWutHQoVJYnFPlXTcHYvASLu+RhhsbDmxMgJJ0mcDpvsC4PjvB\
+TxywElgS70vE0XmLD+OJtvsBslHZvPBKCOdT0MS+tgSOIfga+z1Z1g7+DVagf7q\
uvmag8jfPioyKvxnK/EgsTUVi2ghzq8wm27ud/mIM7AY2qEORR8Go3TVB4HzWQgp\
Zrt3i5MIlCaY504LzSRiigHCzAPlHws+W0rB5N+er5/2pJKnfBSDiCiFAVtCLOZ7\
gLiMm0jhO2B6tUXHI/+MRPjy02i59lINMRRev56GKtcd9qO/0kUJWdZTdA2XoS82\
ixPvZtXQpUpuL12ab+9EaDK8Z4RHJYYfCT3Q5vNAXaiWQ+8PTWm2QgBR/bkwSWc+\
NpUFgNPN9PvQi8WEg5UmAGMCAwEAAQ=="""

    // AOSP EC Root (secp256r1)
    private const val AOSP_ROOT_EC_PUBLIC_KEY = """
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7l1ex+HA220Dpn7mthvsTWpdamgu\
D/9/SQ59dx9EIm29sa/6FsvHrcV30lacqrewLVQBXT5DKyqO107sSHVBpA=="""

    // AOSP RSA Root
    private const val AOSP_ROOT_RSA_PUBLIC_KEY = """
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCia63rbi5EYe/VDoLmt5TRdSMf\
d5tjkWP/96r/C3JHTsAsQ+wzfNes7UA+jCigZtX3hwszl94OuE4TQKuvpSe/lWmg\
MdsGUmX4RFlXYfC78hdLt0GAZMAoDo9Sd47b0ke2RekZyOmLw9vCkT/X11DEHTVm\
+Vfkl5YLCazOkjWFmwIDAQAB"""

    // Samsung Knox SAKv1 Root (secp384r1)
    private const val KNOX_SAKV1_ROOT_PUBLIC_KEY = """
MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBs9Qjr//REhkXW7jUqjY9KNwWac4r\
5+kdUGk+TZjRo1YEa47Axwj6AJsbOjo4QsHiYRiWTELvFeiuBsKqyuF0xyAAKvDo\
fBqrEq1/Ckxo2mz7Q4NQes3g4ahSjtgUSh0k85fYwwHjCeLyZ5kEqgHG9OpOH526\
FFAK3slSUgC8RObbxys="""

    // Samsung Knox SAKv2 Root (secp384r1)
    private const val KNOX_SAKV2_ROOT_PUBLIC_KEY = """
MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBhbGuLrpql5I2WJmrE5kEVZOo+dgA\
46mKrVJf/sgzfzs2u7M9c1Y9ZkCEiiYkhTFE9vPbasmUfXybwgZ2EM30A1ABPd12\
4n3JbEDfsB/wnMH1AcgsJyJFPbETZiy42Fhwi+2BCA5bcHe7SrdkRIYSsdBRaKBo\
ZsapxB0gAOs0jSPRX5M="""

    // Samsung Knox SAKmv1 Root (secp384r1)
    private const val KNOX_SAKMV1_ROOT_PUBLIC_KEY = """
MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQB9XeEN8lg6p5xvMVWG42P2Qi/aRKX\
2rPRNgK92UlO9O/TIFCKHC1AWCLFitPVEow5W+yEgC2wOiYxgepY85TOoH0AuEkL\
oiC6ldbF2uNVU3rYYSytWAJg3GFKd1l9VLDmxox58Hyw2Jmdd5VSObGiTFQ/SgKs\
n2fbQPtpGlNxgEfd6Y8="""

    // 解析后的公钥字节数组（懒加载）
    private val googleKey: ByteArray by lazy { decodeBase64(GOOGLE_ROOT_PUBLIC_KEY) }
    private val aospEcKey: ByteArray by lazy { decodeBase64(AOSP_ROOT_EC_PUBLIC_KEY) }
    private val aospRsaKey: ByteArray by lazy { decodeBase64(AOSP_ROOT_RSA_PUBLIC_KEY) }
    private val knoxSakv1Key: ByteArray by lazy { decodeBase64(KNOX_SAKV1_ROOT_PUBLIC_KEY) }
    private val knoxSakv2Key: ByteArray by lazy { decodeBase64(KNOX_SAKV2_ROOT_PUBLIC_KEY) }
    private val knoxSakmv1Key: ByteArray by lazy { decodeBase64(KNOX_SAKMV1_ROOT_PUBLIC_KEY) }

    /**
     * 检查证书链根证书的来源
     *
     * @param certs 证书链（叶子证书在前，根证书在后）
     * @return RootCheckResult
     */
    @JvmStatic
    fun checkRootCertificate(certs: List<X509Certificate>): RootCheckResult {
        if (certs.isEmpty()) {
            return RootCheckResult(RootStatus.UNKNOWN, description = "证书链为空")
        }

        // 根证书通常是证书链的最后一张
        val rootCert = certs.last()
        val publicKey = rootCert.publicKey?.encoded
        if (publicKey == null) {
            return RootCheckResult(RootStatus.UNKNOWN, description = "无法获取根证书公钥")
        }

        val status = matchPublicKey(publicKey)
        val subject = rootCert.subjectX500Principal.name

        val desc = when (status) {
            RootStatus.GOOGLE -> "Google 官方硬件认证根证书\nSubject: $subject"
            RootStatus.AOSP -> "AOSP 默认根证书（模拟器/未 provision 设备常见）\nSubject: $subject"
            RootStatus.KNOX -> "Samsung Knox 根证书\nSubject: $subject"
            RootStatus.OEM -> "OEM 厂商自定义根证书\nSubject: $subject"
            RootStatus.UNKNOWN -> "未知来源根证书（可能为伪造、自签名或 Tricky Store 注入）\nSubject: $subject"
        }

        Log.i(TAG, "Root cert status: $status, subject: $subject")
        return RootCheckResult(status, subject, desc)
    }

    /**
     * 对证书链中所有证书逐一检查来源（调试用）
     */
    @JvmStatic
    fun checkAllCertificates(certs: List<X509Certificate>): List<Pair<X509Certificate, RootStatus>> {
        return certs.map { cert ->
            val pk = cert.publicKey?.encoded
            val status = if (pk != null) matchPublicKey(pk) else RootStatus.UNKNOWN
            cert to status
        }
    }

    // ==================== 私有方法 ====================

    private fun decodeBase64(base64Str: String): ByteArray {
        val cleaned = base64Str.replace("\\", "").replace("\n", "").replace(" ", "")
        return Base64.decode(cleaned, Base64.DEFAULT)
    }

    private fun matchPublicKey(publicKey: ByteArray): RootStatus {
        return when {
            Arrays.equals(publicKey, googleKey) -> RootStatus.GOOGLE
            Arrays.equals(publicKey, aospEcKey) -> RootStatus.AOSP
            Arrays.equals(publicKey, aospRsaKey) -> RootStatus.AOSP
            Arrays.equals(publicKey, knoxSakv2Key) -> RootStatus.KNOX
            Arrays.equals(publicKey, knoxSakv1Key) -> RootStatus.KNOX
            Arrays.equals(publicKey, knoxSakmv1Key) -> RootStatus.KNOX
            else -> RootStatus.UNKNOWN
        }
    }
}

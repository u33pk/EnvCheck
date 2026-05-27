package qpdb.env.check.attestation

import android.util.Log
import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERUTF8String
import java.nio.charset.StandardCharsets
import java.security.cert.CertificateParsingException

/**
 * Attestation Package Info
 *
 * 表示证书绑定的应用包信息，包含包名和版本号。
 * 参考 Android AOSP 实现。
 */
class AttestationPackageInfo(asn1Encodable: ASN1Encodable) {

    companion object {
        private const val TAG = "AttestationPackageInfo"
        private const val PACKAGE_NAME_INDEX = 0
        private const val VERSION_INDEX = 1
    }

    val packageName: String
    val versionCode: Long

    init {
        if (asn1Encodable !is ASN1Sequence) {
            throw CertificateParsingException(
                "Expected sequence for AttestationPackageInfo, found ${asn1Encodable.javaClass.name}"
            )
        }

        // packageName 可能是 DERUTF8String 或 DEROctetString
        val nameObj = asn1Encodable.getObjectAt(PACKAGE_NAME_INDEX)
        packageName = when (nameObj) {
            is DERUTF8String -> nameObj.string
            is DEROctetString -> String(nameObj.octets, StandardCharsets.UTF_8)
            else -> {
                Log.w(TAG, "Unexpected packageName type: ${nameObj.javaClass.name}, trying toString")
                nameObj.toString()
            }
        }

        // versionCode 可能是 ASN1Integer 或其他整数类型
        val versionObj = asn1Encodable.getObjectAt(VERSION_INDEX)
        versionCode = when (versionObj) {
            is ASN1Integer -> versionObj.value.toLong()
            else -> {
                Log.w(TAG, "Unexpected versionCode type: ${versionObj.javaClass.name}, defaulting to 0")
                0L
            }
        }
    }

    override fun toString(): String {
        return "package_name: $packageName\nversion: $versionCode"
    }
}

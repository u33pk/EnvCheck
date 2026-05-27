package qpdb.env.check.attestation

import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.ASN1Set
import java.security.cert.CertificateParsingException

/**
 * Attestation Application ID
 *
 * 证书绑定的应用标识信息，包含包名列表和签名摘要。
 * 用于验证证书是否绑定到特定应用。
 */
class AttestationApplicationId(asn1Encodable: ASN1Encodable) {

    companion object {
        private const val PACKAGE_INFOS_INDEX = 0
        private const val SIGNATURE_DIGESTS_INDEX = 1
    }

    val packageInfos: List<AttestationPackageInfo>
    val signatureDigests: List<ByteArray>

    init {
        if (asn1Encodable !is ASN1Sequence) {
            throw CertificateParsingException(
                "Expected sequence for AttestationApplicationId, found ${asn1Encodable.javaClass.name}"
            )
        }

        packageInfos = parsePackageInfos(asn1Encodable.getObjectAt(PACKAGE_INFOS_INDEX))
        signatureDigests = parseSignatureDigests(asn1Encodable.getObjectAt(SIGNATURE_DIGESTS_INDEX))
    }

    override fun toString(): String {
        val sb = StringBuilder()
        packageInfos.forEachIndexed { index, info ->
            sb.append("Package ${index + 1}/${packageInfos.size}:\n$info\n")
        }
        if (signatureDigests.isNotEmpty()) {
            sb.append("\nSignature digests (${signatureDigests.size}):\n")
            signatureDigests.forEachIndexed { index, digest ->
                sb.append("  [${index + 1}] ${digest.joinToString("") { b -> "%02x".format(b) }}\n")
            }
        }
        return sb.toString().trim()
    }

    @Throws(CertificateParsingException::class)
    private fun parsePackageInfos(asn1Encodable: ASN1Encodable): List<AttestationPackageInfo> {
        if (asn1Encodable !is ASN1Set) {
            throw CertificateParsingException(
                "Expected set for AttestationPackageInfos, found ${asn1Encodable.javaClass.name}"
            )
        }
        return asn1Encodable.map { AttestationPackageInfo(it) }
    }

    @Throws(CertificateParsingException::class)
    private fun parseSignatureDigests(asn1Encodable: ASN1Encodable): List<ByteArray> {
        if (asn1Encodable !is ASN1Set) {
            throw CertificateParsingException(
                "Expected set for Signature digests, found ${asn1Encodable.javaClass.name}"
            )
        }
        return asn1Encodable.map {
            Asn1Utils.getByteArrayFromAsn1(it)
        }
    }
}

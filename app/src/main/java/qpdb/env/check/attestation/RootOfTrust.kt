package qpdb.env.check.attestation

import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.util.encoders.Hex
import java.security.cert.CertificateParsingException

class RootOfTrust(
    val verifiedBootKey: ByteArray,
    val deviceLocked: Boolean,
    val verifiedBootState: Int,
    val verifiedBootHash: ByteArray?
) {

    companion object {
        const val KM_VERIFIED_BOOT_VERIFIED = 0
        const val KM_VERIFIED_BOOT_SELF_SIGNED = 1
        const val KM_VERIFIED_BOOT_UNVERIFIED = 2
        const val KM_VERIFIED_BOOT_FAILED = 3

        @JvmStatic
        fun verifiedBootStateToString(verifiedBootState: Int): String {
            return when (verifiedBootState) {
                KM_VERIFIED_BOOT_VERIFIED -> "Verified"
                KM_VERIFIED_BOOT_SELF_SIGNED -> "Self-signed"
                KM_VERIFIED_BOOT_UNVERIFIED -> "Unverified"
                KM_VERIFIED_BOOT_FAILED -> "Failed"
                else -> "Unknown ($verifiedBootState)"
            }
        }
    }

    @Throws(CertificateParsingException::class)
    constructor(asn1Encodable: ASN1Encodable) : this(
        verifiedBootKey = extractVerifiedBootKey(asn1Encodable),
        deviceLocked = extractDeviceLocked(asn1Encodable),
        verifiedBootState = extractVerifiedBootState(asn1Encodable),
        verifiedBootHash = extractVerifiedBootHash(asn1Encodable)
    )

    override fun toString(): String {
        val sb = StringBuilder()
            .append("verifiedBootKey: ").append(Hex.toHexString(verifiedBootKey))
            .append("\ndeviceLocked: ").append(deviceLocked)
            .append("\nverifiedBootState: ").append(verifiedBootStateToString(verifiedBootState))
        verifiedBootHash?.let {
            sb.append("\nverifiedBootHash: ").append(Hex.toHexString(it))
        }
        return sb.toString()
    }
}

@Throws(CertificateParsingException::class)
private fun extractVerifiedBootKey(asn1Encodable: ASN1Encodable): ByteArray {
    val sequence = asn1Encodable as? ASN1Sequence
        ?: throw CertificateParsingException(
            "Expected sequence for root of trust, found ${asn1Encodable.javaClass.name}"
        )
    return Asn1Utils.getByteArrayFromAsn1(sequence.getObjectAt(0))
}

@Throws(CertificateParsingException::class)
private fun extractDeviceLocked(asn1Encodable: ASN1Encodable): Boolean {
    val sequence = asn1Encodable as ASN1Sequence
    return Asn1Utils.getBooleanFromAsn1(sequence.getObjectAt(1))
}

@Throws(CertificateParsingException::class)
private fun extractVerifiedBootState(asn1Encodable: ASN1Encodable): Int {
    val sequence = asn1Encodable as ASN1Sequence
    return Asn1Utils.getIntegerFromAsn1(sequence.getObjectAt(2))
}

@Throws(CertificateParsingException::class)
private fun extractVerifiedBootHash(asn1Encodable: ASN1Encodable): ByteArray? {
    val sequence = asn1Encodable as ASN1Sequence
    return if (sequence.size() == 3) null
    else Asn1Utils.getByteArrayFromAsn1(sequence.getObjectAt(3))
}

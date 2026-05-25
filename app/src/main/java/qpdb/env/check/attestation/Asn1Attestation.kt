package qpdb.env.check.attestation

import org.bouncycastle.asn1.ASN1Sequence
import java.security.cert.CertificateParsingException
import java.security.cert.X509Certificate

class Asn1Attestation(x509Cert: X509Certificate) : Attestation(x509Cert) {

    companion object {
        private const val ATTESTATION_VERSION_INDEX = 0
        private const val ATTESTATION_SECURITY_LEVEL_INDEX = 1
        private const val KEYMASTER_VERSION_INDEX = 2
        private const val KEYMASTER_SECURITY_LEVEL_INDEX = 3
        private const val ATTESTATION_CHALLENGE_INDEX = 4
        private const val UNIQUE_ID_INDEX = 5
        private const val SW_ENFORCED_INDEX = 6
        private const val TEE_ENFORCED_INDEX = 7
    }

    override val attestationSecurityLevel: Int

    init {
        val seq = getAttestationSequence(x509Cert)
        attestationVersion = Asn1Utils.getIntegerFromAsn1(seq.getObjectAt(ATTESTATION_VERSION_INDEX))
        attestationSecurityLevel = Asn1Utils.getIntegerFromAsn1(seq.getObjectAt(ATTESTATION_SECURITY_LEVEL_INDEX))
        keymasterVersion = Asn1Utils.getIntegerFromAsn1(seq.getObjectAt(KEYMASTER_VERSION_INDEX))
        keymasterSecurityLevel = Asn1Utils.getIntegerFromAsn1(seq.getObjectAt(KEYMASTER_SECURITY_LEVEL_INDEX))
        attestationChallenge = Asn1Utils.getByteArrayFromAsn1(seq.getObjectAt(ATTESTATION_CHALLENGE_INDEX))
        uniqueId = Asn1Utils.getByteArrayFromAsn1(seq.getObjectAt(UNIQUE_ID_INDEX))
        softwareEnforced = AuthorizationList(seq.getObjectAt(SW_ENFORCED_INDEX))
        teeEnforced = AuthorizationList(seq.getObjectAt(TEE_ENFORCED_INDEX))
    }

    @Throws(CertificateParsingException::class)
    private fun getAttestationSequence(x509Cert: X509Certificate): ASN1Sequence {
        val attestationExtensionBytes = x509Cert.getExtensionValue(ASN1_OID)
        if (attestationExtensionBytes == null || attestationExtensionBytes.isEmpty()) {
            throw CertificateParsingException("Did not find extension with OID $ASN1_OID")
        }
        return Asn1Utils.getAsn1SequenceFromBytes(attestationExtensionBytes)
    }

    override fun getRootOfTrust(): RootOfTrust? {
        return teeEnforced.rootOfTrust ?: softwareEnforced.rootOfTrust
    }
}

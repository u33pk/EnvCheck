package qpdb.env.check.attestation

import android.util.Base64
import java.security.cert.CertificateParsingException
import java.security.cert.X509Certificate

abstract class Attestation protected constructor(x509Cert: X509Certificate) {

    companion object {
        const val ASN1_OID = "1.3.6.1.4.1.11129.2.1.17"
        const val EAT_OID = "1.3.6.1.4.1.11129.2.1.25"

        const val KM_SECURITY_LEVEL_SOFTWARE = 0
        const val KM_SECURITY_LEVEL_TRUSTED_ENVIRONMENT = 1
        const val KM_SECURITY_LEVEL_STRONG_BOX = 2

        @JvmStatic
        @Throws(CertificateParsingException::class)
        fun loadFromCertificate(x509Cert: X509Certificate): Attestation {
            if (x509Cert.getExtensionValue(EAT_OID) == null &&
                x509Cert.getExtensionValue(ASN1_OID) == null
            ) {
                throw CertificateParsingException("No attestation extensions found")
            }
            if (x509Cert.getExtensionValue(EAT_OID) != null) {
                throw CertificateParsingException("EAT attestation not supported in this version")
            }
            return Asn1Attestation(x509Cert)
        }

        fun securityLevelToString(attestationSecurityLevel: Int): String {
            return when (attestationSecurityLevel) {
                KM_SECURITY_LEVEL_SOFTWARE -> "Software"
                KM_SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> "TEE"
                KM_SECURITY_LEVEL_STRONG_BOX -> "StrongBox"
                else -> "Unknown ($attestationSecurityLevel)"
            }
        }

        fun attestationVersionToString(version: Int): String {
            return when (version) {
                1 -> "Keymaster 2.0"
                2 -> "Keymaster 3.0"
                3 -> "Keymaster 4.0"
                4 -> "Keymaster 4.1"
                100 -> "KeyMint 1.0"
                200 -> "KeyMint 2.0"
                300 -> "KeyMint 3.0"
                400 -> "KeyMint 4.0"
                else -> "Unknown ($version)"
            }
        }

        fun keymasterVersionToString(version: Int): String {
            return when (version) {
                0 -> "Keymaster 0.2 or 0.3"
                1 -> "Keymaster 1.0"
                2 -> "Keymaster 2.0"
                3 -> "Keymaster 3.0"
                4 -> "Keymaster 4.0"
                41 -> "Keymaster 4.1"
                100 -> "KeyMint 1.0"
                200 -> "KeyMint 2.0"
                300 -> "KeyMint 3.0"
                400 -> "KeyMint 4.0"
                else -> "Unknown ($version)"
            }
        }
    }

    var attestationVersion: Int = 0
        protected set
    var keymasterVersion: Int = 0
        protected set
    var keymasterSecurityLevel: Int = 0
        protected set
    var attestationChallenge: ByteArray? = null
        protected set
    var uniqueId: ByteArray? = null
        protected set
    lateinit var softwareEnforced: AuthorizationList
        protected set
    lateinit var teeEnforced: AuthorizationList
        protected set

    abstract val attestationSecurityLevel: Int

    abstract fun getRootOfTrust(): RootOfTrust?

    override fun toString(): String {
        val s = StringBuilder()
        s.append("Attest version: ${attestationVersionToString(attestationVersion)}")
        s.append("\nAttest security: ${securityLevelToString(attestationSecurityLevel)}")
        s.append("\nKM version: ${keymasterVersionToString(keymasterVersion)}")
        s.append("\nKM security: ${securityLevelToString(keymasterSecurityLevel)}")

        s.append("\nChallenge")
        val stringChallenge = attestationChallenge?.let { String(it) } ?: ""
        if (attestationChallenge.contentEquals(stringChallenge.toByteArray())) {
            s.append(": [$stringChallenge]")
        } else if (attestationChallenge != null) {
            s.append(" (base64): [${Base64.encodeToString(attestationChallenge, 0)}]")
        }
        uniqueId?.let {
            s.append("\nUnique ID: [${it.joinToString("") { b -> "%02x".format(b) }}]")
        }

        s.append("\n-- SW enforced --")
        s.append(softwareEnforced)
        s.append("\n-- TEE enforced --")
        s.append(teeEnforced)

        return s.toString()
    }
}

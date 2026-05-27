package qpdb.env.check.attestation

import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.ASN1TaggedObject
import java.security.cert.CertificateParsingException
import java.util.Date

class AuthorizationList(asn1Encodable: ASN1Encodable) {

    companion object {
        // Keymaster tag classes
        private const val KM_ENUM = 1 shl 28
        private const val KM_ENUM_REP = 2 shl 28
        private const val KM_UINT = 3 shl 28
        private const val KM_UINT_REP = 4 shl 28
        private const val KM_ULONG = 5 shl 28
        private const val KM_DATE = 6 shl 28
        private const val KM_BOOL = 7 shl 28
        private const val KM_BYTES = 9 shl 28

        private const val KEYMASTER_TAG_TYPE_MASK = 0x0FFFFFFF

        // Keymaster tags
        private const val KM_TAG_PURPOSE = KM_ENUM_REP or 1
        private const val KM_TAG_ALGORITHM = KM_ENUM or 2
        private const val KM_TAG_KEY_SIZE = KM_UINT or 3
        private const val KM_TAG_DIGEST = KM_ENUM_REP or 5
        private const val KM_TAG_PADDING = KM_ENUM_REP or 6
        private const val KM_TAG_ROLLBACK_RESISTANCE = KM_BOOL or 303
        private const val KM_TAG_EARLY_BOOT_ONLY = KM_BOOL or 305
        private const val KM_TAG_NO_AUTH_REQUIRED = KM_BOOL or 503
        private const val KM_TAG_CREATION_DATETIME = KM_DATE or 701
        private const val KM_TAG_ORIGIN = KM_ENUM or 702
        private const val KM_TAG_ROLLBACK_RESISTANT = KM_BOOL or 703
        private const val KM_TAG_ROOT_OF_TRUST = KM_BYTES or 704
        private const val KM_TAG_OS_VERSION = KM_UINT or 705
        private const val KM_TAG_OS_PATCHLEVEL = KM_UINT or 706
        private const val KM_TAG_VENDOR_PATCHLEVEL = KM_UINT or 718
        private const val KM_TAG_BOOT_PATCHLEVEL = KM_UINT or 719
        private const val KM_TAG_DEVICE_UNIQUE_ATTESTATION = KM_BOOL or 720

        // Attestation ID tags (device binding info)
        private const val KM_TAG_ATTESTATION_APPLICATION_ID = KM_BYTES or 709
        private const val KM_TAG_ATTESTATION_ID_BRAND = KM_BYTES or 710
        private const val KM_TAG_ATTESTATION_ID_DEVICE = KM_BYTES or 711
        private const val KM_TAG_ATTESTATION_ID_PRODUCT = KM_BYTES or 712
        private const val KM_TAG_ATTESTATION_ID_SERIAL = KM_BYTES or 713
        private const val KM_TAG_ATTESTATION_ID_IMEI = KM_BYTES or 714
        private const val KM_TAG_ATTESTATION_ID_MEID = KM_BYTES or 715
        private const val KM_TAG_ATTESTATION_ID_MANUFACTURER = KM_BYTES or 716
        private const val KM_TAG_ATTESTATION_ID_MODEL = KM_BYTES or 717
        private const val KM_TAG_ATTESTATION_ID_SECOND_IMEI = KM_BYTES or 723
        private const val KM_TAG_MODULE_HASH = KM_BYTES or 724

        const val KM_ORIGIN_GENERATED = 0
        const val KM_ORIGIN_DERIVED = 1
        const val KM_ORIGIN_IMPORTED = 2
        const val KM_ORIGIN_UNKNOWN = 3
        const val KM_ORIGIN_SECURELY_IMPORTED = 4

        const val KM_ALGORITHM_RSA = 1
        const val KM_ALGORITHM_EC = 3
    }

    var purposes: Set<Int>? = null
        private set
    var algorithm: Int? = null
        private set
    var keySize: Int? = null
        private set
    var digests: Set<Int>? = null
        private set
    var paddingModes: Set<Int>? = null
        private set
    var rollbackResistance: Boolean? = null
        private set
    var earlyBootOnly: Boolean? = null
        private set
    var noAuthRequired: Boolean? = null
        private set
    var creationDateTime: Date? = null
        private set
    var origin: Int? = null
        private set
    var rollbackResistant: Boolean? = null
        private set
    var rootOfTrust: RootOfTrust? = null
        private set
    var osVersion: Int? = null
        private set
    var osPatchLevel: Int? = null
        private set
    var vendorPatchLevel: Int? = null
        private set
    var bootPatchLevel: Int? = null
        private set
    var deviceUniqueAttestation: Boolean? = null
        private set
    var attestationApplicationId: AttestationApplicationId? = null
        private set
    var brand: String? = null
        private set
    var device: String? = null
        private set
    var product: String? = null
        private set
    var serialNumber: String? = null
        private set
    var imei: String? = null
        private set
    var meid: String? = null
        private set
    var manufacturer: String? = null
        private set
    var model: String? = null
        private set
    var secondImei: String? = null
        private set
    var moduleHash: ByteArray? = null
        private set

    init {
        if (asn1Encodable !is ASN1Sequence) {
            throw CertificateParsingException(
                "Expected sequence for authorization list, found ${asn1Encodable.javaClass.name}"
            )
        }
        for (entry in asn1Encodable) {
            if (entry !is ASN1TaggedObject) {
                throw CertificateParsingException(
                    "Expected tagged object, found ${entry.javaClass.name}"
                )
            }
            val tag = entry.tagNo
            val value = entry.baseObject.toASN1Primitive()
            when (tag) {
                KM_TAG_PURPOSE and KEYMASTER_TAG_TYPE_MASK ->
                    purposes = Asn1Utils.getIntegersFromAsn1Set(value)
                KM_TAG_ALGORITHM and KEYMASTER_TAG_TYPE_MASK ->
                    algorithm = Asn1Utils.getIntegerFromAsn1(value)
                KM_TAG_KEY_SIZE and KEYMASTER_TAG_TYPE_MASK ->
                    keySize = Asn1Utils.getIntegerFromAsn1(value)
                KM_TAG_DIGEST and KEYMASTER_TAG_TYPE_MASK ->
                    digests = Asn1Utils.getIntegersFromAsn1Set(value)
                KM_TAG_PADDING and KEYMASTER_TAG_TYPE_MASK ->
                    paddingModes = Asn1Utils.getIntegersFromAsn1Set(value)
                KM_TAG_ROLLBACK_RESISTANCE and KEYMASTER_TAG_TYPE_MASK ->
                    rollbackResistance = true
                KM_TAG_EARLY_BOOT_ONLY and KEYMASTER_TAG_TYPE_MASK ->
                    earlyBootOnly = true
                KM_TAG_NO_AUTH_REQUIRED and KEYMASTER_TAG_TYPE_MASK ->
                    noAuthRequired = true
                KM_TAG_CREATION_DATETIME and KEYMASTER_TAG_TYPE_MASK ->
                    creationDateTime = Asn1Utils.getDateFromAsn1(value)
                KM_TAG_ORIGIN and KEYMASTER_TAG_TYPE_MASK ->
                    origin = Asn1Utils.getIntegerFromAsn1(value)
                KM_TAG_ROLLBACK_RESISTANT and KEYMASTER_TAG_TYPE_MASK ->
                    rollbackResistant = true
                KM_TAG_ROOT_OF_TRUST and KEYMASTER_TAG_TYPE_MASK ->
                    rootOfTrust = RootOfTrust(value)
                KM_TAG_OS_VERSION and KEYMASTER_TAG_TYPE_MASK ->
                    osVersion = Asn1Utils.getIntegerFromAsn1(value)
                KM_TAG_OS_PATCHLEVEL and KEYMASTER_TAG_TYPE_MASK ->
                    osPatchLevel = Asn1Utils.getIntegerFromAsn1(value)
                KM_TAG_VENDOR_PATCHLEVEL and KEYMASTER_TAG_TYPE_MASK ->
                    vendorPatchLevel = Asn1Utils.getIntegerFromAsn1(value)
                KM_TAG_BOOT_PATCHLEVEL and KEYMASTER_TAG_TYPE_MASK ->
                    bootPatchLevel = Asn1Utils.getIntegerFromAsn1(value)
                KM_TAG_DEVICE_UNIQUE_ATTESTATION and KEYMASTER_TAG_TYPE_MASK ->
                    deviceUniqueAttestation = true
                KM_TAG_ATTESTATION_APPLICATION_ID and KEYMASTER_TAG_TYPE_MASK ->
                    try {
                        attestationApplicationId = AttestationApplicationId(
                            Asn1Utils.getAsn1EncodableFromBytes(Asn1Utils.getByteArrayFromAsn1(value))
                        )
                    } catch (e: Exception) {
                        android.util.Log.w("AuthorizationList", "Failed to parse AttestationApplicationId: ${e.message}")
                    }
                KM_TAG_ATTESTATION_ID_BRAND and KEYMASTER_TAG_TYPE_MASK ->
                    brand = Asn1Utils.getStringFromAsn1OctetStreamAssumingUTF8(value)
                KM_TAG_ATTESTATION_ID_DEVICE and KEYMASTER_TAG_TYPE_MASK ->
                    device = Asn1Utils.getStringFromAsn1OctetStreamAssumingUTF8(value)
                KM_TAG_ATTESTATION_ID_PRODUCT and KEYMASTER_TAG_TYPE_MASK ->
                    product = Asn1Utils.getStringFromAsn1OctetStreamAssumingUTF8(value)
                KM_TAG_ATTESTATION_ID_SERIAL and KEYMASTER_TAG_TYPE_MASK ->
                    serialNumber = Asn1Utils.getStringFromAsn1OctetStreamAssumingUTF8(value)
                KM_TAG_ATTESTATION_ID_IMEI and KEYMASTER_TAG_TYPE_MASK ->
                    imei = Asn1Utils.getStringFromAsn1OctetStreamAssumingUTF8(value)
                KM_TAG_ATTESTATION_ID_MEID and KEYMASTER_TAG_TYPE_MASK ->
                    meid = Asn1Utils.getStringFromAsn1OctetStreamAssumingUTF8(value)
                KM_TAG_ATTESTATION_ID_MANUFACTURER and KEYMASTER_TAG_TYPE_MASK ->
                    manufacturer = Asn1Utils.getStringFromAsn1OctetStreamAssumingUTF8(value)
                KM_TAG_ATTESTATION_ID_MODEL and KEYMASTER_TAG_TYPE_MASK ->
                    model = Asn1Utils.getStringFromAsn1OctetStreamAssumingUTF8(value)
                KM_TAG_ATTESTATION_ID_SECOND_IMEI and KEYMASTER_TAG_TYPE_MASK ->
                    secondImei = Asn1Utils.getStringFromAsn1OctetStreamAssumingUTF8(value)
                KM_TAG_MODULE_HASH and KEYMASTER_TAG_TYPE_MASK ->
                    moduleHash = Asn1Utils.getByteArrayFromAsn1(value)
            }
        }
    }

    override fun toString(): String {
        val s = StringBuilder()
        algorithm?.let { s.append("\nAlgorithm: $it") }
        keySize?.let { s.append("\nKeySize: $it") }
        purposes?.takeIf { it.isNotEmpty() }?.let { s.append("\nPurposes: $it") }
        digests?.takeIf { it.isNotEmpty() }?.let { s.append("\nDigests: $it") }
        paddingModes?.takeIf { it.isNotEmpty() }?.let { s.append("\nPadding modes: $it") }
        earlyBootOnly?.let { s.append("\nEarly boot only") }
        noAuthRequired?.let { s.append("\nNo auth required") }
        origin?.let { s.append("\nOrigin: $it") }
        rollbackResistant?.let { s.append("\nRollback resistant") }
        rollbackResistance?.let { s.append("\nRollback resistance") }
        osVersion?.let { s.append("\nOS version: $it") }
        osPatchLevel?.let { s.append("\nOS patch level: $it") }
        vendorPatchLevel?.let { s.append("\nVendor patch level: $it") }
        bootPatchLevel?.let { s.append("\nBoot patch level: $it") }
        deviceUniqueAttestation?.let { s.append("\nDevice unique attestation") }
        attestationApplicationId?.let { s.append("\nAttestation Application Id:\n$it") }
        brand?.let { s.append("\nBrand: $it") }
        device?.let { s.append("\nDevice type: $it") }
        product?.let { s.append("\nProduct: $it") }
        serialNumber?.let { s.append("\nSerial: $it") }
        imei?.let { s.append("\nIMEI: $it") }
        secondImei?.let { s.append("\nSecond IMEI: $it") }
        meid?.let { s.append("\nMEID: $it") }
        manufacturer?.let { s.append("\nManufacturer: $it") }
        model?.let { s.append("\nModel: $it") }
        moduleHash?.let { s.append("\nModule Hash: ${it.joinToString("") { b -> "%02x".format(b) }}") }
        rootOfTrust?.let { s.append("\n-- Root of Trust --\n$it") }
        return s.toString()
    }
}

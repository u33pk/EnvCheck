package qpdb.env.check.attestation

import org.bouncycastle.asn1.*
import java.io.IOException
import java.math.BigInteger
import java.nio.charset.StandardCharsets
import java.security.cert.CertificateParsingException
import java.util.*

object Asn1Utils {

    @Throws(CertificateParsingException::class)
    fun getIntegerFromAsn1(asn1Value: ASN1Encodable): Int {
        return when (asn1Value) {
            is ASN1Integer -> bigIntegerToInt(asn1Value.value)
            is ASN1Enumerated -> bigIntegerToInt(asn1Value.value)
            else -> throw CertificateParsingException(
                "Integer value expected, ${asn1Value.javaClass.name} found."
            )
        }
    }

    @Throws(CertificateParsingException::class)
    fun getLongFromAsn1(asn1Value: ASN1Encodable): Long {
        if (asn1Value is ASN1Integer) {
            return bigIntegerToLong(asn1Value.value)
        }
        throw CertificateParsingException(
            "Integer value expected, ${asn1Value.javaClass.name} found."
        )
    }

    @Throws(CertificateParsingException::class)
    fun getByteArrayFromAsn1(asn1Encodable: ASN1Encodable): ByteArray {
        if (asn1Encodable !is DEROctetString) {
            throw CertificateParsingException("Expected DEROctetString")
        }
        return asn1Encodable.octets
    }

    @Throws(CertificateParsingException::class)
    fun getAsn1EncodableFromBytes(bytes: ByteArray): ASN1Encodable {
        return try {
            ASN1InputStream(bytes).use { it.readObject() }
        } catch (e: IOException) {
            throw CertificateParsingException("Failed to parse Encodable", e)
        }
    }

    @Throws(CertificateParsingException::class)
    fun getAsn1SequenceFromBytes(bytes: ByteArray): ASN1Sequence {
        return try {
            ASN1InputStream(bytes).use { getAsn1SequenceFromStream(it) }
        } catch (e: IOException) {
            throw CertificateParsingException("Failed to parse SEQUENCE", e)
        }
    }

    @Throws(IOException::class, CertificateParsingException::class)
    private fun getAsn1SequenceFromStream(asn1InputStream: ASN1InputStream): ASN1Sequence {
        var asn1Primitive = asn1InputStream.readObject()
        if (asn1Primitive !is ASN1OctetString) {
            throw CertificateParsingException(
                "Expected octet stream, found ${asn1Primitive.javaClass.name}"
            )
        }
        ASN1InputStream(asn1Primitive.octets).use { seqInputStream ->
            asn1Primitive = seqInputStream.readObject()
            if (asn1Primitive !is ASN1Sequence) {
                throw CertificateParsingException(
                    "Expected sequence, found ${asn1Primitive.javaClass.name}"
                )
            }
            return asn1Primitive
        }
    }

    @Throws(CertificateParsingException::class)
    fun getIntegersFromAsn1Set(set: ASN1Encodable): Set<Int> {
        if (set !is ASN1Set) {
            throw CertificateParsingException("Expected set, found ${set.javaClass.name}")
        }
        val result = mutableSetOf<Int>()
        val e = set.objects
        while (e.hasMoreElements()) {
            result.add(getIntegerFromAsn1(e.nextElement() as ASN1Integer))
        }
        return result
    }

    @Throws(CertificateParsingException::class)
    fun getStringFromAsn1OctetStreamAssumingUTF8(encodable: ASN1Encodable): String {
        if (encodable !is ASN1OctetString) {
            throw CertificateParsingException(
                "Expected octet string, found ${encodable.javaClass.name}"
            )
        }
        return String(encodable.octets, StandardCharsets.UTF_8)
    }

    @Throws(CertificateParsingException::class)
    fun getDateFromAsn1(value: ASN1Primitive): Date {
        return Date(getLongFromAsn1(value))
    }

    @Throws(CertificateParsingException::class)
    fun getBooleanFromAsn1(value: ASN1Encodable): Boolean {
        if (value !is ASN1Boolean) {
            throw CertificateParsingException(
                "Expected boolean, found ${value.javaClass.name}"
            )
        }
        return when {
            value == ASN1Boolean.TRUE -> true
            value == ASN1Boolean.FALSE -> false
            else -> throw CertificateParsingException(
                "DER-encoded boolean values must contain either 0x00 or 0xFF"
            )
        }
    }

    @Throws(CertificateParsingException::class)
    private fun bigIntegerToInt(bigInt: BigInteger): Int {
        if (bigInt > BigInteger.valueOf(Int.MAX_VALUE.toLong()) || bigInt < BigInteger.ZERO) {
            throw CertificateParsingException("INTEGER out of bounds")
        }
        return bigInt.toInt()
    }

    @Throws(CertificateParsingException::class)
    private fun bigIntegerToLong(bigInt: BigInteger): Long {
        if (bigInt > BigInteger.valueOf(Long.MAX_VALUE) || bigInt < BigInteger.ZERO) {
            throw CertificateParsingException("INTEGER out of bounds")
        }
        return bigInt.toLong()
    }
}

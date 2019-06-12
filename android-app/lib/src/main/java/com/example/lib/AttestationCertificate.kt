package com.example.lib

import org.bouncycastle.asn1.*
import org.bouncycastle.cert.X509CertificateHolder
import java.time.Instant
import java.util.*

class AttestationCertificate(holder: X509CertificateHolder) {

    val attestationChallenge: ByteArray?
    val attestationVersion: Int?
    val keymasterVersion: Int?
    val attestationSecurityLevel: SecurityLevel
    val keymasterSecurityLevel: SecurityLevel
    val uniqueId: ByteArray?
    val softwareEnforced: SecurityProperties?
    val teeEnforced: SecurityProperties?

    init {
        val extension = holder.getExtension(ASN1ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17"))
        val sequence = extension?.parsedValue as ASN1Sequence?
        this.attestationVersion = sequence?.objectAt(0)?.toInt()
        this.attestationSecurityLevel = SecurityLevel.valueOf(sequence?.objectAt(1)?.toInt())
        this.keymasterVersion = sequence?.objectAt(2)?.toInt()
        this.keymasterSecurityLevel = SecurityLevel.valueOf(sequence?.objectAt(3)?.toInt())
        this.attestationChallenge = sequence?.objectAt(4)?.toByteArray()
        this.uniqueId = sequence?.objectAt(5)?.toByteArray()
        this.softwareEnforced = (sequence?.objectAt(6) as ASN1Sequence?)?.let {
            SecurityProperties(it)
        }
        this.teeEnforced = (sequence?.objectAt(7) as ASN1Sequence?)?.let { SecurityProperties(it) }
    }

    class SecurityProperties(seq: ASN1Sequence) {

        val purpose: List<Purpose?>?
        val algorithm: Algorithm?
        val keySize: Int?
        val digest: List<Digest?>?
        val padding: List<Padding?>?
        val ecCurve: Curve?
        val rsaPublicExponent: Int?
        val rollbackResistance: Boolean?
        val activeDateTime: Instant?
        val originationExpireDateTime: Instant?
        val usageExpireDateTime: Instant?
        val noAuthRequired: Boolean?
        val userAuthType: List<Auth?>?
        val authTimeout: Int?
        val allowWhileOnBody: Boolean?
        val trustedUserPresenceRequired: Boolean?
        val trustedConfirmationRequired: Boolean?
        val unlockedDeviceRequired: Boolean?
        val allApplications: Boolean?
        val applicationId: String?
        val creation: Instant?
        val keyOrigin: KeyOrigin
        val rollbackResistant: Boolean?
        val rootOfTrust: RootOfTrust?
        val osVersion: Int?
        val osPatchLevel: Int?
        val attestationApplication: AttestationApplication?
        val vendorPatchLevel: Int?
        val bootPatchLevel: Int?

        init {
            this.purpose = (seq.find(1) as ASN1Set?)?.asSequence()?.map { Purpose.valueOf(it?.toInt()) }?.toList()
            this.algorithm = Algorithm.valueOf(seq.find(2)?.toInt())
            this.keySize = seq.find(3)?.toInt()
            this.digest = (seq.find(5) as ASN1Set?)?.asSequence()?.map { Digest.valueOf(it?.toInt()) }?.toList()
            this.padding = (seq.find(6) as ASN1Set?)?.asSequence()?.map { Padding.valueOf(it?.toInt()) }?.toList()
            this.ecCurve = Curve.valueOf(seq.find(10)?.toInt())
            this.rsaPublicExponent = seq.find(200)?.toInt()
            this.rollbackResistance = if (seq.find(303) != null) true else null
            this.activeDateTime = seq.find(400)?.toInstant()
            this.originationExpireDateTime = seq.find(401)?.toInstant()
            this.usageExpireDateTime = seq.find(402)?.toInstant()
            this.applicationId = seq.find(601)?.toString()
            this.noAuthRequired = if (seq.find(503) != null) true else null
            val authValue = seq.find(504)?.toInt()
            this.userAuthType = if (authValue != null) Auth.values().filter { authValue and it.value == 1 } else null
            this.authTimeout = seq.find(505)?.toInt()
            this.allowWhileOnBody = if (seq.find(506) != null) true else null
            this.trustedUserPresenceRequired = if (seq.find(507) != null) true else null
            this.trustedConfirmationRequired = if (seq.find(508) != null) true else null
            this.unlockedDeviceRequired = if (seq.find(509) != null) true else null
            this.allApplications = if (seq.find(600) != null) true else null
            this.creation = seq.find(701)?.toInstant()
            this.keyOrigin = KeyOrigin.valueOf(seq.find(702)?.toInt())
            this.rollbackResistant = if (seq.find(703) != null) true else null
            this.rootOfTrust = seq.find(704)?.let { RootOfTrust(it) }
            this.osVersion = seq.find(705)?.toInt()
            this.osPatchLevel = seq.find(706)?.toInt()
            this.attestationApplication = seq.find(709)?.let {
                AttestationApplication(it)
            }
            this.vendorPatchLevel = seq.find(718)?.toInt()
            this.bootPatchLevel = seq.find(719)?.toInt()
        }

        class AttestationApplication(primitive: ASN1Primitive) {

            val packageName: String?
            val version: Int?
            var signatureDigests: List<ByteArray?>?

            init {
                val sequence = ASN1Sequence.fromByteArray(primitive.toByteArray()) as ASN1Sequence?
                val packageInfo = sequence?.objectAt(0) as ASN1Set?
                val packageSequence = packageInfo?.objects?.asSequence()?.first() as ASN1Sequence?
                this.packageName = packageSequence?.objectAt(0)?.toByteArray()?.let { String(it) }
                this.version = packageSequence?.objectAt(1)?.toInt()
                val signatureDigestSet = sequence?.objectAt(1) as ASN1Set?
                this.signatureDigests = signatureDigestSet?.asSequence()?.map { it.toByteArray() }?.toList()
            }

            override fun toString() = fancyToString(this, 4)

        }

        class RootOfTrust(primitive: ASN1Primitive) {

            val verifiedBootKey: ByteArray?
            val deviceLocked: Boolean?
            val verifiedBootState: BootState?
            val verifiedBootHash: ByteArray?

            init {
                val sequence = primitive as ASN1Sequence?
                this.verifiedBootKey = sequence?.objectAt(0)?.toByteArray()
                this.deviceLocked = (sequence?.objectAt(1) as ASN1Boolean?)?.isTrue
                this.verifiedBootState = BootState.valueOf(sequence?.objectAt(2)?.toInt())
                this.verifiedBootHash = sequence?.objectAt(3)?.toByteArray()
            }

            override fun toString() = fancyToString(this, 4)

        }

        override fun toString() = fancyToString(this, 2)
    }

    override fun toString() = fancyToString(this, 0)

}

private fun ASN1Primitive?.objectAt(index: Int): ASN1Encodable? {
    return when (this) {
        is ASN1Sequence -> try {
            this.getObjectAt(index)
        } catch (e: ArrayIndexOutOfBoundsException) {
            null
        }
        else -> null
    }
}

private fun ASN1Primitive?.toInt(): Int? {
    return when (this) {
        is ASN1Enumerated -> this.value.toInt()
        is ASN1Integer -> this.value.toInt()
        else -> null
    }
}

private fun ASN1Encodable?.toInt(): Int? {
    return when (this) {
        is ASN1Enumerated -> this.value.toInt()
        is ASN1Integer -> this.value.toInt()
        else -> null
    }
}

private fun ASN1Primitive?.toInstant(): Instant? {
    return when (this) {
        is ASN1Integer -> Instant.ofEpochMilli(this.value.toLong())
        else -> null
    }
}

private fun ASN1Encodable?.toInstant(): Instant? {
    return when (this) {
        is ASN1Integer -> Instant.ofEpochMilli(this.value.toLong())
        else -> null
    }
}

private fun ASN1Primitive?.toByteArray(): ByteArray? {
    return when (this) {
        is ASN1OctetString -> this.octets
        else -> null
    }
}

private fun ASN1Encodable?.toByteArray(): ByteArray? {
    return when (this) {
        is ASN1OctetString -> this.octets
        else -> null
    }
}

private fun ASN1Sequence.find(tag: Int): ASN1Primitive? {
    return toArray()
        .asSequence()
        .filterIsInstance<ASN1TaggedObject>()
        .firstOrNull { it.tagNo == tag }
        ?.`object`
}

enum class SecurityLevel(val value: Int) {
    NULL(-1),
    SOFTWARE(0),
    TEE(1),
    STRONGBOX(2);

    companion object {
        fun valueOf(value: Int?): SecurityLevel = values().find { it.value == value } ?: NULL
    }
}

enum class BootState(val value: Int) {
    NULL(-1),
    VERIFIED(0),
    SELF_SIGNED(1),
    UNVERIFIED(2),
    FAILED(3);

    companion object {
        fun valueOf(value: Int?): BootState = values().find { it.value == value } ?: NULL
    }
}

enum class KeyOrigin(val value: Int) {
    NULL(-1),
    GENERATED(0),
    DERIVED(1),
    IMPORTED(2),
    UNKNOWN(3);

    companion object {
        fun valueOf(value: Int?): KeyOrigin = values().find { it.value == value } ?: NULL
    }
}

enum class Purpose(val value: Int) {
    NULL(-1),
    ENCRYPT(0),
    DECRYPT(1),
    SIGN(2),
    VERIFY(3),
    DERIVE_KEY(4),
    WRAP_KEY(5);

    companion object {
        fun valueOf(value: Int?): Purpose = values().find { it.value == value } ?: NULL
    }
}

enum class Algorithm(val value: Int) {
    NULL(-1),
    RSA(1),
    DSA(2),
    EC(3),
    AES(32),
    TRIPLE_DES(33),
    HMAC(128);

    companion object {
        fun valueOf(value: Int?): Algorithm = values().find { it.value == value } ?: NULL
    }
}

enum class Digest(val value: Int) {
    NULL(-1),
    NONE(0),
    MD5(1),
    SHA1(2),
    SHA224(3),
    SHA256(4),
    SHA384(5),
    SHA512(6);

    companion object {
        fun valueOf(value: Int?): Digest = values().find { it.value == value } ?: NULL
    }
}

enum class Padding(val value: Int) {
    NULL(-1),
    NONE(1),
    RSA_OAEP(2),
    RSA_PSS(3),
    PKCS1_15_ENCRYPT(4),
    PKCS1_15_SIGN(5),
    PKCS7(64);

    companion object {
        fun valueOf(value: Int?): Padding = values().find { it.value == value } ?: NULL
    }
}

enum class Curve(val value: Int) {
    NULL(-1),
    P224(0),
    P256(1),
    P384(2),
    P512(3);

    companion object {
        fun valueOf(value: Int?): Curve = values().find { it.value == value } ?: NULL
    }
}

enum class Auth(val value: Int) {
    NULL(-1),
    NONE(0),
    PASSWORD(1),
    FINGERPRINT(2);

    companion object {
        fun valueOf(value: Int?): Auth = values().find { it.value == value } ?: NULL
    }
}


fun ByteArray.toBase64(): String =
    Base64.getEncoder().encodeToString(this)

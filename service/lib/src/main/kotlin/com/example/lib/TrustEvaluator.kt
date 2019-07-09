package com.example.lib

import java.security.SecureRandom

public class TrustEvaluator(
        private val osPatchLevel: Int, private val packageName: String, private val signatureDigestBase64: String
) {

    private val challenges = ArrayList<String>()

    fun getNewChallenge(): ByteArray {
        val random = randomBytes()
        challenges.add(random.toBase64())
        return random
    }

    @Throws(IllegalArgumentException::class)
    fun evaluateLevelOfTrust(attestationCertificate: AttestationCertificate): LevelOfTrustContainer {
        if (!isChallengeCorrect(attestationCertificate)) {
            throw IllegalArgumentException("Attestation challenge incorrect")
        }
        if (!isCorrectClientApplication(attestationCertificate)) {
            throw IllegalArgumentException("Wrong client application")
        }

        var lot = LevelOfTrust.HIGH
        val explanation = mutableListOf<String>()

        if (!isLatestAndroidOs(attestationCertificate)) {
            lot = LevelOfTrust.MEDIUM
            explanation.add("Android OS not up-to-date")
        }

        if (!isTeeEnforcedAttestation(attestationCertificate)) {
            lot = LevelOfTrust.LOW
            explanation.add("Attestation security level is not hardware-backed")
        }

        if (!isRootOfTrustPresent(attestationCertificate)) {
            lot = LevelOfTrust.LOW
            explanation.add("Verified Boot state unknown")
        } else {
            if (!isLockedBootloader(attestationCertificate)) {
                lot = LevelOfTrust.LOW
                explanation.add("Bootloader not locked")
            }
            if (!isSystemImageVerified(attestationCertificate)) {
                lot = LevelOfTrust.LOW
                explanation.add("System image not verified")
            }
        }

        return LevelOfTrustContainer(lot, explanation.joinToString(", "))
    }

    private fun isTeeEnforcedAttestation(attestationCertificate: AttestationCertificate) =
            ((attestationCertificate.attestationSecurityLevel == SecurityLevel.TEE || attestationCertificate.attestationSecurityLevel == SecurityLevel.STRONGBOX)
                    && (attestationCertificate.keymasterSecurityLevel == SecurityLevel.TEE || attestationCertificate.keymasterSecurityLevel == SecurityLevel.STRONGBOX))

    private fun isChallengeCorrect(attestationCertificate: AttestationCertificate) =
            challenges.remove(attestationCertificate.attestationChallenge?.toBase64() ?: "null")

    private fun isLatestAndroidOs(attestationCertificate: AttestationCertificate) =
            (attestationCertificate.teeEnforced?.osPatchLevel ?: 0 >= osPatchLevel)

    private fun isRootOfTrustPresent(attestationCertificate: AttestationCertificate) =
            (attestationCertificate.teeEnforced?.rootOfTrust != null)

    private fun isLockedBootloader(attestationCertificate: AttestationCertificate) =
            (attestationCertificate.teeEnforced?.rootOfTrust?.deviceLocked ?: false)

    private fun isSystemImageVerified(attestationCertificate: AttestationCertificate) =
            (attestationCertificate.teeEnforced?.rootOfTrust?.deviceLocked ?: false
                    && attestationCertificate.teeEnforced?.rootOfTrust?.verifiedBootState ?: BootState.FAILED == BootState.VERIFIED)

    private fun isCorrectClientApplication(attestationCertificate: AttestationCertificate) =
            (attestationCertificate.softwareEnforced?.attestationApplication?.packageName ?: "" == packageName
                    && attestationCertificate.softwareEnforced?.attestationApplication?.signatureDigests?.filter { it?.toBase64() ?: "" == signatureDigestBase64 }?.any() ?: false)

    private fun randomBytes(): ByteArray {
        val result = ByteArray(16)
        val random = SecureRandom()
        random.nextBytes(result)
        return result
    }

}

package com.example.attestationservice

import com.example.lib.LevelOfTrust
import com.example.lib.toBase64
import java.util.*

class ChallengeResponse(val challenge: ByteArray) {

    override fun toString(): String {
        return "ChallengeResponse(" +
                "challenge=${challenge.toBase64()}" +
                ")"
    }

}

class BindRequest {

    var attestationCertificates: List<ByteArray> = ArrayList()

    override fun toString(): String {
        val str = attestationCertificates.asSequence().map(Base64.getEncoder()::encodeToString).joinToString(",")
        return "BindRequest(" +
                "attestationCertificates=$str" +
                ")"
    }

}

class BindResponse(val level: LevelOfTrust, val explanation: String) {

    override fun toString(): String {
        return "BindResponse(level=$level, explanation='$explanation')"
    }

}

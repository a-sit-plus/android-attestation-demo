package com.example.lib

class LevelOfTrustContainer(val level: LevelOfTrust, val explanation: String) {

    override fun toString(): String {
        return "LevelOfTrustContainer(level=$level, explanation='$explanation')"
    }

}

enum class LevelOfTrust {
    UNKNOWN,
    LOW,
    MEDIUM,
    HIGH
}


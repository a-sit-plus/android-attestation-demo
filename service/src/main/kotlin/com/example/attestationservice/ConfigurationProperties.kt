package com.example.attestationservice

import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.stereotype.Component

@Component
@ConfigurationProperties("app")
public class ConfigurationProperties {

    lateinit var packageName: String
    lateinit var signatureDigest: String
    @Suppress("PLATFORM_CLASS_MAPPED_TO_KOTLIN")
    lateinit var osPatchLevel: Integer

}
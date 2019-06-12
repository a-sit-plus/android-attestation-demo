package com.example.attestationservice

import com.example.lib.TrustEvaluator
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration

@Configuration
class AttestationConfiguration {

    @Autowired
    private lateinit var configurationProperties: ConfigurationProperties

    @Bean
    public fun trustEvaluator(): TrustEvaluator {
        return TrustEvaluator(configurationProperties.osPatchLevel.toInt(),
                configurationProperties.packageName,
                configurationProperties.signatureDigest)
    }

}
package com.example.attestationservice

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.boot.runApplication

@SpringBootApplication
@EnableConfigurationProperties
class AttestationApplication {

    companion object {
        @JvmStatic
        fun main(args: Array<String>) {
            runApplication<AttestationApplication>(*args)
        }
    }

}
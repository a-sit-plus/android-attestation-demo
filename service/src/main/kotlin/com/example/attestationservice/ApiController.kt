package com.example.attestationservice

import com.example.lib.AttestationCertificate
import com.example.lib.TrustEvaluator
import com.example.lib.toBase64
import org.bouncycastle.cert.X509CertificateHolder
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.core.Authentication
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RestController
import java.security.Principal

@RestController
class ApiController {

    private val logger = LoggerFactory.getLogger(javaClass)

    @Autowired
    private lateinit var trustEvaluator: TrustEvaluator

    @Autowired
    private lateinit var userDetailsService: AttestedUserDetailsService

    @GetMapping("/")
    fun index(): ChallengeResponse {
        logger.debug("/ called")
        val random = trustEvaluator.getNewChallenge()
        val response = ChallengeResponse(random)
        logger.debug("/ returns {}", response)
        return response
    }

    @PostMapping("/bind")
    fun postBinding(@RequestBody request: BindRequest, principal: Principal): BindResponse {
        logger.debug("/bind called {}, {}", request, principal)
        try {
            val clientCertificate = request.attestationCertificates.first()
            val user = (principal as Authentication).principal as AttestedUser
            if (user.x509Certificate == null || !user.x509Certificate!!.contentEquals(clientCertificate)) {
                throw BadCredentialsException("Client certificates do not match")
            }
            val holder = X509CertificateHolder(clientCertificate)
            val attestationCertificate = AttestationCertificate(holder)
            val certificate = holder.encoded
            logger.debug("Examining {}", attestationCertificate)
            val lot = trustEvaluator.evaluateLevelOfTrust(attestationCertificate)
            userDetailsService.update(principal.name, certificate, lot.level)
            logger.debug("/bind returns {} for {}", lot, certificate.toBase64())
            return BindResponse(lot.level, lot.explanation)
        } catch (t: Throwable) {
            throw BadCredentialsException(t.message)
        }
    }

    @GetMapping("/lot/high")
    fun lotHigh(principal: Principal): String {
        return "High security area for ${principal.name}"
    }

    @GetMapping("/lot/medium")
    fun lotMedium(principal: Principal): String {
        return "Medium security area for ${principal.name}"
    }

    @GetMapping("/lot/low")
    fun lotLow(principal: Principal): String {
        return "Low security area for ${principal.name}"
    }

}

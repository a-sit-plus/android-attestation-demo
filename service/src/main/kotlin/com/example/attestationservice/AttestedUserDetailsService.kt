package com.example.attestationservice

import com.example.lib.LevelOfTrust
import com.example.lib.toBase64
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException
import org.springframework.security.core.authority.AuthorityUtils
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken
import org.springframework.stereotype.Service
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.*

@Service
class AttestedUserDetailsService : AuthenticationUserDetailsService<PreAuthenticatedAuthenticationToken> {

    private val users = mutableMapOf<String, AttestedUser>()

    private val roleLotUnknown = "ROLE_LOT_${LevelOfTrust.UNKNOWN.name}"

    override fun loadUserDetails(token: PreAuthenticatedAuthenticationToken?): UserDetails {
        if (token == null) {
            throw UsernameNotFoundException("token null")
        }
        val clientCertificate = getCertificate(token)
        val digest = MessageDigest.getInstance("SHA-1").digest(clientCertificate.encoded).toBase64()
        if (!users.containsKey(digest)) {
            val authorities = AuthorityUtils.createAuthorityList(roleLotUnknown)
            users[digest] = AttestedUser(digest, "N/A", authorities, clientCertificate.encoded)
        }
        return users[digest]!!
    }

    private fun getCertificate(token: PreAuthenticatedAuthenticationToken): X509Certificate {
        val credentials = token.credentials
        val principal = token.principal
        if (credentials is X509Certificate)
            return credentials
        if (credentials is String && credentials.isNotEmpty())
            try {
                return parseCert(credentials)
            } catch (e: Exception) {
            }
        if (principal is X509Certificate)
            return principal
        if (principal is String && principal.isNotEmpty()) {
            try {
                return parseCert(principal)
            } catch (e: Exception) {
            }
        }
        throw AuthenticationCredentialsNotFoundException("No cert found")
    }

    private fun parseCert(string: String): X509Certificate {
        val cleanString = string.replace("-----BEGIN CERTIFICATE-----", "").replace("-----END CERTIFICATE-----", "")
                .replace(" ", "").replace("\n", "").replace("\r", "")
        val decoded = Base64.getDecoder().decode(cleanString)
        return CertificateFactory.getInstance("X.509").generateCertificate(decoded.inputStream()) as X509Certificate
    }

    fun update(digest: String?, certificate: ByteArray?, lot: LevelOfTrust) {
        if (digest == null || !users.containsKey(digest)) {
            throw UsernameNotFoundException(digest)
        }
        val authorities = AuthorityUtils.createAuthorityList("ROLE_LOT_${lot.name}")
        users[digest] = AttestedUser(digest, "N/A", authorities, certificate)
    }

}
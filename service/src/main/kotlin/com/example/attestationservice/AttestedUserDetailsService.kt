package com.example.attestationservice

import com.example.lib.LevelOfTrust
import com.example.lib.toBase64
import org.springframework.security.core.authority.AuthorityUtils
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken
import org.springframework.stereotype.Service
import java.security.MessageDigest
import java.security.cert.X509Certificate

@Service
class AttestedUserDetailsService : AuthenticationUserDetailsService<PreAuthenticatedAuthenticationToken> {

    private val users = mutableMapOf<String, AttestedUser>()

    private val roleLotUnknown = "ROLE_LOT_${LevelOfTrust.UNKNOWN.name}"

    override fun loadUserDetails(token: PreAuthenticatedAuthenticationToken?): UserDetails {
        if (token == null) {
            throw UsernameNotFoundException("token null")
        }
        val clientCertificate = token.credentials as X509Certificate
        val digest = MessageDigest.getInstance("SHA-1").digest(clientCertificate.encoded).toBase64()
        if (!users.containsKey(digest)) {
            val authorities = AuthorityUtils.createAuthorityList(roleLotUnknown)
            users[digest] = AttestedUser(digest, "N/A", authorities, clientCertificate.encoded)
        }
        return users[digest]!!
    }

    fun update(digest: String?, certificate: ByteArray?, lot: LevelOfTrust) {
        if (digest == null || !users.containsKey(digest)) {
            throw UsernameNotFoundException(digest)
        }
        val authorities =
                AuthorityUtils.createAuthorityList("ROLE_LOT_${lot.name}")
        users[digest] = AttestedUser(digest, "N/A", authorities, certificate)
    }

}
package com.example.attestationservice

import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.userdetails.User

class AttestedUser(
        username: String?, password: String?, authorities: MutableCollection<out GrantedAuthority>?,
        var x509Certificate: ByteArray? = null
) : User(username, password, authorities) {

}
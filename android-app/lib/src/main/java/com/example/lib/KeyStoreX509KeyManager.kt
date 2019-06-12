package com.example.lib

import java.net.Socket
import java.security.KeyStore
import java.security.Principal
import java.security.PrivateKey
import java.security.cert.X509Certificate
import javax.net.ssl.X509KeyManager

internal class KeyStoreX509KeyManager
constructor(private val keyAlias: String) : X509KeyManager {

    private val keyStore: KeyStore = KeyStore.getInstance("AndroidKeyStore")

    init {
        keyStore.load(null, null)
    }

    override fun getClientAliases(keyType: String, issuers: Array<Principal>?): Array<String> {
        return arrayOf(keyAlias)
    }

    override fun chooseClientAlias(keyType: Array<String>, issuers: Array<Principal>?, socket: Socket?): String {
        return keyAlias
    }

    override fun getServerAliases(keyType: String, issuers: Array<Principal>?): Array<String> {
        return arrayOf()
    }

    override fun chooseServerAlias(keyType: String, issuers: Array<Principal>?, socket: Socket?): String? {
        return null
    }

    override fun getCertificateChain(alias: String): Array<X509Certificate>? {
        val chain = keyStore.getCertificateChain(keyAlias)
        val result = mutableListOf<X509Certificate>()
        for (cert in chain) {
            result.add(cert as X509Certificate)
        }
        return result.toTypedArray()
    }

    override fun getPrivateKey(alias: String): PrivateKey? {
        return keyStore.getKey(keyAlias, null) as PrivateKey
    }

}

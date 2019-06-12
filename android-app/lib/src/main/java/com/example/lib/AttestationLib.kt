package com.example.lib

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.support.annotation.WorkerThread
import okhttp3.*
import org.bouncycastle.cert.X509CertificateHolder
import org.json.JSONArray
import org.json.JSONObject
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.cert.Certificate
import java.util.*
import javax.net.ssl.*


class AttestationLib {

    @WorkerThread
    fun bind(url: String, success: (JSONObject) -> Unit, error: (String) -> Unit) {
        try {
            safeBind(url, success)
        } catch (e: Exception) {
            error(e.localizedMessage)
        }
    }

    @WorkerThread
    fun provideOkHttpClientBuilder(): OkHttpClient.Builder {
        return authenticatedHttpClient(keyStoreAlias)
    }

    fun getAttestationCertificate(): AttestationCertificate? {
        val chain = getAttestationChain(keyStoreAlias)
        return when {
            chain != null -> AttestationCertificate(X509CertificateHolder(chain.first().encoded))
            else -> null
        }
    }

    private fun safeBind(url: String, success: (JSONObject) -> Unit) {
        val json = getChallengeJson(url)
        val challenge = json.getString("challenge")
        val challengeBytes = Base64.getDecoder().decode(challenge)

        KeyPairGenerator.getInstance("EC", "AndroidKeyStore").also {
            val purposes = KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
            val keyGenSpec =
                KeyGenParameterSpec.Builder(keyStoreAlias, purposes)
                    .setKeySize(256)
                    // NONE is required for mutual authenticated TLS
                    .setDigests(KeyProperties.DIGEST_NONE, KeyProperties.DIGEST_SHA256)
                    .setAttestationChallenge(challengeBytes)
                    .build()
            it.initialize(keyGenSpec)
            it.generateKeyPair()
            val result = postAttestationCertificate(url, keyStoreAlias)
            success(result)
        }
    }

    private fun getChallengeJson(url: String): JSONObject {
        val httpUrl = HttpUrl.parse(url) ?: throw Exception("URL not valid")
        val urlRoot = httpUrl.newBuilder().addPathSegment("").build()
        val request = Request.Builder().url(urlRoot).addHeader("Accept", "application/json").get().build()
        val client = OkHttpClient.Builder().build()
        val response = client.newCall(request).execute()
        return when {
            response.isSuccessful -> JSONObject(response.body()?.string())
            else -> throw Exception("GET not successful")
        }
    }

    private fun getAttestationChain(keyStoreAlias: String): Array<out Certificate>? {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").also {
            it.load(null, null)
        }
        return keyStore.getCertificateChain(keyStoreAlias)
    }

    private fun postAttestationCertificate(url: String, keyStoreAlias: String): JSONObject {
        val httpUrl = HttpUrl.parse(url) ?: throw Exception("URL not valid")
        val urlBind = httpUrl.newBuilder().addPathSegment("bind").build()
        val jsonCerts = JSONArray()
        getAttestationChain(keyStoreAlias)?.forEach { jsonCerts.put(Base64.getEncoder().encodeToString(it.encoded)) }
        val requestBodyJson = JSONObject().put("attestationCertificates", jsonCerts)
        val requestBody = RequestBody.create(MediaType.parse("application/json"), requestBodyJson.toString())
        val request = Request.Builder().url(urlBind).addHeader("Accept", "application/json").post(requestBody).build()
        val client = authenticatedHttpClient(keyStoreAlias).build()
        val response = client.newCall(request).execute()
        return when {
            response.isSuccessful -> JSONObject(response.body()?.string())
            else -> throw Exception("Binding failed")
        }
    }

    private fun authenticatedHttpClient(keyStoreAlias: String): OkHttpClient.Builder {
        val defaultAlgorithm = TrustManagerFactory.getDefaultAlgorithm()
        val trustManagerFactory = TrustManagerFactory.getInstance(defaultAlgorithm)
        trustManagerFactory.init(null as KeyStore?)
        val trustManager = trustManagerFactory.trustManagers[0]
        val sslContext = SSLContext.getInstance("TLS")
        val keyManagers = arrayOf<KeyManager>(KeyStoreX509KeyManager(keyStoreAlias))
        val trustManagers = arrayOf<TrustManager>(trustManager)
        sslContext.init(keyManagers, trustManagers, null)
        return OkHttpClient.Builder().sslSocketFactory(sslContext.socketFactory, trustManager as X509TrustManager)
    }

    companion object {
        private const val keyStoreAlias = "alias"
    }

}

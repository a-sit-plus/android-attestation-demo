package com.example.trustedapplication

import android.os.AsyncTask
import android.os.Bundle
import android.support.v7.app.AppCompatActivity
import com.example.lib.AttestationLib
import kotlinx.android.synthetic.main.activity_main.*
import okhttp3.HttpUrl
import okhttp3.Request

class MainActivity : AppCompatActivity() {

    private lateinit var attestationLib: AttestationLib

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        attestationLib = AttestationLib()

        btBind.setOnClickListener {
            AsyncTask.execute {
                attestationLib.bind(
                    etServiceUri.text.toString(),
                    { message ->
                        successFun(message.toString())
                        runOnUiThread {
                            tvStatus.append("\nNow try to access the API")
                        }
                        appendAttestationCert()
                    },
                    { message ->
                        errorFun(message)
                        appendAttestationCert()
                    }
                )
            }
        }

        btAccessHigh.setOnClickListener {
            AsyncTask.execute {
                accessApi("high")
            }
        }
        btAccessMedium.setOnClickListener {
            AsyncTask.execute {
                accessApi("medium")
            }
        }
        btAccessLow.setOnClickListener {
            AsyncTask.execute {
                accessApi("low")
            }
        }
    }

    private fun appendAttestationCert() {
        val attestationCertificate = attestationLib.getAttestationCertificate()
        runOnUiThread {
            if (attestationCertificate != null)
                tvStatus.append("\nAttestation certificate of this device: $attestationCertificate")
            else
                tvStatus.append("\nNo attestation certificate available")
        }
    }

    private fun accessApi(apiEndpoint: String) {
        try {
            val url = etServiceUri.text.toString()
            val httpUrl = HttpUrl.parse(url) ?: throw Exception("URL not valid")
            val getUrl =
                httpUrl.newBuilder().addPathSegment("").addPathSegment("lot").addPathSegment(apiEndpoint).build()
            val request = Request.Builder().url(getUrl).get().build()
            val client = attestationLib.provideOkHttpClientBuilder().build()
            val response = client.newCall(request).execute().body()?.string() ?: "GET not successful"
            successFun(response)
        } catch (t: Throwable) {
            errorFun("Please bind first: " + t.localizedMessage)
        }
    }

    private fun errorFun(message: String) {
        runOnUiThread {
            tvStatus.text = "Error:\n$message"
        }
    }

    private fun successFun(message: String) {
        runOnUiThread {
            tvStatus.text = "Server response:\n$message"
        }
    }

}

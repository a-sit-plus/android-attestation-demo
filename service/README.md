# Fides – Android Key Attestation Service

API endpoints:
 - `/` sends a random attestation challenge to the client
 - `/bind` expects a chain of attestation certificates from the client, and responds with a level of trust (plus explanation) for this client.
 - `/lot/high`, `/lot/medium`, `/lot/low` are dummy services, each requiring the respective level of trust of the client (and thus a binding beforehand)

## Library: Trust evaluation

Evaluation of the level of trust depends on following properties (see [TrustEvaluator](./lib/src/main/kotlin/com/example/lib/TrustEvaluator.kt) for the implementation):
 - Correct challenge, otherwise access is denied
 - Correct client application, verified by signature certificate and package name, otherwise access is denied
 - Keymaster and attestation security level is TEE or StrongBox, otherwise access is denied
 - Latest Android security patch level, otherwise level of trust is medium
 - Verified boot state, i.e. a locked bootloader and verified system image, otherwise level of trust is low
 - If all checks pass, the level of trust is high

The values for the latest Android patch level, package name and signature certificate digest for the client application can be configured in the [application.properties](./src/main/resources/application.properties).
 
All properties above are read from the attestation certificate of the client, and are thus attested by the operating system and/or secure hardware on the client.

The endpoint `/bind` is secured by a client authenticated TLS session. The [truststore](./src/main/resources/truststore.p12) for the TLS server contains the Google software attestation root and Google hardware attestation root certificates. Therefore, only Android devices with a correct key attestation certificate chain can access this endpoint.

## API

The [ApiController](./src/main/kotlin/com/example/attestationservice/ApiController.kt) offers three endpoints with different required levels of trust from the client. [WebSecurityConfiguration](./src/main/kotlin/com/example/attestationservice/WebSecurityConfiguration.kt) provides the configuration of the endpoints by using Spring Security.

## Running this Service

The default profile `direct` should be used if this service is directly exposed to the Internet (see [application-direct.properties](./src/main/resources/application-direct.properties) for details). The profile `reverseproxy` should be used if the service is running behind a reverse proxy like Apache2 or nginx (see [application-reverseproxy.properties](./src/main/resources/application-reverseproxy.properties) for details). It can be activated by stating `spring.profiles.active=direct` in [application.properties](./src/main/resources/application.properties).

### Direct mode 

To run the service in `direct` mode, a TLS certificate needs to be created and configured. Create a private key and a self-signed X.509 certificate with these extensions:

 - Extended Key Usage (`2.5.29.37`) TLS Web Server Authentication (`1.3.6.1.5.5.7.3.1`)
 - Subject Alternative Name (`2.5.29.17`) containing the hostname or IP address of the server
 - Subject Key Identifier (`2.5.29.14`) matching the key
 
 Place the private key and certificate into the [keystore.p12](./src/main/resources/keystore.p12). Trust the certificate in the app by exporting it into [my_ca](./../android-app/app/src/main/res/raw/my_ca), and modify [network_security_config.xml](./../android-app/app/src/main/res/xml/network_security_config.xml) to include the domain of your server.
 
### Reverse proxy

The reverse proxy needs to terminate the TLS connection and pass the information about the Client's TLS certificate. Copy the [truststore.p12](./src/main/resources/truststore.p12) to the server. This mode has the advantage, that you can use the TLS certificate from your webserver, i.e. do not need to create or explicitly trust a custom CA in your app.

Example config for Apache2:
```conf
SSLCACertificateFile "/path/to/truststore.p12"
<Location "/bind">
  ProxyPass "http://localhost:8080/service"
  ProxyPassReverse "http://localhost:8080/service"
  SSLVerifyClient optional
  SSLVerifyDepth 5
  SSLOptions +ExportCertData
  RequestHeader set SSL_CLIENT_CERT "%{SSL_CLIENT_CERT}s"
</Location>
```

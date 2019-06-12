# Fides - Android Key Attestation Service & Library

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
# Fides - Android Key Attestation Library

[AttestationLib](./lib/src/main/java/com/example/lib/AttestationLib.kt) performs the following procedure:
 1. Lib gets an attestation challenge (TLS with server authentication) from the service (under the path `/`)
 2. Service generates a random challenge
 3. Lib receives this attestation challenge
 4. Lib generates a private/public key pair, using the Android KeyStore system and the attestation challenge
 5. Using the key pair, Lib initiates a client authenticated TLS session to the service (path `/bind`)
 6. Service verifies the attestation certificate
 7. Service evaluates the result against a policy
 8. Lib receives the level of trust from the service

The server's TLS certificate is explicitly trusted in the [Network Security Config](./app/src/main/res/xml/network_security_config.xml).

[MainActivity](./app/src/main/java/com/example/trustedapplication/MainActivity.kt) also performs GET requests of the API requiring different levels of trust (low, medium, high). The connection is again client-authenticated TLS, which requires a binding with the service beforehand.

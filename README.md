# Fides - Unleashing the Full Potential of Remote Attestation

In connected mobile app settings, back-ends have no means to reliably verify the integrity of clients. For this reason, services aimed at mobile users employ (unreliable) heuristics to establish trust. We tackle the issue of mobile client trust on the Android platform by harnessing features of current Android devices and show how it is now possible to remotely verify the integrity of mobile client applications at runtime. This makes it possible to perform sensitive operations on devices outside a service operator's control.

We present Fides, which improves the security properties of typical connected applications and foregoes heuristics for determining a device's state such as SafetyNet or root checks. At its core, our work is based on the advancements of Android's key attestation capabilities, which means that it does not impose a performance penalty. Our concept is widely applicable in the real world and does not remain a purely academic thought experiment. We demonstrate this by providing a light-weight, easy-to use library that is freely available as open source software. We have verified that Fides even outperforms the security measures integrated into critical applications like Google Pay.

[Fides — Unleashing the Full Potential of Remote Attestation](https://graz.pure.elsevier.com/en/publications/fides-unleashing-the-full-potential-of-remote-attestation), paper by Bernd Prünster, Gerald Palfinger, and Christian Kollmann, presented at [SECRYPT 2019](http://www.secrypt.icete.org/?y=2019).

## Android Key Attestation Service & Library

The [service](./service) is a Spring Boot service demonstrating the binding process and evaluation of the attestation certificate. See [README.md](./service/README.md) for details.
The [android-app](./android-app) is an Android app demonstrating the key generation process and exporting of the attestation certificate. See [README.md](./android-app/README.md) for details.

## Deployment

The Spring Boot service can be started directly with `gradlew bootRun`. It starts an integrated Tomcat application container, running on port 443.

To run the service, a TLS certificate needs to be created and configured. Create a private key and a self-signed X.509 certificate with these extensions:
- Extended Key Usage (`2.5.29.37`) TLS Web Server Authentication (`1.3.6.1.5.5.7.3.1`)
- Subject Alternative Name (`2.5.29.17`) containing the hostname or IP address of the server
- Subject Key Identifier (`2.5.29.14`) matching the key

Place the private key and certificate into the [keystore.p12](./service/src/main/resources/keystore.p12). Trust the certificate in the app by exporting it into [my_ca](./android-app/app/src/main/res/raw/my_ca), and modify [network_security_config.xml](./android-app/app/src/main/res/xml/network_security_config.xml) to include the domain of your server.

The password for all keystores and truststores is `changeit` by default.


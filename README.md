# Fides – Unleashing the Full Potential of Remote Attestation

In connected mobile app settings, back-ends have no means to reliably verify the integrity of clients. For this reason, services aimed at mobile users employ (unreliable) heuristics to establish trust. We tackle the issue of mobile client trust on the Android platform by harnessing features of current Android devices and show how it is now possible to remotely verify the integrity of mobile client applications at runtime. This makes it possible to perform sensitive operations on devices outside a service operator's control.

We present Fides, which improves the security properties of typical connected applications and foregoes heuristics for determining a device's state such as SafetyNet or root checks. At its core, our work is based on the advancements of Android's key attestation capabilities, which means that it does not impose a performance penalty. Our concept is widely applicable in the real world and does not remain a purely academic thought experiment. We demonstrate this by providing a light-weight, easy-to use library that is freely available as open source software. We have verified that Fides even outperforms the security measures integrated into critical applications like Google Pay.

[Fides – Unleashing the Full Potential of Remote Attestation](https://graz.pure.elsevier.com/en/publications/fides-unleashing-the-full-potential-of-remote-attestation), paper by Bernd Prünster, Gerald Palfinger, and Christian Kollmann, presented at [SECRYPT 2019](http://www.secrypt.icete.org/?y=2019).

## Android Key Attestation Service & Library

The [service](./service) is a Spring Boot service demonstrating the binding process and evaluation of the attestation certificate. See [README.md](./service/README.md) for details.
The [android-app](./android-app) is an Android app demonstrating the key generation process and exporting of the attestation certificate. See [README.md](./android-app/README.md) for details.

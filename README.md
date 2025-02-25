# Quantum Secure Messaging Protocol (QSMP)

**QSMP is a post-quantum alternative to traditional key exchange protocols (such as TLS) that integrates robust key exchange, authentication, and an encrypted tunnel into a single specification.**

See the dcumentation at: https://qrcs-corp.github.io/QSMP/

## Overview

QSMP is designed to provide strong post-quantum security using modern asymmetric and symmetric cryptographic primitives. It supports two distinct operational models:

- **SIMPLEX Protocol:**  
  A one-way trust model where the client trusts the server. This mode establishes a 256-bit secure bidirectional encrypted tunnel with only two round trips. It is ideal for scenarios requiring efficient, high-performance communications where the server is trusted.

- **DUPLEX Protocol:**  
  A two-way trust model where both hosts authenticate each other. Each host contributes a secret that is combined to key 512-bit secure symmetric cipher instances (using the RCS cipher). This mode is well suited for peer-to-peer and high-security communications, delivering a fully 512-bit secure end-to-end crypto system when configured with the appropriate parameter sets.

QSMP breaks new ground by designing these mechanisms from the ground up—eschewing backward compatibility concerns—to deliver streamlined, modern, and quantum-safe cryptographic solutions.


## Introduction

In today's digital landscape, many key exchange protocols (like those used in TLS, PGP, and SSH) rely on established methods to exchange secret keys and establish encrypted tunnels. However, with the advent of quantum computing, there is an urgent need to replace legacy schemes with post-quantum alternatives.

QSMP provides a complete specification that:
- Integrates post-quantum secure key exchange with built-in authentication and encrypted tunnel establishment.
- Uses state-of-the-art asymmetric ciphers (e.g., Kyber and McEliece) and signature schemes (e.g., Dilithium or SPHINCS+) standardized by NIST.
- Leverages a robust symmetric cipher (RCS) with enhanced key schedules and authenticated encryption (via KMAC or QMAC).

By designing QSMP without the constraints of legacy systems, the protocol offers simplicity, improved performance, and superior security for future-proof communications.


## Design Philosophy

QSMP was developed with a clear focus on:
- **Modernity:** Avoiding legacy APIs and compatibility issues to deliver a streamlined, secure protocol.
- **Performance:** Incorporating multi-threading and hardware-specific optimizations (using AVX, AVX2, and AVX512 intrinsics) for best-in-class throughput.
- **Security:** Employing next-generation post-quantum cryptographic primitives, QSMP ensures both the confidentiality and integrity of communications.
- **Flexibility:** Offering both SIMPLEX and DUPLEX modes to cater to different operational environments—from client-server deployments to peer-to-peer networks.


## Cryptographic Primitives

QSMP employs state-of-the-art cryptographic algorithms:

### Asymmetric Cryptography
- **Key Encapsulation Mechanisms:**  
  - *McEliece:* Uses the Niederreiter dual form.  
  - *Kyber:* Supports the full range of parameter sets (updated to NIST standards).  

- **Digital Signature Schemes:**  
  - *Dilithium* and *Sphincs+:* NIST-standardized for post-quantum security.  

### Symmetric Cryptography

- **Stream Ciphers:**  
  - *RCS:* An authenticated stream cipher based on wide-block Rijndael with enhanced key schedules and AEAD (using KMAC/QMAC).

### Hash Functions and MACs
- **Hash Functions:**  
  - *SHA3* (256 and 512-bit variants).

- **Message Authentication Codes:**  
  - *KMAC, plus a variant called *QMAC* (GMAC(2^256)).

### Additional Primitives
- **DRBG, XOF, and PRNGs:**  
  - Uses Keccak-based functions (SHA3, SHAKE, cSHAKE).
  
- **Entropy Providers:**  
  - ACP that integrates system providers, system state, hardware randomness (e.g., Intel RDRAND) hashed with SHAKE-512.


## Protocol Specifications

QSMP defines two complete protocol specifications:

### SIMPLEX Protocol
- **Model:** One-way trust; the client trusts the server.
- **Operation:**  
  - The server signs its public asymmetric key.
  - The client verifies the signature using the server’s public verification key.
  - A 256-bit secure two-way encrypted tunnel is established in just two round trips.
- **Ideal for:** Scenarios where a high-performance, secure channel is needed between a trusted server and its clients.

### DUPLEX Protocol
- **Model:** Bi-directional trust; both hosts authenticate each other.
- **Operation:**  
  - Both hosts exchange signed public asymmetric cipher keys.
  - Each host contributes a secret that is combined to derive 512-bit secure symmetric cipher keys.
- **Ideal for:** Peer-to-peer connections and high-security communications between remote hosts. This mode can be integrated with SIMPLEX for host registration and secure key distribution.


## Testing and Deployment

### Windows Visual Studio Self-Test

**Simplex Mode:**
- Set the server project as the startup project and run it.
- In the project pane, right-click the client project and choose **Debug → New Instance**.
- Enter the loopback IP address `127.0.0.1` and specify the path to the public key created during server initialization.

**Duplex Mode:**
- Set the Listener project as the startup project and run it.
- Right-click the client project in the project pane and choose **Debug → New Instance**.
- Enter the loopback IP address `127.0.0.1` and specify the path to the public key created when the listener was initialized.

## References

- For further details on cryptographic primitives and implementations, please refer to the [QSC Library Documentation](https://qrcs-corp.github.io/QSC/).

## Keywords

Cryptography, Post-Quantum, Asymmetric Cryptography, Symmetric Cryptography, Digital Signature, Key Encapsulation, Key Exchange, Hash Function, MAC, Pseudo-Random Number Generator, DRBG, Entropy, SIMD, AVX, AVX2, AVX512, Secure Memory, Asynchronous, MISRA, QSMP.

## License

QRCS-PL private License. See license file for details.  
Software is copyrighted and QSMP is patent pending.
Written by John G. Underhill, under the QRCS-PL license, see the included license file for details. 
Not to be redistributed or used commercially without the author's expressed written permission. 
_All rights reserved by QRCS Corp. (2025)._

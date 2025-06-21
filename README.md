# Quantum Secure Messaging Protocol (QSMP)

## Introduction

[![Build](https://github.com/QRCS-CORP/QSMP/actions/workflows/build.yml/badge.svg?branch=main)](https://github.com/QRCS-CORP/QSMP/actions/workflows/build.yml)
[![CodeQL](https://github.com/QRCS-CORP/QSMP/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/QRCS-CORP/QSMP/actions/workflows/codeql-analysis.yml)
[![CodeFactor](https://www.codefactor.io/repository/github/qrcs-corp/qsmp/badge)](https://www.codefactor.io/repository/github/qrcs-corp/qsmp)
[![Platforms](https://img.shields.io/badge/platforms-Linux%20|%20macOS%20|%20Windows-blue)](#)
[![Security Policy](https://img.shields.io/badge/security-policy-blue)](https://github.com/QRCS-CORP/QSMP/security/policy)
[![License: QRCS License](https://img.shields.io/badge/License-QRCS%20License-blue.svg)](https://github.com/QRCS-CORP/QSMP/blob/main/License.txt)
[![Language](https://img.shields.io/static/v1?label=Language&message=C%2023&color=blue)](https://www.open-std.org/jtc1/sc22/wg14/www/docs/n3220.pdf)
[![docs](https://img.shields.io/badge/docs-online-brightgreen)](https://qrcs-corp.github.io/QSMP/)
[![GitHub release](https://img.shields.io/github/v/release/QRCS-CORP/QSMP)](https://github.com/QRCS-CORP/QSMP/releases/tag/2025-06-04)
[![GitHub Last Commit](https://img.shields.io/github/last-commit/QRCS-CORP/QSMP.svg)](https://github.com/QRCS-CORP/QSMP/commits/main)
[![Custom: Standard](https://img.shields.io/static/v1?label=Security%20Standard&message=MISRA&color=blue)](https://misra.org.uk/)
[![Custom: Target](https://img.shields.io/static/v1?label=Target%20Industry&message=Communications&color=brightgreen)](#)

**QSMP is a post-quantum alternative to traditional key exchange protocols (such as TLS) that integrates robust key exchange, authentication, and an encrypted tunnel into a single specification.**

[QSMP Help Documentation](https://qrcs-corp.github.io/QSMP/)  
[QSMP Protocol Specification](https://qrcs-corp.github.io/QSMP/pdf/QSMP_Specification.pdf)  
[QSMP Summary Document](https://qrcs-corp.github.io/QSMP/pdf/QSMP_Summary.pdf)  

## Overview

QSMP is designed to provide strong post-quantum security using modern asymmetric and symmetric cryptographic primitives. It supports two distinct operational models:

- **SIMPLEX Protocol:**  
  A one-way trust model where the client trusts the server. This mode establishes a 256-bit secure bidirectional encrypted tunnel with only two round trips. It is ideal for scenarios requiring efficient, high-performance communications where the server is trusted.

- **DUPLEX Protocol:**  
  A two-way trust model where both hosts authenticate each other. Each host contributes a secret that is combined to key 512-bit secure symmetric cipher instances (using the RCS cipher). This mode is well suited for peer-to-peer and high-security communications, delivering a fully 512-bit secure end-to-end crypto system when configured with the appropriate parameter sets.

QSMP breaks new ground by designing these mechanisms from the ground up, eschewing backward compatibility concerns—to deliver streamlined, modern, and quantum-safe cryptographic solutions.


## Introduction

In today's digital landscape, many key exchange protocols (like those used in TLS, PGP, and SSH) rely on established methods to exchange secret keys and establish encrypted tunnels. However, with the advent of quantum computing, there is an urgent need to replace legacy schemes with post-quantum alternatives.

QSMP provides a complete specification that:
- Integrates post-quantum secure key exchange with built-in authentication and encrypted tunnel establishment.
- Uses state-of-the-art asymmetric ciphers (e.g., Kyber or McEliece) and signature schemes (e.g., Dilithium or SPHINCS+) standardized by NIST.
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
  - *Kyber:* Supports the full range of parameter sets (updated to the NIST FIPS 203 standard).  

- **Digital Signature Schemes:**  
  - *Dilithium* and *Sphincs+:* NIST-standardized for post-quantum security (updated to the FIPS 204 AND 205 standards).  

### Symmetric Cryptography

- **Stream Ciphers:**  
  - *RCS:* An authenticated stream cipher based on wide-block Rijndael with enhanced key schedule and AEAD (using KMAC/QMAC).

### Hash Functions and MACs
- **Hash Functions:**  
  - *SHA3* (256 and 512-bit variants).

- **Message Authentication Codes:**  
  - *KMAC, or a variant called *QMAC* (GMAC(2^256)).

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

## Compilation

QSMP uses the QSC cryptographic library. QSC is a standalone, portable, and MISRA-aligned cryptographic library written in C. It supports platform-optimized builds across **Windows**, **macOS**, and **Linux** via [CMake](https://cmake.org/), and includes support for modern hardware acceleration such as AES-NI, AVX2/AVX-512, and RDRAND.

### Prerequisites

- **CMake**: 3.15 or newer
- **Windows**: Visual Studio 2022 or newer
- **macOS**: Clang via Xcode or Homebrew
- **Ubuntu**: GCC or Clang  

### Building the QSMP library and the Client/Server projects

#### Windows (MSVC)

Use the Visual Studio solution to create the library and the server and client projects: QSMP, Simplex: Server, and Client, Duplex: Listener and Sender.
Extract the files, and open the Server or Client projects. The QSMP library has a default location in a folder parallel to the Server and Client project folders.  
The server and client projects additional files folder are set to: **$(SolutionDir)QSMP** and **$(SolutionDir)..\QSC\QSC**, if this is not the location of the library files, change it by going to server/client project properties **Configuration Properties->C/C++->General->Additional Include Directories** and set the library files location.  
Ensure that the **[server/client]->References** property contains a reference to the QSMP library, and that the QSMP library contains a valid reference to the QSC library.  
QSC and QSMP support every AVX instruction family (AVX/AVX2/AVX-512).  
Set the QSC and QSMP libries and every server/client project to the same AVX family setting in **Configuration Properties->C/C++->All Options->Enable Enhanced Instruction Set**.  
Set both QSC and QSMP to the same instruction set in Debug and Release Solution Configurations.  
Compile the QSC library (right-click and choose build), build the QSMP library, then build the Server and Client, Listener and Sender projects.

#### MacOS / Ubuntu (Eclipse)

The QSC and the QSMP library projects, along with the server and client projects have been tested using the Eclipse IDE on Ubuntu and MacOS.  
In the Eclipse folder there are subfolders for Ubuntu and MacOS that contain the **.project**, **.cproject**, and **.settings** Eclipse project files.  Copy those files directly into the folders containing the code files; move the files in the **Eclipse\Ubuntu\project-name** or **Eclipse\MacOS\project-name** folder to the folder containing the project's header and implementation files for QSMP and each of the Server and Client projects.  
Create a new project for QSC, select C/C++ project, and then **Create an empty project** with the same name as the folder with the files, 'QSC'. Repeat for each additional project.  
Eclipse should load the project with all of the settings into the project view window. The same proceedure is true for **MacOS and Ubuntu**, but some settings are different (GCC/Clang), so choose the project files that correspond to the operating system.  
The default projects use minimal flags, but are set to use AVX2, AES-NI, and RDRand by default.

Sample flag sets and their meanings:  
-**AVX Support**: -msse2 -mavx -maes -mpclmul -mrdrnd -mbmi2  
-**msse2**        # baseline for x86_64  
-**mavx**         # 256-bit FP/SIMD  
-**maes**         # AES-NI (128-bit AES rounds)  
-**mpclmul**      # PCLMUL (carry-less multiply)  
-**mrdrnd**       # RDRAND (hardware RNG)  
-**mbmi2**        # BMI2 (PEXT/PDEP, bit-manipulation)  

-**AVX2 Support**: -msse2 -mavx -mavx2 -mpclmul -maes -mrdrnd -mbmi2  
-**msse2**        # baseline for x86_64  
-**mavx**         # AVX baseline  
-**mavx2**        # 256-bit integer + FP SIMD  
-**mpclmul**      # PCLMUL (carry-less multiply for AES-GCM, GHASH, etc.)  
-**maes**         # AES-NI (128-bit AES rounds)  
-**mrdrnd**       # RDRAND (hardware RNG)  
-**mbmi2**        # BMI2 (PEXT/PDEP, bit-manipulation)  

-**AVX-512 Support**: -msse2 -mavx -mavx2 -mavx512f -mavx512bw -mvaes -mpclmul -mrdrnd -mbmi2 -maes  
-**msse2**        # baseline for x86_64  
-**mavx**         # AVX baseline  
-**mavx2**        # AVX2 baseline (implied by AVX-512 but explicit is safer)  
-**mavx512f**     # 512-bit Foundation instructions  
-**mavx512bw**    # 512-bit Byte/Word integer instructions  
-**mvaes**        # Vector-AES (VAES) in 512-bit registers  
-**mpclmul**      # PCLMUL (carry-less multiply for GF(2ⁿ))  
-**mrdrnd**       # RDRAND (hardware RNG)  
-**mbmi2**        # BMI2 (PEXT/PDEP, bit-manipulation)  
-**maes**         # AES-NI (128-bit AES rounds; optional if VAES covers your AES use)  


## Keywords

Cryptography, Post-Quantum, Asymmetric Cryptography, Symmetric Cryptography, Digital Signature, Key Encapsulation, Key Exchange, Hash Function, MAC, Pseudo-Random Number Generator, DRBG, Entropy, SIMD, AVX, AVX2, AVX512, Secure Memory, Asynchronous, MISRA, QSMP.

## License

ACQUISITION INQUIRIES:
QRCS is currently seeking a corporate acquirer for this technology.
Parties interested in exclusive licensing or acquisition should contact: contact@qrcscorp.ca

PATENT NOTICE:
One or more patent applications (provisional and/or non-provisional) covering aspects of this software have been filed with the United States Patent and 
Trademark Office (USPTO). Unauthorized use may result in patent infringement liability.  

QRCS-PL private License. See license file for details.  
Software is copyrighted and QSMP is patent pending.
Written by John G. Underhill, under the QRCS-PL license, see the included license file for details. 
Not to be redistributed or used commercially without the author's expressed written permission. 
_All rights reserved by QRCS Corp. 2025._

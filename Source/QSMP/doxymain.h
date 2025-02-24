#ifndef QSMP_DOXYMAIN_H
#define QSMP_DOXYMAIN_H

/**
 * \mainpage Quantum Secure Messaging Protocol (QSMP)
 *
 * \section intro_sec Introduction
 *
 * In today's digital landscape, numerous key exchange protocols are widely used; examples include the mechanisms
 * found in secure networking protocols such as TLS, PGP, and SSH. These protocols define methods for exchanging
 * secret keys between devices, typically as part of a larger scheme that also incorporates authentication and
 * establishes an encrypted tunnel for communication. In such systems, the shared secret is used to key symmetric
 * ciphers for encrypting and decrypting traffic.
 *
 * \section qsmp_sec About QSMP
 *
 * QSMP is a complete specification that not only defines a robust key exchange function but also integrates
 * authentication mechanisms and an encrypted tunnel within a single protocol. Rather than retrofitting existing
 * schemes with quantum-strength primitives, QSMP breaks new ground by introducing an entirely new set of mechanisms
 * designed from the ground up for security and performance in the post-quantum era.
 *
 * \section design_sec Design Philosophy
 *
 * Recognizing that a large-scale migration to post-quantum cryptography is inevitable, QSMP was developed without
 * the constraints of backward compatibility or the unnecessary complexity of legacy protocols. This new design
 * avoids artifacts from older systems, such as outdated APIs, cumbersome versioning, and compatibility issues, and
 * instead focuses on modern, streamlined solutions.
 *
 * \section crypto_sec Cryptographic Primitives
 *
 * QSMP employs state-of-the-art cryptographic algorithms to ensure high levels of security:
 *
 * - **Asymmetric Ciphers:** QSMP supports the Kyber and McEliece asymmetric ciphers with the full range of parameter sets.
 * - **Signature Schemes:** QSMP can use Dilithium or Sphincs+ signature schemes, which were both standardized by NIST.
 * - **Symmetric Cipher:** For symmetric encryption, QSMP uses the authenticated symmetric stream cipher RCS,
 *   which is based on the wide-block Rijndael cipher. This cipher is enhanced with increased rounds, a strong key-schedule,
 *   and AEAD authentication using KMAC or QMAC message authentication functions.
 *
 * \section protocol_spec Protocol Specifications
 *
 * QSMP defines two complete protocol specifications that cater to different trust and performance requirements:
 *
 * - **SIMPLEX Protocol:** This protocol defines a streamlined, one-way authenticated key exchange.
 *   In SIMPLEX, the client trusts the server. As part of the exchange, the server signs its public asymmetric key,
 *   and the client verifies the signature using the server's public signature-verification key. This protocol establishes
 *   a 256-bit secure two-way encrypted network stream between the server and client in just two round trips, making it
 *   ideal for scenarios where an efficient and secure encrypted channel is needed between a server and a client.
 *
 * - **DUPLEX Protocol:** In contrast, the DUPLEX protocol implements a bi-directional trust model.
 *   Both hosts authenticate each other by exchanging signed public asymmetric cipher keys and verifying them using
 *   pre-shared public signature-verification keys. Each host then creates and exchanges a shared secret, and these
 *   secrets are combined to key 512-bit secure symmetric cipher instances. The DUPLEX protocol is best suited for
 *   high-security communications between remote hosts and can be used alongside SIMPLEX to register hosts, distribute
 *   public signature keys, and establish a secure network.
 *
 * QSMP offers a modern, flexible, and secure alternative to traditional key exchange protocols that are now being
 * retrofitted with quantum-safe algorithms. Designed specifically for the post-quantum era, QSMP integrates robust
 * key exchange, authentication, and encryption into a single protocol. It is ideally suited for any environment where
 * strong post-quantum security is a priority.
 *
 * \subsection library_dependencies Cryptographic Dependencies
 * QSTP uses the QSC cryptographic library: <a href="https://github.com/QRCS-CORP/QSC">The QSC Library</a>
 * \section conclusion_sec Conclusion
 *
 * QRCS-PL private License. See license file for details.
 * All rights reserved by QRCS Corporation, copyrighted and patents pending.
 * 
 * \author John G. Underhill
 * \date 2025-02-10
 */

#endif

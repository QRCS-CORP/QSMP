/* 2021-2026 Quantum Resistant Cryptographic Solutions Corporation
 * All Rights Reserved.
 *
 * NOTICE:
 * This software and all accompanying materials are the exclusive property of
 * Quantum Resistant Cryptographic Solutions Corporation (QRCS). The intellectual
 * and technical concepts contained herein are proprietary to QRCS and are
 * protected under applicable Canadian, U.S., and international copyright,
 * patent, and trade secret laws.
 *
 * CRYPTOGRAPHIC ALGORITHMS AND IMPLEMENTATIONS:
 * - This software includes implementations of cryptographic primitives and
 *   algorithms that are standardized or in the public domain, such as AES
 *   and SHA-3, which are not proprietary to QRCS.
 * - This software also includes cryptographic primitives, constructions, and
 *   algorithms designed by QRCS, including but not limited to RCS, SCB, CSX, QMAC, and
 *   related components, which are proprietary to QRCS.
 * - All source code, implementations, protocol compositions, optimizations,
 *   parameter selections, and engineering work contained in this software are
 *   original works of QRCS and are protected under this license.
 *
 * LICENSE AND USE RESTRICTIONS:
 * - This software is licensed under the Quantum Resistant Cryptographic Solutions
 *   Public Research and Evaluation License (QRCS-PREL), 2025-2026.
 * - Permission is granted solely for non-commercial evaluation, academic research,
 *   cryptographic analysis, interoperability testing, and feasibility assessment.
 * - Commercial use, production deployment, commercial redistribution, or
 *   integration into products or services is strictly prohibited without a
 *   separate written license agreement executed with QRCS.
 * - Licensing and authorized distribution are solely at the discretion of QRCS.
 *
 * EXPERIMENTAL CRYPTOGRAPHY NOTICE:
 * Portions of this software may include experimental, novel, or evolving
 * cryptographic designs. Use of this software is entirely at the user's risk.
 *
 * DISCLAIMER:
 * THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE, SECURITY, OR NON-INFRINGEMENT. QRCS DISCLAIMS ALL
 * LIABILITY FOR ANY DIRECT, INDIRECT, INCIDENTAL, OR CONSEQUENTIAL DAMAGES
 * ARISING FROM THE USE OR MISUSE OF THIS SOFTWARE.
 *
 * FULL LICENSE:
 * This software is subject to the Quantum Resistant Cryptographic Solutions
 * Public Research and Evaluation License (QRCS-PREL), 2025-2026. The complete license terms
 * are provided in the accompanying LICENSE file or at https://www.qrcscorp.ca.
 *
 * Written by: John G. Underhill
 * Contact: contact@qrcscorp.ca
 */

#ifndef QSMS_CLIENT_H
#define QSMS_CLIENT_H

#include "qsms.h"
#include "rcs.h"
#include "socketclient.h"

/**
 * \file client.h
 * \brief QSMS Client Functions
 *
 * \details
 * This header file defines the client-side functions for the Quantum Secure Messaging Protocol (QSMS).
 * QSMS is a post-quantum secure messaging protocol that supports both Duplex and Simplex key exchange
 * mechanisms over IPv4 and IPv6 networks. These functions enable QSMS clients to initiate secure connections,
 * perform key exchanges, and manage cryptographic ratchet operations during an active session.
 *
 * The QSMS client functionality provided in this header includes:
 *
 * - **Key Ratchet Requests:**
 *   - **Asymmetric Key Ratchet Request:** (conditionally available when QSMS_ASYMMETRIC_RATCHET is defined)
 *     Initiates an asymmetric key ratchet to update session keys using asymmetric cryptographic operations,
 *     thereby enhancing forward secrecy.
 *   - **Symmetric Key Ratchet Request:** Initiates a symmetric key ratchet that updates the session keys
 *     using symmetric operations.
 *
 * - **Duplex Key Exchange Connections:**
 *   - Establishes secure, bi-directional (mutually authenticated) communication channels using the Duplex protocol.
 *   - Supports connection establishment over both IPv4 and IPv6.
 *
 * - **Simplex Key Exchange Connections:**
 *   - Establishes unidirectional secure connections (where the client typically verifies the server's identity)
 *     using the Simplex protocol.
 *   - Supports connection establishment over both IPv4 and IPv6.
 *
 * - **Listener Functions:**
 *   - Functions that start a network listener (acting as a server) to accept incoming connections and perform
 *     either the Simplex or Duplex key exchange protocols. In Duplex mode, an additional key query callback is
 *     provided to identify the correct public key based on a given identifier.
 *
 * All connection functions accept callback functions for sending and receiving data over the QSMS connection,
 * and they return a value of type `qsms_errors` to indicate the success or failure of the operation.
 *
 * \note This header file does not include any internal test functions.
 */

 /**
  * \brief Send a symmetric key-ratchet request to the remote host.
  *
  * \details
  * This function initiates a symmetric key ratchet process in an ongoing QSMS session. By periodically
  * updating the symmetric session keys, it maintains forward secrecy and ensures that any compromise
  * of past keys does not affect the security of future communications.
  *
  * \param cns A pointer to the current QSMS connection state structure.
  *
  * \return Returns true if the symmetric ratchet request was successfully sent, otherwise false.
  */
QSMS_EXPORT_API bool qsms_simplex_send_symmetric_ratchet_request(qsms_connection_state* cns);

/**
 * \brief Connect to a remote server over IPv4 and perform the Simplex key exchange.
 *
 * \details
 * This function establishes a connection to a remote server using its IPv4 address and initiates the Simplex
 * key exchange protocol. In the Simplex protocol, the client typically verifies the server's authenticity
 * using its own public signature verification key. The function sets up the connection and employs the specified
 * callback functions for sending and receiving messages.
 *
 * \param pubk [const] A pointer to the client's public signature verification key.
 * \param address [const] A pointer to the IPv4 address information structure of the server.
 * \param port The QSMS application port number (typically defined by QSMS_SERVER_PORT).
 * \param send_func A pointer to the send callback function that manages the message transmission loop.
 * \param receive_callback A pointer to the receive callback function that processes incoming data from the server.
 *
 * \return Returns a value of type \c qsms_errors representing the outcome of the connection and key exchange process.
 */
QSMS_EXPORT_API qsms_errors qsms_client_simplex_connect_ipv4(const qsms_client_verification_key* pubk, 
	const qsc_ipinfo_ipv4_address* address, uint16_t port, 
	void (*send_func)(qsms_connection_state*), 
	void (*receive_callback)(qsms_connection_state*, const uint8_t*, size_t));

/**
 * \brief Connect to a remote server over IPv6 and perform the Simplex key exchange.
 *
 * \details
 * This function establishes a connection to a remote server using its IPv6 address and initiates the Simplex
 * key exchange protocol. It leverages the client's public signature verification key to verify the server's identity.
 * Callback functions are provided to handle the data flow over the established connection.
 *
 * \param pubk [const] A pointer to the client's public signature verification key.
 * \param address [const] A pointer to the IPv6 address information structure of the server.
 * \param port The QSMS application port number (typically defined by QSMS_SERVER_PORT).
 * \param send_func A pointer to the send callback function responsible for handling outgoing messages.
 * \param receive_callback A pointer to the receive callback function that processes incoming server data.
 *
 * \return Returns a value of type \c qsms_errors indicating the status of the connection and key exchange.
 */
QSMS_EXPORT_API qsms_errors qsms_client_simplex_connect_ipv6(const qsms_client_verification_key* pubk, 
	const qsc_ipinfo_ipv6_address* address, uint16_t port, 
	void (*send_func)(qsms_connection_state*), 
	void (*receive_callback)(qsms_connection_state*, const uint8_t*, size_t));

/**
 * \brief Start the server in Simplex mode over IPv4 and listen for client connections.
 *
 * \details
 * This function initiates a network listener on the IPv4 interface to wait for incoming client connections.
 * Upon a client connection, it executes the Simplex key exchange protocol, establishing a secure channel for
 * subsequent communications. The connected socket and QSMS connection state are delivered to the specified
 * callback functions.
 *
 * \param kset [const] A pointer to the QSMS server signature key used for signing and authenticating messages.
 * \param send_func A pointer to the send callback function that manages the transmission of messages.
 * \param receive_callback A pointer to the receive callback function that processes incoming client data.
 *
 * \return Returns a value of type \c qsms_errors representing the result of initializing the listener and key exchange.
 */
QSMS_EXPORT_API qsms_errors qsms_client_simplex_listen_ipv4(const qsms_server_signature_key* kset, 
	void (*send_func)(qsms_connection_state*), 
	void (*receive_callback)(qsms_connection_state*, const uint8_t*, size_t));

/**
 * \brief Start the server in Simplex mode over IPv6 and listen for client connections.
 *
 * \details
 * This function sets up a network listener on the IPv6 interface to accept incoming client connections.
 * Once a connection is established, the Simplex key exchange protocol is executed to create a secure
 * communication channel. The function utilizes the provided callback functions to handle sending and receiving data.
 *
 * \param kset [const] A pointer to the QSMS server signature key used for message signing and authentication.
 * \param send_func A pointer to the send callback function responsible for outgoing message management.
 * \param receive_callback A pointer to the receive callback function that processes data received from clients.
 *
 * \return Returns a value of type \c qsms_errors indicating the success or failure of the listener setup and key exchange.
 */
QSMS_EXPORT_API qsms_errors qsms_client_simplex_listen_ipv6(const qsms_server_signature_key* kset, 
	void (*send_func)(qsms_connection_state*), 
	void (*receive_callback)(qsms_connection_state*, const uint8_t*, size_t));

#endif

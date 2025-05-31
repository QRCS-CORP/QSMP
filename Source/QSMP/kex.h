/* 2025 Quantum Resistant Cryptographic Solutions Corporation
 * All Rights Reserved.
 *
 * NOTICE: This software and all accompanying materials are the exclusive 
 * property of Quantum Resistant Cryptographic Solutions Corporation (QRCS).
 * The intellectual and technical concepts contained within this implementation 
 * are proprietary to QRCS and its authorized licensors and are protected under 
 * applicable U.S. and international copyright, patent, and trade secret laws.
 *
 * CRYPTOGRAPHIC STANDARDS:
 * - This software includes implementations of cryptographic algorithms such as 
 *   SHA3, AES, and others. These algorithms are public domain or standardized 
 *   by organizations such as NIST and are NOT the property of QRCS.
 * - However, all source code, optimizations, and implementations in this library 
 *   are original works of QRCS and are protected under this license.
 *
 * RESTRICTIONS:
 * - Redistribution, modification, or unauthorized distribution of this software, 
 *   in whole or in part, is strictly prohibited.
 * - This software is provided for non-commercial, educational, and research 
 *   purposes only. Commercial use in any form is expressly forbidden.
 * - Licensing and authorized distribution are solely at the discretion of QRCS.
 * - Any use of this software implies acceptance of these restrictions.
 *
 * DISCLAIMER:
 * This software is provided "as is," without warranty of any kind, express or 
 * implied, including but not limited to warranties of merchantability or fitness 
 * for a particular purpose. QRCS disclaims all liability for any direct, indirect, 
 * incidental, or consequential damages resulting from the use or misuse of this software.
 *
 * FULL LICENSE:
 * This software is subject to the **Quantum Resistant Cryptographic Solutions 
 * Proprietary License (QRCS-PL)**. The complete license terms are included 
 * in the LICENSE.txt file distributed with this software.
 *
 * Written by: John G. Underhill
 * Contact: contact@qrcscorp.ca
 */

#ifndef QSMP_KEX_H
#define QSMP_KEX_H

#include "qsmp.h"

/**
 * \file kex.h
 * \brief QSMP Key Exchange Functions.
 *
 * \details
 * This header file contains the internal key exchange functions for the Quantum Secure Messaging Protocol (QSMP).
 * QSMP supports two key exchange variants:
 * 
 * - **Duplex:** A bidirectional key exchange method that enables mutual authentication and secure session key
 *   establishment. Both parties exchange cryptographic material to derive a shared secret.
 *
 * - **Simplex:** A unidirectional key exchange method where typically the client verifies the server's identity.
 *
 * The file defines internal state structures for both the client and server roles in Duplex and Simplex key exchanges.
 * These structures encapsulate various cryptographic parameters such as key identities, session token hashes,
 * asymmetric keys (for encryption, signing, and verification), shared secrets, and session expiration times.
 *
 * The following internal (non-exportable) functions are declared:
 *
 * - \c qsmp_kex_duplex_server_key_exchange: Executes the server-side Duplex key exchange.
 * - \c qsmp_kex_duplex_client_key_exchange: Executes the client-side Duplex key exchange.
 * - \c qsmp_kex_simplex_server_key_exchange: Executes the server-side Simplex key exchange.
 * - \c qsmp_kex_simplex_client_key_exchange: Executes the client-side Simplex key exchange.
 * - \c qsmp_kex_test: Runs a suite of internal tests to validate the correctness of the key exchange operations.
 *
 * \note These functions and state structures are internal and are not part of the public QSMP API.
 */

/**
 * \struct qsmp_kex_duplex_client_state
 * \brief Internal state for the Duplex key exchange (client-side).
 *
 * \details
 * This structure holds the state information required by a client participating in a Duplex key exchange.
 * It includes:
 * - \c keyid: A unique key identity string (of size \c QSMP_KEYID_SIZE) that identifies the key exchange session.
 * - \c schash: A session token hash (of size \c QSMP_DUPLEX_SCHASH_SIZE) used to verify session integrity.
 * - \c prikey: The client's asymmetric cipher private key (of size \c QSMP_ASYMMETRIC_PRIVATE_KEY_SIZE).
 * - \c pubkey: The client's asymmetric cipher public key (of size \c QSMP_ASYMMETRIC_PUBLIC_KEY_SIZE).
 * - \c rverkey: The remote party's asymmetric signature verification key (of size \c QSMP_ASYMMETRIC_VERIFY_KEY_SIZE).
 * - \c sigkey: The client's asymmetric signature signing key (of size \c QSMP_ASYMMETRIC_SIGNING_KEY_SIZE).
 * - \c ssec: The derived asymmetric shared secret (of size \c QSMP_SECRET_SIZE) computed during key exchange.
 * - \c verkey: The client's local asymmetric signature verification key (of size \c QSMP_ASYMMETRIC_VERIFY_KEY_SIZE).
 * - \c expiration: A timestamp (in seconds from the epoch) indicating when the key exchange session expires.
 */
typedef struct qsmp_kex_duplex_client_state
{
	uint8_t keyid[QSMP_KEYID_SIZE];							/*!< The key identity string */
	uint8_t schash[QSMP_DUPLEX_SCHASH_SIZE];				/*!< The session token hash */
	uint8_t prikey[QSMP_ASYMMETRIC_PRIVATE_KEY_SIZE];		/*!< The asymmetric cipher private key */
	uint8_t pubkey[QSMP_ASYMMETRIC_PUBLIC_KEY_SIZE];		/*!< The asymmetric cipher public key */
	uint8_t rverkey[QSMP_ASYMMETRIC_VERIFY_KEY_SIZE];		/*!< The remote asymmetric signature verification-key */
	uint8_t sigkey[QSMP_ASYMMETRIC_SIGNING_KEY_SIZE];		/*!< The asymmetric signature signing-key */
	uint8_t ssec[QSMP_SECRET_SIZE];							/*!< The asymmetric shared secret */
	uint8_t verkey[QSMP_ASYMMETRIC_VERIFY_KEY_SIZE];		/*!< The local asymmetric signature verification-key */
	uint64_t expiration;									/*!< The expiration time, in seconds from epoch */
} qsmp_kex_duplex_client_state;

/**
 * \struct qsmp_kex_duplex_server_state
 * \brief Internal state for the Duplex key exchange (server-side).
 *
 * \details
 * This structure holds the state information required by a server participating in a Duplex key exchange.
 * It contains cryptographic parameters including key identities, session hashes, asymmetric keys, and an expiration
 * timestamp. In addition, it includes a callback function (\c key_query) that is used to retrieve the appropriate
 * public key during the key exchange process.
 */
typedef struct qsmp_kex_duplex_server_state
{
	uint8_t keyid[QSMP_KEYID_SIZE];							/*!< The key identity string */
	uint8_t schash[QSMP_DUPLEX_SCHASH_SIZE];				/*!< The session token hash */
	uint8_t prikey[QSMP_ASYMMETRIC_PRIVATE_KEY_SIZE];		/*!< The asymmetric cipher private key */
	uint8_t pubkey[QSMP_ASYMMETRIC_PUBLIC_KEY_SIZE];		/*!< The asymmetric cipher public key */
	uint8_t rverkey[QSMP_ASYMMETRIC_VERIFY_KEY_SIZE];		/*!< The remote asymmetric signature verification-key */
	uint8_t sigkey[QSMP_ASYMMETRIC_SIGNING_KEY_SIZE];		/*!< The asymmetric signature signing-key */
	uint8_t verkey[QSMP_ASYMMETRIC_VERIFY_KEY_SIZE];		/*!< The local asymmetric signature verification-key */
	uint64_t expiration;									/*!< The expiration time, in seconds from epoch */
	bool (*key_query)(uint8_t*, const uint8_t*);			/*!< The key query callback */
} qsmp_kex_duplex_server_state;

/**
 * \struct qsmp_kex_simplex_client_state
 * \brief Internal state for the Simplex key exchange (client-side).
 *
 * \details
 * This structure stores the state information for a client involved in a Simplex key exchange.
 * It includes a unique key identity, the remote party's signature verification key, the client's signing key,
 * a session token hash (of size \c QSMP_SIMPLEX_SCHASH_SIZE), and an expiration timestamp.
 */
typedef struct qsmp_kex_simplex_client_state
{
	uint8_t keyid[QSMP_KEYID_SIZE];							/*!< The key identity string */
	uint8_t rverkey[QSMP_ASYMMETRIC_VERIFY_KEY_SIZE];		/*!< The remote asymmetric signature verification-key */
	uint8_t sigkey[QSMP_ASYMMETRIC_SIGNING_KEY_SIZE];		/*!< The asymmetric signature signing-key */
	uint8_t schash[QSMP_SIMPLEX_SCHASH_SIZE];				/*!< The session token hash */
	uint8_t verkey[QSMP_ASYMMETRIC_VERIFY_KEY_SIZE];		/*!< The local asymmetric signature verification-key */
	uint64_t expiration;									/*!< The expiration time, in seconds from epoch */
} qsmp_kex_simplex_client_state;

/**
 * \struct qsmp_kex_simplex_server_state
 * \brief Internal state for the Simplex key exchange (server-side).
 *
 * \details
 * This structure holds the server-side state for a Simplex key exchange operation.
 * It includes the key identity, a session token hash, asymmetric keys for encryption and signing,
 * the local verification key, and an expiration time indicating the validity of the session.
 */
typedef struct qsmp_kex_simplex_server_state
{
	uint8_t keyid[QSMP_KEYID_SIZE];							/*!< The key identity string */
	uint8_t schash[QSMP_SIMPLEX_SCHASH_SIZE];				/*!< The session token hash */
	uint8_t prikey[QSMP_ASYMMETRIC_PRIVATE_KEY_SIZE];		/*!< The asymmetric cipher private key */
	uint8_t pubkey[QSMP_ASYMMETRIC_PUBLIC_KEY_SIZE];		/*!< The asymmetric cipher public key */
	uint8_t sigkey[QSMP_ASYMMETRIC_SIGNING_KEY_SIZE];		/*!< The asymmetric signature signing-key */
	uint8_t verkey[QSMP_ASYMMETRIC_VERIFY_KEY_SIZE];		/*!< The local asymmetric signature verification-key */
	uint64_t expiration;									/*!< The expiration time, in seconds from epoch */
} qsmp_kex_simplex_server_state;

/**
 * \brief Execute the server-side Duplex key exchange.
 *
 * \details
 * This function processes an incoming Duplex key exchange request on the server side.
 * It uses the server key exchange state (\c qsmp_kex_duplex_server_state) to verify client credentials,
 * exchange the necessary asymmetric keys, and update the QSMP connection state accordingly.
 *
 * \param kss A pointer to the duplex server key exchange state structure.
 * \param cns A pointer to the current QSMP connection state.
 *
 * \return Returns a value of type \c qsmp_errors indicating the outcome of the key exchange process.
 *
 * \note This is an internal non-exportable API.
 */
qsmp_errors qsmp_kex_duplex_server_key_exchange(qsmp_kex_duplex_server_state* kss, qsmp_connection_state* cns);

/**
 * \brief Execute the client-side Duplex key exchange.
 *
 * \details
 * This function initiates and completes the Duplex key exchange from the client side.
 * It processes the server's response, computes the shared secret, and updates the QSMP connection state
 * with the derived cryptographic parameters.
 *
 * \param kcs A pointer to the duplex client key exchange state structure.
 * \param cns A pointer to the current QSMP connection state.
 *
 * \return Returns a value of type \c qsmp_errors representing the result of the key exchange operation.
 *
 * \note This is an internal non-exportable API.
 */
qsmp_errors qsmp_kex_duplex_client_key_exchange(qsmp_kex_duplex_client_state* kcs, qsmp_connection_state* cns);

/**
 * \brief Execute the server-side Simplex key exchange.
 *
 * \details
 * This function handles the Simplex key exchange on the server side. It processes the client's connection
 * request, validates the provided cryptographic material, and updates the QSMP connection state with the
 * negotiated session parameters.
 *
 * \param kss A pointer to the simplex server key exchange state structure.
 * \param cns A pointer to the current QSMP connection state.
 *
 * \return Returns a value of type \c qsmp_errors indicating the success or failure of the key exchange.
 *
 * \note This is an internal non-exportable API.
 */
qsmp_errors qsmp_kex_simplex_server_key_exchange(qsmp_kex_simplex_server_state* kss, qsmp_connection_state* cns);

/**
 * \brief Execute the client-side Simplex key exchange.
 *
 * \details
 * This function initiates and completes the Simplex key exchange from the client side.
 * It exchanges the necessary cryptographic keys, verifies the server's identity using the remote verification key,
 * and updates the QSMP connection state with the established session parameters.
 *
 * \param kcs A pointer to the simplex client key exchange state structure.
 * \param cns A pointer to the current QSMP connection state.
 *
 * \return Returns a value of type \c qsmp_errors representing the outcome of the key exchange process.
 *
 * \note This is an internal non-exportable API.
 */
qsmp_errors qsmp_kex_simplex_client_key_exchange(qsmp_kex_simplex_client_state* kcs, qsmp_connection_state* cns);

/**
 * \brief Run internal tests for the key exchange functions.
 *
 * \details
 * This function executes a suite of internal tests designed to validate the correct operation of the QSMP
 * key exchange mechanisms. The tests include:
 *
 * - Verifying the proper initialization and management of state structures for both Duplex and Simplex modes.
 * - Testing the cryptographic operations involved in key generation, shared secret derivation, and session token hashing.
 * - Ensuring that the key exchange functions correctly update the QSMP connection state.
 *
 * The function returns true if all internal tests pass, confirming the reliability and correctness of the key exchange implementation.
 *
 * \return Returns true if the key exchange tests succeed; otherwise, false.
 *
 * \note This is an internal non-exportable API.
 */
bool qsmp_kex_test(void);

#endif

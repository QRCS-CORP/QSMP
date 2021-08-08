/* 2021 Digital Freedom Defense Incorporated
 * All Rights Reserved.
 *
 * NOTICE:  All information contained herein is, and remains
 * the property of Digital Freedom Defense Incorporated.
 * The intellectual and technical concepts contained
 * herein are proprietary to Digital Freedom Defense Incorporated
 * and its suppliers and may be covered by U.S. and Foreign Patents,
 * patents in process, and are protected by trade secret or copyright law.
 * Dissemination of this information or reproduction of this material
 * is strictly forbidden unless prior written permission is obtained
 * from Digital Freedom Defense Incorporated.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */

/**
* \file qserver.h
* \brief <b>QSMP Server functions</b> \n
* Functions used to implement the server in the Quantum Secure Messaging Protocol (QSMP).
*
* \author		John G. Underhill
* \version		1.0.0.0a
* \date			February 1, 2021
* \updated		May 26, 2021
* \contact:		develop@vtdev.com
*/

#ifndef QSMP_SERVER_H
#define QSMP_SERVER_H

#include "qsmp.h"
#include "../QSC/rcs.h"
#include "../QSC/socketserver.h"

/*!
* \struct qsmp_server_key
* \brief The QSMP server key structure
*/
typedef struct qsmp_server_key
{
	uint64_t expiration;					/*!< The expiration time, in seconds from epoch */
	uint8_t config[QSMP_CONFIG_SIZE];		/*!< The primitive configuration string */
	uint8_t keyid[QSMP_KEYID_SIZE];			/*!< The key identity string */
	uint8_t sigkey[QSMP_SIGNKEY_SIZE];		/*!< The asymmetric signature signing-key */
	uint8_t verkey[QSMP_VERIFYKEY_SIZE];	/*!< The asymmetric signature verification-key */
} qsmp_server_key;

/*!
* \struct qsmp_kex_server_state
* \brief The QSMP server state structure
*/
typedef struct qsmp_kex_server_state
{
	qsc_rcs_state rxcpr;					/*!< The receive channel cipher state */
	qsc_rcs_state txcpr;					/*!< The transmit channel cipher state */
	uint8_t config[QSMP_CONFIG_SIZE];		/*!< The primitive configuration string */
	uint8_t keyid[QSMP_KEYID_SIZE];			/*!< The key identity string */
	uint8_t pkhash[QSMP_PKCODE_SIZE];		/*!< The session token hash */
	uint8_t prikey[QSMP_PRIVATEKEY_SIZE];	/*!< The asymmetric cipher private key */
	uint8_t pubkey[QSMP_PUBLICKEY_SIZE];	/*!< The asymmetric cipher public key */
	uint8_t sigkey[QSMP_SIGNKEY_SIZE];		/*!< The asymmetric signature signing-key */
	uint8_t token[QSMP_STOKEN_SIZE];		/*!< The session token */
	uint8_t verkey[QSMP_VERIFYKEY_SIZE];	/*!< The asymmetric signature verification-key */
	qsmp_flags exflag;						/*!< The KEX position flag */
	uint64_t expiration;					/*!< The expiration time, in seconds from epoch */
	uint64_t rxseq;							/*!< The receive channels packet sequence number  */
	uint64_t txseq;							/*!< The transmit channels packet sequence number  */
} qsmp_kex_server_state;

/* Helper Functions */

/**
* \brief Decode a secret signature key structure and copy to a string
*
* \param serverkey: A pointer to the output server key structure
* \param input: The input encoded secret key string
*/
void qsmp_server_deserialize_signature_key(qsmp_server_key* serverkey, const uint8_t input[QSMP_SIGKEY_ENCODED_SIZE]);

/**
* \brief Encode a public key structure and copy to a string
*
* \param ctx: A pointer to the server state structure
* \param output: The output encoded public key string
* \param serverkey: A pointer to the server key structure
*/
void qsmp_server_encode_public_key(char output[QSMP_PUBKEY_STRING_SIZE], const qsmp_server_key* serverkey);

/**
* \brief Send an error code to the remote host
*
* \param sock: A pointer to the initialized socket structure
* \param error: The error code
*/
void qsmp_server_send_error(const qsc_socket* sock, qsmp_errors error);

/**
* \brief Send a keep-alive to the remote host
*
* \param kctx: The keep-alive state
* \param sock: A pointer to the initialized socket structure
*
* \return: The function error state
*/
qsmp_errors qsmp_server_send_keep_alive(qsmp_keep_alive_state* kctx, const qsc_socket* sock);

/**
* \brief Encode a secret key structure and copy to a string
*
* \param output: The output encoded public key string
* \param serverkey: A pointer to the secret server key structure
*/
void qsmp_server_serialize_signature_key(uint8_t output[QSMP_SIGKEY_ENCODED_SIZE], const qsmp_server_key* serverkey);

/* Primary Functions */

/**
* \brief Close the remote session and dispose of resources
*
* \param sock: A pointer to the initialized socket structure
* \param error: The error code
*/
void qsmp_server_connection_close(qsmp_kex_server_state* ctx, const qsc_socket* sock, qsmp_errors error);

/**
* \brief Initialize a server state structure
*
* \param ctx: A pointer to the server state structure
* \param ckey: [const] A pointer to a server key structure
*/
void qsmp_server_initialize(qsmp_kex_server_state* ctx, const qsmp_server_key* skey);

/**
* \brief Run the IPv4 networked key exchange function.
* Returns the connected socket and the QSMP server state.
*
* \param ctx: A pointer to the qsmp server state structure
* \param sock: A pointer to the socket structure
* \param skey: A pointer to the server private-key structure
* \param address: The servers IPv4 address
* \param port: The servers port number
*
* \return: The function error state
*/
qsmp_errors qsmp_server_listen_ipv4(qsmp_kex_server_state* ctx, qsc_socket* sock, const qsc_ipinfo_ipv4_address* address, uint16_t port);

/**
* \brief Run the IPv6 networked key exchange function.
* Returns the connected socket and the QSMP server state.
*
* \param ctx: A pointer to the qsmp server state structure
* \param sock: A pointer to the socket structure
* \param skey: A pointer to the server private-key structure
* \param address: The servers IPv6 address
* \param port: The servers port number
*
* \return: The function error state
*/
qsmp_errors qsmp_server_listen_ipv6(qsmp_kex_server_state* ctx, qsc_socket* sock, const qsc_ipinfo_ipv6_address* address, uint16_t port);

/**
* \brief Decrypt a message and copy it to the message output
*
* \param ctx: A pointer to the server state structure
* \param packetin: [const] A pointer to the input packet structure
* \param message: The message output array
* \param msglen: A pointer receiving the message length
*
* \return: The function error state
*/
qsmp_errors qsmp_server_decrypt_packet(qsmp_kex_server_state* ctx, const qsmp_packet* packetin, uint8_t* message, size_t* msglen);

/**
* \brief Encrypt a message and build an output packet
*
* \param ctx: A pointer to the server state structure
* \param message: [const] The input message array
* \param msglen: The length of the message array
* \param packetout: A pointer to the output packet structure
*
* \return: The function error state
*/
qsmp_errors qsmp_server_encrypt_packet(qsmp_kex_server_state* ctx, const uint8_t* message, size_t msglen, qsmp_packet* packetout);

/**
* \brief Generate a QSMP key-pair.
* Generates the public and private keys.
*
* \param pubkey: The public key, distributed to clients
* \param prikey: The private key, a secret key known only by the server
* \param keyid: The key identity string
*/
void qsmp_server_generate_keypair(qsmp_client_key* pubkey, qsmp_server_key* prikey, const uint8_t keyid[QSMP_KEYID_SIZE]);

#endif
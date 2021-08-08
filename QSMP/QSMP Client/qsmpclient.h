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
* \file qsmp.h
* \brief <b>QSMP Client functions</b> \n
* Functions used to implement the client in the Quantum Secure Messaging Protocol (QSMP).
*
* \author		John G. Underhill
* \version		1.0.0.0a
* \date			February 1, 2021
* \updated		May 26, 2021
* \contact:		develop@vtdev.com
*/

#ifndef QSMP_CLIENT_H
#define QSMP_CLIENT_H

#include "qsmp.h"
#include "../QSC/rcs.h"
#include "../QSC/socketclient.h"

/*!
* \struct qsmp_client_key
* \brief The QSMP client state structure
*/
typedef struct qsmp_kex_client_state
{
	qsc_rcs_state rxcpr;						/*!< The receive channel cipher state */
	qsc_rcs_state txcpr;						/*!< The transmit channel cipher state */
	uint8_t config[QSMP_CONFIG_SIZE];			/*!< The primitive configuration string */
	uint8_t keyid[QSMP_KEYID_SIZE];				/*!< The key identity string */
	uint8_t mackey[QSMP_MACKEY_SIZE];			/*!< The intermediate mac key */
	uint8_t pkhash[QSMP_PKCODE_SIZE];			/*!< The session token hash */
	uint8_t prikey[QSMP_PRIVATEKEY_SIZE];		/*!< The asymmetric cipher private key */
	uint8_t pubkey[QSMP_PUBLICKEY_SIZE];		/*!< The asymmetric cipher public key */
	uint8_t token[QSMP_STOKEN_SIZE];			/*!< The session token */
	uint8_t verkey[QSMP_VERIFYKEY_SIZE];		/*!< The asymmetric signature verification-key */
	qsmp_flags exflag;							/*!< The KEX position flag */
	uint64_t expiration;						/*!< The expiration time, in seconds from epoch */
	uint64_t rxseq;								/*!< The receive channels packet sequence number  */
	uint64_t txseq;								/*!< The transmit channels packet sequence number  */
} qsmp_kex_client_state;


/* Helper Functions */

/**
* \brief Decode a public key string and populate a client key structure
*
* \param clientkey: A pointer to the output client key
* \param input: [const] The input encoded key
*
* \return: Returns true for success
*/
bool qsmp_client_decode_public_key(qsmp_client_key* clientkey, const char input[QSMP_PUBKEY_STRING_SIZE]);

/**
* \brief Send an error code to the remote host
*
* \param sock: A pointer to the initialized socket structure
* \param error: The error code
*/
void qsmp_client_send_error(const qsc_socket* sock, qsmp_errors error);

/* Public Functions */

/**
* \brief Run the IPv4 networked key exchange function.
* Returns the connected socket and the QSMP server state.
*
* \param ctx: A pointer to the qsmp client state structure
* \param sock: A pointer to the socket structure
* \param ckey: A pointer to the client public-key structure
* \param address: The servers IPv4 address
* \param port: The servers port number
*
* \return: The function error state
*/
qsmp_errors qsmp_client_connect_ipv4(qsmp_kex_client_state* ctx, qsc_socket* sock, const qsmp_client_key* ckey, const qsc_ipinfo_ipv4_address* address, uint16_t port);

/**
* \brief Run the IPv6 networked key exchange function.
* Returns the connected socket and the QSMP server state.
*
* \param ctx: A pointer to the qsmp client state structure
* \param sock: A pointer to the socket structure
* \param ckey: A pointer to the client public-key structure
* \param address: The servers IPv6 address structure
* \param port: The servers port number
*
* \return: The function error state
*/
qsmp_errors qsmp_client_connect_ipv6(qsmp_kex_client_state* ctx, qsc_socket* sock, const qsmp_client_key* ckey, const qsc_ipinfo_ipv6_address* address, uint16_t port);

/**
* \brief Close the remote session and dispose of resources
*
* \param sock: A pointer to the initialized socket structure
* \param error: The error code
*/
void qsmp_client_connection_close(qsmp_kex_client_state* ctx, const qsc_socket* sock, qsmp_errors error);

/**
* \brief Decrypt a message and copy it to the message output
*
* \param ctx: A pointer to the client state structure
* \param packetin: [const] A pointer to the input packet structure
* \param message: The message output array
* \param msglen: A pointer receiving the message length
*
* \return: The function error state
*/
qsmp_errors qsmp_client_decrypt_packet(qsmp_kex_client_state* ctx, const qsmp_packet* packetin, uint8_t* message, size_t* msglen);

/**
* \brief Encrypt a message and build an output packet
*
* \param ctx: A pointer to the client state structure
* \param message: [const] The input message array
* \param msglen: The length of the message array
* \param packetout: A pointer to the output packet structure
*
* \return: The function error state
*/
qsmp_errors qsmp_client_encrypt_packet(qsmp_kex_client_state* ctx, const uint8_t* message, size_t msglen, qsmp_packet* packetout);

#endif
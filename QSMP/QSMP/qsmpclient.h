
/* 2024 Quantum Resistant Cryptographic Solutions Corporation
 * All Rights Reserved.
 *
 * NOTICE:  All information contained herein is, and remains
 * the property of Quantum Resistant Cryptographic Solutions Incorporated.
 * The intellectual and technical concepts contained
 * herein are proprietary to Quantum Resistant Cryptographic Solutions Incorporated
 * and its suppliers and may be covered by U.S. and Foreign Patents,
 * patents in process, and are protected by trade secret or copyright law.
 * Dissemination of this information or reproduction of this material
 * is strictly forbidden unless prior written permission is obtained
 * from Quantum Resistant Cryptographic Solutions Incorporated.
 *
 * Written by John G. Underhill
 * Contact: develop@qrcs.ca
 */

#ifndef QSMP_CLIENT_H
#define QSMP_CLIENT_H

#include "qsmp.h"
#include "../../QSC/QSC/rcs.h"
#include "../../QSC/QSC/socketclient.h"

/**
* \file qsmp.h
* \brief <b>QSMP Client functions</b> \n
* Functions used to implement the client in the Quantum Secure Messaging Protocol (QSMP).
*
* \author   John G. Underhill
* \version  1.2a: 2022-05-01
* \date     May 1, 2022
* \contact: develop@qscs.ca
*/

#if defined(QSMP_ASYMMETRIC_RATCHET)
/**
* \brief Send an asymmetric key-ratchet request to the remote host
*
* \param cns: A pointer to the connection state
*
* \return: Returns true if the operation succeeded
*/
QSMP_EXPORT_API bool qsmp_duplex_send_asymmetric_ratchet_request(qsmp_connection_state* cns);
#endif

/**
* \brief Send a symmetric key-ratchet request to the remote host
*
* \param cns: A pointer to the connection state
*
* \return: Returns true if the operation succeeded
*/
QSMP_EXPORT_API bool qsmp_duplex_send_symmetric_ratchet_request(qsmp_connection_state* cns);

/**
* \brief Connect to the remote host using IPv4, and run the Duplex key exchange function.
* Returns the connected socket and the QSMP client state through the callback functions.
*
* \param kset: [const] A pointer to the client's private signature key
* \param rverkey: [const] A pointer to the remote clients public signature verification key
* \param address: [const] The servers IPv4 network address
* \param port: The QSMP application port number (QSMP_CLIENT_PORT)
* \param send_func: A pointer to the send callback function, that contains a message send loop
* \param receive_callback: A pointer to the receive callback function, used to process the client data stream
*
* \return: Returns the function error state
*/
QSMP_EXPORT_API qsmp_errors qsmp_client_duplex_connect_ipv4(const qsmp_server_signature_key* kset, const qsmp_client_signature_key* rverkey, 
	const qsc_ipinfo_ipv4_address* address, uint16_t port, 
	void (*send_func)(qsmp_connection_state*), 
	void (*receive_callback)(qsmp_connection_state*, const char*, size_t));

/**
* \brief Connect to the remote host using IPv6, and run the Duplex key exchange function.
* Returns the connected socket and the QSMP client state through the callback functions.
*
* \param kset: [const] A pointer to the client's private signature key
* \param rverkey: [const] A pointer to the remote clients public signature verification key
* \param address: [const] The servers IPv6 network address
* \param port: The QSMP application port number (QSMP_CLIENT_PORT)
* \param send_func: A pointer to the send callback function, that contains a message send loop
* \param receive_callback: A pointer to the receive callback function, used to process the client data stream
*
* \return: Returns the function error state
*/
QSMP_EXPORT_API qsmp_errors qsmp_client_duplex_connect_ipv6(const qsmp_server_signature_key* kset, const qsmp_client_signature_key* rverkey,
	const qsc_ipinfo_ipv6_address* address, uint16_t port,
	void (*send_func)(qsmp_connection_state*),
	void (*receive_callback)(qsmp_connection_state*, const char*, size_t));

/**
* \brief Connect to the remote server using IPv4, and run the Simplex key exchange function.
* Returns the connected socket and the QSMP client state through the callback functions.
*
* \param pubk: [const] A pointer to the client's public signature verification key
* \param address: [const] The servers IPv4 network address
* \param port: The QSMP application port number (QSMP_SERVER_PORT)
* \param send_func: A pointer to the send callback function, that contains a message send loop
* \param receive_callback: A pointer to the receive callback function, used to process the server data stream
*
* \return: Returns the function error state
*/
QSMP_EXPORT_API qsmp_errors qsmp_client_simplex_connect_ipv4(const qsmp_client_signature_key* pubk, 
	const qsc_ipinfo_ipv4_address* address, uint16_t port, 
	void (*send_func)(qsmp_connection_state*), 
	void (*receive_callback)(qsmp_connection_state*, const char*, size_t));

/**
* \brief Connect to the remote server using IPv6, and run the networked simplex key exchange function.
* Returns the connected socket and the QSMP client state through the callback functions.
*
* \param pubk: [const] A pointer to the client's public signature verification key
* \param address: [const] The servers network IPv6 address
* \param port: The QSMP application port number (QSMP_SERVER_PORT)
* \param send_func: A pointer to the send callback function, that contains a message send loop
* \param receive_callback: A pointer to the receive callback function, used to process the server data stream
*
* \return: Returns the function error state
*/
QSMP_EXPORT_API qsmp_errors qsmp_client_simplex_connect_ipv6(const qsmp_client_signature_key* pubk, 
	const qsc_ipinfo_ipv6_address* address, uint16_t port, 
	void (*send_func)(qsmp_connection_state*), 
	void (*receive_callback)(qsmp_connection_state*, const char*, size_t));

/**
* \brief Start the server and run the IPv4 network listener function, 
* which executes the Simplex key exchange each time a client connects.
* Returns the connected socket in the connected state through the callback functions.
*
* \param kset: [const] A pointer to the qsmp server key
* \param send_func: A pointer to the send callback function, that contains a message send loop
* \param receive_callback: A pointer to the receive callback function, used to process the server data stream
*
* \return: Returns the function error state
*/
QSMP_EXPORT_API qsmp_errors qsmp_client_simplex_listen_ipv4(const qsmp_server_signature_key* kset, 
	void (*send_func)(qsmp_connection_state*), 
	void (*receive_callback)(qsmp_connection_state*, const char*, size_t));

/**
* \brief Start the server, and run the IPv6 network listener function,
* which executes the Simplex key exchange each time a client connects.
* Returns the connected socket in the connection state through the callback functions.
*
* \param kset: [const] A pointer to the qsmp server key
* \param send_func: A pointer to the send callback function, that contains a message send loop
* \param receive_callback: A pointer to the receive callback function, used to process the server data stream
*
* \return: Returns the function error state
*/
QSMP_EXPORT_API qsmp_errors qsmp_client_simplex_listen_ipv6(const qsmp_server_signature_key* kset, 
	void (*send_func)(qsmp_connection_state*), 
	void (*receive_callback)(qsmp_connection_state*, const char*, size_t));

/**
* \brief Start the server, and run the IPv4 network listener function,
* which executes the Duplex key exchange when the remote host connects.
* Places the local socket in the listening state for a single host-to-host connection operation.
*
* \param kset: [const] A pointer to the qsmp server key
* \param send_func: A pointer to the send callback function, that contains a message send loop
* \param receive_callback: A pointer to the receive callback function, used to process the client data stream
* \param key_query: A pointer the key-query function, used to identify and return the correct public key
*
* \return: Returns the function error state
*/
QSMP_EXPORT_API qsmp_errors qsmp_client_duplex_listen_ipv4(const qsmp_server_signature_key* kset, 
	void (*send_func)(qsmp_connection_state*),
	void (*receive_callback)(qsmp_connection_state*, const char*, size_t),
	bool (*key_query)(uint8_t* rvkey, const uint8_t* pkid));

/**
* \brief Start the server, and run the IPv6 network listener function,
* which executes the Duplex key exchange when the remote host connects.
* Places the local socket in the listening state for a single host-to-host connection operation.
*
* \param kset: [const] A pointer to the qsmp server key
* \param send_func: A pointer to the send callback function, that contains a message send loop
* \param receive_callback: A pointer to the receive callback function, used to process the client data stream
* \param key_query: A pointer the key-query function, used to identify and return the correct public key
*
* \return: Returns the function error state
*/
QSMP_EXPORT_API qsmp_errors qsmp_client_duplex_listen_ipv6(const qsmp_server_signature_key* kset, 
	void (*send_func)(qsmp_connection_state*),
	void (*receive_callback)(qsmp_connection_state*, const char*, size_t),
	bool (*key_query)(uint8_t* rvkey, const uint8_t* pkid));

#endif
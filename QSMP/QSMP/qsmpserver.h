/* 2022 Digital Freedom Defense Incorporated
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
* \author   John G. Underhill
* \version  1.2a: 2022-05-01
* \date     May 1, 2022
* \contact: develop@dfdef.com
*/

#ifndef QSMP_SERVER_H
#define QSMP_SERVER_H

#include "qsmp.h"
#include "../QSC/rcs.h"
#include "../QSC/socketserver.h"

/*!
* \def QSMP_SERVER_PAUSE_INTERVAL
* \brief The pause interval used by the server pause function 
*/
#define QSMP_SERVER_PAUSE_INTERVAL 100

/**
* \brief Broadcast a message to all connected hosts
*
* \param message: [const] The message to broadcast
* \param msglen: The length of the message
*/
QSMP_EXPORT_API void qsmp_server_broadcast(const uint8_t* message, size_t msglen);

/**
* \brief Pause the server, suspending new joins
*/
QSMP_EXPORT_API void qsmp_server_pause(void);

/**
* \brief Quit the server, closing all connections
*/
QSMP_EXPORT_API void qsmp_server_quit(void);

/**
* \brief Resume the server listener function from a paused state
*/
QSMP_EXPORT_API void qsmp_server_resume(void);

/**
* \brief Start the IPv4 multi-threaded server
*
* \param prik: [const] A pointer to the QSMP private key
* \param receive_callback: A pointer to the receive callback function, used to process client data streams
*
* \return: Returns the function error state
*/
QSMP_EXPORT_API qsmp_errors qsmp_server_start_ipv4(const qsmp_server_key* prik, 
	void (*receive_callback)(qsmp_connection_state*, const char*, size_t));

/**
* \brief Start the IPv6 multi-threaded server.
*
* \param prik: [const] A pointer to the QSMP private key
* \param receive_callback: A pointer to the receive callback function, used to process client data streams
*
* \return: Returns the function error state
*/
QSMP_EXPORT_API qsmp_errors qsmp_server_start_ipv6(const qsmp_server_key* prik, 
	void (*receive_callback)(qsmp_connection_state*, const char*, size_t));

#endif
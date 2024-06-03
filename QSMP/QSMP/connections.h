
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

#ifndef QSMP_CONNECTIONS_H
#define QSMP_CONNECTIONS_H

#include "common.h"
#include "qsmp.h"

/**
* \file connections.h
* \brief The server connection collection
* \note These are internal non-exportable functions.
* Version 1.2a: 2022-05-01
*/

/**
* \brief Check if a collection member is set to active
*
* \param index: The socket index number
* \return: Returns true if the connection is active
*/
bool qsmp_connections_active(size_t index);

/**
* \brief Add an item to the collection and set it to active
*
* \return: Returns a pointer to the new item or NULL
*/
qsmp_connection_state* qsmp_connections_add(void);

/**
* \brief Get the number of available items in the collection
*
* \return: Returns the number of available items
*/
size_t qsmp_connections_available(void);

/**
* \brief Get a pointer from an instance number
*
* \param instance: The socket instance number
* 
* \return: Returns the connection state pointer
*/
qsmp_connection_state* qsmp_connections_get(uint32_t instance);

/**
* \brief Initialize the connections collection, and creates at least one new item
*
* \param count: The number of initial connection states, a minimum of one
* \param maximum: The maximum number of connection states, must be more equal to count
*/
void qsmp_connections_initialize(size_t count, size_t maximum);

/**
* \brief Erase all the collection members
*/
void qsmp_connections_clear(void);

/**
* \brief Dispose of the connections array state
*/
void qsmp_connections_dispose(void);

/**
* \brief Get a connection state pointer from the index
*
* \param index: The sockets collection index number
* 
* \return: Returns the collection state pointer or NULL
*/
qsmp_connection_state* qsmp_connections_index(size_t index);

/**
* \brief Check if the collection is full
*
* \return: Returns true if the collection is full
*/
bool qsmp_connections_full(void);

/**
* \brief Get the next available connection state
*
* \return: Returns the next available collection state pointer or NULL
*/
qsmp_connection_state* qsmp_connections_next(void);

/**
* \brief Reset a connection from the collection
*
* \param instance: The socket instance number
*/
void qsmp_connections_reset(uint32_t instance);

/**
* \brief Get the size of the collection
*
* \return: Returns the total number of items
*/
size_t qsmp_connections_size(void);

/**
* \brief Run the connections queue self-test
*/
void qsmp_connections_self_test(void);

#endif

/* 2025-2026 Quantum Resistant Cryptographic Solutions Corporation
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

#ifndef QSMS_CONNECTIONS_H
#define QSMS_CONNECTIONS_H

#include "qsmscommon.h"
#include "qsms.h"

/**
 * \file connections.h
 * \brief The server connection collection.
 *
 * \details
 * This header defines a set of internal functions for managing the QSTP connection collection.
 * The connection collection is an array or list of QSTP connection state objects that represent
 * active or available network connections. These functions provide mechanisms to:
 *
 * - Check the active status of a connection at a given index.
 * - Add a new connection state to the collection.
 * - Retrieve connection states by instance number or by index.
 * - Initialize, clear, reset, and dispose of the entire connection collection.
 * - Determine the number of available connection states and the total size of the collection.
 *
 * Additionally, a self-test function is provided to verify the correct operation of the connection
 * collection management routines. The self-test exercises various operations including addition,
 * retrieval, reset, and disposal of connection state items.
 *
 * \note These functions are internal and non-exportable.
 */

/**
 * \brief Check if a connection in the collection is active.
 *
 * \details
 * This function checks whether the connection state at the specified index in the connection collection
 * is currently marked as active.
 *
 * \param index: The index (zero-based) in the connections collection.
 *
 * \return Returns true if the connection at the given index is active; otherwise, returns false.
 */
bool qsms_connections_active(size_t index);

/**
 * \brief Get the number of available (inactive) connection states in the collection.
 *
 * \details
 * This function returns the count of connection state slots in the collection that are currently available
 * for new connections.
 *
 * \return The number of available connection state items.
 */
size_t qsms_connections_available(void);

/**
 * \brief Retrieve a connection state pointer using its instance number.
 *
 * \details
 * This function locates and returns the connection state object corresponding to the provided instance number.
 * The instance number uniquely identifies a connection within the collection.
 *
 * \param instance: The unique instance number associated with a connection.
 *
 * \return Returns a pointer to the QSTP connection state if found; otherwise, returns NULL.
 */
qsms_connection_state* qsms_connections_get(uint32_t instance);

/**
 * \brief Initialize the connections collection.
 *
 * \details
 * This function initializes the connection collection by creating an initial set of connection state objects.
 * The \a count parameter specifies the number of connection states to create initially (must be at least one),
 * and the \a maximum parameter defines the maximum capacity of the collection. The maximum must be greater than
 * or equal to the count.
 *
 * \param count: The maximum number of connection states the collection can hold.
 *
 * \return Returns true if the connection array was allocated successfully, otherwise false
 */
bool qsms_connections_initialize(size_t count);

/**
 * \brief Erase all connection states in the collection.
 *
 * \details
 * This function clears all entries in the connection collection, marking each state as inactive.
 * It does not dispose of the collection itself, but resets its contents so that they may be reused.
 */
void qsms_connections_clear(void);

/**
 * \brief Dispose of the connections collection.
 *
 * \details
 * This function releases all resources allocated for the connections collection and resets its state.
 * It should be called when the collection is no longer needed.
 */
void qsms_connections_dispose(void);

/**
 * \brief Check if the connection collection is full.
 *
 * \details
 * This function checks whether the connection collection has reached its maximum capacity.
 * When the collection is full, no additional connection state objects can be added.
 *
 * \return Returns true if the collection is full; otherwise, false.
 */
bool qsms_connections_full(void);

/**
 * \brief Retrieve a connection state pointer by its collection index.
 *
 * \details
 * This function returns the connection state object located at the specified index in the collection.
 * If the index is out of bounds or invalid, the function returns NULL.
 *
 * \param index: The index of the connection state within the collection.
 *
 * \return Returns a pointer to the QSTP connection state, or NULL if the index is invalid.
 */
qsms_connection_state* qsms_connections_index(size_t index);

/**
 * \brief Get the next available connection state.
 *
 * \details
 * This function searches the connection collection for the next available (inactive) connection state
 * and returns a pointer to it. If all connection states are active, the function returns NULL.
 *
 * \return Returns a pointer to the next available QSTP connection state, or NULL if none are available.
 */
qsms_connection_state* qsms_connections_next(void);

/**
 * \brief Reset a connection state in the collection.
 *
 * \details
 * This function resets the connection state identified by the given instance number. Resetting a connection
 * typically clears its data and marks it as inactive so that the slot can be reused.
 *
 * \param instance: The unique instance number of the connection to reset.
 */
void qsms_connections_reset(uint32_t instance);

/**
 * \brief Get the total number of connection state objects in the collection.
 *
 * \details
 * This function returns the total size of the connection collection, including both active and inactive states.
 *
 * \return Returns the total number of connection state items in the collection.
 */
size_t qsms_connections_size(void);

#endif

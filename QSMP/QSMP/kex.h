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
* \file kex.h
* \brief QSMP key exchange functions.
* The QSMP key exchange variants; Duplex and Simplex.
* \note These are internal non-exportable functions.
* 
* \author   John G. Underhill
* \version  1.2a: 2022-05-01
* \date     May 1, 2022
* \contact: develop@dfdef.com
*/

#ifndef QSMP_KEX_H
#define QSMP_KEX_H

#include "common.h"
#include "../QSMP/qsmp.h"

/*!
* \struct qsmp_kex_duplex_client_state
* \brief The QSMP duplex client state structure
*/
typedef struct qsmp_kex_duplex_client_state
{
	uint8_t keyid[QSMP_KEYID_SIZE];					/*!< The key identity string */
	uint8_t schash[QSMP_DUPLEX_SCHASH_SIZE];		/*!< The session token hash */
	uint8_t prikey[QSMP_PRIVATEKEY_SIZE];			/*!< The asymmetric cipher private key */
	uint8_t pubkey[QSMP_PUBLICKEY_SIZE];			/*!< The asymmetric cipher public key */
	uint8_t rverkey[QSMP_VERIFYKEY_SIZE];			/*!< The remote asymmetric signature verification-key */
	uint8_t sigkey[QSMP_SIGNKEY_SIZE];				/*!< The asymmetric signature signing-key */
	uint8_t ssec[QSMP_SECRET_SIZE];					/*!< The asymmetric shared secret */
	uint8_t verkey[QSMP_VERIFYKEY_SIZE];			/*!< The local asymmetric signature verification-key */
	uint64_t expiration;							/*!< The expiration time, in seconds from epoch */
} qsmp_kex_duplex_client_state;

/*!
* \struct qsmp_kex_duplex_server_state
* \brief The QSMP duplex server state structure
*/
typedef struct qsmp_kex_duplex_server_state
{
	uint8_t keyid[QSMP_KEYID_SIZE];					/*!< The key identity string */
	uint8_t schash[QSMP_DUPLEX_SCHASH_SIZE];		/*!< The session token hash */
	uint8_t prikey[QSMP_PRIVATEKEY_SIZE];			/*!< The asymmetric cipher private key */
	uint8_t pubkey[QSMP_PUBLICKEY_SIZE];			/*!< The asymmetric cipher public key */
	uint8_t rverkey[QSMP_VERIFYKEY_SIZE];			/*!< The remote asymmetric signature verification-key */
	uint8_t sigkey[QSMP_SIGNKEY_SIZE];				/*!< The asymmetric signature signing-key */
	uint8_t verkey[QSMP_VERIFYKEY_SIZE];			/*!< The local asymmetric signature verification-key */
	uint64_t expiration;							/*!< The expiration time, in seconds from epoch */
	bool (*key_query)(uint8_t*, const uint8_t*);	/*!< The key query callback */
} qsmp_kex_duplex_server_state;

/*!
* \struct qsmp_kex_simplex_client_state
* \brief The QSMP simplex client state structure
*/
typedef struct qsmp_kex_simplex_client_state
{
	uint8_t keyid[QSMP_KEYID_SIZE];					/*!< The key identity string */
	uint8_t rverkey[QSMP_VERIFYKEY_SIZE];			/*!< The remote asymmetric signature verification-key */
	uint8_t sigkey[QSMP_SIGNKEY_SIZE];				/*!< The asymmetric signature signing-key */
	uint8_t schash[QSMP_SIMPLEX_SCHASH_SIZE];		/*!< The session token hash */
	uint8_t verkey[QSMP_VERIFYKEY_SIZE];			/*!< The local asymmetric signature verification-key */
	uint64_t expiration;							/*!< The expiration time, in seconds from epoch */
} qsmp_kex_simplex_client_state;

/*!
* \struct qsmp_kex_simplex_server_state
* \brief The QSMP simplex server state structure
*/
typedef struct qsmp_kex_simplex_server_state
{
	uint8_t keyid[QSMP_KEYID_SIZE];					/*!< The key identity string */
	uint8_t schash[QSMP_SIMPLEX_SCHASH_SIZE];		/*!< The session token hash */
	uint8_t prikey[QSMP_PRIVATEKEY_SIZE];			/*!< The asymmetric cipher private key */
	uint8_t pubkey[QSMP_PUBLICKEY_SIZE];			/*!< The asymmetric cipher public key */
	uint8_t sigkey[QSMP_SIGNKEY_SIZE];				/*!< The asymmetric signature signing-key */
	uint8_t verkey[QSMP_VERIFYKEY_SIZE];			/*!< The local asymmetric signature verification-key */
	uint64_t expiration;							/*!< The expiration time, in seconds from epoch */
} qsmp_kex_simplex_server_state;

/**
* \brief Run the network client listener version of the duplex key exchange.
* 
* \note This is an internal non-exportable API.
*
* \param kss: A pointer to server key exchange state
* \param cns: A pointer to the connection state
*
* \return: Returns the function error state
*/
qsmp_errors qsmp_kex_duplex_server_key_exchange(qsmp_kex_duplex_server_state* kss, qsmp_connection_state* cns);

/**
* \brief Run the network client sender version of the duplex key exchange.
*
* \note This is an internal non-exportable API.
*
* \param kcs: A pointer to client key exchange state
* \param cns: A pointer to the connection state
*
* \return: Returns the function error state
*/
qsmp_errors qsmp_kex_duplex_client_key_exchange(qsmp_kex_duplex_client_state* kcs, qsmp_connection_state* cns);

/**
* \brief Run the network server version of the simplex key exchange.
*
* \note This is an internal non-exportable API.
*
* \param kss: A pointer to server key exchange state
* \param cns: A pointer to the connection state
*
* \return: Returns the function error state
*/
qsmp_errors qsmp_kex_simplex_server_key_exchange(qsmp_kex_simplex_server_state* kss, qsmp_connection_state* cns);

/**
* \brief Run the network client version of the simplex key exchange.
*
* \note This is an internal non-exportable API.
*
* \param kcs: A pointer to client key exchange state
* \param cns: A pointer to the connection state
*
* \return: Returns the function error state
*/
qsmp_errors qsmp_kex_simplex_client_key_exchange(qsmp_kex_simplex_client_state* kcs, qsmp_connection_state* cns);

/**
* \brief Run the internal function tests
*
* \note This is an internal non-exportable API.
*
* \return: Returns true if the tests succeed
*/
bool qsmp_kex_test();

#endif


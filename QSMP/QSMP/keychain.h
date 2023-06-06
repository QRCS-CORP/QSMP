/* 2023 Quantum Secure Cryptographic Solutions QSCS Corp. (QSCS.ca)
* All Rights Reserved.
*
* NOTICE:  All information contained herein is, and remains
* the property of the QSCS Corporation.
* The intellectual and technical concepts contained
* herein are proprietary to the QSCS Corporation
* and its suppliers and may be covered by U.S. and Foreign Patents,
* patents in process, and are protected by trade secret or copyright law.
* Dissemination of this information or reproduction of this material
* is strictly forbidden unless prior written permission is obtained
* from the QSCS Corporation.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
*/

#ifndef QSMP_KEYCHAIN_H
#define QSMP_KEYCHAIN_H

#include "common.h"
#include "qsmp.h"

#define QSMP_KEYCHAIN_SIZE (((QSMP_ASYMMETRIC_PUBLIC_KEY_SIZE + QSMP_ASYMMETRIC_PRIVATE_KEY_SIZE) * QSMP_ASYMMETRIC_KEYCHAIN_COUNT) + (2 * QSMP_SIMPLEX_SYMMETRIC_KEY_SIZE) + sizeof(uint32_t))

/*!
* \struct qsmp_asymmetric_keychain
* \brief The QSMP asymmetric key-chain structure
*/
QSMP_EXPORT_API typedef struct qsmp_asymmetric_keychain
{
	uint8_t* pubkeys;			/*!< A pointer to the public key set */
	uint8_t* prikeys;			/*!< A pointer to the private key set */
	uint64_t* ktags;			/*!< A pointer to the keytag array */
	uint32_t count;				/*!< The number of keys in the keychain */
} qsmp_asymmetric_keychain;

/**
* \brief Create an asymmetric keychain
* \warning The dispose function must be called to free memory buffers
* 
* \param keychain: A pointer to the keychain structure
* 
* \return Returns true if the keychain was created successfully
*/
QSMP_EXPORT_API bool qsmp_keychain_create(qsmp_asymmetric_keychain* keychain);

/**
* \brief Release the memory and dispose of an asymmetric keychain
* \warning The caller must still dispose of the structure itself
*
* \param keychain: A pointer to the keychain structure
*/
QSMP_EXPORT_API void qsmp_keychain_dispose(qsmp_asymmetric_keychain* keychain);

/**
* \brief Deserailize a keychain structure
*
* \param keychain: A pointer to the keychain structure
* \param input: [const] A pointer to a serialized keychain array
* \param inplen: The size of the input array
*/
QSMP_EXPORT_API void qsmp_keychain_deserialize(qsmp_asymmetric_keychain* keychain, const uint8_t* input, size_t inplen);

/**
* \brief Remove a key-set from the queue
*
* \param keychain: A pointer to the keychain structure
* \param keypair: A pointer to the keyset structure
*/
QSMP_EXPORT_API bool qsmp_keychain_pop(qsmp_asymmetric_keychain* keychain, qsmp_asymmetric_cipher_keypair* keypair);

/**
* \brief Serialize the keychain to an output array
*
* \param output: A pointer to the output array
* \param otplen: The output array size
* \param keychain: [const] A pointer to the keychain structure
*/
QSMP_EXPORT_API void qsmp_keychain_serialize(uint8_t* output, size_t otplen, const qsmp_asymmetric_keychain* keychain);

#endif
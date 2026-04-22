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

#ifndef QSMS_H
#define QSMS_H

#include "rcs.h"
#include "sha3.h"

/**
* \file qsmp.h
* \brief QSMS support header
* Common defined parameters and functions of the qsmp client and server implementations.
* 
* Note:
* These definitions determine the asymmetric protocol set used by QSMS.
* The individual parameter sets for each cipher and signature scheme,
* can be configured in the QSC libraries common.h file.
* For maximum security, I recommend the McElice/SPHINCS+ set.
* For a balance of performance and security, the Dilithium/Kyber,
* or Dilithium/McEliece sets are recommended.
* 
* Parameter Sets:
* Kyber-S1, Dilithium-S1
* Kyber-S3, Dilithium-S3
* Kyber-S5, Dilithium-S5
* Kyber-S6, Dilithium-S5
* McEliece-S1, Dilithium-S1
* McEliece-S3, Dilithium-S3
* McEliece-S5, Dilithium-S5
* McEliece-S6, Dilithium-S5
* McEliece-S7, Dilithium-S5
* McEliece-S1, Sphincs-S1(f,s)
* McEliece-S3, Sphincs-S3(f,s)
* McEliece-S5, Sphincs-S5(f,s)
* McEliece-S6, Sphincs-S5(f,s)
* McEliece-S7, Sphincs-S6(f,s)
* 
* Recommended:
* Kyber-S5, Dilithium-S5
* Kyber-S6, Dilithium-S5
* McEliece-S5, Dilithium-S5
* McEliece-S5, Sphincs-S5(f,s)
* 
* The parameter sets used by QSMS are selected in the QSC library in the 
* libraries common.h file. Settings are at library defaults, however, a true 512-bit
* security system can be acheived by selecting the McEliece/SPHINCS+ parameter in QSMS
* and setting SPHINCS+ to one of the 512-bit options in the QSC library.
*/

/*!
* \def QSMS_CONFIG_DILITHIUM_KYBER
* \brief Sets the asymmetric cryptographic primitive-set to Dilithium/Kyber.
*/
#define QSMS_CONFIG_DILITHIUM_KYBER

///*!
//* \def QSMS_CONFIG_DILITHIUM_MCELIECE
//* \brief Sets the asymmetric cryptographic primitive-set to Dilithium/McEliece.
//*/
//#define QSMS_CONFIG_DILITHIUM_MCELIECE

///*!
//* \def QSMS_CONFIG_SPHINCS_MCELIECE
//* \brief Sets the asymmetric cryptographic primitive-set to Sphincs+/McEliece.
//*/
//#define QSMS_CONFIG_SPHINCS_MCELIECE

/** \cond DOXYGEN_NO_DOCUMENT */
#if (!defined(QSMS_CONFIG_DILITHIUM_KYBER) && !defined(QSMS_CONFIG_DILITHIUM_MCELIECE) && !defined(QSMS_CONFIG_SPHINCS_MCELIECE))
#	define QSMS_CONFIG_DILITHIUM_KYBER
#endif
/** \endcond DOXYGEN_NO_DOCUMENT */

#include "qsmscommon.h"
#include "socketbase.h"

#if defined(QSMS_CONFIG_DILITHIUM_KYBER)
#	include "dilithium.h"
#	include "kyber.h"
#elif defined(QSMS_CONFIG_DILITHIUM_MCELIECE)
#	include "dilithium.h"
#	include "mceliece.h"
#elif defined(QSMS_CONFIG_SPHINCS_MCELIECE)
#	include "sphincsplus.h"
#	include "mceliece.h"
#else
#	error Invalid parameter set!
#endif

/*!
* \def QSMS_ASYMMETRIC_RATCHET
* \brief Enable the asymmetric ratchet option
*/
#define QSMS_ASYMMETRIC_RATCHET

/*!
* \def QSMS_CONFIG_SIZE
* \brief The size of the protocol configuration string
*/
#define QSMS_CONFIG_SIZE 34U

/*!
* \def QSMS_SIMPLEX_HASH_SIZE
* \brief The Simplex 256-bit hash function output size
*/
#define QSMS_SIMPLEX_HASH_SIZE 32U

/*!
* \def QSMS_SIMPLEX_MACKEY_SIZE
* \brief The Simplex 256-bit mac key size
*/
#define QSMS_SIMPLEX_MACKEY_SIZE 32U

/*!
* \def QSMS_SIMPLEX_MACTAG_SIZE
* \brief The Simplex 256-bit mac key size
*/
#define QSMS_SIMPLEX_MACTAG_SIZE 32U

/*!
* \def QSMS_SIMPLEX_SYMMETRIC_KEY_SIZE
* \brief The Simplex 256-bit symmetric cipher key size
*/
#define QSMS_SIMPLEX_SYMMETRIC_KEY_SIZE 32U

/*!
* \def QSMS_ASYMMETRIC_KEYCHAIN_COUNT
* \brief The key-chain asymmetric key count
*/
#define QSMS_ASYMMETRIC_KEYCHAIN_COUNT 10U

/*!
* \def QSMS_CLIENT_PORT
* \brief The default client port address
*/
#define QSMS_CLIENT_PORT 31118U

/*!
 * \def QSMS_CONNECTIONS_MAX
 * \brief The maximum number of QSMS connections.
 * \details This is a modifiable constant: set to the desired number of maximum connections.
 *
 * \details Modifiable constant: calculated given approx 5k
 * (3480 connection state + 1500 mtu + overhead), per connection on 256GB of DRAM.
 * Can be scaled to a greater number provided the hardware can support it.
 */
#define QSMS_CONNECTIONS_MAX 100U

/*!
* \def QSMS_CONNECTION_MTU
* \brief The QSMS packet buffer size
*/
#define QSMS_CONNECTION_MTU 1500U

/*!
* \def QSMS_ERROR_SEQUENCE
* \brief The packet error sequence number
*/
#define QSMS_ERROR_SEQUENCE 0xFF00000000000000ULL

/*!
* \def QSMS_ERROR_MESSAGE_SIZE
* \brief The packet error message size
*/
#define QSMS_ERROR_MESSAGE_SIZE 1U

/*!
* \def QSMS_FLAG_SIZE
* \brief The packet flag size
*/
#define QSMS_FLAG_SIZE 1U

/*!
* \def QSMS_HEADER_SIZE
* \brief The QSMS packet header size
*/
#define QSMS_HEADER_SIZE 21U

/*!
* \def QSMS_KEEPALIVE_STRING
* \brief The keep alive string size
*/
#define QSMS_KEEPALIVE_STRING 20U

/*!
* \def QSMS_KEEPALIVE_TIMEOUT
* \brief The keep alive timeout in milliseconds (2 minutes)
*/
#define QSMS_KEEPALIVE_TIMEOUT (120U * 1000U)

/*!
* \def QSMS_KEYID_SIZE
* \brief The QSMS key identity size
*/
#define QSMS_KEYID_SIZE 16U

/*!
* \def QSMS_MSGLEN_SIZE
* \brief The size of the packet message length
*/
#define QSMS_MSGLEN_SIZE 4U

/*!
* \def QSMS_NETWORK_MTU_SIZE
* \brief The size of the packet MTU length
*/
#define QSMS_NETWORK_MTU_SIZE 1500U

/*!
* \def QSMS_NONCE_SIZE
* \brief The size of the symmetric cipher nonce
*/
#define QSMS_NONCE_SIZE 32U

/*!
* \def QSMS_RTOK_SIZE
* \brief The size of the ratchet token
*/
#define QSMS_RTOK_SIZE 32U

/*!
* \def QSMS_SERVER_PORT
* \brief The default server port address
*/
#define QSMS_SERVER_PORT 31119U

/*!
* \def QSMS_PACKET_TIME_THRESHOLD
* \brief The maximum number of seconds a packet is valid
* Note: On interior networks with a shared (NTP) time source, this could be set at 1 second,
* depending on network and device traffic conditions. For exterior networks, this time needs to
* be adjusted to account for clock-time differences, between 30-100 seconds.
*/
#define QSMS_PACKET_TIME_THRESHOLD 60U

/*!
* \def QSMS_POLLING_INTERVAL
* \brief The polling interval in milliseconds (2 minutes)
*/
#define QSMS_POLLING_INTERVAL (120U * 1000U)

/*!
* \def QSMS_PUBKEY_DURATION_DAYS
* \brief The number of days a public key remains valid
*/
#define QSMS_PUBKEY_DURATION_DAYS 365U

/*!
* \def QSMS_PUBKEY_DURATION_SECONDS
* \brief The number of seconds a public key remains valid
*/
#define QSMS_PUBKEY_DURATION_SECONDS (QSMS_PUBKEY_DURATION_DAYS * 24U * 60U * 60U)

/*!
* \def QSMS_PUBKEY_LINE_LENGTH
* \brief The line length of the printed QSMS public key
*/
#define QSMS_PUBKEY_LINE_LENGTH 64U

/*!
* \def QSMS_SECRET_SIZE
* \brief The size of the shared secret for each channel
*/
#define QSMS_SECRET_SIZE 32U

/*!
* \def QSMS_SEQUENCE_SIZE
* \brief The size of the packet sequence number
*/
#define QSMS_SEQUENCE_SIZE 8U

/*!
* \def QSMS_SEQUENCE_TERMINATOR
* \brief The sequence number of a packet that closes a connection
*/
#define QSMS_SEQUENCE_TERMINATOR 0xFFFFFFFFUL

/*!
* \def QSMS_SRVID_SIZE
* \brief The QSMS server identity size
*/
#define QSMS_SRVID_SIZE 8U

/*!
* \def QSMS_STOKEN_SIZE
* \brief The session token size
*/
#define QSMS_STOKEN_SIZE 64U

/*!
* \def QSMS_TIMESTAMP_SIZE
* \brief The key expiration timestamp size
*/
#define QSMS_TIMESTAMP_SIZE 8U

/*!
* \def QSMS_TIMESTAMP_STRING_SIZE
* \brief The key expiration timestamp string size
*/
#define QSMS_TIMESTAMP_STRING_SIZE 20U

/*!
* \def QSMS_MESSAGE_MAX
* \brief The maximum message size used during the key exchange (1 GB)
*/
#define QSMS_MESSAGE_MAX 0x10000UL

/** \cond DOXYGEN_NO_DOCUMENT */
extern const char QSMS_CONFIG_STRING[QSMS_CONFIG_SIZE];
/** \endcond DOXYGEN_NO_DOCUMENT */

#if defined(QSMS_CONFIG_DILITHIUM_KYBER)

	/*!
	 * \def qsms_cipher_generate_keypair
	 * \brief Generate an asymmetric cipher key-pair
	 */
#	define qsms_cipher_generate_keypair qsc_kyber_generate_keypair
	/*!
	 * \def qsms_cipher_decapsulate
	 * \brief Decapsulate a shared-secret with the asymmetric cipher
	 */
#	define qsms_cipher_decapsulate qsc_kyber_decapsulate
	/*!
	 * \def qsms_cipher_encapsulate
	 * \brief Encapsulate a shared-secret with the asymmetric cipher
	 */
#	define qsms_cipher_encapsulate qsc_kyber_encapsulate
	/*!
	 * \def qsms_signature_generate_keypair
	 * \brief Generate an asymmetric signature key-pair
	 */
#	define qsms_signature_generate_keypair qsc_dilithium_generate_keypair
	/*!
	 * \def qsms_signature_sign
	 * \brief Sign a message with the asymmetric signature scheme
	 */
#	define qsms_signature_sign qsc_dilithium_sign
	/*!
	 * \def qsms_signature_verify
	 * \brief Verify a message with the asymmetric signature scheme
	 */
#	define qsms_signature_verify qsc_dilithium_verify

/*!
* \def QSMS_ASYMMETRIC_CIPHER_TEXT_SIZE
* \brief The byte size of the asymmetric cipher-text array
*/
#	define QSMS_ASYMMETRIC_CIPHER_TEXT_SIZE (QSC_KYBER_CIPHERTEXT_SIZE)

/*!
* \def QSMS_ASYMMETRIC_PRIVATE_KEY_SIZE
* \brief The byte size of the asymmetric cipher private-key array
*/
#	define QSMS_ASYMMETRIC_PRIVATE_KEY_SIZE (QSC_KYBER_PRIVATEKEY_SIZE)

/*!
* \def QSMS_ASYMMETRIC_PUBLIC_KEY_SIZE
* \brief The byte size of the asymmetric cipher public-key array
*/
#	define QSMS_ASYMMETRIC_PUBLIC_KEY_SIZE (QSC_KYBER_PUBLICKEY_SIZE)

/*!
* \def QSMS_ASYMMETRIC_SIGNING_KEY_SIZE
* \brief The byte size of the asymmetric signature signing-key array
*/
#	define QSMS_ASYMMETRIC_SIGNING_KEY_SIZE (QSC_DILITHIUM_PRIVATEKEY_SIZE)

/*!
* \def QSMS_ASYMMETRIC_VERIFY_KEY_SIZE
* \brief The byte size of the asymmetric signature verification-key array
*/
#	define QSMS_ASYMMETRIC_VERIFY_KEY_SIZE (QSC_DILITHIUM_PUBLICKEY_SIZE)

/*!
* \def QSMS_ASYMMETRIC_SIGNATURE_SIZE
* \brief The byte size of the asymmetric signature array
*/
#	define QSMS_ASYMMETRIC_SIGNATURE_SIZE (QSC_DILITHIUM_SIGNATURE_SIZE)

#elif defined(QSMS_CONFIG_DILITHIUM_MCELIECE)
	/*!
	 * \def qsms_cipher_generate_keypair
	 * \brief Generate an asymmetric cipher key-pair
	 */
#	define qsms_cipher_generate_keypair qsc_mceliece_generate_keypair
	/*!
	 * \def qsms_cipher_decapsulate
	 * \brief Decapsulate a shared-secret with the asymmetric cipher
	 */
#	define qsms_cipher_decapsulate qsc_mceliece_decapsulate
	/*!
	 * \def qsms_cipher_encapsulate
	 * \brief Encapsulate a shared-secret with the asymmetric cipher
	 */
#	define qsms_cipher_encapsulate qsc_mceliece_encapsulate
	/*!
	 * \def qsms_signature_generate_keypair
	 * \brief Generate an asymmetric signature key-pair
	 */
#	define qsms_signature_generate_keypair qsc_dilithium_generate_keypair
	/*!
	 * \def qsms_signature_sign
	 * \brief Sign a message with the asymmetric signature scheme
	 */
#	define qsms_signature_sign qsc_dilithium_sign
	/*!
	 * \def qsms_signature_verify
	 * \brief Verify a message with the asymmetric signature scheme
	 */
#	define qsms_signature_verify qsc_dilithium_verify

/*!
* \def QSMS_ASYMMETRIC_CIPHER_TEXT_SIZE
* \brief The byte size of the asymmetric cipher-text array
*/
#	define QSMS_ASYMMETRIC_CIPHER_TEXT_SIZE (QSC_MCELIECE_CIPHERTEXT_SIZE)

/*!
* \def QSMS_ASYMMETRIC_PRIVATE_KEY_SIZE
* \brief The byte size of the asymmetric cipher private-key array
*/
#	define QSMS_ASYMMETRIC_PRIVATE_KEY_SIZE (QSC_MCELIECE_PRIVATEKEY_SIZE)

/*!
* \def QSMS_ASYMMETRIC_PUBLIC_KEY_SIZE
* \brief The byte size of the asymmetric cipher public-key array
*/
#	define QSMS_ASYMMETRIC_PUBLIC_KEY_SIZE (QSC_MCELIECE_PUBLICKEY_SIZE)

/*!
* \def QSMS_ASYMMETRIC_SIGNING_KEY_SIZE
* \brief The byte size of the asymmetric signature signing-key array
*/
#	define QSMS_ASYMMETRIC_SIGNING_KEY_SIZE (QSC_DILITHIUM_PRIVATEKEY_SIZE)

/*!
* \def QSMS_ASYMMETRIC_VERIFY_KEY_SIZE
* \brief The byte size of the asymmetric signature verification-key array
*/
#	define QSMS_ASYMMETRIC_VERIFY_KEY_SIZE (QSC_DILITHIUM_PUBLICKEY_SIZE)

/*!
* \def QSMS_ASYMMETRIC_SIGNATURE_SIZE
* \brief The byte size of the asymmetric signature array
*/
#	define QSMS_ASYMMETRIC_SIGNATURE_SIZE (QSC_DILITHIUM_SIGNATURE_SIZE)

#elif defined(QSMS_CONFIG_SPHINCS_MCELIECE)

	/*!
	 * \def qsms_cipher_generate_keypair
	 * \brief Generate an asymmetric cipher key-pair
	 */
#	define qsms_cipher_generate_keypair qsc_mceliece_generate_keypair
	/*!
	 * \def qsms_cipher_decapsulate
	 * \brief Decapsulate a shared-secret with the asymmetric cipher
	 */
#	define qsms_cipher_decapsulate qsc_mceliece_decapsulate
	/*!
	 * \def qsms_cipher_encapsulate
	 * \brief Encapsulate a shared-secret with the asymmetric cipher
	 */
#	define qsms_cipher_encapsulate qsc_mceliece_encapsulate
	/*!
	 * \def qsms_signature_generate_keypair
	 * \brief Generate an asymmetric signature key-pair
	 */
#	define qsms_signature_generate_keypair qsc_sphincsplus_generate_keypair
	/*!
	 * \def qsms_signature_sign
	 * \brief Sign a message with the asymmetric signature scheme
	 */
#	define qsms_signature_sign qsc_sphincsplus_sign
	/*!
	 * \def qsms_signature_verify
	 * \brief Verify a message with the asymmetric signature scheme
	 */
#	define qsms_signature_verify qsc_sphincsplus_verify

/*!
* \def QSMS_ASYMMETRIC_CIPHER_TEXT_SIZE
* \brief The byte size of the cipher-text array
*/
#	define QSMS_ASYMMETRIC_CIPHER_TEXT_SIZE (QSC_MCELIECE_CIPHERTEXT_SIZE)

/*!
* \def QSMS_ASYMMETRIC_PRIVATE_KEY_SIZE
* \brief The byte size of the asymmetric cipher private-key array
*/
#	define QSMS_ASYMMETRIC_PRIVATE_KEY_SIZE (QSC_MCELIECE_PRIVATEKEY_SIZE)

/*!
* \def QSMS_ASYMMETRIC_PUBLIC_KEY_SIZE
* \brief The byte size of the asymmetric cipher public-key array
*/
#	define QSMS_ASYMMETRIC_PUBLIC_KEY_SIZE (QSC_MCELIECE_PUBLICKEY_SIZE)

/*!
* \def QSMS_ASYMMETRIC_SIGNING_KEY_SIZE
* \brief The byte size of the asymmetric signature signing-key array
*/
#	define QSMS_ASYMMETRIC_SIGNING_KEY_SIZE (QSC_SPHINCSPLUS_PRIVATEKEY_SIZE)

/*!
* \def QSMS_ASYMMETRIC_VERIFY_KEY_SIZE
* \brief The byte size of the asymmetric signature verification-key array
*/
#	define QSMS_ASYMMETRIC_VERIFY_KEY_SIZE (QSC_SPHINCSPLUS_PUBLICKEY_SIZE)

/*!
* \def QSMS_ASYMMETRIC_SIGNATURE_SIZE
* \brief The byte size of the asymmetric signature array
*/
#	define QSMS_ASYMMETRIC_SIGNATURE_SIZE (QSC_SPHINCSPLUS_SIGNATURE_SIZE)

#else
#	error invalid parameter set!
#endif

/* public key encoding constants */

/*!
* \def QSMS_VERIFICATION_KEY_SERIALIZED_SIZE
* \brief The verification key serialized size
*/
#define QSMS_VERIFICATION_KEY_SERIALIZED_SIZE (QSMS_KEYID_SIZE + \
	QSMS_TIMESTAMP_SIZE + \
	QSMS_CONFIG_SIZE + \
	QSMS_ASYMMETRIC_VERIFY_KEY_SIZE)

/*!
* \def QSMS_SIGNATURE_KEY_SERIALIZED_SIZE
* \brief The secret signature key serialized size
*/
#define QSMS_SIGNATURE_KEY_SERIALIZED_SIZE (QSMS_KEYID_SIZE + \
	QSMS_TIMESTAMP_SIZE + \
	QSMS_CONFIG_SIZE + \
	QSMS_ASYMMETRIC_SIGNING_KEY_SIZE + \
	QSMS_ASYMMETRIC_VERIFY_KEY_SIZE)

/*!
* \def QSMS_PUBKEY_HEADER_SIZE
* \brief The size of the QSMS public key header
*/
#define QSMS_PUBKEY_HEADER_SIZE 40U

/*!
* \def QSMS_PUBKEY_VERSION_SIZE
* \brief The size of the QSMS public key version string
*/
#define QSMS_PUBKEY_VERSION_SIZE 19U

/*!
* \def QSMS_PUBKEY_CONFIG_SIZE
* \brief The size of the QSMS public key configuration prefix
*/
#define QSMS_PUBKEY_CONFIG_SIZE 16

/*!
* \def QSMS_PUBKEY_KEYID_SIZE
* \brief The size of the QSMS public key identifier prefix
*/
#define QSMS_PUBKEY_KEYID_SIZE 10U

/*!
* \def QSMS_PUBKEY_EXPIRATION_SIZE
* \brief The size of the QSMS public key expiration prefix
*/
#define QSMS_PUBKEY_EXPIRATION_SIZE 13U

/*!
* \def QSMS_PUBKEY_FOOTER_SIZE
* \brief The size of the QSMS public key footer
*/
#define QSMS_PUBKEY_FOOTER_SIZE 38U

/*!
* \var QSMS_PUBKEY_HEADER
* \brief The QSMS public key header string
*/
static const char QSMS_PUBKEY_HEADER[QSMS_PUBKEY_HEADER_SIZE] = "------BEGIN QSMS PUBLIC KEY BLOCK------";

/*!
* \var QSMS_PUBKEY_VERSION
* \brief The QSMS public key version string
*/
static const char QSMS_PUBKEY_VERSION[QSMS_PUBKEY_VERSION_SIZE] = "Version: QSMS v1.2";

/*!
* \var QSMS_PUBKEY_CONFIG_PREFIX
* \brief The QSMS public key configuration prefix string
*/
static const char QSMS_PUBKEY_CONFIG_PREFIX[QSMS_PUBKEY_CONFIG_SIZE] = "Configuration: ";

/*!
* \var QSMS_PUBKEY_KEYID_PREFIX
* \brief The QSMS public key keyid prefix string
*/
static const char QSMS_PUBKEY_KEYID_PREFIX[QSMS_PUBKEY_KEYID_SIZE] = "Host ID: ";

/*!
* \var QSMS_PUBKEY_EXPIRATION_PREFIX
* \brief The QSMS public key expiration prefix string
*/
static const char QSMS_PUBKEY_EXPIRATION_PREFIX[QSMS_PUBKEY_EXPIRATION_SIZE] = "Expiration: ";

/*!
* \var QSMS_PUBKEY_FOOTER
* \brief The QSMS public key footer string
*/
static const char QSMS_PUBKEY_FOOTER[QSMS_PUBKEY_FOOTER_SIZE] = "------END QSMS PUBLIC KEY BLOCK------";

/* error code strings */

/*!
* \def QSMS_ERROR_STRING_DEPTH
* \brief The depth of the QSMS error string array
*/
#define QSMS_ERROR_STRING_DEPTH 27U

/*!
* \def QSMS_ERROR_STRING_WIDTH
* \brief The width of each QSMS error string
*/
#define QSMS_ERROR_STRING_WIDTH 128U

/** \cond DOXYGEN_NO_DOCUMENT */
extern const char QSMS_ERROR_STRINGS[QSMS_ERROR_STRING_DEPTH][QSMS_ERROR_STRING_WIDTH];
/** \endcond DOXYGEN_NO_DOCUMENT */

/*!
* \def QSMS_MESSAGE_STRING_DEPTH
* \brief The depth of the QSMS message string array
*/
#define QSMS_MESSAGE_STRING_DEPTH 21U
/*!
* \def QSMS_MESSAGE_STRING_WIDTH
* \brief The width of each QSMS message string
*/
#define QSMS_MESSAGE_STRING_WIDTH 128U

/** \cond DOXYGEN_NO_DOCUMENT */
extern const char QSMS_MESSAGE_STRINGS[QSMS_MESSAGE_STRING_DEPTH][QSMS_MESSAGE_STRING_WIDTH];
/** \endcond DOXYGEN_NO_DOCUMENT */

/*!
* \enum qsms_configuration
* \brief The asymmetric cryptographic primitive configuration
*/
typedef enum qsms_configuration
{
	qsms_configuration_none = 0x00U,				/*!< No configuration was specified */
	qsms_configuration_sphincs_mceliece = 0x01U,	/*!< The Sphincs+ and McEliece configuration */
	qsms_configuration_dilithium_kyber = 0x02U,		/*!< The Dilithium and Kyber configuration */
	qsms_configuration_dilithium_mceliece = 0x03U,	/*!< The Dilithium and Kyber configuration */
	qsms_configuration_dilithium_ntru = 0x04U,		/*!< The Dilithium and NTRU configuration */
	qsms_configuration_falcon_kyber = 0x05U,		/*!< The Falcon and Kyber configuration */
	qsms_configuration_falcon_mceliece = 0x06U,		/*!< The Falcon and McEliece configuration */
	qsms_configuration_falcon_ntru = 0x07U,			/*!< The Falcon and NTRU configuration */
} qsms_configuration;

/*!
* \enum qsms_messages
* \brief The logging message enumeration
*/
typedef enum qsms_messages
{
	qsms_messages_none = 0x00U,						/*!< No configuration was specified */
	qsms_messages_accept_fail = 0x01U,				/*!< The socket accept failed */
	qsms_messages_listen_fail = 0x02U,				/*!< The listener socket could not connect */
	qsms_messages_bind_fail = 0x03U,				/*!< The listener socket could not bind to the address */
	qsms_messages_create_fail = 0x04U,				/*!< The listener socket could not be created */
	qsms_messages_connect_success = 0x05U,			/*!< The server connected to a host */
	qsms_messages_receive_fail = 0x06U,				/*!< The socket receive function failed */
	qsms_messages_allocate_fail = 0x07U,			/*!< The server memory allocation request has failed */
	qsms_messages_kex_fail = 0x08U,					/*!< The key exchange has experienced a failure */
	qsms_messages_disconnect = 0x09U,				/*!< The server has disconnected the client */
	qsms_messages_disconnect_fail = 0x0AU,			/*!< The server has disconnected the client due to an error */
	qsms_messages_socket_message = 0x0BU,			/*!< The server has had a socket level error */
	qsms_messages_queue_empty = 0x0CU,				/*!< The server has reached the maximum number of connections */
	qsms_messages_listener_fail = 0x0DU,			/*!< The server listener socket has failed */
	qsms_messages_sockalloc_fail = 0x0EU,			/*!< The server has run out of socket connections */
	qsms_messages_decryption_fail = 0x0FU,			/*!< The message decryption has failed */
	qsms_messages_keepalive_fail = 0x10U,			/*!< The keepalive function has failed */
	qsms_messages_keepalive_timeout = 0x11U,		/*!< The keepalive period has been exceeded */
	qsms_messages_connection_fail = 0x12U,			/*!< The connection failed or was interrupted */
	qsms_messages_invalid_request = 0x13U,			/*!< The function received an invalid request */
	qsms_messages_symmetric_ratchet = 0x14U,		/*!< The host received a symmetric ratchet request */
} qsms_messages;

/*!
* \enum qsms_errors
* \brief The QSMS error values
*/
typedef enum qsms_errors
{
	qsms_error_none = 0x00U,						/*!< No error was detected */
	qsms_error_accept_fail = 0x01U,					/*!< The socket accept function returned an error */
	qsms_error_authentication_failure = 0x02U,		/*!< The symmetric cipher had an authentication failure */
	qsms_error_channel_down = 0x03U,				/*!< The communications channel has failed */
	qsms_error_connection_failure = 0x04U,			/*!< The device could not make a connection to the remote host */
	qsms_error_connection_refused = 0x05U,			/*!< The remote host has refused the connection */
	qsms_error_decapsulation_failure = 0x06U,		/*!< The asymmetric cipher failed to decapsulate the shared secret */
	qsms_error_decryption_failure = 0x07U,			/*!< The decryption authentication has failed */
	qsms_error_establish_failure = 0x08U,			/*!< The transmission failed at the KEX establish phase */
	qsms_error_exchange_failure = 0x09U,			/*!< The transmission failed at the KEX exchange phase */
	qsms_error_hash_invalid = 0x0AU,				/*!< The public-key hash is invalid */
	qsms_error_hosts_exceeded = 0x0BU,				/*!< The server has run out of socket connections */
	qsms_error_invalid_input = 0x0CU,				/*!< The expected input was invalid */
	qsms_error_invalid_request = 0x0DU,				/*!< The packet flag was unexpected */
	qsms_error_key_expired = 0x0EU,					/*!< The QSMS public key has expired  */
	qsms_error_key_unrecognized = 0x0FU,			/*!< The key identity is unrecognized */
	qsms_error_keychain_fail = 0x10U,				/*!< The ratchet operation has failed */
	qsms_error_listener_fail = 0x11U,				/*!< The listener function failed to initialize */
	qsms_error_memory_allocation = 0x12U,			/*!< The server has run out of memory */
	qsms_error_message_time_invalid = 0x13U,		/*!< The packet has valid time expired */
	qsms_error_packet_unsequenced = 0x14U,			/*!< The packet was received out of sequence */
	qsms_error_random_failure = 0x15U,				/*!< The random generator has failed */
	qsms_error_receive_failure = 0x16U,				/*!< The receiver failed at the network layer */
	qsms_error_transmit_failure = 0x17U,			/*!< The transmitter failed at the network layer */
	qsms_error_unknown_protocol = 0x18U,			/*!< The protocol string was not recognized */
	qsms_error_verify_failure = 0x19U,				/*!< The expected data could not be verified */
	qsms_messages_system_message = 0x1AU,			/*!< The remote host sent an error or disconnect message */
} qsms_errors;

/*!
* \enum qsms_flags
* \brief The QSMS packet flags
*/
typedef enum qsms_flags
{
	qsms_flag_none = 0x00U,							/*!< No flag was specified */
	qsms_flag_connect_request = 0x01U,				/*!< The QSMS key-exchange client connection request flag  */
	qsms_flag_connect_response = 0x02U,				/*!< The QSMS key-exchange server connection response flag */
	qsms_flag_connection_terminate = 0x03U,			/*!< The connection is to be terminated */
	qsms_flag_encrypted_message = 0x04U,			/*!< The message has been encrypted flag */
	qsms_flag_exstart_request = 0x05U,				/*!< The QSMS key-exchange client exstart request flag */
	qsms_flag_exstart_response = 0x06U,				/*!< The QSMS key-exchange server exstart response flag */
	qsms_flag_exchange_request = 0x07U,				/*!< The QSMS key-exchange client exchange request flag */
	qsms_flag_exchange_response = 0x08U,			/*!< The QSMS key-exchange server exchange response flag */
	qsms_flag_establish_request = 0x09U,			/*!< The QSMS key-exchange client establish request flag */
	qsms_flag_establish_response = 0x0AU,			/*!< The QSMS key-exchange server establish response flag */
	qsms_flag_remote_connected = 0x0BU,				/*!< The remote host is connected flag */
	qsms_flag_remote_terminated = 0x0CU,			/*!< The remote host has terminated the connection */
	qsms_flag_session_established = 0x0DU,			/*!< The exchange is in the established state */
	qsms_flag_session_establish_verify = 0x0EU,		/*!< The exchange is in the established verify state */
	qsms_flag_unrecognized_protocol = 0x0FU,		/*!< The protocol string is not recognized */
	qsms_flag_asymmetric_ratchet_request = 0x10U,	/*!< The host has received a asymmetric key ratchet request */
	qsms_flag_asymmetric_ratchet_response = 0x11U,	/*!< The host has received a asymmetric key ratchet request */
	qsms_flag_symmetric_ratchet_request = 0x12U,	/*!< The host has received a symmetric key ratchet request */
	qsms_flag_transfer_request = 0x13U,				/*!< Reserved - The host has received a transfer request */
	qsms_flag_error_condition = 0x14U,				/*!< The connection experienced an error */
} qsms_flags;

/*!
* \struct qsms_asymmetric_cipher_keypair
* \brief The QSMS asymmetric cipher key container
*/
QSMS_EXPORT_API typedef struct qsms_asymmetric_cipher_keypair
{
	uint8_t* prikey;
	uint8_t* pubkey;
} qsms_asymmetric_cipher_keypair;

/*!
* \struct qsms_asymmetric_signature_keypair
* \brief The QSMS asymmetric signature key container
*/
QSMS_EXPORT_API typedef struct qsms_asymmetric_signature_keypair
{
	uint8_t* sigkey;
	uint8_t* verkey;
} qsms_asymmetric_signature_keypair;

/*!
* \struct qsms_network_packet
* \brief The QSMS packet structure
*/
QSMS_EXPORT_API typedef struct qsms_network_packet
{
	uint8_t flag;									/*!< The packet flag */
	uint32_t msglen;								/*!< The packets message length */
	uint64_t sequence;								/*!< The packet sequence number */
	uint64_t utctime;								/*!< The UTC time the packet was created in seconds */
	uint8_t* pmessage;								/*!< A pointer to the packets message buffer */
} qsms_network_packet;

/*!
* \struct qsms_client_verification_key
* \brief The QSMS client key structure
*/
QSMS_EXPORT_API typedef struct qsms_client_verification_key
{
	uint64_t expiration;							/*!< The expiration time, in seconds from epoch */
	uint8_t config[QSMS_CONFIG_SIZE];				/*!< The primitive configuration string */
	uint8_t keyid[QSMS_KEYID_SIZE];					/*!< The key identity string */
	uint8_t verkey[QSMS_ASYMMETRIC_VERIFY_KEY_SIZE];/*!< The asymmetric signatures verification-key */
} qsms_client_verification_key;

/*!
* \struct qsms_server_signature_key
* \brief The QSMS server key structure
*/
QSMS_EXPORT_API typedef struct qsms_server_signature_key
{
	uint64_t expiration;							/*!< The expiration time, in seconds from epoch */
	uint8_t config[QSMS_CONFIG_SIZE];				/*!< The primitive configuration string */
	uint8_t keyid[QSMS_KEYID_SIZE];					/*!< The key identity string */
	uint8_t sigkey[QSMS_ASYMMETRIC_SIGNING_KEY_SIZE];/*!< The asymmetric signature signing-key */
	uint8_t verkey[QSMS_ASYMMETRIC_VERIFY_KEY_SIZE]; /*!< The asymmetric signature verification-key */
} qsms_server_signature_key;

/*!
* \struct qsms_connection_state
* \brief The QSMS socket connection state structure
*/
QSMS_EXPORT_API typedef struct qsms_connection_state
{
	qsc_socket target;								/*!< The target socket structure */
	qsc_rcs_state rxcpr;							/*!< The receive channel cipher state */
	qsc_rcs_state txcpr;							/*!< The transmit channel cipher state */
	uint64_t rxseq;									/*!< The receive channels packet sequence number  */
	uint64_t txseq;									/*!< The transmit channels packet sequence number  */
	uint32_t cid;									/*!< The connections instance count */
	qsms_flags exflag;								/*!< The KEX position flag */
	bool receiver;									/*!< The instance was initialized in listener mode */
	uint8_t rtcs[QSMS_SIMPLEX_SYMMETRIC_KEY_SIZE];	/*!< The symmetric ratchet key */
} qsms_connection_state;

/*!
* \brief Close the network connection between hosts
*
* \param cns: A pointer to the connection state structure
* \param err: The error message
* \param notify: Notify the remote host connection is closing
*/
QSMS_EXPORT_API void qsms_connection_close(qsms_connection_state* cns, qsms_errors err, bool notify);

/*!
 * \brief Decrypt an error message.
 *
 * \param cns A pointer to the QSMS connection state structure.
 * \param message [const] The serialized error packet.
 * \param merr A pointer to an \c qsms_errors error value.
 *
 * \return Returns true if the message was decrypted successfully, false on failure.
 */
QSMS_EXPORT_API bool qsms_decrypt_error_message(qsms_errors* merr, qsms_connection_state* cns, const uint8_t* message);

/*!
* \brief Reset the connection state
*
* \param cns: A pointer to the connection state structure
*/
QSMS_EXPORT_API void qsms_connection_state_dispose(qsms_connection_state* cns);

/*!
* \brief Return a pointer to a string description of an error code
*
* \param error: The error type
* 
* \return Returns a pointer to an error string or NULL
*/
QSMS_EXPORT_API const char* qsms_error_to_string(qsms_errors error);

/*!
* \brief Populate a packet header and set the creation time
*
* \param packetout: A pointer to the output packet structure
* \param flag: The packet flag
* \param sequence: The packet sequence number
* \param msglen: The length of the message array
*/
QSMS_EXPORT_API void qsms_header_create(qsms_network_packet* packetout, qsms_flags flag, uint64_t sequence, uint32_t msglen);

/*!
* \brief Validate a packet header and timestamp
*
* \param cns: A pointer to the connection state structure
* \param packetin: A pointer to the input packet structure
* \param kexflag: The packet flag
* \param pktflag: The packet flag
* \param sequence: The packet sequence number
* \param msglen: The length of the message array
*
* \return: Returns the function error state
*/
QSMS_EXPORT_API qsms_errors qsms_header_validate(qsms_connection_state* cns, const qsms_network_packet* packetin, qsms_flags kexflag, qsms_flags pktflag, uint64_t sequence, uint32_t msglen);

/*!
* \brief Generate a QSMS key-pair; generates the public and private asymmetric signature keys.
*
* \param pubkey: The public key, distributed to clients
* \param prikey: The private key, a secret key known only by the server
* \param keyid: [const] The key identity string
*/
QSMS_EXPORT_API void qsms_generate_keypair(qsms_client_verification_key* pubkey, qsms_server_signature_key* prikey, const uint8_t* keyid);

/*!
* \brief Get the error string description
*
* \param emsg: The message enumeration
* 
* \return Returns a pointer to the message string or NULL
*/
QSMS_EXPORT_API const char* qsms_get_error_description(qsms_messages emsg);

/*!
* \brief Log the message, socket error, and string description
*
* \param emsg: The message enumeration
* \param err: The socket exception enumeration
* \param msg: [const] The message string
*/
QSMS_EXPORT_API void qsms_log_error(qsms_messages emsg, qsc_socket_exceptions err, const char* msg);

/*!
* \brief Log a message
*
* \param emsg: The message enumeration
*/
QSMS_EXPORT_API void qsms_log_message(qsms_messages emsg);

/*!
* \brief Log a system error message
*
* \param err: The system error enumerator
*/
QSMS_EXPORT_API void qsms_log_system_error(qsms_errors err);

/*!
* \brief Log a message and description
*
* \param emsg: The message enumeration
* \param msg: [const] The message string
*/
QSMS_EXPORT_API void qsms_log_write(qsms_messages emsg, const char* msg);

/*!
* \brief Clear a packet's state
*
* \param packet: A pointer to the packet structure
*/
QSMS_EXPORT_API void qsms_packet_clear(qsms_network_packet* packet);

/*!
* \brief Decrypt a message and copy it to the message output
*
* \param cns: A pointer to the connection state structure
* \param message: The message output array
* \param msglen: A pointer receiving the message length
* \param packetin: [const] A pointer to the input packet structure
*
* \return: Returns the function error state
*/
QSMS_EXPORT_API qsms_errors qsms_packet_decrypt(qsms_connection_state* cns, uint8_t* message, size_t* msglen, const qsms_network_packet* packetin);

/*!
* \brief Encrypt a message and build an output packet
*
* \param cns: A pointer to the connection state structure
* \param packetout: A pointer to the output packet structure
* \param message: [const] The input message array
* \param msglen: The length of the message array
*
* \return: Returns the function error state
*/
QSMS_EXPORT_API qsms_errors qsms_packet_encrypt(qsms_connection_state* cns, qsms_network_packet* packetout, const uint8_t* message, size_t msglen);

/*!
* \brief Populate a packet structure with an error message
*
* \param packet: A pointer to the packet structure
* \param error: The error type
*/
QSMS_EXPORT_API void qsms_packet_error_message(qsms_network_packet* packet, qsms_errors error);

/*!
* \brief Deserialize a byte array to a packet header
*
* \param packet: [const] The header byte array to deserialize
* \param header: A pointer to the packet structure
*/
QSMS_EXPORT_API void qsms_packet_header_deserialize(const uint8_t* header, qsms_network_packet* packet);

/*!
* \brief Serialize a packet header to a byte array
*
* \param packet: [const] A pointer to the packet structure to serialize
* \param header: The header byte array
*/
QSMS_EXPORT_API void qsms_packet_header_serialize(const qsms_network_packet* packet, uint8_t* header);

/*!
* \brief Sets the local UTC seconds time in the packet header
*
* \param packet: A pointer to a network packet
*/
QSMS_EXPORT_API void qsms_packet_set_utc_time(qsms_network_packet* packet);

/*!
* \brief Checks the local UTC seconds time against the packet sent time for validity within the packet time threshold
*
* \param packet: [const] A pointer to a network packet
*
* \return Returns true if the packet was received within the valid-time threhold
*/
QSMS_EXPORT_API bool qsms_packet_time_valid(const qsms_network_packet* packet);

/*!
* \brief Serialize a packet to a byte array
*
* \param packet: [const] The header byte array to deserialize
* \param pstream: A pointer to the packet structure
* 
* \return Returns the size of the byte stream
*/
QSMS_EXPORT_API size_t qsms_packet_to_stream(const qsms_network_packet* packet, uint8_t* pstream);

/*!
* \brief Compares two public keys for equality
*
* \param a: [const] The first public key
* \param b: [const] The second public key
*
* \return Returns true if the certificates are identical
*/
QSMS_EXPORT_API bool qsms_public_key_compare(const qsms_client_verification_key* a, const qsms_client_verification_key* b);

/*!
* \brief Decode a public key string and populate a client key structure
*
* \param pubk: A pointer to the output client key
* \param enck: [const] The input encoded key
*
* \return: Returns true for success
*/
QSMS_EXPORT_API bool qsms_public_key_decode(qsms_client_verification_key* pubk, const char* enck, size_t enclen);

/*!
* \brief Encode a public key structure and copy to a string
*
* \param enck: The output encoded public key string
* \param enclen: The length of the encoding array
* \param pubk: [const] A pointer to the public key structure
*
* \return: Returns the encoded string length
*/
QSMS_EXPORT_API size_t qsms_public_key_encode(char* enck, size_t enclen, const qsms_client_verification_key* pubk);

/*!
* \brief Get the key encoding string size
*
* \return Returns the size of the encoded string
*/
QSMS_EXPORT_API size_t qsms_public_key_encoding_size(void);

/*!
* \brief Decode a secret signature key structure and copy to an array
*
* \param kset: A pointer to the output server key structure
* \param serk: [const] The input encoded secret key string
*/
QSMS_EXPORT_API void qsms_signature_key_deserialize(qsms_server_signature_key* kset, const uint8_t* serk);

/*!
* \brief Encode a secret key structure and copy to a string
*
* \param serk: The output encoded public key string
* \param kset: [const] A pointer to the secret server key structure
*/
QSMS_EXPORT_API void qsms_signature_key_serialize(uint8_t* serk, const qsms_server_signature_key* kset);

/*!
* \brief Deserialize a byte array to a packet
*
* \param pstream: [const] The header byte array to deserialize
* \param packet: A pointer to the packet structure
*/
QSMS_EXPORT_API void qsms_stream_to_packet(const uint8_t* pstream, qsms_network_packet* packet);

#if defined (QSMS_DEBUG_MODE)
/*!
* \brief Test the certificate encoding and decoding functions
*
* \return Returns true if the encoding tests succeed
*/
QSMS_EXPORT_API bool qsms_certificate_encoding_test(void);
#endif

#endif

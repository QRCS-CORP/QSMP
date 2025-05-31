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

#ifndef QSMP_H
#define QSMP_H

#include "rcs.h"
#include "sha3.h"

/**
* \file qsmp.h
* \brief QSMP support header
* Common defined parameters and functions of the qsmp client and server implementations.
* 
* Note:
* These definitions determine the asymmetric protocol set used by QSMP.
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
* The parameter sets used by QSMP are selected in the QSC library in the 
* libraries common.h file. Settings are at library defaults, however, a true 512-bit
* security system can be acheived by selecting the McEliece/SPHINCS+ parameter in QSMP
* and setting SPHINCS+ to one of the 512-bit options in the QSC library.
*/

/*!
* \def QSMP_CONFIG_DILITHIUM_KYBER
* \brief Sets the asymmetric cryptographic primitive-set to Dilithium/Kyber.
*/
#define QSMP_CONFIG_DILITHIUM_KYBER

///*!
//* \def QSMP_CONFIG_DILITHIUM_MCELIECE
//* \brief Sets the asymmetric cryptographic primitive-set to Dilithium/McEliece.
//*/
//#define QSMP_CONFIG_DILITHIUM_MCELIECE

///*!
//* \def QSMP_CONFIG_SPHINCS_MCELIECE
//* \brief Sets the asymmetric cryptographic primitive-set to Sphincs+/McEliece.
//*/
//#define QSMP_CONFIG_SPHINCS_MCELIECE

#include "qsmpcommon.h"
#include "socketbase.h"

#if defined(QSMP_CONFIG_DILITHIUM_KYBER)
#	include "dilithium.h"
#	include "kyber.h"
#elif defined(QSMP_CONFIG_DILITHIUM_MCELIECE)
#	include "dilithium.h"
#	include "mceliece.h"
#elif defined(QSMP_CONFIG_SPHINCS_MCELIECE)
#	include "sphincsplus.h"
#	include "mceliece.h"
#else
#	error Invalid parameter set!
#endif

///*!
//* \def QSMP_ASYMMETRIC_RATCHET
//* \brief Enable the asymmetric ratchet option
//*/
//#define QSMP_ASYMMETRIC_RATCHET

/*!
* \def QSMP_CONFIG_SIZE
* \brief The size of the protocol configuration string
*/
#define QSMP_CONFIG_SIZE 48U

/*!
* \def QSMP_SIMPLEX_HASH_SIZE
* \brief The Simplex 256-bit hash function output size
*/
#define QSMP_SIMPLEX_HASH_SIZE 32U

/*!
* \def QSMP_SIMPLEX_MACKEY_SIZE
* \brief The Simplex 256-bit mac key size
*/
#define QSMP_SIMPLEX_MACKEY_SIZE 32U

/*!
* \def QSMP_SIMPLEX_MACTAG_SIZE
* \brief The Simplex 256-bit mac key size
*/
#define QSMP_SIMPLEX_MACTAG_SIZE 32U

/*!
* \def QSMP_SIMPLEX_SYMMETRIC_KEY_SIZE
* \brief The Simplex 256-bit symmetric cipher key size
*/
#define QSMP_SIMPLEX_SYMMETRIC_KEY_SIZE 32U

/*!
* \def QSMP_SIMPLEX_SCHASH_SIZE
* \brief The Simplex 256-bit session token hash size
*/
#define QSMP_SIMPLEX_SCHASH_SIZE 32U

/*!
* \def QSMP_DUPLEX_HASH_SIZE
* \brief The Duplex 512-bit hash function size
*/
#define QSMP_DUPLEX_HASH_SIZE 64U

/*!
* \def QSMP_DUPLEX_MACKEY_SIZE
* \brief The Duplex 512-bit mac key size
*/
#define QSMP_DUPLEX_MACKEY_SIZE 64U

/*!
* \def QSMP_DUPLEX_MACTAG_SIZE
* \brief The Duplex 512-bit mac key size
*/
#define QSMP_DUPLEX_MACTAG_SIZE 64U

/*!
* \def QSMP_DUPLEX_SYMMETRIC_KEY_SIZE
* \brief TheDuplex  512-bit symmetric cipher key size
*/
#define QSMP_DUPLEX_SYMMETRIC_KEY_SIZE 64U

/*!
* \def QSMP_DUPLEX_SCHASH_SIZE
* \brief The Duplex session token 512-bit hash size
*/
#define QSMP_DUPLEX_SCHASH_SIZE 64U

/*!
* \def QSMP_ASYMMETRIC_KEYCHAIN_COUNT
* \brief The key-chain asymmetric key count
*/
#define QSMP_ASYMMETRIC_KEYCHAIN_COUNT 10U

/*!
* \def QSMP_CLIENT_PORT
* \brief The default client port address
*/
#define QSMP_CLIENT_PORT 31118U

/*!
* \def QSMP_CONNECTIONS_INIT 
* \brief The intitial QSMP connections queue size
*/
#define QSMP_CONNECTIONS_INIT 1000U

/*!
* \def QSMP_CONNECTIONS_MAX
* \brief The maximum number of connections
* Calculated given approx 5k (3480 connection state + 1500 mtu + overhead),
* per connection on 256GB of DRAM.
* Can be scaled to a greater number provided the hardware can support it.
*/
#define QSMP_CONNECTIONS_MAX 50000U

/*!
* \def QSMP_CONNECTION_MTU
* \brief The QSMP packet buffer size
*/
#define QSMP_CONNECTION_MTU 1500U

/*!
* \def QSMP_ERROR_SEQUENCE
* \brief The packet error sequence number
*/
#define QSMP_ERROR_SEQUENCE 0xFF00000000000000ULL

/*!
* \def QSMP_ERROR_MESSAGE_SIZE
* \brief The packet error message size
*/
#define QSMP_ERROR_MESSAGE_SIZE 1U

/*!
* \def QSMP_FLAG_SIZE
* \brief The packet flag size
*/
#define QSMP_FLAG_SIZE 1U

/*!
* \def QSMP_HEADER_SIZE
* \brief The QSMP packet header size
*/
#define QSMP_HEADER_SIZE 21U

/*!
* \def QSMP_KEEPALIVE_STRING
* \brief The keep alive string size
*/
#define QSMP_KEEPALIVE_STRING 20U

/*!
* \def QSMP_KEEPALIVE_TIMEOUT
* \brief The keep alive timeout in milliseconds (2 minutes)
*/
#define QSMP_KEEPALIVE_TIMEOUT (120U * 1000U)

/*!
* \def QSMP_KEYID_SIZE
* \brief The QSMP key identity size
*/
#define QSMP_KEYID_SIZE 16U

/*!
* \def QSMP_MSGLEN_SIZE
* \brief The size of the packet message length
*/
#define QSMP_MSGLEN_SIZE 4U

/*!
* \def QSMP_NETWORK_MTU_SIZE
* \brief The size of the packet MTU length
*/
#define QSMP_NETWORK_MTU_SIZE 1500U

/*!
* \def QSMP_NONCE_SIZE
* \brief The size of the symmetric cipher nonce
*/
#define QSMP_NONCE_SIZE 32U

/*!
* \def QSMP_RTOK_SIZE
* \brief The size of the ratchet token
*/
#define QSMP_RTOK_SIZE 32U

/*!
* \def QSMP_SERVER_PORT
* \brief The default server port address
*/
#define QSMP_SERVER_PORT 31119U

/*!
* \def QSMP_PACKET_TIME_THRESHOLD
* \brief The maximum number of seconds a packet is valid
* Note: On interior networks with a shared (NTP) time source, this could be set at 1 second,
* depending on network and device traffic conditions. For exterior networks, this time needs to
* be adjusted to account for clock-time differences, between 30-100 seconds.
*/
#define QSMP_PACKET_TIME_THRESHOLD 60U

/*!
* \def QSMP_POLLING_INTERVAL
* \brief The polling interval in milliseconds (2 minutes)
*/
#define QSMP_POLLING_INTERVAL (120U * 1000U)

/*!
* \def QSMP_PUBKEY_DURATION_DAYS
* \brief The number of days a public key remains valid
*/
#define QSMP_PUBKEY_DURATION_DAYS 365U

/*!
* \def QSMP_PUBKEY_DURATION_SECONDS
* \brief The number of seconds a public key remains valid
*/
#define QSMP_PUBKEY_DURATION_SECONDS (QSMP_PUBKEY_DURATION_DAYS * 24U * 60U * 60U)

/*!
* \def QSMP_PUBKEY_LINE_LENGTH
* \brief The line length of the printed QSMP public key
*/
#define QSMP_PUBKEY_LINE_LENGTH 64U

/*!
* \def QSMP_SECRET_SIZE
* \brief The size of the shared secret for each channel
*/
#define QSMP_SECRET_SIZE 32U

/*!
* \def QSMP_SEQUENCE_SIZE
* \brief The size of the packet sequence number
*/
#define QSMP_SEQUENCE_SIZE 8U

/*!
* \def QSMP_SEQUENCE_TERMINATOR
* \brief The sequence number of a packet that closes a connection
*/
#define QSMP_SEQUENCE_TERMINATOR 0xFFFFFFFFUL

/*!
* \def QSMP_SRVID_SIZE
* \brief The QSMP server identity size
*/
#define QSMP_SRVID_SIZE 8U

/*!
* \def QSMP_STOKEN_SIZE
* \brief The session token size
*/
#define QSMP_STOKEN_SIZE 64U

/*!
* \def QSMP_TIMESTAMP_SIZE
* \brief The key expiration timestamp size
*/
#define QSMP_TIMESTAMP_SIZE 8U

/*!
* \def QSMP_TIMESTAMP_STRING_SIZE
* \brief The key expiration timestamp string size
*/
#define QSMP_TIMESTAMP_STRING_SIZE 20U

/*!
* \def QSMP_MESSAGE_MAX
* \brief The maximum message size used during the key exchange (1 GB)
*/
#define QSMP_MESSAGE_MAX 0x3D090000UL

#if defined(QSMP_CONFIG_DILITHIUM_KYBER)

	/*!
	 * \def qsmp_cipher_generate_keypair
	 * \brief Generate an asymmetric cipher key-pair
	 */
#	define qsmp_cipher_generate_keypair qsc_kyber_generate_keypair
	/*!
	 * \def qsmp_cipher_decapsulate
	 * \brief Decapsulate a shared-secret with the asymmetric cipher
	 */
#	define qsmp_cipher_decapsulate qsc_kyber_decapsulate
	/*!
	 * \def qsmp_cipher_encapsulate
	 * \brief Encapsulate a shared-secret with the asymmetric cipher
	 */
#	define qsmp_cipher_encapsulate qsc_kyber_encapsulate
	/*!
	 * \def qsmp_signature_generate_keypair
	 * \brief Generate an asymmetric signature key-pair
	 */
#	define qsmp_signature_generate_keypair qsc_dilithium_generate_keypair
	/*!
	 * \def qsmp_signature_sign
	 * \brief Sign a message with the asymmetric signature scheme
	 */
#	define qsmp_signature_sign qsc_dilithium_sign
	/*!
	 * \def qsmp_signature_verify
	 * \brief Verify a message with the asymmetric signature scheme
	 */
#	define qsmp_signature_verify qsc_dilithium_verify

/** \cond */
#	if defined(QSC_DILITHIUM_S1P2544) && defined(QSC_KYBER_S1P1632)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "dilithium-s1_kyber-s1_sha3_rcs";
#	elif defined(QSC_DILITHIUM_S3P4016) && defined(QSC_KYBER_S3P2400)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "dilithium-s3_kyber-s3_sha3_rcs";
#	elif defined(QSC_DILITHIUM_S5P4880) && defined(QSC_KYBER_S5P3168)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "dilithium-s5_kyber-s5_sha3_rcs";
#	elif defined(QSC_DILITHIUM_S5P4880) && defined(QSC_KYBER_S6P3936)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "dilithium-s5_kyber-s6_sha3_rcs";
#	else
#		error Invalid parameter set!
#	endif
/** \endcond */

/*!
* \def QSMP_ASYMMETRIC_CIPHER_TEXT_SIZE
* \brief The byte size of the asymmetric cipher-text array
*/
#	define QSMP_ASYMMETRIC_CIPHER_TEXT_SIZE (QSC_KYBER_CIPHERTEXT_SIZE)

/*!
* \def QSMP_ASYMMETRIC_PRIVATE_KEY_SIZE
* \brief The byte size of the asymmetric cipher private-key array
*/
#	define QSMP_ASYMMETRIC_PRIVATE_KEY_SIZE (QSC_KYBER_PRIVATEKEY_SIZE)

/*!
* \def QSMP_ASYMMETRIC_PUBLIC_KEY_SIZE
* \brief The byte size of the asymmetric cipher public-key array
*/
#	define QSMP_ASYMMETRIC_PUBLIC_KEY_SIZE (QSC_KYBER_PUBLICKEY_SIZE)

/*!
* \def QSMP_ASYMMETRIC_SIGNING_KEY_SIZE
* \brief The byte size of the asymmetric signature signing-key array
*/
#	define QSMP_ASYMMETRIC_SIGNING_KEY_SIZE (QSC_DILITHIUM_PRIVATEKEY_SIZE)

/*!
* \def QSMP_ASYMMETRIC_VERIFY_KEY_SIZE
* \brief The byte size of the asymmetric signature verification-key array
*/
#	define QSMP_ASYMMETRIC_VERIFY_KEY_SIZE (QSC_DILITHIUM_PUBLICKEY_SIZE)

/*!
* \def QSMP_ASYMMETRIC_SIGNATURE_SIZE
* \brief The byte size of the asymmetric signature array
*/
#	define QSMP_ASYMMETRIC_SIGNATURE_SIZE (QSC_DILITHIUM_SIGNATURE_SIZE)

#elif defined(QSMP_CONFIG_DILITHIUM_MCELIECE)
	/*!
	 * \def qsmp_cipher_generate_keypair
	 * \brief Generate an asymmetric cipher key-pair
	 */
#	define qsmp_cipher_generate_keypair qsc_mceliece_generate_keypair
	/*!
	 * \def qsmp_cipher_decapsulate
	 * \brief Decapsulate a shared-secret with the asymmetric cipher
	 */
#	define qsmp_cipher_decapsulate qsc_mceliece_decapsulate
	/*!
	 * \def qsmp_cipher_encapsulate
	 * \brief Encapsulate a shared-secret with the asymmetric cipher
	 */
#	define qsmp_cipher_encapsulate qsc_mceliece_encapsulate
	/*!
	 * \def qsmp_signature_generate_keypair
	 * \brief Generate an asymmetric signature key-pair
	 */
#	define qsmp_signature_generate_keypair qsc_dilithium_generate_keypair
	/*!
	 * \def qsmp_signature_sign
	 * \brief Sign a message with the asymmetric signature scheme
	 */
#	define qsmp_signature_sign qsc_dilithium_sign
	/*!
	 * \def qsmp_signature_verify
	 * \brief Verify a message with the asymmetric signature scheme
	 */
#	define qsmp_signature_verify qsc_dilithium_verify

/** \cond */
#	if defined(QSC_DILITHIUM_S1P2544) && defined(QSC_MCELIECE_S1N3488T64)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "dilithium-s1_mceliece-s1_sha3_rcs";
#	elif defined(QSC_DILITHIUM_S3P4016) && defined(QSC_MCELIECE_S3N4608T96)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "dilithium-s3_mceliece-s3_sha3_rcs";
#	elif defined(QSC_DILITHIUM_S5P4880) && defined(QSC_MCELIECE_S5N6688T128)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "dilithium-s5_mceliece-s5_sha3_rcs";
#	elif defined(QSC_DILITHIUM_S5P4880) && defined(QSC_MCELIECE_S6N6960T119)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "dilithium-s5_mceliece-s6_sha3_rcs";
#	elif defined(QSC_DILITHIUM_S5P4880) && defined(QSC_MCELIECE_S7N8192T128)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "dilithium-s5_mceliece-s7_sha3_rcs";
#	else
#		error Invalid parameter set!
#	endif
/** \endcond */

/*!
* \def QSMP_ASYMMETRIC_CIPHER_TEXT_SIZE
* \brief The byte size of the asymmetric cipher-text array
*/
#	define QSMP_ASYMMETRIC_CIPHER_TEXT_SIZE (QSC_MCELIECE_CIPHERTEXT_SIZE)

/*!
* \def QSMP_ASYMMETRIC_PRIVATE_KEY_SIZE
* \brief The byte size of the asymmetric cipher private-key array
*/
#	define QSMP_ASYMMETRIC_PRIVATE_KEY_SIZE (QSC_MCELIECE_PRIVATEKEY_SIZE)

/*!
* \def QSMP_ASYMMETRIC_PUBLIC_KEY_SIZE
* \brief The byte size of the asymmetric cipher public-key array
*/
#	define QSMP_ASYMMETRIC_PUBLIC_KEY_SIZE (QSC_MCELIECE_PUBLICKEY_SIZE)

/*!
* \def QSMP_ASYMMETRIC_SIGNING_KEY_SIZE
* \brief The byte size of the asymmetric signature signing-key array
*/
#	define QSMP_ASYMMETRIC_SIGNING_KEY_SIZE (QSC_DILITHIUM_PRIVATEKEY_SIZE)

/*!
* \def QSMP_ASYMMETRIC_VERIFY_KEY_SIZE
* \brief The byte size of the asymmetric signature verification-key array
*/
#	define QSMP_ASYMMETRIC_VERIFY_KEY_SIZE (QSC_DILITHIUM_PUBLICKEY_SIZE)

/*!
* \def QSMP_ASYMMETRIC_SIGNATURE_SIZE
* \brief The byte size of the asymmetric signature array
*/
#	define QSMP_ASYMMETRIC_SIGNATURE_SIZE (QSC_DILITHIUM_SIGNATURE_SIZE)

#elif defined(QSMP_CONFIG_SPHINCS_MCELIECE)

	/*!
	 * \def qsmp_cipher_generate_keypair
	 * \brief Generate an asymmetric cipher key-pair
	 */
#	define qsmp_cipher_generate_keypair qsc_mceliece_generate_keypair
	/*!
	 * \def qsmp_cipher_decapsulate
	 * \brief Decapsulate a shared-secret with the asymmetric cipher
	 */
#	define qsmp_cipher_decapsulate qsc_mceliece_decapsulate
	/*!
	 * \def qsmp_cipher_encapsulate
	 * \brief Encapsulate a shared-secret with the asymmetric cipher
	 */
#	define qsmp_cipher_encapsulate qsc_mceliece_encapsulate
	/*!
	 * \def qsmp_signature_generate_keypair
	 * \brief Generate an asymmetric signature key-pair
	 */
#	define qsmp_signature_generate_keypair qsc_sphincsplus_generate_keypair
	/*!
	 * \def qsmp_signature_sign
	 * \brief Sign a message with the asymmetric signature scheme
	 */
#	define qsmp_signature_sign qsc_sphincsplus_sign
	/*!
	 * \def qsmp_signature_verify
	 * \brief Verify a message with the asymmetric signature scheme
	 */
#	define qsmp_signature_verify qsc_sphincsplus_verify

/** \cond */
#	if defined(QSC_SPHINCSPLUS_S1S128SHAKERF) && defined(QSC_MCELIECE_S1N3488T64)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "sphincs-s1f_mceliece-s1_sha3_rcs";
#	elif defined(QSC_SPHINCSPLUS_S1S128SHAKERS) && defined(QSC_MCELIECE_S1N3488T64)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "sphincs-s1s_mceliece-s1_sha3_rcs";
#	elif defined(QSC_SPHINCSPLUS_S3S192SHAKERF) && defined(QSC_MCELIECE_S3N4608T96)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "sphincs-3f_mceliece-s3_sha3_rcs";
#	elif defined(QSC_SPHINCSPLUS_S3S192SHAKERS) && defined(QSC_MCELIECE_S3N4608T96)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "sphincs-3s_mceliece-s3_sha3_rcs";
#	elif defined(QSC_SPHINCSPLUS_S5S256SHAKERF) && defined(QSC_MCELIECE_S5N6688T128)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "sphincs-s5f_mceliece-s5_sha3_rcs";
#	elif defined(QSC_SPHINCSPLUS_S5S256SHAKERS) && defined(QSC_MCELIECE_S5N6688T128)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "sphincs-s5s_mceliece-s5_sha3_rcs";
#	elif defined(QSC_SPHINCSPLUS_S5S256SHAKERF) && defined(QSC_MCELIECE_S6N6960T119)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "sphincs-s5f_mceliece-s6_sha3_rcs";
#	elif defined(QSC_SPHINCSPLUS_S5S256SHAKERS) && defined(QSC_MCELIECE_S6N6960T119)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "sphincs-s5s_mceliece-s6_sha3_rcs";
#	elif defined(QSC_SPHINCSPLUS_S5S256SHAKERF) && defined(QSC_MCELIECE_S7N8192T128)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "sphincs-s5f_mceliece-s7_sha3_rcs";
#	elif defined(QSC_SPHINCSPLUS_S5S256SHAKERS) && defined(QSC_MCELIECE_S7N8192T128)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "sphincs-s5s_mceliece-s7_sha3_rcs";
#	else
#		error Invalid parameter set!
#	endif
/** \endcond */

/*!
* \def QSMP_ASYMMETRIC_CIPHER_TEXT_SIZE
* \brief The byte size of the cipher-text array
*/
#	define QSMP_ASYMMETRIC_CIPHER_TEXT_SIZE (QSC_MCELIECE_CIPHERTEXT_SIZE)

/*!
* \def QSMP_ASYMMETRIC_PRIVATE_KEY_SIZE
* \brief The byte size of the asymmetric cipher private-key array
*/
#	define QSMP_ASYMMETRIC_PRIVATE_KEY_SIZE (QSC_MCELIECE_PRIVATEKEY_SIZE)

/*!
* \def QSMP_ASYMMETRIC_PUBLIC_KEY_SIZE
* \brief The byte size of the asymmetric cipher public-key array
*/
#	define QSMP_ASYMMETRIC_PUBLIC_KEY_SIZE (QSC_MCELIECE_PUBLICKEY_SIZE)

/*!
* \def QSMP_ASYMMETRIC_SIGNING_KEY_SIZE
* \brief The byte size of the asymmetric signature signing-key array
*/
#	define QSMP_ASYMMETRIC_SIGNING_KEY_SIZE (QSC_SPHINCSPLUS_PRIVATEKEY_SIZE)

/*!
* \def QSMP_ASYMMETRIC_VERIFY_KEY_SIZE
* \brief The byte size of the asymmetric signature verification-key array
*/
#	define QSMP_ASYMMETRIC_VERIFY_KEY_SIZE (QSC_SPHINCSPLUS_PUBLICKEY_SIZE)

/*!
* \def QSMP_ASYMMETRIC_SIGNATURE_SIZE
* \brief The byte size of the asymmetric signature array
*/
#	define QSMP_ASYMMETRIC_SIGNATURE_SIZE (QSC_SPHINCSPLUS_SIGNATURE_SIZE)

#else
#	error invalid parameter set!
#endif

/* public key encoding constants */

/*!
* \def QSMP_SIGKEY_ENCODED_SIZE
* \brief The secret signature key size
*/
#define QSMP_SIGKEY_ENCODED_SIZE (QSMP_KEYID_SIZE + QSMP_TIMESTAMP_SIZE + QSMP_CONFIG_SIZE + QSMP_ASYMMETRIC_SIGNING_KEY_SIZE + QSMP_ASYMMETRIC_VERIFY_KEY_SIZE)

/*!
* \def QSMP_PUBKEY_HEADER_SIZE
* \brief The size of the QSMP public key header
*/
#define QSMP_PUBKEY_HEADER_SIZE 40U

/*!
* \def QSMP_PUBKEY_VERSION_SIZE
* \brief The size of the QSMP public key version string
*/
#define QSMP_PUBKEY_VERSION_SIZE 19U

/*!
* \def QSMP_PUBKEY_CONFIG_SIZE
* \brief The size of the QSMP public key configuration prefix
*/
#define QSMP_PUBKEY_CONFIG_SIZE 16

/*!
* \def QSMP_PUBKEY_KEYID_SIZE
* \brief The size of the QSMP public key identifier prefix
*/
#define QSMP_PUBKEY_KEYID_SIZE 10U

/*!
* \def QSMP_PUBKEY_EXPIRATION_SIZE
* \brief The size of the QSMP public key expiration prefix
*/
#define QSMP_PUBKEY_EXPIRATION_SIZE 13U

/*!
* \def QSMP_PUBKEY_FOOTER_SIZE
* \brief The size of the QSMP public key footer
*/
#define QSMP_PUBKEY_FOOTER_SIZE 38U

/*!
* \var QSMP_PUBKEY_HEADER
* \brief The QSMP public key header string
*/
static const char QSMP_PUBKEY_HEADER[QSMP_PUBKEY_HEADER_SIZE] = "------BEGIN QSMP PUBLIC KEY BLOCK------";

/*!
* \var QSMP_PUBKEY_VERSION
* \brief The QSMP public key version string
*/
static const char QSMP_PUBKEY_VERSION[QSMP_PUBKEY_VERSION_SIZE] = "Version: QSMP v1.2";

/*!
* \var QSMP_PUBKEY_CONFIG_PREFIX
* \brief The QSMP public key configuration prefix string
*/
static const char QSMP_PUBKEY_CONFIG_PREFIX[QSMP_PUBKEY_CONFIG_SIZE] = "Configuration: ";

/*!
* \var QSMP_PUBKEY_KEYID_PREFIX
* \brief The QSMP public key keyid prefix string
*/
static const char QSMP_PUBKEY_KEYID_PREFIX[QSMP_PUBKEY_KEYID_SIZE] = "Host ID: ";

/*!
* \var QSMP_PUBKEY_EXPIRATION_PREFIX
* \brief The QSMP public key expiration prefix string
*/
static const char QSMP_PUBKEY_EXPIRATION_PREFIX[QSMP_PUBKEY_EXPIRATION_SIZE] = "Expiration: ";

/*!
* \var QSMP_PUBKEY_FOOTER
* \brief The QSMP public key footer string
*/
static const char QSMP_PUBKEY_FOOTER[QSMP_PUBKEY_FOOTER_SIZE] = "------END QSMP PUBLIC KEY BLOCK------";

/* error code strings */

/*!
* \def QSMP_ERROR_STRING_DEPTH
* \brief The depth of the QSMP error string array
*/
#define QSMP_ERROR_STRING_DEPTH 29U

/*!
* \def QSMP_ERROR_STRING_WIDTH
* \brief The width of each QSMP error string
*/
#define QSMP_ERROR_STRING_WIDTH 128U

/** \cond */
static const char QSMP_ERROR_STRINGS[QSMP_ERROR_STRING_DEPTH][QSMP_ERROR_STRING_WIDTH] =
{
	"No error was detected",
	"The socket accept function returned an error",
	"The symmetric cipher had an authentication failure",
	"The keep alive check failed",
	"The communications channel has failed",
	"The device could not make a connection to the remote host",
	"The transmission failed at the KEX connection phase",
	"The asymmetric cipher failed to decapsulate the shared secret",
	"The decryption authentication has failed",
	"The transmission failed at the KEX establish phase",
	"The transmission failed at the KEX exchange phase",
	"The public - key hash is invalid",
	"The server has run out of socket connections",
	"The expected input was invalid",
	"The packet flag was unexpected",
	"The keep alive has expired with no response",
	"The decryption authentication has failed",
	"The QSMP public key has expired ",
	"The key identity is unrecognized",
	"The ratchet operation has failed",
	"The listener function failed to initialize",
	"The server has run out of memory",
	"The packet has valid time expired",
	"The packet was received out of sequence",
	"The random generator has failed",
	"The receiver failed at the network layer",
	"The transmitter failed at the network layer",
	"The protocol string was not recognized",
	"The expected data could not be verified",
};
/** \endcond */

/*!
* \def QSMP_MESSAGE_STRING_DEPTH
* \brief The depth of the QSMP message string array
*/
#define QSMP_MESSAGE_STRING_DEPTH 22U
/*!
* \def QSMP_MESSAGE_STRING_WIDTH
* \brief The width of each QSMP message string
*/
#define QSMP_MESSAGE_STRING_WIDTH 128U

/** \cond */
static const char QSMP_MESSAGE_STRINGS[QSMP_MESSAGE_STRING_DEPTH][QSMP_MESSAGE_STRING_WIDTH] =
{
	"The operation completed succesfully.",
	"The socket server accept function failed.",
	"The listener socket listener could not connect.",
	"The listener socket could not bind to the address.",
	"The listener socket could not be created.",
	"The server is connected to remote host: ",
	"The socket receive function failed.",
	"The server had a memory allocation failure.",
	"The key exchange has experienced a failure.",
	"The server has disconnected from the remote host: ",
	"The server has disconnected the client due to an error",
	"The server has had a socket level error: ",
	"The server has reached the maximum number of connections",
	"The server listener socket has failed.",
	"The server has run out of socket connections",
	"The message decryption has failed",
	"The keepalive function has failed",
	"The keepalive period has been exceeded",
	"The connection failed or was interrupted",
	"The function received an invalid request",
};
/** \endcond */

/*!
* \enum qsmp_configuration
* \brief The asymmetric cryptographic primitive configuration
*/
QSMP_EXPORT_API typedef enum qsmp_configuration
{
	qsmp_configuration_none = 0x00U,				/*!< No configuration was specified */
	qsmp_configuration_sphincs_mceliece = 0x01U,	/*!< The Sphincs+ and McEliece configuration */
	qsmp_configuration_dilithium_kyber = 0x02U,		/*!< The Dilithium and Kyber configuration */
	qsmp_configuration_dilithium_mceliece = 0x03U,	/*!< The Dilithium and Kyber configuration */
	qsmp_configuration_dilithium_ntru = 0x04U,		/*!< The Dilithium and NTRU configuration */
	qsmp_configuration_falcon_kyber = 0x05U,		/*!< The Falcon and Kyber configuration */
	qsmp_configuration_falcon_mceliece = 0x06U,		/*!< The Falcon and McEliece configuration */
	qsmp_configuration_falcon_ntru = 0x07U,			/*!< The Falcon and NTRU configuration */
} qsmp_configuration;

/*!
* \enum qsmp_messages
* \brief The logging message enumeration
*/
QSMP_EXPORT_API typedef enum qsmp_messages
{
	qsmp_messages_none = 0x00U,						/*!< No configuration was specified */
	qsmp_messages_accept_fail = 0x01U,				/*!< The socket accept failed */
	qsmp_messages_listen_fail = 0x02U,				/*!< The listener socket could not connect */
	qsmp_messages_bind_fail = 0x03U,				/*!< The listener socket could not bind to the address */
	qsmp_messages_create_fail = 0x04U,				/*!< The listener socket could not be created */
	qsmp_messages_connect_success = 0x05U,			/*!< The server connected to a host */
	qsmp_messages_receive_fail = 0x06U,				/*!< The socket receive function failed */
	qsmp_messages_allocate_fail = 0x07U,			/*!< The server memory allocation request has failed */
	qsmp_messages_kex_fail = 0x08U,					/*!< The key exchange has experienced a failure */
	qsmp_messages_disconnect = 0x09U,				/*!< The server has disconnected the client */
	qsmp_messages_disconnect_fail = 0x0AU,			/*!< The server has disconnected the client due to an error */
	qsmp_messages_socket_message = 0x0BU,			/*!< The server has had a socket level error */
	qsmp_messages_queue_empty = 0x0CU,				/*!< The server has reached the maximum number of connections */
	qsmp_messages_listener_fail = 0x0DU,			/*!< The server listener socket has failed */
	qsmp_messages_sockalloc_fail = 0x0EU,			/*!< The server has run out of socket connections */
	qsmp_messages_decryption_fail = 0x0FU,			/*!< The message decryption has failed */
	qsmp_messages_keepalive_fail = 0x10U,			/*!< The keepalive function has failed */
	qsmp_messages_keepalive_timeout = 0x11U,		/*!< The keepalive period has been exceeded */
	qsmp_messages_connection_fail = 0x12U,			/*!< The connection failed or was interrupted */
	qsmp_messages_invalid_request = 0x13U,			/*!< The function received an invalid request */
} qsmp_messages;

/*!
* \enum qsmp_errors
* \brief The QSMP error values
*/
QSMP_EXPORT_API typedef enum qsmp_errors
{
	qsmp_error_none = 0x00U,						/*!< No error was detected */
	qsmp_error_accept_fail = 0x01U,					/*!< The socket accept function returned an error */
	qsmp_error_authentication_failure = 0x02U,		/*!< The symmetric cipher had an authentication failure */
	qsmp_error_bad_keep_alive = 0x03U,				/*!< The keep alive check failed */
	qsmp_error_channel_down = 0x04U,				/*!< The communications channel has failed */
	qsmp_error_connection_failure = 0x05U,			/*!< The device could not make a connection to the remote host */
	qsmp_error_connect_failure = 0x06U,				/*!< The transmission failed at the KEX connection phase */
	qsmp_error_decapsulation_failure = 0x07U,		/*!< The asymmetric cipher failed to decapsulate the shared secret */
	qsmp_error_decryption_failure = 0x08U,			/*!< The decryption authentication has failed */
	qsmp_error_establish_failure = 0x09U,			/*!< The transmission failed at the KEX establish phase */
	qsmp_error_exchange_failure = 0x0AU,			/*!< The transmission failed at the KEX exchange phase */
	qsmp_error_hash_invalid = 0x0BU,				/*!< The public-key hash is invalid */
	qsmp_error_hosts_exceeded = 0x0CU,				/*!< The server has run out of socket connections */
	qsmp_error_invalid_input = 0x0DU,				/*!< The expected input was invalid */
	qsmp_error_invalid_request = 0x0EU,				/*!< The packet flag was unexpected */
	qsmp_error_keepalive_expired = 0x0FU,			/*!< The keep alive has expired with no response */
	qsmp_error_keepalive_timeout = 0x10U,			/*!< The decryption authentication has failed */
	qsmp_error_key_expired = 0x11U,					/*!< The QSMP public key has expired  */
	qsmp_error_key_unrecognized = 0x12U,			/*!< The key identity is unrecognized */
	qsmp_error_keychain_fail = 0x13U,				/*!< The ratchet operation has failed */
	qsmp_error_listener_fail = 0x14U,				/*!< The listener function failed to initialize */
	qsmp_error_memory_allocation = 0x15U,			/*!< The server has run out of memory */
	qsmp_error_message_time_invalid = 0x06U,		/*!< The packet has valid time expired */
	qsmp_error_packet_unsequenced = 0x17U,			/*!< The packet was received out of sequence */
	qsmp_error_random_failure = 0x18U,				/*!< The random generator has failed */
	qsmp_error_receive_failure = 0x19U,				/*!< The receiver failed at the network layer */
	qsmp_error_transmit_failure = 0x1AU,			/*!< The transmitter failed at the network layer */
	qsmp_error_unknown_protocol = 0x1BU,			/*!< The protocol string was not recognized */
	qsmp_error_verify_failure = 0x1CU,				/*!< The expected data could not be verified */
} qsmp_errors;

/*!
* \enum qsmp_flags
* \brief The QSMP packet flags
*/
QSMP_EXPORT_API typedef enum qsmp_flags
{
	qsmp_flag_none = 0x00U,							/*!< No flag was specified */
	qsmp_flag_connect_request = 0x01U,				/*!< The QSMP key-exchange client connection request flag  */
	qsmp_flag_connect_response = 0x02U,				/*!< The QSMP key-exchange server connection response flag */
	qsmp_flag_connection_terminate = 0x03U,			/*!< The connection is to be terminated */
	qsmp_flag_encrypted_message = 0x04U,			/*!< The message has been encrypted flag */
	qsmp_flag_exstart_request = 0x05U,				/*!< The QSMP key-exchange client exstart request flag */
	qsmp_flag_exstart_response = 0x06U,				/*!< The QSMP key-exchange server exstart response flag */
	qsmp_flag_exchange_request = 0x07U,				/*!< The QSMP key-exchange client exchange request flag */
	qsmp_flag_exchange_response = 0x08U,			/*!< The QSMP key-exchange server exchange response flag */
	qsmp_flag_establish_request = 0x09U,			/*!< The QSMP key-exchange client establish request flag */
	qsmp_flag_establish_response = 0x0AU,			/*!< The QSMP key-exchange server establish response flag */
	qsmp_flag_keep_alive_request = 0x0BU,			/*!< The packet contains a keep alive request */
	qsmp_flag_keep_alive_response = 0x0CU,			/*!< The packet contains a keep alive response */
	qsmp_flag_remote_connected = 0x0DU,				/*!< The remote host is connected flag */
	qsmp_flag_remote_terminated = 0x0EU,			/*!< The remote host has terminated the connection */
	qsmp_flag_session_established = 0x0FU,			/*!< The exchange is in the established state */
	qsmp_flag_session_establish_verify = 0x10U,		/*!< The exchange is in the established verify state */
	qsmp_flag_unrecognized_protocol = 0x11U,		/*!< The protocol string is not recognized */
	qsmp_flag_asymmetric_ratchet_request = 0x12U,	/*!< The host has received a asymmetric key ratchet request */
	qsmp_flag_asymmetric_ratchet_response = 0x13U,	/*!< The host has received a asymmetric key ratchet request */
	qsmp_flag_symmetric_ratchet_request = 0x14U,	/*!< The host has received a symmetric key ratchet request */
	qsmp_flag_transfer_request = 0x15U,				/*!< Reserved - The host has received a transfer request */
	qsmp_flag_error_condition = 0xFFU,				/*!< The connection experienced an error */
} qsmp_flags;

/*!
* \enum qsmp_mode
* \brief The QSMP mode enumeration
*/
QSMP_EXPORT_API typedef enum qsmp_mode
{
	qsmp_mode_simplex = 0x00U,
	qsmp_mode_duplex = 0x01U,
} qsmp_mode;

/*!
* \struct qsmp_asymmetric_cipher_keypair
* \brief The QSMP asymmetric cipher key container
*/
QSMP_EXPORT_API typedef struct qsmp_asymmetric_cipher_keypair
{
	uint8_t* prikey;
	uint8_t* pubkey;
} qsmp_asymmetric_cipher_keypair;

/*!
* \struct qsmp_asymmetric_signature_keypair
* \brief The QSMP asymmetric signature key container
*/
QSMP_EXPORT_API typedef struct qsmp_asymmetric_signature_keypair
{
	uint8_t* sigkey;
	uint8_t* verkey;
} qsmp_asymmetric_signature_keypair;

/*!
* \struct qsmp_network_packet
* \brief The QSMP packet structure
*/
QSMP_EXPORT_API typedef struct qsmp_network_packet
{
	uint8_t flag;									/*!< The packet flag */
	uint32_t msglen;								/*!< The packets message length */
	uint64_t sequence;								/*!< The packet sequence number */
	uint64_t utctime;								/*!< The UTC time the packet was created in seconds */
	uint8_t* pmessage;								/*!< A pointer to the packets message buffer */
} qsmp_network_packet;

/*!
* \struct qsmp_client_verification_key
* \brief The QSMP client key structure
*/
QSMP_EXPORT_API typedef struct qsmp_client_verification_key
{
	uint64_t expiration;							/*!< The expiration time, in seconds from epoch */
	uint8_t config[QSMP_CONFIG_SIZE];				/*!< The primitive configuration string */
	uint8_t keyid[QSMP_KEYID_SIZE];					/*!< The key identity string */
	uint8_t verkey[QSMP_ASYMMETRIC_VERIFY_KEY_SIZE];/*!< The asymmetric signatures verification-key */
} qsmp_client_verification_key;

/*!
* \struct qsmp_server_signature_key
* \brief The QSMP server key structure
*/
QSMP_EXPORT_API typedef struct qsmp_server_signature_key
{
	uint64_t expiration;							/*!< The expiration time, in seconds from epoch */
	uint8_t config[QSMP_CONFIG_SIZE];				/*!< The primitive configuration string */
	uint8_t keyid[QSMP_KEYID_SIZE];					/*!< The key identity string */
	uint8_t sigkey[QSMP_ASYMMETRIC_SIGNING_KEY_SIZE];/*!< The asymmetric signature signing-key */
	uint8_t verkey[QSMP_ASYMMETRIC_VERIFY_KEY_SIZE]; /*!< The asymmetric signature verification-key */
} qsmp_server_signature_key;

/*!
* \struct qsmp_keepalive_state
* \brief The QSMP keep alive state structure
*/
QSMP_EXPORT_API typedef struct qsmp_keepalive_state
{
	qsc_socket target;								/*!< The target socket structure */
	uint64_t etime;									/*!< The keep alive epoch time  */
	uint64_t seqctr;								/*!< The keep alive packet sequence counter  */
	bool recd;										/*!< The keep alive response received status  */
} qsmp_keepalive_state;

/*!
* \struct qsmp_connection_state
* \brief The QSMP socket connection state structure
*/
QSMP_EXPORT_API typedef struct qsmp_connection_state
{
	uint8_t rtcs[QSMP_DUPLEX_SYMMETRIC_KEY_SIZE];	/*!< The ratchet key generation state */
	qsc_socket target;								/*!< The target socket structure */
	qsc_rcs_state rxcpr;							/*!< The receive channel cipher state */
	qsc_rcs_state txcpr;							/*!< The transmit channel cipher state */
	uint64_t rxseq;									/*!< The receive channels packet sequence number  */
	uint64_t txseq;									/*!< The transmit channels packet sequence number  */
	uint32_t cid;									/*!< The connections instance count */
	qsmp_flags exflag;								/*!< The KEX position flag */
	bool receiver;									/*!< The instance was initialized in listener mode */
	qsmp_mode mode;									/*!< The QSMP operations mode */
} qsmp_connection_state;

/*!
* \brief Dispose of an asymmetric cipher keypair
*
* \param keypair: A pointer to the cipher keypair
*/
QSMP_EXPORT_API void qsmp_asymmetric_cipher_keypair_dispose(qsmp_asymmetric_cipher_keypair* keypair);

/*!
* \brief Initialize an asymmetric cipher keypair
*
* \return Returns a pointer to an asymmetric cipher keypair
*/
QSMP_EXPORT_API qsmp_asymmetric_cipher_keypair* qsmp_asymmetric_cipher_keypair_initialize(void);

/*!
* \brief Dispose of an asymmetric signature keypair
*
* \param keypair: A pointer to the signature keypair
*/
QSMP_EXPORT_API void qsmp_asymmetric_signature_keypair_dispose(qsmp_asymmetric_signature_keypair* keypair);

/*!
* \brief Initialize an asymmetric signature keypair
*
* \return Returns a pointer to an asymmetric signature keypair
*/
QSMP_EXPORT_API qsmp_asymmetric_signature_keypair* qsmp_asymmetric_signature_keypair_initialize(void);

/*!
* \brief Close the network connection between hosts
*
* \param cns: A pointer to the connection state structure
* \param err: The error message
* \param notify: Notify the remote host connection is closing
*/
QSMP_EXPORT_API void qsmp_connection_close(qsmp_connection_state* cns, qsmp_errors err, bool notify);

/*!
* \brief Reset the connection state
*
* \param cns: A pointer to the connection state structure
*/
QSMP_EXPORT_API void qsmp_connection_state_dispose(qsmp_connection_state* cns);

/*!
* \brief Return a pointer to a string description of an error code
*
* \param error: The error type
* 
* \return Returns a pointer to an error string or NULL
*/
QSMP_EXPORT_API const char* qsmp_error_to_string(qsmp_errors error);

/*!
* \brief Populate a packet header and set the creation time
*
* \param packetout: A pointer to the output packet structure
* \param flag: The packet flag
* \param sequence: The packet sequence number
* \param msglen: The length of the message array
*/
QSMP_EXPORT_API void qsmp_header_create(qsmp_network_packet* packetout, qsmp_flags flag, uint64_t sequence, uint32_t msglen);

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
QSMP_EXPORT_API qsmp_errors qsmp_header_validate(qsmp_connection_state* cns, const qsmp_network_packet* packetin, qsmp_flags kexflag, qsmp_flags pktflag, uint64_t sequence, uint32_t msglen);

/*!
* \brief Generate a QSMP key-pair; generates the public and private asymmetric signature keys.
*
* \param pubkey: The public key, distributed to clients
* \param prikey: The private key, a secret key known only by the server
* \param keyid: [const] The key identity string
*/
QSMP_EXPORT_API void qsmp_generate_keypair(qsmp_client_verification_key* pubkey, qsmp_server_signature_key* prikey, const uint8_t keyid[QSMP_KEYID_SIZE]);

/*!
* \brief Get the error string description
*
* \param emsg: The message enumeration
* 
* \return Returns a pointer to the message string or NULL
*/
QSMP_EXPORT_API const char* qsmp_get_error_description(qsmp_messages emsg);

/*!
* \brief Log the message, socket error, and string description
*
* \param emsg: The message enumeration
* \param err: The socket exception enumeration
* \param msg: [const] The message string
*/
QSMP_EXPORT_API void qsmp_log_error(qsmp_messages emsg, qsc_socket_exceptions err, const char* msg);

/*!
* \brief Log a message
*
* \param emsg: The message enumeration
*/
QSMP_EXPORT_API void qsmp_log_message(qsmp_messages emsg);

/*!
* \brief Log a message and description
*
* \param emsg: The message enumeration
* \param msg: [const] The message string
*/
QSMP_EXPORT_API void qsmp_log_write(qsmp_messages emsg, const char* msg);

/*!
* \brief Clear a packet's state
*
* \param packet: A pointer to the packet structure
*/
QSMP_EXPORT_API void qsmp_packet_clear(qsmp_network_packet* packet);

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
QSMP_EXPORT_API qsmp_errors qsmp_packet_decrypt(qsmp_connection_state* cns, uint8_t* message, size_t* msglen, const qsmp_network_packet* packetin);

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
QSMP_EXPORT_API qsmp_errors qsmp_packet_encrypt(qsmp_connection_state* cns, qsmp_network_packet* packetout, const uint8_t* message, size_t msglen);

/*!
* \brief Populate a packet structure with an error message
*
* \param packet: A pointer to the packet structure
* \param error: The error type
*/
QSMP_EXPORT_API void qsmp_packet_error_message(qsmp_network_packet* packet, qsmp_errors error);

/*!
* \brief Deserialize a byte array to a packet header
*
* \param packet: [const] The header byte array to deserialize
* \param header: A pointer to the packet structure
*/
QSMP_EXPORT_API void qsmp_packet_header_deserialize(const uint8_t* header, qsmp_network_packet* packet);

/*!
* \brief Serialize a packet header to a byte array
*
* \param packet: [const] A pointer to the packet structure to serialize
* \param header: The header byte array
*/
QSMP_EXPORT_API void qsmp_packet_header_serialize(const qsmp_network_packet* packet, uint8_t* header);

/*!
* \brief Sets the local UTC seconds time in the packet header
*
* \param packet: A pointer to a network packet
*/
QSMP_EXPORT_API void qsmp_packet_set_utc_time(qsmp_network_packet* packet);

/*!
* \brief Checks the local UTC seconds time against the packet sent time for validity within the packet time threshold
*
* \param packet: [const] A pointer to a network packet
*
* \return Returns true if the packet was received within the valid-time threhold
*/
QSMP_EXPORT_API bool qsmp_packet_time_valid(const qsmp_network_packet* packet);

/*!
* \brief Serialize a packet to a byte array
*
* \param packet: [const] The header byte array to deserialize
* \param pstream: A pointer to the packet structure
* 
* \return Returns the size of the byte stream
*/
QSMP_EXPORT_API size_t qsmp_packet_to_stream(const qsmp_network_packet* packet, uint8_t* pstream);

/*!
* \brief Compares two public keys for equality
*
* \param a: [const] The first public key
* \param b: [const] The second public key
*
* \return Returns true if the certificates are identical
*/
QSMP_EXPORT_API bool qsmp_public_key_compare(const qsmp_client_verification_key* a, const qsmp_client_verification_key* b);

/*!
* \brief Decode a public key string and populate a client key structure
*
* \param pubk: A pointer to the output client key
* \param enck: [const] The input encoded key
*
* \return: Returns true for success
*/
QSMP_EXPORT_API bool qsmp_public_key_decode(qsmp_client_verification_key* pubk, const char* enck, size_t enclen);

/*!
* \brief Encode a public key structure and copy to a string
*
* \param enck: The output encoded public key string
* \param enclen: The length of the encoding array
* \param pubk: [const] A pointer to the public key structure
*
* \return: Returns the encoded string length
*/
QSMP_EXPORT_API size_t qsmp_public_key_encode(char* enck, size_t enclen, const qsmp_client_verification_key* pubk);

/*!
* \brief Get the key encoding string size
*
* \return Returns the size of the encoded string
*/
QSMP_EXPORT_API size_t qsmp_public_key_encoding_size(void);

/*!
* \brief Decode a secret signature key structure and copy to an array
*
* \param kset: A pointer to the output server key structure
* \param serk: [const] The input encoded secret key string
*/
QSMP_EXPORT_API void qsmp_signature_key_deserialize(qsmp_server_signature_key* kset, const uint8_t serk[QSMP_SIGKEY_ENCODED_SIZE]);

/*!
* \brief Encode a secret key structure and copy to a string
*
* \param serk: The output encoded public key string
* \param kset: [const] A pointer to the secret server key structure
*/
QSMP_EXPORT_API void qsmp_signature_key_serialize(uint8_t serk[QSMP_SIGKEY_ENCODED_SIZE], const qsmp_server_signature_key* kset);

/*!
* \brief Deserialize a byte array to a packet
*
* \param pstream: [const] The header byte array to deserialize
* \param packet: A pointer to the packet structure
*/
QSMP_EXPORT_API void qsmp_stream_to_packet(const uint8_t* pstream, qsmp_network_packet* packet);

#if defined (QSMP_DEBUG_MODE)
/*!
* \brief Test the certificate encoding and decoding functions
*
* \return Returns true if the encoding tests succeed
*/
QSMP_EXPORT_API bool qsmp_certificate_encoding_test(void);
#endif

#endif

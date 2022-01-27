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
 * \brief <b>QSMP support header</b> \n
 * Common parameters and functions of the qsmp client and server implementations.
 *
 * \author		John G. Underhill
 * \version		1.0.0.0b
 * \date		February 1, 2021
 * \updated		January 25, 2022
 * \contact:	develop@dfdef.com
 *
 * \remarks
 * \section Param Sets:
 * kyber-dilithium-rcs256-shake256
 * mceliece-dilithium-rcs256-shake256
 * ntru-dilithium-rcs256-shake256
 * mceliece-sphincs-rcs256-shake256
 */

#ifndef QSMP_H
#define QSMP_H

 /*!
 * \def QSMP_CONFIG_DILITHIUM_KYBER
 * \brief Sets the asymmetric cryptographic primitive-set to Dilithium/Kyber.
 */
//#define QSMP_CONFIG_DILITHIUM_KYBER

 /*!
 * \def QSMP_CONFIG_DILITHIUM_MCELIECE
 * \brief Sets the asymmetric cryptographic primitive-set to Dilithium/McEliece.
 */
//#define QSMP_CONFIG_DILITHIUM_MCELIECE

 /*!
 * \def QSMP_CONFIG_DILITHIUM_NTRU
 * \brief Sets the asymmetric cryptographic primitive-set to Dilithium/NTRU.
 */
#define QSMP_CONFIG_DILITHIUM_NTRU

// not currently implemented
 /*!
 * \def QSMP_CONFIG_FALCON_KYBER
 * \brief Sets the asymmetric cryptographic primitive-set to Falcon/Kyber.
 */
//#define QSMP_CONFIG_FALCON_KYBER

 /*!
 * \def QSMP_CONFIG_FALCON_MCELIECE
 * \brief Sets the asymmetric cryptographic primitive-set to Falcon/McEliece.
 */
//#define QSMP_CONFIG_FALCON_MCELIECE

 /*!
 * \def QSMP_CONFIG_FALCON_NTRU
 * \brief Sets the asymmetric cryptographic primitive-set to Falcon/NTRU.
 */
//#define QSMP_CONFIG_FALCON_NTRU

 /*!
 * \def QSMP_CONFIG_SPHINCS_MCELIECE
 * \brief Sets the asymmetric cryptographic primitive-set to Sphincs+/McEliece, default is Dilithium/Kyber.
 * Note: You may have to increase the stack reserve size on both projects, McEliece and Sphincs+ use a lot of resources.
 */
//#define QSMP_CONFIG_SPHINCS_MCELIECE

#include "common.h"

#if defined(QSMP_CONFIG_DILITHIUM_KYBER)
#	include "../QSC/dilithium.h"
#	include "../QSC/kyber.h"
#elif defined(QSMP_CONFIG_DILITHIUM_NTRU)
#	include "../QSC/dilithium.h"
#	include "../QSC/ntru.h"
#elif defined(QSMP_CONFIG_DILITHIUM_MCELIECE)
#	include "../QSC/dilithium.h"
#	include "../QSC/mceliece.h"
#elif defined(QSMP_CONFIG_FALCON_KYBER)
#	include "../QSC/falcon.h"
#	include "../QSC/kyber.h"
#elif defined(QSMP_CONFIG_FALCON_MCELIECE)
#	include "../QSC/falcon.h"
#	include "../QSC/mceliece.h"
#elif defined(QSMP_CONFIG_FALCON_NTRU)
#	include "../QSC/falcon.h"
#	include "../QSC/ntru.h"
#elif defined(QSMP_CONFIG_SPHINCS_MCELIECE)
#	include "../QSC/sphincsplus.h"
#	include "../QSC/mceliece.h"
#else
#	error Invalid parameter set!
#endif

#if defined(QSMP_CONFIG_FALCON_KYBER) || defined(QSMP_CONFIG_FALCON_MCELIECE) || defined(QSMP_CONFIG_FALCON_NTRU)
#define QSMP_FALCON_SIGNATURE
#endif

/*!
* \def QSMP_SERVER_PORT
* \brief The default server port address
*/
#define QSMP_SERVER_PORT 3119

/*!
* \def QSMP_CONFIG_SIZE
* \brief The size of the protocol configuration string
*/
#define QSMP_CONFIG_SIZE 48

/*!
* \def QSMP_CONFIG_STRING
* \brief The QSMP cryptographic primitive configuration string
*/
#if defined(QSMP_CONFIG_DILITHIUM_KYBER)
#	if defined(QSC_DILITHIUM_S2N256Q8380417K4)
#		if defined(QSC_KYBER_S3Q3329N256K3)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "dilithium-s2_kyber-s3_sha3-256_rcs-256";
#		elif defined(QSC_KYBER_S5Q3329N256K4)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "dilithium-s2_kyber-s5_sha3-256_rcs-256";
#		elif defined(QSC_KYBER_S6Q3329N256K5)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "dilithium-s2_kyber-s6_sha3-256_rcs-256";
#		else
#			error Invalid parameter set!
#		endif
#	elif defined(QSC_DILITHIUM_S3N256Q8380417K6)
#		if defined(QSC_KYBER_S3Q3329N256K3)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "dilithium-s3_kyber-s3_sha3-256_rcs-256";
#		elif defined(QSC_KYBER_S5Q3329N256K4)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "dilithium-s3_kyber-s5_sha3-256_rcs-256";
#		elif defined(QSC_KYBER_S6Q3329N256K5)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "dilithium-s3_kyber-s6_sha3-256_rcs-256";
#		else
#			error Invalid parameter set!
#		endif
#	elif defined(QSC_DILITHIUM_S5N256Q8380417K8)
#		if defined(QSC_KYBER_S3Q3329N256K3)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "dilithium-s5_kyber-s3_sha3-256_rcs-256";
#		elif defined(QSC_KYBER_S5Q3329N256K4)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "dilithium-s5_kyber-s5_sha3-256_rcs-256";
#		elif defined(QSC_KYBER_S6Q3329N256K5)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "dilithium-s5_kyber-s6_sha3-256_rcs-256";
#		else
#			error Invalid parameter set!
#		endif
#	else
#		error Invalid parameter set!
#	endif
#elif defined(QSMP_CONFIG_DILITHIUM_NTRU)
#	if defined(QSC_DILITHIUM_S2N256Q8380417K4)
#		if defined(QSC_NTRU_S1HPS2048509)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "dilithium-s2_ntru-s1_sha3-256_rcs-256";
#		elif defined(QSC_NTRU_HPSS32048677)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "dilithium-s2_ntru-s3_sha3-256_rcs-256";
#		elif defined(QSC_NTRU_S5HPS4096821)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "dilithium-s2_ntru-s5ps_sha3-256_rcs-256";
#		elif defined(QSC_NTRU_S5HRSS701)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "dilithium-s2_ntru-s5ss_sha3-256_rcs-256";
#		else
#			error Invalid parameter set!
#		endif
#	elif defined(QSC_DILITHIUM_S3N256Q8380417K6)
#		if defined(QSC_NTRU_S1HPS2048509)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "dilithium-s3_ntru-s1_sha3-256_rcs-256";
#		elif defined(QSC_NTRU_HPSS32048677)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "dilithium-s3_ntru-s3_sha3-256_rcs-256";
#		elif defined(QSC_NTRU_S5HPS4096821)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "dilithium-s3_ntru-s5ps_sha3-256_rcs-256";
#		elif defined(QSC_NTRU_S5HRSS701)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "dilithium-s3_ntru-s5ss_sha3-256_rcs-256";
#		else
#			error Invalid parameter set!
#		endif
#	elif defined(QSC_DILITHIUM_S5N256Q8380417K8)
#		if defined(QSC_NTRU_S1HPS2048509)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "dilithium-s5_ntru-s1_sha3-256_rcs-256";
#		elif defined(QSC_NTRU_HPSS32048677)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "dilithium-s5_ntru-s3_sha3-256_rcs-256";
#		elif defined(QSC_NTRU_S5HPS4096821)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "dilithium-s5_ntru-s5ps_sha3-256_rcs-256";
#		elif defined(QSC_NTRU_S5HRSS701)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "dilithium-s5_ntru-s5ss_sha3-256_rcs-256";
#		else
#			error Invalid parameter set!
#		endif
#	else
#		error Invalid parameter set!
#	endif
#elif defined(QSMP_CONFIG_DILITHIUM_MCELIECE)
#	if defined(QSC_DILITHIUM_S2N256Q8380417K4)
#		if defined(QSC_MCELIECE_S3N4608T96)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "dilithium-s2_mceliece-s3_sha3-256_rcs-256";
#		elif defined(QSC_MCELIECE_S5N6688T128)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "dilithium-s2_mceliece-s5a_sha3-256_rcs-256";
#		elif defined(QSC_MCELIECE_S5N6960T119)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "dilithium-s2_mceliece-s5b_sha3-256_rcs-256";
#		elif defined(QSC_MCELIECE_S5N8192T128)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "dilithium-s2_mceliece-s5c_sha3-256_rcs-256";
#		else
#			error Invalid parameter set!
#		endif
#	elif defined(QSC_DILITHIUM_S3N256Q8380417K6)
#		if defined(QSC_MCELIECE_S3N4608T96)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "dilithium-s3_mceliece-s3_sha3-256_rcs-256";
#		elif defined(QSC_MCELIECE_S5N6688T128)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "dilithium-s3_mceliece-s5a_sha3-256_rcs-256";
#		elif defined(QSC_MCELIECE_S5N6960T119)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "dilithium-s3_mceliece-s5b_sha3-256_rcs-256";
#		elif defined(QSC_MCELIECE_S5N8192T128)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "dilithium-s3_mceliece-s5c_sha3-256_rcs-256";
#		else
#			error Invalid parameter set!
#		endif
#	elif defined(QSC_DILITHIUM_S5N256Q8380417K8)
#		if defined(QSC_MCELIECE_S3N4608T96)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "dilithium-s5_mceliece-s3_sha3-256_rcs-256";
#		elif defined(QSC_MCELIECE_S5N6688T128)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "dilithium-s5_mceliece-s5a_sha3-256_rcs-256";
#		elif defined(QSC_MCELIECE_S5N6960T119)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "dilithium-s5_mceliece-s5b_sha3-256_rcs-256";
#		elif defined(QSC_MCELIECE_S5N8192T128)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "dilithium-s5_mceliece-s5c_sha3-256_rcs-256";
#		else
#			error Invalid parameter set!
#		endif
#	else
#		error Invalid parameter set!
#	endif
#elif defined(QSMP_CONFIG_FALCON_KYBER)
#	if defined(QSC_FALCON_S3SHAKE256F512)
#		if defined(QSC_KYBER_S3Q3329N256K3)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "falcon-s3_kyber-s3_sha3-256_rcs-256";
#		elif defined(QSC_KYBER_S5Q3329N256K4)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "falcon-s3_kyber-s5_sha3-256_rcs-256";
#		elif defined(QSC_KYBER_S6Q3329N256K5)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "falcon-s3_kyber-s6_sha3-256_rcs-256";
#		else
#			error Invalid parameter set!
#		endif
#	elif defined(QSC_FALCON_S5SHAKE256F1024)
#		if defined(QSC_KYBER_S3Q3329N256K3)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "falcon-s5_kyber-s3_sha3-256_rcs-256";
#		elif defined(QSC_KYBER_S5Q3329N256K4)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "falcon-s5_kyber-s5_sha3-256_rcs-256";
#		elif defined(QSC_KYBER_S6Q3329N256K5)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "falcon-s5_kyber-s6_sha3-256_rcs-256";
#		else
#			error Invalid parameter set!
#		endif
#	else
#		error Invalid parameter set!
#	endif
#elif defined(QSMP_CONFIG_FALCON_MCELIECE)
#	if defined(QSC_FALCON_S3SHAKE256F512)
#		if defined(QSC_MCELIECE_S3N4608T96)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "falcon-s3_mceliece-s3_sha3-256_rcs-256";
#		elif defined(QSC_MCELIECE_S5N6688T128)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "falcon-s3_mceliece-s5a_sha3-256_rcs-256";
#		elif defined(QSC_MCELIECE_S5N6960T119)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "falcon-s3_mceliece-s5b_sha3-256_rcs-256";
#		elif defined(QSC_MCELIECE_S5N8192T128)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "falcon-s3_mceliece-s5c_sha3-256_rcs-256";
#		else
#			error Invalid parameter set!
#		endif
#	elif defined(QSC_FALCON_S5SHAKE256F1024)
#		if defined(QSC_MCELIECE_S3N4608T96)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "falcon-s5_mceliece-s3_sha3-256_rcs-256";
#		elif defined(QSC_MCELIECE_S5N6688T128)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "falcon-s5_mceliece-s5a_sha3-256_rcs-256";
#		elif defined(QSC_MCELIECE_S5N6960T119)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "falcon-s5_mceliece-s5b_sha3-256_rcs-256";
#		elif defined(QSC_MCELIECE_S5N8192T128)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "falcon-s5_mceliece-s5c_sha3-256_rcs-256";
#		else
#			error Invalid parameter set!
#		endif
#	else
#		error Invalid parameter set!
#	endif
#elif defined(QSMP_CONFIG_FALCON_NTRU)
#	if defined(QSC_FALCON_S3SHAKE256F512)
#		if defined(QSC_NTRU_S1HPS2048509)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "falcon-s3_ntru-s1_sha3-256_rcs-256";
#		elif defined(QSC_NTRU_HPSS32048677)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "falcon-s3_ntru-s3_sha3-256_rcs-256";
#		elif defined(QSC_NTRU_S5HPS4096821)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "falcon-s3_ntru-s5ps_sha3-256_rcs-256";
#		elif defined(QSC_NTRU_S5HRSS701)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "falcon-s3_ntru-s5ss_sha3-256_rcs-256";
#		else
#			error Invalid parameter set!
#		endif
#	elif defined(QSC_FALCON_S5SHAKE256F1024)
#		if defined(QSC_NTRU_S1HPS2048509)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "falcon-s5_ntru-s1_sha3-256_rcs-256";
#		elif defined(QSC_NTRU_HPSS32048677)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "falcon-s5_ntru-s3_sha3-256_rcs-256";
#		elif defined(QSC_NTRU_S5HPS4096821)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "falcon-s5_ntru-s5ps_sha3-256_rcs-256";
#		elif defined(QSC_NTRU_S5HRSS701)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "falcon-s5_ntru-s5ss_sha3-256_rcs-256";
#		else
#			error Invalid parameter set!
#		endif
#	else
#		error Invalid parameter set!
#	endif
#elif defined(QSMP_CONFIG_SPHINCS_MCELIECE)
#	if defined(QSC_SPHINCSPLUS_S3S192SHAKERS)
#		if defined(QSC_MCELIECE_S3N4608T96)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "sphincs-s3s_mceliece-s3_sha3-256_rcs-256";
#		elif defined(QSC_MCELIECE_S5N6688T128)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "sphincs-s3s_mceliece-s5a_sha3-256_rcs-256";
#		elif defined(QSC_MCELIECE_S5N6960T119)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "sphincs-s3s_mceliece-s5b_sha3-256_rcs-256";
#		elif defined(QSC_MCELIECE_S5N8192T128)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "sphincs-s3s_mceliece-s5c_sha3-256_rcs-256";
#		else
#			error Invalid parameter set!
#		endif
#	elif defined(QSC_SPHINCSPLUS_S3S192SHAKERF)
#		if defined(QSC_MCELIECE_S3N4608T96)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "sphincs-s3f_mceliece-s3_sha3-256_rcs-256";
#		elif defined(QSC_MCELIECE_S5N6688T128)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "sphincs-s3f_mceliece-s5a_sha3-256_rcs-256";
#		elif defined(QSC_MCELIECE_S5N6960T119)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "sphincs-s3f_mceliece-s5b_sha3-256_rcs-256";
#		elif defined(QSC_MCELIECE_S5N8192T128)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "sphincs-s35_mceliece-s5c_sha3-256_rcs-256";
#		else
#			error Invalid parameter set!
#		endif
#	elif defined(QSC_SPHINCSPLUS_S5S256SHAKERS)
#		if defined(QSC_MCELIECE_S3N4608T96)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "sphincs-s5s_mceliece-s3_sha3-256_rcs-256";
#		elif defined(QSC_MCELIECE_S5N6688T128)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "sphincs-s5s_mceliece-s5a_sha3-256_rcs-256";
#		elif defined(QSC_MCELIECE_S5N6960T119)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "sphincs-s5s_mceliece-s5b_sha3-256_rcs-256";
#		elif defined(QSC_MCELIECE_S5N8192T128)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "sphincs-s5s_mceliece-s5c_sha3-256_rcs-256";
#		else
#			error Invalid parameter set!
#		endif
#	elif defined(QSC_SPHINCSPLUS_S5S256SHAKERF)
#		if defined(QSC_MCELIECE_S3N4608T96)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "sphincs-s5f_mceliece-s3_sha3-256_rcs-256";
#		elif defined(QSC_MCELIECE_S5N6688T128)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "sphincs-s5f_mceliece-s5a_sha3-256_rcs-256";
#		elif defined(QSC_MCELIECE_S5N6960T119)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "sphincs-s5f_mceliece-s5b_sha3-256_rcs-256";
#		elif defined(QSC_MCELIECE_S5N8192T128)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "sphincs-s5f_mceliece-s5c_sha3-256_rcs-256";
#		else
#			error Invalid parameter set!
#		endif
#	else
#		error Invalid parameter set!
#	endif
#else
#	error Invalid parameter set!
#endif

#if defined(QSMP_CONFIG_DILITHIUM_KYBER)
/*!
* \def QSMP_CIPHERTEXT_SIZE
* \brief The byte size of the asymmetric cipher-text array
*/
#	define QSMP_CIPHERTEXT_SIZE (QSC_KYBER_CIPHERTEXT_SIZE)

/*!
* \def QSMP_PRIVATEKEY_SIZE
* \brief The byte size of the asymmetric cipher private-key array
*/
#	define QSMP_PRIVATEKEY_SIZE (QSC_KYBER_PRIVATEKEY_SIZE)

/*!
* \def QSMP_PUBLICKEY_SIZE
* \brief The byte size of the asymmetric cipher public-key array
*/
#	define QSMP_PUBLICKEY_SIZE (QSC_KYBER_PUBLICKEY_SIZE)

/*!
* \def QSMP_SIGNKEY_SIZE
* \brief The byte size of the asymmetric signature signing-key array
*/
#	define QSMP_SIGNKEY_SIZE (QSC_DILITHIUM_PRIVATEKEY_SIZE)

/*!
* \def QSMP_VERIFYKEY_SIZE
* \brief The byte size of the asymmetric signature verification-key array
*/
#	define QSMP_VERIFYKEY_SIZE (QSC_DILITHIUM_PUBLICKEY_SIZE)

/*!
* \def QSMP_SIGNATURE_SIZE
* \brief The byte size of the asymmetric signature array
*/
#	define QSMP_SIGNATURE_SIZE (QSC_DILITHIUM_SIGNATURE_SIZE)

/*!
* \def QSMP_PUBKEY_ENCODING_SIZE
* \brief The byte size of the encoded QSMP public-key
*/
#	if defined(QSC_DILITHIUM_S2N256Q8380417K4)
#		define QSMP_PUBKEY_ENCODING_SIZE 1752
#	elif defined(QSC_DILITHIUM_S3N256Q8380417K6)
#		define QSMP_PUBKEY_ENCODING_SIZE 2604
#	elif defined(QSC_DILITHIUM_S5N256Q8380417K8)
#		define QSMP_PUBKEY_ENCODING_SIZE 3456
#	else
#		error invalid dilithium parameter!
#	endif

/*!
* \def QSMP_PUBKEY_STRING_SIZE
* \brief The string size of the serialized QSMP client-key structure
*/
#	if defined(QSC_DILITHIUM_S2N256Q8380417K4)
#		define QSMP_PUBKEY_STRING_SIZE 2014
#	elif defined(QSC_DILITHIUM_S3N256Q8380417K6)
#		define QSMP_PUBKEY_STRING_SIZE 2879
#	elif defined(QSC_DILITHIUM_S5N256Q8380417K8)
#		define QSMP_PUBKEY_STRING_SIZE 3745
#	else
#		error invalid dilithium parameter!
#	endif

#elif defined(QSMP_CONFIG_DILITHIUM_NTRU)
/*!
* \def QSMP_CIPHERTEXT_SIZE
* \brief The byte size of the asymmetric cipher-text array
*/
#	define QSMP_CIPHERTEXT_SIZE (QSC_NTRU_CIPHERTEXT_SIZE)

/*!
* \def QSMP_PRIVATEKEY_SIZE
* \brief The byte size of the asymmetric cipher private-key array
*/
#	define QSMP_PRIVATEKEY_SIZE (QSC_NTRU_PRIVATEKEY_SIZE)

/*!
* \def QSMP_PUBLICKEY_SIZE
* \brief The byte size of the asymmetric cipher public-key array
*/
#	define QSMP_PUBLICKEY_SIZE (QSC_NTRU_PUBLICKEY_SIZE)

/*!
* \def QSMP_SIGNKEY_SIZE
* \brief The byte size of the asymmetric signature signing-key array
*/
#	define QSMP_SIGNKEY_SIZE (QSC_DILITHIUM_PRIVATEKEY_SIZE)

/*!
* \def QSMP_VERIFYKEY_SIZE
* \brief The byte size of the asymmetric signature verification-key array
*/
#	define QSMP_VERIFYKEY_SIZE (QSC_DILITHIUM_PUBLICKEY_SIZE)

/*!
* \def QSMP_SIGNATURE_SIZE
* \brief The byte size of the asymmetric signature array
*/
#	define QSMP_SIGNATURE_SIZE (QSC_DILITHIUM_SIGNATURE_SIZE)

/*!
* \def QSMP_PUBKEY_ENCODING_SIZE
* \brief The byte size of the encoded QSMP public-key
*/
#	if defined(QSC_DILITHIUM_S2N256Q8380417K4)
#		define QSMP_PUBKEY_ENCODING_SIZE 1752
#	elif defined(QSC_DILITHIUM_S3N256Q8380417K6)
#		define QSMP_PUBKEY_ENCODING_SIZE 2604
#	elif defined(QSC_DILITHIUM_S5N256Q8380417K8)
#		define QSMP_PUBKEY_ENCODING_SIZE 3456
#	else
#		error invalid dilithium parameter!
#	endif

/*!
* \def QSMP_PUBKEY_STRING_SIZE
* \brief The string size of the serialized QSMP client-key structure
*/
#	if defined(QSC_DILITHIUM_S2N256Q8380417K4)
#		define QSMP_PUBKEY_STRING_SIZE 2014
#	elif defined(QSC_DILITHIUM_S3N256Q8380417K6)
#		define QSMP_PUBKEY_STRING_SIZE 2879
#	elif defined(QSC_DILITHIUM_S5N256Q8380417K8)
#		define QSMP_PUBKEY_STRING_SIZE 3745
#	else
#		error invalid dilithium parameter!
#	endif

#elif defined(QSMP_CONFIG_DILITHIUM_MCELIECE)
/*!
* \def QSMP_CIPHERTEXT_SIZE
* \brief The byte size of the asymmetric cipher-text array
*/
#	define QSMP_CIPHERTEXT_SIZE (QSC_MCELIECE_CIPHERTEXT_SIZE)

/*!
* \def QSMP_PRIVATEKEY_SIZE
* \brief The byte size of the asymmetric cipher private-key array
*/
#	define QSMP_PRIVATEKEY_SIZE (QSC_MCELIECE_PRIVATEKEY_SIZE)

/*!
* \def QSMP_PUBLICKEY_SIZE
* \brief The byte size of the asymmetric cipher public-key array
*/
#	define QSMP_PUBLICKEY_SIZE (QSC_MCELIECE_PUBLICKEY_SIZE)

/*!
* \def QSMP_SIGNKEY_SIZE
* \brief The byte size of the asymmetric signature signing-key array
*/
#	define QSMP_SIGNKEY_SIZE (QSC_DILITHIUM_PRIVATEKEY_SIZE)

/*!
* \def QSMP_VERIFYKEY_SIZE
* \brief The byte size of the asymmetric signature verification-key array
*/
#	define QSMP_VERIFYKEY_SIZE (QSC_DILITHIUM_PUBLICKEY_SIZE)

/*!
* \def QSMP_SIGNATURE_SIZE
* \brief The byte size of the asymmetric signature array
*/
#	define QSMP_SIGNATURE_SIZE (QSC_DILITHIUM_SIGNATURE_SIZE)

/*!
* \def QSMP_PUBKEY_ENCODING_SIZE
* \brief The byte size of the encoded QSMP public-key
*/
#	if defined(QSC_DILITHIUM_S2N256Q8380417K4)
#		define QSMP_PUBKEY_ENCODING_SIZE 1752
#	elif defined(QSC_DILITHIUM_S3N256Q8380417K6)
#		define QSMP_PUBKEY_ENCODING_SIZE 2604
#	elif defined(QSC_DILITHIUM_S5N256Q8380417K8)
#		define QSMP_PUBKEY_ENCODING_SIZE 3456
#	else
#		error invalid dilithium parameter!
#	endif

/*!
* \def QSMP_PUBKEY_STRING_SIZE
* \brief The string size of the serialized QSMP client-key structure
*/
#	if defined(QSC_DILITHIUM_S2N256Q8380417K4)
#		define QSMP_PUBKEY_STRING_SIZE 2014
#	elif defined(QSC_DILITHIUM_S3N256Q8380417K6)
#		define QSMP_PUBKEY_STRING_SIZE 2879
#	elif defined(QSC_DILITHIUM_S5N256Q8380417K8)
#		define QSMP_PUBKEY_STRING_SIZE 3745
#	else
#		error invalid dilithium parameter!
#	endif

#elif defined(QSMP_CONFIG_FALCON_KYBER)
/*!
* \def QSMP_CIPHERTEXT_SIZE
* \brief The byte size of the asymmetric cipher-text array
*/
#	define QSMP_CIPHERTEXT_SIZE (QSC_KYBER_CIPHERTEXT_SIZE)

/*!
* \def QSMP_PRIVATEKEY_SIZE
* \brief The byte size of the asymmetric cipher private-key array
*/
#	define QSMP_PRIVATEKEY_SIZE (QSC_KYBER_PRIVATEKEY_SIZE)

/*!
* \def QSMP_PUBLICKEY_SIZE
* \brief The byte size of the asymmetric cipher public-key array
*/
#	define QSMP_PUBLICKEY_SIZE (QSC_KYBER_PUBLICKEY_SIZE)

/*!
* \def QSMP_SIGNKEY_SIZE
* \brief The byte size of the asymmetric signature signing-key array
*/
#	define QSMP_SIGNKEY_SIZE (QSC_FALCON_PRIVATEKEY_SIZE)

/*!
* \def QSMP_VERIFYKEY_SIZE
* \brief The byte size of the asymmetric signature verification-key array
*/
#	define QSMP_VERIFYKEY_SIZE (QSC_FALCON_PUBLICKEY_SIZE)

/*!
* \def QSMP_SIGNATURE_SIZE
* \brief The byte size of the asymmetric signature array
*/
#	define QSMP_SIGNATURE_SIZE (QSC_FALCON_SIGNATURE_SIZE)

/*!
* \def QSMP_PUBKEY_ENCODING_SIZE
* \brief The byte size of the encoded QSMP public-key
*/
#	if defined(QSC_FALCON_S3SHAKE256F512)
#		define QSMP_PUBKEY_ENCODING_SIZE 1196
#	elif defined(QSC_FALCON_S5SHAKE256F1024)
#		define QSMP_PUBKEY_ENCODING_SIZE 2392
#	else
#		error invalid dilithium parameter!
#	endif

/*!
* \def QSMP_PUBKEY_STRING_SIZE
* \brief The string size of the serialized QSMP client-key structure
*/
#	if defined(QSC_FALCON_S3SHAKE256F512)
#		define QSMP_PUBKEY_STRING_SIZE 2014
#	elif defined(QSC_FALCON_S5SHAKE256F1024)
#		define QSMP_PUBKEY_STRING_SIZE 2664
#	else
#		error invalid dilithium parameter!
#	endif

#elif defined(QSMP_CONFIG_FALCON_MCELIECE)

/*!
* \def QSMP_CIPHERTEXT_SIZE
* \brief The byte size of the asymmetric cipher-text array
*/
#	define QSMP_CIPHERTEXT_SIZE (QSC_MCELIECE_CIPHERTEXT_SIZE)

/*!
* \def QSMP_PRIVATEKEY_SIZE
* \brief The byte size of the asymmetric cipher private-key array
*/
#	define QSMP_PRIVATEKEY_SIZE (QSC_MCELIECE_PRIVATEKEY_SIZE)

/*!
* \def QSMP_PUBLICKEY_SIZE
* \brief The byte size of the asymmetric cipher public-key array
*/
#	define QSMP_PUBLICKEY_SIZE (QSC_MCELIECE_PUBLICKEY_SIZE)

/*!
* \def QSMP_SIGNKEY_SIZE
* \brief The byte size of the asymmetric signature signing-key array
*/
#	define QSMP_SIGNKEY_SIZE (QSC_FALCON_PRIVATEKEY_SIZE)

/*!
* \def QSMP_VERIFYKEY_SIZE
* \brief The byte size of the asymmetric signature verification-key array
*/
#	define QSMP_VERIFYKEY_SIZE (QSC_FALCON_PUBLICKEY_SIZE)

/*!
* \def QSMP_SIGNATURE_SIZE
* \brief The byte size of the asymmetric signature array
*/
#	define QSMP_SIGNATURE_SIZE (QSC_FALCON_SIGNATURE_SIZE)

/*!
* \def QSMP_PUBKEY_ENCODING_SIZE
* \brief The byte size of the encoded QSMP public-key
*/
#	if defined(QSC_FALCON_S3SHAKE256F512)
#		define QSMP_PUBKEY_ENCODING_SIZE 1196
#	elif defined(QSC_FALCON_S5SHAKE256F1024)
#		define QSMP_PUBKEY_ENCODING_SIZE 2392
#	else
#		error invalid dilithium parameter!
#	endif

/*!
* \def QSMP_PUBKEY_STRING_SIZE
* \brief The string size of the serialized QSMP client-key structure
*/
#	if defined(QSC_FALCON_S3SHAKE256F512)
#		define QSMP_PUBKEY_STRING_SIZE 2014
#	elif defined(QSC_FALCON_S5SHAKE256F1024)
#		define QSMP_PUBKEY_STRING_SIZE 2664
#	else
#		error invalid dilithium parameter!
#	endif

#elif defined(QSMP_CONFIG_FALCON_NTRU)
/*!
* \def QSMP_CIPHERTEXT_SIZE
* \brief The byte size of the asymmetric cipher-text array
*/
#	define QSMP_CIPHERTEXT_SIZE (QSC_NTRU_CIPHERTEXT_SIZE)

/*!
* \def QSMP_PRIVATEKEY_SIZE
* \brief The byte size of the asymmetric cipher private-key array
*/
#	define QSMP_PRIVATEKEY_SIZE (QSC_NTRU_PRIVATEKEY_SIZE)

/*!
* \def QSMP_PUBLICKEY_SIZE
* \brief The byte size of the asymmetric cipher public-key array
*/
#	define QSMP_PUBLICKEY_SIZE (QSC_NTRU_PUBLICKEY_SIZE)

/*!
* \def QSMP_SIGNKEY_SIZE
* \brief The byte size of the asymmetric signature signing-key array
*/
#	define QSMP_SIGNKEY_SIZE (QSC_FALCON_PRIVATEKEY_SIZE)

/*!
* \def QSMP_VERIFYKEY_SIZE
* \brief The byte size of the asymmetric signature verification-key array
*/
#	define QSMP_VERIFYKEY_SIZE (QSC_FALCON_PUBLICKEY_SIZE)

/*!
* \def QSMP_SIGNATURE_SIZE
* \brief The byte size of the asymmetric signature array
*/
#	define QSMP_SIGNATURE_SIZE (QSC_FALCON_SIGNATURE_SIZE)

/*!
* \def QSMP_PUBKEY_ENCODING_SIZE
* \brief The byte size of the encoded QSMP public-key
*/
#	if defined(QSC_FALCON_S3SHAKE256F512)
#		define QSMP_PUBKEY_ENCODING_SIZE 1196
#	elif defined(QSC_FALCON_S5SHAKE256F1024)
#		define QSMP_PUBKEY_ENCODING_SIZE 2392
#	else
#		error invalid dilithium parameter!
#	endif

/*!
* \def QSMP_PUBKEY_STRING_SIZE
* \brief The string size of the serialized QSMP client-key structure
*/
#	if defined(QSC_FALCON_S3SHAKE256F512)
#		define QSMP_PUBKEY_STRING_SIZE 2014
#	elif defined(QSC_FALCON_S5SHAKE256F1024)
#		define QSMP_PUBKEY_STRING_SIZE 2664
#	else
#		error invalid dilithium parameter!
#	endif

#elif defined(QSMP_CONFIG_SPHINCS_MCELIECE)
/*!
* \def QSMP_CIPHERTEXT_SIZE
* \brief The byte size of the cipher-text array
*/
#	define QSMP_CIPHERTEXT_SIZE (QSC_MCELIECE_CIPHERTEXT_SIZE)

/*!
* \def QSMP_PRIVATEKEY_SIZE
* \brief The byte size of the asymmetric cipher private-key array
*/
#	define QSMP_PRIVATEKEY_SIZE (QSC_MCELIECE_PRIVATEKEY_SIZE)

/*!
* \def QSMP_PUBLICKEY_SIZE
* \brief The byte size of the asymmetric cipher public-key array
*/
#	define QSMP_PUBLICKEY_SIZE (QSC_MCELIECE_PUBLICKEY_SIZE)

/*!
* \def QSMP_SIGNKEY_SIZE
* \brief The byte size of the asymmetric signature signing-key array
*/
#	define QSMP_SIGNKEY_SIZE (QSC_SPHINCSPLUS_PRIVATEKEY_SIZE)

/*!
* \def QSMP_VERIFYKEY_SIZE
* \brief The byte size of the asymmetric signature verification-key array
*/
#	define QSMP_VERIFYKEY_SIZE (QSC_SPHINCSPLUS_PUBLICKEY_SIZE)

/*!
* \def QSMP_SIGNATURE_SIZE
* \brief The byte size of the asymmetric signature array
*/
#	define QSMP_SIGNATURE_SIZE (QSC_SPHINCSPLUS_SIGNATURE_SIZE)

/*!
* \def QSMP_PUBKEY_ENCODING_SIZE
* \brief The byte size of the encoded QSMP public-key
*/
#	if defined(QSC_SPHINCSPLUS_S3S192SHAKERS)
#		define QSMP_PUBKEY_ENCODING_SIZE 64
#	elif defined(QSC_SPHINCSPLUS_S3S192SHAKERF)
#		define QSMP_PUBKEY_ENCODING_SIZE 64
#	elif defined(QSC_SPHINCSPLUS_S5S256SHAKERS)
#		define QSMP_PUBKEY_ENCODING_SIZE 88
#	elif defined(QSC_SPHINCSPLUS_S5S256SHAKERF)
#		define QSMP_PUBKEY_ENCODING_SIZE 88
#	else
#		error invalid sphincs+ parameter!
#	endif

/*!
* \def QSMP_PUBKEY_STRING_SIZE
* \brief The string size of the serialized QSMP client-key structure
*/
#	if defined(QSC_SPHINCSPLUS_S3S192SHAKERS)
#		define QSMP_PUBKEY_STRING_SIZE 300
#	elif defined(QSC_SPHINCSPLUS_S3S192SHAKERF)
#		define QSMP_PUBKEY_STRING_SIZE 300
#	elif defined(QSC_SPHINCSPLUS_S5S256SHAKERS)
#		define QSMP_PUBKEY_STRING_SIZE 324
#	elif defined(QSC_SPHINCSPLUS_S5S256SHAKERF)
#		define QSMP_PUBKEY_STRING_SIZE 324
#	else
#		error invalid sphincs+ parameter!
#	endif
#else
#	error invalid parameter set!
#endif

/*!
* \def QSMP_HASH_SIZE
* \brief The size of the hash function output
*/
#define QSMP_HASH_SIZE 32

/*!
* \def QSMP_HEADER_SIZE
* \brief The QSMP packet header size
*/
#define QSMP_HEADER_SIZE 13

/*!
* \def QSMP_KEEPALIVE_STRING
* \brief The keep alive string size
*/
#define QSMP_KEEPALIVE_STRING 20

/*!
* \def QSMP_KEEPALIVE_TIMEOUT
* \brief The keep alive timeout in milliseconds (5 minutes)
*/
#define QSMP_KEEPALIVE_TIMEOUT (300 * 1000)

/*!
* \def QSMP_KEYID_SIZE
* \brief The QSMP key identity size
*/
#define QSMP_KEYID_SIZE 16

/*!
* \def QSMP_MACKEY_SIZE
* \brief The QSMP mac key size
*/
#define QSMP_MACKEY_SIZE 32

/*!
* \def QSMP_MACTAG_SIZE
* \brief The size of the mac function output
*/
#define QSMP_MACTAG_SIZE 32

/*!
* \def QSMP_SRVID_SIZE
* \brief The QSMP server identity size
*/
#define QSMP_SRVID_SIZE 8

/*!
* \def QSMP_TIMESTAMP_SIZE
* \brief The key expiration timestamp size
*/
#define QSMP_TIMESTAMP_SIZE 8

/*!
* \def QSMP_MESSAGE_MAX
* \brief The maximum message size used during the key exchange (may exceed mtu)
*/
#define QSMP_MESSAGE_MAX (QSMP_SIGNATURE_SIZE + QSMP_PUBLICKEY_SIZE + QSMP_HASH_SIZE + QSMP_HEADER_SIZE)

/*!
* \def QSMP_PKCODE_SIZE
* \brief The size of the session token hash
*/
#define QSMP_PKCODE_SIZE 32

/*!
* \def QSMP_PUBKEY_DURATION_DAYS
* \brief The number of days a public key remains valid
*/
#define QSMP_PUBKEY_DURATION_DAYS 365

/*!
* \def QSMP_PUBKEY_DURATION_SECONDS
* \brief The number of seconds a public key remains valid
*/
#define QSMP_PUBKEY_DURATION_SECONDS (QSMP_PUBKEY_DURATION_DAYS * 24 * 60 * 60)

/*!
* \def QSMP_PUBKEY_LINE_LENGTH
* \brief The line length of the printed QSMP public key
*/
#define QSMP_PUBKEY_LINE_LENGTH 64

/*!
* \def QSMP_SECRET_SIZE
* \brief The size of the shared secret for each channel
*/
#define QSMP_SECRET_SIZE 32

/*!
* \def QSMP_STOKEN_SIZE
* \brief The session token size
*/
#define QSMP_STOKEN_SIZE 32

/*!
* \def QSMP_SIGKEY_ENCODED_SIZE
* \brief The secret signature key size
*/
#define QSMP_SIGKEY_ENCODED_SIZE (QSMP_KEYID_SIZE + QSMP_TIMESTAMP_SIZE + QSMP_CONFIG_SIZE + QSMP_SIGNKEY_SIZE + QSMP_VERIFYKEY_SIZE)

/*!
* \def QSMP_SEQUENCE_TERMINATOR
* \brief The sequence number of a packet that closes a connection
*/
#define QSMP_SEQUENCE_TERMINATOR 0xFFFFFFFFUL

/*!
* \def QSMP_CONNECT_REQUEST_SIZE
* \brief The key-exchange connect stage request packet size
*/
#define QSMP_CONNECT_REQUEST_SIZE (QSMP_KEYID_SIZE + QSMP_STOKEN_SIZE + QSMP_CONFIG_SIZE + QSMP_HEADER_SIZE)

/*!
* \def QSMP_EXSTART_REQUEST_SIZE
* \brief The key-exchange exstart stage request packet size
*/
#define QSMP_EXSTART_REQUEST_SIZE (QSMP_CIPHERTEXT_SIZE + QSMP_HEADER_SIZE)

/*!
* \def QSMP_EXCHANGE_REQUEST_SIZE
* \brief The key-exchange exchange stage request packet size
*/
#define QSMP_EXCHANGE_REQUEST_SIZE (QSMP_MACKEY_SIZE + QSMP_PUBLICKEY_SIZE + QSMP_MACTAG_SIZE + QSMP_HEADER_SIZE)

/*!
* \def QSMP_ESTABLISH_REQUEST_SIZE
* \brief The key-exchange establish stage request packet size
*/
#define QSMP_ESTABLISH_REQUEST_SIZE (QSMP_STOKEN_SIZE + QSMP_MACTAG_SIZE + QSMP_HEADER_SIZE)

/*!
* \def QSMP_CONNECT_RESPONSE_SIZE
* \brief The key-exchange connect stage response packet size
*/
#define QSMP_CONNECT_RESPONSE_SIZE (QSMP_SIGNATURE_SIZE + QSMP_HASH_SIZE + QSMP_PUBLICKEY_SIZE + QSMP_HEADER_SIZE)

/*!
* \def QSMP_EXSTART_RESPONSE_SIZE
* \brief The key-exchange exstart stage response packet size
*/
#define QSMP_EXSTART_RESPONSE_SIZE (QSMP_HEADER_SIZE + 1)

/*!
* \def QSMP_EXCHANGE_RESPONSE_SIZE
* \brief The key-exchange exchange stage response packet size
*/
#define QSMP_EXCHANGE_RESPONSE_SIZE (QSMP_CIPHERTEXT_SIZE + QSMP_MACTAG_SIZE + QSMP_HEADER_SIZE)

/*!
* \def QSMP_ESTABLISH_RESPONSE_SIZE
* \brief The key-exchange establish stage response packet size
*/
#define QSMP_ESTABLISH_RESPONSE_SIZE (QSMP_HASH_SIZE + QSMP_MACTAG_SIZE + QSMP_HEADER_SIZE)

/* public key encoding constants */

static const char QSMP_PUBKEY_HEADER[] = "------BEGIN QSMP PUBLIC KEY BLOCK------";
static const char QSMP_PUBKEY_VERSION[] = "Version: QSMP v1.0";
static const char QSMP_PUBKEY_CONFIG_PREFIX[] = "Configuration: ";
static const char QSMP_PUBKEY_KEYID_PREFIX[] = "Host ID: ";
static const char QSMP_PUBKEY_EXPIRATION_PREFIX[] = "Expiration: ";
static const char QSMP_PUBKEY_FOOTER[] = "------END QSMP PUBLIC KEY BLOCK------";

/* error code strings */

#define QSMP_ERROR_STRING_DEPTH 22
#define QSMP_ERROR_STRING_WIDTH 128

static const char QSMP_ERROR_STRINGS[QSMP_ERROR_STRING_DEPTH][QSMP_ERROR_STRING_WIDTH] =
{
	"No error was detected.",
	"The asymmetric signature had an authentication failure.",
	"The keep alive check failed.",
	"The communications channel has failed.",
	"The device could not make a connnection to the remote host.",
	"The transmission failed at the kex connection phase.",
	"The asymmetric cipher failed to decapsulate the shared secret.",
	"The transmission failed at the kex establish phase.",
	"The transmission failed at the kex exstart phase.",
	"The transmission failed at the kex exchange phase.",
	"The public-key hash is invalid.",
	"The expected input was invalid.",
	"The packet flag was unexpected.",
	"The keep alive has expired with no response.",
	"The QSMP public key has expired.",
	"The key identity is unrecognized.",
	"The packet was received out of sequence.",
	"The random generator has failed.",
	"The receiver failed at the network layer.",
	"The transmitter failed at the network layer.",
	"The expected data could not be verified.",
	"The protocol string was not recognized.",
};

/*!
* \enum qsmp_configuration
* \brief The asymmetric cryptographic primitive configuration
*/
typedef enum qsmp_configuration
{
	qsmp_configuration_none = 0,				/*!< No configuration was specified */
	qsmp_configuration_sphincs_mceliece = 1,	/*!< The Sphincs+ and McEliece configuration */
	qsmp_configuration_dilithium_kyber = 2,		/*!< The Dilithium and Kyber configuration */
	qsmp_configuration_dilithium_mceliece = 3,	/*!< The Dilithium and Kyber configuration */
	qsmp_configuration_dilithium_ntru = 4,		/*!< The Dilithium and NTRU configuration */
	qsmp_configuration_falcon_kyber = 5,		/*!< The Falcon and Kyber configuration */
	qsmp_configuration_falcon_mceliece = 6,		/*!< The Falcon and McEliece configuration */
	qsmp_configuration_falcon_ntru = 7,			/*!< The Falcon and NTRU configuration */
} qsmp_configuration;

/*!
* \enum qsmp_errors
* \brief The QSMP error values
*/
typedef enum qsmp_errors
{
	qsmp_error_none = 0x00,						/*!< No error was detected */
	qsmp_error_authentication_failure = 0x01,	/*!< The symmetric cipher had an authentication failure */
	qsmp_error_bad_keep_alive = 0x02,			/*!< The keep alive check failed */
	qsmp_error_channel_down = 0x03,				/*!< The communications channel has failed */
	qsmp_error_connection_failure = 0x04,		/*!< The device could not make a connection to the remote host */
	qsmp_error_connect_failure = 0x05,			/*!< The transmission failed at the KEX connection phase */
	qsmp_error_decapsulation_failure = 0x06,	/*!< The asymmetric cipher failed to decapsulate the shared secret */
	qsmp_error_establish_failure = 0x07,		/*!< The transmission failed at the KEX establish phase */
	qsmp_error_exstart_failure = 0x08,			/*!< The transmission failed at the KEX exstart phase */
	qsmp_error_exchange_failure = 0x09,			/*!< The transmission failed at the KEX exchange phase */
	qsmp_error_hash_invalid = 0x0A,				/*!< The public-key hash is invalid */
	qsmp_error_invalid_input = 0x0B,			/*!< The expected input was invalid */
	qsmp_error_invalid_request = 0x0C,			/*!< The packet flag was unexpected */
	qsmp_error_keep_alive_expired = 0x0D,		/*!< The keep alive has expired with no response */
	qsmp_error_key_expired = 0x0E,				/*!< The QSMP public key has expired  */
	qsmp_error_key_unrecognized = 0x0F,			/*!< The key identity is unrecognized */
	qsmp_error_packet_unsequenced = 0x10,		/*!< The packet was received out of sequence */
	qsmp_error_random_failure = 0x11,			/*!< The random generator has failed */
	qsmp_error_receive_failure = 0x12,			/*!< The receiver failed at the network layer */
	qsmp_error_transmit_failure = 0x13,			/*!< The transmitter failed at the network layer */
	qsmp_error_verify_failure = 0x14,			/*!< The expected data could not be verified */
	qsmp_error_unknown_protocol = 0x15,			/*!< The protocol string was not recognized */
} qsmp_errors;

/*!
* \enum qsmp_flags
* \brief The QSMP packet flags
*/
typedef enum qsmp_flags
{
	qsmp_flag_none = 0x00,						/*!< No flag was specified */
	qsmp_flag_connect_request = 0x01,			/*!< The QSMP key-exchange client connection request flag  */
	qsmp_flag_connect_response = 0x02,			/*!< The QSMP key-exchange server connection response flag */
	qsmp_flag_connection_terminate = 0x03,		/*!< The connection is to be terminated */
	qsmp_flag_encrypted_message = 0x04,			/*!< The message has been encrypted flag */
	qsmp_flag_exstart_request = 0x05,			/*!< The QSMP key-exchange client exstart request flag */
	qsmp_flag_exstart_response = 0x06,			/*!< The QSMP key-exchange server exstart response flag */
	qsmp_flag_exchange_request = 0x07,			/*!< The QSMP key-exchange client exchange request flag */
	qsmp_flag_exchange_response = 0x08,			/*!< The QSMP key-exchange server exchange response flag */
	qsmp_flag_establish_request = 0x09,			/*!< The QSMP key-exchange client establish request flag */
	qsmp_flag_establish_response = 0x0A,		/*!< The QSMP key-exchange server establish response flag */
	qsmp_flag_keep_alive_request = 0x0B,		/*!< The packet contains a keep alive request */
	qsmp_flag_remote_connected = 0x0C,			/*!< The remote host is connected flag */
	qsmp_flag_remote_terminated = 0x0D,			/*!< The remote host has terminated the connection */
	qsmp_flag_session_established = 0x0E,		/*!< The exchange is in the established state */
	qsmp_flag_session_establish_verify = 0x0F,	/*!< The exchange is in the established verify state */
	qsmp_flag_unrecognized_protocol = 0x10,		/*!< The protocol string is not recognized */
	qsmp_flag_error_condition = 0xFF,			/*!< The connection experienced an error */
} qsmp_flags;

/*!
* \struct qsmp_packet
* \brief The QSMP packet structure
*/
typedef struct qsmp_packet
{
	uint8_t flag;								/*!< The packet flag */
	uint32_t msglen;							/*!< The packets message length */
	uint64_t sequence;							/*!< The packet sequence number */
	uint8_t message[QSMP_MESSAGE_MAX];			/*!< The packets message data */
} qsmp_packet;

/*!
* \struct qsmp_client_key
* \brief The QSMP client key structure
*/
typedef struct qsmp_client_key
{
	uint64_t expiration;						/*!< The expiration time, in seconds from epoch */
	uint8_t config[QSMP_CONFIG_SIZE];			/*!< The primitive configuration string */
	uint8_t keyid[QSMP_KEYID_SIZE];				/*!< The key identity string */
	uint8_t verkey[QSMP_VERIFYKEY_SIZE];		/*!< The asymmetric signatures verification-key */
} qsmp_client_key;

/*!
* \struct qsmp_keep_alive_state
* \brief The QSMP keep alive state structure
*/
typedef struct qsmp_keep_alive_state
{
	uint64_t etime;								/*!< The keep alive epoch time  */
	uint64_t seqctr;							/*!< The keep alive packet sequence number  */
	bool recd;									/*!< The keep alive response received status  */
} qsmp_keep_alive_state;

#if defined(QSMP_CONFIG_DILITHIUM_NTRU)
#	define qsmp_cipher_generate_keypair qsc_ntru_generate_keypair
#	define qsmp_cipher_decapsulate qsc_ntru_decapsulate
#	define qsmp_cipher_encapsulate qsc_ntru_encapsulate
#	define qsmp_signature_generate_keypair qsc_dilithium_generate_keypair
#	define qsmp_signature_sign qsc_dilithium_sign
#	define qsmp_signature_verify qsc_dilithium_verify
#elif defined(QSMP_CONFIG_DILITHIUM_MCELIECE)
#	define qsmp_cipher_generate_keypair qsc_mceliece_generate_keypair
#	define qsmp_cipher_decapsulate qsc_mceliece_decapsulate
#	define qsmp_cipher_encapsulate qsc_mceliece_encapsulate
#	define qsmp_signature_generate_keypair qsc_dilithium_generate_keypair
#	define qsmp_signature_sign qsc_dilithium_sign
#	define qsmp_signature_verify qsc_dilithium_verify
#elif defined(QSMP_CONFIG_SPHINCS_MCELIECE)
#	define qsmp_cipher_generate_keypair qsc_mceliece_generate_keypair
#	define qsmp_cipher_decapsulate qsc_mceliece_decapsulate
#	define qsmp_cipher_encapsulate qsc_mceliece_encapsulate
#	define qsmp_signature_generate_keypair qsc_sphincsplus_generate_keypair
#	define qsmp_signature_sign qsc_sphincsplus_sign
#	define qsmp_signature_verify qsc_sphincsplus_verify
#elif defined(QSMP_CONFIG_FALCON_KYBER)
#	define qsmp_cipher_generate_keypair qsc_kyber_generate_keypair
#	define qsmp_cipher_decapsulate qsc_kyber_decapsulate
#	define qsmp_cipher_encapsulate qsc_kyber_encapsulate
#	define qsmp_signature_generate_keypair qsc_falcon_generate_keypair
#	define qsmp_signature_sign qsc_falcon_sign
#	define qsmp_signature_verify qsc_falcon_verify
#elif defined(QSMP_CONFIG_FALCON_MCELIECE)
#	define qsmp_cipher_generate_keypair qsc_mceliece_generate_keypair
#	define qsmp_cipher_decapsulate qsc_mceliece_decapsulate
#	define qsmp_cipher_encapsulate qsc_mceliece_encapsulate
#	define qsmp_signature_generate_keypair qsc_falcon_generate_keypair
#	define qsmp_signature_sign qsc_falcon_sign
#	define qsmp_signature_verify qsc_falcon_verify
#elif defined(QSMP_CONFIG_FALCON_NTRU)
#	define qsmp_cipher_generate_keypair qsc_ntru_generate_keypair
#	define qsmp_cipher_decapsulate qsc_ntru_decapsulate
#	define qsmp_cipher_encapsulate qsc_ntru_encapsulate
#	define qsmp_signature_generate_keypair qsc_falcon_generate_keypair
#	define qsmp_signature_sign qsc_falcon_sign
#	define qsmp_signature_verify qsc_falcon_verify
#else
#	define qsmp_cipher_generate_keypair qsc_kyber_generate_keypair
#	define qsmp_cipher_decapsulate qsc_kyber_decapsulate
#	define qsmp_cipher_encapsulate qsc_kyber_encapsulate
#	define qsmp_signature_generate_keypair qsc_dilithium_generate_keypair
#	define qsmp_signature_sign qsc_dilithium_sign
#	define qsmp_signature_verify qsc_dilithium_verify
#endif

/**
* \brief Clear a packet's state
*
* \param packet: A pointer to the packet structure
*/
void qsmp_packet_clear(qsmp_packet* packet);

/**
* \brief Return a pointer to a string description of an error code
*
* \param error: The error type
* \return Returns a pointer to an error string, or NULL if not recognized
*/
const char* qsmp_error_to_string(qsmp_errors error);

/**
* \brief Populate a packet structure with an error message
*
* \param packet: A pointer to the packet structure
* \param error: The error type
*/
void qsmp_packet_error_message(qsmp_packet* packet, qsmp_errors error);

/**
* \brief Deserialize a byte array to a packet header
*
* \param packet: The header byte array to deserialize
* \param header: A pointer to the packet structure
*/
void qsmp_packet_header_deserialize(const uint8_t* header, qsmp_packet* packet);

/**
* \brief Serialize a packet header to a byte array
*
* \param packet: A pointer to the packet structure to serialize
* \param header: The header byte array
*/
void qsmp_packet_header_serialize(const qsmp_packet* packet, uint8_t* header);

/**
* \brief Serialize a packet to a byte array
*
* \param packet: The header byte array to deserialize
* \param pstream: A pointer to the packet structure
* \return Returns the size of the byte stream
*/
size_t qsmp_packet_to_stream(const qsmp_packet* packet, uint8_t* pstream);

/**
* \brief Deserialize a byte array to a packet
*
* \param pstream: The header byte array to deserialize
* \param packet: A pointer to the packet structure
*/
void qsmp_stream_to_packet(const uint8_t* pstream, qsmp_packet* packet);

#endif

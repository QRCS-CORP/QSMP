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
* \file qsmp.h
* \brief <b>QSMP support header</b> \n
* Common defined parameters and functions of the qsmp client and server implementations.
* 
* \author   John G. Underhill
* \version  1.2a: 2022-05-01
* \date     May 1, 2022
* \contact: develop@dfdef.com
*/

#ifndef QSMP_H
#define QSMP_H

#include "../QSC/rcs.h"
#include "../QSC/sha3.h"

/*
* Note:
* These definitions determine the asymmetric protocol set used by QSMP.
* The individual parameter sets for each cipher and signature scheme,
* can be configured in the QSC libraries common.h file.
* For maximum security, I recommend the McElice/SPHINCS+ set.
* For a balance of performance and security, the Dilithium/Kyber,
* or Dilithium/NTRU sets are recommended.
* 
* In Visual Studio, when using the McEliece/SPHINCS options, 
* The maximum stack size should be increased in each project options settings
* to accomodate the larger key sizes, set to 200KB for the maximum setting values.
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

/*!
* \def QSMP_CONFIG_DILITHIUM_MCELIECE
* \brief Sets the asymmetric cryptographic primitive-set to Dilithium/McEliece.
*/
//#define QSMP_CONFIG_DILITHIUM_MCELIECE

/*!
* \def QSMP_CONFIG_DILITHIUM_NTRU
* \brief Sets the asymmetric cryptographic primitive-set to Dilithium/NTRU.
*/
//#define QSMP_CONFIG_DILITHIUM_NTRU

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
#include "../QSC/socketbase.h"

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
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "dilithium-s2_kyber-s3_sha3_rcs";
#		elif defined(QSC_KYBER_S5Q3329N256K4)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "dilithium-s2_kyber-s5_sha3_rcs";
#		elif defined(QSC_KYBER_S6Q3329N256K5)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "dilithium-s2_kyber-s6_sha3_rcs";
#		else
#			error Invalid parameter set!
#		endif
#	elif defined(QSC_DILITHIUM_S3N256Q8380417K6)
#		if defined(QSC_KYBER_S3Q3329N256K3)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "dilithium-s3_kyber-s3_sha3_rcs";
#		elif defined(QSC_KYBER_S5Q3329N256K4)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "dilithium-s3_kyber-s5_sha3_rcs";
#		elif defined(QSC_KYBER_S6Q3329N256K5)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "dilithium-s3_kyber-s6_sha3_rcs";
#		else
#			error Invalid parameter set!
#		endif
#	elif defined(QSC_DILITHIUM_S5N256Q8380417K8)
#		if defined(QSC_KYBER_S3Q3329N256K3)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "dilithium-s5_kyber-s3_sha3_rcs";
#		elif defined(QSC_KYBER_S5Q3329N256K4)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "dilithium-s5_kyber-s5_sha3_rcs";
#		elif defined(QSC_KYBER_S6Q3329N256K5)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "dilithium-s5_kyber-s6_sha3_rcs";
#		else
#			error Invalid parameter set!
#		endif
#	else
#		error Invalid parameter set!
#	endif
#elif defined(QSMP_CONFIG_DILITHIUM_NTRU)
#	if defined(QSC_DILITHIUM_S2N256Q8380417K4)
#		if defined(QSC_NTRU_S1HPS2048509)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "dilithium-s2_ntru-s1_sha3_rcs";
#		elif defined(QSC_NTRU_HPSS32048677)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "dilithium-s2_ntru-s3_sha3_rcs";
#		elif defined(QSC_NTRU_S5HPS4096821)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "dilithium-s2_ntru-s5ps_sha3_rcs";
#		elif defined(QSC_NTRU_S5HRSS701)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "dilithium-s2_ntru-s5ss_sha3_rcs";
#		else
#			error Invalid parameter set!
#		endif
#	elif defined(QSC_DILITHIUM_S3N256Q8380417K6)
#		if defined(QSC_NTRU_S1HPS2048509)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "dilithium-s3_ntru-s1_sha3_rcs";
#		elif defined(QSC_NTRU_HPSS32048677)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "dilithium-s3_ntru-s3_sha3_rcs";
#		elif defined(QSC_NTRU_S5HPS4096821)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "dilithium-s3_ntru-s5ps_sha3_rcs";
#		elif defined(QSC_NTRU_S5HRSS701)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "dilithium-s3_ntru-s5ss_sha3_rcs";
#		else
#			error Invalid parameter set!
#		endif
#	elif defined(QSC_DILITHIUM_S5N256Q8380417K8)
#		if defined(QSC_NTRU_S1HPS2048509)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "dilithium-s5_ntru-s1_sha3_rcs";
#		elif defined(QSC_NTRU_HPSS32048677)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "dilithium-s5_ntru-s3_sha3_rcs";
#		elif defined(QSC_NTRU_S5HPS4096821)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "dilithium-s5_ntru-s5ps_sha3_rcs";
#		elif defined(QSC_NTRU_S5HRSS701)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "dilithium-s5_ntru-s5ss_sha3_rcs";
#		else
#			error Invalid parameter set!
#		endif
#	else
#		error Invalid parameter set!
#	endif
#elif defined(QSMP_CONFIG_DILITHIUM_MCELIECE)
#	if defined(QSC_DILITHIUM_S2N256Q8380417K4)
#		if defined(QSC_MCELIECE_S3N4608T96)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "dilithium-s2_mceliece-s3_sha3_rcs";
#		elif defined(QSC_MCELIECE_S5N6688T128)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "dilithium-s2_mceliece-s5a_sha3_rcs";
#		elif defined(QSC_MCELIECE_S5N6960T119)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "dilithium-s2_mceliece-s5b_sha3_rcs";
#		elif defined(QSC_MCELIECE_S5N8192T128)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "dilithium-s2_mceliece-s5c_sha3_rcs";
#		else
#			error Invalid parameter set!
#		endif
#	elif defined(QSC_DILITHIUM_S3N256Q8380417K6)
#		if defined(QSC_MCELIECE_S3N4608T96)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "dilithium-s3_mceliece-s3_sha3_rcs";
#		elif defined(QSC_MCELIECE_S5N6688T128)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "dilithium-s3_mceliece-s5a_sha3_rcs";
#		elif defined(QSC_MCELIECE_S5N6960T119)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "dilithium-s3_mceliece-s5b_sha3_rcs";
#		elif defined(QSC_MCELIECE_S5N8192T128)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "dilithium-s3_mceliece-s5c_sha3_rcs";
#		else
#			error Invalid parameter set!
#		endif
#	elif defined(QSC_DILITHIUM_S5N256Q8380417K8)
#		if defined(QSC_MCELIECE_S3N4608T96)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "dilithium-s5_mceliece-s3_sha3_rcs";
#		elif defined(QSC_MCELIECE_S5N6688T128)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "dilithium-s5_mceliece-s5a_sha3_rcs";
#		elif defined(QSC_MCELIECE_S5N6960T119)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "dilithium-s5_mceliece-s5b_sha3_rcs";
#		elif defined(QSC_MCELIECE_S5N8192T128)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "dilithium-s5_mceliece-s5c_sha3_rcs";
#		else
#			error Invalid parameter set!
#		endif
#	else
#		error Invalid parameter set!
#	endif
#elif defined(QSMP_CONFIG_FALCON_KYBER)
#	if defined(QSC_FALCON_S3SHAKE256F512)
#		if defined(QSC_KYBER_S3Q3329N256K3)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "falcon-s3_kyber-s3_sha3_rcs";
#		elif defined(QSC_KYBER_S5Q3329N256K4)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "falcon-s3_kyber-s5_sha3_rcs";
#		elif defined(QSC_KYBER_S6Q3329N256K5)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "falcon-s3_kyber-s6_sha3_rcs";
#		else
#			error Invalid parameter set!
#		endif
#	elif defined(QSC_FALCON_S5SHAKE256F1024)
#		if defined(QSC_KYBER_S3Q3329N256K3)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "falcon-s5_kyber-s3_sha3_rcs";
#		elif defined(QSC_KYBER_S5Q3329N256K4)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "falcon-s5_kyber-s5_sha3_rcs";
#		elif defined(QSC_KYBER_S6Q3329N256K5)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "falcon-s5_kyber-s6_sha3_rcs";
#		else
#			error Invalid parameter set!
#		endif
#	else
#		error Invalid parameter set!
#	endif
#elif defined(QSMP_CONFIG_FALCON_MCELIECE)
#	if defined(QSC_FALCON_S3SHAKE256F512)
#		if defined(QSC_MCELIECE_S3N4608T96)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "falcon-s3_mceliece-s3_sha3_rcs";
#		elif defined(QSC_MCELIECE_S5N6688T128)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "falcon-s3_mceliece-s5a_sha3_rcs";
#		elif defined(QSC_MCELIECE_S5N6960T119)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "falcon-s3_mceliece-s5b_sha3_rcs";
#		elif defined(QSC_MCELIECE_S5N8192T128)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "falcon-s3_mceliece-s5c_sha3_rcs";
#		else
#			error Invalid parameter set!
#		endif
#	elif defined(QSC_FALCON_S5SHAKE256F1024)
#		if defined(QSC_MCELIECE_S3N4608T96)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "falcon-s5_mceliece-s3_sha3_rcs";
#		elif defined(QSC_MCELIECE_S5N6688T128)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "falcon-s5_mceliece-s5a_sha3_rcs";
#		elif defined(QSC_MCELIECE_S5N6960T119)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "falcon-s5_mceliece-s5b_sha3_rcs";
#		elif defined(QSC_MCELIECE_S5N8192T128)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "falcon-s5_mceliece-s5c_sha3_rcs";
#		else
#			error Invalid parameter set!
#		endif
#	else
#		error Invalid parameter set!
#	endif
#elif defined(QSMP_CONFIG_FALCON_NTRU)
#	if defined(QSC_FALCON_S3SHAKE256F512)
#		if defined(QSC_NTRU_S1HPS2048509)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "falcon-s3_ntru-s1_sha3_rcs";
#		elif defined(QSC_NTRU_HPSS32048677)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "falcon-s3_ntru-s3_sha3_rcs";
#		elif defined(QSC_NTRU_S5HPS4096821)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "falcon-s3_ntru-s5ps_sha3_rcs";
#		elif defined(QSC_NTRU_S5HRSS701)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "falcon-s3_ntru-s5ss_sha3_rcs";
#		else
#			error Invalid parameter set!
#		endif
#	elif defined(QSC_FALCON_S5SHAKE256F1024)
#		if defined(QSC_NTRU_S1HPS2048509)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "falcon-s5_ntru-s1_sha3_rcs";
#		elif defined(QSC_NTRU_HPSS32048677)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "falcon-s5_ntru-s3_sha3_rcs";
#		elif defined(QSC_NTRU_S5HPS4096821)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "falcon-s5_ntru-s5ps_sha3_rcs";
#		elif defined(QSC_NTRU_S5HRSS701)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "falcon-s5_ntru-s5ss_sha3_rcs";
#		else
#			error Invalid parameter set!
#		endif
#	else
#		error Invalid parameter set!
#	endif
#elif defined(QSMP_CONFIG_SPHINCS_MCELIECE)
#	if defined(QSC_SPHINCSPLUS_S3S192SHAKERS)
#		if defined(QSC_MCELIECE_S3N4608T96)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "sphincs-s3s_mceliece-s3_sha3_rcs";
#		elif defined(QSC_MCELIECE_S5N6688T128)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "sphincs-s3s_mceliece-s5a_sha3_rcs";
#		elif defined(QSC_MCELIECE_S5N6960T119)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "sphincs-s3s_mceliece-s5b_sha3_rcs";
#		elif defined(QSC_MCELIECE_S5N8192T128)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "sphincs-s3s_mceliece-s5c_sha3_rcs";
#		else
#			error Invalid parameter set!
#		endif
#	elif defined(QSC_SPHINCSPLUS_S3S192SHAKERF)
#		if defined(QSC_MCELIECE_S3N4608T96)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "sphincs-s3f_mceliece-s3_sha3_rcs";
#		elif defined(QSC_MCELIECE_S5N6688T128)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "sphincs-s3f_mceliece-s5a_sha3_rcs";
#		elif defined(QSC_MCELIECE_S5N6960T119)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "sphincs-s3f_mceliece-s5b_sha3_rcs";
#		elif defined(QSC_MCELIECE_S5N8192T128)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "sphincs-s35_mceliece-s5c_sha3_rcs";
#		else
#			error Invalid parameter set!
#		endif
#	elif defined(QSC_SPHINCSPLUS_S5S256SHAKERS)
#		if defined(QSC_MCELIECE_S3N4608T96)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "sphincs-s5s_mceliece-s3_sha3_rcs";
#		elif defined(QSC_MCELIECE_S5N6688T128)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "sphincs-s5s_mceliece-s5a_sha3_rcs";
#		elif defined(QSC_MCELIECE_S5N6960T119)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "sphincs-s5s_mceliece-s5b_sha3_rcs";
#		elif defined(QSC_MCELIECE_S5N8192T128)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "sphincs-s5s_mceliece-s5c_sha3_rcs";
#		else
#			error Invalid parameter set!
#		endif
#	elif defined(QSC_SPHINCSPLUS_S5S256SHAKERF)
#		if defined(QSC_MCELIECE_S3N4608T96)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "sphincs-s5f_mceliece-s3_sha3_rcs";
#		elif defined(QSC_MCELIECE_S5N6688T128)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "sphincs-s5f_mceliece-s5a_sha3_rcs";
#		elif defined(QSC_MCELIECE_S5N6960T119)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "sphincs-s5f_mceliece-s5b_sha3_rcs";
#		elif defined(QSC_MCELIECE_S5N8192T128)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "sphincs-s5f_mceliece-s5c_sha3_rcs";
#		else
#			error Invalid parameter set!
#		endif
#	elif defined(QSC_SPHINCSPLUS_S6S512SHAKERS)
#		if defined(QSC_MCELIECE_S3N4608T96)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "sphincs-s6s_mceliece-s3_sha3_rcs";
#		elif defined(QSC_MCELIECE_S5N6688T128)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "sphincs-s6s_mceliece-s5a_sha3_rcs";
#		elif defined(QSC_MCELIECE_S5N6960T119)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "sphincs-s6s_mceliece-s5b_sha3_rcs";
#		elif defined(QSC_MCELIECE_S5N8192T128)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "sphincs-s6s_mceliece-s5c_sha3_rcs";
#		else
#			error Invalid parameter set!
#		endif

#	elif defined(QSC_SPHINCSPLUS_S6S512SHAKERF)
#		if defined(QSC_MCELIECE_S3N4608T96)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "sphincs-s6f_mceliece-s3_sha3_rcs";
#		elif defined(QSC_MCELIECE_S5N6688T128)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "sphincs-s6f_mceliece-s5a_sha3_rcs";
#		elif defined(QSC_MCELIECE_S5N6960T119)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "sphincs-s6f_mceliece-s5b_sha3_rcs";
#		elif defined(QSC_MCELIECE_S5N8192T128)
static const char QSMP_CONFIG_STRING[QSMP_CONFIG_SIZE] = "sphincs-s6f_mceliece-s5c_sha3_rcs";
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

#	elif defined(QSC_SPHINCSPLUS_S6S512SHAKERS)
#		define QSMP_PUBKEY_ENCODING_SIZE 172
#	elif defined(QSC_SPHINCSPLUS_S6S512SHAKERF)
#		define QSMP_PUBKEY_ENCODING_SIZE 172

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

#	elif defined(QSC_SPHINCSPLUS_S6S512SHAKERS)
#		define QSMP_PUBKEY_STRING_SIZE 409
#	elif defined(QSC_SPHINCSPLUS_S6S512SHAKERF)
#		define QSMP_PUBKEY_STRING_SIZE 409

#	else
#		error invalid sphincs+ parameter!
#	endif
#else
#	error invalid parameter set!
#endif

/*!
* \def QSMP_SIMPLEX_HASH_SIZE
* \brief The Simplex 256-bit hash function output size
*/
#define QSMP_SIMPLEX_HASH_SIZE 32

/*!
* \def QSMP_SIMPLEX_MACKEY_SIZE
* \brief The Simplex 256-bit mac key size
*/
#define QSMP_SIMPLEX_MACKEY_SIZE 32

/*!
* \def QSMP_SIMPLEX_MACTAG_SIZE
* \brief The Simplex 256-bit mac key size
*/
#define QSMP_SIMPLEX_MACTAG_SIZE 32

/*!
* \def QSMP_SIMPLEX_SKEY_SIZE
* \brief The Simplex 256-bit symmetric cipher key size
*/
#define QSMP_SIMPLEX_SKEY_SIZE 32

/*!
* \def QSMP_SIMPLEX_SCHASH_SIZE
* \brief The Simplex 256-bit session token hash size
*/
#define QSMP_SIMPLEX_SCHASH_SIZE 32

/*!
* \def QSMP_DUPLEX_HASH_SIZE
* \brief The Duplex 512-bit hash function size
*/
#define QSMP_DUPLEX_HASH_SIZE 64

/*!
* \def QSMP_DUPLEX_MACKEY_SIZE
* \brief The Duplex 512-bit mac key size
*/
#define QSMP_DUPLEX_MACKEY_SIZE 64

/*!
* \def QSMP_DUPLEX_MACKEY_SIZE
* \brief The Duplex 512-bit mac tag size
*/
#define QSMP_DUPLEX_MACTAG_SIZE 64

/*!
* \def QSMP_DUPLEX_SKEY_SIZE
* \brief TheDuplex  512-bit symmetric cipher key size
*/
#define QSMP_DUPLEX_SKEY_SIZE 64

/*!
* \def QSMP_DUPLEX_SCHASH_SIZE
* \brief The Duplex session token 512-bit hash size
*/
#define QSMP_DUPLEX_SCHASH_SIZE 64

/*!
* \def QSMP_RTOK_SIZE
* \brief The size of the ratchet token
*/
#define QSMP_RTOK_SIZE 32

/*!
* \def QSMP_NONCE_SIZE
* \brief The size of the symmetric cipher nonce
*/
#define QSMP_NONCE_SIZE 32
/*!
* \def QSMP_CLIENT_PORT
* \brief The default client port address
*/
#define QSMP_CLIENT_PORT 3118

/*!
* \def QSMP_SERVER_PORT
* \brief The default server port address
*/
#define QSMP_SERVER_PORT 3119

/*!
* \def QSMP_CONNECTIONS_INIT 
* \brief The intitial QSMP connections queue size
*/
#define QSMP_CONNECTIONS_INIT 1000

/*!
* \def QSMP_CONNECTIONS_MAX
* \brief The maximum number of connections
* Calculated given approx 5k (3480 connection state + 1500 mtu + overhead),
* per connection on 256GB of DRAM.
* Can be scaled to a greater number provided the hardware can support it.
*/
#define QSMP_CONNECTIONS_MAX 50000

/*!
* \def QSMP_CONNECTION_MTU
* \brief The QSMP packet buffer size
*/
#define QSMP_CONNECTION_MTU 1500

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
* \brief The keep alive timeout in milliseconds (2 minutes)
*/
#define QSMP_KEEPALIVE_TIMEOUT (120 * 1000)

/*!
* \def QSMP_KEYID_SIZE
* \brief The QSMP key identity size
*/
#define QSMP_KEYID_SIZE 16

/*!
* \def QSMP_POLLING_INTERVAL
* \brief The polling interval in milliseconds (2 minutes)
*/
#define QSMP_POLLING_INTERVAL (120 * 1000)

/*!
* \def QSMP_SECRET_SIZE
* \brief The size of the shared secret for each channel
*/
#define QSMP_SECRET_SIZE 32

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
* \def QSMP_TIMESTAMP_STRING_SIZE
* \brief The key expiration timestamp string size
*/
#define QSMP_TIMESTAMP_STRING_SIZE 20

/*!
* \def QSMP_STOKEN_SIZE
* \brief The session token size
*/
#define QSMP_STOKEN_SIZE 64

/*!
* \def QSMP_MESSAGE_MAX
* \brief The maximum message size used during the key exchange (may exceed mtu)
*/
#define QSMP_MESSAGE_MAX (QSMP_HEADER_SIZE + QSMP_CIPHERTEXT_SIZE + QSMP_PUBLICKEY_SIZE + QSMP_DUPLEX_HASH_SIZE + QSMP_SIGNATURE_SIZE)

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
* \def QSMP_SIGKEY_ENCODED_SIZE
* \brief The secret signature key size
*/
#define QSMP_SIGKEY_ENCODED_SIZE (QSMP_KEYID_SIZE + QSMP_TIMESTAMP_SIZE + QSMP_CONFIG_SIZE + QSMP_SIGNKEY_SIZE + QSMP_VERIFYKEY_SIZE)

/*!
* \def QSMP_SEQUENCE_TERMINATOR
* \brief The sequence number of a packet that closes a connection
*/
#define QSMP_SEQUENCE_TERMINATOR 0xFFFFFFFFUL

/* public key encoding constants */

static const char QSMP_PUBKEY_HEADER[] = "------BEGIN QSMP PUBLIC KEY BLOCK------";
static const char QSMP_PUBKEY_VERSION[] = "Version: QSMP v1.2";
static const char QSMP_PUBKEY_CONFIG_PREFIX[] = "Configuration: ";
static const char QSMP_PUBKEY_KEYID_PREFIX[] = "Host ID: ";
static const char QSMP_PUBKEY_EXPIRATION_PREFIX[] = "Expiration: ";
static const char QSMP_PUBKEY_FOOTER[] = "------END QSMP PUBLIC KEY BLOCK------";

/* error code strings */

#define QSMP_ERROR_STRING_DEPTH 26
#define QSMP_ERROR_STRING_WIDTH 128

/*!
* \enum qsmp_configuration
* \brief The asymmetric cryptographic primitive configuration
* Note: Not implemented, informational only
*/
QSMP_EXPORT_API typedef enum qsmp_configuration
{
	qsmp_configuration_none = 0x00,					/*!< No configuration was specified */
	qsmp_configuration_sphincs_mceliece = 0x01,		/*!< The Sphincs+ and McEliece configuration */
	qsmp_configuration_dilithium_kyber = 0x02,		/*!< The Dilithium and Kyber configuration */
	qsmp_configuration_dilithium_mceliece = 0x03,	/*!< The Dilithium and Kyber configuration */
	qsmp_configuration_dilithium_ntru = 0x04,		/*!< The Dilithium and NTRU configuration */
	qsmp_configuration_falcon_kyber = 0x05,			/*!< The Falcon and Kyber configuration */
	qsmp_configuration_falcon_mceliece = 0x06,		/*!< The Falcon and McEliece configuration */
	qsmp_configuration_falcon_ntru = 0x07,			/*!< The Falcon and NTRU configuration */
} qsmp_configuration;

#define QSMP_MESSAGE_STRING_DEPTH 22
#define QSMP_MESSAGE_STRING_WIDTH 128

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

/*!
* \enum qsmp_messages
* \brief The logging message enumeration
*/
QSMP_EXPORT_API typedef enum qsmp_messages
{
	qsmp_messages_none = 0x00,						/*!< No configuration was specified */
	qsmp_messages_accept_fail = 0x01,				/*!< The socket accept failed */
	qsmp_messages_listen_fail = 0x02,				/*!< The listener socket could not connect */
	qsmp_messages_bind_fail = 0x03,					/*!< The listener socket could not bind to the address */
	qsmp_messages_create_fail = 0x04,				/*!< The listener socket could not be created */
	qsmp_messages_connect_success = 0x05,			/*!< The server connected to a host */
	qsmp_messages_receive_fail = 0x06,				/*!< The socket receive function failed */
	qsmp_messages_allocate_fail = 0x07,				/*!< The server memory allocation request has failed */
	qsmp_messages_kex_fail = 0x08,					/*!< The key exchange has experienced a failure */
	qsmp_messages_disconnect = 0x09,				/*!< The server has disconnected the client */
	qsmp_messages_disconnect_fail = 0x0A,			/*!< The server has disconnected the client due to an error */
	qsmp_messages_socket_message = 0x0B,			/*!< The server has had a socket level error */
	qsmp_messages_queue_empty = 0x0C,				/*!< The server has reached the maximum number of connections */
	qsmp_messages_listener_fail = 0x0D,				/*!< The server listener socket has failed */
	qsmp_messages_sockalloc_fail = 0x0E,			/*!< The server has run out of socket connections */
	qsmp_messages_decryption_fail = 0x0F,			/*!< The message decryption has failed */
	qsmp_messages_keepalive_fail = 0x10,			/*!< The keepalive function has failed */
	qsmp_messages_keepalive_timeout = 0x11,			/*!< The keepalive period has been exceeded */
	qsmp_messages_connection_fail = 0x12,			/*!< The connection failed or was interrupted */
	qsmp_messages_invalid_request = 0x13,			/*!< The function received an invalid request */
} qsmp_messages;

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
	"The listener function failed to initialize.",
	"The server has run out of memory.",
	"The keepalive period has been exceeded",
	"The ratchet operation has failed",
};

/*!
* \enum qsmp_errors
* \brief The QSMP error values
*/
QSMP_EXPORT_API typedef enum qsmp_errors
{
	qsmp_error_none = 0x00,						/*!< No error was detected */
	qsmp_error_authentication_failure = 0x01,	/*!< The symmetric cipher had an authentication failure */
	qsmp_error_bad_keep_alive = 0x02,			/*!< The keep alive check failed */
	qsmp_error_channel_down = 0x03,					/*!< The communications channel has failed */
	qsmp_error_connection_failure = 0x04,			/*!< The device could not make a connection to the remote host */
	qsmp_error_connect_failure = 0x05,				/*!< The transmission failed at the KEX connection phase */
	qsmp_error_decapsulation_failure = 0x06,		/*!< The asymmetric cipher failed to decapsulate the shared secret */
	qsmp_error_establish_failure = 0x07,			/*!< The transmission failed at the KEX establish phase */
	qsmp_error_exstart_failure = 0x08,				/*!< The transmission failed at the KEX exstart phase */ //TODO: fix this
	qsmp_error_exchange_failure = 0x09,				/*!< The transmission failed at the KEX exchange phase */
	qsmp_error_hash_invalid = 0x0A,					/*!< The public-key hash is invalid */
	qsmp_error_invalid_input = 0x0B,				/*!< The expected input was invalid */
	qsmp_error_invalid_request = 0x0C,				/*!< The packet flag was unexpected */
	qsmp_error_keep_alive_expired = 0x0D,			/*!< The keep alive has expired with no response */
	qsmp_error_key_expired = 0x0E,					/*!< The QSMP public key has expired  */
	qsmp_error_key_unrecognized = 0x0F,				/*!< The key identity is unrecognized */
	qsmp_error_packet_unsequenced = 0x10,			/*!< The packet was received out of sequence */
	qsmp_error_random_failure = 0x11,				/*!< The random generator has failed */
	qsmp_error_receive_failure = 0x12,				/*!< The receiver failed at the network layer */
	qsmp_error_transmit_failure = 0x13,				/*!< The transmitter failed at the network layer */
	qsmp_error_verify_failure = 0x14,				/*!< The expected data could not be verified */
	qsmp_error_unknown_protocol = 0x15,				/*!< The protocol string was not recognized */
	qsmp_error_listener_fail = 0x16,				/*!< The listener function failed to initialize */
	qsmp_error_accept_fail = 0x17,					/*!< The socket accept function returned an error */
	qsmp_error_hosts_exceeded = 0x18,				/*!< The server has run out of socket connections */
	qsmp_error_memory_allocation = 0x19,			/*!< The server has run out of memory */
	qsmp_error_decryption_failure = 0x1A,			/*!< The decryption authentication has failed */
	qsmp_error_keepalive_timeout = 0x1B,			/*!< The decryption authentication has failed */
	qsmp_error_ratchet_fail = 0x1C,					/*!< The ratchet operation has failed */
} qsmp_errors;

/*!
* \enum qsmp_flags
* \brief The QSMP packet flags
*/
QSMP_EXPORT_API typedef enum qsmp_flags
{
	qsmp_flag_none = 0x00,							/*!< No flag was specified */
	qsmp_flag_connect_request = 0x01,				/*!< The QSMP key-exchange client connection request flag  */
	qsmp_flag_connect_response = 0x02,				/*!< The QSMP key-exchange server connection response flag */
	qsmp_flag_connection_terminate = 0x03,			/*!< The connection is to be terminated */
	qsmp_flag_encrypted_message = 0x04,				/*!< The message has been encrypted flag */
	qsmp_flag_exstart_request = 0x05,				/*!< The QSMP key-exchange client exstart request flag */
	qsmp_flag_exstart_response = 0x06,				/*!< The QSMP key-exchange server exstart response flag */
	qsmp_flag_exchange_request = 0x07,				/*!< The QSMP key-exchange client exchange request flag */
	qsmp_flag_exchange_response = 0x08,				/*!< The QSMP key-exchange server exchange response flag */
	qsmp_flag_establish_request = 0x09,				/*!< The QSMP key-exchange client establish request flag */
	qsmp_flag_establish_response = 0x0A,			/*!< The QSMP key-exchange server establish response flag */
	qsmp_flag_keep_alive_request = 0x0B,			/*!< The packet contains a keep alive request */
	qsmp_flag_keep_alive_response = 0x0C,			/*!< The packet contains a keep alive response */
	qsmp_flag_remote_connected = 0x0D,				/*!< The remote host is connected flag */
	qsmp_flag_remote_terminated = 0x0E,				/*!< The remote host has terminated the connection */
	qsmp_flag_session_established = 0x0F,			/*!< The exchange is in the established state */
	qsmp_flag_session_establish_verify = 0x10,		/*!< The exchange is in the established verify state */
	qsmp_flag_unrecognized_protocol = 0x11,			/*!< The protocol string is not recognized */
	qsmp_flag_ratchet_request = 0x12,				/*!< The host has received a symmetric key ratchet request */
	qsmp_flag_transfer_request = 0x13,				/*!< Reserved - The host has received a transfer request */
	qsmp_flag_error_condition = 0xFF,				/*!< The connection experienced an error */
} qsmp_flags;

/*!
* \struct qsmp_packet
* \brief The QSMP packet structure
*/
QSMP_EXPORT_API typedef struct qsmp_packet
{
	uint8_t flag;									/*!< The packet flag */
	uint32_t msglen;								/*!< The packets message length */
	uint64_t sequence;								/*!< The packet sequence number */
	uint8_t message[QSMP_MESSAGE_MAX];				/*!< The packets message data */
} qsmp_packet;

/*!
* \struct qsmp_client_key
* \brief The QSMP client key structure
*/
QSMP_EXPORT_API typedef struct qsmp_client_key
{
	uint64_t expiration;							/*!< The expiration time, in seconds from epoch */
	uint8_t config[QSMP_CONFIG_SIZE];				/*!< The primitive configuration string */
	uint8_t keyid[QSMP_KEYID_SIZE];					/*!< The key identity string */
	uint8_t verkey[QSMP_VERIFYKEY_SIZE];			/*!< The asymmetric signatures verification-key */
} qsmp_client_key;

/*!
* \struct qsmp_server_key
* \brief The QSMP server key structure
*/
QSMP_EXPORT_API typedef struct qsmp_server_key
{
	uint64_t expiration;							/*!< The expiration time, in seconds from epoch */
	uint8_t config[QSMP_CONFIG_SIZE];				/*!< The primitive configuration string */
	uint8_t keyid[QSMP_KEYID_SIZE];					/*!< The key identity string */
	uint8_t sigkey[QSMP_SIGNKEY_SIZE];				/*!< The asymmetric signature signing-key */
	uint8_t verkey[QSMP_VERIFYKEY_SIZE];			/*!< The asymmetric signature verification-key */
} qsmp_server_key;

/*!
* \struct qsmp_keep_alive_state
* \brief The QSMP keep alive state structure
*/
QSMP_EXPORT_API typedef struct qsmp_keep_alive_state
{
	qsc_socket target;								/*!< The target socket structure */
	uint64_t etime;									/*!< The keep alive epoch time  */
	uint64_t seqctr;								/*!< The keep alive packet sequence counter  */
	bool recd;										/*!< The keep alive response received status  */
} qsmp_keep_alive_state;

/*!
* \struct qsmp_connection_state
* \brief The QSMP socket connection state structure
*/
QSMP_EXPORT_API typedef struct qsmp_connection_state
{
	qsc_socket target;								/*!< The target socket structure */
	qsc_rcs_state rxcpr;							/*!< The receive channel cipher state */
	qsc_rcs_state txcpr;							/*!< The transmit channel cipher state */
	uint64_t rxseq;									/*!< The receive channels packet sequence number  */
	uint64_t txseq;									/*!< The transmit channels packet sequence number  */
	uint32_t instance;								/*!< The connections instance count */
	qsmp_flags exflag;								/*!< The KEX position flag */
	qsc_keccak_state rtcs;							/*!< The ratchet key generation state */
} qsmp_connection_state;

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
* \brief Close the network connection between hosts
*
* \param cns: A pointer to the connection state structure
* \param err: The error message
* \param notify: Notify the remote host connection is closing
*/
QSMP_EXPORT_API void qsmp_connection_close(qsmp_connection_state* cns, qsmp_errors err, bool notify);

/**
* \brief Reset the connection state
*
* \param cns: A pointer to the connection state structure
*/
QSMP_EXPORT_API void qsmp_connection_state_dispose(qsmp_connection_state* cns);

/**
* \brief Decode a public key string and populate a client key structure
*
* \param pubk: A pointer to the output client key
* \param enck: [const] The input encoded key
*
* \return: Returns true for success
*/
QSMP_EXPORT_API bool qsmp_decode_public_key(qsmp_client_key* pubk, const char enck[QSMP_PUBKEY_STRING_SIZE]);

/**
* \brief Decode a secret signature key structure and copy to an array
*
* \param prik: A pointer to the output server key structure
* \param serk: [const] The input encoded secret key string
*/
QSMP_EXPORT_API void qsmp_deserialize_signature_key(qsmp_server_key* prik, const uint8_t serk[QSMP_SIGKEY_ENCODED_SIZE]);

/**
* \brief Encode a public key structure and copy to a string
*
* \param enck: The output encoded public key string
* \param prik: [const] A pointer to the server key structure
*/
QSMP_EXPORT_API void qsmp_encode_public_key(char enck[QSMP_PUBKEY_STRING_SIZE], const qsmp_server_key* prik);

/**
* \brief Decrypt a message and copy it to the message output
*
* \param cns: A pointer to the connection state structure
* \param message: The message output array
* \param msglen: A pointer receiving the message length
* \param packetin: [const] A pointer to the input packet structure
*
* \return: Returns the function error state
*/
QSMP_EXPORT_API qsmp_errors qsmp_decrypt_packet(qsmp_connection_state* cns, uint8_t* message, size_t* msglen, const qsmp_packet* packetin);

/**
* \brief Encrypt a message and build an output packet
*
* \param cns: A pointer to the connection state structure
* \param packetout: A pointer to the output packet structure
* \param message: [const] The input message array
* \param msglen: The length of the message array
*
* \return: Returns the function error state
*/
QSMP_EXPORT_API qsmp_errors qsmp_encrypt_packet(qsmp_connection_state* cns, qsmp_packet* packetout, const uint8_t* message, size_t msglen);

/**
* \brief Return a pointer to a string description of an error code
*
* \param error: The error type
* 
* \return Returns a pointer to an error string or NULL
*/
QSMP_EXPORT_API const char* qsmp_error_to_string(qsmp_errors error);

/**
* \brief Generate a QSMP key-pair; generates the public and private asymmetric signature keys.
*
* \param pubkey: The public key, distributed to clients
* \param prikey: The private key, a secret key known only by the server
* \param keyid: [const] The key identity string
*/
QSMP_EXPORT_API void qsmp_generate_keypair(qsmp_client_key* pubkey, qsmp_server_key* prikey, const uint8_t keyid[QSMP_KEYID_SIZE]);

/**
* \brief Get the error string description
*
* \param emsg: The message enumeration
* 
* \return Returns a pointer to the message string or NULL
*/
QSMP_EXPORT_API const char* qsmp_get_error_description(qsmp_messages emsg);

/**
* \brief Log the message, socket error, and string description
*
* \param emsg: The message enumeration
* \param err: The socket exception enumeration
* \param msg: [const] The message string
*/
QSMP_EXPORT_API void qsmp_log_error(qsmp_messages emsg, qsc_socket_exceptions err, const char* msg);

/**
* \brief Log a message
*
* \param emsg: The message enumeration
*/
QSMP_EXPORT_API void qsmp_log_message(qsmp_messages emsg);

/**
* \brief Log a message and description
*
* \param emsg: The message enumeration
* \param msg: [const] The message string
*/
QSMP_EXPORT_API void qsmp_log_write(qsmp_messages emsg, const char* msg);

/**
* \brief Clear a packet's state
*
* \param packet: A pointer to the packet structure
*/
QSMP_EXPORT_API void qsmp_packet_clear(qsmp_packet* packet);

/**
* \brief Populate a packet structure with an error message
*
* \param packet: A pointer to the packet structure
* \param error: The error type
*/
QSMP_EXPORT_API void qsmp_packet_error_message(qsmp_packet* packet, qsmp_errors error);

/**
* \brief Deserialize a byte array to a packet header
*
* \param packet: [const] The header byte array to deserialize
* \param header: A pointer to the packet structure
*/
QSMP_EXPORT_API void qsmp_packet_header_deserialize(const uint8_t* header, qsmp_packet* packet);

/**
* \brief Serialize a packet header to a byte array
*
* \param packet: [const] A pointer to the packet structure to serialize
* \param header: The header byte array
*/
QSMP_EXPORT_API void qsmp_packet_header_serialize(const qsmp_packet* packet, uint8_t* header);

/**
* \brief Serialize a packet to a byte array
*
* \param packet: [const] The header byte array to deserialize
* \param pstream: A pointer to the packet structure
* 
* \return Returns the size of the byte stream
*/
QSMP_EXPORT_API size_t qsmp_packet_to_stream(const qsmp_packet* packet, uint8_t* pstream);

/**
* \brief Encode a secret key structure and copy to a string
*
* \param serk: The output encoded public key string
* \param prik: [const] A pointer to the secret server key structure
*/
QSMP_EXPORT_API void qsmp_serialize_signature_key(uint8_t serk[QSMP_SIGKEY_ENCODED_SIZE], const qsmp_server_key* prik);

/**
* \brief Deserialize a byte array to a packet
*
* \param [const] pstream: The header byte array to deserialize
* \param packet: A pointer to the packet structure
*/
QSMP_EXPORT_API void qsmp_stream_to_packet(const uint8_t* pstream, qsmp_packet* packet);

#endif

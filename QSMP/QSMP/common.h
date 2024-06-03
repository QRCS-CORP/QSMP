
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

#ifndef QSMP_MASTER_COMMON_H
#define QSMP_MASTER_COMMON_H

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include "../../QSC/QSC/common.h"

/**
* \file common.h
* \brief QSMP common includes and definitions
* \note These are internal definitions.
*
* \author   John G. Underhill
* \version  1.2a: 2022-05-01
* \date     May 1, 2022
* \contact: develop@qscs.ca
*/

/*!
\def QSMP_DLL_API
* \brief Enables the dll api exports
*/
#if defined(_DLL)
#	define QSMP_DLL_API
#endif
/*!
\def QSMP_EXPORT_API
* \brief The api export prefix
*/
#if defined(QSMP_DLL_API)
#	if defined(QSC_SYSTEM_COMPILER_MSC)
#		if defined(QSMP_DLL_IMPORT)
#			define QSMP_EXPORT_API __declspec(dllimport)
#		else
#			define QSMP_EXPORT_API __declspec(dllexport)
#		endif
#	elif defined(QSC_SYSTEM_COMPILER_GCC)
#		if defined(QSMP_DLL_IMPORT)
#		define QSMP_EXPORT_API __attribute__((dllimport))
#		else
#		define QSMP_EXPORT_API __attribute__((dllexport))
#		endif
#	else
#		if defined(__SUNPRO_C)
#			if !defined(__GNU_C__)
#				define QSMP_EXPORT_API __attribute__ (visibility(__global))
#			else
#				define QSMP_EXPORT_API __attribute__ __global
#			endif
#		elif defined(_MSG_VER)
#			define QSMP_EXPORT_API extern __declspec(dllexport)
#		else
#			define QSMP_EXPORT_API __attribute__ ((visibility ("default")))
#		endif
#	endif
#else
#	define QSMP_EXPORT_API
#endif


#endif

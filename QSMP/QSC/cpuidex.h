/*
* 2022 John G. Underhill
* All Rights Reserved.
*
* NOTICE:  All information contained herein is, and remains
* the property of John G. Underhill.
* The intellectual and technical concepts contained
* herein are proprietary to John G. Underhill
* and his suppliers and may be covered by U.S. and Foreign Patents,
* patents in process, and are protected by trade secret or copyright law.
* Dissemination of this information or reproduction of this material
* is strictly forbidden unless prior written permission is obtained
* from Digital Freedom Defense Incorporated.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
*
* This library was published publicly in hopes that it would aid in prototyping
* post-quantum secure primitives for educational purposes only.
* All and any commercial uses of this library are exclusively reserved by the author
* John G. Underhill.
* Any use of this library in a commercial context must be approved by the author
* in writing.
* All rights for commercial and/or non-educational purposes, are fully reserved
* by the author.
*/

#ifndef QSC_CPUIDEX_H
#define QSC_CPUIDEX_H

/**
* \file cpuidex.h
* \brief Retrieves CPU features and capabilities
*/

#include "common.h"

/*!
* \def QSC_CPUIDEX_SERIAL_LENGTH
* \brief The CPU serial number length
*/
#define QSC_CPUIDEX_SERIAL_LENGTH 12

/*!
* \def QSC_CPUIDEX_VENDOR_LENGTH
* \brief The CPU vendor name length
*/
#if defined(QSC_SYSTEM_OS_APPLE) && defined(QSC_SYSTEM_COMPILER_GCC)
#	define QSC_CPUIDEX_VENDOR_LENGTH 32
#else
#	define QSC_CPUIDEX_VENDOR_LENGTH 12
#endif

/*!
* \enum qsc_cpuidex_cpu_type
* \brief The detectable CPU architectures
*/
typedef enum qsc_cpuidex_cpu_type
{
    qsc_cpuid_unknown = 0,                  /*!< The CPU type is unknown  */
    qsc_cpuid_amd = 1,                      /*!< The CPU type is AMD  */
    qsc_cpuid_intel = 2,                    /*!< The CPU type is Intel */
    qsc_cpuid_via = 3,                      /*!< The CPU type is VIA */
    qsc_cpuid_hygion = 4,                   /*!< The CPU type is Hygion */
} qsc_cpuidex_cpu_type;

/*!
* \struct qsc_cpuidex_cpu_features
* \brief Contains the CPU feature availability
*/
QSC_EXPORT_API typedef struct qsc_cpuidex_cpu_features
{
	bool adx;	                            	/*!< The ADX flag  */
    bool aesni;	                            	/*!< The AESNI flag  */
    bool pcmul;                             	/*!< The PCLMULQDQ flag */

    bool armv7;                                 /*!< ARMv7 cpu flag */
    bool neon;                                  /*!< Neon instructions flag */
    bool sha256;                                /*!< SHA2-256 flag */
    bool sha512;                                /*!< SHA2-512 flag */
    bool sha3;                                  /*!< SHA3 flag */

    bool avx;                               	/*!< The AVX flag */
    bool avx2;                              	/*!< The AVX2 flag */
    bool avx512f;                           	/*!< The AVX512F flag */
    bool hyperthread;                       	/*!< The hyper-thread flag */
    bool rdrand;                            	/*!< The RDRAND flag */
    bool rdtcsp;                            	/*!< The RDTCSP flag */

    uint32_t cacheline;                     	/*!< The number of cache lines */
    uint32_t cores;                         	/*!< The number of cores */
    uint32_t cpus;                          	/*!< The number of CPUs */
    uint32_t freqbase;                      	/*!< The frequency base */
    uint32_t freqmax;                       	/*!< The frequency maximum */
    uint32_t freqref;                       	/*!< The frequency reference */
    uint32_t l1cache;                       	/*!< The L1 cache size */
    uint32_t l1cacheline;                   	/*!< The L1 cache line size */
    uint32_t l2associative;                 	/*!< The L2 associative size */
    uint32_t l2cache;                       	/*!< The L2 cache size */
    char serial[QSC_CPUIDEX_SERIAL_LENGTH];   	/*!< The CPU serial number */
    char vendor[QSC_CPUIDEX_VENDOR_LENGTH];   	/*!< The CPU vendor name */
    qsc_cpuidex_cpu_type cputype;             	/*!< The CPU manufacturer */
} qsc_cpuidex_cpu_features;


/**
* \brief Get a list of supported CPU features
*
* \param features: A qsc_cpuidex_cpu_features structure
* \return Returns true for success, false if CPU is not recognized
*/
QSC_EXPORT_API bool qsc_cpuidex_features_set(qsc_cpuidex_cpu_features* const features);

/**
* \brief Print a list of supported CPU features
*/
QSC_EXPORT_API void qsc_cpuidex_print_stats();

#endif

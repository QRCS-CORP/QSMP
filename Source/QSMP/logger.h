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

#ifndef QSMP_LOGGER_H
#define QSMP_LOGGER_H

#include "qsmpcommon.h"

/**
 * \file logger.h
 * \brief QSMP logging functions.
 *
 * \details
 * This header file defines the internal logging functions for the Quantum Secure Messaging Protocol (QSMP).
 * The logging subsystem provides basic functionality to create, manage, and inspect log files. These functions
 * allow the QSMP system to record operational events, errors, and other informational messages which can be used
 * for debugging and monitoring purposes.
 *
 * The following constants are defined:
 *
 * - \c QSMP_LOGGING_MESSAGE_MAX: Maximum length allowed for a single log message.
 * - \c QSMP_LOGGER_PATH: The default directory path for QSMP log files.
 * - \c QSMP_LOGGER_FILE: The default filename for the QSMP log.
 * - \c QSMP_LOGGER_HEAD: The header string for the log file, which typically includes version information.
 *
 * \note These functions and constants are internal and non-exportable.
 */

/**
 * \def QSMP_LOGGING_MESSAGE_MAX
 * \brief Maximum length of a log message.
 *
 * This macro defines the maximum number of characters that a single log message may contain.
 */
#define QSMP_LOGGING_MESSAGE_MAX 256U

/**
 * \var QSMP_LOGGER_PATH
 * \brief Default directory path for QSMP log files.
 *
 * This static constant defines the default directory where the QSMP log file is stored.
 */
static const char QSMP_LOGGER_PATH[] = "QSMP";

/**
 * \var QSMP_LOGGER_FILE
 * \brief Default log file name.
 *
 * This static constant defines the default name of the QSMP log file.
 */
static const char QSMP_LOGGER_FILE[] = "qsmp.log";

/**
 * \var QSMP_LOGGER_HEAD
 * \brief Default log file header.
 *
 * This static constant contains the header information written to the log file, typically including version information.
 */
static const char QSMP_LOGGER_HEAD[] = "QSMP Version 1.1a";

/**
 * \brief Check if the QSMP log file exists.
 *
 * \details
 * This function checks for the existence of the QSMP log file in the configured logging directory.
 *
 * \return Returns true if the log file exists; otherwise, false.
 */
bool qsmp_logger_exists(void);

/**
 * \brief Initialize the QSMP logger.
 *
 * \details
 * This function initializes the logging subsystem by setting the log file path and creating the log file if it does not
 * already exist. The default header (\c QSMP_LOGGER_HEAD) is written to the log file upon initialization.
 *
 * \param path The file path or directory where the log file should be created.
 */
void qsmp_logger_initialize(const char* path);

/**
 * \brief Print the contents of the QSMP log file.
 *
 * \details
 * This function outputs the entire contents of the QSMP log file to the standard output or designated debug stream.
 * It is useful for real-time monitoring and debugging purposes.
 */
void qsmp_logger_print(void);

/**
 * \brief Read the QSMP log file into a provided buffer.
 *
 * \details
 * This function reads the content of the QSMP log file and copies it into the specified output buffer.
 * The caller must ensure that the output buffer is large enough to hold the log data, up to \c otplen bytes.
 *
 * \param output A pointer to the buffer where the log content will be stored.
 * \param otplen The size, in bytes, of the output buffer.
 */
void qsmp_logger_read(char* output, size_t otplen);

/**
 * \brief Reset the QSMP log.
 *
 * \details
 * This function erases all the contents of the QSMP log file, effectively resetting it to an empty state.
 * This operation is useful for clearing old log data before starting a new session.
 */
void qsmp_logger_reset(void);

/**
 * \brief Get the current size of the QSMP log file.
 *
 * \details
 * This function returns the size of the log file in bytes. It can be used to monitor log growth and manage log rotation.
 *
 * \return The size of the log file in bytes.
 */
size_t qsmp_logger_size(void);

/**
 * \brief Write a message to the QSMP log file.
 *
 * \details
 * This function writes the specified log message to the QSMP log file. The message should be a null-terminated string,
 * and its length should not exceed \c QSMP_LOGGING_MESSAGE_MAX characters.
 *
 * \param message [const] The log message to be written.
 *
 * \return Returns true if the message was successfully written to the log file; otherwise, false.
 */
bool qsmp_logger_write(const char* message);

/**
 * \brief Run a manual test of the QSMP logger functions.
 *
 * \details
 * This function performs a series of tests on the QSMP logging subsystem. The test routine includes:
 *
 * - Initializing the logger with a test path.
 * - Writing one or more test messages to the log.
 * - Reading and printing the log content.
 * - Resetting the log and verifying that it has been cleared.
 * - Checking the reported log file size.
 *
 * The function returns true if all logger operations work as expected.
 *
 * \return Returns true if all logger tests succeed; otherwise, false.
 */
bool qsmp_logger_test(void);

#endif

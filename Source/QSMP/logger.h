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
 * Contact: john.underhill@protonmail.com
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
#define QSMP_LOGGING_MESSAGE_MAX 256

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

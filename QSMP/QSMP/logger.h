
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

#ifndef QSMP_LOGGER_H
#define QSMP_LOGGER_H

#include "common.h"

/**
* \file logger.h
* \brief QSMP logging functions.
* \note These are internal non-exportable functions.
* \author   John G. Underhill
* \version  1.2a: 2022-05-01
* \date     May 1, 2022
* \contact: develop@qscs.ca
*/

#define QSMP_LOGGING_MESSAGE_MAX 256

static const char QSMP_LOGGER_PATH[] = "QSMP";
static const char QSMP_LOGGER_FILE[] = "qsmp.log";
static const char QSMP_LOGGER_HEAD[] = "QSMP Version 1.1a";

/**
* \brief Test if the log exists
*
* \return: True if the log file exists
*/
bool qsmp_logger_exists(void);

/**
* \brief Initialize the logger
*
* \param path: The log file path
*/
void qsmp_logger_initialize(const char* path);

/**
* \brief Print the log file
*/
void qsmp_logger_print(void);

/**
* \brief Read from the log
*
* \param output: The output array
* \param otplen: The size of the output array
*/
void qsmp_logger_read(char* output, size_t otplen);

/**
* \brief Reset the logger, erasing the log file.
*/
void qsmp_logger_reset(void);

/**
* \brief Get the log file size
* 
* \return: Returns the log file size
*/
size_t qsmp_logger_size(void);

/**
* \brief Write a message to the log
*
* \param message: [const] The log message
* 
* \return: Returns true on success
*/
bool qsmp_logger_write(const char* message);

/**
* \brief A manual test of the logger functions
* 
* \return: Returns true on success
*/
bool qsmp_logger_test(void);

#endif
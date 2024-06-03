
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

#ifndef QSMP_SENDER_APP_H
#define QSMP_SENDER_APP_H

#include "common.h"

/**
* \file appclt.h
* \brief The client application
* Version 1.2a: 2022-05-01
*/

static const char QSMP_PUBKEY_EXTENSION[] = ".qpkey";
static const char QSMP_PUBKEY_NAME[] = "sender_public_key.qpkey";
static const char QSMP_PRIKEY_NAME[] = "sender_secret_key.qskey";
static const char QSMP_APP_PATH[] = "QSMP";
static const char QSMP_LISTENER_PATH[] = "Listener";
static const char QSMP_SENDER_PATH[] = "Sender";

#endif

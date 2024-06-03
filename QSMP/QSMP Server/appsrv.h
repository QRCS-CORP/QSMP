
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

#ifndef QSMP_SERVER_APP_H
#define QSMP_SERVER_APP_H

#include "common.h"
#include "../../QSC/QSC/socketbase.h"
#include "../../QSC/QSC/socketserver.h"

/**
* \file appsrv.h
* \brief The server application
* Version 1.2a: 2022-05-01
*/

#define QSMP_SERVER_MAX_CLIENTS 8192

static const char QSMP_PUBKEY_NAME[] = "server_public_key.qpkey";
static const char QSMP_PRIKEY_NAME[] = "server_secret_key.qskey";
static const char QSMP_APP_PATH[] = "QSMP";

#endif

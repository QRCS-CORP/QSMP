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

#ifndef QSMP_CLIENT_APP_H
#define QSMP_CLIENT_APP_H

#include "common.h"
#include "../QSC/socketbase.h"

#define QSMP_MESSAGE_MAX 10240
#define QSMP_SERVER_PORT 2020

static const char QSMP_PUBKEY_NAME[] = "\\pubkey.qpkey";

void qsc_socket_exception_callback(qsc_socket* source, qsc_socket_exceptions error);
void qsc_socket_receive_async_callback(qsc_socket* source, uint8_t* message, size_t msglen);

#endif
/*
* Copyright (c) 2023 Quantum Secure Cryptographic Solutions QSCS Corp. (QSCS.ca).
* This file is part of the QSC Cryptographic library.
* The QSC library was written as a prototyping library for post-quantum primitives,
* in the hopes that it would be useful for educational purposes only.
* Any use of the QSC library in a commercial context, or reproduction of original material
* contained in this library is strictly forbidden unless prior written consent is obtained
* from the QSCS Corporation.
*
* The AGPL version 3 License (AGPLv3)
* This program is free software : you can redistribute it and / or modify
* it under the terms of the GNU Affero General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
* See the GNU Affero General Public License for more details.
*
* You should have received a copy of the GNU Affero General Public License
* along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef QSC_NETUTILS_H
#define QSC_NETUTILS_H

#include "common.h"
#include "ipinfo.h"
#include "socket.h"
#include "socketbase.h"

/*
* \file netutils.h
* \brief Network utilities; common networking support functions
*/

/* bogus winbase.h error */
QSC_SYSTEM_CONDITION_IGNORE(5105)

/*!
\def QSC_NETUTILS_ADAPTOR_NAME_SIZE
* The network adaptors info string
*/
#define QSC_NETUTILS_ADAPTOR_NAME_SIZE 0x104

/*!
\def QSC_NETUTILS_ADAPTOR_DESCRIPTION_SIZE
* The network adaptors description string
*/
#define QSC_NETUTILS_ADAPTOR_DESCRIPTION_SIZE 0x84

/*!
\def QSC_NETUTILS_ADAPTOR_INFO_ARRAY_SIZE
* The network adaptors info array size
*/
#define QSC_NETUTILS_ADAPTOR_INFO_ARRAY_SIZE 0x08

/*!
\def QSC_NETUTILS_DOMAIN_NAME_SIZE
* The size of the domain name buffer
*/
#define QSC_NETUTILS_DOMAIN_NAME_SIZE 0x104

/*!
\def QSC_NETUTILS_HOSTS_NAME_SIZE
* The size of the hosts name buffer
*/
#define QSC_NETUTILS_HOSTS_NAME_SIZE 0x104

/*!
\def QSC_NETUTILS_IP_STRING_SIZE
* The IP address string size
*/
#define QSC_NETUTILS_IP_STRING_SIZE 0x80

/*!
\def QSC_NETUTILS_MAC_ADDRESS_SIZE
* The MAC address buffer length
*/
#define QSC_NETUTILS_MAC_ADDRESS_SIZE 0x12

/*!
\def QSC_NETUTILS_NAME_BUFFER_SIZE
* The size of the protocol name buffer
*/
#define QSC_NETUTILS_NAME_BUFFER_SIZE 0x80

/*!
\def QSC_NETUTILS_SERVICE_NAME_BUFFER_SIZE
* The size of the service name buffer
*/
#define QSC_NETUTILS_SERVICE_NAME_BUFFER_SIZE 0x80

/*!
\def QSC_NETUTILS_SUBNET_STRING_SIZE
* The size of the subnet string
*/
#define QSC_NETUTILS_SUBNET_STRING_SIZE 0x10

/*! \struct qsc_netutils_adaptor_info
* \brief The netutils adaptor info structure
*/
typedef struct qsc_netutils_adaptor_info
{
	char desc[QSC_NETUTILS_ADAPTOR_DESCRIPTION_SIZE];	/*!< The description string  */
	char dhcp[QSC_NETUTILS_IP_STRING_SIZE];			/*!< The DHCP address  */
	char gateway[QSC_NETUTILS_IP_STRING_SIZE];		/*!< The IP gateway address  */
	char ip[QSC_NETUTILS_IP_STRING_SIZE];				/*!< The interface IP address  */
	uint8_t mac[QSC_NETUTILS_MAC_ADDRESS_SIZE];		/*!< The MAC address  */
	char name[QSC_NETUTILS_ADAPTOR_NAME_SIZE];		/*!< The host name  */
	char subnet[QSC_NETUTILS_IP_STRING_SIZE];			/*!< The subnet address  */

} qsc_netutils_adaptor_info;

//~~~IP Address~~~//

/**
* \brief Retrieves the address information on a named addressable interface
*
* \param info: The adaptor info structure
* \param infname: The adaptor interface name, ex 'eth0' or 'wlan0'
*/
QSC_EXPORT_API void qsc_netutils_get_adaptor_info(qsc_netutils_adaptor_info* info, const char* infname);

/**
* \brief Retrieves the mac address of the primary interface
*
* \param mac: The outout array receiving the MAC address
*/
QSC_EXPORT_API void qsc_netutils_get_mac_address(uint8_t mac[QSC_NETUTILS_MAC_ADDRESS_SIZE]);

/**
* \brief Parse a string for a number
*
* \param source: [const] The string to convert
*
* \return The number found in the string
*/
QSC_EXPORT_API uint32_t qsc_netutils_atoi(const char* source);

/**
* \brief Retrieves the hosts domain name
*
* \param output: The source socket instance
*
* \return Returns the peers name string
*/
QSC_EXPORT_API size_t qsc_netutils_get_domain_name(char output[QSC_NETUTILS_DOMAIN_NAME_SIZE]);

/**
* \brief Retrieves the host name of the local machine
*
* \param host: The host name
* \return The size of the host name
*/
QSC_EXPORT_API size_t qsc_netutils_get_host_name(char host[QSC_NETUTILS_HOSTS_NAME_SIZE]);

/**
* \brief Retrieves fully qualified name from an IPv4 address
*
* \param address: The input IPv4 address string
* \param host: The output host name
*/
QSC_EXPORT_API void qsc_netutils_get_name_from_ipv4_address(const qsc_ipinfo_ipv4_address address, char host[QSC_NETUTILS_HOSTS_NAME_SIZE]);

/**
* \brief Retrieves the local IPv4 address
*
* \return The default interface IP address
*/
QSC_EXPORT_API qsc_ipinfo_ipv4_address qsc_netutils_get_ipv4_address(void);

/**
* \brief Retrieves the local IPv6 address
*
* \return The default interface IP address
*/
QSC_EXPORT_API qsc_ipinfo_ipv6_address qsc_netutils_get_ipv6_address(void);

/**
* \brief Retrieves the IPv4 address information for a remote host
*
* \param host: [const] The hosts qualified name
* \param service: [const] The service name
*
* \return Returns the default interface IP info
*/
QSC_EXPORT_API qsc_ipinfo_ipv4_info qsc_netutils_get_ipv4_info(const char host[QSC_NETUTILS_HOSTS_NAME_SIZE], const char service[QSC_NETUTILS_SERVICE_NAME_BUFFER_SIZE]);

/**
* \brief Retrieves the IPv6 address information for a remote host
*
* \param host: [const] The hosts qualified name
* \param service: [const] The service name
*
* \return Returns the default interface IP info
*/
QSC_EXPORT_API qsc_ipinfo_ipv6_info qsc_netutils_get_ipv6_info(const char host[QSC_NETUTILS_HOSTS_NAME_SIZE], const char service[QSC_NETUTILS_SERVICE_NAME_BUFFER_SIZE]);

/**
* \brief Retrieves the host name of the connected peer
*
* \param output: The output buffer
* \param sock: [const] The source socket instance
*
* \return Returns the peers name string
*/
QSC_EXPORT_API void qsc_netutils_get_peer_name(char output[QSC_NETUTILS_HOSTS_NAME_SIZE], const qsc_socket* sock);

/**
* \brief Retrieves the socket name of the connected peer
*
* \param output: The output buffer
* \param sock: [const] The source socket instance
*
* \return Retrieves the name of the socket
*/
QSC_EXPORT_API void qsc_netutils_get_socket_name(char output[QSC_NETUTILS_NAME_BUFFER_SIZE], const qsc_socket* sock);

/**
* \brief Get the port number using the connection parameters
*
* \param portname: [const] The port name
* \param protocol: [const] The protocol name
*
* \return The port number, or zero on failure
*/
QSC_EXPORT_API uint16_t qsc_netutils_port_name_to_number(const char portname[QSC_NETUTILS_HOSTS_NAME_SIZE], const char protocol[QSC_NETUTILS_NAME_BUFFER_SIZE]);

#if defined(QSC_DEBUG_MODE)
/**
* \brief Print the output of network function calls
*/
QSC_EXPORT_API void qsc_netutils_values_print(void);
#endif

#endif

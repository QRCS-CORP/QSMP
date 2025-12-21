
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

#include "appclt.h"
#include "client.h"
#include "async.h"
#include "consoleutils.h"
#include "fileutils.h"
#include "folderutils.h"
#include "memutils.h"
#include "stringutils.h"

static void client_print_prompt(void)
{
	qsc_consoleutils_print_safe("client> ");
}

static void client_print_message(const char* message)
{
	size_t slen;

	if (message != NULL)
	{
		slen = qsc_stringutils_string_size(message);

		if (slen != 0U)
		{
			client_print_prompt();
			qsc_consoleutils_print_line(message);
		}
		else
		{
			client_print_prompt();
		}
	}
}

static void client_print_string(const char* message, size_t msglen)
{
	if (message != NULL && msglen != 0U)
	{
		qsc_consoleutils_print_line(message);
	}
}

static void client_print_banner(void)
{
	qsc_consoleutils_print_line("QSMP: Client Example Project");
	qsc_consoleutils_print_line("Quantum Secure Messaging Protocol simplex-mode client.");
	qsc_consoleutils_print_line("Enter the IP address and the server public key to connect.");
	qsc_consoleutils_print_line("Type 'qsmp quit' to close the connection and exit the application.");
	qsc_consoleutils_print_line("");
	qsc_consoleutils_print_line("Release:   v1.3.0.0c (A3)");
	qsc_consoleutils_print_line("Date:      December 19, 2025");
	qsc_consoleutils_print_line("Contact:   contact@qrcscorp.ca");
	qsc_consoleutils_print_line("");
}

static bool client_ipv4_dialogue(qsc_ipinfo_ipv4_address* address, qsmp_client_verification_key* ckey)
{
	uint8_t* pkey;
	char fpath[QSC_SYSTEM_MAX_PATH] = { 0 };
	char sadd[QSC_SYSTEM_MAX_PATH] = { 0 };
	qsc_ipinfo_ipv4_address addv4t = { 0 };
	size_t elen;
	size_t slen;
	bool res;

	res = false;

	client_print_message("Enter the destination IPv4 address, ex. 192.168.1.1");
	client_print_message("");
	slen = qsc_consoleutils_get_formatted_line(sadd, sizeof(sadd));

	if (slen >= QSC_IPINFO_IPV4_MINLEN)
	{
		addv4t = qsc_ipinfo_ipv4_address_from_string(sadd);

		res = (qsc_ipinfo_ipv4_address_is_valid(&addv4t) == true && 
			qsc_ipinfo_ipv4_address_is_zeroed(&addv4t) == false);

		if (res == true)
		{
			qsc_memutils_copy(address->ipv4, addv4t.ipv4, sizeof(addv4t.ipv4));
		}
		else
		{
			client_print_message("The address format is invalid.");
		}
	}
	else
	{
		client_print_message("The address format is invalid.");
	}

	if (res == true)
	{
		client_print_message("Enter the path of the public key:");
		client_print_message("");
		slen = qsc_consoleutils_get_line(fpath, sizeof(fpath)) - 1;

		if (slen > 0)
		{
			if (qsc_fileutils_exists(fpath) == true && qsc_stringutils_string_contains(fpath, QSMP_PUBKEY_NAME) == true)
			{
				elen = qsmp_public_key_encoding_size();
				pkey = qsc_memutils_malloc(elen);

				if (pkey != NULL)
				{
					qsc_memutils_clear(pkey, elen);
					qsc_fileutils_copy_file_to_stream(fpath, (char*)pkey, elen);
					res = qsmp_public_key_decode(ckey, (char*)pkey, elen);
					qsc_memutils_alloc_free(pkey);
				}
				else
				{
					res = false;
				}

				if (res == false)
				{
					client_print_message("The public key is invalid.");
				}
			}
			else
			{
				res = false;
				client_print_message("The path is invalid or inaccessable.");
			}
		}
	}

	return res;
}

static void client_receive_callback(qsmp_connection_state* cns, const uint8_t* pmsg, size_t msglen)
{
	char* cmsg;
	
	(void)cns;
	cmsg = qsc_memutils_malloc(msglen + sizeof(char));

	if (cmsg != NULL)
	{
		qsc_memutils_clear(cmsg, msglen + sizeof(char));
		qsc_memutils_copy(cmsg, pmsg, msglen);
		client_print_string(cmsg, msglen);
		client_print_prompt();
		qsc_memutils_alloc_free(cmsg);
	}
}

static void client_send_loop(qsmp_connection_state* cns)
{
	qsmp_network_packet pkt = { 0 };
	uint8_t pmsg[QSMP_CONNECTION_MTU] = { 0U };
	uint8_t msgstr[QSMP_CONNECTION_MTU] = { 0U };
	char sin[QSMP_CONNECTION_MTU + 1U] = { 0 };
	size_t mlen;

	mlen = 0U;

	/* start the sender loop */
	while (true)
	{
		client_print_prompt();

		if (qsc_consoleutils_line_contains(sin, "qsmp quit"))
		{
			qsmp_connection_close(cns, qsmp_error_none, true);
			break;
		}
		else
		{
			if (mlen > 0U)
			{
				/* convert the packet to bytes */
				pkt.pmessage = pmsg;
				qsmp_packet_encrypt(cns, &pkt, (const uint8_t*)sin, mlen);
				qsc_memutils_clear((uint8_t*)sin, sizeof(sin));
				mlen = qsmp_packet_to_stream(&pkt, msgstr);
				qsc_socket_send(&cns->target, msgstr, mlen, qsc_socket_send_flag_none);
			}
		}

		mlen = qsc_consoleutils_get_line(sin, sizeof(sin)) - 1U;

		if (mlen > 0U && (sin[0] == '\n' || sin[0U] == '\r'))
		{
			client_print_message("");
			mlen = 0U;
		}
	}
}

int main(void)
{
	qsmp_client_verification_key ckey = { 0 };
	qsc_ipinfo_ipv4_address addv4t = { 0 };
	size_t ectr;
	qsmp_errors qerr;
	bool res;

	res = false;
	ectr = 0U;
	client_print_banner();

	while (ectr < 3U)
	{
		res = client_ipv4_dialogue(&addv4t, &ckey);

		if (res == true)
		{
			break;
		}
		else
		{
			qsc_consoleutils_print_line("");
		}

		++ectr;
	}

	if (res == true)
	{
		qerr = qsmp_client_simplex_connect_ipv4(&ckey, &addv4t, QSMP_SERVER_PORT, &client_send_loop, &client_receive_callback);

		if (qerr != qsmp_error_none)
		{
			const char* serr = qsmp_error_to_string(qerr);
			qsc_consoleutils_print_line(serr);
		}
	}
	else
	{
		qsc_consoleutils_print_line("Invalid input, exiting the application.");
	}

	qsc_consoleutils_print_line("The application has exited. Press any key to close..");
	qsc_consoleutils_get_wait();

	return 0;
}

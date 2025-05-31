
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

#include "appsrv.h"
#include "server.h"
#include "acp.h"
#include "async.h"
#include "consoleutils.h"
#include "fileutils.h"
#include "folderutils.h"
#include "ipinfo.h"
#include "netutils.h"
#include "socketbase.h"
#include "socketserver.h"
#include "stringutils.h"

static void server_print_prompt(void)
{
	qsc_consoleutils_print_safe("server> ");
}

static void server_print_message(const char* message)
{
	size_t slen;

	if (message != NULL)
	{
		slen = qsc_stringutils_string_size(message);

		if (slen != 0U)
		{
			server_print_prompt();
			qsc_consoleutils_print_line(message);
		}
		else
		{
			qsc_consoleutils_print_line("");
			server_print_prompt();
		}
	}
}

static void server_print_error(qsmp_errors error)
{
	const char* msg;

	msg = qsmp_error_to_string(error);

	if (msg != NULL)
	{
		server_print_message(msg);
	}
}

static void server_print_banner(void)
{
	qsc_consoleutils_print_line("QSMP: Server Example Project");
	qsc_consoleutils_print_line("Quantum Secure Messaging Protocol simplex-mode server.");
	qsc_consoleutils_print_line("Release:   v1.3.0.0b (A3)");
	qsc_consoleutils_print_line("Date:      May 30, 2025");
	qsc_consoleutils_print_line("Contact:   contact@qrcscorp.ca");
	qsc_consoleutils_print_line("");
}

static bool server_get_storage_path(char* path, size_t pathlen)
{
	bool res;

	qsc_folderutils_get_directory(qsc_folderutils_directories_user_documents, path);
	qsc_folderutils_append_delimiter(path);
	qsc_stringutils_concat_strings(path, pathlen, QSMP_APP_PATH);
	res = qsc_folderutils_directory_exists(path);

	if (res == false)
	{
		res = qsc_folderutils_create_directory(path);
	}

	return res;
}

static bool server_prikey_exists(void)
{
	char fpath[QSC_SYSTEM_MAX_PATH] = { 0 };
	bool res;

	res = server_get_storage_path(fpath, sizeof(fpath));

	if (res == true)
	{
		qsc_folderutils_append_delimiter(fpath);
		qsc_stringutils_concat_strings(fpath, sizeof(fpath), QSMP_PRIKEY_NAME);
		res = qsc_fileutils_exists(fpath);
	}

	return res;
}

#if defined(QSMP_FUTURE_EXTENSION)
static bool server_pubkey_exists(char fpath[QSC_SYSTEM_MAX_PATH], size_t pathlen)
{
	bool res;

	qsc_folderutils_get_directory(qsc_folderutils_directories_user_documents, fpath);
	qsc_folderutils_append_delimiter(fpath);
	qsc_stringutils_concat_strings(fpath, pathlen, QSMP_APP_PATH);
	res = qsc_folderutils_directory_exists(fpath);

	if (res == true)
	{
		qsc_folderutils_append_delimiter(fpath);
		qsc_stringutils_concat_strings(fpath, pathlen, QSMP_PUBKEY_NAME);

		res = qsc_fileutils_exists(fpath);
	}

	return res;
}

static void server_certificate_print(const qsmp_client_verification_key* pubk)
{
	assert(pubk != NULL);

	char* penk;
	size_t elen;
	size_t slen;

	elen = qsmp_public_key_encoding_size();
	penk = qsc_memutils_malloc(elen);

	if (penk != NULL)
	{
		slen = qsmp_public_key_encode(penk, elen, pubk);

		if (slen == elen)
		{
			qsc_consoleutils_print_safe(penk);
			qsc_consoleutils_print_line("");
		}

		qsc_memutils_alloc_free(penk);
	}
}
#endif

static bool server_key_dialogue(qsmp_server_signature_key* prik, qsmp_client_verification_key* pubk, uint8_t keyid[QSMP_KEYID_SIZE])
{
	uint8_t spri[QSMP_SIGKEY_ENCODED_SIZE] = { 0U };
	char dir[QSC_SYSTEM_MAX_PATH] = { 0 };
	char fpath[QSC_SYSTEM_MAX_PATH] = { 0 };
	bool res;

	if (server_prikey_exists() == true)
	{
		res = server_get_storage_path(dir, sizeof(dir));

		if (res == true)
		{
			qsc_stringutils_copy_string(fpath, sizeof(fpath), dir);
			qsc_folderutils_append_delimiter(fpath);
			qsc_stringutils_concat_strings(fpath, sizeof(fpath), QSMP_PRIKEY_NAME);
			res = qsc_fileutils_copy_file_to_stream(fpath, (char*)spri, sizeof(spri));

			if (res == true)
			{
				qsmp_signature_key_deserialize(prik, spri);
				qsc_memutils_copy(keyid, prik->keyid, QSMP_KEYID_SIZE);
				qsc_memutils_copy(pubk->config, prik->config, QSMP_CONFIG_SIZE);
				qsc_memutils_copy(pubk->keyid, prik->keyid, QSMP_KEYID_SIZE);
				qsc_memutils_copy(pubk->verkey, prik->verkey, QSMP_ASYMMETRIC_VERIFY_KEY_SIZE);
				pubk->expiration = prik->expiration;
				qsc_consoleutils_print_line("server> The private-key has been loaded.");
			}
			else
			{
				qsc_consoleutils_print_line("server> Could not load the key-pair, aborting startup.");
			}
		}
		else
		{
			qsc_consoleutils_print_line("server> Could not load the key-pair, aborting startup.");
		}
	}
	else
	{
		res = server_get_storage_path(dir, sizeof(dir));

		if (res == true)
		{
			qsc_stringutils_copy_string(fpath, sizeof(fpath), dir);
			qsc_folderutils_append_delimiter(fpath);
			qsc_stringutils_concat_strings(fpath, sizeof(fpath), QSMP_PUBKEY_NAME);

			qsc_consoleutils_print_line("server> The private-key was not detected, generating a new private/public keypair...");
			res = qsc_acp_generate(keyid, QSMP_KEYID_SIZE);

			if (res == true)
			{
				char* spub;
				size_t elen;

				qsmp_generate_keypair(pubk, prik, keyid);

				elen = qsmp_public_key_encoding_size();
				spub = qsc_memutils_malloc(elen);

				if (spub != NULL)
				{
					qsc_memutils_clear(spub, elen);
					qsmp_public_key_encode(spub, elen, pubk);
					res = qsc_fileutils_copy_stream_to_file(fpath, spub, elen);
					qsc_memutils_alloc_free(spub);
				}
				else
				{
					res = false;
				}

				if (res == true)
				{
					qsc_consoleutils_print_safe("server> The publickey has been saved to ");
					qsc_consoleutils_print_line(fpath);
					qsc_consoleutils_print_line("server> Distribute the public-key to intended clients.");
					qsc_consoleutils_print_line("server> ");

					qsc_stringutils_clear_string(fpath);
					qsc_stringutils_copy_string(fpath, sizeof(fpath), dir);
					qsc_folderutils_append_delimiter(fpath);
					qsc_stringutils_concat_strings(fpath, sizeof(fpath), QSMP_PRIKEY_NAME);
					qsmp_signature_key_serialize(spri, prik);
					qsc_fileutils_copy_stream_to_file(fpath, (char*)spri, sizeof(spri));
				}
				else
				{
					qsc_consoleutils_print_line("server> Could not load the key-pair, aborting startup.");
				}
			}
			else
			{
				qsc_consoleutils_print_line("server> Could not create the key-pair, aborting startup.");
			}
		}
	}

	return res;
}

static void server_send_echo(qsmp_connection_state* cns, const char* message, size_t msglen)
{
	/* This function can be modified to send data to a remote host.*/

	char mstr[QSMP_CONNECTION_MTU] = "ECHO: ";
	char rstr[QSMP_CONNECTION_MTU] = "RCVD #";
	uint8_t pmsg[QSMP_CONNECTION_MTU] = { 0U };
	qsmp_network_packet pkt = { 0 };
	qsc_mutex mtx;
	size_t mlen;

	if (msglen > 0)
	{
		mlen = qsc_stringutils_string_size(rstr);
		qsc_stringutils_int_to_string((int)cns->target.connection, rstr + mlen, sizeof(rstr) - mlen);
		qsc_stringutils_concat_strings(rstr, sizeof(rstr), ": ");
		qsc_stringutils_concat_strings(rstr, sizeof(rstr), message);

		mtx = qsc_async_mutex_lock_ex();
		server_print_message(rstr);
		qsc_async_mutex_unlock_ex(mtx);

		mlen = qsc_stringutils_concat_strings(mstr, sizeof(mstr), message);
		pkt.pmessage = pmsg;
		qsmp_packet_encrypt(cns, &pkt, (uint8_t*)mstr, mlen);
		mlen = qsmp_packet_to_stream(&pkt, (uint8_t*)mstr);
		qsc_socket_send(&cns->target, (const uint8_t*)mstr, mlen, qsc_socket_send_flag_none);
	}
}

static void server_disconnect_callback(qsmp_connection_state* cns)
{
	qsc_mutex mtx;

	mtx = qsc_async_mutex_lock_ex();
	server_print_prompt();
	qsc_consoleutils_print_safe("The server has disconnected from host: ");
	qsc_consoleutils_print_line((const char*)cns->target.address);
	qsc_async_mutex_unlock_ex(mtx);
}

static void server_receive_callback(qsmp_connection_state* cns, const uint8_t* message, size_t msglen)
{
	/* Envelope data in an application header, in a request->response model.
	   Parse that header here, process requests from the client, and transmit the response. */

	server_send_echo(cns, (const char*)message, msglen);
}

int main(void)
{
	qsmp_server_signature_key prik = { 0 };
	qsmp_client_verification_key verk = { 0 };
	qsc_socket source = { 0 };
	uint8_t kid[QSMP_KEYID_SIZE] = { 0U };
	qsmp_errors qerr;

#if defined(QSMP_DEBUG_MODE)
	qsmp_certificate_encoding_test();
#endif

	server_print_banner();

	if (server_key_dialogue(&prik, &verk, kid) == true)
	{
		server_print_message("Waiting for a connection...");
		qerr = qsmp_server_start_ipv4(&source, &prik, &server_receive_callback, &server_disconnect_callback);

		if (qerr != qsmp_error_none)
		{
			server_print_error(qerr);
			server_print_message("The network key-exchange failed, the application will exit.");
		}

		qsmp_server_quit();
	}
	else
	{
		server_print_message("The signature key-pair could not be created, the application will exit.");
	}

	server_print_message("Press any key to close...");
	qsc_consoleutils_get_wait();

	return 0;
}

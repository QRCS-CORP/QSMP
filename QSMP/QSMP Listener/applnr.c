
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

#include "applnr.h"
#include "../QSMP/qsmpclient.h"
#include "../../QSC/QSC/acp.h"
#include "../../QSC/QSC/async.h"
#include "../../QSC/QSC/consoleutils.h"
#include "../../QSC/QSC/fileutils.h"
#include "../../QSC/QSC/folderutils.h"
#include "../../QSC/QSC/ipinfo.h"
#include "../../QSC/QSC/netutils.h"
#include "../../QSC/QSC/stringutils.h"

static void listener_print_prompt(void)
{
	qsc_consoleutils_print_safe("listener> ");
}

static void listener_print_error(qsmp_errors error)
{
	const char* msg;

	msg = qsmp_error_to_string(error);

	if (msg != NULL)
	{
		listener_print_prompt();
		qsc_consoleutils_print_line(msg);
	}
}

static void listener_print_message(const char* message)
{
	size_t slen;

	if (message != NULL)
	{
		slen = qsc_stringutils_string_size(message);

		if (slen != 0)
		{
			listener_print_prompt();
			qsc_consoleutils_print_line(message);
		}
		else
		{
			qsc_consoleutils_print_line("");
			listener_print_prompt();
		}
	}
}

static void listener_print_string(const char* message, size_t msglen)
{
	if (message != NULL && msglen != 0)
	{
		qsc_consoleutils_print_line(message);
	}
}

static void listener_print_banner(void)
{
	qsc_consoleutils_print_line("***************************************************");
	qsc_consoleutils_print_line("* QSMP: Listener Example Project                  *");
	qsc_consoleutils_print_line("*                                                 *");
	qsc_consoleutils_print_line("* Release:   v1.3.0.0a (A3)                       *");
	qsc_consoleutils_print_line("* Date:      March 29, 2024                       *");
	qsc_consoleutils_print_line("* Contact:   develop@qscs.ca                      *");
	qsc_consoleutils_print_line("***************************************************");
	qsc_consoleutils_print_line("");
}

static bool listener_get_storage_path(char* path, size_t pathlen)
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

static bool listener_prikey_exists(char fpath[QSC_SYSTEM_MAX_PATH], size_t pathlen)
{
	bool res;

	res = listener_get_storage_path(fpath, pathlen);

	if (res == true)
	{
		qsc_folderutils_append_delimiter(fpath);
		qsc_stringutils_concat_strings(fpath, pathlen, QSMP_PRIKEY_NAME);

		res = qsc_fileutils_exists(fpath);
	}

	return res;
}

static bool listener_senderkey_exists(char fpath[QSC_SYSTEM_MAX_PATH], size_t pathlen)
{
	bool res;

	qsc_folderutils_get_directory(qsc_folderutils_directories_user_documents, fpath);
	qsc_folderutils_append_delimiter(fpath);
	qsc_stringutils_concat_strings(fpath, pathlen, QSMP_APP_PATH);
	res = qsc_folderutils_directory_exists(fpath);

	if (res == true)
	{
		qsc_folderutils_append_delimiter(fpath);
		qsc_stringutils_concat_strings(fpath, pathlen, QSMP_SENDER_PUBKEY_NAME);

		res = qsc_fileutils_exists(fpath);
	}

	return res;
}

static bool listener_key_query(uint8_t* rvkey, const uint8_t* pkid)
{
	qsmp_client_signature_key ckey = { 0 };
	uint8_t pskey[QSMP_PUBKEY_STRING_SIZE] = { 0 };
	char fpath[QSC_SYSTEM_MAX_PATH] = { 0 };
	bool res;

	res = false;

	/* Note: This is where you would check a set of public key files,
	   using a list of key-ids and corresponding filenames,
	   comparing them to the pkid to match the correct key,
	   and returning the correct key ot NULL. */

	if (listener_senderkey_exists(fpath, sizeof(fpath)))
	{
		qsc_fileutils_copy_file_to_stream(fpath, (char*)pskey, sizeof(pskey));
		res = qsmp_decode_public_key(&ckey, (char*)pskey);

		if (res == true)
		{
			qsc_memutils_copy(rvkey, ckey.verkey, sizeof(ckey.verkey));
		}
	}
	
	return res;
}

static bool listener_key_dialogue(qsmp_server_signature_key* prik, qsmp_client_signature_key* pubk, uint8_t keyid[QSMP_KEYID_SIZE])
{
	uint8_t spub[QSMP_PUBKEY_STRING_SIZE] = { 0 };
	uint8_t spri[QSMP_SIGKEY_ENCODED_SIZE] = { 0 };
	char dir[QSC_SYSTEM_MAX_PATH] = { 0 };
	char fpath[QSC_SYSTEM_MAX_PATH] = { 0 };
	bool res;

	res = listener_prikey_exists(fpath, sizeof(fpath));

	if (res == true)
	{
		res = qsc_fileutils_copy_file_to_stream(fpath, (char*)spri, sizeof(spri));

		if (res == true)
		{
			qsmp_deserialize_signature_key(prik, spri);
			qsc_memutils_copy(keyid, prik->keyid, QSMP_KEYID_SIZE);
			qsc_memutils_copy(pubk->config, prik->config, QSMP_CONFIG_SIZE);
			qsc_memutils_copy(pubk->keyid, prik->keyid, QSMP_KEYID_SIZE);
			qsc_memutils_copy(pubk->verkey, prik->verkey, QSMP_ASYMMETRIC_VERIFY_KEY_SIZE);
			pubk->expiration = prik->expiration;
			qsc_consoleutils_print_line("listener> The private-key has been loaded.");
		}
		else
		{
			qsc_consoleutils_print_line("listener> Could not load the key-pair, aborting startup.");
		}
	}
	else
	{
		res = listener_get_storage_path(dir, sizeof(dir));

		if (res == true)
		{
			qsc_stringutils_copy_string(fpath, sizeof(fpath), dir);
			qsc_folderutils_append_delimiter(fpath);
			qsc_stringutils_concat_strings(fpath, sizeof(fpath), QSMP_PUBKEY_NAME);

			qsc_consoleutils_print_line("listener> The private-key was not detected, generating a new private/public keypair...");
			res = qsc_acp_generate(keyid, QSMP_KEYID_SIZE);

			if (res == true)
			{
				qsmp_generate_keypair(pubk, prik, keyid);
				/* uses the public verkey and key attributes contained in the server key */
				qsmp_encode_public_key((char*)spub, prik);
				res = qsc_fileutils_copy_stream_to_file(fpath, (char*)spub, sizeof(spub));

				if (res == true)
				{
					qsc_consoleutils_print_safe("listener> The publickey has been saved to ");
					qsc_consoleutils_print_line(fpath);
					qsc_consoleutils_print_line("listener> Distribute the public-key to intended clients.");
					qsc_consoleutils_print_line("listener> ");

					qsc_stringutils_clear_string(fpath);
					qsc_stringutils_copy_string(fpath, sizeof(fpath), dir);
					qsc_folderutils_append_delimiter(fpath);
					qsc_stringutils_concat_strings(fpath, sizeof(fpath), QSMP_PRIKEY_NAME);
					qsmp_serialize_signature_key(spri, prik);
					qsc_fileutils_copy_stream_to_file(fpath, (char*)spri, sizeof(spri));
				}
				else
				{
					qsc_consoleutils_print_line("listener> Could not load the key-pair, aborting startup.");
				}
			}
			else
			{
				qsc_consoleutils_print_line("listener> Could not create the key-pair, aborting startup.");
			}
		}
	}

	return res;
}

static void listener_receive_callback(qsmp_connection_state* cns, const char* pmsg, size_t msglen)
{
	qsc_consoleutils_print_safe("RECD: ");
	listener_print_string(pmsg, msglen);
	listener_print_prompt();
}

static void listener_send_loop(qsmp_connection_state* cns)
{
	qsmp_network_packet pkt = { 0 };
	uint8_t msgstr[QSMP_CONNECTION_MTU] = { 0 };
	/* Note: the buffer can be sized to the expected message maximum */
	uint8_t pmsg[QSMP_CONNECTION_MTU] = { 0 };
	char sin[QSMP_CONNECTION_MTU + 1] = { 0 };
	size_t mlen;
	size_t slen;

	mlen = 0;
	pkt.pmessage = pmsg;

	/* start the sender loop */
	while (true)
	{
		listener_print_prompt();

		if (qsc_consoleutils_line_contains(sin, "qsmp quit"))
		{
			break;
		}
		else if (qsc_consoleutils_line_contains(sin, "qsmp asymmetric ratchet"))
		{
			qsmp_duplex_send_asymmetric_ratchet_request(cns);
			qsc_memutils_clear((uint8_t*)sin, sizeof(sin));
		}
		else if (qsc_consoleutils_line_contains(sin, "qsmp symmetric ratchet"))
		{
			qsmp_duplex_send_symmetric_ratchet_request(cns);
			qsc_memutils_clear((uint8_t*)sin, sizeof(sin));
		}
		else
		{
			if (mlen > 0)
			{
				/* convert the packet to bytes */
				qsmp_encrypt_packet(cns, &pkt, (const uint8_t*)sin, mlen);
				qsc_memutils_clear((uint8_t*)sin, sizeof(sin));
				mlen = qsmp_packet_to_stream(&pkt, msgstr);
				slen = qsc_socket_send(&cns->target, msgstr, mlen, qsc_socket_send_flag_none);
			}
		}

		mlen = qsc_consoleutils_get_line(sin, sizeof(sin)) - 1;

		if (mlen > 0 && (sin[0] == '\n' || sin[0] == '\r'))
		{
			listener_print_message("");
			mlen = 0;
		}
	}

	qsmp_connection_close(cns, qsmp_error_none, true);
}

int main(void)
{
	qsmp_server_signature_key prik = { 0 };
	qsmp_client_signature_key pubk = { 0 };
	uint8_t kid[QSMP_KEYID_SIZE] = { 0 };
	qsmp_errors qerr;

	listener_print_banner();

	if (listener_key_dialogue(&prik, &pubk, kid) == true)
	{
		listener_print_message("Waiting for a connection...");
		qerr = qsmp_client_duplex_listen_ipv4((const qsmp_server_signature_key*)&prik, &listener_send_loop, &listener_receive_callback, &listener_key_query);

		if (qerr != qsmp_error_none)
		{
			qsc_consoleutils_print_line("");
			listener_print_error(qerr);
			listener_print_message("The network key-exchange failed, the application will exit.");
		}
	}
	else
	{
		listener_print_message("The signature key-pair could not be created, the application will exit.");
	}

	qsc_consoleutils_print_line("");
	listener_print_message("Press any key to close...");
	qsc_consoleutils_get_wait();

	return 0;
}

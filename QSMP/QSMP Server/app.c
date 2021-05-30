#include "app.h"
#include "qsmpserver.h"
#include "../QSC/acp.h"
#include "../QSC/consoleutils.h"
#include "../QSC/fileutils.h"
#include "../QSC/folderutils.h"
#include "../QSC/ipinfo.h"
#include "../QSC/netutils.h"
#include "../QSC/stringutils.h"
#include "../QSC/async.h"

static qsc_qsmp_keep_alive_state m_qsmp_keep_alive;
static qsc_qsmp_kex_server_state m_qsmp_server_ctx;

static void qsmp_server_print_error(qsc_qsmp_errors error)
{
	const char* msg;

	msg = qsc_qsmp_error_to_string(qsc_qsmp_error_bad_keep_alive);

	if (msg != NULL)
	{
		qsc_consoleutils_print_safe("server> ");
		qsc_consoleutils_print_line(msg);
	}
}

static void qsmp_server_print_message(const char* message)
{
	size_t slen;

	if (message != NULL)
	{
		slen = qsc_stringutils_string_size(message);

		if (slen != 0)
		{
			qsc_consoleutils_print_safe("server> ");
			qsc_consoleutils_print_line(message);
		}
		else
		{
			qsc_consoleutils_print_safe("server> ");
		}
	}
}

void qsc_socket_exception_callback(qsc_socket* source, qsc_socket_exceptions error)
{
	assert(source != NULL);

	if (source != NULL)
	{
		qsmp_server_print_error(error);
	}
}

void qsc_socket_receive_async_callback(qsc_socket* source, uint8_t* message, size_t msglen)
{
	assert(message != NULL);
	assert(source != NULL);

	qsc_qsmp_packet pkt = { 0 };
	char msgstr[QSMP_MESSAGE_MAX] = { 0 };

	if (message != NULL && source != NULL && msglen > 0)
	{
		/* convert the bytes to packet */
		qsc_qsmp_stream_to_packet(message, &pkt);

		if (pkt.flag == qsc_qsmp_message_encrypted_message)
		{
			qsc_qsmp_server_decrypt_packet(&m_qsmp_server_ctx, &pkt, (uint8_t*)msgstr, &msglen);
			qsc_consoleutils_print_line(msgstr);
			qsc_consoleutils_print_safe("server> ");
		}
		else if (pkt.flag == qsc_qsmp_message_connection_terminate)
		{
			qsmp_server_print_message("The connection was terminated by the remote host.");
			qsc_qsmp_server_connection_close(&m_qsmp_server_ctx, source, qsc_qsmp_error_none);
		}
		else if (pkt.flag == qsc_qsmp_message_keep_alive_request)
		{
			/* test the keepalive */

			if (pkt.sequence == m_qsmp_keep_alive.seqctr)
			{
				uint64_t tme;

				tme = qsc_intutils_le8to64(pkt.message);

				if (m_qsmp_keep_alive.etime == tme)
				{
					m_qsmp_keep_alive.seqctr += 1;
					m_qsmp_keep_alive.recd = true;
				}
				else
				{
					qsmp_server_print_error(qsc_qsmp_error_bad_keep_alive);
					qsc_qsmp_server_connection_close(&m_qsmp_server_ctx, source, qsc_qsmp_error_bad_keep_alive);
				}
			}
			else
			{
				qsmp_server_print_error(qsc_qsmp_error_bad_keep_alive);
				qsc_qsmp_server_connection_close(&m_qsmp_server_ctx, source, qsc_qsmp_error_bad_keep_alive);
			}
		}
		else
		{
			qsmp_server_print_message("The connection experienced a fatal error.");
			qsc_qsmp_server_connection_close(&m_qsmp_server_ctx, source, qsc_qsmp_error_connection_failure);
		}
	}
}

static void qsmp_server_print_banner()
{
	qsc_consoleutils_print_line("***************************************************");
	qsc_consoleutils_print_line("* QSMP: Quantum Secure Messaging Protocol Server  *");
	qsc_consoleutils_print_line("*                                                 *");
	qsc_consoleutils_print_line("* Release:   v1.0.0.0a (A0)                       *");
	qsc_consoleutils_print_line("* License:   AGPLv3                               *");
	qsc_consoleutils_print_line("* Date:      May 28, 2021                         *");
	qsc_consoleutils_print_line("* Contact:   develop@vtdev.com                    *");
	qsc_consoleutils_print_line("***************************************************");
	qsc_consoleutils_print_line("");
}

static bool qsmp_server_get_storage_path(char* path, size_t pathlen)
{
	bool res;

	qsc_folderutils_get_directory(qsc_folderutils_directories_user_documents, path);
	qsc_stringutils_concat_strings(path, pathlen, QSMP_APP_PATH);
	res = qsc_folderutils_directory_exists(path);

	if (res == false)
	{
		res = qsc_folderutils_create_directory(path);
	}

	return res;
}

static bool qsmp_server_prikey_exists()
{
	char fpath[QSC_SYSTEM_MAX_PATH] = { 0 };
	bool res;

	res = qsmp_server_get_storage_path(fpath, sizeof(fpath));

	if (res == true)
	{
		qsc_stringutils_concat_strings(fpath, sizeof(fpath), "\\");
		qsc_stringutils_concat_strings(fpath, sizeof(fpath), QSMP_PRIKEY_NAME);

		res = qsc_filetools_file_exists(fpath);
	}

	return res;
}

static bool qsmp_server_key_dialogue(qsc_qsmp_server_key* prik, qsc_qsmp_client_key* pubk, uint8_t keyid[QSC_QSMP_KEYID_SIZE])
{
	uint8_t spub[QSC_QSMP_PUBKEY_STRING_SIZE] = { 0 };
	uint8_t spri[QSC_QSMP_SIGKEY_ENCODED_SIZE] = { 0 };
	char dir[QSC_SYSTEM_MAX_PATH] = { 0 };
	char fpath[QSC_SYSTEM_MAX_PATH] = { 0 };
	bool res;

	if (qsmp_server_prikey_exists() == true)
	{
		res = qsmp_server_get_storage_path(dir, sizeof(dir));

		if (res == true)
		{
			qsc_stringutils_copy_string(fpath, sizeof(fpath), dir);
			qsc_stringutils_concat_strings(fpath, sizeof(fpath), "\\");
			qsc_stringutils_concat_strings(fpath, sizeof(fpath), QSMP_PRIKEY_NAME);
			res = qsc_filetools_copy_file_to_stream(fpath, spri, sizeof(spri));

			if (res == true)
			{
				qsc_qsmp_server_deserialize_signature_key(prik, spri);
				qsc_memutils_copy(keyid, prik->keyid, sizeof(keyid));
				qsc_memutils_copy(pubk->config, prik->config, sizeof(prik->config));
				qsc_memutils_copy(pubk->keyid, prik->keyid, sizeof(prik->keyid));
				qsc_memutils_copy(pubk->verkey, prik->verkey, sizeof(prik->verkey));
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
		res = qsmp_server_get_storage_path(dir, sizeof(dir));

		if (res == true)
		{
			qsc_stringutils_copy_string(fpath, sizeof(fpath), dir);
			qsc_stringutils_concat_strings(fpath, sizeof(fpath), "\\");
			qsc_stringutils_concat_strings(fpath, sizeof(fpath), QSMP_PUBKEY_NAME);

			qsc_consoleutils_print_line("server> The private-key was not detected, generating a new private/public keypair...");
			res = qsc_acp_generate(keyid, QSC_QSMP_KEYID_SIZE);

			if (res == true)
			{
				qsc_qsmp_server_generate_keypair(pubk, prik, keyid);
				qsc_qsmp_server_encode_public_key(spub, prik);
				res = qsc_filetools_copy_stream_to_file(fpath, spub, sizeof(spub));

				if (res == true)
				{
					qsc_consoleutils_print_safe("server> The publickey has been saved to ");
					qsc_consoleutils_print_line(fpath);
					qsc_consoleutils_print_line("server> Distribute the public-key to intended clients.");
					qsc_consoleutils_print_line("server> ");

					qsc_stringutils_clear_string(fpath);
					qsc_stringutils_copy_string(fpath, sizeof(fpath), dir);
					qsc_stringutils_concat_strings(fpath, sizeof(fpath), "\\");
					qsc_stringutils_concat_strings(fpath, sizeof(fpath), QSMP_PRIKEY_NAME);
					qsc_qsmp_server_serialize_signature_key(spri, prik);
					qsc_filetools_copy_stream_to_file(fpath, spri, sizeof(spri));
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

static qsc_qsmp_errors qsmp_server_keep_alive_loop(qsc_socket* sock)
{
	qsc_async_mutex mtx;
	qsc_qsmp_errors qerr;

	qsc_async_mutex_lock_ex(&mtx);

	do
	{
		m_qsmp_keep_alive.recd = false;

		qerr = qsc_qsmp_server_send_keep_alive(&m_qsmp_keep_alive, sock);
		qsc_async_thread_sleep(QSC_QSMP_KEEPALIVE_TIMEOUT);

		if (m_qsmp_keep_alive.recd == false)
		{
			qerr = qsc_qsmp_error_keep_alive_expired;
		}
	} 
	while (qerr == qsc_qsmp_error_none);

	qsc_async_mutex_unlock_ex(&mtx);

	return qerr;
}

static qsc_qsmp_errors qsmp_server_listen_ipv4(qsc_qsmp_server_key* prik)
{
	qsc_socket_receive_async_state actx = { 0 };
	qsc_socket ssck = { 0 };
	qsc_qsmp_packet pkt = { 0 };
	qsc_ipinfo_ipv4_address addt = { 0 };
	
	uint8_t msgstr[QSMP_MESSAGE_MAX] = { 0 };
	uint8_t spub[QSC_QSMP_PUBKEY_STRING_SIZE] = { 0 };
	uint8_t spri[QSC_QSMP_SIGKEY_ENCODED_SIZE] = { 0 };
	char sin[QSMP_MESSAGE_MAX + 1] = { 0 };
	qsc_qsmp_errors qerr;
	size_t mlen;

	qsc_memutils_clear((uint8_t*)&m_qsmp_server_ctx, sizeof(m_qsmp_server_ctx));
	addt = qsc_ipinfo_ipv4_address_any();

	/* begin listening on the port, when a client connects it triggers the key exchange*/
	qerr = qsc_qsmp_server_listen_ipv4(&m_qsmp_server_ctx, &ssck, prik, &addt, QSC_QSMP_SERVER_PORT);

	if (qerr == qsc_qsmp_error_none)
	{
		qsc_consoleutils_print_safe("server> Connected to remote host: ");
		qsc_consoleutils_print_line((char*)ssck.address);

		/* start the keep-alive mechanism */
		qsc_async_thread_initialize(qsmp_server_keep_alive_loop, &ssck);

		/* send and receive loops */
		memset((char*)&actx, 0x00, sizeof(qsc_socket_receive_async_state));
		actx.callback = qsc_socket_receive_async_callback;
		actx.error = qsc_socket_exception_callback;
		actx.source = &ssck;
		qsc_socket_receive_async(&actx);

		mlen = 0;
		qsmp_server_print_message("");

		while (qsc_consoleutils_line_contains(sin, "qsmp quit") == false)
		{
			if (mlen > 0)
			{
				/* convert the packet to bytes */
				qsc_qsmp_server_encrypt_packet(&m_qsmp_server_ctx, (uint8_t*)sin, mlen, &pkt);
				mlen = qsc_qsmp_packet_to_stream(&pkt, msgstr);
				qsc_socket_send(&ssck, msgstr, mlen, qsc_socket_send_flag_none);
				memset(sin, 0x00, mlen);
				mlen = 0;
			}

			mlen = qsc_consoleutils_get_formatted_line(sin, sizeof(sin));
			qsmp_server_print_message("");
		}

		qsc_qsmp_server_connection_close(&m_qsmp_server_ctx, &ssck, qsc_qsmp_error_none);
	}
	else
	{
		qsmp_server_print_message("Could not connect to the remote host.");
	}

	return qerr;
}

int main(void)
{
	qsc_qsmp_server_key skey = { 0 };
	qsc_qsmp_client_key ckey = { 0 };
	uint8_t kid[QSC_QSMP_KEYID_SIZE] = { 0 };
	qsc_qsmp_errors qerr;

	qsmp_server_print_banner();

	if (qsmp_server_key_dialogue(&skey, &ckey, kid) == true)
	{
		qsmp_server_print_message("Waiting for a connection...");
		qerr = qsmp_server_listen_ipv4(&skey);

		if (qerr != qsc_qsmp_error_none)
		{
			qsmp_server_print_error(qerr);
			qsmp_server_print_message("The network key-exchange failed, the application will exit.");
		}
	}
	else
	{
		qsmp_server_print_message("The signature key-pair could not be created, the application will exit.");
	}

	qsmp_server_print_message("Press any key to close...");
	qsc_consoleutils_get_wait();

	return 0;
}

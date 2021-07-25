#include "appsrv.h"
#include "qsmpserver.h"
#include "../QSC/acp.h"
#include "../QSC/consoleutils.h"
#include "../QSC/fileutils.h"
#include "../QSC/folderutils.h"
#include "../QSC/ipinfo.h"
#include "../QSC/netutils.h"
#include "../QSC/stringutils.h"
#include "../QSC/async.h"

static qsmp_keep_alive_state m_qsmp_keep_alive;
static qsmp_kex_server_state m_qsmp_server_ctx;

static void server_print_prompt()
{
	qsc_consoleutils_print_safe("server> ");
}

static void server_print_error(qsmp_errors error)
{
	const char* msg;

	msg = qsmp_error_to_string(error);

	if (msg != NULL)
	{
		server_print_prompt();
		qsc_consoleutils_print_line(msg);
	}
}

static void server_print_message(const char* message)
{
	size_t slen;

	if (message != NULL)
	{
		slen = qsc_stringutils_string_size(message);

		if (slen != 0)
		{
			server_print_prompt();
			qsc_consoleutils_print_line(message);
		}
		else
		{
			server_print_prompt();
		}
	}
}

static void server_print_banner()
{
	qsc_consoleutils_print_line("***************************************************");
	qsc_consoleutils_print_line("* QSMP: Quantum Secure Messaging Protocol Server  *");
	qsc_consoleutils_print_line("*                                                 *");
	qsc_consoleutils_print_line("* Release:   v1.0.0.0e (A0)                       *");
	qsc_consoleutils_print_line("* Date:      June 10, 2021                        *");
	qsc_consoleutils_print_line("* Contact:   develop@vtdev.com                    *");
	qsc_consoleutils_print_line("***************************************************");
	qsc_consoleutils_print_line("");
}

static bool server_get_storage_path(char* path, size_t pathlen)
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

static bool server_prikey_exists()
{
	char fpath[QSC_SYSTEM_MAX_PATH] = { 0 };
	bool res;

	res = server_get_storage_path(fpath, sizeof(fpath));

	if (res == true)
	{
		qsc_stringutils_concat_strings(fpath, sizeof(fpath), "\\");
		qsc_stringutils_concat_strings(fpath, sizeof(fpath), QSMP_PRIKEY_NAME);

		res = qsc_filetools_file_exists(fpath);
	}

	return res;
}

static bool server_key_dialogue(qsmp_server_key* prik, qsmp_client_key* pubk, uint8_t keyid[QSMP_KEYID_SIZE])
{
	uint8_t spub[QSMP_PUBKEY_STRING_SIZE] = { 0 };
	uint8_t spri[QSMP_SIGKEY_ENCODED_SIZE] = { 0 };
	char dir[QSC_SYSTEM_MAX_PATH] = { 0 };
	char fpath[QSC_SYSTEM_MAX_PATH] = { 0 };
	bool res;

	if (server_prikey_exists() == true)
	{
		res = server_get_storage_path(dir, sizeof(dir));

		if (res == true)
		{
			qsc_stringutils_copy_string(fpath, sizeof(fpath), dir);
			qsc_stringutils_concat_strings(fpath, sizeof(fpath), "\\");
			qsc_stringutils_concat_strings(fpath, sizeof(fpath), QSMP_PRIKEY_NAME);
			res = qsc_filetools_copy_file_to_stream(fpath, spri, sizeof(spri));

			if (res == true)
			{
				qsmp_server_deserialize_signature_key(prik, spri);
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
		res = server_get_storage_path(dir, sizeof(dir));

		if (res == true)
		{
			qsc_stringutils_copy_string(fpath, sizeof(fpath), dir);
			qsc_stringutils_concat_strings(fpath, sizeof(fpath), "\\");
			qsc_stringutils_concat_strings(fpath, sizeof(fpath), QSMP_PUBKEY_NAME);

			qsc_consoleutils_print_line("server> The private-key was not detected, generating a new private/public keypair...");
			res = qsc_acp_generate(keyid, QSMP_KEYID_SIZE);

			if (res == true)
			{
				qsmp_server_generate_keypair(pubk, prik, keyid);
				qsmp_server_encode_public_key(spub, prik);
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
					qsmp_server_serialize_signature_key(spri, prik);
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

static qsmp_errors server_keep_alive_loop(const qsc_socket* sock)
{
	qsc_async_mutex mtx;
	qsmp_errors qerr;

	qsc_async_mutex_lock_ex(&mtx);

	do
	{
		m_qsmp_keep_alive.recd = false;

		qerr = qsmp_server_send_keep_alive(&m_qsmp_keep_alive, sock);
		qsc_async_thread_sleep(QSMP_KEEPALIVE_TIMEOUT);

		if (m_qsmp_keep_alive.recd == false)
		{
			qerr = qsmp_error_keep_alive_expired;
		}
	} 
	while (qerr == qsmp_error_none);

	qsc_async_mutex_unlock_ex(&mtx);

	return qerr;
}

static qsmp_errors server_listen_ipv4(const qsmp_server_key* prik)
{
	qsc_socket_receive_async_state actx = { 0 };
	qsc_socket ssck = { 0 };
	qsmp_packet pkt = { 0 };
	qsc_ipinfo_ipv4_address addt = { 0 };
	
	uint8_t msgstr[QSMP_MESSAGE_MAX] = { 0 };
	char sin[QSMP_MESSAGE_MAX + 1] = { 0 };
	qsmp_errors qerr;
	size_t mlen;

	qsc_memutils_clear((uint8_t*)&m_qsmp_server_ctx, sizeof(m_qsmp_server_ctx));
	addt = qsc_ipinfo_ipv4_address_any();

	/* initialize the server */
	qsmp_server_initialize(&m_qsmp_server_ctx, prik);
	/* begin listening on the port, when a client connects it triggers the key exchange*/
	qerr = qsmp_server_listen_ipv4(&m_qsmp_server_ctx, &ssck, &addt, QSMP_SERVER_PORT);

	if (qerr == qsmp_error_none)
	{
		qsc_consoleutils_print_safe("server> Connected to remote host: ");
		qsc_consoleutils_print_line((char*)ssck.address);
		server_print_message("Type 'qsmp quit' to exit.");

		/* after key exchange has succeeded, start the keep-alive mechanism on a new thread */
		qsc_async_thread_initialize(&server_keep_alive_loop, &ssck);

		/* initialize send and receive loops */
		memset((char*)&actx, 0x00, sizeof(qsc_socket_receive_async_state));
		actx.callback = &qsc_socket_receive_async_callback;
		actx.error = &qsc_socket_exception_callback;
		actx.source = &ssck;
		qsc_socket_receive_async(&actx);

		mlen = 0;
		server_print_message("");

		while (qsc_consoleutils_line_contains(sin, "qsmp quit") == false)
		{
			if (mlen > 0)
			{
				/* convert the packet to bytes */
				qsmp_server_encrypt_packet(&m_qsmp_server_ctx, (uint8_t*)sin, mlen, &pkt);
				qsc_memutils_clear((uint8_t*)sin, mlen);
				mlen = qsmp_packet_to_stream(&pkt, msgstr);
				qsc_socket_send(&ssck, msgstr, mlen, qsc_socket_send_flag_none);
			}

			mlen = qsc_consoleutils_get_line(sin, sizeof(sin));

			if (mlen == 1 && sin[0] == '\n')
			{
				mlen = 0;
				server_print_message("");
			}
			else
			{
				server_print_prompt();
			}
		}

		qsmp_server_connection_close(&m_qsmp_server_ctx, &ssck, qsmp_error_none);
	}
	else
	{
		server_print_message("Could not connect to the remote host.");
	}

	return qerr;
}

void qsc_socket_exception_callback(const qsc_socket* source, qsc_socket_exceptions error)
{
	assert(source != NULL);

	if (source != NULL)
	{
		server_print_error((qsmp_errors)error);
	}
}

void qsc_socket_receive_async_callback(const qsc_socket* source, const uint8_t* message, size_t msglen)
{
	assert(message != NULL);
	assert(source != NULL);

	qsmp_packet pkt = { 0 };
	char msgstr[QSMP_MESSAGE_MAX] = { 0 };
	qsmp_errors qerr;

	if (message != NULL && source != NULL && msglen > 0)
	{
		/* convert the bytes to packet */
		qsmp_stream_to_packet(message, &pkt);

		if (pkt.flag == qsmp_flag_encrypted_message)
		{
			qerr = qsmp_server_decrypt_packet(&m_qsmp_server_ctx, &pkt, (uint8_t*)msgstr, &msglen);

			if (qerr == qsmp_error_none)
			{
				qsc_consoleutils_print_formatted(msgstr, msglen);
				server_print_message("");
			}
			else
			{
				server_print_message(qsmp_error_to_string(qerr));
			}
		}
		else if (pkt.flag == qsmp_flag_connection_terminate)
		{
			server_print_message("The connection was terminated by the remote host.");
			qsmp_server_connection_close(&m_qsmp_server_ctx, source, qsmp_error_none);
		}
		else if (pkt.flag == qsmp_flag_keep_alive_request)
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
					server_print_error(qsmp_error_bad_keep_alive);
					qsmp_server_connection_close(&m_qsmp_server_ctx, source, qsmp_error_bad_keep_alive);
				}
			}
			else
			{
				server_print_error(qsmp_error_bad_keep_alive);
				qsmp_server_connection_close(&m_qsmp_server_ctx, source, qsmp_error_bad_keep_alive);
			}
		}
		else
		{
			server_print_message("The connection experienced a fatal error.");
			qsmp_server_connection_close(&m_qsmp_server_ctx, source, qsmp_error_connection_failure);
		}
	}
}

int main(void)
{
	qsmp_server_key skey = { 0 };
	qsmp_client_key ckey = { 0 };
	uint8_t kid[QSMP_KEYID_SIZE] = { 0 };
	qsmp_errors qerr;

	server_print_banner();

	if (server_key_dialogue(&skey, &ckey, kid) == true)
	{
		server_print_message("Waiting for a connection...");
		qerr = server_listen_ipv4(&skey);

		if (qerr != qsmp_error_none)
		{
			server_print_error(qerr);
			server_print_message("The network key-exchange failed, the application will exit.");
		}
	}
	else
	{
		server_print_message("The signature key-pair could not be created, the application will exit.");
	}

	server_print_message("Press any key to close...");
	qsc_consoleutils_get_wait();

	return 0;
}

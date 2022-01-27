#include "appclt.h"
#include "qsmpclient.h"
#include "../QSC/consoleutils.h"
#include "../QSC/fileutils.h"
#include "../QSC/folderutils.h"
#include "../QSC/memutils.h"
#include "../QSC/socketclient.h"
#include "../QSC/stringutils.h"

static qsmp_kex_client_state m_qsmp_client_ctx;

static void client_print_prompt(void)
{
	qsc_consoleutils_print_safe("client> ");
}

static void client_print_error(qsmp_errors error)
{
	const char* msg;

	msg = qsmp_error_to_string(error);

	if (msg != NULL)
	{
		client_print_prompt();
		qsc_consoleutils_print_line(msg);
	}
}

static void client_print_message(const char* message)
{
	size_t slen;

	if (message != NULL)
	{
		slen = qsc_stringutils_string_size(message);

		if (slen != 0)
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
	if (message != NULL && msglen != 0)
	{
		qsc_consoleutils_print_line(message);
	}
}

static void client_print_banner(void)
{
	qsc_consoleutils_print_line("***************************************************");
	qsc_consoleutils_print_line("* QSMP: Quantum Secure Messaging Protocol Client  *");
	qsc_consoleutils_print_line("*                                                 *");
	qsc_consoleutils_print_line("* Release:   v1.0.0.0f (A0)                       *");
	qsc_consoleutils_print_line("* Date:      September 1, 2021                    *");
	qsc_consoleutils_print_line("* Contact:   develop@dfdef.com                    *");
	qsc_consoleutils_print_line("***************************************************");
	qsc_consoleutils_print_line("");
}

static bool client_ipv4_dialogue(qsc_ipinfo_ipv4_address* address, qsmp_client_key* ckey)
{
	uint8_t pskey[QSMP_PUBKEY_STRING_SIZE];
	char fpath[QSC_SYSTEM_MAX_PATH + 1] = { 0 };
	char sadd[QSC_IPINFO_IPV4_STRNLEN] = { 0 };
	qsc_ipinfo_ipv4_address addv4t = { 0 };
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
				qsc_fileutils_copy_file_to_stream(fpath, (char*)pskey, sizeof(pskey));
				res = qsmp_client_decode_public_key(ckey, (char*)pskey);

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

void qsc_socket_exception_callback(const qsc_socket* source, qsc_socket_exceptions error)
{
	assert(source != NULL);

	const char* emsg;

	if (source != NULL)
	{
		emsg = qsc_socket_error_to_string(error);
		client_print_message(emsg);
	}
}

void qsc_socket_receive_async_callback(const qsc_socket* source, const uint8_t* message, size_t* msglen)
{
	assert(message != NULL);
	assert(source != NULL);

	qsmp_packet pkt = { 0 };
	char msgstr[QSMP_MESSAGE_MAX] = { 0 };
	size_t mlen;
	qsmp_errors qerr;

	if (message != NULL && source != NULL && msglen != NULL)
	{
		/* convert the bytes to packet */
		qsmp_stream_to_packet(message, &pkt);

		if (pkt.flag == qsmp_flag_encrypted_message)
		{
			qerr = qsmp_client_decrypt_packet(&m_qsmp_client_ctx, &pkt, (uint8_t*)msgstr, msglen);

			if (qerr == qsmp_error_none)
			{
				client_print_string(msgstr, *msglen);
				client_print_message("");
			}
			else
			{
				client_print_message(qsmp_error_to_string(qerr));
			}
		}
		else if (pkt.flag == qsmp_flag_connection_terminate)
		{
			client_print_message("The connection was terminated by the remote host.");
			qsmp_client_connection_close(&m_qsmp_client_ctx, source, qsmp_error_none);
		}
		else if (pkt.flag == qsmp_flag_keep_alive_request)
		{
			/* copy the keep-alive packet and send it back */
			mlen = qsmp_packet_to_stream(&pkt, (uint8_t*)msgstr);
			qsc_socket_send(source, (uint8_t*)msgstr, mlen, qsc_socket_send_flag_none);
		}
		else if (pkt.flag == qsmp_flag_error_condition)
		{
			if (pkt.msglen > 0)
			{
				qerr = (qsmp_errors)pkt.message[0];
				client_print_error(qerr);
			}

			client_print_message("The connection experienced a fatal error.");
			qsmp_client_connection_close(&m_qsmp_client_ctx, source, qsmp_error_connection_failure);
		}
		else
		{
			client_print_message("The connection experienced a fatal error.");
			qsmp_client_connection_close(&m_qsmp_client_ctx, source, qsmp_error_connection_failure);
		}
	}
}

static void client_connect_ipv4(const qsc_ipinfo_ipv4_address* address, const qsmp_client_key* ckey)
{
	qsc_socket_receive_async_state actx = { 0 };
	qsc_socket csck = { 0 };
	qsmp_packet pkt = { 0 };
	uint8_t msgstr[QSMP_MESSAGE_MAX] = { 0 };
	char sin[QSMP_MESSAGE_MAX + 1] = { 0 };
	qsmp_errors qerr;
	size_t mlen;

	qsc_memutils_clear((uint8_t*)&m_qsmp_client_ctx, sizeof(m_qsmp_client_ctx));
	qerr = qsmp_client_connect_ipv4(&m_qsmp_client_ctx, &csck, ckey, address, QSMP_SERVER_PORT);

	if (qerr == qsmp_error_none)
	{
		qsc_consoleutils_print_safe("client> Connected to server: ");
		qsc_consoleutils_print_line((char*)csck.address);
		client_print_message("Enter 'qsmp quit' to exit the application.");

		/* send and receive loops */

		memset((char*)&actx, 0x00, sizeof(qsc_socket_receive_async_state));
		actx.callback = &qsc_socket_receive_async_callback;
		actx.error = &qsc_socket_exception_callback;
		actx.source = &csck;
		qsc_socket_receive_async(&actx);

		mlen = 0;

		while (qsc_consoleutils_line_contains(sin, "qsmp quit") == false)
		{
			client_print_prompt();

			if (mlen > 0)
			{
				/* convert the packet to bytes */
				qsmp_client_encrypt_packet(&m_qsmp_client_ctx, (uint8_t*)sin, mlen, &pkt);
				qsc_memutils_clear((uint8_t*)sin, mlen);
				mlen = qsmp_packet_to_stream(&pkt, msgstr);
				qsc_socket_send(&csck, msgstr, mlen, qsc_socket_send_flag_none);
			}

			mlen = qsc_consoleutils_get_line(sin, sizeof(sin)) - 1;

			if (mlen > 0 && (sin[0] == '\n' || sin[0] == '\r'))
			{
				client_print_message("");
				mlen = 0;
			}
		}

		qsmp_client_connection_close(&m_qsmp_client_ctx, &csck, qsmp_error_none);
	}
	else
	{
		client_print_message("Could not connect to the remote host.");
		client_print_error(qerr);
	}
}

int main(void)
{
	qsmp_client_key ckey = { 0 };
	qsc_ipinfo_ipv4_address addv4t = { 0 };
	size_t ectr;
	bool res;

	ectr = 0;
	client_print_banner();

	while (ectr < 3)
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
		client_connect_ipv4(&addv4t, &ckey);
	}
	else
	{
		qsc_consoleutils_print_line("Invalid input, exiting the application.");
	}

	qsc_consoleutils_print_line("The application has exited. Press any key to close..");
	qsc_consoleutils_get_wait();

	return 0;
}

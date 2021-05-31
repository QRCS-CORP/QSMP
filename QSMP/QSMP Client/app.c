#include "app.h"
#include "qsmpclient.h"
#include "../QSC/consoleutils.h"
#include "../QSC/fileutils.h"
#include "../QSC/folderutils.h"
#include "../QSC/memutils.h"
#include "../QSC/socketclient.h"
#include "../QSC/stringutils.h"

static qsc_qsmp_kex_client_state m_qsmp_client_ctx;

static void qsmp_client_print_error(qsc_qsmp_errors error)
{
	const char* msg;

	msg = qsc_qsmp_error_to_string(qsc_qsmp_error_bad_keep_alive);

	if (msg != NULL)
	{
		qsc_consoleutils_print_safe("client> ");
		qsc_consoleutils_print_line(msg);
	}
}

static void qsmp_client_print_message(const char* message)
{
	size_t slen;

	if (message != NULL)
	{
		slen = qsc_stringutils_string_size(message);

		if (slen != 0)
		{
			qsc_consoleutils_print_safe("client> ");
			qsc_consoleutils_print_line(message);
		}
		else
		{
			qsc_consoleutils_print_safe("client> ");
		}
	}
}

void qsc_socket_exception_callback(qsc_socket* source, qsc_socket_exceptions error)
{
	assert(source != NULL);

	const char* emsg;

	if (source != NULL)
	{
		emsg = qsc_socket_error_to_string(error);
		qsc_consoleutils_print_line(emsg);
	}
}

void qsc_socket_receive_async_callback(qsc_socket* source, uint8_t* message, size_t msglen)
{
	assert(message != NULL);
	assert(source != NULL);

	qsc_qsmp_packet pkt = { 0 };
	char msgstr[QSMP_MESSAGE_MAX] = { 0 };
	size_t mlen;
	qsc_qsmp_errors qerr;

	if (message != NULL && source != NULL && msglen > 0)
	{
		/* convert the bytes to packet */
		qsc_qsmp_stream_to_packet(message, &pkt);

		if (pkt.flag == qsc_qsmp_message_encrypted_message)
		{
			qsc_qsmp_client_decrypt_packet(&m_qsmp_client_ctx, &pkt, (uint8_t*)msgstr, &msglen);
			qsc_consoleutils_print_line(msgstr);
			qsmp_client_print_message("");
		}
		else if (pkt.flag == qsc_qsmp_message_connection_terminate)
		{
			qsmp_client_print_message("The connection was terminated by the remote host.");
			qsc_qsmp_client_connection_close(&m_qsmp_client_ctx, source, qsc_qsmp_error_none);
		}
		else if (pkt.flag == qsc_qsmp_message_keep_alive_request)
		{
			/* copy the keep-alive packet and send it back */
			mlen = qsc_qsmp_packet_to_stream(&pkt, msgstr);
			qsc_socket_send(source, msgstr, mlen, qsc_socket_send_flag_none);
		}
		else if (pkt.flag == qsc_qsmp_message_error_condition)
		{
			if (pkt.msglen > 0)
			{
				qerr = (qsc_qsmp_errors)pkt.message[0];
				qsmp_client_print_error(qerr);
			}

			qsmp_client_print_message("The connection experienced a fatal error.");
			qsc_qsmp_client_connection_close(&m_qsmp_client_ctx, source, qsc_qsmp_error_connection_failure);
		}
		else
		{
			qsmp_client_print_message("The connection experienced a fatal error.");
			qsc_qsmp_client_connection_close(&m_qsmp_client_ctx, source, qsc_qsmp_error_connection_failure);
		}
	}
}

static void qsmp_client_print_banner()
{
	qsc_consoleutils_print_line("***************************************************");
	qsc_consoleutils_print_line("* QSMP: Quantum Secure Messaging Protocol Client  *");
	qsc_consoleutils_print_line("*                                                 *");
	qsc_consoleutils_print_line("* Release:   v1.0.0.0a (A0)                       *");
	qsc_consoleutils_print_line("* Date:      May 28, 2021                         *");
	qsc_consoleutils_print_line("* Contact:   develop@vtdev.com                    *");
	qsc_consoleutils_print_line("***************************************************");
	qsc_consoleutils_print_line("");
}

static bool qsmp_client_dialogue(qsc_qsmp_client_key* ckey, qsc_ipinfo_ipv4_address* address)
{
	uint8_t pskey[QSC_QSMP_PUBKEY_STRING_SIZE];
	char fpath[FILENAME_MAX + 1] = { 0 };
	char sadd[QSC_IPINFO_IPV4_STRNLEN] = { 0 };
	qsc_ipinfo_ipv4_address addv4t;
	size_t slen;
	bool res;

	res = false;

	qsmp_client_print_message("Enter the destination IPv4 address, ex. 192.168.1.1");
	qsmp_client_print_message("");
	slen = qsc_consoleutils_get_formatted_line(sadd, sizeof(sadd));

	if (slen >= QSC_IPINFO_IPV4_MINLEN)
	{
		addv4t = qsc_ipinfo_ipv4_address_from_string(sadd);
		res = qsc_ipinfo_ipv4_address_is_valid(&addv4t);

		if (res == true)
		{
			qsc_memutils_copy(address->ipv4, addv4t.ipv4, sizeof(addv4t.ipv4));
		}
		else
		{
			qsmp_client_print_message("The address format is invalid.");
		}
	}
	else
	{
		qsmp_client_print_message("The address format is invalid.");
	}

	if (res == true)
	{
		qsmp_client_print_message("Enter the path of the public key:");
		qsmp_client_print_message("");
		slen = qsc_consoleutils_get_formatted_line(fpath, sizeof(fpath));

		if (qsc_filetools_file_exists(fpath) == true && qsc_stringutils_string_contains(fpath, QSMP_PUBKEY_NAME) == true)
		{
			qsc_filetools_copy_file_to_stream(fpath, pskey, sizeof(pskey));
			qsc_qsmp_client_decode_public_key(ckey, pskey);
			res = true;
		}
		else
		{
			res = false;
			qsmp_client_print_message("The path is invalid or inaccessable.");
		}
	}

	return res;
}

static void qsmp_client_connect_ipv4(const qsc_ipinfo_ipv4_address* address, qsc_qsmp_client_key* ckey)
{
	qsc_socket_receive_async_state actx = { 0 };
	qsc_socket csck = { 0 };
	qsc_qsmp_packet pkt = { 0 };
	uint8_t msgstr[QSMP_MESSAGE_MAX] = { 0 };
	char sin[QSMP_MESSAGE_MAX + 1] = { 0 };
	qsc_qsmp_errors qerr;
	size_t mlen;

	qsc_memutils_clear((uint8_t*)&m_qsmp_client_ctx, sizeof(m_qsmp_client_ctx));
	qerr = qsc_qsmp_client_connect_ipv4(&m_qsmp_client_ctx, &csck, ckey, address, QSC_QSMP_SERVER_PORT);

	if (qerr == qsc_qsmp_error_none)
	{
		qsc_consoleutils_print_safe("client> Connected to server: ");
		qsc_consoleutils_print_line((char*)csck.address);
		qsmp_client_print_message("Enter 'qsmp quit' to exit the application.");

		/* send and receive loops */

		memset((char*)&actx, 0x00, sizeof(qsc_socket_receive_async_state));
		actx.callback = qsc_socket_receive_async_callback;
		actx.error = qsc_socket_exception_callback;
		actx.source = &csck;
		qsc_socket_receive_async(&actx);

		mlen = 0;
		qsc_consoleutils_print_safe("client> ");

		while (qsc_consoleutils_line_contains(sin, "qsmp quit") == false)
		{
			if (mlen > 0)
			{
				/* convert the packet to bytes */
				qsc_qsmp_client_encrypt_packet(&m_qsmp_client_ctx, (uint8_t*)sin, mlen, &pkt);
				mlen = qsc_qsmp_packet_to_stream(&pkt, msgstr);
				qsc_socket_send(&csck, msgstr, mlen, qsc_socket_send_flag_none);
				memset(sin, 0x00, mlen);
				mlen = 0;
			}

			mlen = qsc_consoleutils_get_formatted_line(sin, sizeof(sin));
			qsc_consoleutils_print_safe("client> ");
		}

		qsc_qsmp_client_connection_close(&m_qsmp_client_ctx, &csck, qsc_qsmp_error_none);
	}
	else
	{
		qsmp_client_print_message("Could not connect to the remote host.");
	}
}

int main(void)
{
	qsc_qsmp_client_key ckey = { 0 };
	qsc_ipinfo_ipv4_address addv4t = { 0 };
	size_t ectr;
	bool res;

	ectr = 0;
	qsmp_client_print_banner();

	while (ectr < 3)
	{
		res = qsmp_client_dialogue(&ckey, &addv4t);

		if (res == true)
		{
			break;
		}
		else
		{
			qsc_consoleutils_print_line("");
		}
	}

	if (res == true)
	{
		qsmp_client_connect_ipv4(&addv4t, &ckey);
	}
	else
	{
		qsc_consoleutils_print_line("Invalid input, exiting the application.");
	}

	qsc_consoleutils_print_line("The application has exited. Press any key to close..");
	qsc_consoleutils_get_wait();

	return 0;
}

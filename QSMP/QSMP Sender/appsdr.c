#include "appsdr.h"
#include "../QSMP/qsmpclient.h"
#include "../QSC/acp.h"
#include "../QSC/async.h"
#include "../QSC/consoleutils.h"
#include "../QSC/fileutils.h"
#include "../QSC/folderutils.h"
#include "../QSC/memutils.h"
#include "../QSC/stringutils.h"

static void sender_print_prompt(void)
{
	qsc_consoleutils_print_safe("sender> ");
}

static void sender_print_error(qsmp_errors error)
{
	const char* msg;

	msg = qsmp_error_to_string(error);

	if (msg != NULL)
	{
		sender_print_prompt();
		qsc_consoleutils_print_line(msg);
	}
}

static void sender_print_message(const char* message)
{
	size_t slen;

	if (message != NULL)
	{
		slen = qsc_stringutils_string_size(message);

		if (slen != 0)
		{
			sender_print_prompt();
			qsc_consoleutils_print_line(message);
		}
		else
		{
			sender_print_prompt();
		}
	}
}

static void sender_print_string(const char* message, size_t msglen)
{
	if (message != NULL && msglen != 0)
	{
		qsc_consoleutils_print_line(message);
	}
}

static void sender_print_banner(void)
{
	qsc_consoleutils_print_line("***************************************************");
	qsc_consoleutils_print_line("* QSMP: Sender Example Project                    *");
	qsc_consoleutils_print_line("*                                                 *");
	qsc_consoleutils_print_line("* Release:   v1.2.0.0a (A2)                       *");
	qsc_consoleutils_print_line("* Date:      May 1, 2021                          *");
	qsc_consoleutils_print_line("* Contact:   develop@dfdef.com                    *");
	qsc_consoleutils_print_line("***************************************************");
	qsc_consoleutils_print_line("");
}

static bool sender_get_storage_path(char fpath[QSC_SYSTEM_MAX_PATH], size_t pathlen)
{
	bool res;

	qsc_folderutils_get_directory(qsc_folderutils_directories_user_documents, fpath);
	qsc_folderutils_append_delimiter(fpath);
	qsc_stringutils_concat_strings(fpath, pathlen, QSMP_APP_PATH);
	res = qsc_folderutils_directory_exists(fpath);

	if (res == false)
	{
		res = qsc_folderutils_create_directory(fpath);
	}

	return res;
}

static bool sender_prikey_exists(char fpath[QSC_SYSTEM_MAX_PATH], size_t pathlen)
{
	bool res;

	res = sender_get_storage_path(fpath, pathlen);

	if (res == true)
	{
		qsc_folderutils_append_delimiter(fpath);
		qsc_stringutils_concat_strings(fpath, pathlen, QSMP_PRIKEY_NAME);

		res = qsc_fileutils_exists(fpath);
	}

	return res;
}

static bool sender_ipv4_dialogue(qsc_ipinfo_ipv4_address* address, qsmp_server_key* prik, qsmp_client_key* rverk)
{
	uint8_t spub[QSMP_PUBKEY_STRING_SIZE] = { 0 };
	uint8_t spri[QSMP_SIGKEY_ENCODED_SIZE] = { 0 };
	qsc_ipinfo_ipv4_address addv4t = { 0 };
	char sadd[QSC_IPINFO_IPV4_STRNLEN] = { 0 };
	char dir[QSC_SYSTEM_MAX_PATH] = { 0 };
	char fpath[QSC_SYSTEM_MAX_PATH] = { 0 };
	size_t slen;
	bool res;

	res = false;

	/* get the ip address from the user */
	sender_print_message("Enter the destination IPv4 address, ex. 192.168.1.1");
	sender_print_message("");
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
			sender_print_message("The address format is invalid.");
		}
	}
	else
	{
		sender_print_message("The address format is invalid.");
	}

	/* get the path to the targets public key */
	if (res == true)
	{
		sender_print_message("Enter the path of the public key:");
		sender_print_message("");
		slen = qsc_consoleutils_get_line(fpath, sizeof(fpath)) - 1;
		res = false;

		if (slen > 0)
		{
			uint8_t pskey[QSMP_PUBKEY_STRING_SIZE] = { 0 };

			if (qsc_fileutils_exists(fpath) == true && qsc_stringutils_string_contains(fpath, QSMP_PUBKEY_EXTENSION) == true)
			{
				qsc_fileutils_copy_file_to_stream(fpath, (char*)pskey, sizeof(pskey));
				res = qsmp_decode_public_key(rverk, (char*)pskey);

				if (res == false)
				{
					sender_print_message("The public key is invalid.");
				}
			}
			else
			{
				sender_print_message("The path is invalid or inaccessable.");
			}
		}
	}

	/* get the clients private key from storage */
	if (res == true)
	{
		res = sender_prikey_exists(fpath, sizeof(fpath));

		if (res == true)
		{
			res = qsc_fileutils_copy_file_to_stream(fpath, (char*)spri, sizeof(spri));

			if (res == true)
			{
				qsmp_deserialize_signature_key(prik, spri);
				qsc_consoleutils_print_line("sender> The private-key has been loaded.");
			}
			else
			{
				qsc_consoleutils_print_line("sender> Could not load the key-pair, aborting startup.");
			}
		}
		else
		{
			res = sender_get_storage_path(dir, sizeof(dir));

			if (res == true)
			{
				uint8_t keyid[QSMP_KEYID_SIZE] = { 0 };

				qsc_stringutils_copy_string(fpath, sizeof(fpath), dir);
				qsc_folderutils_append_delimiter(fpath);
				qsc_stringutils_concat_strings(fpath, sizeof(fpath), QSMP_PUBKEY_NAME);

				qsc_consoleutils_print_line("sender> The private-key was not detected, generating a new private/public keypair...");
				res = qsc_acp_generate(keyid, QSMP_KEYID_SIZE);

				if (res == true)
				{
					qsmp_client_key pubk = { 0 };

					qsmp_generate_keypair(&pubk, prik, keyid);
					/* note: copies the public verify-key and key attributes contained in the server key */
					qsmp_encode_public_key((char*)spub, prik);
					/* store the encoded public key */
					res = qsc_fileutils_copy_stream_to_file(fpath, (char*)spub, sizeof(spub));

					if (res == true)
					{
						qsc_consoleutils_print_safe("sender> The publickey has been saved to ");
						qsc_consoleutils_print_line(fpath);
						qsc_consoleutils_print_line("sender> Distribute the public-key to intended clients.");
						qsc_consoleutils_print_line("sender> ");

						/* store the private key */
						qsc_stringutils_clear_string(fpath);
						qsc_stringutils_copy_string(fpath, sizeof(fpath), dir);
						qsc_folderutils_append_delimiter(fpath);
						qsc_stringutils_concat_strings(fpath, sizeof(fpath), QSMP_PRIKEY_NAME);
						qsmp_serialize_signature_key(spri, prik);
						res = qsc_fileutils_copy_stream_to_file(fpath, (char*)spri, sizeof(spri));
					}
					else
					{
						qsc_consoleutils_print_line("sender> Could not load the key-pair, aborting startup.");
					}
				}
				else
				{
					qsc_consoleutils_print_line("sender> Could not create the key-pair, aborting startup.");
				}
			}
		}
	}

	return res;
}

static void sender_receive_callback(const qsmp_connection_state* cns, const char* pmsg, size_t msglen)
{
	sender_print_string(pmsg, msglen);
	sender_print_prompt();
}

static void sender_send_loop(qsmp_connection_state* cns)
{
	qsmp_packet pkt = { 0 };
	uint8_t msgstr[QSMP_CONNECTION_MTU] = { 0 };
	char sin[QSMP_CONNECTION_MTU + 1] = { 0 };
	size_t mlen;

	mlen = 0;

	/* start the sender loop */
	while (true)
	{
		sender_print_prompt();

		if (qsc_consoleutils_line_contains(sin, "qsmp quit"))
		{
			break;
		}
		else if (qsc_consoleutils_line_contains(sin, "qsmp ratchet"))
		{
			qsmp_client_duplex_send_ratchet_request(cns, false);
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
				qsc_socket_send(&cns->target, msgstr, mlen, qsc_socket_send_flag_none);
			}
		}

		mlen = qsc_consoleutils_get_line(sin, sizeof(sin)) - 1;

		if (mlen > 0 && (sin[0] == '\n' || sin[0] == '\r'))
		{
			sender_print_message("");
			mlen = 0;
		}
	}

	qsmp_connection_close(cns, qsmp_error_none, true);
}

int main(void)
{
	qsmp_server_key prik = { 0 };
	qsmp_client_key rverk = { 0 };
	qsc_ipinfo_ipv4_address addv4t = { 0 };
	size_t ectr;
	bool res;

	ectr = 0;
	sender_print_banner();

	while (ectr < 3)
	{
		res = sender_ipv4_dialogue(&addv4t, &prik , &rverk);

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
		qsmp_errors err;

		err = qsmp_client_duplex_connect_ipv4(&prik, &rverk , &addv4t, QSMP_CLIENT_PORT, &sender_send_loop, &sender_receive_callback);

		if (err != qsmp_error_none)
		{
			sender_print_error(err);
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

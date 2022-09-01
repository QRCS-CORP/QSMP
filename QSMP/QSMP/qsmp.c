#include "qsmp.h"
#include "../QSMP/logger.h"
#include "../QSC/acp.h"
#include "../QSC/encoding.h"
#include "../QSC/intutils.h"
#include "../QSC/memutils.h"
#include "../QSC/stringutils.h"
#include "../QSC/timestamp.h"

const char* qsmp_error_to_string(qsmp_errors error)
{
	const char* dsc;

	dsc = NULL;

	if ((uint32_t)error < QSMP_ERROR_STRING_DEPTH)
	{
		dsc = QSMP_ERROR_STRINGS[(size_t)error];
	}

	return dsc;
}

void qsmp_connection_close(qsmp_connection_state* cns, qsmp_errors err, bool notify)
{
	assert(cns != NULL);

	if (cns != NULL)
	{
		if (qsc_socket_is_connected(&cns->target) == true)
		{
			if (notify == true)
			{
				qsmp_packet resp = { 0 };
				uint8_t spct[QSMP_MESSAGE_MAX] = { 0 };
				size_t plen;

				/* send a disconnect message */
				resp.flag = qsmp_flag_connection_terminate;
				resp.sequence = QSMP_SEQUENCE_TERMINATOR;
				resp.msglen = 1;
				resp.message[0] = (uint8_t)err;
				plen = qsmp_packet_to_stream(&resp, spct);
				qsc_socket_send(&cns->target, spct, plen, qsc_socket_send_flag_none);
			}

			/* close the socket */
			qsc_socket_close_socket(&cns->target);
		}
	}
}

void qsmp_connection_state_dispose(qsmp_connection_state* cns)
{
	assert(cns != NULL);

	if (cns != NULL)
	{
		qsc_rcs_dispose(&cns->rxcpr);
		qsc_rcs_dispose(&cns->txcpr);
		qsc_memutils_clear((uint8_t*)&cns->target, sizeof(qsc_socket));
		qsc_keccak_dispose(&cns->rtcs);
		cns->rxseq = 0;
		cns->txseq = 0;
		cns->instance = 0;
		cns->exflag = qsmp_flag_none;
	}
}

bool qsmp_decode_public_key(qsmp_client_key* pubk, const char enck[QSMP_PUBKEY_STRING_SIZE])
{
	assert(pubk != NULL);

	char dtm[QSC_TIMESTAMP_STRING_SIZE] = { 0 };
	char tmpvk[QSMP_PUBKEY_ENCODING_SIZE] = { 0 };
	size_t spos;
	size_t slen;
	bool res;

	res = false;

	if (pubk != NULL)
	{
		spos = sizeof(QSMP_PUBKEY_HEADER) + sizeof(QSMP_PUBKEY_VERSION) + sizeof(QSMP_PUBKEY_CONFIG_PREFIX) - 1;
		slen = QSMP_CONFIG_SIZE - 1;
		qsc_memutils_copy(pubk->config, (enck + spos), slen);

		spos += slen + sizeof(QSMP_PUBKEY_EXPIRATION_PREFIX) - 3;
		qsc_intutils_hex_to_bin((enck + spos), pubk->keyid, QSMP_KEYID_SIZE * 2);

		spos += (QSMP_KEYID_SIZE * 2) + sizeof(QSMP_PUBKEY_EXPIRATION_PREFIX);
		slen = QSC_TIMESTAMP_STRING_SIZE - 1;
		qsc_memutils_copy(dtm, (enck + spos), slen);
		pubk->expiration = qsc_timestamp_datetime_to_seconds(dtm);
		spos += QSC_TIMESTAMP_STRING_SIZE;

		qsc_stringutils_remove_line_breaks(tmpvk, sizeof(tmpvk), (enck + spos), (QSMP_PUBKEY_STRING_SIZE - (spos + sizeof(QSMP_PUBKEY_FOOTER))));
		res = qsc_encoding_base64_decode(pubk->verkey, QSMP_VERIFYKEY_SIZE, tmpvk, QSMP_PUBKEY_ENCODING_SIZE);
	}

	return res;
}

qsmp_errors qsmp_decrypt_packet(qsmp_connection_state* cns, uint8_t* message, size_t* msglen, const qsmp_packet* packetin)
{
	assert(cns != NULL);
	assert(packetin != NULL);
	assert(message != NULL);
	assert(msglen != NULL);

	uint8_t hdr[QSMP_HEADER_SIZE] = { 0 };
	qsmp_errors qerr;

	qerr = qsmp_error_invalid_input;

	if (cns != NULL && message != NULL && msglen != NULL && packetin != NULL)
	{
		cns->rxseq += 1;

		if (packetin->sequence == cns->rxseq)
		{
			if (cns->exflag == qsmp_flag_session_established)
			{
				const uint32_t MACLEN = (cns->txcpr.ctype == qsc_rcs_cipher_256) ? 32 : 64;

				/* serialize the header and add it to the ciphers associated data */
				qsmp_packet_header_serialize(packetin, hdr);
				qsc_rcs_set_associated(&cns->rxcpr, hdr, QSMP_HEADER_SIZE);
				*msglen = packetin->msglen - MACLEN;

				/* authenticate then decrypt the data */
				if (qsc_rcs_transform(&cns->rxcpr, message, packetin->message, *msglen) == true)
				{
					qerr = qsmp_error_none;
				}
				else
				{
					*msglen = 0;
					qerr = qsmp_error_authentication_failure;
				}
			}
			else
			{
				*msglen = 0;
				qerr = qsmp_error_channel_down;
			}
		}
		else
		{
			*msglen = 0;
			qerr = qsmp_error_packet_unsequenced;
		}
	}

	return qerr;
}

void qsmp_deserialize_signature_key(qsmp_server_key* prik, const uint8_t serk[QSMP_SIGKEY_ENCODED_SIZE])
{
	assert(prik != NULL);

	size_t pos;

	qsc_memutils_copy(prik->config, serk, QSMP_CONFIG_SIZE);
	pos = QSMP_CONFIG_SIZE;
	prik->expiration = qsc_intutils_le8to64((serk + pos));
	pos += QSMP_TIMESTAMP_SIZE;
	qsc_memutils_copy(prik->keyid, (serk + pos), QSMP_KEYID_SIZE);
	pos += QSMP_KEYID_SIZE;
	qsc_memutils_copy(prik->sigkey, (serk + pos), QSMP_SIGNKEY_SIZE);
	pos += QSMP_SIGNKEY_SIZE;
	qsc_memutils_copy(prik->verkey, (serk + pos), QSMP_VERIFYKEY_SIZE);
}

void qsmp_encode_public_key(char enck[QSMP_PUBKEY_STRING_SIZE], const qsmp_server_key* prik)
{
	assert(prik != NULL);

	char dtm[QSMP_TIMESTAMP_STRING_SIZE] = { 0 };
	char hexid[QSMP_KEYID_SIZE * 2] = { 0 };
	char tmpvk[QSMP_PUBKEY_ENCODING_SIZE] = { 0 };
	size_t slen;
	size_t spos;

	if (prik != NULL)
	{
		slen = sizeof(QSMP_PUBKEY_HEADER) - 1;
		qsc_memutils_copy(enck, QSMP_PUBKEY_HEADER, slen);
		spos = slen;
		enck[spos] = '\n';
		++spos;

		slen = sizeof(QSMP_PUBKEY_VERSION) - 1;
		qsc_memutils_copy((enck + spos), QSMP_PUBKEY_VERSION, slen);
		spos += slen;
		enck[spos] = '\n';
		++spos;

		slen = sizeof(QSMP_PUBKEY_CONFIG_PREFIX) - 1;
		qsc_memutils_copy((enck + spos), QSMP_PUBKEY_CONFIG_PREFIX, slen);
		spos += slen;
		slen = sizeof(QSMP_CONFIG_STRING) - 1;
		qsc_memutils_copy((enck + spos), QSMP_CONFIG_STRING, slen);
		spos += slen;
		enck[spos] = '\n';
		++spos;

		slen = sizeof(QSMP_PUBKEY_KEYID_PREFIX) - 1;
		qsc_memutils_copy((enck + spos), QSMP_PUBKEY_KEYID_PREFIX, slen);
		spos += slen;
		qsc_intutils_bin_to_hex(prik->keyid, hexid, QSMP_KEYID_SIZE);
		slen = sizeof(hexid);
		qsc_memutils_copy((enck + spos), hexid, slen);
		spos += slen;
		enck[spos] = '\n';
		++spos;

		slen = sizeof(QSMP_PUBKEY_EXPIRATION_PREFIX) - 1;
		qsc_memutils_copy((enck + spos), QSMP_PUBKEY_EXPIRATION_PREFIX, slen);
		spos += slen;
		qsc_timestamp_seconds_to_datetime(prik->expiration, dtm);
		slen = sizeof(dtm) - 1;
		qsc_memutils_copy((enck + spos), dtm, slen);
		spos += slen;
		enck[spos] = '\n';
		++spos;

		size_t enclen = qsc_encoding_base64_encoded_size(sizeof(prik->verkey));
		slen = QSMP_VERIFYKEY_SIZE;
		qsc_encoding_base64_encode(tmpvk, QSMP_PUBKEY_ENCODING_SIZE, prik->verkey, slen);
		spos += qsc_stringutils_add_line_breaks((enck + spos), QSMP_PUBKEY_STRING_SIZE - spos, QSMP_PUBKEY_LINE_LENGTH, tmpvk, sizeof(tmpvk));
		enck[spos] = '\n';
		++spos;

		slen = sizeof(QSMP_PUBKEY_FOOTER) - 1;
		qsc_memutils_copy((enck + spos), QSMP_PUBKEY_FOOTER, slen);
		spos += slen;
		enck[spos] = '\n';
	}
}

qsmp_errors qsmp_encrypt_packet(qsmp_connection_state* cns, qsmp_packet* packetout, const uint8_t* message, size_t msglen)
{
	assert(cns != NULL);
	assert(message != NULL);
	assert(packetout != NULL);

	qsmp_errors qerr;

	qerr = qsmp_error_invalid_input;

	if (cns != NULL && message != NULL && packetout != NULL)
	{
		if (cns->exflag == qsmp_flag_session_established && msglen != 0)
		{
			uint8_t hdr[QSMP_HEADER_SIZE] = { 0 };
			const uint32_t MACLEN = (cns->txcpr.ctype == qsc_rcs_cipher_256) ? 32 : 64;

			/* assemble the encryption packet */
			cns->txseq += 1;
			qsc_memutils_clear(packetout->message, QSMP_MESSAGE_MAX);
			packetout->flag = qsmp_flag_encrypted_message;
			packetout->msglen = (uint32_t)msglen + MACLEN;
			packetout->sequence = cns->txseq;

			/* serialize the header and add it to the ciphers associated data */
			qsmp_packet_header_serialize(packetout, hdr);
			qsc_rcs_set_associated(&cns->txcpr, hdr, QSMP_HEADER_SIZE);
			/* encrypt the message */
			qsc_rcs_transform(&cns->txcpr, packetout->message, message, msglen);

			qerr = qsmp_error_none;
		}
		else
		{
			qerr = qsmp_error_channel_down;
		}
	}

	return qerr;
}

void qsmp_log_error(qsmp_messages emsg, qsc_socket_exceptions err, const char* msg)
{
	assert(msg != NULL);

	char mtmp[QSMP_ERROR_STRING_WIDTH * 2] = { 0 };
	const char* perr;
	const char* phdr;
	const char* pmsg;

	pmsg = qsmp_get_error_description(emsg);

	if (pmsg != NULL)
	{
		if (msg != NULL)
		{
			qsc_stringutils_copy_string(mtmp, sizeof(mtmp), pmsg);
			qsc_stringutils_concat_strings(mtmp, sizeof(mtmp), msg);
			qsmp_logger_write(mtmp);
		}
		else
		{
			qsmp_logger_write(pmsg);
		}
	}

	phdr = qsmp_get_error_description(qsmp_messages_socket_message);
	perr = qsc_socket_error_to_string(err);

	if (pmsg != NULL && perr != NULL)
	{
		qsc_stringutils_clear_string(mtmp);
		qsc_stringutils_copy_string(mtmp, sizeof(mtmp), phdr);
		qsc_stringutils_concat_strings(mtmp, sizeof(mtmp), perr);
		qsmp_logger_write(mtmp);
	}
}

void qsmp_log_message(qsmp_messages emsg)
{
	const char* msg = qsmp_get_error_description(emsg);

	if (msg != NULL)
	{
		qsmp_logger_write(msg);
	}
}

void qsmp_log_write(qsmp_messages emsg, const char* msg)
{
	assert(msg != NULL);

	const char* pmsg = qsmp_get_error_description(emsg);

	if (pmsg != NULL)
	{
		if (msg != NULL)
		{
			char mtmp[QSMP_ERROR_STRING_WIDTH] = { 0 };

			qsc_stringutils_copy_string(mtmp, sizeof(mtmp), pmsg);
			qsc_stringutils_concat_strings(mtmp, sizeof(mtmp), msg);
			qsmp_logger_write(mtmp);
		}
		else
		{
			qsmp_logger_write(pmsg);
		}
	}
}

const char* qsmp_get_error_description(qsmp_messages message)
{
	const char* dsc;

	dsc = NULL;

	if ((uint32_t)message < QSMP_MESSAGE_STRING_DEPTH)
	{
		dsc = QSMP_MESSAGE_STRINGS[(size_t)message];

	}

	return dsc;
}

void qsmp_generate_keypair(qsmp_client_key* pubkey, qsmp_server_key* prikey, const uint8_t keyid[QSMP_KEYID_SIZE])
{
	assert(prikey != NULL);
	assert(pubkey != NULL);

	if (prikey != NULL && pubkey != NULL)
	{
		/* add the timestamp plus duration to the key */
		prikey->expiration = qsc_timestamp_epochtime_seconds() + QSMP_PUBKEY_DURATION_SECONDS;

		/* set the configuration string and key-identity strings */
		qsc_memutils_copy(prikey->config, QSMP_CONFIG_STRING, QSMP_CONFIG_SIZE);
		qsc_memutils_copy(prikey->keyid, keyid, QSMP_KEYID_SIZE);

		/* generate the signature key-pair */
		qsmp_signature_generate_keypair(prikey->verkey, prikey->sigkey, qsc_acp_generate);

		/* copy the key expiration, config, key-id, and the signatures verification key, to the public key structure */
		pubkey->expiration = prikey->expiration;
		qsc_memutils_copy(pubkey->config, prikey->config, QSMP_CONFIG_SIZE);
		qsc_memutils_copy(pubkey->keyid, prikey->keyid, QSMP_KEYID_SIZE);
		qsc_memutils_copy(pubkey->verkey, prikey->verkey, QSMP_VERIFYKEY_SIZE);
	}
}

void qsmp_packet_clear(qsmp_packet* packet)
{
	packet->flag = (uint8_t)qsmp_flag_none;
	packet->msglen = 0;
	packet->sequence = 0;
	qsc_memutils_clear(packet->message, sizeof(packet->message));
}

void qsmp_packet_error_message(qsmp_packet* packet, qsmp_errors error)
{
	assert(packet != NULL);

	if (packet != NULL)
	{
		packet->flag = qsmp_flag_error_condition;
		packet->message[0] = (uint8_t)error;
		packet->msglen = 1;
		packet->sequence = QSMP_SEQUENCE_TERMINATOR;
	}
}

void qsmp_packet_header_deserialize(const uint8_t* header, qsmp_packet* packet)
{
	assert(header != NULL);
	assert(packet != NULL);

	if (header != NULL && packet != NULL)
	{
		packet->flag = header[0];
		packet->msglen = qsc_intutils_le8to32((header + sizeof(uint8_t)));
		packet->sequence = qsc_intutils_le8to64((header + sizeof(uint8_t) + sizeof(uint32_t)));
	}
}

void qsmp_packet_header_serialize(const qsmp_packet* packet, uint8_t* header)
{
	assert(header != NULL);
	assert(packet != NULL);

	if (header != NULL && packet != NULL)
	{
		header[0] = packet->flag;
		qsc_intutils_le32to8((header + sizeof(uint8_t)), packet->msglen);
		qsc_intutils_le64to8((header + sizeof(uint8_t) + sizeof(uint32_t)), packet->sequence);
	}
}

size_t qsmp_packet_to_stream(const qsmp_packet* packet, uint8_t* pstream)
{
	assert(packet != NULL);
	assert(pstream != NULL);

	size_t res;

	res = 0;

	if (packet != NULL && pstream != NULL)
	{
		pstream[0] = packet->flag;
		qsc_intutils_le32to8((pstream + sizeof(uint8_t)), packet->msglen);
		qsc_intutils_le64to8((pstream + sizeof(uint8_t) + sizeof(uint32_t)), packet->sequence);

		if (packet->msglen <= QSMP_MESSAGE_MAX)
		{
			qsc_memutils_copy((pstream + sizeof(uint8_t) + sizeof(uint32_t) + sizeof(uint64_t)), packet->message, packet->msglen);
			res = (size_t)QSMP_HEADER_SIZE + packet->msglen;
		}
	}

	return res;
}

void qsmp_serialize_signature_key(uint8_t serk[QSMP_SIGKEY_ENCODED_SIZE], const qsmp_server_key* prik)
{
	assert(prik != NULL);

	size_t pos;

	qsc_memutils_copy(serk, prik->config, QSMP_CONFIG_SIZE);
	pos = QSMP_CONFIG_SIZE;
	qsc_intutils_le64to8((serk + pos), prik->expiration);
	pos += QSMP_TIMESTAMP_SIZE;
	qsc_memutils_copy((serk + pos), prik->keyid, QSMP_KEYID_SIZE);
	pos += QSMP_KEYID_SIZE;
	qsc_memutils_copy((serk + pos), prik->sigkey, QSMP_SIGNKEY_SIZE);
	pos += QSMP_SIGNKEY_SIZE;
	qsc_memutils_copy((serk + pos), prik->verkey, QSMP_VERIFYKEY_SIZE);
}

void qsmp_stream_to_packet(const uint8_t* pstream, qsmp_packet* packet)
{
	assert(packet != NULL);
	assert(pstream != NULL);

	if (packet != NULL && pstream != NULL)
	{
		packet->flag = pstream[0];
		packet->msglen = qsc_intutils_le8to32((pstream + sizeof(uint8_t)));
		packet->sequence = qsc_intutils_le8to64((pstream + sizeof(uint8_t) + sizeof(uint32_t)));

		if (packet->msglen <= QSMP_MESSAGE_MAX)
		{
			qsc_memutils_copy(packet->message, (pstream + sizeof(uint8_t) + sizeof(uint32_t) + sizeof(uint64_t)), packet->msglen);
		}
	}
}

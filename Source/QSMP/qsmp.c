#include "qsmp.h"
#include "logger.h"
#include "async.h"
#include "acp.h"
#include "encoding.h"
#include "intutils.h"
#include "memutils.h"
#include "stringutils.h"
#include "timestamp.h"

void qsmp_asymmetric_cipher_keypair_dispose(qsmp_asymmetric_cipher_keypair* keypair)
{
	if (keypair != NULL)
	{
		if (keypair->prikey != NULL)
		{
			qsc_memutils_alloc_free(keypair->prikey);
			keypair->prikey = NULL;
		}

		if (keypair->pubkey != NULL)
		{
			qsc_memutils_alloc_free(keypair->pubkey);
			keypair->pubkey = NULL;
		}

		qsc_memutils_alloc_free(keypair);
		keypair = NULL;
	}
}

qsmp_asymmetric_cipher_keypair* qsmp_asymmetric_cipher_keypair_initialize(void)
{
	qsmp_asymmetric_cipher_keypair* pkp;

	pkp = qsc_memutils_malloc(sizeof(qsmp_asymmetric_cipher_keypair));

	if (pkp != NULL)
	{
		pkp->prikey = qsc_memutils_malloc(QSMP_ASYMMETRIC_PRIVATE_KEY_SIZE);

		if (pkp->prikey != NULL)
		{
			qsc_memutils_clear(pkp->prikey, QSMP_ASYMMETRIC_PRIVATE_KEY_SIZE);

			pkp->pubkey = qsc_memutils_malloc(QSMP_ASYMMETRIC_PUBLIC_KEY_SIZE);

			if (pkp->pubkey != NULL)
			{
				qsc_memutils_clear(pkp->pubkey, QSMP_ASYMMETRIC_PUBLIC_KEY_SIZE);
			}
		}
	}

	return pkp;
}

void qsmp_asymmetric_signature_keypair_dispose(qsmp_asymmetric_signature_keypair* keypair)
{
	if (keypair != NULL)
	{
		if (keypair->sigkey != NULL)
		{
			qsc_memutils_alloc_free(keypair->sigkey);
			keypair->sigkey = NULL;
		}

		if (keypair->verkey != NULL)
		{
			qsc_memutils_alloc_free(keypair->verkey);
			keypair->verkey = NULL;
		}

		qsc_memutils_alloc_free(keypair);
		keypair = NULL;
	}
}

qsmp_asymmetric_signature_keypair* qsmp_asymmetric_signature_keypair_initialize(void)
{
	qsmp_asymmetric_signature_keypair* pkp;

	pkp = qsc_memutils_malloc(sizeof(qsmp_asymmetric_signature_keypair));

	if (pkp != NULL)
	{
		pkp->sigkey = qsc_memutils_malloc(QSMP_ASYMMETRIC_SIGNING_KEY_SIZE);

		if (pkp->sigkey != NULL)
		{
			qsc_memutils_clear(pkp->sigkey, QSMP_ASYMMETRIC_SIGNING_KEY_SIZE);

			pkp->verkey = qsc_memutils_malloc(QSMP_ASYMMETRIC_VERIFY_KEY_SIZE);

			if (pkp->verkey != NULL)
			{
				qsc_memutils_clear(pkp->verkey, QSMP_ASYMMETRIC_VERIFY_KEY_SIZE);
			}
		}
	}

	return pkp;
}

void qsmp_connection_close(qsmp_connection_state* cns, qsmp_errors err, bool notify)
{
	QSMP_ASSERT(cns != NULL);

	if (cns != NULL)
	{
		if (qsc_socket_is_connected(&cns->target) == true)
		{
			if (notify == true)
			{
				if (err == qsmp_error_none)
				{
					qsmp_network_packet resp = { 0 };
					uint8_t spct[QSMP_HEADER_SIZE] = { 0 };

					/* send a disconnect message */
					resp.pmessage = spct + QSMP_HEADER_SIZE;
					resp.flag = qsmp_flag_connection_terminate;
					resp.sequence = QSMP_SEQUENCE_TERMINATOR;
					resp.msglen = 0;
					resp.pmessage = NULL;

					qsmp_packet_header_serialize(&resp, spct);
					qsc_socket_send(&cns->target, spct, sizeof(spct), qsc_socket_send_flag_none);
				}
				else
				{
					/* send an error message */
					qsmp_network_packet resp = { 0 };

					uint8_t perr[QSMP_ERROR_MESSAGE_SIZE] = { 0 };
					uint8_t* spct;
					size_t mlen;
					qsmp_errors qerr;

					if (cns->mode == qsmp_mode_simplex)
					{
						mlen = QSMP_HEADER_SIZE + QSMP_FLAG_SIZE + QSMP_SIMPLEX_MACTAG_SIZE;
						
					}
					else
					{
						mlen = QSMP_HEADER_SIZE + QSMP_FLAG_SIZE + QSMP_DUPLEX_MACTAG_SIZE;
					}

					spct = (uint8_t*)qsc_memutils_malloc(mlen);

					if (spct != NULL)
					{
						qsc_memutils_clear(spct, mlen);

						/* send a disconnect message */
						resp.pmessage = spct + QSMP_HEADER_SIZE;
						resp.flag = qsmp_flag_connection_terminate;
						resp.sequence = QSMP_SEQUENCE_TERMINATOR;
						resp.msglen = QSMP_ERROR_MESSAGE_SIZE;
						resp.pmessage = spct + QSMP_HEADER_SIZE;
						perr[0] = err;

						qerr = qsmp_packet_encrypt(cns, &resp, perr, QSMP_ERROR_MESSAGE_SIZE);

						if (qerr == qsmp_error_none)
						{
							qsmp_packet_header_serialize(&resp, spct);
							qsc_socket_send(&cns->target, spct, sizeof(spct), qsc_socket_send_flag_none);
						}

						qsc_memutils_alloc_free(spct);
					}
				}
			}

			/* close the socket */
			qsc_socket_close_socket(&cns->target);
		}
	}
}

void qsmp_connection_state_dispose(qsmp_connection_state* cns)
{
	QSMP_ASSERT(cns != NULL);

	if (cns != NULL)
	{
		qsc_rcs_dispose(&cns->rxcpr);
		qsc_rcs_dispose(&cns->txcpr);
		qsc_memutils_clear((uint8_t*)&cns->target, sizeof(qsc_socket));
		qsc_memutils_clear(&cns->rtcs, QSMP_DUPLEX_SYMMETRIC_KEY_SIZE);
		cns->rxseq = 0;
		cns->txseq = 0;
		cns->cid = 0;
		cns->exflag = qsmp_flag_none;
		cns->receiver = false;
		cns->mode = qsmp_mode_simplex;
	}
}

const char* qsmp_error_to_string(qsmp_errors error)
{
	const char* dsc;

	dsc = NULL;

	if ((int)error < QSMP_ERROR_STRING_DEPTH && (int)error >= 0)
	{
		dsc = QSMP_ERROR_STRINGS[(size_t)error];
	}

	return dsc;
}

void qsmp_header_create(qsmp_network_packet* packetout, qsmp_flags flag, uint64_t sequence, uint32_t msglen)
{
	packetout->flag = flag;
	packetout->sequence = sequence;
	packetout->msglen = msglen;
	/* set the packet creation time */
	qsmp_packet_set_utc_time(packetout);
}

qsmp_errors qsmp_header_validate(qsmp_connection_state* cns, const qsmp_network_packet* packetin, qsmp_flags kexflag, qsmp_flags pktflag, uint64_t sequence, uint32_t msglen)
{
	qsmp_errors merr;

	if (packetin->flag == qsmp_flag_error_condition)
	{
		merr = (qsmp_errors)packetin->pmessage[0];
	}
	else
	{
		if (qsmp_packet_time_valid(packetin) == true)
		{
			if (packetin->msglen == msglen)
			{
				if (packetin->sequence == sequence)
				{
					if (packetin->flag == pktflag)
					{
						if (cns->exflag == kexflag)
						{
							cns->rxseq += 1;
							merr = qsmp_error_none;
						}
						else
						{
							merr = qsmp_error_invalid_request;
						}
					}
					else
					{
						merr = qsmp_error_invalid_request;
					}
				}
				else
				{
					merr = qsmp_error_packet_unsequenced;
				}
			}
			else
			{
				merr = qsmp_error_receive_failure;
			}
		}
		else
		{
			merr = qsmp_error_message_time_invalid;
		}
	}

	return merr;
}

void qsmp_generate_keypair(qsmp_client_verification_key* pubkey, qsmp_server_signature_key* prikey, const uint8_t keyid[QSMP_KEYID_SIZE])
{
	QSMP_ASSERT(prikey != NULL);
	QSMP_ASSERT(pubkey != NULL);

	if (prikey != NULL && pubkey != NULL)
	{
		/* add the timestamp plus duration to the key */
		prikey->expiration = qsc_timestamp_datetime_utc() + QSMP_PUBKEY_DURATION_SECONDS;

		/* set the configuration string and key-identity strings */
		qsc_memutils_copy(prikey->config, QSMP_CONFIG_STRING, QSMP_CONFIG_SIZE);
		qsc_memutils_copy(prikey->keyid, keyid, QSMP_KEYID_SIZE);

		/* generate the signature key-pair */
		qsmp_signature_generate_keypair(prikey->verkey, prikey->sigkey, qsc_acp_generate);

		/* copy the key expiration, config, key-id, and the signatures verification key, to the public key structure */
		pubkey->expiration = prikey->expiration;
		qsc_memutils_copy(pubkey->config, prikey->config, QSMP_CONFIG_SIZE);
		qsc_memutils_copy(pubkey->keyid, prikey->keyid, QSMP_KEYID_SIZE);
		qsc_memutils_copy(pubkey->verkey, prikey->verkey, QSMP_ASYMMETRIC_VERIFY_KEY_SIZE);
	}
}

const char* qsmp_get_error_description(qsmp_messages message)
{
	const char* dsc;

	dsc = NULL;

	if ((int)message < QSMP_MESSAGE_STRING_DEPTH && (int)message >= 0)
	{
		dsc = QSMP_MESSAGE_STRINGS[(size_t)message];

	}

	return dsc;
}

void qsmp_log_error(qsmp_messages emsg, qsc_socket_exceptions err, const char* msg)
{
	QSMP_ASSERT(msg != NULL);

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
	QSMP_ASSERT(msg != NULL);

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

void qsmp_packet_clear(qsmp_network_packet* packet)
{
	if (packet->msglen != 0)
	{
		qsc_memutils_clear(packet->pmessage, packet->msglen);
	}

	packet->flag = (uint8_t)qsmp_flag_none;
	packet->msglen = 0;
	packet->sequence = 0;
	packet->utctime = 0;
}

qsmp_errors qsmp_packet_decrypt(qsmp_connection_state* cns, uint8_t* message, size_t* msglen, const qsmp_network_packet* packetin)
{
	QSMP_ASSERT(cns != NULL);
	QSMP_ASSERT(packetin != NULL);
	QSMP_ASSERT(message != NULL);
	QSMP_ASSERT(msglen != NULL);

	uint8_t hdr[QSMP_HEADER_SIZE] = { 0 };
	qsmp_errors qerr;

	qerr = qsmp_error_invalid_input;
	*msglen = 0;

	if (cns != NULL && message != NULL && msglen != NULL && packetin != NULL)
	{
		cns->rxseq += 1;

		if (packetin->sequence == cns->rxseq)
		{
			if (cns->exflag == qsmp_flag_session_established)
			{
				if (qsmp_packet_time_valid(packetin) == true)
				{
					const uint32_t MACLEN = (cns->txcpr.ctype == RCS256) ? QSMP_SIMPLEX_MACTAG_SIZE : QSMP_DUPLEX_MACTAG_SIZE;

					/* serialize the header and add it to the ciphers associated data */
					qsmp_packet_header_serialize(packetin, hdr);

					qsc_rcs_set_associated(&cns->rxcpr, hdr, QSMP_HEADER_SIZE);
					*msglen = (size_t)packetin->msglen - MACLEN;

					/* authenticate then decrypt the data */
					if (qsc_rcs_transform(&cns->rxcpr, message, packetin->pmessage, *msglen) == true)
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
					qerr = qsmp_error_message_time_invalid;
				}
			}
			else
			{
				qerr = qsmp_error_channel_down;
			}
		}
		else
		{
			qerr = qsmp_error_packet_unsequenced;
		}
	}

	return qerr;
}

qsmp_errors qsmp_packet_encrypt(qsmp_connection_state* cns, qsmp_network_packet* packetout, const uint8_t* message, size_t msglen)
{
	QSMP_ASSERT(cns != NULL);
	QSMP_ASSERT(message != NULL);
	QSMP_ASSERT(packetout != NULL);

	qsmp_errors qerr;

	qerr = qsmp_error_invalid_input;

	if (cns != NULL && message != NULL && packetout != NULL)
	{
		if (cns->exflag == qsmp_flag_session_established && msglen != 0)
		{
			uint8_t hdr[QSMP_HEADER_SIZE] = { 0 };
			const uint32_t MACLEN = (cns->txcpr.ctype == RCS256) ? QSMP_SIMPLEX_MACTAG_SIZE : QSMP_DUPLEX_MACTAG_SIZE;

			/* assemble the encryption packet */
			cns->txseq += 1;
			qsmp_header_create(packetout, qsmp_flag_encrypted_message, cns->txseq, (uint32_t)msglen + MACLEN);

			/* serialize the header and add it to the ciphers associated data */
			qsmp_packet_header_serialize(packetout, hdr);
			qsc_rcs_set_associated(&cns->txcpr, hdr, QSMP_HEADER_SIZE);
			/* encrypt the message */
			qsc_rcs_transform(&cns->txcpr, packetout->pmessage, message, msglen);

			qerr = qsmp_error_none;
		}
		else
		{
			qerr = qsmp_error_channel_down;
		}
	}

	return qerr;
}

void qsmp_packet_error_message(qsmp_network_packet* packet, qsmp_errors error)
{
	QSMP_ASSERT(packet != NULL);

	if (packet != NULL)
	{
		packet->flag = qsmp_flag_error_condition;
		packet->msglen = QSMP_ERROR_MESSAGE_SIZE;
		packet->sequence = QSMP_ERROR_SEQUENCE;
		packet->pmessage[0] = (uint8_t)error;
		qsmp_packet_set_utc_time(packet);
	}
}

void qsmp_packet_header_deserialize(const uint8_t* header, qsmp_network_packet* packet)
{
	QSMP_ASSERT(header != NULL);
	QSMP_ASSERT(packet != NULL);

	if (header != NULL && packet != NULL)
	{
		size_t pos;

		packet->flag = header[0];
		pos = QSMP_FLAG_SIZE;
		packet->msglen = qsc_intutils_le8to32(header + pos);
		pos += QSMP_MSGLEN_SIZE;
		packet->sequence = qsc_intutils_le8to64(header + pos);
		pos += QSMP_SEQUENCE_SIZE;
		packet->utctime = qsc_intutils_le8to64(header + pos);
	}
}

void qsmp_packet_header_serialize(const qsmp_network_packet* packet, uint8_t* header)
{
	QSMP_ASSERT(header != NULL);
	QSMP_ASSERT(packet != NULL);

	if (header != NULL && packet != NULL)
	{
		size_t pos;

		header[0] = packet->flag;
		pos = QSMP_FLAG_SIZE;
		qsc_intutils_le32to8(header + pos, packet->msglen);
		pos += QSMP_MSGLEN_SIZE;
		qsc_intutils_le64to8(header + pos, packet->sequence);
		pos += QSMP_SEQUENCE_SIZE;
		qsc_intutils_le64to8(header + pos, packet->utctime);
	}
}

void qsmp_packet_set_utc_time(qsmp_network_packet* packet)
{
	packet->utctime = qsc_timestamp_datetime_utc();
}

bool qsmp_packet_time_valid(const qsmp_network_packet* packet)
{
	uint64_t ltime;

	ltime = qsc_timestamp_datetime_utc();

	return (ltime >= packet->utctime - QSMP_PACKET_TIME_THRESHOLD && ltime <= packet->utctime + QSMP_PACKET_TIME_THRESHOLD);
}

bool qsmp_public_key_compare(const qsmp_client_verification_key* a, const qsmp_client_verification_key* b)
{
	bool res;

	res = false;

	if (a->expiration == b->expiration)
	{
		if (qsc_memutils_are_equal(a->config, b->config, QSMP_CONFIG_SIZE) == true)
		{
			if (qsc_memutils_are_equal(a->keyid, b->keyid, QSMP_KEYID_SIZE) == true)
			{
				res = qsc_memutils_are_equal(a->verkey, b->verkey, QSMP_ASYMMETRIC_VERIFY_KEY_SIZE);
			}
		}
	}

	return res;
}

bool qsmp_public_key_decode(qsmp_client_verification_key* pubk, const char* enck, size_t enclen)
{
	QSMP_ASSERT(pubk != NULL);

	char dtm[QSC_TIMESTAMP_STRING_SIZE] = { 0 };
	char* pvk;
	size_t elen;
	size_t spos;
	size_t slen;
	bool res;

	res = false;

	if (pubk != NULL)
	{
		spos = sizeof(QSMP_PUBKEY_HEADER) - 1;
		++spos;

		slen = sizeof(QSMP_PUBKEY_VERSION) - 1;
		spos += slen;
		++spos;

		spos += sizeof(QSMP_PUBKEY_CONFIG_PREFIX) - 1;
		slen = qsc_stringutils_find_char(enck + spos, '\n');
		qsc_memutils_copy(pubk->config, enck + spos, slen);
		spos += slen;
		++spos;

		spos += sizeof(QSMP_PUBKEY_KEYID_PREFIX) - 1;
		qsc_intutils_hex_to_bin(enck + spos, pubk->keyid, QSMP_KEYID_SIZE);
		spos += (QSMP_KEYID_SIZE * 2);
		++spos;

		spos += sizeof(QSMP_PUBKEY_EXPIRATION_PREFIX) - 1;
		slen = QSC_TIMESTAMP_STRING_SIZE - 1;
		qsc_memutils_copy(dtm, enck + spos, slen);
		spos += QSC_TIMESTAMP_STRING_SIZE;
		pubk->expiration = qsc_timestamp_datetime_to_seconds(dtm);

		elen = qsc_encoding_base64_encoded_size(QSMP_ASYMMETRIC_VERIFY_KEY_SIZE);
		pvk = qsc_memutils_malloc(elen);

		if (pvk != NULL)
		{
			qsc_memutils_clear(pvk, elen);
			elen = qsc_stringutils_remove_line_breaks(pvk, elen, enck + spos, enclen - spos);
			res = qsc_encoding_base64_decode(pubk->verkey, QSMP_ASYMMETRIC_VERIFY_KEY_SIZE, pvk, elen);
			qsc_memutils_alloc_free(pvk);
		}
	}

	return res;
}

size_t qsmp_public_key_encode(char* enck, size_t enclen, const qsmp_client_verification_key* pubk)
{
	QSMP_ASSERT(pubk != NULL);

	char dtm[QSMP_TIMESTAMP_STRING_SIZE] = { 0 };
	char hexid[(QSMP_KEYID_SIZE * 2)] = { 0 };
	char* prvs;
	size_t elen;
	size_t slen;
	size_t spos;

	spos = 0;

	if (pubk != NULL)
	{
		slen = sizeof(QSMP_PUBKEY_HEADER) - 1;
		qsc_memutils_copy(enck, QSMP_PUBKEY_HEADER, slen);
		spos = slen;
		enck[spos] = '\n';
		++spos;

		slen = sizeof(QSMP_PUBKEY_VERSION) - 1;
		qsc_memutils_copy(enck + spos, QSMP_PUBKEY_VERSION, slen);
		spos += slen;
		enck[spos] = '\n';
		++spos;

		slen = sizeof(QSMP_PUBKEY_CONFIG_PREFIX) - 1;
		qsc_memutils_copy(enck + spos, QSMP_PUBKEY_CONFIG_PREFIX, slen);
		spos += slen;
		slen = qsc_stringutils_string_size(QSMP_CONFIG_STRING);
		qsc_memutils_copy(enck + spos, QSMP_CONFIG_STRING, slen);
		spos += slen;
		enck[spos] = '\n';
		++spos;

		slen = sizeof(QSMP_PUBKEY_KEYID_PREFIX) - 1;
		qsc_memutils_copy(enck + spos, QSMP_PUBKEY_KEYID_PREFIX, slen);
		spos += slen;
		qsc_intutils_bin_to_hex(pubk->keyid, hexid, QSMP_KEYID_SIZE);
		slen = sizeof(hexid);
		qsc_memutils_copy(enck + spos, hexid, slen);
		spos += slen;
		enck[spos] = '\n';
		++spos;

		slen = sizeof(QSMP_PUBKEY_EXPIRATION_PREFIX) - 1;
		qsc_memutils_copy(enck + spos, QSMP_PUBKEY_EXPIRATION_PREFIX, slen);
		spos += slen;
		qsc_timestamp_seconds_to_datetime(pubk->expiration, dtm);
		slen = QSC_TIMESTAMP_STRING_SIZE - 1;
		qsc_memutils_copy(enck + spos, dtm, slen);
		spos += slen;
		enck[spos] = '\n';
		++spos;

		slen = QSMP_ASYMMETRIC_VERIFY_KEY_SIZE;
		elen = qsc_encoding_base64_encoded_size(slen);
		prvs = qsc_memutils_malloc(elen);

		if (prvs != NULL)
		{
			qsc_memutils_clear(prvs, elen);
			qsc_encoding_base64_encode(prvs, elen, pubk->verkey, slen);
			spos += qsc_stringutils_add_line_breaks(enck + spos, enclen - spos, QSMP_PUBKEY_LINE_LENGTH, prvs, elen);
			qsc_memutils_alloc_free(prvs);
		}

		slen = sizeof(QSMP_PUBKEY_FOOTER) - 1;
		qsc_memutils_copy((enck + spos), QSMP_PUBKEY_FOOTER, slen);
		spos += slen;
		enck[spos] = '\n';
	}

	return spos;
}

size_t qsmp_public_key_encoding_size(void)
{
	size_t elen;
	size_t klen;

	elen = sizeof(QSMP_PUBKEY_HEADER) - 1;
	++elen;
	elen += sizeof(QSMP_PUBKEY_VERSION) - 1;
	++elen;
	elen += sizeof(QSMP_PUBKEY_CONFIG_PREFIX) - 1;
	elen += sizeof(QSMP_CONFIG_STRING) - 1;
	++elen;
	elen += sizeof(QSMP_PUBKEY_KEYID_PREFIX) - 1;
	elen += (QSMP_KEYID_SIZE * 2);
	++elen;
	elen += sizeof(QSMP_PUBKEY_EXPIRATION_PREFIX) - 1;
	elen += QSC_TIMESTAMP_STRING_SIZE - 1;
	++elen;
	klen = qsc_encoding_base64_encoded_size(QSMP_ASYMMETRIC_VERIFY_KEY_SIZE);
	elen += klen + (klen / QSMP_PUBKEY_LINE_LENGTH) + 1;
	++elen;
	elen += sizeof(QSMP_PUBKEY_FOOTER) - 1;
	++elen;

	return elen;
}

void qsmp_signature_key_deserialize(qsmp_server_signature_key* kset, const uint8_t serk[QSMP_SIGKEY_ENCODED_SIZE])
{
	QSMP_ASSERT(kset != NULL);

	size_t pos;

	qsc_memutils_copy(kset->config, serk, QSMP_CONFIG_SIZE);
	pos = QSMP_CONFIG_SIZE;
	kset->expiration = qsc_intutils_le8to64((serk + pos));
	pos += QSMP_TIMESTAMP_SIZE;
	qsc_memutils_copy(kset->keyid, (serk + pos), QSMP_KEYID_SIZE);
	pos += QSMP_KEYID_SIZE;
	qsc_memutils_copy(kset->sigkey, (serk + pos), QSMP_ASYMMETRIC_SIGNING_KEY_SIZE);
	pos += QSMP_ASYMMETRIC_SIGNING_KEY_SIZE;
	qsc_memutils_copy(kset->verkey, (serk + pos), QSMP_ASYMMETRIC_VERIFY_KEY_SIZE);
}

void qsmp_signature_key_serialize(uint8_t serk[QSMP_SIGKEY_ENCODED_SIZE], const qsmp_server_signature_key* kset)
{
	QSMP_ASSERT(kset != NULL);

	size_t pos;

	qsc_memutils_copy(serk, kset->config, QSMP_CONFIG_SIZE);
	pos = QSMP_CONFIG_SIZE;
	qsc_intutils_le64to8((serk + pos), kset->expiration);
	pos += QSMP_TIMESTAMP_SIZE;
	qsc_memutils_copy((serk + pos), kset->keyid, QSMP_KEYID_SIZE);
	pos += QSMP_KEYID_SIZE;
	qsc_memutils_copy((serk + pos), kset->sigkey, QSMP_ASYMMETRIC_SIGNING_KEY_SIZE);
	pos += QSMP_ASYMMETRIC_SIGNING_KEY_SIZE;
	qsc_memutils_copy((serk + pos), kset->verkey, QSMP_ASYMMETRIC_VERIFY_KEY_SIZE);
}

void qsmp_stream_to_packet(const uint8_t* pstream, qsmp_network_packet* packet)
{
	QSMP_ASSERT(packet != NULL);
	QSMP_ASSERT(pstream != NULL);

	size_t pos;

	if (packet != NULL && pstream != NULL)
	{
		packet->flag = pstream[0];
		pos = QSMP_FLAG_SIZE;
		packet->msglen = qsc_intutils_le8to32(pstream + pos);
		pos += QSMP_MSGLEN_SIZE;
		packet->sequence = qsc_intutils_le8to64(pstream + pos);
		pos += QSMP_SEQUENCE_SIZE;
		packet->utctime = qsc_intutils_le8to64(pstream + pos);
		pos += QSMP_TIMESTAMP_SIZE;
		qsc_memutils_copy(packet->pmessage, pstream + pos, packet->msglen);
	}
}

size_t qsmp_packet_to_stream(const qsmp_network_packet* packet, uint8_t* pstream)
{
	QSMP_ASSERT(packet != NULL);
	QSMP_ASSERT(pstream != NULL);

	size_t pos;
	size_t res;

	res = 0;

	if (packet != NULL && pstream != NULL)
	{
		pstream[0] = packet->flag;
		pos = QSMP_FLAG_SIZE;
		qsc_intutils_le32to8(pstream + pos, packet->msglen);
		pos += QSMP_MSGLEN_SIZE;
		qsc_intutils_le64to8(pstream + pos, packet->sequence);
		pos += QSMP_SEQUENCE_SIZE;
		qsc_intutils_le64to8(pstream + pos, packet->utctime);
		pos += QSMP_TIMESTAMP_SIZE;
		qsc_memutils_copy(pstream + pos, packet->pmessage, packet->msglen);
		res = (size_t)QSMP_HEADER_SIZE + packet->msglen;
	}

	return res;
}

#if defined (QSMP_DEBUG_MODE)
bool qsmp_certificate_encoding_test(void)
{
	qsmp_client_verification_key pcpy = { 0 };
	qsmp_client_verification_key pkey = { 0 };
	qsmp_server_signature_key skey = { 0 };
	uint8_t keyid[QSMP_KEYID_SIZE] = { 0 };
	char* enck;
	size_t elen;
	bool res;

	res = false;
	qsc_acp_generate(keyid, sizeof(keyid));
	qsmp_generate_keypair(&pkey, &skey, keyid);

	elen = qsmp_public_key_encoding_size();
	enck = qsc_memutils_malloc(elen);

	if (enck != NULL)
	{
		qsc_memutils_clear(enck, elen);

		qsmp_public_key_encode(enck, elen, &pkey);
		qsmp_public_key_decode(&pcpy, enck, elen);

		res = qsmp_public_key_compare(&pkey, &pcpy);
		qsc_memutils_alloc_free(enck);
	}

	return res;
}
#endif

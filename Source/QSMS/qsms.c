#include "qsms.h"
#include "logger.h"
#include "async.h"
#include "acp.h"
#include "encoding.h"
#include "intutils.h"
#include "memutils.h"
#include "stringutils.h"
#include "timestamp.h"

#if defined(QSMS_CONFIG_DILITHIUM_KYBER)
#	if defined(QSC_DILITHIUM_S1P44) && defined(QSC_KYBER_S1K2P512)
const char QSMS_CONFIG_STRING[QSMS_CONFIG_SIZE] = "dilithium-s1_kyber-s1_sha3_rcs";
#	elif defined(QSC_DILITHIUM_S3P65) && defined(QSC_KYBER_S3K3P768)
const char QSMS_CONFIG_STRING[QSMS_CONFIG_SIZE] = "dilithium-s3_kyber-s3_sha3_rcs";
#	elif defined(QSC_DILITHIUM_S5P87) && defined(QSC_KYBER_S5K4P1024)
const char QSMS_CONFIG_STRING[QSMS_CONFIG_SIZE] = "dilithium-s5_kyber-s5_sha3_rcs";
#	elif defined(QSC_DILITHIUM_S5P87) && defined(QSC_KYBER_S6K5P1280)
const char QSMS_CONFIG_STRING[QSMS_CONFIG_SIZE] = "dilithium-s5_kyber-s6_sha3_rcs";
#	else
#		error Invalid parameter set!
#	endif
#elif defined(QSMS_CONFIG_DILITHIUM_MCELIECE)
#	if defined(QSC_DILITHIUM_S1P44) && defined(QSC_MCELIECE_S1N3488T64)
const char QSMS_CONFIG_STRING[QSMS_CONFIG_SIZE] = "dilithium-s1_mceliece-s1_sha3_rcs";
#	elif defined(QSC_DILITHIUM_S3P65) && defined(QSC_MCELIECE_S3N4608T96)
const char QSMS_CONFIG_STRING[QSMS_CONFIG_SIZE] = "dilithium-s3_mceliece-s3_sha3_rcs";
#	elif defined(QSC_DILITHIUM_S5P87) && defined(QSC_MCELIECE_S5N6688T128)
const char QSMS_CONFIG_STRING[QSMS_CONFIG_SIZE] = "dilithium-s5_mceliece-s5_sha3_rcs";
#	elif defined(QSC_DILITHIUM_S5P87) && defined(QSC_MCELIECE_S6N6960T119)
const char QSMS_CONFIG_STRING[QSMS_CONFIG_SIZE] = "dilithium-s5_mceliece-s6_sha3_rcs";
#	elif defined(QSC_DILITHIUM_S5P87) && defined(QSC_MCELIECE_S7N8192T128)
const char QSMS_CONFIG_STRING[QSMS_CONFIG_SIZE] = "dilithium-s5_mceliece-s7_sha3_rcs";
#	else
#		error Invalid parameter set!
#	endif
#elif defined(QSMS_CONFIG_SPHINCS_MCELIECE)
#	if defined(QSC_SPHINCSPLUS_S1S128SHAKERF) && defined(QSC_MCELIECE_S1N3488T64)
const char QSMS_CONFIG_STRING[QSMS_CONFIG_SIZE] = "sphincs-s1f_mceliece-s1_sha3_rcs";
#	elif defined(QSC_SPHINCSPLUS_S1S128SHAKERS) && defined(QSC_MCELIECE_S1N3488T64)
const char QSMS_CONFIG_STRING[QSMS_CONFIG_SIZE] = "sphincs-s1s_mceliece-s1_sha3_rcs";
#	elif defined(QSC_SPHINCSPLUS_S3S192SHAKERF) && defined(QSC_MCELIECE_S3N4608T96)
const char QSMS_CONFIG_STRING[QSMS_CONFIG_SIZE] = "sphincs-3f_mceliece-s3_sha3_rcs";
#	elif defined(QSC_SPHINCSPLUS_S3S192SHAKERS) && defined(QSC_MCELIECE_S3N4608T96)
const char QSMS_CONFIG_STRING[QSMS_CONFIG_SIZE] = "sphincs-3s_mceliece-s3_sha3_rcs";
#	elif defined(QSC_SPHINCSPLUS_S5S256SHAKERF) && defined(QSC_MCELIECE_S5N6688T128)
const char QSMS_CONFIG_STRING[QSMS_CONFIG_SIZE] = "sphincs-s5f_mceliece-s5_sha3_rcs";
#	elif defined(QSC_SPHINCSPLUS_S5S256SHAKERS) && defined(QSC_MCELIECE_S5N6688T128)
const char QSMS_CONFIG_STRING[QSMS_CONFIG_SIZE] = "sphincs-s5s_mceliece-s5_sha3_rcs";
#	elif defined(QSC_SPHINCSPLUS_S5S256SHAKERF) && defined(QSC_MCELIECE_S6N6960T119)
const char QSMS_CONFIG_STRING[QSMS_CONFIG_SIZE] = "sphincs-s5f_mceliece-s6_sha3_rcs";
#	elif defined(QSC_SPHINCSPLUS_S5S256SHAKERS) && defined(QSC_MCELIECE_S6N6960T119)
const char QSMS_CONFIG_STRING[QSMS_CONFIG_SIZE] = "sphincs-s5s_mceliece-s6_sha3_rcs";
#	elif defined(QSC_SPHINCSPLUS_S5S256SHAKERF) && defined(QSC_MCELIECE_S7N8192T128)
const char QSMS_CONFIG_STRING[QSMS_CONFIG_SIZE] = "sphincs-s5f_mceliece-s7_sha3_rcs";
#	elif defined(QSC_SPHINCSPLUS_S5S256SHAKERS) && defined(QSC_MCELIECE_S7N8192T128)
const char QSMS_CONFIG_STRING[QSMS_CONFIG_SIZE] = "sphincs-s5s_mceliece-s7_sha3_rcs";
#	else
#		error Invalid parameter set!
#	endif
#endif

const char QSMS_ERROR_STRINGS[QSMS_ERROR_STRING_DEPTH][QSMS_ERROR_STRING_WIDTH] =
{
	"No error was detected",
	"The socket accept function returned an error",
	"The symmetric cipher had an authentication failure",
	"The communications channel has failed",
	"The device could not make a connection to the remote host",
	"The transmission failed at the KEX connection phase",
	"The asymmetric cipher failed to decapsulate the shared secret",
	"The decryption authentication has failed",
	"The transmission failed at the KEX establish phase",
	"The transmission failed at the KEX exchange phase",
	"The public - key hash is invalid",
	"The server has run out of socket connections",
	"The expected input was invalid",
	"The decryption authentication has failed",
	"The QSMS public key has expired ",
	"The key identity is unrecognized",
	"The ratchet operation has failed",
	"The listener function failed to initialize",
	"The server has run out of memory",
	"The packet has valid time expired",
	"The packet was received out of sequence",
	"The random generator has failed",
	"The receiver failed at the network layer",
	"The transmitter failed at the network layer",
	"The protocol string was not recognized",
	"The expected data could not be verified",
	"The remote host sent an error or disconnect message",
};

const char QSMS_MESSAGE_STRINGS[QSMS_MESSAGE_STRING_DEPTH][QSMS_MESSAGE_STRING_WIDTH] =
{
	"The operation completed succesfully.",
	"The socket server accept function failed.",
	"The listener socket listener could not connect.",
	"The listener socket could not bind to the address.",
	"The listener socket could not be created.",
	"The server is connected to remote host: ",
	"The socket receive function failed.",
	"The server had a memory allocation failure.",
	"The key exchange has experienced a failure.",
	"The server has disconnected from the remote host: ",
	"The server has disconnected the client due to an error",
	"The server has had a socket level error: ",
	"The server has reached the maximum number of connections",
	"The server listener socket has failed.",
	"The server has run out of socket connections",
	"The message decryption has failed",
	"The keepalive function has failed",
	"The keepalive period has been exceeded",
	"The connection failed or was interrupted",
	"The function received an invalid request",
	"The host received a symmetric ratchet request"
};

void qsms_connection_close(qsms_connection_state* cns, qsms_errors err, bool notify)
{
	QSMS_ASSERT(cns != NULL);

	if (cns != NULL)
	{
		if (qsc_socket_is_connected(&cns->target) == true)
		{
			if (notify == true)
			{
				qsms_network_packet resp = { 0U };

				/* build a disconnect message */
				cns->txseq += 1U;
				resp.flag = qsms_flag_error_condition;
				resp.sequence = cns->txseq;
				resp.msglen = QSMS_SIMPLEX_MACTAG_SIZE + 1U;
				
				qsms_packet_set_utc_time(&resp);

				/* tunnel gets encrypted message */
				if (cns->exflag == qsms_flag_session_established)
				{
					uint8_t spct[QSMS_HEADER_SIZE + QSMS_SIMPLEX_MACTAG_SIZE + 1U] = { 0U };
					uint8_t pmsg[1U] = { 0U };

					resp.pmessage = spct + QSMS_HEADER_SIZE;
					qsms_packet_header_serialize(&resp, spct);
					/* the error is the message */
					pmsg[0U] = (uint8_t)err;

					/* add the header to aad */
					qsc_rcs_set_associated(&cns->txcpr, spct, QSMS_HEADER_SIZE);
					/* encrypt the message */
					qsc_rcs_transform(&cns->txcpr, resp.pmessage, pmsg, sizeof(pmsg));
					/* send the message */
					qsc_socket_send(&cns->target, spct, sizeof(spct), qsc_socket_send_flag_none);
				}
				else
				{
					/* pre-established phase */
					uint8_t spct[QSMS_HEADER_SIZE + 1U] = { 0U };

					qsms_packet_header_serialize(&resp, spct);
					spct[QSMS_HEADER_SIZE] = (uint8_t)err;
					/* send the message */
					qsc_socket_send(&cns->target, spct, sizeof(spct), qsc_socket_send_flag_none);
				}
			}

			/* close the socket */
			qsc_socket_close_socket(&cns->target);
		}
	}
}

bool qsms_decrypt_error_message(qsms_errors* merr, qsms_connection_state* cns, const uint8_t* message)
{
	QSMS_ASSERT(merr != NULL);
	QSMS_ASSERT(cns != NULL);
	QSMS_ASSERT(message != NULL);

	qsms_network_packet pkt = { 0U };
	uint8_t dmsg[1U] = { 0U };
	const uint8_t* emsg;
	size_t mlen;
	qsms_errors err;
	bool res;

	mlen = 0U;
	res = false;
	err = qsms_error_invalid_input;

	if (cns->exflag == qsms_flag_session_established)
	{
		qsms_packet_header_deserialize(message, &pkt);
		emsg = message + QSMS_HEADER_SIZE;

		if (cns != NULL && message != NULL)
		{
			if (pkt.sequence == cns->rxseq + 1U)
			{
				/* anti-replay; verify the packet time */
				if (qsms_packet_time_valid(&pkt) == true)
				{
					if (pkt.msglen > QSMS_SIMPLEX_MACTAG_SIZE)
					{
						qsc_rcs_set_associated(&cns->rxcpr, message, QSMS_HEADER_SIZE);
						mlen = pkt.msglen - QSMS_SIMPLEX_MACTAG_SIZE;

						if (mlen == 1U)
						{
							/* authenticate then decrypt the data */
							if (qsc_rcs_transform(&cns->rxcpr, dmsg, emsg, mlen) == true)
							{
								cns->rxseq += 1;
								err = (qsms_errors)dmsg[0U];
								res = true;
							}
						}
					}
				}
			}
		}
	}

	*merr = err;

	return res;
}

void qsms_connection_state_dispose(qsms_connection_state* cns)
{
	QSMS_ASSERT(cns != NULL);

	if (cns != NULL)
	{
		qsc_rcs_dispose(&cns->rxcpr);
		qsc_rcs_dispose(&cns->txcpr);
		qsc_memutils_secure_erase((uint8_t*)&cns->target, sizeof(qsc_socket));
		qsc_memutils_secure_erase(&cns->rtcs, QSMS_SIMPLEX_SYMMETRIC_KEY_SIZE);
		cns->rxseq = 0U;
		cns->txseq = 0U;
		cns->cid = 0U;
		cns->exflag = qsms_flag_none;
		cns->receiver = false;
	}
}

const char* qsms_error_to_string(qsms_errors error)
{
	const char* dsc;

	dsc = NULL;

	if ((size_t)error < QSMS_ERROR_STRING_DEPTH && error >= 0)
	{
		dsc = QSMS_ERROR_STRINGS[(size_t)error];
	}

	return dsc;
}

void qsms_header_create(qsms_network_packet* packetout, qsms_flags flag, uint64_t sequence, uint32_t msglen)
{
	QSMS_ASSERT(packetout != NULL);

	if (packetout != NULL)
	{
		packetout->flag = flag;
		packetout->sequence = sequence;
		packetout->msglen = msglen;
		/* set the packet creation time */
		qsms_packet_set_utc_time(packetout);
	}
}

qsms_errors qsms_header_validate(qsms_connection_state* cns, const qsms_network_packet* packetin, qsms_flags kexflag, qsms_flags pktflag, uint64_t sequence, uint32_t msglen)
{
	QSMS_ASSERT(cns != NULL);
	QSMS_ASSERT(packetin != NULL);

	qsms_errors merr;

	merr = qsms_error_invalid_input;

	if (cns != NULL && packetin != NULL)
	{
		if (packetin->flag == qsms_flag_error_condition)
		{
			if (packetin->pmessage != NULL)
			{
				merr = (qsms_errors)packetin->pmessage[0U];
			}
			else
			{
				merr = qsms_error_invalid_request;
			}
		}
		else
		{
			if (qsms_packet_time_valid(packetin) == true)
			{
				if (packetin->msglen == msglen)
				{
					if (packetin->sequence == sequence)
					{
						if (packetin->flag == pktflag)
						{
							if (cns->exflag == kexflag)
							{
								cns->rxseq += 1U;
								merr = qsms_error_none;
							}
							else
							{
								merr = qsms_error_invalid_request;
							}
						}
						else
						{
							merr = qsms_error_invalid_request;
						}
					}
					else
					{
						merr = qsms_error_packet_unsequenced;
					}
				}
				else
				{
					merr = qsms_error_receive_failure;
				}
			}
			else
			{
				merr = qsms_error_message_time_invalid;
			}
		}
	}

	return merr;
}

void qsms_generate_keypair(qsms_client_verification_key* pubkey, qsms_server_signature_key* prikey, const uint8_t* keyid)
{
	QSMS_ASSERT(prikey != NULL);
	QSMS_ASSERT(pubkey != NULL);
	QSMS_ASSERT(keyid != NULL);

	if (prikey != NULL && pubkey != NULL && keyid != NULL)
	{
		/* add the timestamp plus duration to the key */
		prikey->expiration = qsc_timestamp_datetime_utc() + QSMS_PUBKEY_DURATION_SECONDS;

		/* set the configuration string and key-identity strings */
		qsc_memutils_copy(prikey->config, QSMS_CONFIG_STRING, QSMS_CONFIG_SIZE);
		qsc_memutils_copy(prikey->keyid, keyid, QSMS_KEYID_SIZE);

		/* generate the signature key-pair */
		qsms_signature_generate_keypair(prikey->verkey, prikey->sigkey, qsc_acp_generate);

		/* copy the key expiration, config, key-id, and the signatures verification key, to the public key structure */
		pubkey->expiration = prikey->expiration;
		qsc_memutils_copy(pubkey->config, prikey->config, QSMS_CONFIG_SIZE);
		qsc_memutils_copy(pubkey->keyid, prikey->keyid, QSMS_KEYID_SIZE);
		qsc_memutils_copy(pubkey->verkey, prikey->verkey, QSMS_ASYMMETRIC_VERIFY_KEY_SIZE);
	}
}

const char* qsms_get_error_description(qsms_messages emsg)
{
	const char* dsc;

	dsc = NULL;

	if ((size_t)emsg < QSMS_MESSAGE_STRING_DEPTH && emsg >= 0U)
	{
		dsc = QSMS_MESSAGE_STRINGS[(size_t)emsg];
	}

	return dsc;
}

void qsms_log_error(qsms_messages emsg, qsc_socket_exceptions err, const char* msg)
{
	QSMS_ASSERT(msg != NULL);

	char mtmp[QSMS_ERROR_STRING_WIDTH * 2] = { 0 };
	const char* perr;
	const char* phdr;
	const char* pmsg;

	pmsg = qsms_get_error_description(emsg);

	if (pmsg != NULL)
	{
		if (msg != NULL)
		{
			qsc_stringutils_copy_string(mtmp, sizeof(mtmp), pmsg);
			qsc_stringutils_concat_strings(mtmp, sizeof(mtmp), msg);
			qsms_logger_write(mtmp);
		}
		else
		{
			qsms_logger_write(pmsg);
		}
	}

	phdr = qsms_get_error_description(qsms_messages_socket_message);
	perr = qsc_socket_error_to_string(err);

	if (pmsg != NULL && perr != NULL)
	{
		qsc_stringutils_clear_string(mtmp);
		qsc_stringutils_copy_string(mtmp, sizeof(mtmp), phdr);
		qsc_stringutils_concat_strings(mtmp, sizeof(mtmp), perr);
		qsms_logger_write(mtmp);
	}
}

void qsms_log_message(qsms_messages emsg)
{
	const char* msg = qsms_get_error_description(emsg);

	if (msg != NULL)
	{
		qsms_logger_write(msg);
	}
}

void qsms_log_system_error(qsms_errors err)
{
	char mtmp[QSMS_ERROR_STRING_WIDTH * 2U] = { 0 };
	const char* perr;
	const char* pmsg;

	pmsg = qsms_error_to_string(qsms_messages_system_message);
	perr = qsms_error_to_string(err);

	qsc_stringutils_copy_string(mtmp, sizeof(mtmp), pmsg);
	qsc_stringutils_concat_strings(mtmp, sizeof(mtmp), ": ");
	qsc_stringutils_concat_strings(mtmp, sizeof(mtmp), perr);

	qsms_logger_write(mtmp);
}

void qsms_log_write(qsms_messages emsg, const char* msg)
{
	QSMS_ASSERT(msg != NULL);

	const char* pmsg = qsms_get_error_description(emsg);

	if (pmsg != NULL)
	{
		if (msg != NULL)
		{
			char mtmp[QSMS_ERROR_STRING_WIDTH + 1U] = { 0 };

			qsc_stringutils_copy_string(mtmp, sizeof(mtmp), pmsg);

			if ((qsc_stringutils_string_size(msg) + qsc_stringutils_string_size(mtmp)) < sizeof(mtmp))
			{
				qsc_stringutils_concat_strings(mtmp, sizeof(mtmp), msg);
				qsms_logger_write(mtmp);
			}
		}
		else
		{
			qsms_logger_write(pmsg);
		}
	}
}

void qsms_packet_clear(qsms_network_packet* packet)
{
	QSMS_ASSERT(packet != NULL);

	if (packet != NULL)
	{
		if (packet->msglen != 0U)
		{
			qsc_memutils_secure_erase(packet->pmessage, packet->msglen);
		}

		packet->flag = (uint8_t)qsms_flag_none;
		packet->msglen = 0U;
		packet->sequence = 0U;
		packet->utctime = 0U;
	}
}

qsms_errors qsms_packet_decrypt(qsms_connection_state* cns, uint8_t* message, size_t* msglen, const qsms_network_packet* packetin)
{
	QSMS_ASSERT(cns != NULL);
	QSMS_ASSERT(packetin != NULL);
	QSMS_ASSERT(message != NULL);
	QSMS_ASSERT(msglen != NULL);

	uint8_t hdr[QSMS_HEADER_SIZE] = { 0U };
	qsms_errors qerr;

	qerr = qsms_error_invalid_input;
	*msglen = 0U;

	if (cns != NULL && message != NULL && msglen != NULL && packetin != NULL)
	{
		if (packetin->sequence == cns->rxseq + 1U)
		{
			if (cns->exflag == qsms_flag_session_established)
			{
				if (qsms_packet_time_valid(packetin) == true)
				{
					if (packetin->msglen > QSMS_SIMPLEX_MACTAG_SIZE)
					{
						/* serialize the header and add it to the ciphers associated data */
						qsms_packet_header_serialize(packetin, hdr);

						qsc_rcs_set_associated(&cns->rxcpr, hdr, QSMS_HEADER_SIZE);
						*msglen = (size_t)packetin->msglen - QSMS_SIMPLEX_MACTAG_SIZE;

						/* authenticate then decrypt the data */
						if (qsc_rcs_transform(&cns->rxcpr, message, packetin->pmessage, *msglen) == true)
						{
							cns->rxseq += 1U;
							qerr = qsms_error_none;
						}
						else
						{
							*msglen = 0U;
							qerr = qsms_error_authentication_failure;
						}
					}
					else
					{
						*msglen = 0U;
						qerr = qsms_error_receive_failure;
					}
				}
				else
				{
					qerr = qsms_error_message_time_invalid;
				}
			}
			else
			{
				qerr = qsms_error_channel_down;
			}
		}
		else
		{
			qerr = qsms_error_packet_unsequenced;
		}
	}

	return qerr;
}

qsms_errors qsms_packet_encrypt(qsms_connection_state* cns, qsms_network_packet* packetout, const uint8_t* message, size_t msglen)
{
	QSMS_ASSERT(cns != NULL);
	QSMS_ASSERT(message != NULL);
	QSMS_ASSERT(packetout != NULL);

	qsms_errors qerr;

	qerr = qsms_error_invalid_input;

	if (cns != NULL && message != NULL && packetout != NULL)
	{
		if (cns->exflag == qsms_flag_session_established && msglen != 0)
		{
			uint8_t hdr[QSMS_HEADER_SIZE] = { 0U };

			/* assemble the encryption packet */
			cns->txseq += 1U;
			qsms_header_create(packetout, qsms_flag_encrypted_message, cns->txseq, (uint32_t)msglen + QSMS_SIMPLEX_MACTAG_SIZE);

			/* serialize the header and add it to the ciphers associated data */
			qsms_packet_header_serialize(packetout, hdr);
			qsc_rcs_set_associated(&cns->txcpr, hdr, QSMS_HEADER_SIZE);
			/* encrypt the message */
			(void)qsc_rcs_transform(&cns->txcpr, packetout->pmessage, message, msglen);

			qerr = qsms_error_none;
		}
		else
		{
			qerr = qsms_error_channel_down;
		}
	}

	return qerr;
}

void qsms_packet_error_message(qsms_network_packet* packet, qsms_errors error)
{
	QSMS_ASSERT(packet != NULL);

	if (packet != NULL)
	{
		packet->flag = qsms_flag_error_condition;
		packet->msglen = QSMS_ERROR_MESSAGE_SIZE;
		packet->sequence = QSMS_ERROR_SEQUENCE;
		packet->pmessage[0U] = (uint8_t)error;
		qsms_packet_set_utc_time(packet);
	}
}

void qsms_packet_header_deserialize(const uint8_t* header, qsms_network_packet* packet)
{
	QSMS_ASSERT(header != NULL);
	QSMS_ASSERT(packet != NULL);

	if (header != NULL && packet != NULL)
	{
		size_t pos;

		packet->flag = header[0U];
		pos = QSMS_FLAG_SIZE;
		packet->msglen = qsc_intutils_le8to32(header + pos);
		pos += QSMS_MSGLEN_SIZE;
		packet->sequence = qsc_intutils_le8to64(header + pos);
		pos += QSMS_SEQUENCE_SIZE;
		packet->utctime = qsc_intutils_le8to64(header + pos);
	}
}

void qsms_packet_header_serialize(const qsms_network_packet* packet, uint8_t* header)
{
	QSMS_ASSERT(header != NULL);
	QSMS_ASSERT(packet != NULL);

	if (header != NULL && packet != NULL)
	{
		size_t pos;

		header[0U] = packet->flag;
		pos = QSMS_FLAG_SIZE;
		qsc_intutils_le32to8(header + pos, packet->msglen);
		pos += QSMS_MSGLEN_SIZE;
		qsc_intutils_le64to8(header + pos, packet->sequence);
		pos += QSMS_SEQUENCE_SIZE;
		qsc_intutils_le64to8(header + pos, packet->utctime);
	}
}

void qsms_packet_set_utc_time(qsms_network_packet* packet)
{
	QSMS_ASSERT(packet != NULL);

	if (packet != NULL)
	{
		packet->utctime = qsc_timestamp_datetime_utc();
	}
}

bool qsms_packet_time_valid(const qsms_network_packet* packet)
{
	QSMS_ASSERT(packet != NULL);

	uint64_t ltime;
	bool res;

	res = false;

	if (packet != NULL)
	{
		ltime = qsc_timestamp_datetime_utc();

		/* two-way variance to account for differences in system clocks */
		if (ltime > 0U && ltime < UINT64_MAX &&
			UINT64_MAX - packet->utctime >= QSMS_PACKET_TIME_THRESHOLD &&
			packet->utctime >= QSMS_PACKET_TIME_THRESHOLD)
		{
			res = (ltime >= packet->utctime - QSMS_PACKET_TIME_THRESHOLD && ltime <= packet->utctime + QSMS_PACKET_TIME_THRESHOLD);
		}
	}

	return res;
}

bool qsms_public_key_compare(const qsms_client_verification_key* a, const qsms_client_verification_key* b)
{
	QSMS_ASSERT(a != NULL);
	QSMS_ASSERT(b != NULL);

	bool res;

	res = false;

	if (a != NULL && b != NULL)
	{
		if (a->expiration == b->expiration)
		{
			if (qsc_memutils_are_equal(a->config, b->config, QSMS_CONFIG_SIZE) == true)
			{
				if (qsc_memutils_are_equal(a->keyid, b->keyid, QSMS_KEYID_SIZE) == true)
				{
					res = qsc_memutils_are_equal(a->verkey, b->verkey, QSMS_ASYMMETRIC_VERIFY_KEY_SIZE);
				}
			}
		}
	}

	return res;
}

bool qsms_public_key_decode(qsms_client_verification_key* pubk, const char* enck, size_t enclen)
{
	QSMS_ASSERT(pubk != NULL);
	QSMS_ASSERT(enck != NULL);

	char dtm[QSC_TIMESTAMP_STRING_SIZE] = { 0 };
	char* pvk;
	size_t elen;
	size_t spos;
	size_t slen;
	bool res;

	res = false;

	if (pubk != NULL && enck != NULL)
	{
		spos = sizeof(QSMS_PUBKEY_HEADER) - 1U;
		++spos;

		slen = sizeof(QSMS_PUBKEY_VERSION) - 1U;
		spos += slen;
		++spos;

		spos += sizeof(QSMS_PUBKEY_CONFIG_PREFIX) - 1U;
		slen = qsc_stringutils_find_char(enck + spos, '\n');
		qsc_memutils_copy(pubk->config, enck + spos, slen);
		spos += slen;
		++spos;

		spos += sizeof(QSMS_PUBKEY_KEYID_PREFIX) - 1U;
		qsc_intutils_hex_to_bin(enck + spos, pubk->keyid, QSMS_KEYID_SIZE);
		spos += (QSMS_KEYID_SIZE * 2U);
		++spos;

		spos += sizeof(QSMS_PUBKEY_EXPIRATION_PREFIX) - 1U;
		slen = QSC_TIMESTAMP_STRING_SIZE - 1U;
		qsc_memutils_copy(dtm, enck + spos, slen);
		spos += QSC_TIMESTAMP_STRING_SIZE;
		pubk->expiration = qsc_timestamp_datetime_to_seconds(dtm);

		elen = qsc_encoding_base64_encoded_size(QSMS_ASYMMETRIC_VERIFY_KEY_SIZE);
		pvk = qsc_memutils_malloc(elen);

		if (pvk != NULL)
		{
			qsc_memutils_clear(pvk, elen);
			elen = qsc_stringutils_remove_line_breaks(pvk, elen, enck + spos, enclen - spos);
			res = qsc_encoding_base64_decode(pubk->verkey, QSMS_ASYMMETRIC_VERIFY_KEY_SIZE, pvk, elen);
			qsc_memutils_alloc_free(pvk);
		}
	}

	return res;
}

size_t qsms_public_key_encode(char* enck, size_t enclen, const qsms_client_verification_key* pubk)
{
	QSMS_ASSERT(enck != NULL);
	QSMS_ASSERT(pubk != NULL);

	char dtm[QSMS_TIMESTAMP_STRING_SIZE] = { 0 };
	char hexid[(QSMS_KEYID_SIZE * 2U)] = { 0 };
	char* prvs;
	size_t elen;
	size_t slen;
	size_t spos;

	spos = 0U;

	if (enck != NULL && pubk != NULL)
	{
		slen = sizeof(QSMS_PUBKEY_HEADER) - 1U;
		qsc_memutils_copy(enck, QSMS_PUBKEY_HEADER, slen);
		spos = slen;
		enck[spos] = '\n';
		++spos;

		slen = sizeof(QSMS_PUBKEY_VERSION) - 1U;
		qsc_memutils_copy(enck + spos, QSMS_PUBKEY_VERSION, slen);
		spos += slen;
		enck[spos] = '\n';
		++spos;

		slen = sizeof(QSMS_PUBKEY_CONFIG_PREFIX) - 1U;
		qsc_memutils_copy(enck + spos, QSMS_PUBKEY_CONFIG_PREFIX, slen);
		spos += slen;
		slen = qsc_stringutils_string_size(QSMS_CONFIG_STRING);
		qsc_memutils_copy(enck + spos, QSMS_CONFIG_STRING, slen);
		spos += slen;
		enck[spos] = '\n';
		++spos;

		slen = sizeof(QSMS_PUBKEY_KEYID_PREFIX) - 1U;
		qsc_memutils_copy(enck + spos, QSMS_PUBKEY_KEYID_PREFIX, slen);
		spos += slen;
		qsc_intutils_bin_to_hex(pubk->keyid, hexid, QSMS_KEYID_SIZE);
		slen = sizeof(hexid);
		qsc_memutils_copy(enck + spos, hexid, slen);
		spos += slen;
		enck[spos] = '\n';
		++spos;

		slen = sizeof(QSMS_PUBKEY_EXPIRATION_PREFIX) - 1U;
		qsc_memutils_copy(enck + spos, QSMS_PUBKEY_EXPIRATION_PREFIX, slen);
		spos += slen;
		qsc_timestamp_seconds_to_datetime(pubk->expiration, dtm);
		slen = QSC_TIMESTAMP_STRING_SIZE - 1U;
		qsc_memutils_copy(enck + spos, dtm, slen);
		spos += slen;
		enck[spos] = '\n';
		++spos;

		slen = QSMS_ASYMMETRIC_VERIFY_KEY_SIZE;
		elen = qsc_encoding_base64_encoded_size(slen);
		prvs = qsc_memutils_malloc(elen);

		if (prvs != NULL)
		{
			qsc_memutils_clear(prvs, elen);
			qsc_encoding_base64_encode(prvs, elen, pubk->verkey, slen);
			spos += qsc_stringutils_add_line_breaks(enck + spos, enclen - spos, QSMS_PUBKEY_LINE_LENGTH, prvs, elen);
			qsc_memutils_alloc_free(prvs);
		}

		slen = sizeof(QSMS_PUBKEY_FOOTER) - 1U;
		qsc_memutils_copy((enck + spos), QSMS_PUBKEY_FOOTER, slen);
		spos += slen;
		enck[spos] = '\n';
	}

	return spos;
}

size_t qsms_public_key_encoding_size(void)
{
	size_t elen;
	size_t klen;

	elen = sizeof(QSMS_PUBKEY_HEADER) - 1U;
	++elen;
	elen += sizeof(QSMS_PUBKEY_VERSION) - 1U;
	++elen;
	elen += sizeof(QSMS_PUBKEY_CONFIG_PREFIX) - 1U;
	elen += sizeof(QSMS_CONFIG_STRING) - 1U;
	++elen;
	elen += sizeof(QSMS_PUBKEY_KEYID_PREFIX) - 1U;
	elen += (QSMS_KEYID_SIZE * 2);
	++elen;
	elen += sizeof(QSMS_PUBKEY_EXPIRATION_PREFIX) - 1U;
	elen += QSC_TIMESTAMP_STRING_SIZE - 1U;
	++elen;
	klen = qsc_encoding_base64_encoded_size(QSMS_ASYMMETRIC_VERIFY_KEY_SIZE);
	elen += klen + (klen / QSMS_PUBKEY_LINE_LENGTH) + 1U;
	++elen;
	elen += sizeof(QSMS_PUBKEY_FOOTER) - 1U;
	++elen;

	return elen;
}

void qsms_signature_key_deserialize(qsms_server_signature_key* kset, const uint8_t* serk)
{
	QSMS_ASSERT(kset != NULL);
	QSMS_ASSERT(serk != NULL);

	size_t pos;

	if (kset != NULL && serk != NULL)
	{
		qsc_memutils_copy(kset->config, serk, QSMS_CONFIG_SIZE);
		pos = QSMS_CONFIG_SIZE;
		kset->expiration = qsc_intutils_le8to64((serk + pos));
		pos += QSMS_TIMESTAMP_SIZE;
		qsc_memutils_copy(kset->keyid, (serk + pos), QSMS_KEYID_SIZE);
		pos += QSMS_KEYID_SIZE;
		qsc_memutils_copy(kset->sigkey, (serk + pos), QSMS_ASYMMETRIC_SIGNING_KEY_SIZE);
		pos += QSMS_ASYMMETRIC_SIGNING_KEY_SIZE;
		qsc_memutils_copy(kset->verkey, (serk + pos), QSMS_ASYMMETRIC_VERIFY_KEY_SIZE);
	}
}

void qsms_signature_key_serialize(uint8_t* serk, const qsms_server_signature_key* kset)
{
	QSMS_ASSERT(serk != NULL);
	QSMS_ASSERT(kset != NULL);

	size_t pos;

	if (serk != NULL && kset != NULL)
	{
		qsc_memutils_copy(serk, kset->config, QSMS_CONFIG_SIZE);
		pos = QSMS_CONFIG_SIZE;
		qsc_intutils_le64to8((serk + pos), kset->expiration);
		pos += QSMS_TIMESTAMP_SIZE;
		qsc_memutils_copy((serk + pos), kset->keyid, QSMS_KEYID_SIZE);
		pos += QSMS_KEYID_SIZE;
		qsc_memutils_copy((serk + pos), kset->sigkey, QSMS_ASYMMETRIC_SIGNING_KEY_SIZE);
		pos += QSMS_ASYMMETRIC_SIGNING_KEY_SIZE;
		qsc_memutils_copy((serk + pos), kset->verkey, QSMS_ASYMMETRIC_VERIFY_KEY_SIZE);
	}
}

void qsms_stream_to_packet(const uint8_t* pstream, qsms_network_packet* packet)
{
	QSMS_ASSERT(packet != NULL);
	QSMS_ASSERT(pstream != NULL);

	size_t pos;

	if (packet != NULL && pstream != NULL)
	{
		packet->flag = pstream[0U];
		pos = QSMS_FLAG_SIZE;
		packet->msglen = qsc_intutils_le8to32(pstream + pos);
		pos += QSMS_MSGLEN_SIZE;
		packet->sequence = qsc_intutils_le8to64(pstream + pos);
		pos += QSMS_SEQUENCE_SIZE;
		packet->utctime = qsc_intutils_le8to64(pstream + pos);
		pos += QSMS_TIMESTAMP_SIZE;
		qsc_memutils_copy(packet->pmessage, pstream + pos, packet->msglen);
	}
}

size_t qsms_packet_to_stream(const qsms_network_packet* packet, uint8_t* pstream)
{
	QSMS_ASSERT(packet != NULL);
	QSMS_ASSERT(pstream != NULL);

	size_t pos;
	size_t res;

	res = 0U;

	if (packet != NULL && pstream != NULL)
	{
		pstream[0U] = packet->flag;
		pos = QSMS_FLAG_SIZE;
		qsc_intutils_le32to8(pstream + pos, packet->msglen);
		pos += QSMS_MSGLEN_SIZE;
		qsc_intutils_le64to8(pstream + pos, packet->sequence);
		pos += QSMS_SEQUENCE_SIZE;
		qsc_intutils_le64to8(pstream + pos, packet->utctime);
		pos += QSMS_TIMESTAMP_SIZE;
		qsc_memutils_copy(pstream + pos, packet->pmessage, packet->msglen);
		res = (size_t)QSMS_HEADER_SIZE + packet->msglen;
	}

	return res;
}

#if defined (QSMS_DEBUG_MODE)
bool qsms_certificate_encoding_test(void)
{
	qsms_client_verification_key pcpy = { 0 };
	qsms_client_verification_key pkey = { 0 };
	qsms_server_signature_key skey = { 0 };
	uint8_t keyid[QSMS_KEYID_SIZE] = { 0U };
	char* enck;
	size_t elen;
	bool res;

	res = false;
	qsc_acp_generate(keyid, sizeof(keyid));
	qsms_generate_keypair(&pkey, &skey, keyid);

	elen = qsms_public_key_encoding_size();
	enck = qsc_memutils_malloc(elen);

	if (enck != NULL)
	{
		qsc_memutils_clear(enck, elen);

		qsms_public_key_encode(enck, elen, &pkey);
		qsms_public_key_decode(&pcpy, enck, elen);

		res = qsms_public_key_compare(&pkey, &pcpy);
		qsc_memutils_alloc_free(enck);
	}

	return res;
}
#endif

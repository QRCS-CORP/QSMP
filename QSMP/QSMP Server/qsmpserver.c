#include "qsmpserver.h"
#include "../QSC/acp.h"
#include "../QSC/encoding.h"
#include "../QSC/intutils.h"
#include "../QSC/memutils.h"
#include "../QSC/sha3.h"
#include "../QSC/stringutils.h"
#include "../QSC/timestamp.h"
#include "../QSC/async.h"

#if defined(QSMP_PUBKEY_SPHINCS)
#	define qsmp_cipher_generate_keypair qsc_mceliece_generate_keypair
#	define qsmp_cipher_decapsulate qsc_mceliece_decapsulate
#	define qsmp_cipher_encapsulate qsc_mceliece_encapsulate
#	define qsmp_signature_generate_keypair qsc_sphincsplus_generate_keypair
#	define qsmp_signature_sign qsc_sphincsplus_sign
#	define qsmp_signature_verify qsc_sphincsplus_verify
#else
#	define qsmp_cipher_generate_keypair qsc_kyber_generate_keypair
#	define qsmp_cipher_decapsulate qsc_kyber_decapsulate
#	define qsmp_cipher_encapsulate qsc_kyber_encapsulate
#	define qsmp_signature_generate_keypair qsc_dilithium_generate_keypair
#	define qsmp_signature_sign qsc_dilithium_sign
#	define qsmp_signature_verify qsc_dilithium_verify
#endif

/* Private Functions */

static void server_state_dispose(qsmp_kex_server_state* ctx)
{
	assert(ctx != NULL);

	if (ctx != NULL)
	{
		qsc_rcs_dispose(&ctx->rxcpr);
		qsc_rcs_dispose(&ctx->txcpr);
		ctx->rxseq = 0;
		ctx->txseq = 0;
		ctx->exflag = qsmp_flag_none;
	}
}

static void server_kex_reset(qsmp_kex_server_state* ctx)
{
	qsc_memutils_clear(ctx->config, QSMP_CONFIG_SIZE);
	qsc_memutils_clear(ctx->keyid, QSMP_KEYID_SIZE);
	qsc_memutils_clear(ctx->pkhash, QSMP_PKCODE_SIZE);
	qsc_memutils_clear(ctx->prikey, QSMP_PRIVATEKEY_SIZE);
	qsc_memutils_clear(ctx->pubkey, QSMP_PUBLICKEY_SIZE);
	qsc_memutils_clear(ctx->token, QSMP_STOKEN_SIZE);
	qsc_memutils_clear(ctx->sigkey, QSMP_SIGNKEY_SIZE);
	qsc_memutils_clear(ctx->verkey, QSMP_VERIFYKEY_SIZE);
	ctx->expiration = 0;
}

static bool server_key_exists(const uint8_t keyid[QSMP_KEYID_SIZE], const uint8_t* cmpid)
{
	bool res;

	/* on a server with multiple keys, the server would load the key into state here,
	from a database, rather than through the initialize call */

	res = qsc_intutils_are_equal8(keyid, cmpid, QSMP_KEYID_SIZE);

	return res;
}

static qsmp_errors server_connect_response(qsmp_kex_server_state* ctx, const qsmp_packet* packetin, qsmp_packet* packetout)
{
	assert(ctx != NULL);
	assert(packetin != NULL);
	assert(packetout != NULL);

	char confs[QSMP_CONFIG_SIZE + 1] = { 0 };
	uint8_t phash[QSC_SHA3_256_HASH_SIZE] = { 0 };
	qsc_keccak_state kstate = { 0 };
	qsmp_errors qerr;
	uint64_t tm;
	size_t mlen;

	if (ctx != NULL && packetin != NULL && packetout != NULL)
	{
		if (packetin->flag == qsmp_flag_connect_request)
		{
			/* compare the state key-id to the id in the message */
			if (server_key_exists(ctx->keyid, packetin->message) == true)
			{
				tm = qsc_timestamp_epochtime_seconds();

				/* check the keys expiration date */
				if (tm <= ctx->expiration)
				{
					/* copy the token to state */
					qsc_memutils_copy(ctx->token, ((uint8_t*)packetin->message + QSMP_KEYID_SIZE), QSMP_STOKEN_SIZE);
					/* get a copy of the configuration string */
					qsc_memutils_copy(confs, ((uint8_t*)packetin->message + QSMP_KEYID_SIZE + QSMP_STOKEN_SIZE), QSMP_CONFIG_SIZE);

					/* compare the state configuration string to the message configuration string */
					if (qsc_stringutils_compare_strings(confs, QSMP_CONFIG_STRING, QSMP_CONFIG_SIZE) == true)
					{
						/* store a hash of the session token, the configuration string, and the public signature key: pkh = H(stok || cfg || pvk) */
						qsc_memutils_clear(ctx->pkhash, QSMP_PKCODE_SIZE);
						qsc_sha3_initialize(&kstate);
						qsc_sha3_update(&kstate, qsc_keccak_rate_256, ctx->token, QSMP_STOKEN_SIZE);
						qsc_sha3_update(&kstate, qsc_keccak_rate_256, QSMP_CONFIG_STRING, QSMP_CONFIG_SIZE);
						qsc_sha3_update(&kstate, qsc_keccak_rate_256, ctx->verkey, QSMP_VERIFYKEY_SIZE);
						qsc_sha3_finalize(&kstate, qsc_keccak_rate_256, ctx->pkhash);

						/* initialize the packet and asymmetric encryption keys */
						qsc_memutils_clear(ctx->pubkey, QSMP_PUBLICKEY_SIZE);
						qsc_memutils_clear(ctx->prikey, QSMP_PRIVATEKEY_SIZE);
						qsc_memutils_clear(packetout->message, QSMP_MESSAGE_MAX);

						/* generate the asymmetric encryption key-pair */
						qsmp_cipher_generate_keypair(ctx->pubkey, ctx->prikey, qsc_acp_generate);

						/* hash the public encryption key */
						qsc_sha3_compute256(phash, ctx->pubkey, QSMP_PUBLICKEY_SIZE);

						/* sign the hash and add it to the message */
						mlen = 0;
						qsmp_signature_sign(packetout->message, &mlen, phash, QSC_SHA3_256_HASH_SIZE, ctx->sigkey, qsc_acp_generate);

						/* copy the public key to the message */
						qsc_memutils_copy(((uint8_t*)packetout->message + mlen), ctx->pubkey, QSMP_PUBLICKEY_SIZE);

						/* assemble the connection-response packet */
						packetout->flag = qsmp_flag_connect_response;
						packetout->msglen = QSMP_SIGNATURE_SIZE + QSC_SHA3_256_HASH_SIZE + QSMP_PUBLICKEY_SIZE;
						packetout->sequence = ctx->txseq;

						qerr = qsmp_error_none;
						ctx->exflag = qsmp_flag_connect_response;
					}
					else
					{
						qerr = qsmp_error_unknown_protocol;
						ctx->exflag = qsmp_flag_none;
					}
				}
				else
				{
					qerr = qsmp_error_key_expired;
					ctx->exflag = qsmp_flag_none;
				}
			}
			else
			{
				qerr = qsmp_error_key_unrecognized;
				ctx->exflag = qsmp_flag_none;
			}
		}
		else
		{
			qerr = qsmp_error_invalid_request;
			ctx->exflag = qsmp_flag_none;
		}
	}
	else
	{
		qerr = qsmp_error_invalid_input;
	}

	return qerr;
}

static qsmp_errors server_exstart_response(qsmp_kex_server_state* ctx, const qsmp_packet* packetin, qsmp_packet* packetout)
{
	assert(ctx != NULL);
	assert(packetin != NULL);
	assert(packetout != NULL);

	qsmp_errors qerr;

	if (ctx != NULL && packetin != NULL && packetout != NULL)
	{
		if (ctx->exflag == qsmp_flag_connect_response && packetin->flag == qsmp_flag_exstart_request)
		{
			uint8_t sec[QSMP_SECRET_SIZE] = { 0 };

			/* decapsulate the shared secret */
			if (qsmp_cipher_decapsulate(sec, packetin->message, ctx->prikey) == true)
			{
				uint8_t prnd[QSC_KECCAK_256_RATE] = { 0 };
				qsc_keccak_state kstate = { 0 };

				/* expand the secret with cshake adding the public verification keys hash; prand = Exp(pkh || sec) */
				qsc_cshake_initialize(&kstate, qsc_keccak_rate_256, sec, QSMP_SECRET_SIZE, NULL, 0, ctx->pkhash, QSMP_PKCODE_SIZE);
				qsc_cshake_squeezeblocks(&kstate, qsc_keccak_rate_256, prnd, 1);

				/* initialize the symmetric cipher, and raise server channel-1 rx */
				qsc_rcs_keyparams kp;
				kp.key = prnd;
				kp.keylen = QSC_RCS256_KEY_SIZE;
				kp.nonce = ((uint8_t*)prnd + QSC_RCS256_KEY_SIZE);
				kp.info = NULL;
				kp.infolen = 0;
				qsc_rcs_initialize(&ctx->rxcpr, &kp, false);

				/* channel-1 VPN is established */

				/* assemble the exstart-response packet */
				qsc_memutils_clear(packetout->message, QSMP_MESSAGE_MAX);
				packetout->flag = qsmp_flag_exstart_response;
				packetout->message[0] = (uint8_t)qsmp_flag_remote_connected; // TODO: is this needed?
				packetout->msglen = 1;
				packetout->sequence = ctx->txseq;

				qerr = qsmp_error_none;
				ctx->exflag = qsmp_flag_exstart_response;
			}
			else
			{
				qerr = qsmp_error_decapsulation_failure;
				ctx->exflag = qsmp_flag_none;
			}
		}
		else
		{
			qerr = qsmp_error_invalid_request;
			ctx->exflag = qsmp_flag_none;
		}
	}
	else
	{
		qerr = qsmp_error_invalid_input;
	}

	return qerr;
}

static qsmp_errors server_exchange_response(qsmp_kex_server_state* ctx, const qsmp_packet* packetin, qsmp_packet* packetout)
{
	assert(ctx != NULL);
	assert(packetin != NULL);
	assert(packetout != NULL);

	qsmp_errors qerr;

	if (ctx != NULL && packetin != NULL && packetout != NULL)
	{
		if (ctx->exflag == qsmp_flag_exstart_response && packetin->flag == qsmp_flag_exchange_request)
		{
			uint8_t hdr[QSMP_HEADER_SIZE] = { 0 };
			uint8_t msg[QSMP_PUBLICKEY_SIZE + QSMP_MACKEY_SIZE] = { 0 };

			/* serialize the packet header and add it to associated data */
			qsmp_packet_header_serialize(packetin, hdr);
			qsc_rcs_set_associated(&ctx->rxcpr, hdr, QSMP_HEADER_SIZE);

			/* authenticate and decrypt the cipher-text */
			if (qsc_rcs_transform(&ctx->rxcpr, msg, packetin->message, packetin->msglen - QSMP_MACTAG_SIZE) == true)
			{
				uint8_t sec[QSMP_SECRET_SIZE] = { 0 };
				uint8_t cpt[QSMP_CIPHERTEXT_SIZE] = { 0 };
				uint8_t mkey[QSMP_MACKEY_SIZE] = { 0 };
				uint8_t prnd[QSC_KECCAK_256_RATE] = { 0 };
				qsc_keccak_state kstate = { 0 };

				qsc_memutils_copy(mkey, msg, sizeof(mkey));
				/* generate and encapsulate the shared secret */
				qsmp_cipher_encapsulate(sec, cpt, ((uint8_t*)msg + QSMP_MACKEY_SIZE), qsc_acp_generate);

				/* expand the shared secret */
				qsc_cshake_initialize(&kstate, qsc_keccak_rate_256, sec, QSMP_SECRET_SIZE, NULL, 0, ctx->pkhash, QSMP_PKCODE_SIZE);
				qsc_cshake_squeezeblocks(&kstate, qsc_keccak_rate_256, prnd, 1);

				/* initialize the symmetric cipher, and raise server channel-2 tx */
				qsc_rcs_keyparams kp;
				kp.key = prnd;
				kp.keylen = QSC_RCS256_KEY_SIZE;
				kp.nonce = ((uint8_t*)prnd + QSC_RCS256_KEY_SIZE);
				kp.info = NULL;
				kp.infolen = 0;
				qsc_rcs_initialize(&ctx->txcpr, &kp, true);

				/* assemble the exstart-response packet */
				qsc_memutils_clear(packetout->message, QSMP_MESSAGE_MAX);
				packetout->flag = qsmp_flag_exchange_response;
				packetout->msglen = QSMP_CIPHERTEXT_SIZE + QSMP_MACTAG_SIZE;
				packetout->sequence = ctx->txseq;

				/* mac the asymmetric cipher-text, and prepend the MAC code */
				qsc_kmac256_compute(packetout->message, QSMP_MACTAG_SIZE, cpt, QSMP_CIPHERTEXT_SIZE, mkey, QSMP_MACKEY_SIZE, NULL, 0);
				/* copy the cipher-text to the packet */
				qsc_memutils_copy(((uint8_t*)packetout->message + QSMP_MACTAG_SIZE), cpt, QSMP_CIPHERTEXT_SIZE);

				qerr = qsmp_error_none;
				ctx->exflag = qsmp_flag_exchange_response;
			}
			else
			{
				qerr = qsmp_error_authentication_failure;
				ctx->exflag = qsmp_flag_none;
			}
		}
		else
		{
			qerr = qsmp_error_invalid_request;
			ctx->exflag = qsmp_flag_none;
		}
	}
	else
	{
		qerr = qsmp_error_invalid_input;
	}

	return qerr;
}

static qsmp_errors server_establish_response(qsmp_kex_server_state* ctx, const qsmp_packet* packetin, qsmp_packet* packetout)
{
	assert(ctx != NULL);
	assert(packetin != NULL);
	assert(packetout != NULL);

	qsmp_errors qerr;

	if (ctx != NULL && packetin != NULL && packetout != NULL)
	{
		if (ctx->exflag == qsmp_flag_exchange_response && packetin->flag == qsmp_flag_establish_request)
		{
			uint8_t hdr[QSMP_HEADER_SIZE] = { 0 };
			uint8_t msg[QSMP_KEYID_SIZE] = { 0 };

			/* serialize the packet header and add it to associated data */
			qsmp_packet_header_serialize(packetin, hdr);
			qsc_rcs_set_associated(&ctx->rxcpr, hdr, QSMP_HEADER_SIZE);

			/* authenticate and decrypt the cipher-text */
			if (qsc_rcs_transform(&ctx->rxcpr, msg, packetin->message, packetin->msglen - QSMP_MACTAG_SIZE) == true)
			{
				/* compare the stored device id with the plain-text */
				if (qsc_intutils_verify(msg, ctx->keyid, QSMP_KEYID_SIZE) == 0)
				{
					/* assemble the establish-response packet */
					qsc_memutils_clear(packetout->message, QSMP_MESSAGE_MAX);
					packetout->flag = qsmp_flag_establish_response;
					packetout->msglen = QSMP_KEYID_SIZE + QSMP_MACTAG_SIZE;
					packetout->sequence = ctx->txseq;

					/* serialize the packet header and add it to the associated data */
					qsc_memutils_clear(hdr, QSMP_HEADER_SIZE);
					qsmp_packet_header_serialize(packetout, hdr);
					qsc_rcs_set_associated(&ctx->txcpr, hdr, QSMP_HEADER_SIZE);

					/* encrypt the message */
					qsc_rcs_transform(&ctx->txcpr, packetout->message, msg, QSMP_KEYID_SIZE);

					qerr = qsmp_error_none;
					ctx->exflag = qsmp_flag_session_established;
				}
				else
				{
					qerr = qsmp_error_verify_failure;
					ctx->exflag = qsmp_flag_none;
				}
			}
			else
			{
				qerr = qsmp_error_authentication_failure;
				ctx->exflag = qsmp_flag_none;
			}
		}
		else
		{
			qerr = qsmp_error_invalid_request;
			ctx->exflag = qsmp_flag_none;
		}
	}
	else
	{
		qerr = qsmp_error_invalid_input;
	}

	return qerr;
}

static qsmp_errors server_key_exchange(qsmp_kex_server_state* ctx, qsc_socket* sock)
{
	uint8_t spct[QSMP_MESSAGE_MAX + 1] = { 0 };
	qsmp_packet reqt = { 0 };
	qsmp_packet resp = { 0 };
	qsmp_errors qerr;
	size_t plen;
	size_t rlen;
	size_t slen;

	/* blocking receive waits for client */
	rlen = qsc_socket_receive(sock, spct, sizeof(spct), qsc_socket_receive_flag_none);

	if (rlen == QSMP_CONNECT_REQUEST_SIZE + QSC_SOCKET_TERMINATOR_SIZE)
	{
		/* convert server response to packet */
		qsmp_stream_to_packet(spct, &resp);
		qsc_memutils_clear(spct, sizeof(spct));

		if (resp.sequence == ctx->rxseq)
		{
			ctx->rxseq += 1;

			if (resp.flag == qsmp_flag_connect_request)
			{
				/* clear the request packet */
				qsmp_packet_clear(&reqt);
				/* create the connection request packet */
				qerr = server_connect_response(ctx, &resp, &reqt);
			}
			else
			{
				if (resp.flag == qsmp_flag_error_condition)
				{
					qerr = (qsmp_errors)resp.message[0];
				}
				else
				{
					qerr = qsmp_error_connect_failure;
				}
			}
		}
		else
		{
			qerr = qsmp_error_packet_unsequenced;
		}
	}
	else
	{
		qerr = qsmp_error_receive_failure;
	}

	if (qerr == qsmp_error_none)
	{
		/* convert the packet to bytes */
		plen = qsmp_packet_to_stream(&reqt, spct);
		/* send the connection response */
		slen = qsc_socket_send(sock, spct, plen, qsc_socket_send_flag_none);
		qsc_memutils_clear(spct, sizeof(spct));

		if (slen == plen + QSC_SOCKET_TERMINATOR_SIZE)
		{
			/* blocking receive waits for client */
			ctx->txseq += 1;
			rlen = qsc_socket_receive(sock, spct, sizeof(spct), qsc_socket_receive_flag_none);

			if (rlen == QSMP_EXSTART_REQUEST_SIZE + QSC_SOCKET_TERMINATOR_SIZE)
			{
				qsmp_stream_to_packet(spct, &resp);
				qsc_memutils_clear(spct, sizeof(spct));

				if (resp.sequence == ctx->rxseq)
				{
					ctx->rxseq += 1;

					if (resp.flag == qsmp_flag_exstart_request)
					{
						qsmp_packet_clear(&reqt);
						/* create the exstart response packet */
						qerr = server_exstart_response(ctx, &resp, &reqt);
					}
					else
					{
						/* get the error message */
						if (resp.flag == qsmp_flag_error_condition)
						{
							qerr = (qsmp_errors)resp.message[0];
						}
						else
						{
							qerr = qsmp_error_exstart_failure;
						}
					}
				}
				else
				{
					qerr = qsmp_error_packet_unsequenced;
				}
			}
			else
			{
				qerr = qsmp_error_receive_failure;
			}
		}
		else
		{
			qerr = qsmp_error_transmit_failure;
		}
	}

	if (qerr == qsmp_error_none)
	{
		plen = qsmp_packet_to_stream(&reqt, spct);
		slen = qsc_socket_send(sock, spct, plen, qsc_socket_send_flag_none);
		qsc_memutils_clear(spct, sizeof(spct));

		if (slen == plen + QSC_SOCKET_TERMINATOR_SIZE)
		{
			ctx->txseq += 1;
			rlen = qsc_socket_receive(sock, spct, sizeof(spct), qsc_socket_receive_flag_none);

			if (rlen == QSMP_EXCHANGE_REQUEST_SIZE + QSC_SOCKET_TERMINATOR_SIZE)
			{
				qsmp_stream_to_packet(spct, &resp);
				qsc_memutils_clear(spct, sizeof(spct));

				if (resp.sequence == ctx->rxseq)
				{
					ctx->rxseq += 1;

					if (resp.flag == qsmp_flag_exchange_request)
					{
						qsmp_packet_clear(&reqt);
						/* create the exchange response packet */
						qerr = server_exchange_response(ctx, &resp, &reqt);
					}
					else
					{
						if (resp.flag == qsmp_flag_error_condition)
						{
							qerr = (qsmp_errors)resp.message[0];
						}
						else
						{
							qerr = qsmp_error_exchange_failure;
						}
					}
				}
				else
				{
					qerr = qsmp_error_packet_unsequenced;
				}
			}
			else
			{
				qerr = qsmp_error_receive_failure;
			}
		}
		else
		{
			qerr = qsmp_error_transmit_failure;
		}
	}

	if (qerr == qsmp_error_none)
	{
		plen = qsmp_packet_to_stream(&reqt, spct);
		slen = qsc_socket_send(sock, spct, plen, qsc_socket_send_flag_none);
		qsc_memutils_clear(spct, sizeof(spct));

		if (slen == plen + QSC_SOCKET_TERMINATOR_SIZE)
		{
			ctx->txseq += 1;
			rlen = qsc_socket_receive(sock, spct, sizeof(spct), qsc_socket_receive_flag_none);

			if (rlen == QSMP_ESTABLISH_REQUEST_SIZE + QSC_SOCKET_TERMINATOR_SIZE)
			{
				ctx->rxseq += 1;
				qsmp_stream_to_packet(spct, &resp);
				qsc_memutils_clear(spct, sizeof(spct));

				if (resp.flag == qsmp_flag_establish_request)
				{
					qsmp_packet_clear(&reqt);
					/* create the establish response packet */
					qerr = server_establish_response(ctx, &resp, &reqt);

					if (qerr == qsmp_error_none)
					{
						plen = qsmp_packet_to_stream(&reqt, spct);
						slen = qsc_socket_send(sock, spct, plen, qsc_socket_send_flag_none);

						if (slen == plen + QSC_SOCKET_TERMINATOR_SIZE)
						{
							ctx->txseq += 1;
						}
						else
						{
							qerr = qsmp_error_transmit_failure;
						}
					}
					else
					{
						qerr = qsmp_error_establish_failure;
					}
				}
				else
				{
					if (resp.flag == qsmp_flag_error_condition)
					{
						qerr = (qsmp_errors)resp.message[0];
					}
					else
					{
						qerr = qsmp_error_establish_failure;
					}
				}
			}
			else
			{
				qerr = qsmp_error_receive_failure;
			}
		}
		else
		{
			qerr = qsmp_error_transmit_failure;
		}
	}

	server_kex_reset(ctx);

	if (qerr != qsmp_error_none)
	{
		if (sock->connection_status == qsc_socket_state_connected)
		{
			qsmp_server_send_error(sock, qerr);
			qsc_socket_shut_down(sock, qsc_socket_shut_down_flag_both);
		}

		server_state_dispose(ctx);
	}

	return qerr;
}

/* Helper Functions */

void qsmp_server_connection_close(qsmp_kex_server_state* ctx, qsc_socket* sock, qsmp_errors error)
{
	if (qsc_socket_is_connected(sock) == true)
	{
		qsmp_packet resp = { 0 };
		uint8_t spct[QSMP_MESSAGE_MAX] = { 0 };
		size_t plen;

		/* send a disconnect message */
		resp.flag = qsmp_flag_connection_terminate;
		resp.sequence = QSMP_SEQUENCE_TERMINATOR;
		resp.msglen = 1;
		resp.message[0] = (uint8_t)error;
		plen = qsmp_packet_to_stream(&resp, spct);
		qsc_socket_send(sock, spct, plen, qsc_socket_send_flag_none);

		/* close the socket */
		qsc_socket_close_socket(sock);
	}

	/* dispose of resources */
	server_state_dispose(ctx);
}

void qsmp_server_deserialize_signature_key(qsmp_server_key* skey, const uint8_t input[QSMP_SIGKEY_ENCODED_SIZE])
{
	size_t pos;

	qsc_memutils_copy(skey->config, input, QSMP_CONFIG_SIZE);
	pos = QSMP_CONFIG_SIZE;
	skey->expiration = qsc_intutils_le8to64(((uint8_t*)input + pos));
	pos += QSMP_TIMESTAMP_SIZE;
	qsc_memutils_copy(skey->keyid, ((uint8_t*)input + pos), QSMP_KEYID_SIZE);
	pos += QSMP_KEYID_SIZE;
	qsc_memutils_copy(skey->sigkey, ((uint8_t*)input + pos), QSMP_SIGNKEY_SIZE);
	pos += QSMP_SIGNKEY_SIZE;
	qsc_memutils_copy(skey->verkey, ((uint8_t*)input + pos), QSMP_VERIFYKEY_SIZE);
	pos += QSMP_VERIFYKEY_SIZE;
}

void qsmp_server_encode_public_key(char output[QSMP_PUBKEY_STRING_SIZE], const qsmp_server_key* skey)
{
	assert(skey != NULL);

	char dtm[QSC_TIMESTAMP_STRING_SIZE] = { 0 };
	char hexid[QSMP_KEYID_SIZE * 2] = { 0 };
	char tmpvk[QSMP_PUBKEY_ENCODING_SIZE] = { 0 };
	size_t slen;
	size_t spos;
	size_t tpos;

	if (skey != NULL)
	{
		spos = 0;
		tpos = 0;
		slen = sizeof(QSMP_PUBKEY_HEADER) - 1;
		qsc_memutils_copy(output, QSMP_PUBKEY_HEADER, slen);
		spos = slen;
		output[spos] = '\n';
		++spos;

		slen = sizeof(QSMP_PUBKEY_VERSION) - 1;
		qsc_memutils_copy(((char*)output + spos), QSMP_PUBKEY_VERSION, slen);
		spos += slen;
		output[spos] = '\n';
		++spos;

		slen = sizeof(QSMP_PUBKEY_CONFIG_PREFIX) - 1;
		qsc_memutils_copy(((char*)output + spos), QSMP_PUBKEY_CONFIG_PREFIX, slen);
		spos += slen;
		slen = sizeof(QSMP_CONFIG_STRING) - 1;
		qsc_memutils_copy(((char*)output + spos), QSMP_CONFIG_STRING, slen);
		spos += slen;
		output[spos] = '\n';
		++spos;

		slen = sizeof(QSMP_PUBKEY_KEYID_PREFIX) - 1;
		qsc_memutils_copy(((char*)output + spos), QSMP_PUBKEY_KEYID_PREFIX, slen);
		spos += slen;
		qsc_intutils_bin_to_hex(skey->keyid, hexid, QSMP_KEYID_SIZE);
		slen = sizeof(hexid);
		qsc_memutils_copy(((char*)output + spos), hexid, slen);
		spos += slen;
		output[spos] = '\n';
		++spos;

		slen = sizeof(QSMP_PUBKEY_EXPIRATION_PREFIX) - 1;
		qsc_memutils_copy(((char*)output + spos), QSMP_PUBKEY_EXPIRATION_PREFIX, slen);
		spos += slen;
		qsc_timestamp_seconds_to_datetime(skey->expiration, dtm);
		slen = sizeof(dtm) - 1;
		qsc_memutils_copy(((char*)output + spos), dtm, slen);
		spos += slen;
		output[spos] = '\n';
		++spos;

		slen = QSMP_VERIFYKEY_SIZE;
		qsc_encoding_base64_encode(tmpvk, QSMP_PUBKEY_ENCODING_SIZE, skey->verkey, slen);
		spos += qsc_stringutils_add_line_breaks(((char*)output + spos), QSMP_PUBKEY_STRING_SIZE - spos, QSMP_PUBKEY_LINE_LENGTH, tmpvk, sizeof(tmpvk));
		output[spos] = '\n';
		++spos;

		slen = sizeof(QSMP_PUBKEY_FOOTER) - 1;
		qsc_memutils_copy(((char*)output + spos), QSMP_PUBKEY_FOOTER, slen);
		spos += slen;
		output[spos] = '\n';
	}
}

void qsmp_server_send_error(qsc_socket* sock, qsmp_errors error)
{
	if (qsc_socket_is_connected(sock) == true)
	{
		qsmp_packet resp = { 0 };
		uint8_t spct[QSMP_MESSAGE_MAX] = { 0 };
		size_t plen;

		qsmp_packet_error_message(&resp, error);
		plen = qsmp_packet_to_stream(&resp, spct);
		qsc_socket_send(sock, spct, plen, qsc_socket_send_flag_none);
	}
}

qsmp_errors qsmp_server_send_keep_alive(qsmp_keep_alive_state* kctx, qsc_socket* sock)
{
	qsmp_errors qerr;

	qerr = qsmp_error_bad_keep_alive;

	if (qsc_socket_is_connected(sock) == true)
	{
		qsmp_packet resp = { 0 };
		uint8_t spct[QSMP_MESSAGE_MAX] = { 0 };
		uint64_t etime;
		size_t plen;
		size_t slen;

		/* set the time and store in keep-alive struct */
		etime = qsc_timestamp_epochtime_seconds();
		kctx->etime = etime;

		/* assemble the keep-alive packet */
		resp.flag = qsmp_flag_keep_alive_request;
		resp.sequence = kctx->seqctr;
		resp.msglen = sizeof(etime);
		qsc_intutils_le64to8(resp.message, etime);
		plen = qsmp_packet_to_stream(&resp, spct);
		slen = qsc_socket_send(sock, spct, plen, qsc_socket_send_flag_none);

		if (slen >= plen)
		{
			qerr = qsmp_error_none;
		}
	}

	return qerr;
}

void qsmp_server_serialize_signature_key(uint8_t output[QSMP_SIGKEY_ENCODED_SIZE], const qsmp_server_key* skey)
{
	size_t pos;

	qsc_memutils_copy(output, skey->config, QSMP_CONFIG_SIZE);
	pos = QSMP_CONFIG_SIZE;
	qsc_intutils_le64to8(((uint8_t*)output + pos), skey->expiration);
	pos += QSMP_TIMESTAMP_SIZE;
	qsc_memutils_copy(((uint8_t*)output + pos), skey->keyid, QSMP_KEYID_SIZE);
	pos += QSMP_KEYID_SIZE;
	qsc_memutils_copy(((uint8_t*)output + pos), skey->sigkey, QSMP_SIGNKEY_SIZE);
	pos += QSMP_SIGNKEY_SIZE;
	qsc_memutils_copy(((uint8_t*)output + pos), skey->verkey, QSMP_VERIFYKEY_SIZE);
	pos += QSMP_VERIFYKEY_SIZE;
}

/* Primary Functions */

void qsmp_server_initialize(qsmp_kex_server_state* ctx, const qsmp_server_key* skey)
{
	assert(ctx != NULL);
	assert(skey != NULL);

	if (ctx != NULL && skey != NULL)
	{
		server_state_dispose(ctx);
		qsc_memutils_copy(ctx->keyid, skey->keyid, QSMP_KEYID_SIZE);
		qsc_memutils_copy(ctx->config, QSMP_CONFIG_STRING, QSMP_CONFIG_SIZE);
		qsc_memutils_copy(ctx->sigkey, skey->sigkey, QSMP_SIGNKEY_SIZE);
		qsc_memutils_copy(ctx->verkey, skey->verkey, QSMP_VERIFYKEY_SIZE);
		ctx->exflag = qsmp_flag_none;
		ctx->expiration = skey->expiration;
	}
}

qsmp_errors qsmp_server_listen_ipv4(qsmp_kex_server_state* ctx, qsc_socket* sock, const qsc_ipinfo_ipv4_address* address, uint16_t port)
{
	qsc_socket srvs;
	qsc_socket_exceptions serr;
	qsmp_errors qerr;

	qerr = qsmp_error_none;
	qsc_socket_server_initialize(sock);
	qsc_socket_server_initialize(&srvs);

	serr = qsc_socket_server_listen_ipv4(&srvs, sock, address, port);

	if (serr == qsc_socket_exception_success)
	{
		qerr = server_key_exchange(ctx, sock);
	}
	else
	{
		qerr = qsmp_error_connection_failure;
	}

	return qerr;
}

qsmp_errors qsmp_server_listen_ipv6(qsmp_kex_server_state* ctx, qsc_socket* sock, const qsc_ipinfo_ipv6_address* address, uint16_t port)
{
	qsc_socket srvs;
	qsc_socket_exceptions serr;
	qsmp_errors qerr;

	qerr = qsmp_error_none;
	qsc_socket_server_initialize(sock);
	qsc_socket_server_initialize(&srvs);

	serr = qsc_socket_server_listen_ipv6(&srvs, sock, address, port);

	if (serr == qsc_socket_exception_success)
	{
		qerr = server_key_exchange(ctx, sock);
	}
	else
	{
		qerr = qsmp_error_connection_failure;
	}

	return qerr;
}

qsmp_errors qsmp_server_decrypt_packet(qsmp_kex_server_state* ctx, const qsmp_packet* packetin, uint8_t* message, size_t* msglen)
{
	assert(ctx != NULL);
	assert(message != NULL);
	assert(msglen != NULL);
	assert(packetin != NULL);

	uint8_t hdr[QSMP_HEADER_SIZE] = { 0 };
	qsmp_errors qerr;

	qerr = qsmp_error_invalid_input;

	if (ctx != NULL && message != NULL && msglen != NULL && packetin != NULL)
	{
		ctx->rxseq += 1;

		if (packetin->sequence == ctx->rxseq)
		{
			if (ctx->exflag == qsmp_flag_session_established)
			{
				/* serialize the header and add it to the ciphers associated data */
				qsmp_packet_header_serialize(packetin, hdr);
				qsc_rcs_set_associated(&ctx->rxcpr, hdr, QSMP_HEADER_SIZE);
				*msglen = packetin->msglen - QSC_RCS256_MAC_SIZE;

				/* authenticate then decrypt the data */
				if (qsc_rcs_transform(&ctx->rxcpr, message, packetin->message, *msglen) == true)
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

qsmp_errors qsmp_server_encrypt_packet(qsmp_kex_server_state* ctx, uint8_t* message, size_t msglen, qsmp_packet* packetout)
{
	assert(ctx != NULL);
	assert(message != NULL);
	assert(packetout != NULL);

	qsmp_errors qerr;

	qerr = qsmp_error_invalid_input;

	if (ctx != NULL && message != NULL && packetout != NULL)
	{
		if (ctx->exflag == qsmp_flag_session_established)
		{
			uint8_t hdr[QSMP_HEADER_SIZE] = { 0 };

			/* assemble the encryption packet */
			ctx->txseq += 1;
			qsc_memutils_clear(packetout->message, QSMP_MESSAGE_MAX);
			packetout->flag = qsmp_flag_encrypted_message;
			packetout->msglen = (uint32_t)msglen + QSC_RCS256_MAC_SIZE;
			packetout->sequence = ctx->txseq;

			/* serialize the header and add it to the ciphers associated data */
			qsmp_packet_header_serialize(packetout, hdr);
			qsc_rcs_set_associated(&ctx->txcpr, hdr, QSMP_HEADER_SIZE);
			/* encrypt the message */
			qsc_rcs_transform(&ctx->txcpr, packetout->message, message, msglen);

			qerr = qsmp_error_none;
		}
		else
		{
			qerr = qsmp_error_channel_down;
		}
	}

	return qerr;
}

void qsmp_server_generate_keypair(qsmp_client_key* pubkey, qsmp_server_key* prikey, const uint8_t keyid[QSMP_KEYID_SIZE])
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
#include "qsmpclient.h"
#include "../QSC/acp.h"
#include "../QSC/encoding.h"
#include "../QSC/intutils.h"
#include "../QSC/memutils.h"
#include "../QSC/sha3.h"
#include "../QSC/stringutils.h"
#include "../QSC/timestamp.h"

/* Private Functions */

static void client_state_dispose(qsmp_kex_client_state* ctx)
{
	assert(ctx != NULL);

	if (ctx != NULL)
	{
		qsc_rcs_dispose(&ctx->rxcpr);
		qsc_rcs_dispose(&ctx->txcpr);
		ctx->exflag = qsmp_flag_none;
		ctx->rxseq = 0;
		ctx->txseq = 0;
	}
}

static void client_kex_reset(qsmp_kex_client_state* ctx)
{
	assert(ctx != NULL);

	if (ctx != NULL)
	{
		qsc_memutils_clear(ctx->config, QSMP_CONFIG_SIZE);
		qsc_memutils_clear(ctx->keyid, QSMP_KEYID_SIZE);
		qsc_memutils_clear(ctx->mackey, QSMP_MACKEY_SIZE);
		qsc_memutils_clear(ctx->pkhash, QSMP_PKCODE_SIZE);
		qsc_memutils_clear(ctx->prikey, QSMP_PRIVATEKEY_SIZE);
		qsc_memutils_clear(ctx->pubkey, QSMP_PUBLICKEY_SIZE);
		qsc_memutils_clear(ctx->token, QSMP_STOKEN_SIZE);
		qsc_memutils_clear(ctx->verkey, QSMP_VERIFYKEY_SIZE);
		ctx->expiration = 0;
	}
}

static void client_state_initialize(qsmp_kex_client_state* ctx, const qsmp_client_key* ckey)
{
	assert(ckey != NULL);
	assert(ctx != NULL);

	if (ckey != NULL && ctx != NULL)
	{
		client_state_dispose(ctx);
		qsc_memutils_copy(ctx->keyid, ckey->keyid, QSMP_KEYID_SIZE);
		qsc_memutils_copy(ctx->config, QSMP_CONFIG_STRING, QSMP_CONFIG_SIZE);
		qsc_memutils_copy(ctx->verkey, ckey->verkey, QSMP_VERIFYKEY_SIZE);
		ctx->expiration = ckey->expiration;
		ctx->exflag = qsmp_flag_none;
	}
}

static qsmp_errors client_connect_request(qsmp_kex_client_state* ctx, qsmp_packet* packetout)
{
	assert(ctx != NULL);
	assert(packetout != NULL);

	qsc_keccak_state kstate = { 0 };
	qsmp_errors qerr;
	uint64_t tm;

	if (ctx != NULL && packetout != NULL)
	{
		tm = qsc_timestamp_epochtime_seconds();

		if (tm <= ctx->expiration)
		{
			qsc_memutils_clear(ctx->token, QSMP_STOKEN_SIZE);

			/* generate the session token */
			if (qsc_acp_generate(ctx->token, QSMP_STOKEN_SIZE) == true)
			{
				/* copy the key-id, token, and configuration string to the message */
				qsc_memutils_copy(packetout->message, ctx->keyid, QSMP_KEYID_SIZE);
				qsc_memutils_copy(((uint8_t*)packetout->message + QSMP_KEYID_SIZE), ctx->token, QSMP_STOKEN_SIZE);
				qsc_memutils_copy(((uint8_t*)packetout->message + QSMP_KEYID_SIZE + QSMP_STOKEN_SIZE), QSMP_CONFIG_STRING, QSMP_CONFIG_SIZE);
				/* assemble the connection-request packet */
				packetout->msglen = QSMP_KEYID_SIZE + QSMP_STOKEN_SIZE + QSMP_CONFIG_SIZE;
				packetout->flag = qsmp_flag_connect_request;
				packetout->sequence = ctx->txseq;

				/* store a hash of the session token, the configuration string, and the public signature key: pkh = H(stok || cfg || pvk) */
				qsc_memutils_clear(ctx->pkhash, QSMP_PKCODE_SIZE);
				qsc_sha3_initialize(&kstate);
				qsc_sha3_update(&kstate, qsc_keccak_rate_256, ctx->token, QSMP_STOKEN_SIZE);
				qsc_sha3_update(&kstate, qsc_keccak_rate_256, QSMP_CONFIG_STRING, QSMP_CONFIG_SIZE);
				qsc_sha3_update(&kstate, qsc_keccak_rate_256, ctx->verkey, QSMP_VERIFYKEY_SIZE);
				qsc_sha3_finalize(&kstate, qsc_keccak_rate_256, ctx->pkhash);

				qerr = qsmp_error_none;
				ctx->exflag = qsmp_flag_connect_request;
			}
			else
			{
				qerr = qsmp_error_random_failure;
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
		qerr = qsmp_error_invalid_input;
	}

	return qerr;
}

static qsmp_errors client_exstart_request(qsmp_kex_client_state* ctx, const qsmp_packet* packetin, qsmp_packet* packetout)
{
	assert(ctx != NULL);
	assert(packetin != NULL);
	assert(packetout != NULL);

	qsmp_errors qerr;
	uint8_t sec[QSMP_SECRET_SIZE] = { 0 };
	uint8_t khash[QSMP_PKCODE_SIZE] = { 0 };
	size_t mlen;
	size_t slen;

	if (ctx != NULL && packetin != NULL && packetout != NULL)
	{
		if (ctx->exflag == qsmp_flag_connect_request && packetin->flag == qsmp_flag_connect_response)
		{
			slen = 0;
			mlen = QSMP_SIGNATURE_SIZE + QSC_SHA3_256_HASH_SIZE;

			/* verify the asymmetric signature */
			if (qsmp_signature_verify(khash, &slen, packetin->message, mlen, ctx->verkey) == true)
			{
				uint8_t phash[QSC_SHA3_256_HASH_SIZE] = { 0 };
				uint8_t pubk[QSMP_PUBLICKEY_SIZE] = { 0 };

				qsc_memutils_copy(pubk, (packetin->message + mlen), QSMP_PUBLICKEY_SIZE);

				/* verify the public key hash */
				qsc_sha3_compute256(phash, pubk, QSMP_PUBLICKEY_SIZE);

				if (qsc_intutils_verify(phash, khash, QSC_SHA3_256_HASH_SIZE) == 0)
				{
					uint8_t prnd[QSC_KECCAK_256_RATE] = { 0 };
					qsc_keccak_state kstate = { 0 };

					/* generate and encapsulate the secret */
					qsc_memutils_clear(packetout->message, QSMP_MESSAGE_MAX);
					qsmp_cipher_encapsulate(sec, packetout->message, pubk, qsc_acp_generate);

					/* expand the secret with cshake adding the public verification keys hash; prand = Exp(sec, pkh) */
					qsc_cshake_initialize(&kstate, qsc_keccak_rate_256, sec, QSMP_SECRET_SIZE, NULL, 0, ctx->pkhash, QSMP_PKCODE_SIZE);
					qsc_cshake_squeezeblocks(&kstate, qsc_keccak_rate_256, prnd, 1);

					/* initialize the symmetric cipher, and raise client channel-1 tx */
					qsc_rcs_keyparams kp;
					kp.key = prnd;
					kp.keylen = QSC_RCS256_KEY_SIZE;
					kp.nonce = ((uint8_t*)prnd + QSC_RCS256_KEY_SIZE);
					kp.info = NULL;
					kp.infolen = 0;
					qsc_rcs_initialize(&ctx->txcpr, &kp, true);

					/* assemble the exstart-request packet */
					packetout->flag = qsmp_flag_exstart_request;
					packetout->msglen = QSMP_CIPHERTEXT_SIZE;
					packetout->sequence = ctx->txseq;

					qerr = qsmp_error_none;
					ctx->exflag = qsmp_flag_exstart_request;
				}
				else
				{
					qerr = qsmp_error_hash_invalid;
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

static qsmp_errors client_exchange_request(qsmp_kex_client_state* ctx, const qsmp_packet* packetin, qsmp_packet* packetout)
{
	assert(ctx != NULL);
	assert(packetin != NULL);
	assert(packetout != NULL);

	qsmp_errors qerr;

	if (ctx != NULL && packetin != NULL && packetout != NULL)
	{
		if (ctx->exflag == qsmp_flag_exstart_request && packetin->flag == qsmp_flag_exstart_response)
		{
			uint8_t hdr[QSMP_HEADER_SIZE] = { 0 };
			uint8_t msg[QSMP_PUBLICKEY_SIZE + QSMP_MACKEY_SIZE] = { 0 };

			/* generate the channel-2 keypair */
			qsmp_cipher_generate_keypair(ctx->pubkey, ctx->prikey, qsc_acp_generate);

			/* generate a mac-key and copy it to state */
			if (qsc_acp_generate(ctx->mackey, QSMP_MACKEY_SIZE) == true)
			{
				/* copy the mac-key and the encapsulation-key to the message */
				qsc_memutils_copy(msg, ctx->mackey, QSMP_MACKEY_SIZE);
				qsc_memutils_copy(((uint8_t*)msg + QSMP_MACKEY_SIZE), ctx->pubkey, QSMP_PUBLICKEY_SIZE);

				/* assemble the exchange-request packet */
				qsc_memutils_clear(packetout->message, QSMP_MESSAGE_MAX);
				packetout->flag = qsmp_flag_exchange_request;
				packetout->msglen = QSMP_MACKEY_SIZE + QSMP_PUBLICKEY_SIZE + QSC_RCS256_MAC_SIZE;
				packetout->sequence = ctx->txseq;

				/* serialize the packet header and add it to associated data */
				qsmp_packet_header_serialize(packetout, hdr);
				qsc_rcs_set_associated(&ctx->txcpr, hdr, QSMP_HEADER_SIZE);
				/* encrypt the public encryption key using the channel-1 */
				qsc_rcs_transform(&ctx->txcpr, packetout->message, msg, sizeof(msg));

				qerr = qsmp_error_none;
				ctx->exflag = qsmp_flag_exchange_request;
			}
			else
			{
				qerr = qsmp_error_random_failure;
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

static qsmp_errors client_establish_request(qsmp_kex_client_state* ctx, const qsmp_packet* packetin, qsmp_packet* packetout)
{
	assert(ctx != NULL);
	assert(packetin != NULL);
	assert(packetout != NULL);

	qsmp_errors qerr;

	if (ctx != NULL && packetin != NULL && packetout != NULL)
	{
		if (ctx->exflag == qsmp_flag_exchange_request && packetin->flag == qsmp_flag_exchange_response)
		{
			uint8_t kcode[QSMP_MACTAG_SIZE] = { 0 };

			/* mac the cipher-text */
			qsc_kmac256_compute(kcode, QSMP_MACTAG_SIZE, (packetin->message + QSMP_MACTAG_SIZE), QSMP_CIPHERTEXT_SIZE, ctx->mackey, QSMP_MACKEY_SIZE, NULL, 0);

			/* verify the mac code against the embedded cipher-text mac */
			if (qsc_intutils_verify(packetin->message, kcode, QSMP_MACTAG_SIZE) == 0)
			{
				uint8_t sec[QSMP_SECRET_SIZE] = { 0 };

				/* decapsulate the shared secret */
				if (qsmp_cipher_decapsulate(sec, (packetin->message + QSMP_MACTAG_SIZE), ctx->prikey) == true)
				{
					qsc_keccak_state kstate;
					uint8_t hdr[QSMP_HEADER_SIZE] = { 0 };
					uint8_t prnd[QSC_KECCAK_256_RATE] = { 0 };

					/* expand the shared secret */
					qsc_cshake_initialize(&kstate, qsc_keccak_rate_256, sec, QSMP_SECRET_SIZE, NULL, 0, ctx->pkhash, QSMP_PKCODE_SIZE);
					qsc_cshake_squeezeblocks(&kstate, qsc_keccak_rate_256, prnd, 1);

					/* initialize the symmetric cipher, and raise client channel-2 rx */
					qsc_rcs_keyparams kp;
					kp.key = prnd;
					kp.keylen = QSC_RCS256_KEY_SIZE;
					kp.nonce = ((uint8_t*)prnd + QSC_RCS256_KEY_SIZE);
					kp.info = NULL;
					kp.infolen = 0;
					qsc_rcs_initialize(&ctx->rxcpr, &kp, false);

					/* assemble the establish-request packet */
					qsc_memutils_clear(packetout->message, QSMP_MESSAGE_MAX);
					packetout->flag = qsmp_flag_establish_request;
					packetout->msglen = QSMP_STOKEN_SIZE + QSMP_MACTAG_SIZE;
					packetout->sequence = ctx->txseq;

					/* serialize the packet header and add it to the associated data */
					qsmp_packet_header_serialize(packetout, hdr);
					qsc_rcs_set_associated(&ctx->txcpr, hdr, QSMP_HEADER_SIZE);

					/* generate a random verification-token and store in the session token state */
					qsc_acp_generate(ctx->token, QSMP_STOKEN_SIZE);

					/* encrypt the token */
					qsc_rcs_transform(&ctx->txcpr, packetout->message, ctx->token, QSMP_STOKEN_SIZE);

					qerr = qsmp_error_none;
					ctx->exflag = qsmp_flag_session_establish_verify;
				}
				else
				{
					qerr = qsmp_error_decapsulation_failure;
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

static qsmp_errors client_establish_verify(qsmp_kex_client_state* ctx, const qsmp_packet* packetin)
{
	assert(ctx != NULL);
	assert(packetin != NULL);

	uint8_t hdr[QSMP_HEADER_SIZE] = { 0 };
	uint8_t msg[QSMP_STOKEN_SIZE] = { 0 };
	qsmp_errors qerr;

	if (ctx != NULL && packetin != NULL)
	{
		if (ctx->exflag == qsmp_flag_session_establish_verify && packetin->flag == qsmp_flag_establish_response)
		{
			/* serialize the packet header and add it to associated data */
			qsmp_packet_header_serialize(packetin, hdr);
			qsc_rcs_set_associated(&ctx->rxcpr, hdr, QSMP_HEADER_SIZE);

			/* authenticate and decrypt the cipher-text */
			if (qsc_rcs_transform(&ctx->rxcpr, msg, packetin->message, packetin->msglen - QSMP_MACTAG_SIZE) == true)
			{
				uint8_t vhash[QSMP_HASH_SIZE] = { 0 };

				/* hash the random verification-token */
				qsc_sha3_compute256(vhash, ctx->token, QSMP_STOKEN_SIZE);

				if (qsc_intutils_verify(vhash, msg, QSMP_HASH_SIZE) == 0)
				{
					ctx->exflag = qsmp_flag_session_established;
					qerr = qsmp_error_none;
				}
				else
				{
					ctx->exflag = qsmp_flag_none;
					qerr = qsmp_error_verify_failure;
				}
			}
			else
			{
				ctx->exflag = qsmp_flag_none;
				qerr = qsmp_error_authentication_failure;
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

static qsmp_errors client_key_exchange(qsmp_kex_client_state* ctx, qsc_socket* sock, const qsmp_client_key* ckey)
{
	assert(ctx != NULL);
	assert(sock != NULL);
	assert(ckey != NULL);

	uint8_t spct[QSMP_MESSAGE_MAX + 1] = { 0 };
	qsmp_packet reqt = { 0 };
	qsmp_packet resp = { 0 };
	qsmp_errors qerr;
	size_t plen;
	size_t rlen;
	size_t slen;

	if (ctx != NULL && sock != NULL && ckey != NULL)
	{
		/* initialize the client */
		client_state_initialize(ctx, ckey);
		/* create the connection request packet */
		qerr = client_connect_request(ctx, &reqt);

		if (qerr == qsmp_error_none)
		{
			/* convert the packet to bytes */
			plen = qsmp_packet_to_stream(&reqt, spct);
			/* send the connection request */
			slen = qsc_socket_send(sock, spct, plen, qsc_socket_send_flag_none);
			qsc_memutils_clear(spct, sizeof(spct));

			if (slen == plen + QSC_SOCKET_TERMINATOR_SIZE)
			{
				ctx->txseq += 1;
				/* blocking receive waits for server */
				rlen = qsc_socket_receive(sock, spct, sizeof(spct), qsc_socket_receive_flag_none);

				if (rlen == QSMP_CONNECT_RESPONSE_SIZE + QSC_SOCKET_TERMINATOR_SIZE)
				{
					/* convert server response to packet */
					qsmp_stream_to_packet(spct, &resp);
					qsc_memutils_clear(spct, sizeof(spct));

					if (resp.sequence == ctx->rxseq)
					{
						ctx->rxseq += 1;

						if (resp.flag == qsmp_flag_connect_response)
						{
							/* clear the request packet */
							qsmp_packet_clear(&reqt);
							/* create the exstart request packet */
							qerr = client_exstart_request(ctx, &resp, &reqt);
						}
						else
						{
							/* if we receive an error, set the error flag from the packet */
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
			}
			else
			{
				qerr = qsmp_error_transmit_failure;
			}
		}

		if (qerr == qsmp_error_none)
		{
			qsmp_packet_clear(&resp);
			plen = qsmp_packet_to_stream(&reqt, spct);
			/* send exstart request */
			slen = qsc_socket_send(sock, spct, plen, qsc_socket_send_flag_none);
			qsc_memutils_clear(spct, sizeof(spct));

			if (slen == plen + QSC_SOCKET_TERMINATOR_SIZE)
			{
				ctx->txseq += 1;
				/* wait for exstart response */
				rlen = qsc_socket_receive(sock, spct, sizeof(spct), qsc_socket_receive_flag_none);

				if (rlen == QSMP_EXSTART_RESPONSE_SIZE + QSC_SOCKET_TERMINATOR_SIZE)
				{
					qsmp_stream_to_packet(spct, &resp);
					qsc_memutils_clear(spct, sizeof(spct));

					if (resp.sequence == ctx->rxseq)
					{
						ctx->rxseq += 1;

						if (resp.flag == qsmp_flag_exstart_response)
						{
							qsmp_packet_clear(&reqt);
							/* create the exchange request packet */
							qerr = client_exchange_request(ctx, &resp, &reqt);
						}
						else
						{
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
			qsmp_packet_clear(&resp);
			plen = qsmp_packet_to_stream(&reqt, spct);
			slen = qsc_socket_send(sock, spct, plen, qsc_socket_send_flag_none);
			qsc_memutils_clear(spct, sizeof(spct));

			if (slen == plen + QSC_SOCKET_TERMINATOR_SIZE)
			{
				ctx->txseq += 1;
				rlen = qsc_socket_receive(sock, spct, sizeof(spct), qsc_socket_receive_flag_none);

				if (rlen == QSMP_EXCHANGE_RESPONSE_SIZE + QSC_SOCKET_TERMINATOR_SIZE)
				{
					qsmp_stream_to_packet(spct, &resp);
					qsc_memutils_clear(spct, sizeof(spct));

					if (resp.sequence == ctx->rxseq)
					{
						ctx->rxseq += 1;

						if (resp.flag == qsmp_flag_exchange_response)
						{
							qsmp_packet_clear(&reqt);
							/* create the establish request packet */
							qerr = client_establish_request(ctx, &resp, &reqt);
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
			qsmp_packet_clear(&resp);
			plen = qsmp_packet_to_stream(&reqt, spct);
			slen = qsc_socket_send(sock, spct, plen, qsc_socket_send_flag_none);
			qsc_memutils_clear(spct, sizeof(spct));

			if (slen == plen + QSC_SOCKET_TERMINATOR_SIZE)
			{
				ctx->txseq += 1;
				rlen = qsc_socket_receive(sock, spct, sizeof(spct), qsc_socket_receive_flag_none);
				qsmp_stream_to_packet(spct, &resp);
				qsc_memutils_clear(spct, sizeof(spct));

				if (rlen == QSMP_ESTABLISH_RESPONSE_SIZE + QSC_SOCKET_TERMINATOR_SIZE)
				{
					if (resp.sequence == ctx->rxseq)
					{
						ctx->rxseq += 1;

						if (resp.flag == qsmp_flag_establish_response)
						{
							/* verify the exchange  */
							qerr = client_establish_verify(ctx, &resp);
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

		client_kex_reset(ctx);

		if (qerr != qsmp_error_none)
		{
			if (sock->connection_status == qsc_socket_state_connected)
			{
				qsmp_client_send_error(sock, qerr);
				qsc_socket_shut_down(sock, qsc_socket_shut_down_flag_both);
			}

			client_state_dispose(ctx);
		}
	}
	else
	{
		qerr = qsmp_error_invalid_input;
	}

	return qerr;
}

/* Helper Functions */

bool qsmp_client_decode_public_key(qsmp_client_key* clientkey, const char input[QSMP_PUBKEY_STRING_SIZE])
{
	assert(clientkey != NULL);

	char dtm[QSC_TIMESTAMP_STRING_SIZE] = { 0 };
	char tmpvk[QSMP_PUBKEY_ENCODING_SIZE] = { 0 };
	size_t spos;
	size_t slen;
	bool res;

	res = false;

	if (clientkey != NULL)
	{
		spos = sizeof(QSMP_PUBKEY_HEADER) + sizeof(QSMP_PUBKEY_VERSION) + sizeof(QSMP_PUBKEY_CONFIG_PREFIX) - 1;
		slen = QSMP_CONFIG_SIZE - 1;
		qsc_memutils_copy(clientkey->config, (input + spos), slen);

		spos += slen + sizeof(QSMP_PUBKEY_EXPIRATION_PREFIX) - 3;
		qsc_intutils_hex_to_bin((input + spos), clientkey->keyid, QSMP_KEYID_SIZE * 2);

		spos += (QSMP_KEYID_SIZE * 2) + sizeof(QSMP_PUBKEY_EXPIRATION_PREFIX);
		slen = QSC_TIMESTAMP_STRING_SIZE - 1;
		qsc_memutils_copy(dtm, (input + spos), slen);
		clientkey->expiration = qsc_timestamp_datetime_to_seconds(dtm);
		spos += QSC_TIMESTAMP_STRING_SIZE;

		qsc_stringutils_remove_line_breaks(tmpvk, sizeof(tmpvk), (input + spos), (QSMP_PUBKEY_STRING_SIZE - (spos + sizeof(QSMP_PUBKEY_FOOTER))));
		res = qsc_encoding_base64_decode(clientkey->verkey, QSMP_VERIFYKEY_SIZE, tmpvk, QSMP_PUBKEY_ENCODING_SIZE);
	}

	return res;
}

void qsmp_client_send_error(const qsc_socket* sock, qsmp_errors error)
{
	assert(sock != NULL);

	qsmp_packet resp = { 0 };
	uint8_t spct[QSMP_MESSAGE_MAX] = { 0 };
	size_t plen;

	if (sock != NULL)
	{
		if (qsc_socket_is_connected(sock) == true)
		{
			resp.flag = qsmp_flag_error_condition;
			resp.sequence = 0xFF;
			resp.msglen = 1;
			resp.message[0] = (uint8_t)error;
			plen = qsmp_packet_to_stream(&resp, spct);
			qsc_socket_send(sock, spct, plen, qsc_socket_send_flag_none);
		}
	}
}

/* Public Functions */

void qsmp_client_connection_close(qsmp_kex_client_state* ctx, const qsc_socket* sock, qsmp_errors error)
{
	assert(ctx != NULL);
	assert(sock != NULL);

	if (ctx != NULL && sock != NULL)
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
		client_state_dispose(ctx);
	}
}

qsmp_errors qsmp_client_connect_ipv4(qsmp_kex_client_state* ctx, qsc_socket* sock, const qsmp_client_key* ckey, const qsc_ipinfo_ipv4_address* address, uint16_t port)
{
	assert(ctx != NULL);
	assert(sock != NULL);
	assert(ckey != NULL);
	assert(address != NULL);

	qsc_socket_exceptions serr;
	qsmp_errors qerr;

	qerr = qsmp_error_invalid_input;

	if (ctx != NULL && sock != NULL && ckey != NULL && address != NULL)
	{

		qsc_socket_client_initialize(sock);
		serr = qsc_socket_client_connect_ipv4(sock, address, port);

		if (serr == qsc_socket_exception_success)
		{
			qerr = client_key_exchange(ctx, sock, ckey);
		}
		else
		{
			qerr = qsmp_error_connection_failure;
		}
	}
	else
	{
		qerr = qsmp_error_invalid_input;
	}

	return qerr;
}

qsmp_errors qsmp_client_connect_ipv6(qsmp_kex_client_state* ctx, qsc_socket* sock, const qsmp_client_key* ckey, const qsc_ipinfo_ipv6_address* address, uint16_t port)
{
	assert(ctx != NULL);
	assert(sock != NULL);
	assert(ckey != NULL);
	assert(address != NULL);

	qsc_socket_exceptions serr;
	qsmp_errors qerr;

	qerr = qsmp_error_invalid_input;

	if (ctx != NULL && sock != NULL && ckey != NULL && address != NULL)
	{
		qsc_socket_client_initialize(sock);
		serr = qsc_socket_client_connect_ipv6(sock, address, port);

		if (serr == qsc_socket_exception_success)
		{
			qerr = client_key_exchange(ctx, sock, ckey);
		}
		else
		{
			qerr = qsmp_error_connection_failure;
		}
	}
	else
	{
		qerr = qsmp_error_invalid_input;
	}

	return qerr;
}

qsmp_errors qsmp_client_decrypt_packet(qsmp_kex_client_state* ctx, const qsmp_packet* packetin, uint8_t* message, size_t* msglen)
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
			else if (ctx->exflag != qsmp_flag_keep_alive_request)
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
	else
	{
		qerr = qsmp_error_invalid_input;
	}

	return qerr;
}

qsmp_errors qsmp_client_encrypt_packet(qsmp_kex_client_state* ctx, const uint8_t* message, size_t msglen, qsmp_packet* packetout)
{
	assert(ctx != NULL);
	assert(message != NULL);
	assert(packetout != NULL);

	qsmp_errors qerr;

	if (ctx != NULL && packetout != NULL && message != NULL)
	{
		if (ctx->exflag == qsmp_flag_session_established)
		{
			uint8_t hdr[QSMP_HEADER_SIZE] = { 0 };

			/* assemble the encryption packet */
			ctx->txseq += 1;
			qsc_memutils_clear(packetout->message, QSMP_MESSAGE_MAX);
			packetout->flag = qsmp_flag_encrypted_message;
			packetout->msglen = (uint32_t)msglen + QSC_RCS256_MAC_SIZE;
			packetout->sequence= ctx->txseq;

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
	else
	{
		qerr = qsmp_error_invalid_input;
	}

	return qerr;
}

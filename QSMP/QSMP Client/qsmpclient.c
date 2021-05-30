#include "qsmpclient.h"
#include "../QSC/acp.h"
#include "../QSC/encoding.h"
#include "../QSC/intutils.h"
#include "../QSC/memutils.h"
#include "../QSC/sha3.h"
#include "../QSC/stringutils.h"
#include "../QSC/timestamp.h"

#if defined(QSC_QSMP_PUBKEY_SPHINCS)
#	define qsc_qsmp_cipher_generate_keypair qsc_mceliece_generate_keypair
#	define qsc_qsmp_cipher_decapsulate qsc_mceliece_decapsulate
#	define qsc_qsmp_cipher_encapsulate qsc_mceliece_encapsulate
#	define qsc_qsmp_signature_sign qsc_sphincsplus_sign
#	define qsc_qsmp_signature_verify qsc_sphincsplus_verify
#else
#	define qsc_qsmp_cipher_generate_keypair qsc_kyber_generate_keypair
#	define qsc_qsmp_cipher_decapsulate qsc_kyber_decapsulate
#	define qsc_qsmp_cipher_encapsulate qsc_kyber_encapsulate
#	define qsc_qsmp_signature_sign qsc_dilithium_sign
#	define qsc_qsmp_signature_verify qsc_dilithium_verify
#endif

/* Private Functions */

static void qsc_qsmp_client_dispose(qsc_qsmp_kex_client_state* ctx)
{
	assert(ctx != NULL);

	if (ctx != NULL)
	{
		qsc_rcs_dispose(&ctx->rxcpr);
		qsc_rcs_dispose(&ctx->txcpr);
		qsc_memutils_clear(ctx->config, sizeof(ctx->config));
		qsc_memutils_clear(ctx->keyid, sizeof(ctx->keyid));
		qsc_memutils_clear(ctx->pkhash, sizeof(ctx->pkhash));
		qsc_memutils_clear(ctx->prikey, sizeof(ctx->prikey));
		qsc_memutils_clear(ctx->pubkey, sizeof(ctx->pubkey));
		qsc_memutils_clear(ctx->token, sizeof(ctx->token));
		qsc_memutils_clear(ctx->verkey, sizeof(ctx->verkey));
		ctx->exflag = 0;
		ctx->expiration = 0;
		ctx->rxseq = 0;
		ctx->txseq = 0;
	}
}

static void qsc_qsmp_client_kex_reset(qsc_qsmp_kex_client_state* ctx)
{
	qsc_memutils_clear(ctx->config, sizeof(ctx->config));
	qsc_memutils_clear(ctx->keyid, sizeof(ctx->keyid));
	qsc_memutils_clear(ctx->mackey, sizeof(ctx->mackey));
	qsc_memutils_clear(ctx->pkhash, sizeof(ctx->pkhash));
	qsc_memutils_clear(ctx->prikey, sizeof(ctx->prikey));
	qsc_memutils_clear(ctx->pubkey, sizeof(ctx->pubkey));
	qsc_memutils_clear(ctx->verkey, sizeof(ctx->verkey));
	qsc_memutils_clear(ctx->token, sizeof(ctx->token));
	ctx->expiration = 0;
}

static void qsc_qsmp_client_initialize(qsc_qsmp_kex_client_state* ctx, const qsc_qsmp_client_key* ckey)
{
	assert(ckey != NULL);
	assert(ctx != NULL);

	if (ckey != NULL && ctx != NULL)
	{
		qsc_qsmp_client_dispose(ctx);
		qsc_memutils_copy(ctx->keyid, ckey->keyid, QSC_QSMP_KEYID_SIZE);
		qsc_memutils_copy(ctx->config, QSC_QSMP_CONFIG_STRING, QSC_QSMP_CONFIG_SIZE);
		qsc_memutils_copy(ctx->verkey, ckey->verkey, sizeof(ctx->verkey));
		ctx->expiration = ckey->expiration;
		ctx->exflag = qsc_qsmp_message_none;
	}
}

static qsc_qsmp_errors qsc_qsmp_client_connection_request(qsc_qsmp_kex_client_state* ctx, qsc_qsmp_packet* packetout)
{
	assert(ctx != NULL);
	assert(packetout != NULL);

	qsc_keccak_state kstate = { 0 };
	qsc_qsmp_errors res;
	uint64_t tm;

	res = qsc_qsmp_error_invalid_input;

	if (ctx != NULL && packetout != NULL)
	{
		tm = qsc_timestamp_epochtime_seconds();

		if (tm <= ctx->expiration)
		{
			/* generate the session token */
			qsc_memutils_clear(ctx->token, QSC_QSMP_STOKEN_SIZE);

			if (qsc_acp_generate(ctx->token, QSC_QSMP_STOKEN_SIZE) == true)
			{
				/* assign the packet parameters */
				qsc_memutils_copy(packetout->message, ctx->keyid, QSC_QSMP_KEYID_SIZE);
				qsc_memutils_copy(((uint8_t*)packetout->message + QSC_QSMP_KEYID_SIZE), ctx->token, QSC_QSMP_STOKEN_SIZE);
				qsc_memutils_copy(((uint8_t*)packetout->message + QSC_QSMP_KEYID_SIZE + QSC_QSMP_STOKEN_SIZE), QSC_QSMP_CONFIG_STRING, QSC_QSMP_CONFIG_SIZE);
				/* assemble the connection-request packet */
				packetout->msglen = QSC_QSMP_KEYID_SIZE + QSC_QSMP_STOKEN_SIZE + QSC_QSMP_CONFIG_SIZE;
				packetout->flag = qsc_qsmp_message_connect_request;
				packetout->sequence = ctx->txseq;

				/* store a hash of the session token, the configuration string, and the public signature key: pkh = H(stok || cfg || psk) */
				qsc_memutils_clear(ctx->pkhash, QSC_QSMP_PKCODE_SIZE);
				qsc_sha3_initialize(&kstate);
				qsc_sha3_update(&kstate, keccak_rate_256, packetout->message, QSC_QSMP_STOKEN_SIZE + QSC_QSMP_CONFIG_SIZE);
				qsc_sha3_update(&kstate, keccak_rate_256, ctx->verkey, QSC_QSMP_VERIFYKEY_SIZE);
				qsc_sha3_finalize(&kstate, keccak_rate_256, ctx->pkhash);

				res = qsc_qsmp_error_none;
				ctx->exflag = qsc_qsmp_message_connect_request;
			}
			else
			{
				ctx->exflag = qsc_qsmp_message_none;
				res = qsc_qsmp_error_random_failure;
			}
		}
		else
		{
			ctx->exflag = qsc_qsmp_message_none;
			res = qsc_qsmp_error_key_expired;
		}
	}

	return res;
}

static qsc_qsmp_errors qsc_qsmp_client_exstart_request(qsc_qsmp_kex_client_state* ctx, const qsc_qsmp_packet* packetin, qsc_qsmp_packet* packetout)
{
	assert(ctx != NULL);
	assert(packetin != NULL);
	assert(packetout != NULL);

	qsc_qsmp_errors res;
	uint8_t sec[QSC_QSMP_SECRET_SIZE] = { 0 };
	uint8_t khash[QSC_QSMP_PKCODE_SIZE] = { 0 };
	size_t mlen;
	size_t slen;

	res = qsc_qsmp_error_invalid_input;

	if (ctx != NULL && packetin != NULL && packetout != NULL)
	{
		if (ctx->exflag == qsc_qsmp_message_connect_request && packetin->flag == qsc_qsmp_message_connect_response)
		{
			slen = 0;
			mlen = QSC_QSMP_SIGNATURE_SIZE + QSC_SHA3_256_HASH_SIZE;

			if (qsc_qsmp_signature_verify(khash, &slen, packetin->message, mlen, ctx->verkey) == true)
			{
				uint8_t phash[QSC_SHA3_256_HASH_SIZE] = { 0 };
				uint8_t pubk[QSC_QSMP_PUBLICKEY_SIZE] = { 0 };

				qsc_memutils_copy(pubk, ((uint8_t*)packetin->message + mlen), QSC_QSMP_PUBLICKEY_SIZE);

				/* verify the public key hash */
				qsc_sha3_compute256(phash, pubk, QSC_QSMP_PUBLICKEY_SIZE);

				if (qsc_intutils_verify(phash, khash, QSC_SHA3_256_HASH_SIZE) == 0)
				{
					uint8_t prnd[QSC_KECCAK_256_RATE] = { 0 };
					qsc_keccak_state kstate = { 0 };

					/* generate and encapsulate the secret */
					qsc_memutils_clear(packetout->message, sizeof(packetout->message));
					qsc_qsmp_cipher_encapsulate(sec, packetout->message, pubk, qsc_acp_generate);

					/* expand the secret with cshake (P) adding the public verification keys hash; prand = P(pv || sec) */
					qsc_cshake_initialize(&kstate, keccak_rate_256, sec, QSC_QSMP_SECRET_SIZE, NULL, 0, ctx->pkhash, QSC_QSMP_PKCODE_SIZE);
					qsc_cshake_squeezeblocks(&kstate, keccak_rate_256, prnd, 1);

					/* initialize the symmetric cipher, and raise client channel-1 tx */
					qsc_rcs_keyparams kp;
					kp.key = prnd;
					kp.keylen = QSC_RCS256_KEY_SIZE;
					kp.nonce = ((uint8_t*)prnd + QSC_RCS256_KEY_SIZE);
					kp.info = NULL;
					kp.infolen = 0;
					qsc_rcs_initialize(&ctx->txcpr, &kp, true);

					/* assemble the exstart-request packet */
					packetout->flag = qsc_qsmp_message_exstart_request;
					packetout->msglen = QSC_QSMP_CIPHERTEXT_SIZE;
					packetout->sequence = ctx->txseq;

					res = qsc_qsmp_error_none;
					ctx->exflag = qsc_qsmp_message_exstart_request;
				}
				else
				{
					qsc_qsmp_packet_error_message(packetout, qsc_qsmp_error_hash_invalid);
					res = qsc_qsmp_error_hash_invalid;
					ctx->exflag = qsc_qsmp_message_none;
				}
			}
			else
			{
				qsc_qsmp_packet_error_message(packetout, qsc_qsmp_error_auth_failure);
				res = qsc_qsmp_error_auth_failure;
				ctx->exflag = qsc_qsmp_message_none;
			}
		}
		else
		{
			qsc_qsmp_packet_error_message(packetout, qsc_qsmp_error_invalid_request);
			ctx->exflag = qsc_qsmp_message_none;
			res = qsc_qsmp_error_invalid_request;
		}
	}

	return res;
}

static qsc_qsmp_errors qsc_qsmp_client_exchange_request(qsc_qsmp_kex_client_state* ctx, const qsc_qsmp_packet* packetin, qsc_qsmp_packet* packetout)
{
	assert(ctx != NULL);
	assert(packetin != NULL);
	assert(packetout != NULL);

	qsc_qsmp_errors res;

	res = qsc_qsmp_error_invalid_input;

	if (ctx != NULL && packetin != NULL && packetout != NULL)
	{
		if (ctx->exflag == qsc_qsmp_message_exstart_request && packetin->flag == qsc_qsmp_message_exstart_response)
		{
			uint8_t hdr[QSC_QSMP_HEADER_SIZE] = { 0 };
			uint8_t msg[QSC_QSMP_PUBLICKEY_SIZE + QSC_QSMP_MACKEY_SIZE] = { 0 };

			/* generate the channel-2 keypair */
			qsc_qsmp_cipher_generate_keypair(ctx->pubkey, ctx->prikey, qsc_acp_generate);
			/* generate a mac-key and copy it to state */
			qsc_acp_generate(ctx->mackey, QSC_QSMP_MACKEY_SIZE);
			/* copy the mac-key and the encapsulation-key to the message */
			qsc_memutils_copy(msg, ctx->mackey, QSC_QSMP_MACKEY_SIZE);
			qsc_memutils_copy(((uint8_t*)msg + QSC_QSMP_MACKEY_SIZE), ctx->pubkey, QSC_QSMP_PUBLICKEY_SIZE);

			/* assemble the exchange-request packet */
			qsc_memutils_clear(packetout->message, sizeof(packetout->message));
			packetout->flag = qsc_qsmp_message_exchange_request;
			packetout->msglen = QSC_QSMP_MACKEY_SIZE + QSC_QSMP_PUBLICKEY_SIZE + QSC_RCS256_MAC_SIZE;
			packetout->sequence = ctx->txseq;

			/* serialize the packet header and add it to associated data */
			qsc_qsmp_packet_header_serialize(packetout, hdr);
			qsc_rcs_set_associated(&ctx->txcpr, hdr, QSC_QSMP_HEADER_SIZE);
			/* encrypt the public encryption key using the channel-1 VPN */
			qsc_rcs_transform(&ctx->txcpr, packetout->message, msg, sizeof(msg));

			res = qsc_qsmp_error_none;
			ctx->exflag = qsc_qsmp_message_exchange_request;

		}
		else
		{
			qsc_qsmp_packet_error_message(packetout, qsc_qsmp_error_invalid_request);
			ctx->exflag = qsc_qsmp_message_none;
			res = qsc_qsmp_error_invalid_request;
		}
	}

	return res;
}

static qsc_qsmp_errors qsc_qsmp_client_establish_request(qsc_qsmp_kex_client_state* ctx, const qsc_qsmp_packet* packetin, qsc_qsmp_packet* packetout)
{
	assert(ctx != NULL);
	assert(packetin != NULL);
	assert(packetout != NULL);

	qsc_qsmp_errors res;

	res = qsc_qsmp_error_invalid_input;

	if (ctx != NULL && packetin != NULL && packetout != NULL)
	{
		if (ctx->exflag == qsc_qsmp_message_exchange_request && packetin->flag == qsc_qsmp_message_exchange_response)
		{
			uint8_t kcode[QSC_QSMP_MACTAG_SIZE] = { 0 };

			/* mac the cipher-text */
			qsc_kmac256_compute(kcode, QSC_QSMP_MACTAG_SIZE, ((uint8_t*)packetin->message + QSC_QSMP_MACTAG_SIZE), QSC_QSMP_CIPHERTEXT_SIZE, ctx->mackey, QSC_QSMP_MACKEY_SIZE, NULL, 0);

			/* verify the code against the embedded cipher-text mac */
			if (qsc_intutils_verify(packetin->message, kcode, QSC_QSMP_MACTAG_SIZE) == 0)
			{
				uint8_t sec[QSC_QSMP_SECRET_SIZE] = { 0 };

				/* decapsulate the shared secret */
				if (qsc_qsmp_cipher_decapsulate(sec, ((uint8_t*)packetin->message + QSC_QSMP_MACTAG_SIZE), ctx->prikey) == true)
				{
					qsc_keccak_state kstate;
					uint8_t prnd[QSC_KECCAK_256_RATE] = { 0 };

					/* expand the shared secret */
					qsc_cshake_initialize(&kstate, keccak_rate_256, sec, QSC_QSMP_SECRET_SIZE, NULL, 0, ctx->pkhash, QSC_QSMP_PKCODE_SIZE);
					qsc_cshake_squeezeblocks(&kstate, keccak_rate_256, prnd, 1);

					/* initialize the symmetric cipher, and raise client channel-2 rx */
					qsc_rcs_keyparams kp;
					kp.key = prnd;
					kp.keylen = QSC_RCS256_KEY_SIZE;
					kp.nonce = ((uint8_t*)prnd + QSC_RCS256_KEY_SIZE);
					kp.info = NULL;
					kp.infolen = 0;
					qsc_rcs_initialize(&ctx->rxcpr, &kp, false);

					/* assemble the establish-request packet */
					qsc_memutils_clear(packetout->message, sizeof(packetout->message));
					packetout->flag = qsc_qsmp_message_establish_request;
					packetout->msglen = 0;
					packetout->sequence = ctx->txseq;

					res = qsc_qsmp_error_none;
					ctx->exflag = qsc_qsmp_message_session_established;
				}
				else
				{
					qsc_qsmp_packet_error_message(packetout, qsc_qsmp_error_decapsulation_failure);
					res = qsc_qsmp_error_decapsulation_failure;
					ctx->exflag = qsc_qsmp_message_none;
				}
			}
			else
			{
				qsc_qsmp_packet_error_message(packetout, qsc_qsmp_error_auth_failure);
				res = qsc_qsmp_error_auth_failure;
				ctx->exflag = qsc_qsmp_message_none;
			}
		}
		else
		{
			qsc_qsmp_packet_error_message(packetout, qsc_qsmp_error_invalid_request);
			ctx->exflag = qsc_qsmp_message_none;
			res = qsc_qsmp_error_invalid_request;
		}
	}

	return res;
}

static qsc_qsmp_errors qsc_qsmp_client_kex(qsc_qsmp_kex_client_state* ctx, qsc_socket* sock, const qsc_qsmp_client_key* ckey)
{
	uint8_t spct[QSC_QSMP_MESSAGE_MAX + 1] = { 0 };
	qsc_qsmp_packet reqt = { 0 };
	qsc_qsmp_packet resp = { 0 };
	qsc_qsmp_errors qerr;
	size_t plen;
	size_t rlen;
	size_t slen;

	/* initialize the client */
	qsc_qsmp_client_initialize(ctx, ckey);
	/* create the connection request packet */
	qerr = qsc_qsmp_client_connection_request(ctx, &reqt);

	if (qerr == qsc_qsmp_error_none)
	{
		/* convert the packet to bytes */
		plen = qsc_qsmp_packet_to_stream(&reqt, spct);
		/* send the connection request */
		slen = qsc_socket_send(sock, spct, plen, qsc_socket_send_flag_none);

		if (slen >= plen)
		{
			ctx->txseq += 1;
			/* blocking receive waits for server */
			rlen = qsc_socket_receive(sock, spct, sizeof(spct), qsc_socket_receive_flag_none);

			if (rlen > 0)
			{
				/* convert server response to packet */
				qsc_qsmp_stream_to_packet(spct, &resp);

				if (resp.sequence == ctx->rxseq)
				{
					ctx->rxseq += 1;

					if (resp.flag == qsc_qsmp_message_connect_response)
					{
						/* clear the request packet */
						qsc_qsmp_packet_clear(&reqt);
						/* create the exstart request packet */
						qerr = qsc_qsmp_client_exstart_request(ctx, &resp, &reqt);
					}
					else
					{
						/* if we receive an error, set the error flag from the packet */
						if (resp.flag == qsc_qsmp_message_error_condition)
						{
							qerr = (qsc_qsmp_errors)resp.message[0];
						}
						else
						{
							qerr = qsc_qsmp_error_connect_failure;
							qsc_qsmp_client_send_error(sock, qerr);
						}
					}
				}
				else
				{
					qerr = qsc_qsmp_error_packet_unsequenced;
					qsc_qsmp_client_send_error(sock, qerr);
				}
			}
			else
			{
				qerr = qsc_qsmp_error_receive_failure;
				qsc_qsmp_client_send_error(sock, qerr);
			}
		}
		else
		{
			qerr = qsc_qsmp_error_transmit_failure;
			qsc_qsmp_client_send_error(sock, qerr);
		}
	}
	else
	{
		qerr = qsc_qsmp_error_connection_failure;
		qsc_qsmp_client_send_error(sock, qerr);
	}

	if (qerr == qsc_qsmp_error_none)
	{
		qsc_qsmp_packet_clear(&resp);
		plen = qsc_qsmp_packet_to_stream(&reqt, spct);
		/* send exstart request */
		slen = qsc_socket_send(sock, spct, plen, qsc_socket_send_flag_none);

		if (slen >= plen)
		{
			ctx->txseq += 1;
			/* wait for exstart response */
			rlen = qsc_socket_receive(sock, spct, sizeof(spct), qsc_socket_receive_flag_none);

			if (rlen > 0)
			{
				qsc_qsmp_stream_to_packet(spct, &resp);

				if (resp.sequence == ctx->rxseq)
				{
					ctx->rxseq += 1;

					if (resp.flag == qsc_qsmp_message_exstart_response)
					{
						qsc_qsmp_packet_clear(&reqt);
						/* create the exchange request packet */
						qerr = qsc_qsmp_client_exchange_request(ctx, &resp, &reqt);
					}
					else
					{
						if (resp.flag == qsc_qsmp_message_error_condition)
						{
							qerr = (qsc_qsmp_errors)resp.message[0];
						}
						else
						{
							qerr = qsc_qsmp_error_exstart_failure;
							qsc_qsmp_client_send_error(sock, qerr);
						}
					}
				}
				else
				{
					qerr = qsc_qsmp_error_packet_unsequenced;
					qsc_qsmp_client_send_error(sock, qerr);
				}
			}
			else
			{
				qerr = qsc_qsmp_error_receive_failure;
				qsc_qsmp_client_send_error(sock, qerr);
			}
		}
		else
		{
			qerr = qsc_qsmp_error_transmit_failure;
			qsc_qsmp_client_send_error(sock, qerr);
		}
	}
	else
	{
		qerr = qsc_qsmp_error_exstart_failure;
		qsc_qsmp_client_send_error(sock, qerr);
	}

	if (qerr == qsc_qsmp_error_none)
	{
		qsc_qsmp_packet_clear(&resp);
		plen = qsc_qsmp_packet_to_stream(&reqt, spct);
		slen = qsc_socket_send(sock, spct, plen, qsc_socket_send_flag_none);

		if (slen >= plen)
		{
			ctx->txseq += 1;
			rlen = qsc_socket_receive(sock, spct, sizeof(spct), qsc_socket_receive_flag_none);

			if (rlen > 0)
			{
				qsc_qsmp_stream_to_packet(spct, &resp);

				if (resp.sequence == ctx->rxseq)
				{
					ctx->rxseq += 1;

					if (resp.flag == qsc_qsmp_message_exchange_response)
					{
						qsc_qsmp_packet_clear(&reqt);
						/* create the establish request packet */
						qerr = qsc_qsmp_client_establish_request(ctx, &resp, &reqt);
					}
					else
					{
						if (resp.flag == qsc_qsmp_message_error_condition)
						{
							qerr = (qsc_qsmp_errors)resp.message[0];
						}
						else
						{
							qerr = qsc_qsmp_error_exchange_failure;
							qsc_qsmp_client_send_error(sock, qerr);
						}
					}
				}
				else
				{
					qerr = qsc_qsmp_error_packet_unsequenced;
					qsc_qsmp_client_send_error(sock, qerr);
				}
			}
			else
			{
				qerr = qsc_qsmp_error_receive_failure;
				qsc_qsmp_client_send_error(sock, qerr);
			}
		}
		else
		{
			qerr = qsc_qsmp_error_transmit_failure;
			qsc_qsmp_client_send_error(sock, qerr);
		}
	}
	else
	{
		qerr = qsc_qsmp_error_exchange_failure;
		qsc_qsmp_client_send_error(sock, qerr);
	}

	if (qerr == qsc_qsmp_error_none)
	{
		qsc_qsmp_packet_clear(&resp);
		plen = qsc_qsmp_packet_to_stream(&reqt, spct);
		slen = qsc_socket_send(sock, spct, plen, qsc_socket_send_flag_none);

		if (slen >= plen)
		{
			ctx->txseq += 1;
			rlen = qsc_socket_receive(sock, spct, sizeof(spct), qsc_socket_receive_flag_none);
			qsc_qsmp_stream_to_packet(spct, &resp);

			if (rlen == 0 || (qsc_qsmp_flags)resp.message[0] != qsc_qsmp_message_session_established)
			{
				qerr = qsc_qsmp_error_receive_failure;
			}
			else
			{
				ctx->rxseq += 1;
			}
		}
		else
		{
			qerr = qsc_qsmp_error_transmit_failure;
			qsc_qsmp_client_send_error(sock, qerr);
		}
	}
	else
	{
		qerr = qsc_qsmp_error_establish_failure;
		qsc_qsmp_client_send_error(sock, qerr);
	}

	if (qerr == qsc_qsmp_error_none)
	{
		qsc_qsmp_client_kex_reset(ctx);
	}
	else
	{
		qsc_qsmp_client_dispose(ctx);
	}

	return qerr;
}

/* Helper Functions */

void qsc_qsmp_client_decode_public_key(qsc_qsmp_client_key* clientkey, const char input[QSC_QSMP_PUBKEY_STRING_SIZE])
{
	assert(clientkey != NULL);

	char dtm[QSC_TIMESTAMP_STRING_SIZE] = { 0 };
	char keyid[QSC_QSMP_KEYID_SIZE] = { 0 };
	char tmpvk[QSC_QSMP_PUBKEY_ENCODING_SIZE] = { 0 };
	size_t spos;
	size_t slen;

	if (clientkey != NULL)
	{
		spos = sizeof(QSC_QSMP_PUBKEY_HEADER) + sizeof(QSC_QSMP_PUBKEY_VERSION) + sizeof(QSC_QSMP_PUBKEY_CONFIG_PREFIX) - 1;
		slen = QSC_QSMP_CONFIG_SIZE - 1;
		qsc_memutils_copy(clientkey->config, ((uint8_t*)input + spos), slen);

		spos += slen + sizeof(QSC_QSMP_PUBKEY_EXPIRATION_PREFIX) - 3;
		qsc_intutils_hex_to_bin(((char*)input + spos), clientkey->keyid, QSC_QSMP_KEYID_SIZE * 2);

		spos += (QSC_QSMP_KEYID_SIZE * 2) + sizeof(QSC_QSMP_PUBKEY_EXPIRATION_PREFIX);
		slen = QSC_TIMESTAMP_STRING_SIZE - 1;
		qsc_memutils_copy(dtm, ((uint8_t*)input + spos), slen);
		clientkey->expiration = qsc_timestamp_datetime_to_seconds(dtm);
		spos += QSC_TIMESTAMP_STRING_SIZE;

		qsc_stringutils_remove_line_breaks(tmpvk, sizeof(tmpvk), ((char*)input + spos), (QSC_QSMP_PUBKEY_STRING_SIZE - (spos + sizeof(QSC_QSMP_PUBKEY_FOOTER))));
		qsc_encoding_base64_decode(clientkey->verkey, QSC_QSMP_VERIFYKEY_SIZE, tmpvk, QSC_QSMP_PUBKEY_ENCODING_SIZE);
	}
}

void qsc_qsmp_client_send_error(qsc_socket* sock, qsc_qsmp_errors error)
{
	qsc_qsmp_packet resp = { 0 };
	uint8_t spct[QSC_QSMP_MESSAGE_MAX] = { 0 };
	size_t plen;

	if (qsc_socket_is_connected(sock) == true)
	{
		resp.flag = qsc_qsmp_message_error_condition;
		resp.sequence = 0xFF;
		resp.msglen = 1;
		resp.message[0] = (uint8_t)error;
		plen = qsc_qsmp_packet_to_stream(&resp, spct);
		qsc_socket_send(sock, spct, plen, qsc_socket_send_flag_none);
	}
}

/* Public Functions */

void qsc_qsmp_client_connection_close(qsc_qsmp_kex_client_state* ctx, qsc_socket* sock, qsc_qsmp_errors error)
{
	if (qsc_socket_is_connected(sock) == true)
	{
		qsc_qsmp_packet resp = { 0 };
		uint8_t spct[QSC_QSMP_MESSAGE_MAX] = { 0 };
		size_t plen;

		/* send a disconnect message */
		resp.flag = qsc_qsmp_message_connection_terminate;
		resp.sequence = QSC_QSMP_SEQUENCE_TERMINATOR;
		resp.msglen = 1;
		resp.message[0] = (uint8_t)error;
		plen = qsc_qsmp_packet_to_stream(&resp, spct);
		qsc_socket_send(sock, spct, plen, qsc_socket_send_flag_none);

		/* close the socket */
		qsc_socket_close_socket(sock);
	}

	/* dispose of resources */
	qsc_qsmp_client_dispose(ctx);
}

qsc_qsmp_errors qsc_qsmp_client_connect_ipv4(qsc_qsmp_kex_client_state* ctx, qsc_socket* sock, const qsc_qsmp_client_key* ckey, const qsc_ipinfo_ipv4_address* address, uint16_t port)
{
	qsc_socket_exceptions serr;
	qsc_qsmp_errors qerr;

	qerr = qsc_qsmp_error_none;
	qsc_socket_client_initialize(sock);
	serr = qsc_socket_client_connect_ipv4(sock, address, port);

	if (serr == qsc_socket_exception_success)
	{
		qerr = qsc_qsmp_client_kex(ctx, sock, ckey);
	}
	else
	{
		qerr = qsc_qsmp_error_connection_failure;
	}

	return qerr;
}

qsc_qsmp_errors qsc_qsmp_client_connect_ipv6(qsc_qsmp_kex_client_state* ctx, qsc_socket* sock, const qsc_qsmp_client_key* ckey, const qsc_ipinfo_ipv6_address* address, uint16_t port)
{
	qsc_socket_exceptions serr;
	qsc_qsmp_errors qerr;

	qerr = qsc_qsmp_error_none;
	qsc_socket_client_initialize(sock);
	serr = qsc_socket_client_connect_ipv6(sock, address, port);

	if (serr == qsc_socket_exception_success)
	{
		qerr = qsc_qsmp_client_kex(ctx, sock, ckey);
	}
	else
	{
		qerr = qsc_qsmp_error_connection_failure;
	}

	return qerr;
}

qsc_qsmp_errors qsc_qsmp_client_decrypt_packet(qsc_qsmp_kex_client_state* ctx, const qsc_qsmp_packet* packetin, uint8_t* message, size_t* msglen)
{
	assert(ctx != NULL);
	assert(message != NULL);
	assert(msglen != NULL);
	assert(packetin != NULL);

	uint8_t hdr[QSC_QSMP_HEADER_SIZE] = { 0 };
	qsc_qsmp_errors qerr;

	qerr = qsc_qsmp_error_invalid_input;

	if (ctx != NULL && message != NULL && msglen != NULL && packetin != NULL)
	{
		ctx->rxseq += 1;

		if (packetin->sequence == ctx->rxseq)
		{
			if (ctx->exflag == qsc_qsmp_message_session_established)
			{
				qsc_qsmp_packet_header_serialize(packetin, hdr);
				qsc_rcs_set_associated(&ctx->rxcpr, hdr, QSC_QSMP_HEADER_SIZE);
				*msglen = packetin->msglen - QSC_RCS256_MAC_SIZE;

				if (qsc_rcs_transform(&ctx->rxcpr, message, packetin->message, *msglen) == true)
				{
					qerr = qsc_qsmp_error_none;
				}
				else
				{
					*msglen = 0;
					qerr = qsc_qsmp_error_auth_failure; 
				}
			}
			else if (ctx->exflag == qsc_qsmp_message_keep_alive_request)
			{

			}
			else
			{
				*msglen = 0;
				qerr = qsc_qsmp_error_channel_down;
			}
		}
		else
		{
			*msglen = 0;
			qerr = qsc_qsmp_error_packet_unsequenced;
		}
	}

	return qerr;
}

qsc_qsmp_errors qsc_qsmp_client_encrypt_packet(qsc_qsmp_kex_client_state* ctx, const uint8_t* message, size_t msglen, qsc_qsmp_packet* packetout)
{
	assert(ctx != NULL);
	assert(message != NULL);
	assert(packetout != NULL);

	qsc_qsmp_errors qerr;

	qerr = qsc_qsmp_error_invalid_input;

	if (ctx != NULL && packetout != NULL && message != NULL)
	{
		if (ctx->exflag == qsc_qsmp_message_session_established)
		{
			uint8_t hdr[QSC_QSMP_HEADER_SIZE] = { 0 };

			ctx->txseq += 1;
			qsc_memutils_clear(packetout->message, sizeof(packetout->message));
			packetout->flag = qsc_qsmp_message_encrypted_message;
			packetout->msglen = (uint32_t)msglen + QSC_RCS256_MAC_SIZE;
			packetout->sequence= ctx->txseq;

			qsc_qsmp_packet_header_serialize(packetout, hdr);
			qsc_rcs_set_associated(&ctx->txcpr, hdr, QSC_QSMP_HEADER_SIZE);
			qsc_rcs_transform(&ctx->txcpr, packetout->message, message, msglen);

			qerr = qsc_qsmp_error_none;
		}
		else
		{
			qerr = qsc_qsmp_error_channel_down;
		}
	}

	return qerr;
}

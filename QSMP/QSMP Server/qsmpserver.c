#include "qsmpserver.h"
#include "../QSC/acp.h"
#include "../QSC/encoding.h"
#include "../QSC/intutils.h"
#include "../QSC/memutils.h"
#include "../QSC/sha3.h"
#include "../QSC/stringutils.h"
#include "../QSC/timestamp.h"
#include "../QSC/async.h"

#if defined(QSC_QSMP_PUBKEY_SPHINCS)
#	define qsc_qsmp_cipher_generate_keypair qsc_mceliece_generate_keypair
#	define qsc_qsmp_cipher_decapsulate qsc_mceliece_decapsulate
#	define qsc_qsmp_cipher_encapsulate qsc_mceliece_encapsulate
#	define qsc_qsmp_signature_generate_keypair qsc_sphincsplus_generate_keypair
#	define qsc_qsmp_signature_sign qsc_sphincsplus_sign
#	define qsc_qsmp_signature_verify qsc_sphincsplus_verify
#else
#	define qsc_qsmp_cipher_generate_keypair qsc_kyber_generate_keypair
#	define qsc_qsmp_cipher_decapsulate qsc_kyber_decapsulate
#	define qsc_qsmp_cipher_encapsulate qsc_kyber_encapsulate
#	define qsc_qsmp_signature_generate_keypair qsc_dilithium_generate_keypair
#	define qsc_qsmp_signature_sign qsc_dilithium_sign
#	define qsc_qsmp_signature_verify qsc_dilithium_verify
#endif

/* Private Functions */

static void qsc_qsmp_server_dispose(qsc_qsmp_kex_server_state* ctx)
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
		qsc_memutils_clear(ctx->sigkey, sizeof(ctx->sigkey));
		qsc_memutils_clear(ctx->verkey, sizeof(ctx->verkey));
		ctx->exflag = 0;
		ctx->expiration = 0;
	}
}

static void qsc_qsmp_server_kex_reset(qsc_qsmp_kex_server_state* ctx)
{
	qsc_memutils_clear(ctx->config, sizeof(ctx->config));
	qsc_memutils_clear(ctx->keyid, sizeof(ctx->keyid));
	qsc_memutils_clear(ctx->pkhash, sizeof(ctx->pkhash));
	qsc_memutils_clear(ctx->prikey, sizeof(ctx->prikey));
	qsc_memutils_clear(ctx->pubkey, sizeof(ctx->pubkey));
	qsc_memutils_clear(ctx->sigkey, sizeof(ctx->sigkey));
	qsc_memutils_clear(ctx->verkey, sizeof(ctx->verkey));
	qsc_memutils_clear(ctx->token, sizeof(ctx->token));
	ctx->expiration = 0;
}

static qsc_qsmp_errors qsc_qsmp_server_connection_response(qsc_qsmp_kex_server_state* ctx, const qsc_qsmp_packet* packetin, qsc_qsmp_packet* packetout)
{
	assert(ctx != NULL);
	assert(packetin != NULL);
	assert(packetout != NULL);

	char confs[QSC_QSMP_CONFIG_SIZE + 1] = { 0 };
	uint8_t phash[QSC_SHA3_256_HASH_SIZE] = { 0 };
	qsc_keccak_state kstate = { 0 };
	qsc_qsmp_errors res;
	uint64_t tm;
	size_t mlen;

	res = qsc_qsmp_error_invalid_input;

	if (ctx != NULL && packetin != NULL && packetout != NULL)
	{
		if (packetin->flag == qsc_qsmp_message_connect_request)
		{
			tm = qsc_timestamp_epochtime_seconds();

			/* check the keys expiration date */
			if (tm <= ctx->expiration)
			{
				/* copy the session token and configuration string */
				qsc_memutils_copy(ctx->keyid, packetout->message, QSC_QSMP_KEYID_SIZE);
				qsc_memutils_copy(ctx->token, ((uint8_t*)packetin->message + QSC_QSMP_KEYID_SIZE), QSC_QSMP_STOKEN_SIZE);
				qsc_memutils_copy(confs, ((uint8_t*)packetin->message + QSC_QSMP_KEYID_SIZE + QSC_QSMP_STOKEN_SIZE), QSC_QSMP_CONFIG_SIZE);

				if (qsc_stringutils_compare_strings(confs, QSC_QSMP_CONFIG_STRING, QSC_QSMP_CONFIG_SIZE) == true)
				{
					/* store a hash of the session token, the configuration string, and the public signature key: pkh = H(stok || cfg || psk) */
					qsc_memutils_clear(ctx->pkhash, QSC_QSMP_PKCODE_SIZE);
					qsc_sha3_initialize(&kstate);
					qsc_sha3_update(&kstate, keccak_rate_256, packetin->message, QSC_QSMP_STOKEN_SIZE + QSC_QSMP_CONFIG_SIZE);
					qsc_sha3_update(&kstate, keccak_rate_256, ctx->verkey, QSC_QSMP_VERIFYKEY_SIZE);
					qsc_sha3_finalize(&kstate, keccak_rate_256, ctx->pkhash);

					/* initialize the packet and asymmetric encryption keys */
					qsc_memutils_clear(ctx->pubkey, QSC_QSMP_PUBLICKEY_SIZE);
					qsc_memutils_clear(ctx->prikey, QSC_QSMP_PRIVATEKEY_SIZE);
					qsc_memutils_clear(packetout->message, sizeof(packetout->message));

					/* generate the asymmetric encryption key-pair */
					qsc_qsmp_cipher_generate_keypair(ctx->pubkey, ctx->prikey, qsc_acp_generate);

					/* hash the public encryption key */
					qsc_sha3_compute256(phash, ctx->pubkey, QSC_QSMP_PUBLICKEY_SIZE);

					/* sign the hash and add it to the message */
					mlen = 0;
					qsc_qsmp_signature_sign(packetout->message, &mlen, phash, QSC_SHA3_256_HASH_SIZE, ctx->sigkey, qsc_acp_generate);

					/* copy the public key to the message */
					qsc_memutils_copy(((uint8_t*)packetout->message + mlen), ctx->pubkey, QSC_QSMP_PUBLICKEY_SIZE);

					/* assemble the connection-response packet */
					packetout->flag = qsc_qsmp_message_connect_response;
					packetout->msglen = QSC_QSMP_SIGNATURE_SIZE + QSC_SHA3_256_HASH_SIZE + QSC_QSMP_PUBLICKEY_SIZE;
					packetout->sequence = ctx->txseq;

					res = qsc_qsmp_error_none;
					ctx->exflag = qsc_qsmp_message_connect_response;
				}
				else
				{
					//qsc_qsmp_message_unrecognized_protocol
					qsc_qsmp_packet_error_message(packetout, qsc_qsmp_error_unknown_protocol);
					ctx->exflag = qsc_qsmp_message_none;
					res = qsc_qsmp_error_unknown_protocol;
				}
			}
			else
			{
				qsc_qsmp_packet_error_message(packetout, qsc_qsmp_error_key_expired);
				ctx->exflag = qsc_qsmp_message_none;
				res = qsc_qsmp_error_key_expired;
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

static qsc_qsmp_errors qsc_qsmp_server_exstart_response(qsc_qsmp_kex_server_state* ctx, const qsc_qsmp_packet* packetin, qsc_qsmp_packet* packetout)
{
	assert(ctx != NULL);
	assert(packetin != NULL);
	assert(packetout != NULL);

	qsc_qsmp_errors res;

	res = qsc_qsmp_error_invalid_input;

	if (ctx != NULL && packetin != NULL && packetout != NULL)
	{
		if (ctx->exflag == qsc_qsmp_message_connect_response && packetin->flag == qsc_qsmp_message_exstart_request)
		{
			uint8_t sec[QSC_QSMP_SECRET_SIZE] = { 0 };

			/* decapsulate the shared secret */
			if (qsc_qsmp_cipher_decapsulate(sec, packetin->message, ctx->prikey) == true)
			{
				uint8_t prnd[QSC_KECCAK_256_RATE] = { 0 };
				qsc_keccak_state kstate = { 0 };

				/* expand the secret with cshake (P) adding the public verification keys hash; prand = P(pv || sec) */
				qsc_cshake_initialize(&kstate, keccak_rate_256, sec, QSC_QSMP_SECRET_SIZE, NULL, 0, ctx->pkhash, QSC_QSMP_PKCODE_SIZE);
				qsc_cshake_squeezeblocks(&kstate, keccak_rate_256, prnd, 1);

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
				qsc_memutils_clear(packetout->message, sizeof(packetout->message));
				packetout->flag = qsc_qsmp_message_exstart_response;
				packetout->message[0] = (uint8_t)qsc_qsmp_message_remote_connected;
				packetout->msglen = 1;
				packetout->sequence = ctx->txseq;

				res = qsc_qsmp_error_none;
				ctx->exflag = qsc_qsmp_message_exstart_response;
			}
			else
			{
				qsc_qsmp_packet_error_message(packetout, qsc_qsmp_error_decapsulation_failure);
				ctx->exflag = qsc_qsmp_message_none;
				res = qsc_qsmp_error_decapsulation_failure;
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

static qsc_qsmp_errors qsc_qsmp_server_exchange_response(qsc_qsmp_kex_server_state* ctx, const qsc_qsmp_packet* packetin, qsc_qsmp_packet* packetout)
{
	assert(ctx != NULL);
	assert(packetin != NULL);
	assert(packetout != NULL);

	qsc_qsmp_errors res;

	res = qsc_qsmp_error_invalid_input;

	if (ctx != NULL && packetin != NULL && packetout != NULL)
	{
		if (ctx->exflag == qsc_qsmp_message_exstart_response && packetin->flag == qsc_qsmp_message_exchange_request)
		{
			uint8_t hdr[QSC_QSMP_HEADER_SIZE] = { 0 };
			uint8_t msg[QSC_QSMP_PUBLICKEY_SIZE + QSC_QSMP_MACKEY_SIZE] = { 0 };

			/* serialize the packet header and add it to associated data */
			qsc_qsmp_packet_header_serialize(packetin, hdr);
			qsc_rcs_set_associated(&ctx->rxcpr, hdr, QSC_QSMP_HEADER_SIZE);

			/* authenticate and decrypt the cipher-text */
			if (qsc_rcs_transform(&ctx->rxcpr, msg, packetin->message, packetin->msglen - QSC_QSMP_MACTAG_SIZE) == true)
			{
				uint8_t sec[QSC_QSMP_SECRET_SIZE] = { 0 };
				uint8_t cpt[QSC_QSMP_CIPHERTEXT_SIZE] = { 0 };
				uint8_t mkey[QSC_QSMP_MACKEY_SIZE] = { 0 };
				uint8_t prnd[QSC_KECCAK_256_RATE] = { 0 };
				qsc_keccak_state kstate = { 0 };

				qsc_memutils_copy(mkey, msg, sizeof(mkey));
				/* generate and encapsulate the shared secret */
				qsc_qsmp_cipher_encapsulate(sec, cpt, ((uint8_t*)msg + QSC_QSMP_MACKEY_SIZE), qsc_acp_generate);

				/* expand the shared secret */
				qsc_cshake_initialize(&kstate, keccak_rate_256, sec, QSC_QSMP_SECRET_SIZE, NULL, 0, ctx->pkhash, QSC_QSMP_PKCODE_SIZE);
				qsc_cshake_squeezeblocks(&kstate, keccak_rate_256, prnd, 1);

				/* initialize the symmetric cipher, and raise server channel-2 tx */
				qsc_rcs_keyparams kp;
				kp.key = prnd;
				kp.keylen = QSC_RCS256_KEY_SIZE;
				kp.nonce = ((uint8_t*)prnd + QSC_RCS256_KEY_SIZE);
				kp.info = NULL;
				kp.infolen = 0;
				qsc_rcs_initialize(&ctx->txcpr, &kp, true);

				/* assemble the exstart-response packet */
				qsc_memutils_clear(packetout->message, sizeof(packetout->message));
				packetout->flag = qsc_qsmp_message_exchange_response;
				packetout->msglen = QSC_QSMP_CIPHERTEXT_SIZE + QSC_QSMP_MACTAG_SIZE;
				packetout->sequence = ctx->txseq;

				/* mac the asymmetric cipher-text, and append the MAC code */
				qsc_kmac256_compute(packetout->message, QSC_QSMP_MACTAG_SIZE, cpt, QSC_QSMP_CIPHERTEXT_SIZE, mkey, QSC_QSMP_MACKEY_SIZE, NULL, 0);
				qsc_memutils_copy(((uint8_t*)packetout->message + QSC_QSMP_MACTAG_SIZE), cpt, QSC_QSMP_CIPHERTEXT_SIZE);

				res = qsc_qsmp_error_none;
				ctx->exflag = qsc_qsmp_message_exchange_response;
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

static qsc_qsmp_errors qsc_qsmp_server_establish_response(qsc_qsmp_kex_server_state* ctx, const qsc_qsmp_packet* packetin, qsc_qsmp_packet* packetout)
{
	assert(ctx != NULL);
	assert(packetin != NULL);
	assert(packetout != NULL);

	qsc_qsmp_errors res;

	res = qsc_qsmp_error_invalid_input;

	if (ctx != NULL && packetin != NULL && packetout != NULL)
	{
		if (ctx->exflag == qsc_qsmp_message_exchange_response && packetin->flag == qsc_qsmp_message_establish_request)
		{
			/* assemble the establish-response packet */
			qsc_memutils_clear(packetout->message, sizeof(packetout->message));
			packetout->flag = qsc_qsmp_message_establish_response;
			packetout->msglen = 1;
			packetout->sequence = ctx->txseq;
			packetout->message[0] = (uint8_t)qsc_qsmp_message_session_established;

			res = qsc_qsmp_error_none;
			ctx->exflag = qsc_qsmp_message_session_established;
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

static qsc_qsmp_errors qsc_qsmp_server_kex(qsc_qsmp_kex_server_state* ctx, qsc_socket* sock, const qsc_qsmp_server_key* skey)
{
	uint8_t spct[QSC_QSMP_MESSAGE_MAX + 1] = { 0 };
	qsc_qsmp_packet reqt = { 0 };
	qsc_qsmp_packet resp = { 0 };
	qsc_qsmp_errors qerr;
	size_t plen;
	size_t rlen;
	size_t slen;

	/* initialize the server */
	qsc_qsmp_server_initialize(ctx, skey);

	/* blocking receive waits for client */
	rlen = qsc_socket_receive(sock, spct, sizeof(spct), qsc_socket_receive_flag_none);

	if (rlen > 0)
	{
		/* convert server response to packet */
		qsc_qsmp_stream_to_packet(spct, &resp);

		if (resp.sequence == ctx->rxseq)
		{
			ctx->rxseq += 1;

			if (resp.flag == qsc_qsmp_message_connect_request)
			{
				/* clear the request packet */
				qsc_qsmp_packet_clear(&reqt);
				/* create the connection request packet */
				qerr = qsc_qsmp_server_connection_response(ctx, &resp, &reqt);
			}
			else
			{
				if (resp.flag == qsc_qsmp_message_error_condition)
				{
					qerr = (qsc_qsmp_errors)resp.message[0];
				}
				else
				{
					qerr = qsc_qsmp_error_connect_failure;
					qsc_qsmp_server_send_error(sock, qerr);
				}
			}
		}
		else
		{
			qerr = qsc_qsmp_error_packet_unsequenced;
			qsc_qsmp_server_send_error(sock, qerr);
		}
	}
	else
	{
		qerr = qsc_qsmp_error_connect_failure;
		qsc_qsmp_server_send_error(sock, qerr);
	}

	if (qerr == qsc_qsmp_error_none)
	{
		/* convert the packet to bytes */
		plen = qsc_qsmp_packet_to_stream(&reqt, spct);
		/* send the connection response */
		slen = qsc_socket_send(sock, spct, plen, qsc_socket_send_flag_none);

		if (slen >= plen)
		{
			/* blocking receive waits for client */
			ctx->txseq += 1;
			rlen = qsc_socket_receive(sock, spct, sizeof(spct), qsc_socket_receive_flag_none);

			if (rlen > 0)
			{
				qsc_qsmp_stream_to_packet(spct, &resp);

				if (resp.sequence == ctx->rxseq)
				{
					ctx->rxseq += 1;

					if (resp.flag == qsc_qsmp_message_exstart_request)
					{
						qsc_qsmp_packet_clear(&reqt);
						/* create the exstart response packet */
						qerr = qsc_qsmp_server_exstart_response(ctx, &resp, &reqt);
					}
					else
					{
						/* get the error message */
						if (resp.flag == qsc_qsmp_message_error_condition)
						{
							qerr = (qsc_qsmp_errors)resp.message[0];
						}
						else
						{
							qerr = qsc_qsmp_error_exstart_failure;
							qsc_qsmp_server_send_error(sock, qerr);
						}
					}
				}
				else
				{
					qerr = qsc_qsmp_error_packet_unsequenced;
					qsc_qsmp_server_send_error(sock, qerr);
				}
			}
			else
			{
				/* send the error to the client */
				qerr = qsc_qsmp_error_receive_failure;
				qsc_qsmp_server_send_error(sock, qerr);
			}
		}
		else
		{
			qerr = qsc_qsmp_error_transmit_failure;
			qsc_qsmp_server_send_error(sock, qerr);
		}
	}
	else
	{
		qerr = qsc_qsmp_error_connection_failure;
		qsc_qsmp_server_send_error(sock, qerr);
	}

	if (qerr == qsc_qsmp_error_none)
	{
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

					if (resp.flag == qsc_qsmp_message_exchange_request)
					{
						qsc_qsmp_packet_clear(&reqt);
						/* create the exchange response packet */
						qerr = qsc_qsmp_server_exchange_response(ctx, &resp, &reqt);
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
							qsc_qsmp_server_send_error(sock, qerr);
						}
					}
				}
				else
				{
					qerr = qsc_qsmp_error_packet_unsequenced;
					qsc_qsmp_server_send_error(sock, qerr);
				}
			}
			else
			{
				qerr = qsc_qsmp_error_receive_failure;
				qsc_qsmp_server_send_error(sock, qerr);
			}
		}
		else
		{
			qerr = qsc_qsmp_error_transmit_failure;
			qsc_qsmp_server_send_error(sock, qerr);
		}
	}
	else
	{
		qerr = qsc_qsmp_error_exstart_failure;
		qsc_qsmp_server_send_error(sock, qerr);
	}

	if (qerr == qsc_qsmp_error_none)
	{
		plen = qsc_qsmp_packet_to_stream(&reqt, spct);
		slen = qsc_socket_send(sock, spct, plen, qsc_socket_send_flag_none);

		if (slen >= plen)
		{
			ctx->txseq += 1;
			rlen = qsc_socket_receive(sock, spct, sizeof(spct), qsc_socket_receive_flag_none);

			if (rlen > 0)
			{
				ctx->rxseq += 1;
				qsc_qsmp_stream_to_packet(spct, &resp);

				if (resp.flag == qsc_qsmp_message_establish_request)
				{
					qsc_qsmp_packet_clear(&reqt);
					/* create the establish response packet */
					qerr = qsc_qsmp_server_establish_response(ctx, &resp, &reqt);

					if (qerr == qsc_qsmp_error_none)
					{
						plen = qsc_qsmp_packet_to_stream(&reqt, spct);
						slen = qsc_socket_send(sock, spct, plen, qsc_socket_send_flag_none);

						if (slen >= plen)
						{
							ctx->txseq += 1;
						}
					}
					else
					{
						qerr = qsc_qsmp_error_establish_failure;
						qsc_qsmp_server_send_error(sock, qerr);
					}
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
						qsc_qsmp_server_send_error(sock, qerr);
					}
				}
			}
			else
			{
				qerr = qsc_qsmp_error_receive_failure;
				qsc_qsmp_server_send_error(sock, qerr);
			}
		}
		else
		{
			qerr = qsc_qsmp_error_transmit_failure;
			qsc_qsmp_server_send_error(sock, qerr);
		}
	}
	else
	{
		qerr = qsc_qsmp_error_exchange_failure;
		qsc_qsmp_server_send_error(sock, qerr);
	}

	if (qerr == qsc_qsmp_error_none)
	{
		qsc_qsmp_server_kex_reset(ctx);
	}
	else
	{
		qsc_qsmp_server_dispose(ctx);
	}

	return qerr;
}

/* Helper Functions */

void qsc_qsmp_server_connection_close(qsc_qsmp_kex_server_state* ctx, qsc_socket* sock, qsc_qsmp_errors error)
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
	qsc_qsmp_server_dispose(ctx);
}

void qsc_qsmp_server_deserialize_signature_key(qsc_qsmp_server_key* skey, const uint8_t input[QSC_QSMP_SIGKEY_ENCODED_SIZE])
{
	size_t pos;

	qsc_memutils_copy(skey->config, input, QSC_QSMP_CONFIG_SIZE);
	pos = QSC_QSMP_CONFIG_SIZE;
	skey->expiration = qsc_intutils_le8to64(((uint8_t*)input + pos));
	pos += QSC_QSMP_TIMESTAMP_SIZE;
	qsc_memutils_copy(skey->keyid, ((uint8_t*)input + pos), QSC_QSMP_KEYID_SIZE);
	pos += QSC_QSMP_KEYID_SIZE;
	qsc_memutils_copy(skey->sigkey, ((uint8_t*)input + pos), QSC_QSMP_SIGNKEY_SIZE);
	pos += QSC_QSMP_SIGNKEY_SIZE;
	qsc_memutils_copy(skey->verkey, ((uint8_t*)input + pos), QSC_QSMP_VERIFYKEY_SIZE);
	pos += QSC_QSMP_VERIFYKEY_SIZE;
}

void qsc_qsmp_server_encode_public_key(char output[QSC_QSMP_PUBKEY_STRING_SIZE], const qsc_qsmp_server_key* skey)
{
	assert(skey != NULL);

	char dtm[QSC_TIMESTAMP_STRING_SIZE] = { 0 };
	char hexid[QSC_QSMP_KEYID_SIZE * 2] = { 0 };
	char tmpvk[QSC_QSMP_PUBKEY_ENCODING_SIZE] = { 0 };
	size_t slen;
	size_t spos;
	size_t tpos;

	if (skey != NULL)
	{
		spos = 0;
		tpos = 0;
		slen = sizeof(QSC_QSMP_PUBKEY_HEADER) - 1;
		qsc_memutils_copy(output, QSC_QSMP_PUBKEY_HEADER, slen);
		spos = slen;
		output[spos] = '\n';
		++spos;

		slen = sizeof(QSC_QSMP_PUBKEY_VERSION) - 1;
		qsc_memutils_copy(((char*)output + spos), QSC_QSMP_PUBKEY_VERSION, slen);
		spos += slen;
		output[spos] = '\n';
		++spos;

		slen = sizeof(QSC_QSMP_PUBKEY_CONFIG_PREFIX) - 1;
		qsc_memutils_copy(((char*)output + spos), QSC_QSMP_PUBKEY_CONFIG_PREFIX, slen);
		spos += slen;
		slen = sizeof(QSC_QSMP_CONFIG_STRING) - 1;
		qsc_memutils_copy(((char*)output + spos), QSC_QSMP_CONFIG_STRING, slen);
		spos += slen;
		output[spos] = '\n';
		++spos;

		slen = sizeof(QSC_QSMP_PUBKEY_KEYID_PREFIX) - 1;
		qsc_memutils_copy(((char*)output + spos), QSC_QSMP_PUBKEY_KEYID_PREFIX, slen);
		spos += slen;
		qsc_intutils_bin_to_hex(skey->keyid, hexid, sizeof(skey->keyid));
		slen = sizeof(hexid);
		qsc_memutils_copy(((char*)output + spos), hexid, slen);
		spos += slen;
		output[spos] = '\n';
		++spos;

		slen = sizeof(QSC_QSMP_PUBKEY_EXPIRATION_PREFIX) - 1;
		qsc_memutils_copy(((char*)output + spos), QSC_QSMP_PUBKEY_EXPIRATION_PREFIX, slen);
		spos += slen;
		qsc_timestamp_seconds_to_datetime(skey->expiration, dtm);
		slen = sizeof(dtm) - 1;
		qsc_memutils_copy(((char*)output + spos), dtm, slen);
		spos += slen;
		output[spos] = '\n';
		++spos;

		slen = sizeof(skey->verkey);
		qsc_encoding_base64_encode(tmpvk, QSC_QSMP_PUBKEY_ENCODING_SIZE, skey->verkey, slen);
		spos += qsc_stringutils_add_line_breaks(((char*)output + spos), QSC_QSMP_PUBKEY_STRING_SIZE - spos, QSC_QSMP_PUBKEY_LINE_LENGTH, tmpvk, sizeof(tmpvk));
		output[spos] = '\n';
		++spos;

		slen = sizeof(QSC_QSMP_PUBKEY_FOOTER) - 1;
		qsc_memutils_copy(((char*)output + spos), QSC_QSMP_PUBKEY_FOOTER, slen);
		spos += slen;
		output[spos] = '\n';
	}
}

void qsc_qsmp_server_send_error(qsc_socket* sock, qsc_qsmp_errors error)
{
	if (qsc_socket_is_connected(sock) == true)
	{
		qsc_qsmp_packet resp = { 0 };
		uint8_t spct[QSC_QSMP_MESSAGE_MAX] = { 0 };
		size_t plen;

		qsc_qsmp_packet_error_message(&resp, error);
		plen = qsc_qsmp_packet_to_stream(&resp, spct);
		qsc_socket_send(sock, spct, plen, qsc_socket_send_flag_none);
	}
}

qsc_qsmp_errors qsc_qsmp_server_send_keep_alive(qsc_qsmp_keep_alive_state* kctx, qsc_socket* sock)
{
	qsc_qsmp_errors qerr;

	qerr = qsc_qsmp_error_bad_keep_alive;

	if (qsc_socket_is_connected(sock) == true)
	{
		qsc_qsmp_packet resp = { 0 };
		uint8_t spct[QSC_QSMP_MESSAGE_MAX] = { 0 };
		uint64_t etime;
		size_t plen;
		size_t slen;

		/* set the time and store in keep-alive struct */
		etime = qsc_timestamp_epochtime_seconds();
		kctx->etime = etime;

		/* assemble the keep-alive packet */
		resp.flag = qsc_qsmp_message_keep_alive_request;
		resp.sequence = kctx->seqctr;
		resp.msglen = sizeof(etime);
		qsc_intutils_le64to8(resp.message, etime);
		plen = qsc_qsmp_packet_to_stream(&resp, spct);
		slen = qsc_socket_send(sock, spct, plen, qsc_socket_send_flag_none);

		if (slen >= plen)
		{
			qerr = qsc_qsmp_error_none;
		}
	}

	return qerr;
}

void qsc_qsmp_server_serialize_signature_key(uint8_t output[QSC_QSMP_SIGKEY_ENCODED_SIZE], const qsc_qsmp_server_key* skey)
{
	size_t pos;

	qsc_memutils_copy(output, skey->config, QSC_QSMP_CONFIG_SIZE);
	pos = QSC_QSMP_CONFIG_SIZE; 
	qsc_intutils_le64to8(((uint8_t*)output + pos), skey->expiration);
	pos += QSC_QSMP_TIMESTAMP_SIZE;
	qsc_memutils_copy(((uint8_t*)output + pos), skey->keyid, QSC_QSMP_KEYID_SIZE);
	pos += QSC_QSMP_KEYID_SIZE;
	qsc_memutils_copy(((uint8_t*)output + pos), skey->sigkey, QSC_QSMP_SIGNKEY_SIZE);
	pos += QSC_QSMP_SIGNKEY_SIZE;
	qsc_memutils_copy(((uint8_t*)output + pos), skey->verkey, QSC_QSMP_VERIFYKEY_SIZE);
	pos += QSC_QSMP_VERIFYKEY_SIZE;
}

/* Primary Functions */

void qsc_qsmp_server_initialize(qsc_qsmp_kex_server_state* ctx, const qsc_qsmp_server_key* skey)
{
	assert(ctx != NULL);
	assert(skey != NULL);

	if (ctx != NULL && skey != NULL)
	{
		qsc_qsmp_server_dispose(ctx);
		qsc_memutils_copy(ctx->keyid, skey->keyid, QSC_QSMP_KEYID_SIZE);
		qsc_memutils_copy(ctx->config, QSC_QSMP_CONFIG_STRING, QSC_QSMP_CONFIG_SIZE);
		qsc_memutils_copy(ctx->sigkey, skey->sigkey, sizeof(ctx->sigkey));
		qsc_memutils_copy(ctx->verkey, skey->verkey, sizeof(ctx->verkey));
		ctx->exflag = qsc_qsmp_message_none;
		ctx->expiration = skey->expiration;
	}
}

qsc_qsmp_errors qsc_qsmp_server_listen_ipv4(qsc_qsmp_kex_server_state* ctx, qsc_socket* sock, const qsc_qsmp_server_key* skey, const qsc_ipinfo_ipv4_address* address, uint16_t port)
{
	qsc_socket srvs;
	qsc_socket_exceptions serr;
	qsc_qsmp_errors qerr;

	qerr = qsc_qsmp_error_none;
	qsc_socket_server_initialize(sock);
	qsc_socket_server_initialize(&srvs);

	serr = qsc_socket_server_listen_ipv4(&srvs, sock, address, port);

	if (serr == qsc_socket_exception_success)
	{
		qerr = qsc_qsmp_server_kex(ctx, sock, skey);
	}
	else
	{
		qerr = qsc_qsmp_error_connection_failure;
	}

	return qerr;
}

qsc_qsmp_errors qsc_qsmp_server_listen_ipv6(qsc_qsmp_kex_server_state* ctx, qsc_socket* sock, const qsc_qsmp_server_key* skey, const qsc_ipinfo_ipv6_address* address, uint16_t port)
{
	qsc_socket srvs;
	qsc_socket_exceptions serr;
	qsc_qsmp_errors qerr;

	qerr = qsc_qsmp_error_none;
	qsc_socket_server_initialize(sock);
	qsc_socket_server_initialize(&srvs);

	serr = qsc_socket_server_listen_ipv6(&srvs, sock, address, port);

	if (serr == qsc_socket_exception_success)
	{
		qerr = qsc_qsmp_server_kex(ctx, sock, skey);
	}
	else
	{
		qerr = qsc_qsmp_error_connection_failure;
	}

	return qerr;
}

qsc_qsmp_errors qsc_qsmp_server_decrypt_packet(qsc_qsmp_kex_server_state* ctx, const qsc_qsmp_packet* packetin, uint8_t* message, size_t* msglen)
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

qsc_qsmp_errors qsc_qsmp_server_encrypt_packet(qsc_qsmp_kex_server_state* ctx, uint8_t* message, size_t msglen, qsc_qsmp_packet* packetout)
{
	assert(ctx != NULL);
	assert(message != NULL);
	assert(packetout != NULL);

	qsc_qsmp_errors res;

	res = qsc_qsmp_error_invalid_input;

	if (ctx != NULL && message != NULL && packetout != NULL)
	{
		if (ctx->exflag == qsc_qsmp_message_session_established)
		{
			uint8_t hdr[QSC_QSMP_HEADER_SIZE] = { 0 };

			ctx->txseq += 1;
			qsc_memutils_clear(packetout->message, sizeof(packetout->message));
			packetout->flag = qsc_qsmp_message_encrypted_message;
			packetout->msglen = (uint32_t)msglen + QSC_RCS256_MAC_SIZE;
			packetout->sequence = ctx->txseq;

			qsc_qsmp_packet_header_serialize(packetout, hdr);
			qsc_rcs_set_associated(&ctx->txcpr, hdr, QSC_QSMP_HEADER_SIZE);
			qsc_rcs_transform(&ctx->txcpr, packetout->message, message, msglen);

			res = qsc_qsmp_error_none;
		}
		else
		{
			res = qsc_qsmp_error_channel_down;
		}
	}

	return res;
}

void qsc_qsmp_server_generate_keypair(qsc_qsmp_client_key* pubkey, qsc_qsmp_server_key* prikey, const uint8_t keyid[QSC_QSMP_KEYID_SIZE])
{
	assert(prikey != NULL);
	assert(pubkey != NULL);

	if (prikey != NULL && pubkey != NULL)
	{
		prikey->expiration = qsc_timestamp_epochtime_seconds() + QSC_QSMP_PUBKEY_DURATION_SECONDS;
		qsc_memutils_copy(prikey->config, QSC_QSMP_CONFIG_STRING, QSC_QSMP_CONFIG_SIZE);
		qsc_memutils_copy(prikey->keyid, keyid, QSC_QSMP_KEYID_SIZE);

		qsc_qsmp_signature_generate_keypair(prikey->verkey, prikey->sigkey, qsc_acp_generate);

		pubkey->expiration = prikey->expiration;
		qsc_memutils_copy(pubkey->config, prikey->config, QSC_QSMP_CONFIG_SIZE);
		qsc_memutils_copy(pubkey->verkey, prikey->verkey, QSC_QSMP_VERIFYKEY_SIZE);
		qsc_memutils_copy(pubkey->keyid, prikey->keyid, QSC_QSMP_KEYID_SIZE);
	}
}
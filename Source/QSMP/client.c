#include "client.h"
#include "kex.h"
#include "logger.h"
#include "acp.h"
#include "async.h"
#include "intutils.h"
#include "memutils.h"
#include "sha3.h"
#include "socketserver.h"
#include "timestamp.h"

/** \cond */
typedef struct client_receiver_state
{
	qsmp_connection_state* pcns;
	void (*callback)(qsmp_connection_state*, const uint8_t*, size_t);
} client_receiver_state;

typedef struct listener_receiver_state
{
	qsmp_connection_state* pcns;
	qsmp_keep_alive_state* pkpa;
	void (*callback)(qsmp_connection_state*, const uint8_t*, size_t);
} listener_receiver_state;
/** \endcond */

#if defined(QSMP_ASYMMETRIC_RATCHET)
/** \cond */
#define QSMP_ASYMMETRIC_RATCHET_REQUEST_MESSAGE_SIZE (QSMP_ASYMMETRIC_PUBLIC_KEY_SIZE + QSMP_ASYMMETRIC_SIGNATURE_SIZE + QSMP_SIMPLEX_HASH_SIZE + QSMP_DUPLEX_MACTAG_SIZE)
#define QSMP_ASYMMETRIC_RATCHET_REQUEST_PACKET_SIZE (QSMP_HEADER_SIZE + QSMP_ASYMMETRIC_PUBLIC_KEY_SIZE + QSMP_ASYMMETRIC_SIGNATURE_SIZE + QSMP_SIMPLEX_HASH_SIZE + QSMP_DUPLEX_MACTAG_SIZE)
#define QSMP_ASYMMETRIC_RATCHET_RESPONSE_MESSAGE_SIZE (QSMP_ASYMMETRIC_CIPHER_TEXT_SIZE + QSMP_ASYMMETRIC_SIGNATURE_SIZE + QSMP_SIMPLEX_HASH_SIZE + QSMP_DUPLEX_MACTAG_SIZE)
#define QSMP_ASYMMETRIC_RATCHET_RESPONSE_PACKET_SIZE (QSMP_HEADER_SIZE + QSMP_ASYMMETRIC_CIPHER_TEXT_SIZE + QSMP_ASYMMETRIC_SIGNATURE_SIZE + QSMP_SIMPLEX_HASH_SIZE + QSMP_DUPLEX_MACTAG_SIZE)

static qsmp_asymmetric_cipher_keypair* m_ckeyset;
static qsmp_asymmetric_signature_keypair* m_skeyset;
/** \endcond */
#endif

/* Private Functions */

/** \cond */
static void client_duplex_state_initialize(qsmp_kex_duplex_client_state* kcs, qsmp_connection_state* cns, const qsmp_server_signature_key* kset, const qsmp_client_verification_key* rverkey)
{
	qsc_memutils_copy(kcs->verkey, kset->verkey, QSMP_ASYMMETRIC_VERIFY_KEY_SIZE);
	qsc_memutils_copy(kcs->sigkey, kset->sigkey, QSMP_ASYMMETRIC_SIGNING_KEY_SIZE);
	qsc_memutils_copy(kcs->keyid, rverkey->keyid, QSMP_KEYID_SIZE);
	qsc_memutils_copy(kcs->rverkey, rverkey->verkey, QSMP_ASYMMETRIC_VERIFY_KEY_SIZE);
	qsc_memutils_clear(cns->rtcs, QSMP_DUPLEX_SYMMETRIC_KEY_SIZE);
	kcs->expiration = rverkey->expiration;
	cns->target.instance = qsc_acp_uint32();
	qsc_rcs_dispose(&cns->rxcpr);
	qsc_rcs_dispose(&cns->txcpr);
	cns->exflag = qsmp_flag_none;
	cns->cid = 0;
	cns->mode = qsmp_mode_duplex;
	cns->rxseq = 0;
	cns->txseq = 0;
	cns->receiver = false;
}

static void listener_duplex_state_initialize(qsmp_kex_duplex_server_state* kss, listener_receiver_state* rcv, 
	const qsmp_server_signature_key* kset, 
	bool (*key_query)(uint8_t* rvkey, const uint8_t* pkid))
{
	qsc_memutils_copy(kss->keyid, kset->keyid, QSMP_KEYID_SIZE);
	qsc_memutils_copy(kss->sigkey, kset->sigkey, QSMP_ASYMMETRIC_SIGNING_KEY_SIZE);
	qsc_memutils_copy(kss->verkey, kset->verkey, QSMP_ASYMMETRIC_VERIFY_KEY_SIZE);
	kss->key_query = key_query;
	kss->expiration = kset->expiration;
	qsc_memutils_copy(&rcv->pkpa->target, &rcv->pcns->target, sizeof(qsc_socket));
	qsc_memutils_clear((uint8_t*)&rcv->pcns->rxcpr, sizeof(qsc_rcs_state));
	qsc_memutils_clear((uint8_t*)&rcv->pcns->txcpr, sizeof(qsc_rcs_state));
	qsc_memutils_clear(&rcv->pcns->rtcs, QSMP_DUPLEX_SYMMETRIC_KEY_SIZE);
	rcv->pcns->exflag = qsmp_flag_none;
	rcv->pcns->mode = qsmp_mode_duplex;
	rcv->pcns->cid = 0;
	rcv->pcns->rxseq = 0;
	rcv->pcns->txseq = 0;
	rcv->pcns->receiver = true;
}

static void client_simplex_state_initialize(qsmp_kex_simplex_client_state* kcs, qsmp_connection_state* cns, const qsmp_client_verification_key* pubk)
{
	qsc_memutils_copy(kcs->keyid, pubk->keyid, QSMP_KEYID_SIZE);
	qsc_memutils_copy(kcs->verkey, pubk->verkey, QSMP_ASYMMETRIC_VERIFY_KEY_SIZE);
	qsc_memutils_clear(cns->rtcs, QSMP_DUPLEX_SYMMETRIC_KEY_SIZE);
	kcs->expiration = pubk->expiration;
	cns->target.instance = qsc_acp_uint32();
	qsc_rcs_dispose(&cns->rxcpr);
	qsc_rcs_dispose(&cns->txcpr);
	cns->exflag = qsmp_flag_none;
	cns->mode = qsmp_mode_simplex;
	cns->cid = 0;
	cns->rxseq = 0;
	cns->txseq = 0;
}

static void listener_simplex_state_initialize(qsmp_kex_simplex_server_state* kss, listener_receiver_state* rcv, const qsmp_server_signature_key* kset)
{
	qsc_memutils_copy(kss->keyid, kset->keyid, QSMP_KEYID_SIZE);
	qsc_memutils_copy(kss->sigkey, kset->sigkey, QSMP_ASYMMETRIC_SIGNING_KEY_SIZE);
	qsc_memutils_copy(kss->verkey, kset->verkey, QSMP_ASYMMETRIC_VERIFY_KEY_SIZE);
	kss->expiration = kset->expiration;
	qsc_memutils_copy(&rcv->pkpa->target, &rcv->pcns->target, sizeof(qsc_socket));
	qsc_memutils_clear((uint8_t*)&rcv->pcns->rxcpr, sizeof(qsc_rcs_state));
	qsc_memutils_clear((uint8_t*)&rcv->pcns->txcpr, sizeof(qsc_rcs_state));
	qsc_memutils_clear(&rcv->pcns->rtcs, QSMP_DUPLEX_SYMMETRIC_KEY_SIZE);
	rcv->pcns->exflag = qsmp_flag_none;
	rcv->pcns->mode = qsmp_mode_simplex;
	rcv->pcns->cid = 0;
	rcv->pcns->rxseq = 0;
	rcv->pcns->txseq = 0;
}

static void symmetric_ratchet(qsmp_connection_state* cns, const uint8_t* secret, size_t seclen)
{
	qsc_keccak_state kstate = { 0 };
	uint8_t prnd[(QSC_KECCAK_512_RATE * 3)] = { 0 };

	/* re-key the ciphers using the token, ratchet key, and configuration name */
	qsc_cshake_initialize(&kstate, qsc_keccak_rate_512, secret, seclen, QSMP_CONFIG_STRING, QSMP_CONFIG_SIZE, cns->rtcs, QSMP_DUPLEX_SYMMETRIC_KEY_SIZE);
	/* re-key the ciphers using the symmetric ratchet key */
	qsc_cshake_squeezeblocks(&kstate, qsc_keccak_rate_512, prnd, 3);

	if (cns->receiver == true)
	{
		/* initialize for decryption, and raise client channel rx */
		qsc_rcs_keyparams kp1;
		kp1.key = prnd;
		kp1.keylen = QSMP_DUPLEX_SYMMETRIC_KEY_SIZE;
		kp1.nonce = ((uint8_t*)prnd + QSMP_DUPLEX_SYMMETRIC_KEY_SIZE);
		kp1.info = NULL;
		kp1.infolen = 0;
		qsc_rcs_initialize(&cns->rxcpr, &kp1, false);

		/* initialize for encryption, and raise client channel tx */
		qsc_rcs_keyparams kp2;
		kp2.key = prnd + QSMP_DUPLEX_SYMMETRIC_KEY_SIZE + QSMP_NONCE_SIZE;
		kp2.keylen = QSMP_DUPLEX_SYMMETRIC_KEY_SIZE;
		kp2.nonce = ((uint8_t*)prnd + QSMP_DUPLEX_SYMMETRIC_KEY_SIZE + QSMP_NONCE_SIZE + QSMP_DUPLEX_SYMMETRIC_KEY_SIZE);
		kp2.info = NULL;
		kp2.infolen = 0;
		qsc_rcs_initialize(&cns->txcpr, &kp2, true);
	}
	else
	{
		/* initialize for encryption, and raise tx */
		qsc_rcs_keyparams kp1;
		kp1.key = prnd;
		kp1.keylen = QSMP_DUPLEX_SYMMETRIC_KEY_SIZE;
		kp1.nonce = ((uint8_t*)prnd + QSMP_DUPLEX_SYMMETRIC_KEY_SIZE);
		kp1.info = NULL;
		kp1.infolen = 0;
		qsc_rcs_initialize(&cns->txcpr, &kp1, true);

		/* initialize decryption, and raise rx */
		qsc_rcs_keyparams kp2;
		kp2.key = prnd + QSMP_DUPLEX_SYMMETRIC_KEY_SIZE + QSMP_NONCE_SIZE;
		kp2.keylen = QSMP_DUPLEX_SYMMETRIC_KEY_SIZE;
		kp2.nonce = ((uint8_t*)prnd + QSMP_DUPLEX_SYMMETRIC_KEY_SIZE + QSMP_NONCE_SIZE + QSMP_DUPLEX_SYMMETRIC_KEY_SIZE);
		kp2.info = NULL;
		kp2.infolen = 0;
		qsc_rcs_initialize(&cns->rxcpr, &kp2, false);
	}

	/* permute key state and store next key */
	qsc_keccak_permute(&kstate, QSC_KECCAK_PERMUTATION_ROUNDS);
	qsc_memutils_copy(cns->rtcs, (uint8_t*)kstate.state, QSMP_DUPLEX_SYMMETRIC_KEY_SIZE);
	/* erase the key array */
	qsc_memutils_clear(prnd, sizeof(prnd));
}

static bool symmetric_ratchet_response(qsmp_connection_state* cns, const qsmp_network_packet* packetin)
{
	uint8_t rkey[QSMP_RTOK_SIZE] = { 0 };
	uint8_t hdr[QSMP_HEADER_SIZE] = { 0 };
	size_t mlen;
	bool res;

	res = false;
	cns->rxseq += 1;

	if (packetin->sequence == cns->rxseq)
	{
		/* serialize the header and add it to the ciphers associated data */
		qsmp_packet_header_serialize(packetin, hdr);
		qsc_rcs_set_associated(&cns->rxcpr, hdr, QSMP_HEADER_SIZE);
		mlen = packetin->msglen - (size_t)QSMP_DUPLEX_MACTAG_SIZE;

		/* authenticate then decrypt the data */
		if (qsc_rcs_transform(&cns->rxcpr, rkey, packetin->pmessage, mlen) == true)
		{
			/* inject into key state */
			symmetric_ratchet(cns, rkey, sizeof(rkey));
			res = true;
		}
	}

	return res;
}

#if defined(QSMP_ASYMMETRIC_RATCHET)
static bool asymmetric_ratchet_response(qsmp_connection_state* cns, const qsmp_network_packet* packetin)
{
	size_t mlen;
	bool res;

	res = false;
	cns->rxseq += 1;

	if (packetin->sequence == cns->rxseq && packetin->msglen == QSMP_ASYMMETRIC_RATCHET_REQUEST_MESSAGE_SIZE)
	{
		uint8_t imsg[QSMP_ASYMMETRIC_PUBLIC_KEY_SIZE + QSMP_ASYMMETRIC_SIGNATURE_SIZE + QSMP_SIMPLEX_HASH_SIZE] = { 0 };
		uint8_t hdr[QSMP_HEADER_SIZE] = { 0 };

		/* serialize the header and add it to the ciphers associated data */
		qsmp_packet_header_serialize(packetin, hdr);
		qsc_rcs_set_associated(&cns->rxcpr, hdr, QSMP_HEADER_SIZE);
		mlen = packetin->msglen - (size_t)QSMP_DUPLEX_MACTAG_SIZE;

		/* authenticate then decrypt the data */
		if (qsc_rcs_transform(&cns->rxcpr, imsg, packetin->pmessage, mlen) == true)
		{
			uint8_t rhash[QSMP_SIMPLEX_HASH_SIZE] = { 0 };
			const uint8_t* rpub = imsg + QSMP_ASYMMETRIC_SIGNATURE_SIZE + QSMP_SIMPLEX_HASH_SIZE;

			/* verify the signature */
			if (qsmp_signature_verify(rhash, &mlen, imsg, QSMP_ASYMMETRIC_SIGNATURE_SIZE + QSMP_SIMPLEX_HASH_SIZE, m_skeyset->verkey) == true)
			{
				uint8_t lhash[QSMP_SIMPLEX_HASH_SIZE] = { 0 };

				/* hash the public key */
				qsc_sha3_compute256(lhash, rpub, QSMP_ASYMMETRIC_PUBLIC_KEY_SIZE);

				/* compare the signed hash with the local hash */
				if (qsc_intutils_verify(rhash, lhash, QSMP_SIMPLEX_HASH_SIZE) == 0)
				{
					qsmp_network_packet pkt = { 0 };
					uint8_t omsg[QSMP_ASYMMETRIC_RATCHET_RESPONSE_PACKET_SIZE] = { 0 };
					uint8_t mtmp[QSMP_ASYMMETRIC_SIGNATURE_SIZE + QSMP_SIMPLEX_HASH_SIZE + QSMP_ASYMMETRIC_CIPHER_TEXT_SIZE] = { 0 };					
					uint8_t khash[QSMP_SIMPLEX_HASH_SIZE] = { 0 };
					uint8_t secret[QSMP_SIMPLEX_SYMMETRIC_KEY_SIZE] = { 0 };
					size_t slen;

					mlen = QSMP_ASYMMETRIC_SIGNATURE_SIZE + QSMP_SIMPLEX_HASH_SIZE;

					/* encapsulate a secret with the public key */
					qsmp_cipher_encapsulate(secret, mtmp + mlen, rpub, qsc_acp_generate);

					/* compute a hash of the cipher-text */
					qsc_sha3_compute256(khash, mtmp + mlen, QSMP_ASYMMETRIC_CIPHER_TEXT_SIZE);

					/* sign the hash */
					mlen = 0;
					qsmp_signature_sign(mtmp, &mlen, khash, sizeof(khash), m_skeyset->sigkey, qsc_acp_generate);

					/* create the outbound packet */
					cns->txseq += 1;
					pkt.flag = qsmp_flag_asymmetric_ratchet_response;
					pkt.msglen = QSMP_ASYMMETRIC_RATCHET_RESPONSE_MESSAGE_SIZE;
					pkt.sequence = cns->txseq;
					mlen += QSMP_HEADER_SIZE + QSMP_ASYMMETRIC_CIPHER_TEXT_SIZE;

					/* serialize the header */
					qsmp_packet_header_serialize(&pkt, omsg);
					/* add the header to the ciphers associated data */
					qsc_rcs_set_associated(&cns->txcpr, omsg, QSMP_HEADER_SIZE);
					/* encrypt the message */
					qsc_rcs_transform(&cns->txcpr, omsg + QSMP_HEADER_SIZE, mtmp, sizeof(mtmp));
					mlen += QSMP_DUPLEX_MACTAG_SIZE;

					/* send the encrypted message */
					slen = qsc_socket_send(&cns->target, omsg, mlen, qsc_socket_send_flag_none);
					
					if (slen == mlen)
					{
						/* pass the secret to the symmetric ratchet */
						symmetric_ratchet(cns, secret, sizeof(secret));
						res = true;
					}
				}
			}
		}
	}

	return res;
}

static bool asymmetric_ratchet_finalize(qsmp_connection_state* cns, const qsmp_network_packet* packetin)
{
	uint8_t hdr[QSMP_HEADER_SIZE] = { 0 };
	uint8_t imsg[QSMP_ASYMMETRIC_CIPHER_TEXT_SIZE + QSMP_ASYMMETRIC_SIGNATURE_SIZE + QSMP_SIMPLEX_HASH_SIZE] = { 0 };
	uint8_t rhash[QSMP_SIMPLEX_HASH_SIZE] = { 0 };
	uint8_t secret[QSMP_SIMPLEX_SYMMETRIC_KEY_SIZE] = { 0 };
	size_t mlen;
	size_t mpos;
	bool res;

	cns->rxseq += 1;

	res = false;
	mlen = 0;
	mpos = QSMP_ASYMMETRIC_SIGNATURE_SIZE + QSMP_SIMPLEX_HASH_SIZE;

	if (packetin->sequence == cns->rxseq && packetin->msglen == QSMP_ASYMMETRIC_RATCHET_RESPONSE_MESSAGE_SIZE)
	{
		/* serialize the header and add it to the ciphers associated data */
		qsmp_packet_header_serialize(packetin, hdr);
		qsc_rcs_set_associated(&cns->rxcpr, hdr, QSMP_HEADER_SIZE);
		mlen = packetin->msglen - (size_t)QSMP_DUPLEX_MACTAG_SIZE;

		/* authenticate then decrypt the data */
		if (qsc_rcs_transform(&cns->rxcpr, imsg, packetin->pmessage, mlen) == true)
		{
			/* verify the signature using the senders public key */
			if (qsmp_signature_verify(rhash, &mlen, imsg, mpos, m_skeyset->verkey) == true)
			{
				uint8_t lhash[QSMP_SIMPLEX_HASH_SIZE] = { 0 };

				/* compute a hash of cipher-text */
				qsc_sha3_compute256(lhash, imsg + mpos, QSMP_ASYMMETRIC_CIPHER_TEXT_SIZE);

				/* verify the embedded hash against a hash of the cipher-text */
				if (qsc_intutils_verify(rhash, lhash, QSMP_SIMPLEX_HASH_SIZE) == 0)
				{
					/* decapsulate the secret */
					res = qsmp_cipher_decapsulate(secret, imsg + mpos, m_ckeyset->prikey);

					if (res == true)
					{
						/* pass the secret to the symmetric ratchet */
						symmetric_ratchet(cns, secret, sizeof(secret));
					}

					qsc_memutils_clear(m_ckeyset->prikey, QSMP_ASYMMETRIC_PRIVATE_KEY_SIZE);
					qsc_memutils_clear(m_ckeyset->pubkey, QSMP_ASYMMETRIC_PUBLIC_KEY_SIZE);
					qsmp_asymmetric_cipher_keypair_dispose(m_ckeyset);
				}
			}
		}
	}

	return res;
}
#endif

static void client_connection_dispose(client_receiver_state* prcv)
{
	/* send a close notification to the server */
	if (qsc_socket_is_connected(&prcv->pcns->target) == true)
	{
		qsmp_connection_close(prcv->pcns, qsmp_error_none, true);
	}

	/* dispose of resources */
	qsmp_connection_state_dispose(prcv->pcns);
}

static void client_receive_loop(client_receiver_state* prcv)
{
	assert(prcv != NULL);

	qsmp_network_packet pkt = { 0 };
	char cadd[QSC_SOCKET_ADDRESS_MAX_SIZE] = { 0 };
	uint8_t* rbuf;
	size_t mlen;
	size_t plen;
	size_t slen;
	qsmp_errors qerr;

	qsc_memutils_copy(cadd, (const char*)prcv->pcns->target.address, sizeof(cadd));

	rbuf = (uint8_t*)qsc_memutils_malloc(QSMP_HEADER_SIZE);

	if (rbuf != NULL)
	{
		while (prcv->pcns->target.connection_status == qsc_socket_state_connected)
		{
			mlen = 0;
			slen = 0;
			qsc_memutils_clear(rbuf, QSMP_HEADER_SIZE);

			plen = qsc_socket_peek(&prcv->pcns->target, rbuf, QSMP_HEADER_SIZE);

			if (plen == QSMP_HEADER_SIZE)
			{
				qsmp_packet_header_deserialize(rbuf, &pkt);

				if (pkt.msglen > 0 && pkt.msglen <= QSMP_MESSAGE_MAX)
				{
					plen = pkt.msglen + QSMP_HEADER_SIZE;
					rbuf = (uint8_t*)qsc_memutils_realloc(rbuf, plen);

					if (rbuf != NULL)
					{
						qsc_memutils_clear(rbuf, plen);
						mlen = qsc_socket_receive(&prcv->pcns->target, rbuf, plen, qsc_socket_receive_flag_wait_all);

						if (mlen > 0)
						{
							pkt.pmessage = rbuf + QSMP_HEADER_SIZE;

							if (pkt.flag == qsmp_flag_encrypted_message)
							{
								uint8_t* rmsg;

								slen = pkt.msglen;
								slen -= prcv->pcns->mode == qsmp_mode_duplex ? QSMP_DUPLEX_MACTAG_SIZE : QSMP_SIMPLEX_MACTAG_SIZE;
								rmsg = (uint8_t*)qsc_memutils_malloc(slen);

								if (rmsg != NULL)
								{
									qsc_memutils_clear(rmsg, slen);
									qerr = qsmp_packet_decrypt(prcv->pcns, rmsg, &mlen, &pkt);

									if (qerr == qsmp_error_none)
									{
										prcv->callback(prcv->pcns, rmsg, mlen);
									}
									else
									{
										/* close the connection on authentication failure */
										qsmp_log_write(qsmp_messages_decryption_fail, cadd);
										break;
									}

									qsc_memutils_alloc_free(rmsg);
								}
								else
								{
									/* close the connection on memory allocation failure */
									qsmp_log_write(qsmp_messages_allocate_fail, cadd);
									break;
								}
							}
							else if (pkt.flag == qsmp_flag_connection_terminate)
							{
								qsmp_log_write(qsmp_messages_disconnect, cadd);
								break;
							}
							else if (pkt.flag == qsmp_flag_keep_alive_request)
							{
								const size_t klen = QSMP_HEADER_SIZE + QSMP_TIMESTAMP_SIZE;
								/* copy the keep-alive packet and send it back */
								pkt.flag = qsmp_flag_keep_alive_response;
								qsmp_packet_header_serialize(&pkt, rbuf);
								qsc_socket_send(&prcv->pcns->target, rbuf, klen, qsc_socket_send_flag_none);
							}
							else if (pkt.flag == qsmp_flag_symmetric_ratchet_request)
							{
								if (symmetric_ratchet_response(prcv->pcns, &pkt) == false)
								{
									qsmp_log_write(qsmp_messages_keepalive_timeout, (const char*)prcv->pcns->target.address);
									break;
								}
							}
#if defined(QSMP_ASYMMETRIC_RATCHET)
							else if (pkt.flag == qsmp_flag_asymmetric_ratchet_request)
							{
								if (prcv->pcns->mode == qsmp_mode_duplex)
								{
									if (asymmetric_ratchet_response(prcv->pcns, &pkt) == false)
									{
										qsmp_log_write(qsmp_messages_keepalive_timeout, (const char*)prcv->pcns->target.address);
										break;
									}
								}
							}
							else if (pkt.flag == qsmp_flag_asymmetric_ratchet_response)
							{
								if (prcv->pcns->mode == qsmp_mode_duplex)
								{
									if (asymmetric_ratchet_finalize(prcv->pcns, &pkt) == false)
									{
										qsmp_log_write(qsmp_messages_keepalive_timeout, (const char*)prcv->pcns->target.address);
										break;
									}
								}
							}
#endif
							else
							{
								qsc_socket_exceptions err = qsc_socket_get_last_error();

								if (err != qsc_socket_exception_success)
								{
									qsmp_log_error(qsmp_messages_receive_fail, err, cadd);

									/* fatal socket errors */
									if (err == qsc_socket_exception_circuit_reset ||
										err == qsc_socket_exception_circuit_terminated ||
										err == qsc_socket_exception_circuit_timeout ||
										err == qsc_socket_exception_dropped_connection ||
										err == qsc_socket_exception_network_failure ||
										err == qsc_socket_exception_shut_down)
									{
										qsmp_log_write(qsmp_messages_connection_fail, cadd);
										break;
									}
								}
							}
						}
						else
						{
							qsmp_log_write(qsmp_messages_receive_fail, cadd);
							break;
						}
					}
				}
				else
				{
					/* close the connection on memory allocation failure */
					qsmp_log_write(qsmp_messages_allocate_fail, cadd);
					break;
				}
			}
			else
			{
				qsmp_log_write(qsmp_messages_receive_fail, cadd);
				break;
			}
		}

		qsc_memutils_alloc_free(rbuf);
	}
	else
	{
		qsmp_log_write(qsmp_messages_allocate_fail, cadd);
	}
}

static qsmp_errors listener_send_keep_alive(qsmp_keep_alive_state* kctx, const qsc_socket* sock)
{
	assert(kctx != NULL);
	assert(sock != NULL);

	qsmp_errors qerr;

	qerr = qsmp_error_bad_keep_alive;

	if (qsc_socket_is_connected(sock) == true)
	{
		uint8_t spct[QSMP_HEADER_SIZE + QSMP_TIMESTAMP_SIZE] = { 0 };
		qsmp_network_packet resp = { 0 };
		uint64_t etime;
		size_t slen;

		/* set the time and store in keep-alive struct */
		etime = qsc_timestamp_datetime_utc();
		kctx->etime = etime;

		/* assemble the keep-alive packet */
		resp.pmessage = spct + QSMP_HEADER_SIZE;
		resp.flag = qsmp_flag_keep_alive_request;
		resp.sequence = kctx->seqctr;
		resp.msglen = QSMP_TIMESTAMP_SIZE;
		qsc_intutils_le64to8(resp.pmessage, etime);
		qsmp_packet_header_serialize(&resp, spct);

		slen = qsc_socket_send(sock, spct, sizeof(spct), qsc_socket_send_flag_none);

		if (slen == QSMP_HEADER_SIZE + QSMP_TIMESTAMP_SIZE)
		{
			qerr = qsmp_error_none;
		}
	}

	return qerr;
}

static void listener_keepalive_loop(qsmp_keep_alive_state* kpa)
{
	assert(kpa != NULL);

	qsc_mutex mtx;
	qsmp_errors qerr;

	do
	{
		mtx = qsc_async_mutex_lock_ex();
		kpa->recd = false;
		qerr = listener_send_keep_alive(kpa, &kpa->target);

		if (kpa->recd == false)
		{
			qerr = qsmp_error_keepalive_expired;
		}

		qsc_async_mutex_unlock_ex(mtx);
		qsc_async_thread_sleep(QSMP_KEEPALIVE_TIMEOUT);
	} 
	while (qerr == qsmp_error_none);
}

static void listener_receive_loop(listener_receiver_state* prcv)
{
	assert(prcv != NULL);

	qsmp_network_packet pkt = { 0 };
	char cadd[QSC_SOCKET_ADDRESS_MAX_SIZE] = { 0 };
	uint8_t* rbuf;
	size_t mlen;
	size_t plen;
	size_t slen;
	qsmp_errors qerr;

	qsc_memutils_copy(cadd, (const char*)prcv->pcns->target.address, sizeof(cadd));

	rbuf = (uint8_t*)qsc_memutils_malloc(QSMP_HEADER_SIZE);

	if (rbuf != NULL)
	{
		while (prcv->pcns->target.connection_status == qsc_socket_state_connected)
		{
			mlen = 0;
			slen = 0;
			qsc_memutils_clear(rbuf, QSMP_HEADER_SIZE);

			plen = qsc_socket_peek(&prcv->pcns->target, rbuf, QSMP_HEADER_SIZE);

			if (plen == QSMP_HEADER_SIZE)
			{
				qsmp_packet_header_deserialize(rbuf, &pkt);

				if (pkt.msglen > 0 && pkt.msglen <= QSMP_MESSAGE_MAX)
				{
					plen = pkt.msglen + QSMP_HEADER_SIZE;
					rbuf = (uint8_t*)qsc_memutils_realloc(rbuf, plen);

					if (rbuf != NULL)
					{
						qsc_memutils_clear(rbuf, plen);
						mlen = qsc_socket_receive(&prcv->pcns->target, rbuf, plen, qsc_socket_receive_flag_wait_all);

						if (mlen > 0)
						{
							pkt.pmessage = rbuf + QSMP_HEADER_SIZE;

							if (pkt.flag == qsmp_flag_encrypted_message)
							{
								uint8_t* rmsg;

								slen = pkt.msglen;
								slen -= prcv->pcns->mode == qsmp_mode_duplex ? QSMP_DUPLEX_MACTAG_SIZE : QSMP_SIMPLEX_MACTAG_SIZE;
								rmsg = (uint8_t*)qsc_memutils_malloc(slen);

								if (rmsg != NULL)
								{
									qsc_memutils_clear(rmsg, slen);
									qerr = qsmp_packet_decrypt(prcv->pcns, rmsg, &mlen, &pkt);

									if (qerr == qsmp_error_none)
									{
										prcv->callback(prcv->pcns, rmsg, mlen);
									}
									else
									{
										/* close the connection on authentication failure */
										qsmp_log_write(qsmp_messages_decryption_fail, cadd);
										break;
									}

									qsc_memutils_alloc_free(rmsg);
								}
								else
								{
									/* close the connection on memory allocation failure */
									qsmp_log_write(qsmp_messages_allocate_fail, cadd);
									break;
								}
							}
							else if (pkt.flag == qsmp_flag_connection_terminate)
							{
								qsmp_log_write(qsmp_messages_disconnect, cadd);
								break;
							}
							else if (pkt.flag == qsmp_flag_keep_alive_response)
							{
								/* test the keepalive */

								if (pkt.sequence == prcv->pkpa->seqctr)
								{
									uint64_t tme;

									tme = qsc_intutils_le8to64(pkt.pmessage);

									if (prcv->pkpa->etime == tme)
									{
										prcv->pkpa->seqctr += 1;
										prcv->pkpa->recd = true;
									}
									else
									{
										qsmp_log_write(qsmp_messages_keepalive_fail, (const char*)prcv->pcns->target.address);
										break;
									}
								}
								else
								{
									qsmp_log_write(qsmp_messages_keepalive_timeout, (const char*)prcv->pcns->target.address);
									break;
								}
							}
							else if (pkt.flag == qsmp_flag_symmetric_ratchet_request)
							{
								if (symmetric_ratchet_response(prcv->pcns, &pkt) == false)
								{
									qsmp_log_write(qsmp_messages_keepalive_timeout, (const char*)prcv->pcns->target.address);
									break;
								}
							}
			#if defined(QSMP_ASYMMETRIC_RATCHET)
							else if (pkt.flag == qsmp_flag_asymmetric_ratchet_request)
							{
								if (asymmetric_ratchet_response(prcv->pcns, &pkt) == false)
								{
									qsmp_log_write(qsmp_messages_keepalive_timeout, (const char*)prcv->pcns->target.address);
									break;
								}
							}
							else if (pkt.flag == qsmp_flag_asymmetric_ratchet_response)
							{
								if (asymmetric_ratchet_finalize(prcv->pcns, &pkt) == false)
								{
									qsmp_log_write(qsmp_messages_keepalive_timeout, (const char*)prcv->pcns->target.address);
									break;
								}
							}
			#endif
							else
							{
								qsc_socket_exceptions err = qsc_socket_get_last_error();

								if (err != qsc_socket_exception_success)
								{
									qsmp_log_error(qsmp_messages_receive_fail, err, cadd);

									/* fatal socket errors */
									if (err == qsc_socket_exception_circuit_reset ||
										err == qsc_socket_exception_circuit_terminated ||
										err == qsc_socket_exception_circuit_timeout ||
										err == qsc_socket_exception_dropped_connection ||
										err == qsc_socket_exception_network_failure ||
										err == qsc_socket_exception_shut_down)
									{
										qsmp_log_write(qsmp_messages_connection_fail, cadd);
										break;
									}
								}
							}
						}
						else
						{
							qsmp_log_write(qsmp_messages_receive_fail, cadd);
							break;
						}
					}
				}
				else
				{
					/* close the connection on memory allocation failure */
					qsmp_log_write(qsmp_messages_allocate_fail, cadd);
					break;
				}
			}
			else
			{
				qsmp_log_write(qsmp_messages_receive_fail, cadd);
				break;
			}
		}

		qsc_memutils_alloc_free(rbuf);
	}
	else
	{
		qsmp_log_write(qsmp_messages_allocate_fail, cadd);
	}
}

static qsmp_errors listener_duplex_start(const qsmp_server_signature_key* kset, 
	listener_receiver_state* prcv, 
	void (*send_func)(qsmp_connection_state*),
	bool (*key_query)(uint8_t* rvkey, const uint8_t* pkid))
{
	assert(kset != NULL);
	assert(prcv != NULL);
	assert(send_func != NULL);

	qsmp_kex_duplex_server_state* pkss;
	qsmp_errors qerr;

	qsmp_logger_initialize(NULL);
	qerr = qsmp_error_invalid_input;
	pkss = (qsmp_kex_duplex_server_state*)qsc_memutils_malloc(sizeof(qsmp_kex_duplex_server_state));

	if (pkss != NULL)
	{
		qsc_memutils_clear((uint8_t*)pkss, sizeof(qsmp_kex_duplex_server_state));

		/* initialize the kex */
		listener_duplex_state_initialize(pkss, prcv, kset, key_query);
		qerr = qsmp_kex_duplex_server_key_exchange(pkss, prcv->pcns);

		if (qerr == qsmp_error_none)
		{
#if defined(QSMP_ASYMMETRIC_RATCHET)
			m_skeyset = qsmp_asymmetric_signature_keypair_initialize();

			/* store the local signing key and the remote verify key for asymmetyric ratchet option */
			qsc_memutils_copy(m_skeyset->sigkey, kset->sigkey, QSMP_ASYMMETRIC_SIGNING_KEY_SIZE);
			qsc_memutils_copy(m_skeyset->verkey, pkss->rverkey, QSMP_ASYMMETRIC_VERIFY_KEY_SIZE);
#endif
			/* start the keep-alive mechanism on a new thread */
			qsc_async_thread_create((void*)&listener_keepalive_loop, prcv->pkpa);
			/* initialize the receiver loop on a new thread */
			qsc_async_thread_create((void*)&listener_receive_loop, prcv);

			/* start the send loop on the *main* thread */
			send_func(prcv->pcns);

#if defined(QSMP_ASYMMETRIC_RATCHET)
			qsmp_asymmetric_signature_keypair_dispose(m_skeyset);
#endif
		}

		qsc_memutils_alloc_free(pkss);
		pkss = NULL;
	}

	return qerr;
}

static qsmp_errors listener_simplex_start(const qsmp_server_signature_key* kset, 
	listener_receiver_state* prcv, 
	void (*send_func)(qsmp_connection_state*))
{
	assert(kset != NULL);
	assert(prcv != NULL);
	assert(send_func != NULL);

	qsmp_kex_simplex_server_state* pkss;
	qsmp_errors qerr;

	qsmp_logger_initialize(NULL);
	qerr = qsmp_error_invalid_input;
	pkss = (qsmp_kex_simplex_server_state*)qsc_memutils_malloc(sizeof(qsmp_kex_simplex_server_state));

	if (pkss != NULL)
	{
		qsc_memutils_clear((uint8_t*)pkss, sizeof(qsmp_kex_simplex_server_state));

		/* initialize the kex */
		listener_simplex_state_initialize(pkss, prcv, kset);
		qerr = qsmp_kex_simplex_server_key_exchange(pkss, prcv->pcns);

		qsc_memutils_alloc_free(pkss);
		pkss = NULL;

		if (qerr == qsmp_error_none)
		{
			/* start the keep-alive mechanism on a new thread */
			qsc_async_thread_create((void*)&listener_keepalive_loop, prcv->pkpa);
			/* initialize the receiver loop on a new thread */
			qsc_async_thread_create((void*)&listener_receive_loop, prcv);

			/* start the send loop on the *main* thread */
			send_func(prcv->pcns);
		}
	}

	return qerr;
}
/** \endcond */

/* Public Functions */

/* The Signal ratchet system:
* Signal forwards a set of public cipher keys from the server to client.
* The client uses a public key to encrypt a shared secret and forward the cipher-text to the server.
* The server decrypts the cipher-text, and both client and server use the secret to re-key a symmetric cipher,
* used to encrypt/decrypt text and files.
* This system is very 'top heavy'. 
* It requires the client and server to cache large asymmetric public/private keys,
* changes the key frequently (per message), and large transfers of asymmetric key chains.
* When a server connects to multiple clients, it must track which key-set belongs to which client,
* cache multiple keys while waiting for cipher-text response, scan cached keys for time-outs,
* and generate and send large sets of keys to clients.
* 
* To make this a more efficient model, asymmetric keys should only be cached for as long as they are needed;
* they are created, transmitted, deployed, and the memory released. 
* The symmetric cipher keys can still be replaced, either periodically or with every message, 
* and a periodic injection of entropy with an asymmetric exchange, that can be triggered by the application,
* ex. exceeding a bandwidth count, or per session or even per message, triggers exchange and injection.
* Previous keys can still be protected by running keccak permute on a persistant key state, and using that to
* re-key the symmetric ciphers (possibly with a salt sent over the encrypted channel).
* This will still require key tracking when dealing with server/client, but keys are removed as soon as they are used,
* in a variable collection (item|tag: find/add/remove).
* In a p2p configuration, clients can each sign their piece of the exchange, public key and cipher-text, 
* and no need to track keys as calls are receive-waiting and can be executed in one function.
*/

#if defined(QSMP_ASYMMETRIC_RATCHET)
bool qsmp_duplex_send_asymmetric_ratchet_request(qsmp_connection_state* cns)
{
	assert(cns != NULL);
	assert(cns->mode == qsmp_mode_duplex);

	bool res;
	
	res = false;

	if (cns != NULL && cns->mode == qsmp_mode_duplex)
	{
		qsmp_network_packet pkt = { 0 };
		uint8_t khash[QSMP_SIMPLEX_HASH_SIZE] = { 0 };
		uint8_t pmsg[QSMP_ASYMMETRIC_SIGNATURE_SIZE + QSMP_SIMPLEX_HASH_SIZE + QSMP_ASYMMETRIC_PUBLIC_KEY_SIZE] = { 0 };
		uint8_t spct[QSMP_ASYMMETRIC_RATCHET_REQUEST_PACKET_SIZE] = { 0 };
		size_t mlen;
		size_t smlen;
		size_t slen;

		cns->txseq += 1;
		pkt.pmessage = spct + QSMP_HEADER_SIZE;
		pkt.flag = qsmp_flag_asymmetric_ratchet_request;
		pkt.msglen = QSMP_ASYMMETRIC_RATCHET_REQUEST_MESSAGE_SIZE;
		pkt.sequence = cns->txseq;

		qsmp_packet_header_serialize(&pkt, spct);
		mlen = QSMP_HEADER_SIZE;

		/* generate the asymmetric cipher keypair */
		m_ckeyset = qsmp_asymmetric_cipher_keypair_initialize();

		if (m_ckeyset != NULL)
		{
			qsmp_cipher_generate_keypair(m_ckeyset->pubkey, m_ckeyset->prikey, qsc_acp_generate);

			/* hash the public key */
			qsc_sha3_compute256(khash, m_ckeyset->pubkey, QSMP_ASYMMETRIC_PUBLIC_KEY_SIZE);

			/* sign the hash */
			smlen = 0;
			qsmp_signature_sign(pmsg, &smlen, khash, sizeof(khash), m_skeyset->sigkey, qsc_acp_generate);
			mlen += smlen;

			/* copy the key to the message */
			qsc_memutils_copy(pmsg + smlen, m_ckeyset->pubkey, QSMP_ASYMMETRIC_PUBLIC_KEY_SIZE);
			mlen += QSMP_ASYMMETRIC_PUBLIC_KEY_SIZE;

			/* encrypt the message */
			qsc_rcs_set_associated(&cns->txcpr, spct, QSMP_HEADER_SIZE);
			qsc_rcs_transform(&cns->txcpr, pkt.pmessage, pmsg, sizeof(pmsg));
			mlen += QSMP_DUPLEX_MACTAG_SIZE;

			/* send the ratchet request */
			slen = qsc_socket_send(&cns->target, spct, mlen, qsc_socket_send_flag_none);

			if (slen == mlen)
			{
				res = true;
			}
		}
	}

	return res;
}
#endif

bool qsmp_duplex_send_symmetric_ratchet_request(qsmp_connection_state* cns)
{
	assert(cns != NULL);
	assert(cns->mode == qsmp_mode_duplex);

	size_t plen;
	size_t slen;
	bool res;
	
	res = false;

	if (cns != NULL && cns->mode == qsmp_mode_duplex)
	{
		qsmp_network_packet pkt = { 0 };
		uint8_t pmsg[QSMP_RTOK_SIZE + QSMP_DUPLEX_MACTAG_SIZE] = { 0 };
		uint8_t rkey[QSMP_RTOK_SIZE] = { 0 };

		/* generate the token key */
		if (qsc_acp_generate(rkey, sizeof(rkey)) == true)
		{
			uint8_t hdr[QSMP_HEADER_SIZE] = { 0 };
			uint8_t spct[QSMP_HEADER_SIZE + QSMP_RTOK_SIZE + QSMP_DUPLEX_MACTAG_SIZE] = { 0 };

			cns->txseq += 1;
			pkt.pmessage = pmsg;
			pkt.flag = qsmp_flag_symmetric_ratchet_request;
			pkt.msglen = QSMP_RTOK_SIZE + QSMP_DUPLEX_MACTAG_SIZE;
			pkt.sequence = cns->txseq;

			/* serialize the header and add it to the ciphers associated data */
			qsmp_packet_header_serialize(&pkt, hdr);
			qsc_rcs_set_associated(&cns->txcpr, hdr, QSMP_HEADER_SIZE);
			/* encrypt the message */
			qsc_rcs_transform(&cns->txcpr, pkt.pmessage, rkey, sizeof(rkey));

			/* convert the packet to bytes */
			plen = qsmp_packet_to_stream(&pkt, spct);

			/* send the ratchet request */
			slen = qsc_socket_send(&cns->target, spct, plen, qsc_socket_send_flag_none);

			if (slen == plen)
			{
				symmetric_ratchet(cns, rkey, sizeof(rkey));
				res = true;
			}
		}
	}

	return res;
}

qsmp_errors qsmp_client_duplex_connect_ipv4(const qsmp_server_signature_key* kset, 
	const qsmp_client_verification_key* rverkey, 
	const qsc_ipinfo_ipv4_address* address, uint16_t port,
	void (*send_func)(qsmp_connection_state*), 
	void (*receive_callback)(qsmp_connection_state*, const uint8_t*, size_t))
{
	assert(kset != NULL);
	assert(rverkey != NULL);
	assert(send_func != NULL);
	assert(send_func != NULL);
	assert(receive_callback != NULL);

	qsmp_kex_duplex_client_state* kcs;
	client_receiver_state* prcv;
	qsc_socket_exceptions serr;
	qsmp_errors qerr;

	kcs = NULL;
	prcv = NULL;
	qsmp_logger_initialize(NULL);

	if (kset != NULL && rverkey != NULL && address != NULL && send_func != NULL && receive_callback != NULL)
	{
		kcs = (qsmp_kex_duplex_client_state*)qsc_memutils_malloc(sizeof(qsmp_kex_duplex_client_state));

		if (kcs != NULL)
		{
			prcv = (client_receiver_state*)qsc_memutils_malloc(sizeof(client_receiver_state));

			if (prcv != NULL)
			{
				qsc_memutils_clear(kcs, sizeof(qsmp_kex_duplex_client_state));
				qsc_memutils_clear(prcv, sizeof(client_receiver_state));

				prcv->pcns = (qsmp_connection_state*)qsc_memutils_malloc(sizeof(qsmp_connection_state));

				if (prcv->pcns != NULL)
				{
					prcv->callback = receive_callback;
					qsc_socket_client_initialize(&prcv->pcns->target);

					serr = qsc_socket_client_connect_ipv4(&prcv->pcns->target, address, port);

					if (serr == qsc_socket_exception_success)
					{
						/* initialize the client */
						client_duplex_state_initialize(kcs, prcv->pcns, kset, rverkey);
						/* perform the simplex key exchange */
						qerr = qsmp_kex_duplex_client_key_exchange(kcs, prcv->pcns);
						qsc_memutils_alloc_free(kcs);
						kcs = NULL;

						if (qerr == qsmp_error_none)
						{
#if defined(QSMP_ASYMMETRIC_RATCHET)
							m_skeyset = qsmp_asymmetric_signature_keypair_initialize();
							/* store the local signing key and the remote verify key for asymmetyric ratchet option */
							qsc_memutils_copy(m_skeyset->sigkey, kset->sigkey, QSMP_ASYMMETRIC_SIGNING_KEY_SIZE);
							qsc_memutils_copy(m_skeyset->verkey, rverkey->verkey, QSMP_ASYMMETRIC_VERIFY_KEY_SIZE);
#endif
							/* start the receive loop on a new thread */
							qsc_async_thread_create((void*)&client_receive_loop, prcv);

							/* start the send loop on the main thread */
							send_func(prcv->pcns);

							/* disconnect the socket */
							client_connection_dispose(prcv);

#if defined(QSMP_ASYMMETRIC_RATCHET)
							qsmp_asymmetric_signature_keypair_dispose(m_skeyset);
#endif
						}
						else
						{
							qsmp_log_write(qsmp_messages_kex_fail, (const char*)prcv->pcns->target.address);
							qerr = qsmp_error_exchange_failure;
						}
					}
					else
					{
						qsmp_log_write(qsmp_messages_kex_fail, (const char*)prcv->pcns->target.address);
						qerr = qsmp_error_connection_failure;
					}
				}
				else
				{
					qsmp_log_message(qsmp_messages_allocate_fail);
					qerr = qsmp_error_memory_allocation;
				}
			}
			else
			{
				qsmp_log_message(qsmp_messages_allocate_fail);
				qerr = qsmp_error_memory_allocation;
			}
		}
		else
		{
			qsmp_log_message(qsmp_messages_allocate_fail);
			qerr = qsmp_error_memory_allocation;
		}
	}
	else
	{
		qsmp_log_message(qsmp_messages_invalid_request);
		qerr = qsmp_error_invalid_input;
	}

	if (kcs != NULL)
	{
		qsc_memutils_alloc_free(kcs);
		kcs = NULL;
	}

	if (prcv != NULL)
	{
		if (prcv->pcns != NULL)
		{
			qsc_memutils_alloc_free(prcv->pcns);
			prcv->pcns = NULL;
		}

		prcv->callback = NULL;
		qsc_memutils_alloc_free(prcv);
		prcv = NULL;
	}

	return qerr;
}

qsmp_errors qsmp_client_duplex_connect_ipv6(const qsmp_server_signature_key* kset, 
	const qsmp_client_verification_key* rverkey,
	const qsc_ipinfo_ipv6_address* address, uint16_t port,
	void (*send_func)(qsmp_connection_state*),
	void (*receive_callback)(qsmp_connection_state*, const uint8_t*, size_t))
{
	assert(kset != NULL);
	assert(rverkey != NULL);
	assert(send_func != NULL);
	assert(send_func != NULL);
	assert(receive_callback != NULL);

	qsmp_kex_duplex_client_state* kcs;
	client_receiver_state* prcv;
	qsc_socket_exceptions serr;
	qsmp_errors qerr;

	kcs = NULL;
	prcv = NULL;
	qsmp_logger_initialize(NULL);

	if (kset != NULL && rverkey != NULL && address != NULL && send_func != NULL && receive_callback != NULL)
	{
		kcs = (qsmp_kex_duplex_client_state*)qsc_memutils_malloc(sizeof(qsmp_kex_duplex_client_state));

		if (kcs != NULL)
		{
			prcv = (client_receiver_state*)qsc_memutils_malloc(sizeof(client_receiver_state));

			if (prcv != NULL)
			{
				qsc_memutils_clear(kcs, sizeof(qsmp_kex_duplex_client_state));
				qsc_memutils_clear(prcv, sizeof(client_receiver_state));

				prcv->pcns = (qsmp_connection_state*)qsc_memutils_malloc(sizeof(qsmp_connection_state));

				if (prcv->pcns != NULL)
				{
					prcv->callback = receive_callback;
					qsc_socket_client_initialize(&prcv->pcns->target);

					serr = qsc_socket_client_connect_ipv6(&prcv->pcns->target, address, port);

					if (serr == qsc_socket_exception_success)
					{
						/* initialize the client */
						client_duplex_state_initialize(kcs, prcv->pcns, kset, rverkey);
						/* perform the simplex key exchange */
						qerr = qsmp_kex_duplex_client_key_exchange(kcs, prcv->pcns);
						qsc_memutils_alloc_free(kcs);
						kcs = NULL;

						if (qerr == qsmp_error_none)
						{
#if defined(QSMP_ASYMMETRIC_RATCHET)
							m_skeyset = qsmp_asymmetric_signature_keypair_initialize();
							/* store the local signing key and the remote verify key for asymmetyric ratchet option */
							qsc_memutils_copy(m_skeyset->sigkey, kset->sigkey, QSMP_ASYMMETRIC_SIGNING_KEY_SIZE);
							qsc_memutils_copy(m_skeyset->verkey, rverkey->verkey, QSMP_ASYMMETRIC_VERIFY_KEY_SIZE);
#endif

							/* start the receive loop on a new thread */
							qsc_async_thread_create((void*)&client_receive_loop, prcv);

							/* start the send loop on the main thread */
							send_func(prcv->pcns);

							/* disconnect the socket */
							client_connection_dispose(prcv);

#if defined(QSMP_ASYMMETRIC_RATCHET)
							qsmp_asymmetric_signature_keypair_dispose(m_skeyset);
#endif
						}
						else
						{
							qsmp_log_write(qsmp_messages_kex_fail, (const char*)prcv->pcns->target.address);
							qerr = qsmp_error_exchange_failure;
						}

						qsmp_connection_close(prcv->pcns, qsmp_error_none, true);
					}
					else
					{
						qsmp_log_write(qsmp_messages_kex_fail, (const char*)prcv->pcns->target.address);
						qerr = qsmp_error_connection_failure;
					}
				}
				else
				{
					qsmp_log_message(qsmp_messages_allocate_fail);
					qerr = qsmp_error_memory_allocation;
				}
			}
			else
			{
				qsmp_log_message(qsmp_messages_allocate_fail);
				qerr = qsmp_error_memory_allocation;
			}
		}
		else
		{
			qsmp_log_message(qsmp_messages_allocate_fail);
			qerr = qsmp_error_memory_allocation;
		}
	}
	else
	{
		qsmp_log_message(qsmp_messages_invalid_request);
		qerr = qsmp_error_invalid_input;
	}

	if (kcs != NULL)
	{
		qsc_memutils_alloc_free(kcs);
		kcs = NULL;
	}

	if (prcv != NULL)
	{
		if (prcv->pcns != NULL)
		{
			qsc_memutils_alloc_free(prcv->pcns);
			prcv->pcns = NULL;
		}

		prcv->callback = NULL;
		qsc_memutils_alloc_free(prcv);
		prcv = NULL;
	}

	return qerr;
}

qsmp_errors qsmp_client_duplex_listen_ipv4(const qsmp_server_signature_key* kset, 
	void (*send_func)(qsmp_connection_state*), 
	void (*receive_callback)(qsmp_connection_state*, const uint8_t*, size_t), 
	bool (*key_query)(uint8_t* rvkey, const uint8_t* pkid))
{
	assert(kset != NULL);
	assert(send_func != NULL);
	assert(receive_callback != NULL);

	qsc_ipinfo_ipv4_address addt = { 0 };
	listener_receiver_state* prcv;
	qsc_socket srvs;
	qsc_socket_exceptions serr;
	qsmp_errors qerr;

	qsmp_logger_initialize(NULL);
	prcv = NULL;

	if (kset != NULL && send_func != NULL && receive_callback != NULL)
	{
		prcv = (listener_receiver_state*)qsc_memutils_malloc(sizeof(listener_receiver_state));

		if (prcv != NULL)
		{
			prcv->pcns = (qsmp_connection_state*)qsc_memutils_malloc(sizeof(qsmp_connection_state));
			prcv->pkpa = (qsmp_keep_alive_state*)qsc_memutils_malloc(sizeof(qsmp_keep_alive_state));

			if (prcv->pcns != NULL && prcv->pkpa != NULL)
			{
				prcv->callback = receive_callback;
				qsc_memutils_clear((uint8_t*)prcv->pcns, sizeof(qsmp_connection_state));
				qsc_memutils_clear((uint8_t*)prcv->pkpa, sizeof(qsmp_keep_alive_state));

				addt = qsc_ipinfo_ipv4_address_any();
				qsc_socket_server_initialize(&prcv->pcns->target);
				qsc_socket_server_initialize(&srvs);

				serr = qsc_socket_server_listen_ipv4(&srvs, &prcv->pcns->target, &addt, QSMP_CLIENT_PORT);

				if (serr == qsc_socket_exception_success)
				{
					qerr = listener_duplex_start(kset, prcv, send_func, key_query);
				}
				else
				{
					qsmp_log_message(qsmp_messages_connection_fail);
					qerr = qsmp_error_connection_failure;
				}
			}
			else
			{
				qsmp_log_message(qsmp_messages_allocate_fail);
				qsc_memutils_alloc_free(prcv);
				qerr = qsmp_error_memory_allocation;
			}
		}
		else
		{
			qsmp_log_message(qsmp_messages_allocate_fail);
			qerr = qsmp_error_memory_allocation;
		}
	}
	else
	{
		qsmp_log_message(qsmp_messages_invalid_request);
		qerr = qsmp_error_invalid_input;
	}

	return qerr;
}

qsmp_errors qsmp_client_duplex_listen_ipv6(const qsmp_server_signature_key* kset, 
	void (*send_func)(qsmp_connection_state*),
	void (*receive_callback)(qsmp_connection_state*, const uint8_t*, size_t),
	bool (*key_query)(uint8_t* rvkey, const uint8_t* pkid))
{
	assert(kset != NULL);
	assert(send_func != NULL);
	assert(receive_callback != NULL);

	qsc_ipinfo_ipv6_address addt = { 0 };
	listener_receiver_state* prcv;
	qsc_socket srvs;
	qsc_socket_exceptions serr;
	qsmp_errors qerr;

	qsmp_logger_initialize(NULL);
	prcv = NULL;

	if (kset != NULL && send_func != NULL && receive_callback != NULL)
	{
		prcv = (listener_receiver_state*)qsc_memutils_malloc(sizeof(listener_receiver_state));

		if (prcv != NULL)
		{
			prcv->pcns = (qsmp_connection_state*)qsc_memutils_malloc(sizeof(qsmp_connection_state));
			prcv->pkpa = (qsmp_keep_alive_state*)qsc_memutils_malloc(sizeof(qsmp_keep_alive_state));

			if (prcv->pcns != NULL && prcv->pkpa != NULL)
			{
				prcv->callback = receive_callback;
				qsc_memutils_clear((uint8_t*)prcv->pcns, sizeof(qsmp_connection_state));
				qsc_memutils_clear((uint8_t*)prcv->pkpa, sizeof(qsmp_keep_alive_state));

				addt = qsc_ipinfo_ipv6_address_any();
				qsc_socket_server_initialize(&prcv->pcns->target);
				qsc_socket_server_initialize(&srvs);

				serr = qsc_socket_server_listen_ipv6(&srvs, &prcv->pcns->target, &addt, QSMP_CLIENT_PORT);

				if (serr == qsc_socket_exception_success)
				{
					qerr = listener_duplex_start(kset, prcv, send_func, key_query);
				}
				else
				{
					qsmp_log_message(qsmp_messages_connection_fail);
					qerr = qsmp_error_connection_failure;
				}
			}
			else
			{
				qsmp_log_message(qsmp_messages_allocate_fail);
				qsc_memutils_alloc_free(prcv);
				qerr = qsmp_error_memory_allocation;
			}
		}
		else
		{
			qsmp_log_message(qsmp_messages_allocate_fail);
			qerr = qsmp_error_memory_allocation;
		}
	}
	else
	{
		qsmp_log_message(qsmp_messages_invalid_request);
		qerr = qsmp_error_invalid_input;
	}

	return qerr;
}

qsmp_errors qsmp_client_simplex_connect_ipv4(const qsmp_client_verification_key* pubk, 
	const qsc_ipinfo_ipv4_address* address, uint16_t port, 
	void (*send_func)(qsmp_connection_state*), 
	void (*receive_callback)(qsmp_connection_state*, const uint8_t*, size_t))
{
	assert(pubk != NULL);
	assert(send_func != NULL);
	assert(send_func != NULL);
	assert(receive_callback != NULL);

	qsmp_kex_simplex_client_state* kcs;
	client_receiver_state* prcv;
	qsc_socket_exceptions serr;
	qsmp_errors qerr;

	kcs = NULL;
	prcv = NULL;
	qsmp_logger_initialize(NULL);

	if (address != NULL && send_func != NULL && receive_callback != NULL)
	{
		kcs = (qsmp_kex_simplex_client_state*)qsc_memutils_malloc(sizeof(qsmp_kex_simplex_client_state));

		if (kcs != NULL)
		{
			prcv = (client_receiver_state*)qsc_memutils_malloc(sizeof(client_receiver_state));

			if (prcv != NULL)
			{
				qsc_memutils_clear(kcs, sizeof(qsmp_kex_simplex_client_state));
				qsc_memutils_clear(prcv, sizeof(client_receiver_state));

				prcv->pcns = (qsmp_connection_state*)qsc_memutils_malloc(sizeof(qsmp_connection_state));

				if (prcv->pcns != NULL)
				{
					prcv->callback = receive_callback;
					qsc_socket_client_initialize(&prcv->pcns->target);

					serr = qsc_socket_client_connect_ipv4(&prcv->pcns->target, address, port);

					if (serr == qsc_socket_exception_success)
					{
						/* initialize the client */
						client_simplex_state_initialize(kcs, prcv->pcns, pubk);
						/* perform the simplex key exchange */
						qerr = qsmp_kex_simplex_client_key_exchange(kcs, prcv->pcns);
						qsc_memutils_alloc_free(kcs);
						kcs = NULL;

						if (qerr == qsmp_error_none)
						{
							/* start the receive loop on a new thread */
							qsc_async_thread_create((void*)&client_receive_loop, prcv);

							/* start the send loop on the main thread */
							send_func(prcv->pcns);
							
							/* disconnect the socket */
							client_connection_dispose(prcv);
						}
						else
						{
							qsmp_log_write(qsmp_messages_kex_fail, (const char*)prcv->pcns->target.address);
							qerr = qsmp_error_exchange_failure;
						}

						if (prcv != NULL && prcv->pcns != NULL)
						{
							qsmp_connection_close(prcv->pcns, qsmp_error_none, true);
						}
					}
					else
					{
						qsmp_log_write(qsmp_messages_kex_fail, (const char*)prcv->pcns->target.address);
						qerr = qsmp_error_connection_failure;
					}
				}
				else
				{
					qsmp_log_message(qsmp_messages_allocate_fail);
					qerr = qsmp_error_memory_allocation;
				}
			}
			else
			{
				qsmp_log_message(qsmp_messages_allocate_fail);
				qerr = qsmp_error_memory_allocation;
			}
		}
		else
		{
			qsmp_log_message(qsmp_messages_allocate_fail);
			qerr = qsmp_error_memory_allocation;
		}
	}
	else
	{
		qsmp_log_message(qsmp_messages_invalid_request);
		qerr = qsmp_error_invalid_input;
	}

	if (kcs != NULL)
	{
		qsc_memutils_alloc_free(kcs);
		kcs = NULL;
	}

	if (prcv != NULL)
	{
		if (prcv->pcns != NULL)
		{
			qsc_memutils_alloc_free(prcv->pcns);
			prcv->pcns = NULL;
		}

		prcv->callback = NULL;
		qsc_memutils_alloc_free(prcv);
		prcv = NULL;
	}

	return qerr;
}

qsmp_errors qsmp_client_simplex_connect_ipv6(const qsmp_client_verification_key* pubk, 
	const qsc_ipinfo_ipv6_address* address, uint16_t port, 
	void (*send_func)(qsmp_connection_state*), 
	void (*receive_callback)(qsmp_connection_state*, const uint8_t*, size_t))
{
	assert(pubk != NULL);
	assert(send_func != NULL);
	assert(send_func != NULL);
	assert(receive_callback != NULL);

	qsmp_kex_simplex_client_state* kcs;
	client_receiver_state* prcv;
	qsc_socket_exceptions serr;
	qsmp_errors qerr;

	kcs = NULL;
	prcv = NULL;
	qsmp_logger_initialize(NULL);

	if (address != NULL && send_func != NULL && receive_callback != NULL)
	{
		kcs = (qsmp_kex_simplex_client_state*)qsc_memutils_malloc(sizeof(qsmp_kex_simplex_client_state));

		if (kcs != NULL)
		{
			prcv = (client_receiver_state*)qsc_memutils_malloc(sizeof(client_receiver_state));

			if (prcv != NULL)
			{
				qsc_memutils_clear(kcs, sizeof(qsmp_kex_simplex_client_state));
				qsc_memutils_clear(prcv, sizeof(client_receiver_state));

				prcv->pcns = (qsmp_connection_state*)qsc_memutils_malloc(sizeof(qsmp_connection_state));

				if (prcv->pcns != NULL)
				{
					prcv->callback = receive_callback;
					qsc_socket_client_initialize(&prcv->pcns->target);

					serr = qsc_socket_client_connect_ipv6(&prcv->pcns->target, address, port);

					if (serr == qsc_socket_exception_success)
					{
						/* initialize the client */
						client_simplex_state_initialize(kcs, prcv->pcns, pubk);
						qerr = qsmp_kex_simplex_client_key_exchange(kcs, prcv->pcns);
						qsc_memutils_alloc_free(kcs);
						kcs = NULL;

						if (qerr == qsmp_error_none)
						{
							/* start the receive loop on a new thread */
							qsc_async_thread_create((void*)&client_receive_loop, prcv);

							/* start the send loop on the main thread */
							send_func(prcv->pcns);

							/* disconnect the socket */
							client_connection_dispose(prcv);
						}
						else
						{
							qsmp_log_write(qsmp_messages_kex_fail, (const char*)prcv->pcns->target.address);
							qerr = qsmp_error_exchange_failure;
						}

						if (prcv && prcv->pcns)
						{
							qsmp_connection_close(prcv->pcns, qsmp_error_none, true);
						}
					}
					else
					{
						qsmp_log_write(qsmp_messages_kex_fail, (const char*)prcv->pcns->target.address);
						qerr = qsmp_error_connection_failure;
					}
				}
				else
				{
					qsmp_log_message(qsmp_messages_allocate_fail);
					qerr = qsmp_error_memory_allocation;
				}
			}
			else
			{
				qsmp_log_message(qsmp_messages_allocate_fail);
				qerr = qsmp_error_memory_allocation;
			}
		}
		else
		{
			qsmp_log_message(qsmp_messages_allocate_fail);
			qerr = qsmp_error_memory_allocation;
		}
	}
	else
	{
		qsmp_log_message(qsmp_messages_invalid_request);
		qerr = qsmp_error_invalid_input;
	}

	if (kcs != NULL)
	{
		qsc_memutils_alloc_free(kcs);
		kcs = NULL;
	}

	if (prcv != NULL)
	{
		if (prcv->pcns != NULL)
		{
			qsc_memutils_alloc_free(prcv->pcns);
			prcv->pcns = NULL;
		}

		prcv->callback = NULL;
		qsc_memutils_alloc_free(prcv);
		prcv = NULL;
	}

	return qerr;
}

qsmp_errors qsmp_client_simplex_listen_ipv4(const qsmp_server_signature_key* kset, 
	void (*send_func)(qsmp_connection_state*), 
	void (*receive_callback)(qsmp_connection_state*, const uint8_t*, size_t))
{
	assert(kset != NULL);
	assert(send_func != NULL);
	assert(receive_callback != NULL);

	qsc_ipinfo_ipv4_address addt = { 0 };
	listener_receiver_state* prcv;
	qsc_socket srvs;
	qsc_socket_exceptions serr;
	qsmp_errors qerr;
	qsmp_logger_initialize(NULL);

	prcv = NULL;

	if (kset != NULL && send_func != NULL && receive_callback != NULL)
	{
		prcv = (listener_receiver_state*)qsc_memutils_malloc(sizeof(listener_receiver_state*));

		if (prcv != NULL)
		{
			prcv->pcns = (qsmp_connection_state*)qsc_memutils_malloc(sizeof(qsmp_connection_state));
			prcv->pkpa = (qsmp_keep_alive_state*)qsc_memutils_malloc(sizeof(qsmp_keep_alive_state));

			if (prcv->pcns != NULL && prcv->pkpa != NULL)
			{
				prcv->callback = receive_callback;
				qsc_memutils_clear((uint8_t*)prcv->pcns, sizeof(qsmp_connection_state));
				qsc_memutils_clear((uint8_t*)prcv->pkpa, sizeof(qsmp_keep_alive_state));

				addt = qsc_ipinfo_ipv4_address_any();
				qsc_socket_server_initialize(&prcv->pcns->target);
				qsc_socket_server_initialize(&srvs);

				serr = qsc_socket_server_listen_ipv4(&srvs, &prcv->pcns->target, &addt, QSMP_SERVER_PORT);

				if (serr == qsc_socket_exception_success)
				{
					qerr = listener_simplex_start(kset, prcv, send_func);
				}
				else
				{
					qsmp_log_message(qsmp_messages_connection_fail);
					qerr = qsmp_error_connection_failure;
				}
			}
			else
			{
				qsmp_log_message(qsmp_messages_allocate_fail);
				qsc_memutils_alloc_free(prcv);
				qerr = qsmp_error_memory_allocation;
			}
		}
		else
		{
			qsmp_log_message(qsmp_messages_allocate_fail);
			qerr = qsmp_error_memory_allocation;
		}
	}
	else
	{
		qsmp_log_message(qsmp_messages_invalid_request);
		qerr = qsmp_error_invalid_input;
	}

	if (prcv != NULL)
	{
		if (prcv->pcns != NULL)
		{
			qsc_memutils_alloc_free(prcv->pcns);
			prcv->pcns = NULL;
		}

		prcv->callback = NULL;
		qsc_memutils_alloc_free(prcv);
		prcv = NULL;
	}

	return qerr;
}

qsmp_errors qsmp_client_simplex_listen_ipv6(const qsmp_server_signature_key* kset, 
	void (*send_func)(qsmp_connection_state*), 
	void (*receive_callback)(qsmp_connection_state*, const uint8_t*, size_t))
{
	assert(kset != NULL);
	assert(send_func != NULL);
	assert(receive_callback != NULL);

	qsc_ipinfo_ipv6_address addt = { 0 };
	listener_receiver_state* prcv;
	qsc_socket srvs;
	qsc_socket_exceptions serr;
	qsmp_errors qerr;

	prcv = NULL;

	if (kset != NULL && send_func != NULL && receive_callback != NULL)
	{
		prcv = (listener_receiver_state*)qsc_memutils_malloc(sizeof(listener_receiver_state*));

		if (prcv != NULL)
		{
			prcv->pcns = (qsmp_connection_state*)qsc_memutils_malloc(sizeof(qsmp_connection_state));
			prcv->pkpa = (qsmp_keep_alive_state*)qsc_memutils_malloc(sizeof(qsmp_keep_alive_state));

			if (prcv->pcns != NULL && prcv->pkpa != NULL)
			{
				prcv->callback = receive_callback;
				qsc_memutils_clear((uint8_t*)prcv->pcns, sizeof(qsmp_connection_state));
				qsc_memutils_clear((uint8_t*)prcv->pkpa, sizeof(qsmp_keep_alive_state));

				addt = qsc_ipinfo_ipv6_address_any();
				qsc_socket_server_initialize(&prcv->pcns->target);
				qsc_socket_server_initialize(&srvs);

				serr = qsc_socket_server_listen_ipv6(&srvs, &prcv->pcns->target, &addt, QSMP_SERVER_PORT);

				if (serr == qsc_socket_exception_success)
				{
					qerr = listener_simplex_start(kset, prcv, send_func);
				}
				else
				{
					qsmp_log_message(qsmp_messages_connection_fail);
					qerr = qsmp_error_connection_failure;
				}
			}
			else
			{
				qsmp_log_message(qsmp_messages_allocate_fail);
				qsc_memutils_alloc_free(prcv);
				qerr = qsmp_error_memory_allocation;
			}
		}
		else
		{
			qsmp_log_message(qsmp_messages_allocate_fail);
			qerr = qsmp_error_memory_allocation;
		}
	}
	else
	{
		qsmp_log_message(qsmp_messages_invalid_request);
		qerr = qsmp_error_invalid_input;
	}

	if (prcv != NULL)
	{
		if (prcv->pcns != NULL)
		{
			qsc_memutils_alloc_free(prcv->pcns);
			prcv->pcns = NULL;
		}

		prcv->callback = NULL;
		qsc_memutils_alloc_free(prcv);
		prcv = NULL;
	}

	return qerr;
}

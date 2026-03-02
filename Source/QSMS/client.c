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
	qsmp_keepalive_state* pkpa;
	void (*callback)(qsmp_connection_state*, const uint8_t*, size_t);
} listener_receiver_state;

typedef struct listener_receive_loop_args
{
	listener_receiver_state* prcv;
} listener_receive_loop_args;
/** \endcond */

#if defined(QSMP_ASYMMETRIC_RATCHET)
/** \cond */
#define QSMP_ASYMMETRIC_RATCHET_REQUEST_MESSAGE_SIZE (QSMP_ASYMMETRIC_PUBLIC_KEY_SIZE + QSMP_ASYMMETRIC_SIGNATURE_SIZE + QSMP_SIMPLEX_HASH_SIZE + QSMP_SIMPLEX_MACTAG_SIZE)
#define QSMP_ASYMMETRIC_RATCHET_REQUEST_PACKET_SIZE (QSMP_HEADER_SIZE + QSMP_ASYMMETRIC_PUBLIC_KEY_SIZE + QSMP_ASYMMETRIC_SIGNATURE_SIZE + QSMP_SIMPLEX_HASH_SIZE + QSMP_SIMPLEX_MACTAG_SIZE)
#define QSMP_ASYMMETRIC_RATCHET_RESPONSE_MESSAGE_SIZE (QSMP_ASYMMETRIC_CIPHER_TEXT_SIZE + QSMP_ASYMMETRIC_SIGNATURE_SIZE + QSMP_SIMPLEX_HASH_SIZE + QSMP_SIMPLEX_MACTAG_SIZE)
#define QSMP_ASYMMETRIC_RATCHET_RESPONSE_PACKET_SIZE (QSMP_HEADER_SIZE + QSMP_ASYMMETRIC_CIPHER_TEXT_SIZE + QSMP_ASYMMETRIC_SIGNATURE_SIZE + QSMP_SIMPLEX_HASH_SIZE + QSMP_SIMPLEX_MACTAG_SIZE)

static qsmp_asymmetric_cipher_keypair* m_ckeyset;
static qsmp_asymmetric_signature_keypair* m_skeyset;
/** \endcond */
#endif

/* Private Functions */

/** \cond */
static void client_simplex_state_initialize(qsmp_kex_simplex_client_state* kcs, qsmp_connection_state* cns, const qsmp_client_verification_key* pubk)
{
	qsc_memutils_copy(kcs->keyid, pubk->keyid, QSMP_KEYID_SIZE);
	qsc_memutils_copy(kcs->verkey, pubk->verkey, QSMP_ASYMMETRIC_VERIFY_KEY_SIZE);
	qsc_memutils_clear(cns->rtcs, QSMP_SIMPLEX_SYMMETRIC_KEY_SIZE);
	kcs->expiration = pubk->expiration;
	cns->target.instance = qsc_acp_uint32();
	qsc_rcs_dispose(&cns->rxcpr);
	qsc_rcs_dispose(&cns->txcpr);
	cns->exflag = qsmp_flag_none;
	cns->cid = 0U;
	cns->rxseq = 0U;
	cns->txseq = 0U;
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
	qsc_memutils_clear(&rcv->pcns->rtcs, QSMP_SIMPLEX_SYMMETRIC_KEY_SIZE);
	rcv->pcns->exflag = qsmp_flag_none;
	rcv->pcns->cid = 0U;
	rcv->pcns->rxseq = 0U;
	rcv->pcns->txseq = 0U;
}

static void symmetric_ratchet(qsmp_connection_state* cns, const uint8_t* secret, size_t seclen)
{
	qsc_keccak_state kstate = { 0 };
	qsc_rcs_keyparams kp = { 0 };
	uint8_t prnd[QSC_KECCAK_256_RATE] = { 0U };

	/* re-key the ciphers using the token, ratchet key, and configuration name */
	qsc_cshake_initialize(&kstate, qsc_keccak_rate_256, secret, seclen, (const uint8_t*)QSMP_CONFIG_STRING, QSMP_CONFIG_SIZE, cns->rtcs, QSMP_SIMPLEX_SYMMETRIC_KEY_SIZE);
	/* re-key the ciphers using the symmetric ratchet key */
	qsc_cshake_squeezeblocks(&kstate, qsc_keccak_rate_256, prnd, 1U);

	if (cns->receiver == true)
	{
		/* initialize for decryption, and raise client channel rx */
		kp.key = prnd;
		kp.keylen = QSMP_SIMPLEX_SYMMETRIC_KEY_SIZE;
		kp.nonce = ((uint8_t*)prnd + QSMP_SIMPLEX_SYMMETRIC_KEY_SIZE);
		kp.info = NULL;
		kp.infolen = 0U;
		qsc_rcs_initialize(&cns->rxcpr, &kp, false);

		/* initialize for encryption, and raise client channel tx */
		kp.key = prnd + QSMP_SIMPLEX_SYMMETRIC_KEY_SIZE + QSMP_NONCE_SIZE;
		kp.keylen = QSMP_SIMPLEX_SYMMETRIC_KEY_SIZE;
		kp.nonce = ((uint8_t*)prnd + QSMP_SIMPLEX_SYMMETRIC_KEY_SIZE + QSMP_NONCE_SIZE + QSMP_SIMPLEX_SYMMETRIC_KEY_SIZE);
		kp.info = NULL;
		kp.infolen = 0U;
		qsc_rcs_initialize(&cns->txcpr, &kp, true);
	}
	else
	{
		/* initialize for encryption, and raise tx */
		kp.key = prnd;
		kp.keylen = QSMP_SIMPLEX_SYMMETRIC_KEY_SIZE;
		kp.nonce = ((uint8_t*)prnd + QSMP_SIMPLEX_SYMMETRIC_KEY_SIZE);
		kp.info = NULL;
		kp.infolen = 0U;
		qsc_rcs_initialize(&cns->txcpr, &kp, true);

		/* initialize decryption, and raise rx */
		kp.key = prnd + QSMP_SIMPLEX_SYMMETRIC_KEY_SIZE + QSMP_NONCE_SIZE;
		kp.keylen = QSMP_SIMPLEX_SYMMETRIC_KEY_SIZE;
		kp.nonce = ((uint8_t*)prnd + QSMP_SIMPLEX_SYMMETRIC_KEY_SIZE + QSMP_NONCE_SIZE + QSMP_SIMPLEX_SYMMETRIC_KEY_SIZE);
		kp.info = NULL;
		kp.infolen = 0U;
		qsc_rcs_initialize(&cns->rxcpr, &kp, false);
	}

	/* permute key state and store next key */
	qsc_keccak_permute(&kstate, QSC_KECCAK_PERMUTATION_ROUNDS);
	qsc_memutils_copy(cns->rtcs, (uint8_t*)kstate.state, QSMP_SIMPLEX_SYMMETRIC_KEY_SIZE);
	/* erase the key array */
	qsc_memutils_secure_erase(prnd, sizeof(prnd));
	qsc_memutils_secure_erase((uint8_t*)&kp, sizeof(qsc_rcs_keyparams));
	qsc_memutils_secure_erase(&kstate, sizeof(qsc_keccak_state));
}

static bool symmetric_ratchet_response(qsmp_connection_state* cns, const qsmp_network_packet* packetin)
{
	uint8_t rkey[QSMP_RTOK_SIZE] = { 0U };
	uint8_t shdr[QSMP_HEADER_SIZE] = { 0U };
	size_t mlen;
	bool res;

	res = false;

	if (packetin->sequence == cns->rxseq + 1U)
	{
		/* serialize the header and add it to the ciphers associated data */
		qsmp_packet_header_serialize(packetin, shdr);
		qsc_rcs_set_associated(&cns->rxcpr, shdr, QSMP_HEADER_SIZE);
		mlen = packetin->msglen - (size_t)QSMP_SIMPLEX_MACTAG_SIZE;

		/* authenticate then decrypt the data */
		if (qsc_rcs_transform(&cns->rxcpr, rkey, packetin->pmessage, mlen) == true)
		{
			cns->rxseq += 1U;
			/* inject into key state */
			symmetric_ratchet(cns, rkey, sizeof(rkey));
			res = true;
		}
	}

	qsc_memutils_secure_erase(rkey, sizeof(rkey));
	qsc_memutils_clear(shdr, sizeof(shdr));

	return res;
}

static void client_connection_dispose(client_receiver_state* prcv)
{
	/* dispose of resources */
	qsmp_connection_state_dispose(prcv->pcns);
}

static void client_receive_loop(void* prcv)
{
	QSMP_ASSERT(prcv != NULL);

	qsmp_network_packet pkt = { 0 };
	char cadd[QSC_SOCKET_ADDRESS_MAX_SIZE] = { 0 };
	client_receiver_state* pprcv;
	uint8_t* rbuf;
	size_t mlen;
	size_t plen;
	size_t slen;
	qsmp_errors qerr;

	pprcv = (client_receiver_state*)prcv;
	qsc_memutils_copy(cadd, (const char*)pprcv->pcns->target.address, sizeof(cadd));

	rbuf = (uint8_t*)qsc_memutils_malloc(QSMP_HEADER_SIZE);

	if (rbuf != NULL)
	{
		while (pprcv->pcns->target.connection_status == qsc_socket_state_connected)
		{
			mlen = 0U;
			slen = 0U;
			qsc_memutils_clear(rbuf, QSMP_HEADER_SIZE);

			plen = qsc_socket_peek(&pprcv->pcns->target, rbuf, QSMP_HEADER_SIZE);

			if (plen == QSMP_HEADER_SIZE)
			{
				qsmp_packet_header_deserialize(rbuf, &pkt);

				if (pkt.msglen > 0U && pkt.msglen <= QSMP_MESSAGE_MAX)
				{
					uint8_t* rtmp;

					plen = pkt.msglen + QSMP_HEADER_SIZE;
					rtmp = (uint8_t*)qsc_memutils_realloc(rbuf, plen);

					if (rtmp != NULL)
					{
						rbuf = rtmp;
						qsc_memutils_clear(rbuf, plen);
						mlen = qsc_socket_receive(&pprcv->pcns->target, rbuf, plen, qsc_socket_receive_flag_wait_all);

						if (mlen > 0U)
						{
							pkt.pmessage = rbuf + QSMP_HEADER_SIZE;

							if (pkt.flag == qsmp_flag_encrypted_message)
							{
								uint8_t* rmsg;

								slen = pkt.msglen;

								if (pkt.msglen > QSMP_SIMPLEX_MACTAG_SIZE)
								{
									slen -= QSMP_SIMPLEX_MACTAG_SIZE;
									rmsg = (uint8_t*)qsc_memutils_malloc(slen);

									if (rmsg != NULL)
									{
										qsc_memutils_clear(rmsg, slen);
										qerr = qsmp_packet_decrypt(pprcv->pcns, rmsg, &mlen, &pkt);

										if (qerr == qsmp_error_none)
										{
											pprcv->callback(pprcv->pcns, rmsg, mlen);
										}
										else
										{
											/* close the connection on authentication failure */
											qsmp_log_write(qsmp_messages_decryption_fail, cadd);
											break;
										}

										qsc_memutils_secure_erase(rmsg, slen);
										qsc_memutils_alloc_free(rmsg);
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
									/* close the connection on receive failure */
									qsmp_log_write(qsmp_messages_receive_fail, cadd);
									break;
								}
							}
							else if (pkt.flag == qsmp_flag_error_condition)
							{
								/* anti-dos: break on error message is conditional
								   on succesful authentication/decryption */
								if (qsmp_decrypt_error_message(&qerr, pprcv->pcns, rbuf) == true)
								{
									qsmp_log_system_error(qerr);
									break;
								}
							}
							else if (pkt.flag == qsmp_flag_symmetric_ratchet_request)
							{
								if (symmetric_ratchet_response(pprcv->pcns, &pkt) == false)
								{
									/* symmetric ratchet authentication failed */
									qsmp_log_write(qsmp_messages_symmetric_ratchet, (const char*)pprcv->pcns->target.address);
									break;
								}
							}
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
			
			qsc_memutils_secure_erase(rbuf, plen);
		}

		qsc_memutils_alloc_free(rbuf);
	}
	else
	{
		qsmp_log_write(qsmp_messages_allocate_fail, cadd);
	}
}

static void listener_receive_loop(listener_receiver_state* prcv)
{
	QSMP_ASSERT(prcv != NULL);

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
			mlen = 0U;
			slen = 0U;
			qsc_memutils_clear(rbuf, QSMP_HEADER_SIZE);

			plen = qsc_socket_peek(&prcv->pcns->target, rbuf, QSMP_HEADER_SIZE);

			if (plen == QSMP_HEADER_SIZE)
			{
				qsmp_packet_header_deserialize(rbuf, &pkt);

				if (pkt.msglen > 0U && pkt.msglen <= QSMP_MESSAGE_MAX)
				{
					uint8_t* rtmp;

					plen = pkt.msglen + QSMP_HEADER_SIZE;
					rtmp = (uint8_t*)qsc_memutils_realloc(rbuf, plen);

					if (rtmp != NULL)
					{
						rbuf = rtmp;
						qsc_memutils_clear(rbuf, plen);
						mlen = qsc_socket_receive(&prcv->pcns->target, rbuf, plen, qsc_socket_receive_flag_wait_all);

						if (mlen > 0U)
						{
							pkt.pmessage = rbuf + QSMP_HEADER_SIZE;

							if (pkt.flag == qsmp_flag_encrypted_message)
							{
								uint8_t* rmsg;

								slen = pkt.msglen;
								slen -= QSMP_SIMPLEX_MACTAG_SIZE;
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

									qsc_memutils_clear(rmsg, slen);
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
							else if (pkt.flag == qsmp_flag_symmetric_ratchet_request)
							{
								if (symmetric_ratchet_response(prcv->pcns, &pkt) == false)
								{
									qsmp_log_write(qsmp_messages_keepalive_timeout, (const char*)prcv->pcns->target.address);
									break;
								}
							}
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

						qsc_memutils_secure_erase(rbuf, plen);
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

static void listener_receive_loop_wrapper(void* state)
{
	listener_receive_loop_args* args = (listener_receive_loop_args*)state;

	if (args != NULL)
	{
		listener_receive_loop(args->prcv);
	}
}

static qsmp_errors listener_simplex_start(const qsmp_server_signature_key* kset, 
	listener_receiver_state* prcv, 
	void (*send_func)(qsmp_connection_state*))
{
	QSMP_ASSERT(kset != NULL);
	QSMP_ASSERT(prcv != NULL);
	QSMP_ASSERT(send_func != NULL);

	listener_receive_loop_args largs = { 0 };
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

		qsc_memutils_clear((uint8_t*)pkss, sizeof(qsmp_kex_simplex_server_state));
		qsc_memutils_alloc_free(pkss);
		pkss = NULL;

		if (qerr == qsmp_error_none)
		{
			/* initialize the receiver loop on a new thread */
			largs.prcv = prcv;
			qsc_async_thread_create(&listener_receive_loop_wrapper, &largs);

			/* start the send loop on the *main* thread */
			send_func(prcv->pcns);
		}
	}

	return qerr;
}
/** \endcond */

/* Public Functions */

bool qsmp_simplex_send_symmetric_ratchet_request(qsmp_connection_state* cns)
{
	QSMP_ASSERT(cns != NULL);

	size_t plen;
	size_t slen;
	bool res;

	res = false;

	if (cns != NULL)
	{
		qsmp_network_packet pkt = { 0 };
		uint8_t pmsg[QSMP_RTOK_SIZE + QSMP_SIMPLEX_MACTAG_SIZE] = { 0U };
		uint8_t rkey[QSMP_RTOK_SIZE] = { 0U };

		/* generate the token key */
		if (qsc_acp_generate(rkey, sizeof(rkey)) == true)
		{
			uint8_t shdr[QSMP_HEADER_SIZE] = { 0U };
			uint8_t spct[QSMP_HEADER_SIZE + QSMP_RTOK_SIZE + QSMP_SIMPLEX_MACTAG_SIZE] = { 0U };

			cns->txseq += 1U;
			pkt.pmessage = pmsg;
			pkt.flag = qsmp_flag_symmetric_ratchet_request;
			pkt.msglen = QSMP_RTOK_SIZE + QSMP_SIMPLEX_MACTAG_SIZE;
			pkt.sequence = cns->txseq;
			qsmp_packet_set_utc_time(&pkt);

			/* serialize the header and add it to the ciphers associated data */
			qsmp_packet_header_serialize(&pkt, shdr);
			qsc_rcs_set_associated(&cns->txcpr, shdr, QSMP_HEADER_SIZE);
			/* encrypt the message */
			(void)qsc_rcs_transform(&cns->txcpr, pkt.pmessage, rkey, sizeof(rkey));

			/* convert the packet to bytes */
			plen = qsmp_packet_to_stream(&pkt, spct);

			/* send the ratchet request */
			slen = qsc_socket_send(&cns->target, spct, plen, qsc_socket_send_flag_none);

			if (slen == plen)
			{
				symmetric_ratchet(cns, rkey, sizeof(rkey));
				res = true;
			}

			qsc_memutils_clear(shdr, sizeof(shdr));
			qsc_memutils_clear(spct, sizeof(spct));
		}

		qsc_memutils_secure_erase(pmsg, sizeof(pmsg));
		qsc_memutils_secure_erase(rkey, sizeof(rkey));
	}

	return res;
}

qsmp_errors qsmp_client_simplex_connect_ipv4(const qsmp_client_verification_key* pubk, 
	const qsc_ipinfo_ipv4_address* address, uint16_t port, 
	void (*send_func)(qsmp_connection_state*), 
	void (*receive_callback)(qsmp_connection_state*, const uint8_t*, size_t))
{
	QSMP_ASSERT(pubk != NULL);
	QSMP_ASSERT(send_func != NULL);
	QSMP_ASSERT(send_func != NULL);
	QSMP_ASSERT(receive_callback != NULL);

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
			qsc_memutils_clear(kcs, sizeof(qsmp_kex_simplex_client_state));
			prcv = (client_receiver_state*)qsc_memutils_malloc(sizeof(client_receiver_state));

			if (prcv != NULL)
			{
				qsc_memutils_clear(prcv, sizeof(client_receiver_state));

				prcv->pcns = (qsmp_connection_state*)qsc_memutils_malloc(sizeof(qsmp_connection_state));

				if (prcv->pcns != NULL)
				{
					qsc_memutils_clear(prcv->pcns, sizeof(qsmp_connection_state));
					prcv->callback = receive_callback;
					qsc_socket_client_initialize(&prcv->pcns->target);

					serr = qsc_socket_client_connect_ipv4(&prcv->pcns->target, address, port);

					if (serr == qsc_socket_exception_success)
					{
						/* initialize the client */
						client_simplex_state_initialize(kcs, prcv->pcns, pubk);
						/* perform the simplex key exchange */
						qerr = qsmp_kex_simplex_client_key_exchange(kcs, prcv->pcns);
						/* clear the kex state */
						qsc_memutils_clear((uint8_t*)kcs, sizeof(qsmp_kex_simplex_client_state));

						if (qerr == qsmp_error_none)
						{
							/* start the receive loop on a new thread */
							qsc_async_thread_create(&client_receive_loop, prcv);

							/* start the send loop on the main thread */
							send_func(prcv->pcns);
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

												
					/* dispose of the state */
					client_connection_dispose(prcv);
					qsc_memutils_alloc_free(prcv->pcns);
					prcv->pcns = NULL;
				}
				else
				{
					qsmp_log_message(qsmp_messages_allocate_fail);
					qerr = qsmp_error_memory_allocation;
				}

				qsc_memutils_alloc_free(prcv);
				prcv = NULL;
			}
			else
			{
				qsmp_log_message(qsmp_messages_allocate_fail);
				qerr = qsmp_error_memory_allocation;
			}

			qsc_memutils_alloc_free(kcs);
			kcs = NULL;
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

qsmp_errors qsmp_client_simplex_connect_ipv6(const qsmp_client_verification_key* pubk, 
	const qsc_ipinfo_ipv6_address* address, uint16_t port, 
	void (*send_func)(qsmp_connection_state*), 
	void (*receive_callback)(qsmp_connection_state*, const uint8_t*, size_t))
{
	QSMP_ASSERT(pubk != NULL);
	QSMP_ASSERT(send_func != NULL);
	QSMP_ASSERT(send_func != NULL);
	QSMP_ASSERT(receive_callback != NULL);

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
			qsc_memutils_clear(kcs, sizeof(qsmp_kex_simplex_client_state));
			prcv = (client_receiver_state*)qsc_memutils_malloc(sizeof(client_receiver_state));

			if (prcv != NULL)
			{
				qsc_memutils_clear(prcv, sizeof(client_receiver_state));

				prcv->pcns = (qsmp_connection_state*)qsc_memutils_malloc(sizeof(qsmp_connection_state));

				if (prcv->pcns != NULL)
				{
					qsc_memutils_clear(prcv->pcns, sizeof(qsmp_connection_state));
					prcv->callback = receive_callback;
					qsc_socket_client_initialize(&prcv->pcns->target);

					serr = qsc_socket_client_connect_ipv6(&prcv->pcns->target, address, port);

					if (serr == qsc_socket_exception_success)
					{
						/* initialize the client */
						client_simplex_state_initialize(kcs, prcv->pcns, pubk);
						/* perform the simplex key exchange */
						qerr = qsmp_kex_simplex_client_key_exchange(kcs, prcv->pcns);
						/* clear the kex state */
						qsc_memutils_clear((uint8_t*)kcs, sizeof(qsmp_kex_simplex_client_state));

						if (qerr == qsmp_error_none)
						{
							/* start the receive loop on a new thread */
							qsc_async_thread_create(&client_receive_loop, prcv);

							/* start the send loop on the main thread */
							send_func(prcv->pcns);
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

												
					/* dispose of the state */
					client_connection_dispose(prcv);
					qsc_memutils_alloc_free(prcv->pcns);
					prcv->pcns = NULL;
				}
				else
				{
					qsmp_log_message(qsmp_messages_allocate_fail);
					qerr = qsmp_error_memory_allocation;
				}

				qsc_memutils_alloc_free(prcv);
				prcv = NULL;
			}
			else
			{
				qsmp_log_message(qsmp_messages_allocate_fail);
				qerr = qsmp_error_memory_allocation;
			}

			qsc_memutils_alloc_free(kcs);
			kcs = NULL;
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

qsmp_errors qsmp_client_simplex_listen_ipv4(const qsmp_server_signature_key* kset, 
	void (*send_func)(qsmp_connection_state*), 
	void (*receive_callback)(qsmp_connection_state*, const uint8_t*, size_t))
{
	QSMP_ASSERT(kset != NULL);
	QSMP_ASSERT(send_func != NULL);
	QSMP_ASSERT(receive_callback != NULL);

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
			prcv->pkpa = (qsmp_keepalive_state*)qsc_memutils_malloc(sizeof(qsmp_keepalive_state));

			if (prcv->pcns != NULL && prcv->pkpa != NULL)
			{
				prcv->callback = receive_callback;
				qsc_memutils_clear((uint8_t*)prcv->pcns, sizeof(qsmp_connection_state));
				qsc_memutils_clear((uint8_t*)prcv->pkpa, sizeof(qsmp_keepalive_state));

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
	QSMP_ASSERT(kset != NULL);
	QSMP_ASSERT(send_func != NULL);
	QSMP_ASSERT(receive_callback != NULL);

	qsc_ipinfo_ipv6_address addt = { 0 };
	listener_receiver_state* prcv;
	qsc_socket srvs;
	qsc_socket_exceptions serr;
	qsmp_errors qerr;

	prcv = NULL;

	if (kset != NULL && send_func != NULL && receive_callback != NULL)
	{
		prcv = (listener_receiver_state*)qsc_memutils_malloc(sizeof(listener_receiver_state));

		if (prcv != NULL)
		{
			prcv->pcns = (qsmp_connection_state*)qsc_memutils_malloc(sizeof(qsmp_connection_state));
			prcv->pkpa = (qsmp_keepalive_state*)qsc_memutils_malloc(sizeof(qsmp_keepalive_state));

			if (prcv->pcns != NULL && prcv->pkpa != NULL)
			{
				prcv->callback = receive_callback;
				qsc_memutils_clear((uint8_t*)prcv->pcns, sizeof(qsmp_connection_state));
				qsc_memutils_clear((uint8_t*)prcv->pkpa, sizeof(qsmp_keepalive_state));

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

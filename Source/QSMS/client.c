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
	qsms_connection_state* pcns;
	void (*callback)(qsms_connection_state*, const uint8_t*, size_t);
} client_receiver_state;

typedef struct listener_receiver_state
{
	qsms_connection_state* pcns;
	void (*callback)(qsms_connection_state*, const uint8_t*, size_t);
} listener_receiver_state;

typedef struct listener_receive_loop_args
{
	listener_receiver_state* prcv;
} listener_receive_loop_args;
/** \endcond */

#if defined(QSMS_ASYMMETRIC_RATCHET)
/** \cond */
#define QSMS_ASYMMETRIC_RATCHET_REQUEST_MESSAGE_SIZE (QSMS_ASYMMETRIC_PUBLIC_KEY_SIZE + QSMS_ASYMMETRIC_SIGNATURE_SIZE + QSMS_SIMPLEX_HASH_SIZE + QSMS_SIMPLEX_MACTAG_SIZE)
#define QSMS_ASYMMETRIC_RATCHET_REQUEST_PACKET_SIZE (QSMS_HEADER_SIZE + QSMS_ASYMMETRIC_PUBLIC_KEY_SIZE + QSMS_ASYMMETRIC_SIGNATURE_SIZE + QSMS_SIMPLEX_HASH_SIZE + QSMS_SIMPLEX_MACTAG_SIZE)
#define QSMS_ASYMMETRIC_RATCHET_RESPONSE_MESSAGE_SIZE (QSMS_ASYMMETRIC_CIPHER_TEXT_SIZE + QSMS_ASYMMETRIC_SIGNATURE_SIZE + QSMS_SIMPLEX_HASH_SIZE + QSMS_SIMPLEX_MACTAG_SIZE)
#define QSMS_ASYMMETRIC_RATCHET_RESPONSE_PACKET_SIZE (QSMS_HEADER_SIZE + QSMS_ASYMMETRIC_CIPHER_TEXT_SIZE + QSMS_ASYMMETRIC_SIGNATURE_SIZE + QSMS_SIMPLEX_HASH_SIZE + QSMS_SIMPLEX_MACTAG_SIZE)

/** \endcond */
#endif

/* Private Functions */

/** \cond */
static void client_simplex_state_initialize(qsms_kex_simplex_client_state* kcs, qsms_connection_state* cns, const qsms_client_verification_key* pubk)
{
	qsc_memutils_copy(kcs->keyid, pubk->keyid, QSMS_KEYID_SIZE);
	qsc_memutils_copy(kcs->verkey, pubk->verkey, QSMS_ASYMMETRIC_VERIFY_KEY_SIZE);
	qsc_memutils_clear(cns->rtcs, QSMS_SIMPLEX_SYMMETRIC_KEY_SIZE);
	kcs->expiration = pubk->expiration;
	cns->target.instance = qsc_acp_uint32();
	qsc_rcs_dispose(&cns->rxcpr);
	qsc_rcs_dispose(&cns->txcpr);
	cns->exflag = qsms_flag_none;
	cns->cid = 0U;
	cns->rxseq = 0U;
	cns->txseq = 0U;
}

static void listener_simplex_state_initialize(qsms_kex_simplex_server_state* kss, listener_receiver_state* rcv, const qsms_server_signature_key* kset)
{
	qsc_memutils_copy(kss->keyid, kset->keyid, QSMS_KEYID_SIZE);
	qsc_memutils_copy(kss->sigkey, kset->sigkey, QSMS_ASYMMETRIC_SIGNING_KEY_SIZE);
	qsc_memutils_copy(kss->verkey, kset->verkey, QSMS_ASYMMETRIC_VERIFY_KEY_SIZE);
	kss->expiration = kset->expiration;
	qsc_memutils_clear((uint8_t*)&rcv->pcns->rxcpr, sizeof(qsc_rcs_state));
	qsc_memutils_clear((uint8_t*)&rcv->pcns->txcpr, sizeof(qsc_rcs_state));
	qsc_memutils_clear(&rcv->pcns->rtcs, QSMS_SIMPLEX_SYMMETRIC_KEY_SIZE);
	rcv->pcns->exflag = qsms_flag_none;
	rcv->pcns->cid = 0U;
	rcv->pcns->rxseq = 0U;
	rcv->pcns->txseq = 0U;
}

static void symmetric_ratchet(qsms_connection_state* cns, const uint8_t* secret, size_t seclen)
{
	qsc_keccak_state kstate = { 0 };
	qsc_rcs_keyparams kp = { 0 };
	uint8_t prnd[QSC_KECCAK_256_RATE] = { 0U };

	/* re-key the ciphers using the token, ratchet key, and configuration name */
	qsc_cshake_initialize(&kstate, qsc_keccak_rate_256, secret, seclen, (const uint8_t*)QSMS_CONFIG_STRING, QSMS_CONFIG_SIZE, cns->rtcs, QSMS_SIMPLEX_SYMMETRIC_KEY_SIZE);
	/* re-key the ciphers using the symmetric ratchet key */
	qsc_cshake_squeezeblocks(&kstate, qsc_keccak_rate_256, prnd, 1U);

	if (cns->receiver == true)
	{
		/* initialize for decryption, and raise client channel rx */
		kp.key = prnd;
		kp.keylen = QSMS_SIMPLEX_SYMMETRIC_KEY_SIZE;
		kp.nonce = ((uint8_t*)prnd + QSMS_SIMPLEX_SYMMETRIC_KEY_SIZE);
		kp.info = NULL;
		kp.infolen = 0U;
		qsc_rcs_initialize(&cns->rxcpr, &kp, false);

		/* initialize for encryption, and raise client channel tx */
		kp.key = prnd + QSMS_SIMPLEX_SYMMETRIC_KEY_SIZE + QSMS_NONCE_SIZE;
		kp.keylen = QSMS_SIMPLEX_SYMMETRIC_KEY_SIZE;
		kp.nonce = ((uint8_t*)prnd + QSMS_SIMPLEX_SYMMETRIC_KEY_SIZE + QSMS_NONCE_SIZE + QSMS_SIMPLEX_SYMMETRIC_KEY_SIZE);
		kp.info = NULL;
		kp.infolen = 0U;
		qsc_rcs_initialize(&cns->txcpr, &kp, true);
	}
	else
	{
		/* initialize for encryption, and raise tx */
		kp.key = prnd;
		kp.keylen = QSMS_SIMPLEX_SYMMETRIC_KEY_SIZE;
		kp.nonce = ((uint8_t*)prnd + QSMS_SIMPLEX_SYMMETRIC_KEY_SIZE);
		kp.info = NULL;
		kp.infolen = 0U;
		qsc_rcs_initialize(&cns->txcpr, &kp, true);

		/* initialize decryption, and raise rx */
		kp.key = prnd + QSMS_SIMPLEX_SYMMETRIC_KEY_SIZE + QSMS_NONCE_SIZE;
		kp.keylen = QSMS_SIMPLEX_SYMMETRIC_KEY_SIZE;
		kp.nonce = ((uint8_t*)prnd + QSMS_SIMPLEX_SYMMETRIC_KEY_SIZE + QSMS_NONCE_SIZE + QSMS_SIMPLEX_SYMMETRIC_KEY_SIZE);
		kp.info = NULL;
		kp.infolen = 0U;
		qsc_rcs_initialize(&cns->rxcpr, &kp, false);
	}

	/* permute key state and store next key */
	qsc_keccak_permute(&kstate, QSC_KECCAK_PERMUTATION_ROUNDS);
	qsc_memutils_copy(cns->rtcs, (uint8_t*)kstate.state, QSMS_SIMPLEX_SYMMETRIC_KEY_SIZE);
	/* erase the key array */
	qsc_memutils_secure_erase(prnd, sizeof(prnd));
	qsc_memutils_secure_erase((uint8_t*)&kp, sizeof(qsc_rcs_keyparams));
	qsc_memutils_secure_erase(&kstate, sizeof(qsc_keccak_state));
}

static bool symmetric_ratchet_response(qsms_connection_state* cns, const qsms_network_packet* packetin)
{
	uint8_t rkey[QSMS_RTOK_SIZE] = { 0U };
	uint8_t shdr[QSMS_HEADER_SIZE] = { 0U };
	size_t mlen;
	bool res;

	res = false;

	if (packetin->sequence == cns->rxseq + 1U)
	{
		/* serialize the header and add it to the ciphers associated data */
		qsms_packet_header_serialize(packetin, shdr);
		qsc_rcs_set_associated(&cns->rxcpr, shdr, QSMS_HEADER_SIZE);
		mlen = packetin->msglen - (size_t)QSMS_SIMPLEX_MACTAG_SIZE;

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
	qsms_connection_state_dispose(prcv->pcns);
}

static void client_receive_loop(void* prcv)
{
	QSMS_ASSERT(prcv != NULL);

	qsms_network_packet pkt = { 0 };
	char cadd[QSC_SOCKET_ADDRESS_MAX_SIZE] = { 0 };
	client_receiver_state* pprcv;
	uint8_t* rbuf;
	size_t mlen;
	size_t plen;
	size_t slen;
	qsms_errors qerr;

	pprcv = (client_receiver_state*)prcv;
	qsc_memutils_copy(cadd, (const char*)pprcv->pcns->target.address, sizeof(cadd));

	rbuf = (uint8_t*)qsc_memutils_malloc(QSMS_HEADER_SIZE);

	if (rbuf != NULL)
	{
		while (pprcv->pcns->target.connection_status == qsc_socket_state_connected)
		{
			mlen = 0U;
			slen = 0U;
			qsc_memutils_clear(rbuf, QSMS_HEADER_SIZE);

			plen = qsc_socket_peek(&pprcv->pcns->target, rbuf, QSMS_HEADER_SIZE);

			if (plen == QSMS_HEADER_SIZE)
			{
				qsms_packet_header_deserialize(rbuf, &pkt);

				if (pkt.msglen > 0U && pkt.msglen <= QSMS_MESSAGE_MAX)
				{
					uint8_t* rtmp;

					plen = pkt.msglen + QSMS_HEADER_SIZE;
					rtmp = (uint8_t*)qsc_memutils_realloc(rbuf, plen);

					if (rtmp != NULL)
					{
						rbuf = rtmp;
						qsc_memutils_clear(rbuf, plen);
						mlen = qsc_socket_receive(&pprcv->pcns->target, rbuf, plen, qsc_socket_receive_flag_wait_all);

						if (mlen > 0U)
						{
							qsms_packet_header_deserialize(rbuf, &pkt);
							pkt.pmessage = rbuf + QSMS_HEADER_SIZE;

							if (pkt.flag == qsms_flag_encrypted_message)
							{
								uint8_t* rmsg;

								slen = pkt.msglen;

								if (pkt.msglen > QSMS_SIMPLEX_MACTAG_SIZE)
								{
									slen -= QSMS_SIMPLEX_MACTAG_SIZE;
									rmsg = (uint8_t*)qsc_memutils_malloc(slen);

									if (rmsg != NULL)
									{
										qsc_memutils_clear(rmsg, slen);
										qerr = qsms_packet_decrypt(pprcv->pcns, rmsg, &mlen, &pkt);

										if (qerr == qsms_error_none)
										{
											pprcv->callback(pprcv->pcns, rmsg, mlen);
										}
										else
										{
											/* close the connection on authentication failure */
											qsms_log_write(qsms_messages_decryption_fail, cadd);
											break;
										}

										qsc_memutils_secure_erase(rmsg, slen);
										qsc_memutils_alloc_free(rmsg);
									}
									else
									{
										/* close the connection on memory allocation failure */
										qsms_log_write(qsms_messages_allocate_fail, cadd);
										break;
									}
								}
								else
								{
									/* close the connection on receive failure */
									qsms_log_write(qsms_messages_receive_fail, cadd);
									break;
								}
							}
							else if (pkt.flag == qsms_flag_error_condition)
							{
								/* anti-dos: break on error message is conditional
								   on succesful authentication/decryption */
								if (qsms_decrypt_error_message(&qerr, pprcv->pcns, rbuf) == true)
								{
									qsms_log_system_error(qerr);
									break;
								}
							}
							else if (pkt.flag == qsms_flag_symmetric_ratchet_request)
							{
								if (symmetric_ratchet_response(pprcv->pcns, &pkt) == false)
								{
									/* symmetric ratchet authentication failed */
									qsms_log_write(qsms_messages_symmetric_ratchet, (const char*)pprcv->pcns->target.address);
									break;
								}
							}
							else
							{
								qsc_socket_exceptions err = qsc_socket_get_last_error();

								if (err != qsc_socket_exception_success)
								{
									qsms_log_error(qsms_messages_receive_fail, err, cadd);

									/* fatal socket errors */
									if (err == qsc_socket_exception_circuit_reset ||
										err == qsc_socket_exception_circuit_terminated ||
										err == qsc_socket_exception_circuit_timeout ||
										err == qsc_socket_exception_dropped_connection ||
										err == qsc_socket_exception_network_failure ||
										err == qsc_socket_exception_shut_down)
									{
										qsms_log_write(qsms_messages_connection_fail, cadd);
										break;
									}
								}
							}
						}
						else
						{
							qsms_log_write(qsms_messages_receive_fail, cadd);
							break;
						}
					}
				}
				else
				{
					/* close the connection on memory allocation failure */
					qsms_log_write(qsms_messages_allocate_fail, cadd);
					break;
				}
			}
			else
			{
				qsms_log_write(qsms_messages_receive_fail, cadd);
				break;
			}
			
			qsc_memutils_secure_erase(rbuf, plen);
		}

		qsc_memutils_alloc_free(rbuf);
	}
	else
	{
		qsms_log_write(qsms_messages_allocate_fail, cadd);
	}
}

static void listener_receive_loop(listener_receiver_state* prcv)
{
	QSMS_ASSERT(prcv != NULL);

	qsms_network_packet pkt = { 0 };
	char cadd[QSC_SOCKET_ADDRESS_MAX_SIZE] = { 0 };
	uint8_t* rbuf;
	size_t mlen;
	size_t plen;
	size_t slen;
	qsms_errors qerr;

	qsc_memutils_copy(cadd, (const char*)prcv->pcns->target.address, sizeof(cadd));

	rbuf = (uint8_t*)qsc_memutils_malloc(QSMS_HEADER_SIZE);

	if (rbuf != NULL)
	{
		while (prcv->pcns->target.connection_status == qsc_socket_state_connected)
		{
			mlen = 0U;
			slen = 0U;
			qsc_memutils_clear(rbuf, QSMS_HEADER_SIZE);

			plen = qsc_socket_peek(&prcv->pcns->target, rbuf, QSMS_HEADER_SIZE);

			if (plen == QSMS_HEADER_SIZE)
			{
				qsms_packet_header_deserialize(rbuf, &pkt);

				if (pkt.msglen > 0U && pkt.msglen <= QSMS_MESSAGE_MAX)
				{
					uint8_t* rtmp;

					plen = pkt.msglen + QSMS_HEADER_SIZE;
					rtmp = (uint8_t*)qsc_memutils_realloc(rbuf, plen);

					if (rtmp != NULL)
					{
						rbuf = rtmp;
						qsc_memutils_clear(rbuf, plen);
						mlen = qsc_socket_receive(&prcv->pcns->target, rbuf, plen, qsc_socket_receive_flag_wait_all);

						if (mlen > 0U)
						{
							qsms_packet_header_deserialize(rbuf, &pkt);
							pkt.pmessage = rbuf + QSMS_HEADER_SIZE;

							if (pkt.flag == qsms_flag_encrypted_message)
							{
								uint8_t* rmsg;

								slen = pkt.msglen;
								slen -= QSMS_SIMPLEX_MACTAG_SIZE;
								rmsg = (uint8_t*)qsc_memutils_malloc(slen);

								if (rmsg != NULL)
								{
									qsc_memutils_clear(rmsg, slen);
									qerr = qsms_packet_decrypt(prcv->pcns, rmsg, &mlen, &pkt);

									if (qerr == qsms_error_none)
									{
										prcv->callback(prcv->pcns, rmsg, mlen);
									}
									else
									{
										/* close the connection on authentication failure */
										qsms_log_write(qsms_messages_decryption_fail, cadd);
										break;
									}

									qsc_memutils_clear(rmsg, slen);
									qsc_memutils_alloc_free(rmsg);
								}
								else
								{
									/* close the connection on memory allocation failure */
									qsms_log_write(qsms_messages_allocate_fail, cadd);
									break;
								}
							}
							else if (pkt.flag == qsms_flag_connection_terminate)
							{
								qsms_log_write(qsms_messages_disconnect, cadd);
								break;
							}
							else if (pkt.flag == qsms_flag_symmetric_ratchet_request)
							{
								if (symmetric_ratchet_response(prcv->pcns, &pkt) == false)
								{
									qsms_log_write(qsms_messages_keepalive_timeout, (const char*)prcv->pcns->target.address);
									break;
								}
							}
							else
							{
								qsc_socket_exceptions err = qsc_socket_get_last_error();

								if (err != qsc_socket_exception_success)
								{
									qsms_log_error(qsms_messages_receive_fail, err, cadd);

									/* fatal socket errors */
									if (err == qsc_socket_exception_circuit_reset ||
										err == qsc_socket_exception_circuit_terminated ||
										err == qsc_socket_exception_circuit_timeout ||
										err == qsc_socket_exception_dropped_connection ||
										err == qsc_socket_exception_network_failure ||
										err == qsc_socket_exception_shut_down)
									{
										qsms_log_write(qsms_messages_connection_fail, cadd);
										break;
									}
								}
							}
						}
						else
						{
							qsms_log_write(qsms_messages_receive_fail, cadd);
							break;
						}

						qsc_memutils_secure_erase(rbuf, plen);
					}
				}
				else
				{
					/* close the connection on memory allocation failure */
					qsms_log_write(qsms_messages_allocate_fail, cadd);
					break;
				}
			}
			else
			{
				qsms_log_write(qsms_messages_receive_fail, cadd);
				break;
			}
		}

		qsc_memutils_alloc_free(rbuf);
	}
	else
	{
		qsms_log_write(qsms_messages_allocate_fail, cadd);
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

static qsms_errors listener_simplex_start(const qsms_server_signature_key* kset, 
	listener_receiver_state* prcv, 
	void (*send_func)(qsms_connection_state*))
{
	QSMS_ASSERT(kset != NULL);
	QSMS_ASSERT(prcv != NULL);
	QSMS_ASSERT(send_func != NULL);

	listener_receive_loop_args largs = { 0 };
	qsms_kex_simplex_server_state* pkss;
	qsc_thread trcv;
	qsms_errors qerr;

	qsms_logger_initialize(NULL);
	qerr = qsms_error_invalid_input;
	pkss = (qsms_kex_simplex_server_state*)qsc_memutils_malloc(sizeof(qsms_kex_simplex_server_state));

	if (pkss != NULL)
	{
		qsc_memutils_clear((uint8_t*)pkss, sizeof(qsms_kex_simplex_server_state));

		/* initialize the kex */
		listener_simplex_state_initialize(pkss, prcv, kset);
		qerr = qsms_kex_simplex_server_key_exchange(pkss, prcv->pcns);

		qsc_memutils_secure_erase((uint8_t*)pkss, sizeof(qsms_kex_simplex_server_state));
		qsc_memutils_alloc_free(pkss);
		pkss = NULL;

		if (qerr == qsms_error_none)
		{
			/* initialize the receiver loop on a new thread */
			largs.prcv = prcv;
			trcv = qsc_async_thread_create(&listener_receive_loop_wrapper, &largs);

			/* start the send loop on the *main* thread */
			send_func(prcv->pcns);

			/* terminate the receiver thread */
			(void)qsc_async_thread_terminate(trcv);
		}
	}

	return qerr;
}
/** \endcond */

/* Public Functions */

bool qsms_simplex_send_symmetric_ratchet_request(qsms_connection_state* cns)
{
	QSMS_ASSERT(cns != NULL);

	size_t plen;
	size_t slen;
	bool res;

	res = false;

	if (cns != NULL)
	{
		qsms_network_packet pkt = { 0 };
		uint8_t pmsg[QSMS_RTOK_SIZE + QSMS_SIMPLEX_MACTAG_SIZE] = { 0U };
		uint8_t rkey[QSMS_RTOK_SIZE] = { 0U };

		/* generate the token key */
		if (qsc_acp_generate(rkey, sizeof(rkey)) == true)
		{
			uint8_t shdr[QSMS_HEADER_SIZE] = { 0U };
			uint8_t spct[QSMS_HEADER_SIZE + QSMS_RTOK_SIZE + QSMS_SIMPLEX_MACTAG_SIZE] = { 0U };

			cns->txseq += 1U;
			pkt.pmessage = pmsg;
			pkt.flag = qsms_flag_symmetric_ratchet_request;
			pkt.msglen = QSMS_RTOK_SIZE + QSMS_SIMPLEX_MACTAG_SIZE;
			pkt.sequence = cns->txseq;
			qsms_packet_set_utc_time(&pkt);

			/* serialize the header and add it to the ciphers associated data */
			qsms_packet_header_serialize(&pkt, shdr);
			qsc_rcs_set_associated(&cns->txcpr, shdr, QSMS_HEADER_SIZE);
			/* encrypt the message */
			(void)qsc_rcs_transform(&cns->txcpr, pkt.pmessage, rkey, sizeof(rkey));

			/* convert the packet to bytes */
			plen = qsms_packet_to_stream(&pkt, spct);

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

qsms_errors qsms_client_simplex_connect_ipv4(const qsms_client_verification_key* pubk, 
	const qsc_ipinfo_ipv4_address* address, uint16_t port, 
	void (*send_func)(qsms_connection_state*), 
	void (*receive_callback)(qsms_connection_state*, const uint8_t*, size_t))
{
	QSMS_ASSERT(pubk != NULL);
	QSMS_ASSERT(send_func != NULL);
	QSMS_ASSERT(send_func != NULL);
	QSMS_ASSERT(receive_callback != NULL);

	qsms_kex_simplex_client_state* kcs;
	client_receiver_state* prcv;
	qsc_thread trcv;
	qsc_socket_exceptions serr;
	qsms_errors qerr;

	kcs = NULL;
	prcv = NULL;
	qsms_logger_initialize(NULL);

	if (address != NULL && send_func != NULL && receive_callback != NULL)
	{
		kcs = (qsms_kex_simplex_client_state*)qsc_memutils_malloc(sizeof(qsms_kex_simplex_client_state));

		if (kcs != NULL)
		{
			qsc_memutils_clear(kcs, sizeof(qsms_kex_simplex_client_state));
			prcv = (client_receiver_state*)qsc_memutils_malloc(sizeof(client_receiver_state));

			if (prcv != NULL)
			{
				qsc_memutils_clear(prcv, sizeof(client_receiver_state));

				prcv->pcns = (qsms_connection_state*)qsc_memutils_malloc(sizeof(qsms_connection_state));

				if (prcv->pcns != NULL)
				{
					qsc_memutils_clear(prcv->pcns, sizeof(qsms_connection_state));
					prcv->callback = receive_callback;
					qsc_socket_client_initialize(&prcv->pcns->target);

					serr = qsc_socket_client_connect_ipv4(&prcv->pcns->target, address, port);

					if (serr == qsc_socket_exception_success)
					{
						/* initialize the client */
						client_simplex_state_initialize(kcs, prcv->pcns, pubk);
						/* perform the simplex key exchange */
						qerr = qsms_kex_simplex_client_key_exchange(kcs, prcv->pcns);

						/* clear the kex state */
						qsc_memutils_secure_erase((uint8_t*)kcs, sizeof(qsms_kex_simplex_client_state));
						qsc_memutils_alloc_free(kcs);
						kcs = NULL;

						if (qerr == qsms_error_none)
						{
							/* start the receive loop on a new thread */
							trcv = qsc_async_thread_create(&client_receive_loop, prcv);

							/* start the send loop on the main thread */
							send_func(prcv->pcns);

							/* terminate the receiver thread */
							(void)qsc_async_thread_terminate(trcv);
						}
						else
						{
							qsms_log_write(qsms_messages_kex_fail, (const char*)prcv->pcns->target.address);
							qerr = qsms_error_exchange_failure;
						}

						if (prcv != NULL && prcv->pcns != NULL)
						{
							qsms_connection_close(prcv->pcns, qsms_error_none, true);
						}
					}
					else
					{
						qsms_log_write(qsms_messages_kex_fail, (const char*)prcv->pcns->target.address);
						qerr = qsms_error_connection_failure;
					}

												
					/* dispose of the state */
					client_connection_dispose(prcv);
					qsc_memutils_alloc_free(prcv->pcns);
					prcv->pcns = NULL;
				}
				else
				{
					qsms_log_message(qsms_messages_allocate_fail);
					qerr = qsms_error_memory_allocation;
				}

				qsc_memutils_alloc_free(prcv);
				prcv = NULL;
			}
			else
			{
				qsms_log_message(qsms_messages_allocate_fail);
				qerr = qsms_error_memory_allocation;
			}

			if (kcs != NULL)
			{
				qsc_memutils_alloc_free(kcs);
				kcs = NULL;
			}
		}
		else
		{
			qsms_log_message(qsms_messages_allocate_fail);
			qerr = qsms_error_memory_allocation;
		}
	}
	else
	{
		qsms_log_message(qsms_messages_invalid_request);
		qerr = qsms_error_invalid_input;
	}

	return qerr;
}

qsms_errors qsms_client_simplex_connect_ipv6(const qsms_client_verification_key* pubk, 
	const qsc_ipinfo_ipv6_address* address, uint16_t port, 
	void (*send_func)(qsms_connection_state*), 
	void (*receive_callback)(qsms_connection_state*, const uint8_t*, size_t))
{
	QSMS_ASSERT(pubk != NULL);
	QSMS_ASSERT(send_func != NULL);
	QSMS_ASSERT(send_func != NULL);
	QSMS_ASSERT(receive_callback != NULL);

	qsms_kex_simplex_client_state* kcs;
	client_receiver_state* prcv;
	qsc_thread trcv;
	qsc_socket_exceptions serr;
	qsms_errors qerr;

	kcs = NULL;
	prcv = NULL;
	qsms_logger_initialize(NULL);

	if (address != NULL && send_func != NULL && receive_callback != NULL)
	{
		kcs = (qsms_kex_simplex_client_state*)qsc_memutils_malloc(sizeof(qsms_kex_simplex_client_state));

		if (kcs != NULL)
		{
			qsc_memutils_clear(kcs, sizeof(qsms_kex_simplex_client_state));
			prcv = (client_receiver_state*)qsc_memutils_malloc(sizeof(client_receiver_state));

			if (prcv != NULL)
			{
				qsc_memutils_clear(prcv, sizeof(client_receiver_state));

				prcv->pcns = (qsms_connection_state*)qsc_memutils_malloc(sizeof(qsms_connection_state));

				if (prcv->pcns != NULL)
				{
					qsc_memutils_clear(prcv->pcns, sizeof(qsms_connection_state));
					prcv->callback = receive_callback;
					qsc_socket_client_initialize(&prcv->pcns->target);

					serr = qsc_socket_client_connect_ipv6(&prcv->pcns->target, address, port);

					if (serr == qsc_socket_exception_success)
					{
						/* initialize the client */
						client_simplex_state_initialize(kcs, prcv->pcns, pubk);
						/* perform the simplex key exchange */
						qerr = qsms_kex_simplex_client_key_exchange(kcs, prcv->pcns);

						/* clear the kex state */
						qsc_memutils_secure_erase((uint8_t*)kcs, sizeof(qsms_kex_simplex_client_state));
						qsc_memutils_alloc_free(kcs);
						kcs = NULL;

						if (qerr == qsms_error_none)
						{
							/* start the receive loop on a new thread */
							trcv = qsc_async_thread_create(&client_receive_loop, prcv);

							/* start the send loop on the main thread */
							send_func(prcv->pcns);

							/* terminate the receiver thread */
							(void)qsc_async_thread_terminate(trcv);
						}
						else
						{
							qsms_log_write(qsms_messages_kex_fail, (const char*)prcv->pcns->target.address);
							qerr = qsms_error_exchange_failure;
						}

						if (prcv != NULL && prcv->pcns != NULL)
						{
							qsms_connection_close(prcv->pcns, qsms_error_none, true);
						}
					}
					else
					{
						qsms_log_write(qsms_messages_kex_fail, (const char*)prcv->pcns->target.address);
						qerr = qsms_error_connection_failure;
					}

												
					/* dispose of the state */
					client_connection_dispose(prcv);
					qsc_memutils_alloc_free(prcv->pcns);
					prcv->pcns = NULL;
				}
				else
				{
					qsms_log_message(qsms_messages_allocate_fail);
					qerr = qsms_error_memory_allocation;
				}

				qsc_memutils_alloc_free(prcv);
				prcv = NULL;
			}
			else
			{
				qsms_log_message(qsms_messages_allocate_fail);
				qerr = qsms_error_memory_allocation;
			}

			if (kcs != NULL)
			{
				qsc_memutils_alloc_free(kcs);
				kcs = NULL;
			}
		}
		else
		{
			qsms_log_message(qsms_messages_allocate_fail);
			qerr = qsms_error_memory_allocation;
		}
	}
	else
	{
		qsms_log_message(qsms_messages_invalid_request);
		qerr = qsms_error_invalid_input;
	}

	return qerr;
}

qsms_errors qsms_client_simplex_listen_ipv4(const qsms_server_signature_key* kset, 
	void (*send_func)(qsms_connection_state*), 
	void (*receive_callback)(qsms_connection_state*, const uint8_t*, size_t))
{
	QSMS_ASSERT(kset != NULL);
	QSMS_ASSERT(send_func != NULL);
	QSMS_ASSERT(receive_callback != NULL);

	qsc_ipinfo_ipv4_address addt = { 0 };
	listener_receiver_state* prcv;
	qsc_socket srvs;
	qsc_socket_exceptions serr;
	qsms_errors qerr;
	qsms_logger_initialize(NULL);

	prcv = NULL;

	if (kset != NULL && send_func != NULL && receive_callback != NULL)
	{
		prcv = (listener_receiver_state*)qsc_memutils_malloc(sizeof(listener_receiver_state));

		if (prcv != NULL)
		{
			prcv->pcns = (qsms_connection_state*)qsc_memutils_malloc(sizeof(qsms_connection_state));

			if (prcv->pcns != NULL)
			{
				prcv->callback = receive_callback;
				qsc_memutils_clear((uint8_t*)prcv->pcns, sizeof(qsms_connection_state));

				addt = qsc_ipinfo_ipv4_address_any();
				qsc_socket_server_initialize(&prcv->pcns->target);
				qsc_socket_server_initialize(&srvs);

				serr = qsc_socket_server_listen_ipv4(&srvs, &prcv->pcns->target, &addt, QSMS_SERVER_PORT);

				if (serr == qsc_socket_exception_success)
				{
					qerr = listener_simplex_start(kset, prcv, send_func);
				}
				else
				{
					qsms_log_message(qsms_messages_connection_fail);
					qerr = qsms_error_connection_failure;
				}
			}
			else
			{
				qsms_log_message(qsms_messages_allocate_fail);
				qsc_memutils_alloc_free(prcv);
				qerr = qsms_error_memory_allocation;
			}
		}
		else
		{
			qsms_log_message(qsms_messages_allocate_fail);
			qerr = qsms_error_memory_allocation;
		}
	}
	else
	{
		qsms_log_message(qsms_messages_invalid_request);
		qerr = qsms_error_invalid_input;
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

qsms_errors qsms_client_simplex_listen_ipv6(const qsms_server_signature_key* kset, 
	void (*send_func)(qsms_connection_state*), 
	void (*receive_callback)(qsms_connection_state*, const uint8_t*, size_t))
{
	QSMS_ASSERT(kset != NULL);
	QSMS_ASSERT(send_func != NULL);
	QSMS_ASSERT(receive_callback != NULL);

	qsc_ipinfo_ipv6_address addt = { 0 };
	listener_receiver_state* prcv;
	qsc_socket srvs;
	qsc_socket_exceptions serr;
	qsms_errors qerr;

	prcv = NULL;

	if (kset != NULL && send_func != NULL && receive_callback != NULL)
	{
		prcv = (listener_receiver_state*)qsc_memutils_malloc(sizeof(listener_receiver_state));

		if (prcv != NULL)
		{
			prcv->pcns = (qsms_connection_state*)qsc_memutils_malloc(sizeof(qsms_connection_state));

			if (prcv->pcns != NULL)
			{
				prcv->callback = receive_callback;
				qsc_memutils_clear((uint8_t*)prcv->pcns, sizeof(qsms_connection_state));

				addt = qsc_ipinfo_ipv6_address_any();
				qsc_socket_server_initialize(&prcv->pcns->target);
				qsc_socket_server_initialize(&srvs);

				serr = qsc_socket_server_listen_ipv6(&srvs, &prcv->pcns->target, &addt, QSMS_SERVER_PORT);

				if (serr == qsc_socket_exception_success)
				{
					qerr = listener_simplex_start(kset, prcv, send_func);
				}
				else
				{
					qsms_log_message(qsms_messages_connection_fail);
					qerr = qsms_error_connection_failure;
				}
			}
			else
			{
				qsms_log_message(qsms_messages_allocate_fail);
				qsc_memutils_alloc_free(prcv);
				qerr = qsms_error_memory_allocation;
			}
		}
		else
		{
			qsms_log_message(qsms_messages_allocate_fail);
			qerr = qsms_error_memory_allocation;
		}
	}
	else
	{
		qsms_log_message(qsms_messages_invalid_request);
		qerr = qsms_error_invalid_input;
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

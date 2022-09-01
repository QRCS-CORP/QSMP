#include "qsmpclient.h"
#include "../QSMP/kex.h"
#include "../QSMP/logger.h"
#include "../QSC/acp.h"
#include "../QSC/async.h"
#include "../QSC/intutils.h"
#include "../QSC/memutils.h"
#include "../QSC/sha3.h"
#include "../QSC/socketserver.h"
#include "../QSC/timestamp.h"

typedef struct client_receiver_state
{
	qsmp_connection_state* pcns;
	void (*callback)(qsmp_connection_state*, const char*, size_t);
} client_receiver_state;

typedef struct listener_receiver_state
{
	qsmp_connection_state* pcns;
	qsmp_keep_alive_state* pkpa;
	void (*callback)(qsmp_connection_state*, const char*, size_t);
} listener_receiver_state;

/* Private Functions */

static void client_duplex_state_initialize(qsmp_kex_duplex_client_state* kcs, qsmp_connection_state* cns, const qsmp_server_key* prik, const qsmp_client_key* rverkey)
{
	qsc_memutils_copy(kcs->verkey, prik->verkey, QSMP_VERIFYKEY_SIZE);
	qsc_memutils_copy(kcs->sigkey, prik->sigkey, QSMP_SIGNKEY_SIZE);
	qsc_memutils_copy(kcs->keyid, rverkey->keyid, QSMP_KEYID_SIZE);
	qsc_memutils_copy(kcs->rverkey, rverkey->verkey, QSMP_VERIFYKEY_SIZE);
	kcs->expiration = rverkey->expiration;
	qsc_rcs_dispose(&cns->rxcpr);
	qsc_rcs_dispose(&cns->txcpr);
	qsc_keccak_dispose(&cns->rtcs);
	cns->exflag = qsmp_flag_none;
	cns->instance = 0;
	cns->rxseq = 0;
	cns->txseq = 0;
}

static void listener_duplex_state_initialize(qsmp_kex_duplex_server_state* kss, listener_receiver_state* rcv, 
	const qsmp_server_key* prik, 
	bool (*key_query)(uint8_t* rvkey, const uint8_t* pkid))
{
	qsc_memutils_copy(kss->keyid, prik->keyid, QSMP_KEYID_SIZE);
	qsc_memutils_copy(kss->sigkey, prik->sigkey, QSMP_SIGNKEY_SIZE);
	qsc_memutils_copy(kss->verkey, prik->verkey, QSMP_VERIFYKEY_SIZE);
	kss->key_query = key_query;
	kss->expiration = prik->expiration;
	qsc_memutils_copy(&rcv->pkpa->target, &rcv->pcns->target, sizeof(qsc_socket));
	qsc_memutils_clear((uint8_t*)&rcv->pcns->rxcpr, sizeof(qsc_rcs_state));
	qsc_memutils_clear((uint8_t*)&rcv->pcns->txcpr, sizeof(qsc_rcs_state));
	qsc_keccak_dispose(&rcv->pcns->rtcs);
	rcv->pcns->exflag = qsmp_flag_none;
	rcv->pcns->instance = 0;
	rcv->pcns->rxseq = 0;
	rcv->pcns->txseq = 0;
}

static void client_simplex_state_initialize(qsmp_kex_simplex_client_state* kcs, qsmp_connection_state* cns, const qsmp_client_key* pubk)
{
	qsc_memutils_copy(kcs->keyid, pubk->keyid, QSMP_KEYID_SIZE);
	qsc_memutils_copy(kcs->verkey, pubk->verkey, QSMP_VERIFYKEY_SIZE);
	kcs->expiration = pubk->expiration;
	qsc_rcs_dispose(&cns->rxcpr);
	qsc_rcs_dispose(&cns->txcpr);
	qsc_keccak_dispose(&cns->rtcs);
	cns->exflag = qsmp_flag_none;
	cns->instance = 0;
	cns->rxseq = 0;
	cns->txseq = 0;
}

static void listener_simplex_state_initialize(qsmp_kex_simplex_server_state* kss, listener_receiver_state* rcv, const qsmp_server_key* prik)
{
	qsc_memutils_copy(kss->keyid, prik->keyid, QSMP_KEYID_SIZE);
	qsc_memutils_copy(kss->sigkey, prik->sigkey, QSMP_SIGNKEY_SIZE);
	qsc_memutils_copy(kss->verkey, prik->verkey, QSMP_VERIFYKEY_SIZE);
	kss->expiration = prik->expiration;
	qsc_memutils_copy(&rcv->pkpa->target, &rcv->pcns->target, sizeof(qsc_socket));
	qsc_memutils_clear((uint8_t*)&rcv->pcns->rxcpr, sizeof(qsc_rcs_state));
	qsc_memutils_clear((uint8_t*)&rcv->pcns->txcpr, sizeof(qsc_rcs_state));
	qsc_keccak_dispose(&rcv->pcns->rtcs);
	rcv->pcns->exflag = qsmp_flag_none;
	rcv->pcns->instance = 0;
	rcv->pcns->rxseq = 0;
	rcv->pcns->txseq = 0;
}

static void client_symmetric_ratchet(qsmp_connection_state* cns, const uint8_t* secret, size_t seclen)
{
	uint8_t prnd[(QSC_KECCAK_512_RATE * 3)] = { 0 };

	/* add the symmetric key to the ratchet key state */
	qsc_cshake_update(&cns->rtcs, qsc_keccak_rate_512, secret, seclen);
	/* re-key the ciphers using the ratchet key state */
	qsc_cshake_squeezeblocks(&cns->rtcs, qsc_keccak_rate_512, prnd, 3);
	/* ratchet key state; permute the state so we are not storing the current keys */
	qsc_keccak_permute(&cns->rtcs, QSC_KECCAK_PERMUTATION_ROUNDS);

	/* initialize for decryption, and raise client channel rx */
	qsc_rcs_keyparams kp1;
	kp1.key = prnd;
	kp1.keylen = QSMP_DUPLEX_SKEY_SIZE;
	kp1.nonce = ((uint8_t*)prnd + QSMP_DUPLEX_SKEY_SIZE);
	kp1.info = NULL;
	kp1.infolen = 0;
	qsc_rcs_initialize(&cns->rxcpr, &kp1, false);

	/* initialize for encryption, and raise client channel tx */
	qsc_rcs_keyparams kp2;
	kp2.key = prnd + QSMP_DUPLEX_SKEY_SIZE + QSMP_NONCE_SIZE;
	kp2.keylen = QSMP_DUPLEX_SKEY_SIZE;
	kp2.nonce = ((uint8_t*)prnd + QSMP_DUPLEX_SKEY_SIZE + QSMP_NONCE_SIZE + QSMP_DUPLEX_SKEY_SIZE);
	kp2.info = NULL;
	kp2.infolen = 0;
	qsc_rcs_initialize(&cns->txcpr, &kp2, true);

	/* erase the keys */
	qsc_memutils_clear(prnd, sizeof(prnd));
}

static bool client_ratchet_response(qsmp_connection_state* cns, const qsmp_packet* packetin)
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
		if (qsc_rcs_transform(&cns->rxcpr, rkey, packetin->message, mlen) == true)
		{
			client_symmetric_ratchet(cns, rkey, sizeof(rkey));
			res = true;
		}
	}

	return res;
}

static void client_receive_loop(client_receiver_state* prcv)
{
	assert(prcv != NULL);

	uint8_t buffer[QSMP_CONNECTION_MTU] = { 0 };
	char msgstr[QSMP_CONNECTION_MTU + 1] = { 0 };
	qsmp_packet pkt = { 0 };
	qsmp_errors qerr;
	size_t mlen;

	while (prcv->pcns->target.connection_status == qsc_socket_state_connected)
	{
		mlen = qsc_socket_receive(&prcv->pcns->target, buffer, sizeof(buffer), qsc_socket_receive_flag_none);

		if (mlen == 0)
		{
			if (qsc_socket_is_connected(&prcv->pcns->target) == false)
			{
				break;
			}
		}

		if (mlen > 0)
		{
			/* convert the bytes to packet */
			qsmp_stream_to_packet(buffer, &pkt);
			qsc_memutils_clear(buffer, mlen);

			if (pkt.flag == qsmp_flag_encrypted_message)
			{
				qerr = qsmp_decrypt_packet(prcv->pcns, (uint8_t*)msgstr, &mlen, &pkt);

				if (qerr == qsmp_error_none)
				{
					prcv->callback(prcv->pcns, msgstr, mlen);
					qsc_memutils_clear(msgstr, sizeof(msgstr));
				}
				else
				{
					/* close the connection on authentication failure */
					qsmp_log_write(qsmp_messages_decryption_fail, (const char*)prcv->pcns->target.address);
					qsmp_connection_close(prcv->pcns, qsmp_error_authentication_failure, true);
					break;
				}
			}
			else if (pkt.flag == qsmp_flag_connection_terminate)
			{
				qsmp_log_write(qsmp_messages_disconnect, (const char*)prcv->pcns->target.address);
				qsmp_connection_close(prcv->pcns, qsmp_error_none, false);
				break;
			}
			else if (pkt.flag == qsmp_flag_keep_alive_request)
			{
				/* copy the keep-alive packet and send it back */
				pkt.flag = qsmp_flag_keep_alive_response;
				mlen = qsmp_packet_to_stream(&pkt, (uint8_t*)msgstr);
				qsc_socket_send(&prcv->pcns->target, (uint8_t*)msgstr, mlen, qsc_socket_send_flag_none);
			}
			else if (pkt.flag == qsmp_flag_ratchet_request)
			{
				if (client_ratchet_response(prcv->pcns, &pkt) == false)
				{
					qsmp_log_write(qsmp_messages_keepalive_timeout, (const char*)prcv->pcns->target.address);
					qsmp_connection_close(prcv->pcns, qsmp_error_ratchet_fail, true);
					break;
				}
			}
			else
			{
				qsc_socket_exceptions err = qsc_socket_get_last_error();

				if (err != qsc_socket_exception_success)
				{
					qsmp_log_error(qsmp_messages_receive_fail, err, prcv->pcns->target.address);

					/* fatal socket errors */
					if (err == qsc_socket_exception_circuit_reset ||
						err == qsc_socket_exception_circuit_terminated ||
						err == qsc_socket_exception_circuit_timeout ||
						err == qsc_socket_exception_dropped_connection ||
						err == qsc_socket_exception_network_failure ||
						err == qsc_socket_exception_shut_down)
					{
						qsmp_log_write(qsmp_messages_connection_fail, (const char*)prcv->pcns->target.address);
						qsmp_connection_close(prcv->pcns, qsmp_error_channel_down, false);
						break;
					}
				}
			}
		}
	}

	/* dispose of resources */
	qsmp_connection_state_dispose(prcv->pcns);

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
}

static void listener_symmetric_ratchet(qsmp_connection_state* cns, const uint8_t* secret, size_t seclen)
{
	uint8_t prnd[(QSC_KECCAK_512_RATE * 3)] = { 0 };

	/* add the symmetric key to the ratchet key state */
	qsc_cshake_update(&cns->rtcs, qsc_keccak_rate_512, secret, seclen);
	/* re-key the ciphers using the ratchet key state */
	qsc_cshake_squeezeblocks(&cns->rtcs, qsc_keccak_rate_512, prnd, 3);
	/* ratchet key state; permute the state so we are not storing the current keys */
	qsc_keccak_permute(&cns->rtcs, QSC_KECCAK_PERMUTATION_ROUNDS);

	/* initialize for encryption, and raise tx */
	qsc_rcs_keyparams kp1;
	kp1.key = prnd;
	kp1.keylen = QSMP_DUPLEX_SKEY_SIZE;
	kp1.nonce = ((uint8_t*)prnd + QSMP_DUPLEX_SKEY_SIZE);
	kp1.info = NULL;
	kp1.infolen = 0;
	qsc_rcs_initialize(&cns->txcpr, &kp1, true);

	/* initialize decryption, and raise rx */
	qsc_rcs_keyparams kp2;
	kp2.key = prnd + QSMP_DUPLEX_SKEY_SIZE + QSMP_NONCE_SIZE;
	kp2.keylen = QSMP_DUPLEX_SKEY_SIZE;
	kp2.nonce = ((uint8_t*)prnd + QSMP_DUPLEX_SKEY_SIZE + QSMP_NONCE_SIZE + QSMP_DUPLEX_SKEY_SIZE);
	kp2.info = NULL;
	kp2.infolen = 0;
	qsc_rcs_initialize(&cns->rxcpr, &kp2, false);

	/* erase the keys */
	qsc_memutils_clear(prnd, sizeof(prnd));
}

static bool listener_ratchet_response(qsmp_connection_state* cns, const qsmp_packet* packetin)
{
	uint8_t rkey[QSMP_DUPLEX_SKEY_SIZE] = { 0 };
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
		if (qsc_rcs_transform(&cns->rxcpr, rkey, packetin->message, mlen) == true)
		{
			listener_symmetric_ratchet(cns, rkey, sizeof(rkey));
			res = true;
		}
	}

	return res;
}

static qsmp_errors listener_send_keep_alive(qsmp_keep_alive_state* kctx, const qsc_socket* sock)
{
	assert(kctx != NULL);
	assert(sock != NULL);

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
			qerr = qsmp_error_keep_alive_expired;
		}

		qsc_async_mutex_unlock_ex(mtx);
		qsc_async_thread_sleep(QSMP_KEEPALIVE_TIMEOUT);
	} 
	while (qerr == qsmp_error_none);
}

static void listener_receive_loop(listener_receiver_state* prcv)
{
	assert(prcv != NULL);

	uint8_t buffer[QSMP_CONNECTION_MTU] = { 0 };
	char msgstr[QSMP_CONNECTION_MTU + 1] = { 0 };
	qsmp_packet pkt = { 0 };
	qsmp_errors qerr;
	size_t mlen;

	while (prcv->pcns->target.connection_status == qsc_socket_state_connected)
	{
		mlen = qsc_socket_receive(&prcv->pcns->target, buffer, sizeof(buffer), qsc_socket_receive_flag_none);

		if (mlen == 0)
		{
			if (qsc_socket_is_connected(&prcv->pcns->target) == false)
			{
				break;
			}
		}

		if (mlen > 0)
		{
			/* convert the bytes to packet */
			qsmp_stream_to_packet(buffer, &pkt);

			if (pkt.flag == qsmp_flag_encrypted_message)
			{
				qerr = qsmp_decrypt_packet(prcv->pcns, (uint8_t*)msgstr, &mlen, &pkt);

				if (qerr == qsmp_error_none)
				{
					prcv->callback(prcv->pcns, msgstr, mlen);
				}
				else
				{
					qsmp_log_write(qsmp_messages_decryption_fail, (const char*)prcv->pcns->target.address);
					qsmp_connection_close(prcv->pcns, qsmp_error_authentication_failure, true);
					break;
				}

				qsc_memutils_clear(msgstr, mlen + 1);
			}
			else if (pkt.flag == qsmp_flag_connection_terminate)
			{
				qsmp_log_write(qsmp_messages_disconnect, (const char*)prcv->pcns->target.address);
				qsmp_connection_close(prcv->pcns, qsmp_error_none, false);
				break;
			}
			else if (pkt.flag == qsmp_flag_keep_alive_response)
			{
				/* test the keepalive */

				if (pkt.sequence == prcv->pkpa->seqctr)
				{
					uint64_t tme;

					tme = qsc_intutils_le8to64(pkt.message);

					if (prcv->pkpa->etime == tme)
					{
						prcv->pkpa->seqctr += 1;
						prcv->pkpa->recd = true;
					}
					else
					{
						qsmp_log_write(qsmp_messages_keepalive_fail, (const char*)prcv->pcns->target.address);
						qsmp_connection_close(prcv->pcns, qsmp_error_bad_keep_alive, true);
						break;
					}
				}
				else
				{
					qsmp_log_write(qsmp_messages_keepalive_timeout, (const char*)prcv->pcns->target.address);
					qsmp_connection_close(prcv->pcns, qsmp_error_bad_keep_alive, true);
					break;
				}
			}
			else if (pkt.flag == qsmp_flag_ratchet_request)
			{
				if (listener_ratchet_response(prcv->pcns, &pkt) == false)
				{
					qsmp_log_write(qsmp_messages_keepalive_timeout, (const char*)prcv->pcns->target.address);
					qsmp_connection_close(prcv->pcns, qsmp_error_authentication_failure, true);
					break;
				}
			}
			else
			{
				qsc_socket_exceptions err = qsc_socket_get_last_error();

				if (err != qsc_socket_exception_success)
				{
					qsmp_log_error(qsmp_messages_receive_fail, err, prcv->pcns->target.address);

					/* fatal socket errors */
					if (err == qsc_socket_exception_circuit_reset ||
						err == qsc_socket_exception_circuit_terminated ||
						err == qsc_socket_exception_circuit_timeout ||
						err == qsc_socket_exception_dropped_connection ||
						err == qsc_socket_exception_network_failure ||
						err == qsc_socket_exception_shut_down)
					{
						qsmp_log_write(qsmp_messages_connection_fail, (const char*)prcv->pcns->target.address);
						qsmp_connection_close(prcv->pcns, qsmp_error_channel_down, false);
						break;
					}
				}
			}
		}
	}

	/* dispose of resources */
	qsmp_connection_state_dispose(prcv->pcns);

	if (prcv != NULL)
	{
		if (prcv->pcns != NULL)
		{
			qsc_memutils_alloc_free(prcv->pcns);
			prcv->pcns = NULL;
		}

		if (prcv->pkpa != NULL)
		{
			qsc_memutils_alloc_free(prcv->pkpa);
			prcv->pkpa = NULL;
		}

		if (prcv->callback != NULL)
		{
			prcv->callback = NULL;
		}

		if (prcv != NULL)
		{
			qsc_memutils_alloc_free(prcv);
			prcv = NULL;
		}
	}
}

static qsmp_errors listener_duplex_start(const qsmp_server_key* prik, 
	listener_receiver_state* prcv, 
	void (*send_func)(qsmp_connection_state*),
	bool (*key_query)(uint8_t* rvkey, const uint8_t* pkid))
{
	assert(prik != NULL);
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
		listener_duplex_state_initialize(pkss, prcv, prik, key_query);
		qerr = qsmp_kex_duplex_server_key_exchange(pkss, prcv->pcns);

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

static qsmp_errors listener_simplex_start(const qsmp_server_key* prik, 
	listener_receiver_state* prcv, 
	void (*send_func)(qsmp_connection_state*))
{
	assert(prik != NULL);
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
		listener_simplex_state_initialize(pkss, prcv, prik);
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

			qsmp_connection_close(prcv->pcns, qsmp_error_none, true);
		}
	}

	return qerr;
}

/* Public Functions */

bool qsmp_client_duplex_send_ratchet_request(qsmp_connection_state* cns, bool listener)
{
	assert(cns != NULL);

	size_t plen;
	size_t slen;
	bool res;
	
	res = false;

	if (cns != NULL)
	{
		qsmp_packet pkt = { 0 };
		uint8_t rkey[QSMP_RTOK_SIZE] = { 0 };

		/* generate the ratchet key */
		if (qsc_acp_generate(rkey, sizeof(rkey)) == true)
		{
			uint8_t hdr[QSMP_HEADER_SIZE] = { 0 };
			uint8_t spct[QSMP_HEADER_SIZE + QSMP_RTOK_SIZE + QSMP_DUPLEX_MACTAG_SIZE + QSC_SOCKET_TERMINATOR_SIZE] = { 0 };

			cns->txseq += 1;
			pkt.flag = qsmp_flag_ratchet_request;
			pkt.msglen = QSMP_RTOK_SIZE + QSMP_DUPLEX_MACTAG_SIZE;
			pkt.sequence = cns->txseq;

			/* serialize the header and add it to the ciphers associated data */
			qsmp_packet_header_serialize(&pkt, hdr);
			qsc_rcs_set_associated(&cns->txcpr, hdr, QSMP_HEADER_SIZE);
			/* encrypt the message */
			qsc_rcs_transform(&cns->txcpr, pkt.message, rkey, sizeof(rkey));

			/* convert the packet to bytes */
			plen = qsmp_packet_to_stream(&pkt, spct);

			/* send the ratchet request */
			slen = qsc_socket_send(&cns->target, spct, plen, qsc_socket_send_flag_none);

			if (slen == plen + QSC_SOCKET_TERMINATOR_SIZE)
			{
				if (listener == true)
				{
					listener_symmetric_ratchet(cns, rkey, sizeof(rkey));
				}
				else
				{
					client_symmetric_ratchet(cns, rkey, sizeof(rkey));
				}

				res = true;
			}
		}
	}

	return res;
}

qsmp_errors qsmp_client_duplex_connect_ipv4(const qsmp_server_key* prik, const qsmp_client_key* rverkey, 
	const qsc_ipinfo_ipv4_address* address, uint16_t port,
	void (*send_func)(qsmp_connection_state*), 
	void (*receive_callback)(qsmp_connection_state*, const char*, size_t))
{
	assert(prik != NULL);
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

	if (prik != NULL && rverkey != NULL && address != NULL && send_func != NULL && receive_callback != NULL)
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
						client_duplex_state_initialize(kcs, prcv->pcns, prik, rverkey);
						/* perform the simplex key exchange */
						qerr = qsmp_kex_duplex_client_key_exchange(kcs, prcv->pcns);
						qsc_memutils_alloc_free(kcs);
						kcs = NULL;

						if (qerr == qsmp_error_none)
						{
							/* start the receive loop on a new thread */
							qsc_async_thread_create((void*)&client_receive_loop, prcv);

							/* start the send loop on the main thread */
							send_func(prcv->pcns);
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

	return qerr;
}

qsmp_errors qsmp_client_duplex_connect_ipv6(const qsmp_server_key* prik, const qsmp_client_key* rverkey,
	const qsc_ipinfo_ipv6_address* address, uint16_t port,
	void (*send_func)(qsmp_connection_state*),
	void (*receive_callback)(qsmp_connection_state*, const char*, size_t))
{
	assert(prik != NULL);
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

	if (prik != NULL && rverkey != NULL && address != NULL && send_func != NULL && receive_callback != NULL)
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
						client_duplex_state_initialize(kcs, prcv->pcns, prik, rverkey);
						/* perform the simplex key exchange */
						qerr = qsmp_kex_duplex_client_key_exchange(kcs, prcv->pcns);
						qsc_memutils_alloc_free(kcs);
						kcs = NULL;

						if (qerr == qsmp_error_none)
						{
							/* start the receive loop on a new thread */
							qsc_async_thread_create((void*)&client_receive_loop, prcv);

							/* start the send loop on the main thread */
							send_func(prcv->pcns);
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

	return qerr;
}

qsmp_errors qsmp_client_simplex_connect_ipv4(const qsmp_client_key* pubk, 
	const qsc_ipinfo_ipv4_address* address, uint16_t port, 
	void (*send_func)(qsmp_connection_state*), 
	void (*receive_callback)(qsmp_connection_state*, const char*, size_t))
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

	return qerr;
}

qsmp_errors qsmp_client_simplex_connect_ipv6(const qsmp_client_key* pubk, 
	const qsc_ipinfo_ipv6_address* address, uint16_t port, 
	void (*send_func)(qsmp_connection_state*), 
	void (*receive_callback)(qsmp_connection_state*, const char*, size_t))
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

	return qerr;
}

qsmp_errors qsmp_client_simplex_listen_ipv4(const qsmp_server_key* prik, 
	void (*send_func)(qsmp_connection_state*), 
	void (*receive_callback)(qsmp_connection_state*, const char*, size_t))
{
	assert(prik != NULL);
	assert(send_func != NULL);
	assert(receive_callback != NULL);

	qsc_ipinfo_ipv4_address addt = { 0 };
	listener_receiver_state* prcv;
	qsc_socket srvs;
	qsc_socket_exceptions serr;
	qsmp_errors qerr;
	qsmp_logger_initialize(NULL);

	prcv = NULL;

	if (prik != NULL && send_func != NULL && receive_callback != NULL)
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
					qerr = listener_simplex_start(prik, prcv, send_func);
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

qsmp_errors qsmp_client_simplex_listen_ipv6(const qsmp_server_key* prik, 
	void (*send_func)(qsmp_connection_state*), 
	void (*receive_callback)(qsmp_connection_state*, const char*, size_t))
{
	assert(prik != NULL);
	assert(send_func != NULL);
	assert(receive_callback != NULL);

	qsc_ipinfo_ipv6_address addt = { 0 };
	listener_receiver_state* prcv;
	qsc_socket srvs;
	qsc_socket_exceptions serr;
	qsmp_errors qerr;

	prcv = NULL;

	if (prik != NULL && send_func != NULL && receive_callback != NULL)
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
					qerr = listener_simplex_start(prik, prcv, send_func);
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

qsmp_errors qsmp_client_duplex_listen_ipv4(const qsmp_server_key* prik, 
	void (*send_func)(qsmp_connection_state*), 
	void (*receive_callback)(qsmp_connection_state*, const char*, size_t), 
	bool (*key_query)(uint8_t* rvkey, const uint8_t* pkid))
{
	assert(prik != NULL);
	assert(send_func != NULL);
	assert(receive_callback != NULL);

	qsc_ipinfo_ipv4_address addt = { 0 };
	listener_receiver_state* prcv;
	qsc_socket srvs;
	qsc_socket_exceptions serr;
	qsmp_errors qerr;

	qsmp_logger_initialize(NULL);
	prcv = NULL;

	if (prik != NULL && send_func != NULL && receive_callback != NULL)
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
					qerr = listener_duplex_start(prik, prcv, send_func, key_query);
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

qsmp_errors qsmp_client_duplex_listen_ipv6(const qsmp_server_key* prik, 
	void (*send_func)(qsmp_connection_state*),
	void (*receive_callback)(qsmp_connection_state*, const char*, size_t),
	bool (*key_query)(uint8_t* rvkey, const uint8_t* pkid))
{
	assert(prik != NULL);
	assert(send_func != NULL);
	assert(receive_callback != NULL);

	qsc_ipinfo_ipv6_address addt = { 0 };
	listener_receiver_state* prcv;
	qsc_socket srvs;
	qsc_socket_exceptions serr;
	qsmp_errors qerr;

	qsmp_logger_initialize(NULL);
	prcv = NULL;

	if (prik != NULL && send_func != NULL && receive_callback != NULL)
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
					qerr = listener_duplex_start(prik, prcv, send_func, key_query);
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

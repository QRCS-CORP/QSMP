#include "qsmpserver.h"
#include "connections.h"
#include "kex.h"
#include "logger.h"
#include "../../QSC/QSC/acp.h"
#include "../../QSC/QSC/async.h"
#include "../../QSC/QSC/encoding.h"
#include "../../QSC/QSC/intutils.h"
#include "../../QSC/QSC/memutils.h"
#include "../../QSC/QSC/sha3.h"
#include "../../QSC/QSC/stringutils.h"
#include "../../QSC/QSC/timestamp.h"

typedef struct server_receiver_state
{
	qsmp_connection_state* pcns;
	const qsmp_server_signature_key* pprik;
	void (*receive_callback)(qsmp_connection_state*, const char*, size_t);
} server_receiver_state;

static bool m_server_pause;
static bool m_server_run;

static void server_state_initialize(qsmp_kex_simplex_server_state* kss, const server_receiver_state* prcv)
{
	qsc_memutils_copy(kss->keyid, prcv->pprik->keyid, QSMP_KEYID_SIZE);
	qsc_memutils_copy(kss->sigkey, prcv->pprik->sigkey, QSMP_ASYMMETRIC_SIGNING_KEY_SIZE);
	qsc_memutils_copy(kss->verkey, prcv->pprik->verkey, QSMP_ASYMMETRIC_VERIFY_KEY_SIZE);
	qsc_memutils_clear(&prcv->pcns->rtcs, QSMP_DUPLEX_SYMMETRIC_KEY_SIZE);
	kss->expiration = prcv->pprik->expiration;
	qsc_rcs_dispose(&prcv->pcns->rxcpr);
	qsc_rcs_dispose(&prcv->pcns->txcpr);
	prcv->pcns->exflag = qsmp_flag_none;
	prcv->pcns->instance = 0;
	prcv->pcns->rxseq = 0;
	prcv->pcns->txseq = 0;
}

static void server_poll_sockets()
{
	size_t clen;
	qsc_mutex mtx;

	clen = qsmp_connections_size();

	for (size_t i = 0; i < clen; ++i)
	{
		const qsmp_connection_state* cns = qsmp_connections_index(i);

		if (cns != NULL && qsmp_connections_active(i) == true)
		{
			mtx = qsc_async_mutex_lock_ex();

			if (qsc_socket_is_connected(&cns->target) == false)
			{
				qsmp_connections_reset(cns->instance);
			}

			qsc_async_mutex_unlock_ex(mtx);
		}
	}
}

static void server_receive_loop(server_receiver_state* prcv)
{
	assert(prcv != NULL);

	qsmp_network_packet pkt = { 0 };
	qsmp_kex_simplex_server_state* pkss;
	uint8_t* rbuf;
	size_t mlen;
	size_t plen;
	size_t slen;
	qsmp_errors qerr;

	pkss = (qsmp_kex_simplex_server_state*)qsc_memutils_malloc(sizeof(qsmp_kex_simplex_server_state));

	if (pkss != NULL)
	{
		server_state_initialize(pkss, prcv);
		qerr = qsmp_kex_simplex_server_key_exchange(pkss, prcv->pcns);
		qsc_memutils_alloc_free(pkss);

		if (qerr == qsmp_error_none)
		{
			while (prcv->pcns->target.connection_status == qsc_socket_state_connected)
			{
				mlen = 0;
				slen = 0;
				rbuf = (uint8_t*)qsc_memutils_malloc(QSMP_HEADER_SIZE);

				if (rbuf != NULL)
				{
					plen = qsc_socket_peek(&prcv->pcns->target, rbuf, QSMP_HEADER_SIZE);

					if (plen == QSMP_HEADER_SIZE)
					{
						qsmp_packet_header_deserialize(rbuf, &pkt);

						if (pkt.msglen > 0 && pkt.msglen <= QSMP_MESSAGE_MAX)
						{
							plen = pkt.msglen + QSMP_HEADER_SIZE + QSC_SOCKET_TERMINATOR_SIZE;
							rbuf = (uint8_t*)qsc_memutils_realloc(rbuf, plen);
						}

						if (rbuf != NULL)
						{
							qsc_memutils_clear(rbuf, plen);
							mlen = qsc_socket_receive(&prcv->pcns->target, rbuf, plen, qsc_socket_receive_flag_none);
						}
						else
						{
							/* close the connection on memory allocation failure */
							qsmp_log_write(qsmp_messages_allocate_fail, (const char*)prcv->pcns->target.address);
							qsmp_connection_close(prcv->pcns, qsmp_messages_allocate_fail, true);
							break;
						}
					}
				}
				else
				{
					/* close the connection on memory allocation failure */
					qsmp_log_write(qsmp_messages_allocate_fail, (const char*)prcv->pcns->target.address);
					qsmp_connection_close(prcv->pcns, qsmp_messages_allocate_fail, true);
					break;
				}

				if (mlen != 0)
				{
					pkt.pmessage = rbuf + QSMP_HEADER_SIZE;

					if (pkt.flag == qsmp_flag_encrypted_message)
					{
						uint8_t* mstr;

						slen = pkt.msglen + QSC_SOCKET_TERMINATOR_SIZE - QSMP_SIMPLEX_MACTAG_SIZE;
						mstr = (uint8_t*)qsc_memutils_malloc(slen);

						if (mstr != NULL)
						{
							qsc_memutils_clear(mstr, slen);

							qerr = qsmp_decrypt_packet(prcv->pcns, mstr, &mlen, &pkt);

							if (qerr == qsmp_error_none)
							{
								prcv->receive_callback(prcv->pcns, (char*)mstr, mlen);
							}
							else
							{
								/* close the connection on authentication failure */
								qsmp_log_write(qsmp_messages_decryption_fail, (const char*)prcv->pcns->target.address);
								qsmp_connection_close(prcv->pcns, qsmp_error_authentication_failure, true);
								break;
							}

							qsc_memutils_alloc_free(mstr);
						}
						else
						{
							/* close the connection on memory allocation failure */
							qsmp_log_write(qsmp_messages_allocate_fail, (const char*)prcv->pcns->target.address);
							qsmp_connection_close(prcv->pcns, qsmp_messages_allocate_fail, true);
							break;
						}
					}
					else if (pkt.flag == qsmp_flag_connection_terminate)
					{
						qsmp_log_write(qsmp_messages_disconnect, (const char*)prcv->pcns->target.address);
						qsmp_connection_close(prcv->pcns, qsmp_error_none, false);
						break;
					}
					else
					{
						/* unknown message type, we fail out of caution but could ignore */
						qsmp_log_write(qsmp_messages_receive_fail, (const char*)prcv->pcns->target.address);
						qsmp_connection_close(prcv->pcns, qsmp_error_connection_failure, true);
						break;
					}
				}
				else
				{
					qsc_socket_exceptions err = qsc_socket_get_last_error();

					if (err != qsc_socket_exception_success)
					{
						qsmp_log_error(qsmp_messages_receive_fail, err, (const char*)prcv->pcns->target.address);

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

				qsc_memutils_alloc_free(rbuf);
			}
		}
		else
		{
			qsmp_log_message(qsmp_messages_kex_fail);
		}

		if (prcv != NULL)
		{
			qsmp_connections_reset(prcv->pcns->instance);
			qsc_memutils_alloc_free(prcv);
			prcv = NULL;
		}
	}
	else
	{
		qsmp_log_message(qsmp_messages_allocate_fail);
	}
}

static qsmp_errors server_start(const qsmp_server_signature_key* kset, 
	const qsc_socket* source, 
	void (*receive_callback)(qsmp_connection_state*, const char*, size_t))
{
	assert(kset != NULL);
	assert(source != NULL);
	assert(receive_callback != NULL);

	qsc_socket_exceptions res;
	qsmp_errors qerr;

	qerr = qsmp_error_none;
	m_server_pause = false;
	m_server_run = true;
	qsmp_logger_initialize(NULL);
	qsmp_connections_initialize(QSMP_CONNECTIONS_INIT, QSMP_CONNECTIONS_MAX);

	do
	{
		qsmp_connection_state* cns = qsmp_connections_next();

		if (cns != NULL)
		{
			res = qsc_socket_accept(source, &cns->target);

			if (res == qsc_socket_exception_success)
			{
				server_receiver_state* rctx = (server_receiver_state*)qsc_memutils_malloc(sizeof(server_receiver_state));

				if (rctx != NULL)
				{
					cns->target.connection_status = qsc_socket_state_connected;
					rctx->pcns = cns;
					rctx->pprik = kset;
					rctx->receive_callback = receive_callback;

					qsmp_log_write(qsmp_messages_connect_success, (const char*)cns->target.address);
					qsc_async_thread_create((void*)&server_receive_loop, rctx);
					server_poll_sockets();
				}
				else
				{
					qsmp_connections_reset(cns->instance);
					qerr = qsmp_error_memory_allocation;
					qsmp_log_message(qsmp_messages_sockalloc_fail);
				}
			}
			else
			{
				qsmp_connections_reset(cns->instance);
				qerr = qsmp_error_accept_fail;
				qsmp_log_message(qsmp_messages_accept_fail);
			}
		}
		else
		{
			qerr = qsmp_error_hosts_exceeded;
			qsmp_log_message(qsmp_messages_queue_empty);
		}

		while (m_server_pause == true)
		{
			qsc_async_thread_sleep(QSMP_SERVER_PAUSE_INTERVAL);
		}
	} 
	while (m_server_run == true);

	return qerr;
}

/* Public Functions */

void qsmp_server_broadcast(const uint8_t* message, size_t msglen)
{
	size_t clen;
	size_t mlen;
	qsc_mutex mtx;
	qsmp_network_packet pkt = { 0 };
	uint8_t msgstr[QSMP_CONNECTION_MTU] = { 0 };

	clen = qsmp_connections_size();

	for (size_t i = 0; i < clen; ++i)
	{
		qsmp_connection_state* cns = qsmp_connections_index(i);

		if (cns != NULL && qsmp_connections_active(i) == true)
		{
			mtx = qsc_async_mutex_lock_ex();

			if (qsc_socket_is_connected(&cns->target) == true)
			{
				qsmp_encrypt_packet(cns, &pkt, message, msglen);
				mlen = qsmp_packet_to_stream(&pkt, msgstr);
				qsc_socket_send(&cns->target, msgstr, mlen, qsc_socket_send_flag_none);
			}

			qsc_async_mutex_unlock_ex(mtx);
		}
	}
}

void qsmp_server_pause()
{
	m_server_pause = true;
}

void qsmp_server_quit()
{
	size_t clen;
	qsc_mutex mtx;

	clen = qsmp_connections_size();

	for (size_t i = 0; i < clen; ++i)
	{
		const qsmp_connection_state* cns = qsmp_connections_index(i);

		if (cns != NULL && qsmp_connections_active(i) == true)
		{
			mtx = qsc_async_mutex_lock_ex();

			if (qsc_socket_is_connected(&cns->target) == true)
			{
				qsc_socket_close_socket(&cns->target);
			}

			qsmp_connections_reset(cns->instance);

			qsc_async_mutex_unlock_ex(mtx);
		}
	}

	qsmp_connections_dispose();
	m_server_run = false;
}

void qsmp_server_resume()
{
	m_server_pause = false;
}

qsmp_errors qsmp_server_start_ipv4(qsc_socket* source, 
	const qsmp_server_signature_key* kset,
	void (*receive_callback)(qsmp_connection_state*, const char*, size_t))
{
	assert(kset != NULL);
	assert(receive_callback != NULL);

	qsc_ipinfo_ipv4_address addt = { 0 };
	qsc_socket_exceptions res;
	qsmp_errors qerr;

	addt = qsc_ipinfo_ipv4_address_any();
	qsc_socket_server_initialize(source);
	res = qsc_socket_create(source, qsc_socket_address_family_ipv4, qsc_socket_transport_stream, qsc_socket_protocol_tcp);

	if (res == qsc_socket_exception_success)
	{
		res = qsc_socket_bind_ipv4(source, &addt, QSMP_SERVER_PORT);

		if (res == qsc_socket_exception_success)
		{
			res = qsc_socket_listen(source, QSC_SOCKET_SERVER_LISTEN_BACKLOG);

			if (res == qsc_socket_exception_success)
			{
				qerr = server_start(kset, source, receive_callback);
			}
			else
			{
				qerr = qsmp_error_listener_fail;
				qsmp_log_message(qsmp_messages_listener_fail);
			}
		}
		else
		{
			qerr = qsmp_error_connection_failure;
			qsmp_log_message(qsmp_messages_bind_fail);
		}
	}
	else
	{
		qerr = qsmp_error_connection_failure;
		qsmp_log_message(qsmp_messages_create_fail);
	}

	return qerr;
}

qsmp_errors qsmp_server_start_ipv6(qsc_socket* source,
	const qsmp_server_signature_key* kset,
	void (*receive_callback)(qsmp_connection_state*, const char*, size_t))
{
	assert(kset != NULL);
	assert(receive_callback != NULL);

	qsc_ipinfo_ipv6_address addt = { 0 };
	qsc_socket_exceptions res;
	qsmp_errors qerr;

	addt = qsc_ipinfo_ipv6_address_any();
	qsc_socket_server_initialize(source);
	res = qsc_socket_create(source, qsc_socket_address_family_ipv6, qsc_socket_transport_stream, qsc_socket_protocol_tcp);

	if (res == qsc_socket_exception_success)
	{
		res = qsc_socket_bind_ipv6(source, &addt, QSMP_SERVER_PORT);

		if (res == qsc_socket_exception_success)
		{
			res = qsc_socket_listen(source, QSC_SOCKET_SERVER_LISTEN_BACKLOG);

			if (res == qsc_socket_exception_success)
			{
				qerr = server_start(kset, source, receive_callback);
			}
			else
			{
				qerr = qsmp_error_listener_fail;
				qsmp_log_message(qsmp_messages_listener_fail);
			}
		}
		else
		{
			qerr = qsmp_error_connection_failure;
			qsmp_log_message(qsmp_messages_bind_fail);
		}
	}
	else
	{
		qerr = qsmp_error_connection_failure;
		qsmp_log_message(qsmp_messages_create_fail);
	}

	return qerr;
}

#include "server.h"
#include "connections.h"
#include "kex.h"
#include "logger.h"
#include "acp.h"
#include "async.h"
#include "csp.h"
#include "encoding.h"
#include "intutils.h"
#include "memutils.h"
#include "sha3.h"
#include "stringutils.h"
#include "timestamp.h"

/** \cond */
typedef struct server_receiver_state
{
	qsms_connection_state* pcns;
	const qsms_server_signature_key* pprik;
	void (*receive_callback)(qsms_connection_state*, const uint8_t*, size_t);
	void (*disconnect_callback)(qsms_connection_state*);
} server_receiver_state;
/** \endcond */

/** \cond */
volatile bool m_server_pause;
volatile bool m_server_run;

static void server_state_initialize(qsms_kex_simplex_server_state* kss, const server_receiver_state* prcv)
{
	qsc_memutils_copy(kss->keyid, prcv->pprik->keyid, QSMS_KEYID_SIZE);
	qsc_memutils_copy(kss->sigkey, prcv->pprik->sigkey, QSMS_ASYMMETRIC_SIGNING_KEY_SIZE);
	qsc_memutils_copy(kss->verkey, prcv->pprik->verkey, QSMS_ASYMMETRIC_VERIFY_KEY_SIZE);
	qsc_memutils_clear(&prcv->pcns->rtcs, QSMS_SIMPLEX_SYMMETRIC_KEY_SIZE);
	kss->expiration = prcv->pprik->expiration;
}

static void server_poll_sockets(void)
{
	size_t clen;
	qsc_mutex mtx;

	clen = qsms_connections_size();

	for (size_t i = 0U; i < clen; ++i)
	{
		const qsms_connection_state* cns = qsms_connections_index(i);

		if (cns != NULL && qsms_connections_active(i) == true)
		{
			mtx = qsc_async_mutex_lock_ex();

			if (qsc_socket_is_connected(&cns->target) == false)
			{
				qsms_connections_reset(cns->cid);
			}

			qsc_async_mutex_unlock_ex(mtx);
		}
	}
}

static void server_receive_loop(void* prcv)
{
	QSMS_ASSERT(prcv != NULL);

	qsms_network_packet pkt = { 0 };
	char cadd[QSC_SOCKET_ADDRESS_MAX_SIZE] = { 0 };
	qsms_kex_simplex_server_state* pkss;
	server_receiver_state* pprcv;
	uint8_t* rbuf;
	size_t mlen;
	size_t plen;
	size_t slen;
	qsms_errors qerr;

	pprcv = (server_receiver_state*)prcv;
	qsc_memutils_copy(cadd, (const char*)pprcv->pcns->target.address, sizeof(cadd));
	pkss = (qsms_kex_simplex_server_state*)qsc_memutils_malloc(sizeof(qsms_kex_simplex_server_state));

	if (pkss != NULL)
	{
		server_state_initialize(pkss, pprcv);
		qerr = qsms_kex_simplex_server_key_exchange(pkss, pprcv->pcns);
		qsc_memutils_secure_erase(pkss, sizeof(qsms_kex_simplex_server_state));
		qsc_memutils_alloc_free(pkss);
		pkss = NULL;

		if (qerr == qsms_error_none)
		{
			rbuf = (uint8_t*)qsc_memutils_malloc(QSMS_HEADER_SIZE);

			if (rbuf != NULL)
			{
				plen = 0U;

				while (pprcv->pcns->target.connection_status == qsc_socket_state_connected)
				{
					mlen = 0U;
					slen = 0U;

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

								if (mlen != 0U)
								{
									pkt.pmessage = rbuf + QSMS_HEADER_SIZE;

									if (pkt.flag == qsms_flag_encrypted_message)
									{
										uint8_t* mstr;

										slen = pkt.msglen + QSMS_SIMPLEX_MACTAG_SIZE;
										mstr = (uint8_t*)qsc_memutils_malloc(slen);

										if (mstr != NULL)
										{
											qsc_memutils_clear(mstr, slen);

											qerr = qsms_packet_decrypt(pprcv->pcns, mstr, &mlen, &pkt);

											if (qerr == qsms_error_none)
											{
												pprcv->receive_callback(pprcv->pcns, mstr, mlen);
											}
											else
											{
												/* close the connection on authentication failure */
												qsms_log_write(qsms_messages_decryption_fail, cadd);
												break;
											}

											qsc_memutils_secure_erase(mstr, slen);
											qsc_memutils_alloc_free(mstr);
										}
										else
										{
											/* close the connection on memory allocation failure */
											qsms_log_write(qsms_messages_allocate_fail, cadd);
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
									else
									{
										/* ignore unknown message type */
										qsms_log_write(qsms_messages_receive_fail, cadd);
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
								/* close the connection on memory allocation failure */
								qsms_log_write(qsms_messages_allocate_fail, cadd);
								break;
							}
						}
						else
						{
							/* close the connection on memory reallocation failure */
							qsms_log_write(qsms_messages_allocate_fail, cadd);
							break;
						}
					}
				}

				qsc_memutils_secure_erase(rbuf, plen);
				qsc_memutils_alloc_free(rbuf);
			}
			else
			{
				/* close the connection on memory allocation failure */
				qsms_log_write(qsms_messages_allocate_fail, cadd);
			}

			if (pprcv->disconnect_callback != NULL)
			{
				pprcv->disconnect_callback(pprcv->pcns);
			}
		}
		else
		{
			qsms_log_message(qsms_messages_kex_fail);
		}

		if (pprcv != NULL)
		{
			qsms_connections_reset(pprcv->pcns->cid);
			qsc_memutils_secure_erase(pprcv, sizeof(server_receiver_state));
			qsc_memutils_alloc_free(pprcv);
			pprcv = NULL;
		}
	}
	else
	{
		qsms_log_message(qsms_messages_allocate_fail);
	}
}

static qsms_errors server_start(const qsms_server_signature_key* kset, 
	const qsc_socket* source, 
	void (*receive_callback)(qsms_connection_state*, const uint8_t*, size_t),
	void (*disconnect_callback)(qsms_connection_state*))
{
	QSMS_ASSERT(kset != NULL);
	QSMS_ASSERT(source != NULL);
	QSMS_ASSERT(receive_callback != NULL);

	qsc_socket_exceptions res;
	qsms_errors qerr;

	qerr = qsms_error_none;
	qsc_async_atomic_bool_store(&m_server_pause, false);
	qsc_async_atomic_bool_store(&m_server_run, true);
	qsms_connections_initialize(QSMS_CONNECTIONS_MAX);

	do
	{
		qsms_connection_state* cns = qsms_connections_next();

		if (cns != NULL)
		{
			res = qsc_socket_accept(source, &cns->target);
			cns->target.instance = qsc_csp_uint32();

			if (res == qsc_socket_exception_success)
			{
				server_receiver_state* prcv = (server_receiver_state*)qsc_memutils_malloc(sizeof(server_receiver_state));

				if (prcv != NULL)
				{
					cns->target.connection_status = qsc_socket_state_connected;
					prcv->pcns = cns;
					prcv->pprik = kset;
					prcv->disconnect_callback = disconnect_callback;
					prcv->receive_callback = receive_callback;

					qsms_log_write(qsms_messages_connect_success, (const char*)cns->target.address);
					/* start the receive loop on a new thread */
					qsc_async_thread_create(&server_receive_loop, prcv);
					server_poll_sockets();
				}
				else
				{
					qsms_connections_reset(cns->cid);
					qerr = qsms_error_memory_allocation;
					qsms_log_message(qsms_messages_sockalloc_fail);
				}
			}
			else
			{
				qsms_connections_reset(cns->cid);
				qerr = qsms_error_accept_fail;
				qsms_log_message(qsms_messages_accept_fail);
			}
		}
		else
		{
			qerr = qsms_error_hosts_exceeded;
			qsms_log_message(qsms_messages_queue_empty);
		}

		while (qsc_async_atomic_bool_load(&m_server_pause) == true)
		{
			qsc_async_thread_sleep(QSMS_SERVER_PAUSE_INTERVAL);
		}
	} 
	while (qsc_async_atomic_bool_load(&m_server_run) == true);

	return qerr;
}
/** \endcond */

/* Public Functions */

void qsms_server_pause(void)
{
	qsc_async_atomic_bool_store(&m_server_pause, true);
}

void qsms_server_quit(void)
{
	size_t clen;
	qsc_mutex mtx;

	clen = qsms_connections_size();

	for (size_t i = 0U; i < clen; ++i)
	{
		qsms_connection_state* cns = qsms_connections_index(i);

		if (cns != NULL && qsms_connections_active(i) == true)
		{
			mtx = qsc_async_mutex_lock_ex();

			if (qsc_socket_is_connected(&cns->target) == true)
			{
				qsc_socket_close_socket(&cns->target);
			}

			qsms_connections_reset(cns->cid);

			qsc_async_mutex_unlock_ex(mtx);
		}
	}

	qsms_connections_dispose();
	qsc_async_atomic_bool_store(&m_server_run, false);
}

void qsms_server_resume(void)
{
	qsc_async_atomic_bool_store(&m_server_pause, false);
}

qsms_errors qsms_server_start_ipv4(qsc_socket* source, 
	const qsms_server_signature_key* kset,
	void (*receive_callback)(qsms_connection_state*, const uint8_t*, size_t),
	void (*disconnect_callback)(qsms_connection_state*))
{
	QSMS_ASSERT(kset != NULL);
	QSMS_ASSERT(receive_callback != NULL);

	qsc_ipinfo_ipv4_address addt = { 0 };
	qsc_socket_exceptions res;
	qsms_errors qerr;

	qsms_logger_initialize(NULL);

	addt = qsc_ipinfo_ipv4_address_any();
	qsc_socket_server_initialize(source);
	res = qsc_socket_create(source, qsc_socket_address_family_ipv4, qsc_socket_transport_stream, qsc_socket_protocol_tcp);

	if (res == qsc_socket_exception_success)
	{
		res = qsc_socket_bind_ipv4(source, &addt, QSMS_SERVER_PORT);

		if (res == qsc_socket_exception_success)
		{
			res = qsc_socket_listen(source, QSC_SOCKET_SERVER_LISTEN_BACKLOG);

			if (res == qsc_socket_exception_success)
			{
				qerr = server_start(kset, source, receive_callback, disconnect_callback);
			}
			else
			{
				qerr = qsms_error_listener_fail;
				qsms_log_message(qsms_messages_listener_fail);
			}
		}
		else
		{
			qerr = qsms_error_connection_failure;
			qsms_log_message(qsms_messages_bind_fail);
		}
	}
	else
	{
		qerr = qsms_error_connection_failure;
		qsms_log_message(qsms_messages_create_fail);
	}

	qsms_logger_dispose();

	return qerr;
}

qsms_errors qsms_server_start_ipv6(qsc_socket* source,
	const qsms_server_signature_key* kset,
	void (*receive_callback)(qsms_connection_state*, const uint8_t*, size_t),
	void (*disconnect_callback)(qsms_connection_state*))
{
	QSMS_ASSERT(kset != NULL);
	QSMS_ASSERT(receive_callback != NULL);

	qsc_ipinfo_ipv6_address addt = { 0 };
	qsc_socket_exceptions res;
	qsms_errors qerr;

	qsms_logger_initialize(NULL);

	addt = qsc_ipinfo_ipv6_address_any();
	qsc_socket_server_initialize(source);
	res = qsc_socket_create(source, qsc_socket_address_family_ipv6, qsc_socket_transport_stream, qsc_socket_protocol_tcp);

	if (res == qsc_socket_exception_success)
	{
		res = qsc_socket_bind_ipv6(source, &addt, QSMS_SERVER_PORT);

		if (res == qsc_socket_exception_success)
		{
			res = qsc_socket_listen(source, QSC_SOCKET_SERVER_LISTEN_BACKLOG);

			if (res == qsc_socket_exception_success)
			{
				qerr = server_start(kset, source, receive_callback, disconnect_callback);
			}
			else
			{
				qerr = qsms_error_listener_fail;
				qsms_log_message(qsms_messages_listener_fail);
			}
		}
		else
		{
			qerr = qsms_error_connection_failure;
			qsms_log_message(qsms_messages_bind_fail);
		}
	}
	else
	{
		qerr = qsms_error_connection_failure;
		qsms_log_message(qsms_messages_create_fail);
	}

	qsms_logger_dispose();

	return qerr;
}

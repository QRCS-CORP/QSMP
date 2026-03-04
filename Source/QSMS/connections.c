#include "connections.h"
#include "async.h"
#include "memutils.h"

/** \cond */
typedef struct qsms_connection_set
{
	qsms_connection_state* conset;
	bool* active;
	size_t count;
} qsms_connection_set;

static qsms_connection_set m_connection_set;
static qsc_mutex m_pool_mutex;
static bool m_state_initialized;
/** \endcond */

bool qsms_connections_active(size_t index)
{
	bool res;

	res = false;

	if (m_state_initialized == true)
	{
		qsc_async_mutex_lock(m_pool_mutex);

		if (index < m_connection_set.count)
		{
			res = m_connection_set.active[index];
		}

		qsc_async_mutex_unlock(m_pool_mutex);
	}

	return res;
}

size_t qsms_connections_available(void)
{
	size_t count;

	count = 0U;

	if (m_state_initialized == true)
	{
		qsc_async_mutex_lock(m_pool_mutex);

		for (size_t i = 0U; i < m_connection_set.count; ++i)
		{
			if (m_connection_set.active[i] == false)
			{
				++count;
			}
		}

		qsc_async_mutex_unlock(m_pool_mutex);
	}

	return count;
}

void qsms_connections_clear(void)
{
	if (m_state_initialized == true)
	{
		qsc_async_mutex_lock(m_pool_mutex);

		qsc_memutils_clear(m_connection_set.conset, sizeof(qsms_connection_state) * m_connection_set.count);

		for (size_t i = 0; i < m_connection_set.count; ++i)
		{
			m_connection_set.active[i] = false;
			m_connection_set.conset[i].cid = (uint32_t)i;
		}

		qsc_async_mutex_unlock(m_pool_mutex);
	}
}

void qsms_connections_dispose(void)
{
	if (m_state_initialized == true)
	{
		if (m_connection_set.conset != NULL)
		{
			qsms_connections_clear();

			if (m_connection_set.conset != NULL)
			{
				qsc_memutils_alloc_free(m_connection_set.conset);
				m_connection_set.conset = NULL;
			}
		}

		if (m_connection_set.active != NULL)
		{
			qsc_memutils_alloc_free(m_connection_set.active);
			m_connection_set.active = NULL;
		}

		m_connection_set.count = 0U;

		if (m_pool_mutex)
		{
			(void)qsc_async_mutex_destroy(m_pool_mutex);
		}

		m_state_initialized = false;
	}
}

bool qsms_connections_full(void)
{
	bool res;

	res = true;

	if (m_state_initialized == true)
	{
		qsc_async_mutex_lock(m_pool_mutex);

		for (size_t i = 0U; i < m_connection_set.count; ++i)
		{
			if (m_connection_set.active[i] == false)
			{
				res = false;
				break;
			}
		}

		qsc_async_mutex_unlock(m_pool_mutex);
	}

	return res;
}

qsms_connection_state* qsms_connections_get(uint32_t cid)
{
	qsms_connection_state* res;

	res = NULL;

	if (m_state_initialized == true)
	{
		qsc_async_mutex_lock(m_pool_mutex);

		for (size_t i = 0U; i < m_connection_set.count; ++i)
		{
			if (m_connection_set.conset[i].cid == cid)
			{
				res = &m_connection_set.conset[i];
			}
		}

		qsc_async_mutex_unlock(m_pool_mutex);
	}

	return res;
}

qsms_connection_state* qsms_connections_index(size_t index)
{
	qsms_connection_state* res;

	res = NULL;

	if (m_state_initialized == true)
	{
		qsc_async_mutex_lock(m_pool_mutex);

		if (index < m_connection_set.count)
		{
			res = &m_connection_set.conset[index];
		}

		qsc_async_mutex_unlock(m_pool_mutex);
	}

	return res;
}

bool qsms_connections_initialize(size_t count)
{
	QSMS_ASSERT(count != 0U);

	bool res;

	res = false;

	if (count != 0U)
	{
		m_pool_mutex = qsc_async_mutex_create();

		m_connection_set.count = count;
		m_connection_set.conset = qsc_memutils_malloc(count * sizeof(qsms_connection_state));

		if (m_connection_set.conset != NULL)
		{
			qsc_memutils_clear(m_connection_set.conset, count * sizeof(qsms_connection_state));
			m_connection_set.active = qsc_memutils_malloc(count * sizeof(bool));

			if (m_connection_set.active != NULL)
			{
				for (size_t i = 0U; i < count; ++i)
				{
					m_connection_set.conset[i].cid = (uint32_t)i;
					m_connection_set.active[i] = false;
				}

				m_state_initialized = true;
				res = true;
			}
		}
	}

	return res;
}

qsms_connection_state* qsms_connections_next(void)
{
	qsms_connection_state* res;

	res = NULL;

	if (m_state_initialized == true)
	{
		qsc_async_mutex_lock(m_pool_mutex);

		for (size_t i = 0U; i < m_connection_set.count; ++i)
		{
			if (m_connection_set.active[i] == false)
			{
				res = &m_connection_set.conset[i];
				m_connection_set.active[i] = true;
				break;
			}
		}

		qsc_async_mutex_unlock(m_pool_mutex);
	}

	return res;
}

void qsms_connections_reset(uint32_t cid)
{
	if (m_state_initialized == true)
	{
		qsc_async_mutex_lock(m_pool_mutex);

		for (size_t i = 0U; i < m_connection_set.count; ++i)
		{
			if (m_connection_set.conset[i].cid == cid)
			{
				qsc_memutils_clear(&m_connection_set.conset[i], sizeof(qsms_connection_state));
				m_connection_set.conset[i].cid = (uint32_t)i;
				m_connection_set.active[i] = false;
				break;
			}
		}

		qsc_async_mutex_unlock(m_pool_mutex);
	}
}

size_t qsms_connections_size(void)
{
	size_t res;

	res = 0U;

	if (m_state_initialized == true)
	{
		qsc_async_mutex_lock(m_pool_mutex);
		res = m_connection_set.count;
		qsc_async_mutex_unlock(m_pool_mutex);
	}

	return res;
}

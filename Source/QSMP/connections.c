#include "connections.h"
#include "memutils.h"

/** \cond */
typedef struct qsmp_connection_set
{
	qsmp_connection_state* conset;
	bool* active;
	size_t maximum;
	size_t length;
} qsmp_connection_set;

static qsmp_connection_set m_connection_set;
/** \endcond */

bool qsmp_connections_active(size_t index)
{
	bool res;

	res = false;

	if (index < m_connection_set.length)
	{
		res = m_connection_set.active[index];
	}

	return res;
}

qsmp_connection_state* qsmp_connections_add(void)
{
	qsmp_connection_state* cns;

	cns = NULL;

	if ((m_connection_set.length + 1U) <= m_connection_set.maximum)
	{
		m_connection_set.conset = qsc_memutils_realloc(m_connection_set.conset, (m_connection_set.length + 1U) * sizeof(qsmp_connection_state));
		m_connection_set.active = qsc_memutils_realloc(m_connection_set.active, (m_connection_set.length + 1U) * sizeof(bool));

		if (m_connection_set.conset != NULL && m_connection_set.active != NULL)
		{
			qsc_memutils_clear(&m_connection_set.conset[m_connection_set.length], sizeof(qsmp_connection_state));
			m_connection_set.conset[m_connection_set.length].cid = (uint32_t)m_connection_set.length;
			m_connection_set.active[m_connection_set.length] = true;
			cns = &m_connection_set.conset[m_connection_set.length];
			++m_connection_set.length;
		}
	}

	return cns;
}

size_t qsmp_connections_available(void)
{
	size_t count;

	count = 0U;

	for (size_t i = 0U; i < m_connection_set.length; ++i)
	{
		if (m_connection_set.active[i] == false)
		{
			++count;
		}
	}
	
	return count;
}

void qsmp_connections_clear(void)
{
	qsc_memutils_clear(m_connection_set.conset, sizeof(qsmp_connection_state) * m_connection_set.length);

	for (size_t i = 0U; i < m_connection_set.length; ++i)
	{
		m_connection_set.active[i] = false;
		m_connection_set.conset[i].cid = (uint32_t)i;
	}
}

void qsmp_connections_dispose(void)
{
	if (m_connection_set.conset != NULL)
	{
		qsmp_connections_clear();

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

	m_connection_set.length = 0U;
	m_connection_set.maximum = 0U;
}

qsmp_connection_state* qsmp_connections_index(size_t index)
{
	qsmp_connection_state* res;

	res = NULL;

	if (index < m_connection_set.length)
	{
		res = &m_connection_set.conset[index];
	}

	return res;
}

bool qsmp_connections_full(void)
{
	bool res;

	res = true;

	for (size_t i = 0U; i < m_connection_set.length; ++i)
	{
		if (m_connection_set.active[i] == false)
		{
			res = false;
			break;
		}
	}

	return res;
}

qsmp_connection_state* qsmp_connections_get(uint32_t cid)
{
	qsmp_connection_state* res;

	res = NULL;

	for (size_t i = 0; i < m_connection_set.length; ++i)
	{
		if (m_connection_set.conset[i].cid == cid)
		{
			res = &m_connection_set.conset[i];
		}
	}

	return res;
}

void qsmp_connections_initialize(size_t count, size_t maximum)
{
	QSMP_ASSERT(count != 0U);
	QSMP_ASSERT(maximum != 0U);
	QSMP_ASSERT(count <= maximum);
	
	if (count != 0U && maximum != 0U && count <= maximum)
	{
		m_connection_set.length = count;
		m_connection_set.maximum = maximum;
		m_connection_set.conset = (qsmp_connection_state*)qsc_memutils_malloc(sizeof(qsmp_connection_state) * m_connection_set.length);
		m_connection_set.active = (bool*)qsc_memutils_malloc(sizeof(bool) * m_connection_set.length);

		if (m_connection_set.conset != NULL && m_connection_set.active != NULL)
		{
			qsc_memutils_clear(m_connection_set.conset, sizeof(qsmp_connection_state) * m_connection_set.length);

			for (size_t i = 0; i < count; ++i)
			{
				m_connection_set.conset[i].cid = (uint32_t)i;
				m_connection_set.active[i] = false;
			}
		}
	}
}

qsmp_connection_state* qsmp_connections_next(void)
{
	qsmp_connection_state* res;

	res = NULL;

	if (qsmp_connections_full() == false)
	{
		for (size_t i = 0U; i < m_connection_set.length; ++i)
		{
			if (m_connection_set.active[i] == false)
			{
				res = &m_connection_set.conset[i];
				m_connection_set.active[i] = true;
				break;
			}
		}
	}
	else
	{
		res = qsmp_connections_add();
	}

	return res;
}

void qsmp_connections_reset(uint32_t cid)
{
	for (size_t i = 0U; i < m_connection_set.length; ++i)
	{
		if (m_connection_set.conset[i].cid == cid)
		{
			qsc_memutils_clear(&m_connection_set.conset[i], sizeof(qsmp_connection_state));
			m_connection_set.conset[i].cid = (uint32_t)i;
			m_connection_set.active[i] = false;
			break;
		}
	}
}

size_t qsmp_connections_size(void)
{
	return m_connection_set.length;
}

#if defined(QSMP_DEBUG_MODE)
void qsmp_connections_self_test(void)
{
	qsmp_connection_state* xn[20U] = { 0 };
	size_t cnt;
	bool full;

	(void)xn;
	(void)full;
	(void)cnt;
	qsmp_connections_initialize(1U, 10U); /* init with 1 */

	for (size_t i = 1U; i < 10U; ++i)
	{
		xn[i] = qsmp_connections_next(); /* init next 9 */
	}

	cnt = qsmp_connections_available(); /* expected 0 */
	full = qsmp_connections_full(); /* expected true */

	qsmp_connections_reset(1U); /* release 5 */
	qsmp_connections_reset(3U);
	qsmp_connections_reset(5U);
	qsmp_connections_reset(7U);
	qsmp_connections_reset(9U);

	full = qsmp_connections_full(); /* expected false */

	xn[11] = qsmp_connections_next(); /* reclaim 5 */
	xn[12] = qsmp_connections_next();
	xn[13] = qsmp_connections_next();
	xn[14] = qsmp_connections_next();
	xn[15] = qsmp_connections_next();

	full = qsmp_connections_full(); /* expected true */

	xn[16] = qsmp_connections_next(); /* should exceed max */

	cnt = qsmp_connections_size(); /* expected 10 */

	qsmp_connections_clear();
	qsmp_connections_dispose();
}
#endif

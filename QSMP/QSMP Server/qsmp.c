#include "qsmp.h"
#include "../QSC/intutils.h"
#include "../QSC/memutils.h"

const char* qsmp_error_to_string(qsmp_errors error)
{
	const char* dsc;

	dsc = NULL;

	if ((uint32_t)error < QSMP_ERROR_STRING_DEPTH)
	{
		dsc = QSMP_ERROR_STRINGS[(size_t)error];
	}

	return dsc;
}

void qsmp_packet_clear(qsmp_packet* packet)
{
	packet->flag = (uint8_t)qsmp_flag_none;
	packet->msglen = 0;
	packet->sequence = 0;
	qsc_memutils_clear(packet->message, sizeof(packet->message));
}

void qsmp_packet_error_message(qsmp_packet* packet, qsmp_errors error)
{
	assert(packet != NULL);

	if (packet != NULL)
	{
		packet->flag = qsmp_flag_error_condition;
		packet->message[0] = (uint8_t)error;
		packet->msglen = 1;
		packet->sequence = QSMP_SEQUENCE_TERMINATOR;
	}
}

void qsmp_packet_header_deserialize(const uint8_t* header, qsmp_packet* packet)
{
	assert(header != NULL);
	assert(packet != NULL);

	if (header != NULL && packet != NULL)
	{
		packet->flag = header[0];
		packet->msglen = qsc_intutils_le8to32(((uint8_t*)header + sizeof(uint8_t)));
		packet->sequence = qsc_intutils_le8to64(((uint8_t*)header + sizeof(uint8_t) + sizeof(uint32_t)));
	}
}

void qsmp_packet_header_serialize(const qsmp_packet* packet, uint8_t* header)
{
	assert(header != NULL);
	assert(packet != NULL);

	if (header != NULL && packet != NULL)
	{
		header[0] = packet->flag;
		qsc_intutils_le32to8(((uint8_t*)header + sizeof(uint8_t)), packet->msglen);
		qsc_intutils_le64to8(((uint8_t*)header + sizeof(uint8_t) + sizeof(uint32_t)), packet->sequence);
	}
}

size_t qsmp_packet_to_stream(const qsmp_packet* packet, uint8_t* pstream)
{
	assert(packet != NULL);
	assert(pstream != NULL);

	size_t res;

	res = 0;

	if (packet != NULL && pstream != NULL)
	{
		pstream[0] = packet->flag;
		qsc_intutils_le32to8(((uint8_t*)pstream + sizeof(uint8_t)), packet->msglen);
		qsc_intutils_le64to8(((uint8_t*)pstream + sizeof(uint8_t) + sizeof(uint32_t)), packet->sequence);

		if (packet->msglen <= QSMP_MESSAGE_MAX)
		{
			qsc_memutils_copy(((uint8_t*)pstream + sizeof(uint8_t) + sizeof(uint32_t) + sizeof(uint64_t)), (uint8_t*)&packet->message, packet->msglen);
			res = QSMP_HEADER_SIZE + packet->msglen;
		}
	}

	return res;
}

void qsmp_stream_to_packet(const uint8_t* pstream, qsmp_packet* packet)
{
	assert(packet != NULL);
	assert(pstream != NULL);

	if (packet != NULL && pstream != NULL)
	{
		packet->flag = pstream[0];
		packet->msglen = qsc_intutils_le8to32(((uint8_t*)pstream + sizeof(uint8_t)));
		packet->sequence = qsc_intutils_le8to64(((uint8_t*)pstream + sizeof(uint8_t) + sizeof(uint32_t)));

		if (packet->msglen <= QSMP_MESSAGE_MAX)
		{
			qsc_memutils_copy((uint8_t*)&packet->message, ((uint8_t*)pstream + sizeof(uint8_t) + sizeof(uint32_t) + sizeof(uint64_t)), packet->msglen);
		}
	}
}
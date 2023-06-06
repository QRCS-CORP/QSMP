#include "keychain.h"
#include "../../QSC/QSC/acp.h"
#include "../../QSC/QSC/intutils.h"
#include "../../QSC/QSC/memutils.h"

bool qsmp_keychain_add(qsmp_asymmetric_keychain* keychain, const uint8_t* pubkey, const uint8_t* prikey)
{
	assert(keychain != NULL);
	assert(prikey != NULL);
	assert(pubkey != NULL);
	bool res;

	res = false;

	if (keychain != NULL)
	{
		if (keychain->count != 0)
		{
			const uint32_t knum = keychain->count + 1;
			keychain->prikeys = (uint8_t*)qsc_memutils_realloc(keychain->prikeys, knum * QSMP_ASYMMETRIC_PRIVATE_KEY_SIZE);
			keychain->pubkeys = (uint8_t*)qsc_memutils_realloc(keychain->pubkeys, knum * QSMP_ASYMMETRIC_PUBLIC_KEY_SIZE);
			keychain->ktags = (uint64_t*)qsc_memutils_realloc(keychain->ktags, knum * sizeof(uint64_t));
		}
		else
		{
			keychain->prikeys = (uint8_t*)qsc_memutils_malloc(QSMP_ASYMMETRIC_PRIVATE_KEY_SIZE);
			keychain->pubkeys = (uint8_t*)qsc_memutils_malloc(QSMP_ASYMMETRIC_PUBLIC_KEY_SIZE);
			keychain->ktags = (uint64_t*)qsc_memutils_malloc(sizeof(uint64_t));
		}

		if (keychain->pubkeys != NULL && keychain->prikeys != NULL && keychain->ktags != NULL)
		{
			qsc_memutils_copy(keychain->prikeys + keychain->count * QSMP_ASYMMETRIC_PRIVATE_KEY_SIZE, prikey, QSMP_ASYMMETRIC_PRIVATE_KEY_SIZE);
			qsc_memutils_copy(keychain->pubkeys + keychain->count * QSMP_ASYMMETRIC_PUBLIC_KEY_SIZE, pubkey, QSMP_ASYMMETRIC_PUBLIC_KEY_SIZE);
			qsc_acp_generate((uint8_t*)keychain->ktags + keychain->count * sizeof(uint64_t), sizeof(uint64_t));
			++keychain->count;
			res = true;
		}
	}

	return res;
}

void qsmp_keychain_dispose(qsmp_asymmetric_keychain* keychain)
{
	assert(keychain != NULL);

	if ((keychain != NULL))
	{
		if (keychain->ktags != NULL)
		{
			qsc_memutils_clear(keychain->ktags, keychain->count * sizeof(uint64_t));
			qsc_memutils_alloc_free(keychain->ktags);
		}

		if (keychain->pubkeys != NULL)
		{
			qsc_memutils_clear(keychain->pubkeys, keychain->count * (uint32_t)QSMP_ASYMMETRIC_PUBLIC_KEY_SIZE);
			qsc_memutils_alloc_free(keychain->pubkeys);
		}

		if (keychain->prikeys != NULL)
		{
			qsc_memutils_clear(keychain->prikeys, keychain->count * (uint32_t)QSMP_ASYMMETRIC_PRIVATE_KEY_SIZE);
			qsc_memutils_alloc_free(keychain->prikeys);
		}

		keychain->count = 0;
	}
}

void qsmp_keychain_deserialize(qsmp_asymmetric_keychain* keychain, const uint8_t* input, size_t inplen)
{
	assert(keychain != NULL);
	assert(input != NULL);

	size_t pos;
	
	if (input != NULL && keychain != NULL)
	{
		keychain->count = qsc_intutils_le8to32(input);

		if (inplen >= QSMP_KEYCHAIN_SIZE)
		{
			pos = sizeof(uint32_t);
			qsc_memutils_copy(keychain->ktags, input + pos, keychain->count * sizeof(uint64_t));
			pos += keychain->count * sizeof(uint64_t);
			qsc_memutils_copy(keychain->pubkeys, input + pos, keychain->count * (uint32_t)QSMP_ASYMMETRIC_PUBLIC_KEY_SIZE);
			pos += (keychain->count * (uint32_t)QSMP_ASYMMETRIC_PUBLIC_KEY_SIZE);
			qsc_memutils_copy(keychain->prikeys, input + pos, keychain->count * (uint32_t)QSMP_ASYMMETRIC_PRIVATE_KEY_SIZE);
		}
	}
}

bool qsmp_keychain_remove(qsmp_asymmetric_keychain* keychain, qsmp_asymmetric_cipher_keypair* keypair, uint64_t tag)
{
	assert(keychain != NULL);
	assert(keypair != NULL);

	size_t idx;
	size_t pos;
	bool res;

	res = false;

	if (keychain != NULL && keypair != NULL)
	{
		for (idx = 0; idx < keychain->count; ++idx)
		{
			if (tag == keychain->ktags[idx])
			{
				break;
			}
		}

		if (idx < keychain->count)
		{
			size_t lpos;
			bool nlast;

			pos = idx * (uint32_t)QSMP_ASYMMETRIC_PUBLIC_KEY_SIZE;
			lpos = (keychain->count - 1) * (uint32_t)QSMP_ASYMMETRIC_PUBLIC_KEY_SIZE;
			nlast = (idx != keychain->count - 1);

			qsc_memutils_copy(keypair->pubkey, keychain->pubkeys + pos, QSMP_ASYMMETRIC_PUBLIC_KEY_SIZE);
			qsc_memutils_clear(keychain->pubkeys + pos, QSMP_ASYMMETRIC_PUBLIC_KEY_SIZE);

			if (nlast == true)
			{
				/* shift the last item into the slot*/
				qsc_memutils_copy(keychain->pubkeys + pos, keychain->pubkeys + lpos, QSMP_ASYMMETRIC_PUBLIC_KEY_SIZE);
			}

			/* resize the public key array */
			qsc_memutils_clear(keychain->pubkeys + lpos, QSMP_ASYMMETRIC_PUBLIC_KEY_SIZE);
			keychain->pubkeys = (uint8_t*)qsc_memutils_realloc(keychain->pubkeys, lpos);

			if (keychain->pubkeys != NULL)
			{
				pos = idx * (uint32_t)QSMP_ASYMMETRIC_PRIVATE_KEY_SIZE;
				lpos = (keychain->count - 1) * (uint32_t)QSMP_ASYMMETRIC_PRIVATE_KEY_SIZE;

				qsc_memutils_copy(keypair->prikey, keychain->prikeys + pos, QSMP_ASYMMETRIC_PRIVATE_KEY_SIZE);
				qsc_memutils_clear(keychain->prikeys + pos, QSMP_ASYMMETRIC_PRIVATE_KEY_SIZE);

				if (nlast == true)
				{
					qsc_memutils_copy(keychain->prikeys + pos, keychain->pubkeys + lpos, QSMP_ASYMMETRIC_PUBLIC_KEY_SIZE);
				}

				qsc_memutils_clear(keychain->prikeys + lpos, QSMP_ASYMMETRIC_PUBLIC_KEY_SIZE);
				keychain->prikeys = (uint8_t*)qsc_memutils_realloc(keychain->prikeys, lpos);

				if (keychain->prikeys != NULL)
				{
					pos = idx * sizeof(uint64_t);
					lpos = (keychain->count - 1) * sizeof(uint64_t);

					if (nlast == true)
					{
						qsc_memutils_copy(keychain->ktags + pos, keychain->ktags + lpos, sizeof(uint64_t));
					}

					qsc_memutils_clear((uint8_t*)keychain->ktags + lpos, sizeof(uint64_t));
					keychain->ktags = (uint64_t*)qsc_memutils_realloc(keychain->ktags, lpos);

					if (keychain->ktags != NULL)
					{
						res = true;
					}
				}
			}
		}
	}

	return res;
}

void qsmp_keychain_serialize(uint8_t* output, size_t otplen, const qsmp_asymmetric_keychain* keychain)
{
	assert(output != NULL);
	assert(keychain != NULL);

	size_t pos;
	
	if (output != NULL && keychain != NULL)
	{
		const size_t datalen = ((((uint32_t)QSMP_ASYMMETRIC_PUBLIC_KEY_SIZE + QSMP_ASYMMETRIC_PRIVATE_KEY_SIZE) * keychain->count) + (2 * QSMP_SIMPLEX_SYMMETRIC_KEY_SIZE) + sizeof(uint32_t));

		if (otplen >= datalen)
		{
			qsc_intutils_le32to8(output, keychain->count);
			pos = sizeof(uint32_t);
			qsc_memutils_copy(output + pos, keychain->ktags, keychain->count * sizeof(uint64_t));
			pos += keychain->count * sizeof(uint64_t);
			qsc_memutils_copy(output + pos, keychain->pubkeys, keychain->count * (uint32_t)QSMP_ASYMMETRIC_PUBLIC_KEY_SIZE);
			pos += (keychain->count * (uint32_t)QSMP_ASYMMETRIC_PUBLIC_KEY_SIZE);
			qsc_memutils_copy(output + pos, keychain->prikeys, keychain->count * (uint32_t)QSMP_ASYMMETRIC_PRIVATE_KEY_SIZE);
		}
	}
}

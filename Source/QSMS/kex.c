#include "kex.h"
#include "acp.h"
#include "encoding.h"
#include "intutils.h"
#include "memutils.h"
#include "rcs.h"
#include "sha3.h"
#include "socketserver.h"
#include "stringutils.h"
#include "timestamp.h"

#define KEX_CONNECT_REQUEST_MESSAGE_SIZE (QSMS_KEYID_SIZE + QSMS_CONFIG_SIZE)
#define KEX_CONNECT_REQUEST_PACKET_SIZE (QSMS_HEADER_SIZE + KEX_CONNECT_REQUEST_MESSAGE_SIZE)
#define KEX_CONNECT_RESPONSE_MESSAGE_SIZE (QSMS_ASYMMETRIC_PUBLIC_KEY_SIZE + QSMS_SIMPLEX_HASH_SIZE + QSMS_ASYMMETRIC_SIGNATURE_SIZE)
#define KEX_CONNECT_RESPONSE_PACKET_SIZE (QSMS_HEADER_SIZE + KEX_CONNECT_RESPONSE_MESSAGE_SIZE)

#define KEX_EXCHANGE_REQUEST_MESSAGE_SIZE (QSMS_ASYMMETRIC_CIPHER_TEXT_SIZE)
#define KEX_EXCHANGE_REQUEST_PACKET_SIZE (QSMS_HEADER_SIZE + KEX_EXCHANGE_REQUEST_MESSAGE_SIZE)
#define KEX_EXCHANGE_RESPONSE_MESSAGE_SIZE (QSMS_SIMPLEX_HASH_SIZE + QSMS_SIMPLEX_MACTAG_SIZE)
#define KEX_EXCHANGE_RESPONSE_PACKET_SIZE (QSMS_HEADER_SIZE + KEX_EXCHANGE_RESPONSE_MESSAGE_SIZE)

static void kex_send_network_error(const qsc_socket* sock, qsms_errors error)
{
	QSMS_ASSERT(sock != NULL);

	if (qsc_socket_is_connected(sock) == true)
	{
		qsms_network_packet resp = { 0 };
		uint8_t spct[QSMS_HEADER_SIZE + QSMS_ERROR_MESSAGE_SIZE] = { 0U };

		resp.pmessage = spct + QSMS_HEADER_SIZE;
		qsms_packet_error_message(&resp, error);
		qsms_packet_header_serialize(&resp, spct);
		qsc_socket_send(sock, spct, sizeof(spct), qsc_socket_send_flag_none);
	}
}

static void kex_simplex_client_reset(qsms_kex_simplex_client_state* kcs)
{
	QSMS_ASSERT(kcs != NULL);

	if (kcs != NULL)
	{
		qsc_memutils_secure_erase(kcs->keyid, QSMS_KEYID_SIZE);
		qsc_memutils_secure_erase(kcs->schash, QSMS_SIMPLEX_HASH_SIZE);
		qsc_memutils_secure_erase(kcs->verkey, QSMS_ASYMMETRIC_VERIFY_KEY_SIZE);
		kcs->expiration = 0U;
	}
}

static bool kex_simplex_server_keyid_verify(const uint8_t* keyid, const uint8_t* message)
{
	bool res;

	res = (qsc_intutils_verify(keyid, message, QSMS_KEYID_SIZE) == 0);

	return res;
}

static void kex_simplex_server_reset(qsms_kex_simplex_server_state* kss)
{
	QSMS_ASSERT(kss != NULL);

	if (kss != NULL)
	{
		qsc_memutils_secure_erase(kss->keyid, QSMS_KEYID_SIZE);
		qsc_memutils_secure_erase(kss->schash, QSMS_SIMPLEX_HASH_SIZE);
		qsc_memutils_secure_erase(kss->prikey, QSMS_ASYMMETRIC_PRIVATE_KEY_SIZE);
		qsc_memutils_secure_erase(kss->pubkey, QSMS_ASYMMETRIC_PUBLIC_KEY_SIZE);
		qsc_memutils_secure_erase(kss->sigkey, QSMS_ASYMMETRIC_SIGNING_KEY_SIZE);
		qsc_memutils_secure_erase(kss->verkey, QSMS_ASYMMETRIC_VERIFY_KEY_SIZE);
		kss->expiration = 0U;
	}
}

/*
Legend:
<-, ->		-Direction operators
:=, !=, ?=	-Equality operators; assignment, not equals, evaluate
C			-The client host, initiates the exchange
S			-The server host, listens for a connection
G			-The asymmetric cipher key generator function
-Esk		-The asymmetric decapsulation function and secret key
Epk			-The asymmetric encapsulation function and public key
Ssk			-Sign data with the secret signature key
Vpk			-Verify a signature the public verification key
cfg			-The protocol configuration string
cond,		-A conditional statement
cprrx		-A receive channels symmetric cipher instance
cprtx		-A transmit channels symmetric cipher instance
cpt			-The symmetric ciphers cipher-text
cpta		-The asymmetric ciphers cipher-text
-Ek			-The symmetric decryption function and key
Ek			-The symmetric encryption function and key
H			-The hash function (SHA3)
k,mk		-A symmetric cipher or MAC key
KDF			-The key expansion function (SHAKE)
kid			-The public keys unique identity array
Mmk			-The MAC function and key (KMAC)
pk,sk		-Asymmetric public and secret keys
pvk			-Public signature verification key
sch			-A hash of the configuration string and and asymmetric verification-keys
sec			-The shared secret derived from asymmetric encapsulation and decapsulation
sph			-The serialized packet header, including the UTC timestamp
spkh		-The signed hash of the asymmetric public encapsulation-key
*/

/*
The client sends a connection request with its configuration string, and asymmetric public signature key identity.
The key identity (kid) is a multi-part 16-byte address and key identification array, 
used to match the intended target to the corresponding key. 
The configuration string defines the cryptographic protocol set being used, these must be identical.
The client stores a hash of the configuration string, the key id, and of the servers signature verification-key, 
which is used as a session cookie during the exchange.
sch := H(cfg || kid || pvk)
The client sends the key identity string, and the configuration string to the server.
C{ kid || cfg }-> S
*/
static qsms_errors kex_simplex_client_connect_request(qsms_kex_simplex_client_state* kcs, qsms_connection_state* cns, qsms_network_packet* packetout)
{
	QSMS_ASSERT(kcs != NULL);
	QSMS_ASSERT(cns != NULL);
	QSMS_ASSERT(packetout != NULL);

	qsc_keccak_state kstate = { 0 };
	qsms_errors qerr;
	uint64_t tm;

	if (kcs != NULL && packetout != NULL)
	{
		tm = qsc_timestamp_datetime_utc();

		if (tm <= kcs->expiration)
		{
			/* copy the key-id and configuration string to the message */
			qsc_memutils_copy(packetout->pmessage, kcs->keyid, QSMS_KEYID_SIZE);
			qsc_memutils_copy(((uint8_t*)packetout->pmessage + QSMS_KEYID_SIZE), QSMS_CONFIG_STRING, QSMS_CONFIG_SIZE);
			/* assemble the connection-request packet */
			qsms_header_create(packetout, qsms_flag_connect_request, cns->txseq, KEX_CONNECT_REQUEST_MESSAGE_SIZE);

			/* store a hash of the configuration string, and the public signature key: pkh = H(cfg || pvk) */
			qsc_memutils_clear(kcs->schash, QSMS_SIMPLEX_HASH_SIZE);

			/* 1) transcript hash: sch = H(conf || kid || pvk) */
			qsc_sha3_initialize(&kstate);
			qsc_sha3_update(&kstate, qsc_keccak_rate_256, (const uint8_t*)QSMS_CONFIG_STRING, QSMS_CONFIG_SIZE);
			qsc_sha3_update(&kstate, qsc_keccak_rate_256, kcs->keyid, QSMS_KEYID_SIZE);
			qsc_sha3_update(&kstate, qsc_keccak_rate_256, kcs->verkey, QSMS_ASYMMETRIC_VERIFY_KEY_SIZE);
			qsc_sha3_finalize(&kstate, qsc_keccak_rate_256, kcs->schash);

			qerr = qsms_error_none;
			cns->exflag = qsms_flag_connect_request;
		}
		else
		{
			cns->exflag = qsms_flag_none;
			qerr = qsms_error_key_expired;
		}
	}
	else
	{
		cns->exflag = qsms_flag_none;
		qerr = qsms_error_invalid_input;
	}

	return qerr;
}

/*
Exchange Request:
The client verifies the packet flag, sequence number, valid-time timestamp, and message size of the connect response packet.
The client verifies the signature of the hash, then generates its own hash of the public key and serialized packet header, 
and compares it with the one contained in the message. 
If the hash matches, the client uses the public-key to encapsulate a shared secret.
cond := Vpk(H(pk)) = (true ?= pk : 0)
cpt, sec := Epk(sec)
The client combines the secret and the session cookie to create the session keys and two unique nonce, 
one key-nonce pair for each channel of the communications stream.
k1, k2, n1, n2 := KDF(sec, sch)
The receive and transmit channel ciphers are initialized.
cprrx(k2,n2)
cprtx(k1,n1)
The client sends the cipher-text to the server.
C{ cpt }-> S
*/
static qsms_errors kex_simplex_client_exchange_request(qsms_kex_simplex_client_state* kcs, qsms_connection_state* cns, const qsms_network_packet* packetin, qsms_network_packet* packetout)
{
	QSMS_ASSERT(kcs != NULL);
	QSMS_ASSERT(cns != NULL);
	QSMS_ASSERT(packetin != NULL);
	QSMS_ASSERT(packetout != NULL);

	uint8_t khash[QSMS_SIMPLEX_HASH_SIZE] = { 0U };
	size_t mlen;
	size_t slen;
	qsms_errors qerr;

	if (kcs != NULL && packetin != NULL && packetout != NULL)
	{
		slen = 0;
		mlen = QSMS_ASYMMETRIC_SIGNATURE_SIZE + QSMS_SIMPLEX_HASH_SIZE;

		/* verify the asymmetric signature */
		if (qsms_signature_verify(khash, &slen, packetin->pmessage, mlen, kcs->verkey) == true)
		{
			qsc_keccak_state kstate = { 0 };
			uint8_t phash[QSMS_SIMPLEX_HASH_SIZE] = { 0U };
			uint8_t shdr[QSMS_HEADER_SIZE] = { 0U };
			uint8_t ssec[QSMS_SECRET_SIZE] = { 0U };
			const uint8_t* pubk = packetin->pmessage + mlen;

			qsms_packet_header_serialize(packetin, shdr);

			/* version 1.2 hash the header and public encapsulation key */
			qsc_sha3_initialize(&kstate);
			qsc_sha3_update(&kstate, qsc_keccak_rate_256, shdr, QSMS_HEADER_SIZE);
			qsc_sha3_update(&kstate, qsc_keccak_rate_256, pubk, QSMS_ASYMMETRIC_PUBLIC_KEY_SIZE);
			qsc_sha3_finalize(&kstate, qsc_keccak_rate_256, phash);

			/* verify the public key hash */
			if (qsc_intutils_verify(phash, khash, QSMS_SIMPLEX_HASH_SIZE) == 0)
			{
				uint8_t prnd[QSC_KECCAK_256_RATE] = { 0U };

				/* 2) transcript hash: sch = H(sch || phash) */
				qsc_sha3_initialize(&kstate);
				qsc_sha3_update(&kstate, qsc_keccak_rate_256, kcs->schash, QSMS_SIMPLEX_HASH_SIZE);
				qsc_sha3_update(&kstate, qsc_keccak_rate_256, phash, QSMS_SIMPLEX_HASH_SIZE);
				qsc_sha3_finalize(&kstate, qsc_keccak_rate_256, kcs->schash);

				/* generate, and encapsulate the secret */

				/* store the cipher-text in the message */
				qsms_cipher_encapsulate(ssec, packetout->pmessage, pubk, qsc_acp_generate);

				/* 3) transcript hash: sch = H(sch || cpt) */
				qsc_sha3_initialize(&kstate);
				qsc_sha3_update(&kstate, qsc_keccak_rate_256, kcs->schash, QSMS_SIMPLEX_HASH_SIZE);
				qsc_sha3_update(&kstate, qsc_keccak_rate_256, packetout->pmessage, QSMS_ASYMMETRIC_CIPHER_TEXT_SIZE);
				qsc_sha3_finalize(&kstate, qsc_keccak_rate_256, kcs->schash);

				/* assemble the exchange-request packet */
				qsms_header_create(packetout, qsms_flag_exchange_request, cns->txseq, KEX_EXCHANGE_REQUEST_MESSAGE_SIZE);

				/* initialize cSHAKE k = H(sec, sch) */
				qsc_cshake_initialize(&kstate, qsc_keccak_rate_256, ssec, QSMS_SECRET_SIZE, kcs->schash, QSMS_SIMPLEX_HASH_SIZE, NULL, 0U);
				qsc_memutils_secure_erase(ssec, sizeof(ssec));
				qsc_cshake_squeezeblocks(&kstate, qsc_keccak_rate_256, prnd, 1U);
				/* permute the state so we are not storing the current key */
				qsc_keccak_permute(&kstate, QSC_KECCAK_PERMUTATION_ROUNDS);

				/* copy as next ratchet seed */
				qsc_memutils_copy(cns->rtcs, (uint8_t*)kstate.state, QSMS_SIMPLEX_SYMMETRIC_KEY_SIZE);
				qsc_memutils_secure_erase(&kstate, sizeof(qsc_keccak_state));

				/* initialize the symmetric cipher, and raise client channel-1 tx */
				qsc_rcs_keyparams kp = { 0 };
				kp.key = prnd;
				kp.keylen = QSMS_SIMPLEX_SYMMETRIC_KEY_SIZE;
				kp.nonce = prnd + QSMS_SIMPLEX_SYMMETRIC_KEY_SIZE;
				kp.info = NULL;
				kp.infolen = 0U;
				qsc_rcs_initialize(&cns->txcpr, &kp, true);

				/* initialize the symmetric cipher, and raise client channel-1 rx */
				kp.key = prnd + QSMS_SIMPLEX_SYMMETRIC_KEY_SIZE + QSMS_NONCE_SIZE;
				kp.keylen = QSMS_SIMPLEX_SYMMETRIC_KEY_SIZE;
				kp.nonce = prnd + QSMS_SIMPLEX_SYMMETRIC_KEY_SIZE + QSMS_NONCE_SIZE + QSMS_SIMPLEX_SYMMETRIC_KEY_SIZE;
				kp.info = NULL;
				kp.infolen = 0U;
				qsc_rcs_initialize(&cns->rxcpr, &kp, false);

				/* erase keying material */
				qsc_memutils_secure_erase(prnd, sizeof(prnd));
				qsc_memutils_secure_erase((uint8_t*)&kp, sizeof(qsc_rcs_keyparams));

				cns->exflag = qsms_flag_exchange_request;
				qerr = qsms_error_none;
			}
			else
			{
				cns->exflag = qsms_flag_none;
				qerr = qsms_error_hash_invalid;
			}

			qsc_memutils_secure_erase(phash, sizeof(phash));
			qsc_memutils_secure_erase(shdr, sizeof(shdr));
		}
		else
		{
			cns->exflag = qsms_flag_none;
			qerr = qsms_error_authentication_failure;
		}
	}
	else
	{
		cns->exflag = qsms_flag_none;
		qerr = qsms_error_invalid_input;
	}

	qsc_memutils_secure_erase(khash, sizeof(khash));

	return qerr;
}

/*
Establish Verify:
The client verifies the packet flag, sequence number, valid-time timestamp, and message size of the establish response packet.
The client checks the flag of the exchange response packet sent by the server. 
If the flag is set to indicate an error state, the tunnel is torn down on both sides,
otherwise the client tunnel is established and in an operational state.
The client sets the operational state to session established, and is now ready to process data.
*/
static qsms_errors kex_simplex_client_establish_verify(const qsms_kex_simplex_client_state* kcs, qsms_connection_state* cns, const qsms_network_packet* packetin)
{
	QSMS_ASSERT(kcs != NULL);
	QSMS_ASSERT(cns != NULL);
	QSMS_ASSERT(packetin != NULL);

	uint8_t csch[QSMS_SIMPLEX_HASH_SIZE] = { 0U };
	uint8_t shdr[QSMS_HEADER_SIZE] = { 0U };
	qsms_errors qerr;

	if (kcs != NULL && packetin != NULL)
	{
		/* 4) transcript hash verify: csch = -Ek(cpt), sch == csch ? 1 : 0 */
		qsms_packet_header_serialize(packetin, shdr);
		qsc_rcs_set_associated(&cns->rxcpr, shdr, sizeof(shdr));

		if (qsc_rcs_transform(&cns->rxcpr, csch, packetin->pmessage, packetin->msglen - QSMS_SIMPLEX_MACTAG_SIZE) == true)
		{
			if (qsc_memutils_are_equal(kcs->schash, csch, QSMS_SIMPLEX_HASH_SIZE) == true)
			{
				cns->exflag = qsms_flag_session_established;
				qerr = qsms_error_none;
			}
			else
			{
				cns->exflag = qsms_flag_none;
				qerr = qsms_error_verify_failure;
			}
		}
		else
		{
			cns->exflag = qsms_flag_none;
			qerr = qsms_error_authentication_failure;
		}
	}
	else
	{
		cns->exflag = qsms_flag_none;
		qerr = qsms_error_invalid_input;
	}

	return qerr;
}

/*
Connect Response:
The server verifies the packet flag, sequence number, valid-time timestamp, and message size of the connect request packet.
The server responds with either an error message, or a response packet. 
Any error during the key exchange will generate an error-packet sent to the remote host, 
which will trigger a tear down of the session and network connection on both sides.
The server first checks that it has the requested asymmetric signature verification key for the host 
using the key-identity array, then verifies that it has a compatible protocol configuration. 
The server stores a hash of the configuration string, key id, and the public signature verification-key, to create the session cookie hash.
sch := H(cfg || kid || pvk)
The server then generates an asymmetric encryption key-pair, stores the private key, hashes the public encapsulation key, 
and then signs the hash of the public encapsulation key and the sewrialized packet header using the asymmetric signature key. 
pk, sk := G(cfg)
pkh := H(pk)
spkh := Ssk(pkh)
The server sends a connect response message containing a signed hash of the public asymmetric encapsulation-key, and a copy of that key.
S{ spkh || pk }-> C
*/
static qsms_errors kex_simplex_server_connect_response(qsms_kex_simplex_server_state* kss, qsms_connection_state* cns, const qsms_network_packet* packetin, qsms_network_packet* packetout)
{
	QSMS_ASSERT(kss != NULL);
	QSMS_ASSERT(cns != NULL);
	QSMS_ASSERT(packetin != NULL);
	QSMS_ASSERT(packetout != NULL);

	char confs[QSMS_CONFIG_SIZE + 1U] = { 0 };
	uint8_t phash[QSMS_SIMPLEX_HASH_SIZE] = { 0U };
	qsc_keccak_state kstate = { 0 };
	qsms_errors qerr;
	uint64_t tm;
	size_t mlen;

	qerr = qsms_error_invalid_input;

	if (cns != NULL && kss != NULL && packetin != NULL && packetout != NULL)
	{
		/* compare the state key-id to the id in the message */
		if (kex_simplex_server_keyid_verify(kss->keyid, packetin->pmessage) == true)
		{
			tm = qsc_timestamp_datetime_utc();

			/* check the keys expiration date */
			if (tm <= kss->expiration)
			{
				/* get a copy of the configuration string */
				qsc_memutils_copy(confs, (packetin->pmessage + QSMS_KEYID_SIZE), QSMS_CONFIG_SIZE);

				/* compare the state configuration string to the message configuration string */
				if (qsc_stringutils_compare_strings(confs, QSMS_CONFIG_STRING, QSMS_CONFIG_SIZE) == true)
				{
					uint8_t shdr[QSMS_HEADER_SIZE] = { 0U };

					qsc_memutils_clear(kss->schash, QSMS_SIMPLEX_HASH_SIZE);

					/* store a hash of the configuration string, and the public signature key: sch = H(cfg || pvk) */
					/* 1) transcript hash: sch = H(conf || kid || pvk) */
					qsc_sha3_initialize(&kstate);
					qsc_sha3_update(&kstate, qsc_keccak_rate_256, (const uint8_t*)QSMS_CONFIG_STRING, QSMS_CONFIG_SIZE);
					qsc_sha3_update(&kstate, qsc_keccak_rate_256, kss->keyid, QSMS_KEYID_SIZE);
					qsc_sha3_update(&kstate, qsc_keccak_rate_256, kss->verkey, QSMS_ASYMMETRIC_VERIFY_KEY_SIZE);
					qsc_sha3_finalize(&kstate, qsc_keccak_rate_256, kss->schash);

					/* initialize the packet and asymmetric encryption keys */
					qsc_memutils_clear(kss->pubkey, QSMS_ASYMMETRIC_PUBLIC_KEY_SIZE);
					qsc_memutils_clear(kss->prikey, QSMS_ASYMMETRIC_PRIVATE_KEY_SIZE);

					/* generate the asymmetric encryption key-pair */
					qsms_cipher_generate_keypair(kss->pubkey, kss->prikey, qsc_acp_generate);

					/* assemble the connection-response packet */
					qsms_header_create(packetout, qsms_flag_connect_response, cns->txseq, KEX_CONNECT_RESPONSE_MESSAGE_SIZE);
					qsms_packet_header_serialize(packetout, shdr);

					/* version 1.2 hash the header and public encapsulation key */
					qsc_sha3_initialize(&kstate);
					qsc_sha3_update(&kstate, qsc_keccak_rate_256, shdr, QSMS_HEADER_SIZE);
					qsc_sha3_update(&kstate, qsc_keccak_rate_256, kss->pubkey, QSMS_ASYMMETRIC_PUBLIC_KEY_SIZE);
					qsc_sha3_finalize(&kstate, qsc_keccak_rate_256, phash);

					/* 2) transcript hash: sch = H(sch || phash) */
					qsc_sha3_initialize(&kstate);
					qsc_sha3_update(&kstate, qsc_keccak_rate_256, kss->schash, QSMS_SIMPLEX_HASH_SIZE);
					qsc_sha3_update(&kstate, qsc_keccak_rate_256, phash, QSMS_SIMPLEX_HASH_SIZE);
					qsc_sha3_finalize(&kstate, qsc_keccak_rate_256, kss->schash);

					/* sign the hash and add it to the message */
					mlen = 0U;
					qsms_signature_sign(packetout->pmessage, &mlen, phash, QSMS_SIMPLEX_HASH_SIZE, kss->sigkey, qsc_acp_generate);

					/* copy the public key to the message */
					qsc_memutils_copy(packetout->pmessage + mlen, kss->pubkey, QSMS_ASYMMETRIC_PUBLIC_KEY_SIZE);

					qerr = qsms_error_none;
					cns->exflag = qsms_flag_connect_response;

					qsc_memutils_secure_erase(shdr, sizeof(shdr));
				}
				else
				{
					qerr = qsms_error_unknown_protocol;
				}
			}
			else
			{
				qerr = qsms_error_key_expired;
			}
		}
		else
		{
			qerr = qsms_error_key_unrecognized;
		}
	}

	qsc_memutils_secure_erase(confs, sizeof(confs));
	qsc_memutils_secure_erase(phash, sizeof(phash));

	return qerr;
}

/*
Exchange Response:
The server verifies the packet flag, sequence number, valid-time timestamp, and message size of the exchange request packet.
The server decapsulates the shared-secret.
sec := -Esk(cpt)
The server combines the shared secret and the session cookie hash to create two session keys, 
and two unique nonce, one key-nonce pair for each channel of the communications stream.
k1, k2, n1, n2 := KDF(sec, sch)
The receive and transmit channel ciphers are initialized.
cprrx(k1, n1)
cprtx(k2, n2)
The server sets the packet flag to exchange response, indicating that the encrypted channels have been raised, 
and sends the notification to the client. The server sets the operational state to session established, 
and is now ready to process data.
S{ f }-> C
*/
static qsms_errors kex_simplex_server_exchange_response(qsms_kex_simplex_server_state* kss, qsms_connection_state* cns, const qsms_network_packet* packetin, qsms_network_packet* packetout)
{
	QSMS_ASSERT(kss != NULL);
	QSMS_ASSERT(cns != NULL);
	QSMS_ASSERT(packetin != NULL);
	QSMS_ASSERT(packetout != NULL);

	qsms_errors qerr;

	if (kss != NULL && packetin != NULL && packetout != NULL)
	{
		uint8_t ssec[QSMS_SECRET_SIZE] = { 0U };

		/* decapsulate the shared secret */
		if (qsms_cipher_decapsulate(ssec, packetin->pmessage, kss->prikey) == true)
		{
			qsc_keccak_state kstate = { 0 };
			uint8_t prnd[QSC_KECCAK_256_RATE] = { 0U };
			uint8_t shdr[QSMS_HEADER_SIZE] = { 0U };

			/* 3) transcript hash: sch = H(sch || cpt) */
			qsc_sha3_initialize(&kstate);
			qsc_sha3_update(&kstate, qsc_keccak_rate_256, kss->schash, QSMS_SIMPLEX_HASH_SIZE);
			qsc_sha3_update(&kstate, qsc_keccak_rate_256, packetin->pmessage, QSMS_ASYMMETRIC_CIPHER_TEXT_SIZE);
			qsc_sha3_finalize(&kstate, qsc_keccak_rate_256, kss->schash);

			/* initialize cSHAKE k = H(ssec, sch) */
			qsc_cshake_initialize(&kstate, qsc_keccak_rate_256, ssec, sizeof(ssec), kss->schash, QSMS_SIMPLEX_HASH_SIZE, NULL, 0U);
			qsc_memutils_secure_erase(ssec, sizeof(ssec));
			qsc_cshake_squeezeblocks(&kstate, qsc_keccak_rate_256, prnd, 1U);
			/* permute the state so we are not storing the current key */
			qsc_keccak_permute(&kstate, QSC_KECCAK_PERMUTATION_ROUNDS);
			/* copy as next key */
			qsc_memutils_copy(cns->rtcs, (uint8_t*)kstate.state, QSMS_SIMPLEX_SYMMETRIC_KEY_SIZE);
			qsc_memutils_secure_erase(&kstate, sizeof(qsc_keccak_state));

			/* initialize the symmetric cipher, and raise client channel-1 tx */
			qsc_rcs_keyparams kp = { 0 };
			kp.key = prnd;
			kp.keylen = QSMS_SIMPLEX_SYMMETRIC_KEY_SIZE;
			kp.nonce = prnd + QSMS_SIMPLEX_SYMMETRIC_KEY_SIZE;
			kp.info = NULL;
			kp.infolen = 0U;
			qsc_rcs_initialize(&cns->rxcpr, &kp, false);

			/* initialize the symmetric cipher, and raise client channel-1 rx */
			kp.key = prnd + QSMS_SIMPLEX_SYMMETRIC_KEY_SIZE + QSMS_NONCE_SIZE;
			kp.keylen = QSMS_SIMPLEX_SYMMETRIC_KEY_SIZE;
			kp.nonce = prnd + QSMS_SIMPLEX_SYMMETRIC_KEY_SIZE + QSMS_NONCE_SIZE + QSMS_SIMPLEX_SYMMETRIC_KEY_SIZE;
			kp.info = NULL;
			kp.infolen = 0U;
			qsc_rcs_initialize(&cns->txcpr, &kp, true);

			qsc_memutils_secure_erase(prnd, sizeof(prnd));
			qsc_memutils_secure_erase((uint8_t*)&kp, sizeof(qsc_rcs_keyparams));

			/* assemble the exchange-response packet */
			qsms_header_create(packetout, qsms_flag_exchange_response, cns->txseq, KEX_EXCHANGE_RESPONSE_MESSAGE_SIZE);

			/* 4) transcript hash transmit: cpt = Ek(sch) */
			qsms_packet_header_serialize(packetout, shdr);
			qsc_rcs_set_associated(&cns->txcpr, shdr, sizeof(shdr));
			(void)qsc_rcs_transform(&cns->txcpr, packetout->pmessage, kss->schash, QSMS_SIMPLEX_HASH_SIZE);

			qerr = qsms_error_none;
			cns->exflag = qsms_flag_session_established;
		}
		else
		{
			qerr = qsms_error_decapsulation_failure;
			cns->exflag = qsms_flag_none;
		}
	}
	else
	{
		cns->exflag = qsms_flag_none;
		qerr = qsms_error_invalid_input;
	}

	return qerr;
}

qsms_errors qsms_kex_simplex_client_key_exchange(qsms_kex_simplex_client_state* kcs, qsms_connection_state* cns)
{
	QSMS_ASSERT(kcs != NULL);
	QSMS_ASSERT(cns != NULL);

	qsms_network_packet reqt = { 0 };
	qsms_network_packet resp = { 0 };
	uint8_t* brqt;
	uint8_t* brsp;
	const size_t lrqt = KEX_EXCHANGE_REQUEST_PACKET_SIZE;
	const size_t lrsp = KEX_CONNECT_RESPONSE_PACKET_SIZE;
	size_t rlen;
	size_t slen;
	qsms_errors qerr;

	qerr = qsms_error_invalid_input;

	if (kcs != NULL && cns != NULL)
	{
		brqt = qsc_memutils_malloc(lrqt);

		if (brqt != NULL)
		{
			/* create the connection request packet */
			qsc_memutils_clear(brqt, lrqt);
			reqt.pmessage = brqt + QSMS_HEADER_SIZE;

			qerr = kex_simplex_client_connect_request(kcs, cns, &reqt);
			qsms_packet_header_serialize(&reqt, brqt);

			if (qerr == qsms_error_none)
			{
				/* send the connection request */
				slen = qsc_socket_send(&cns->target, brqt, KEX_CONNECT_REQUEST_PACKET_SIZE, qsc_socket_send_flag_none);

				if (slen == KEX_CONNECT_REQUEST_PACKET_SIZE)
				{
					cns->txseq += 1U;
					brsp = qsc_memutils_malloc(lrsp);

					if (brsp != NULL)
					{
						qsc_memutils_clear(brsp, lrsp);
						resp.pmessage = brsp + QSMS_HEADER_SIZE;

						/* blocking receive waits for server */
						rlen = qsc_socket_receive(&cns->target, brsp, KEX_CONNECT_RESPONSE_PACKET_SIZE, qsc_socket_receive_flag_wait_all);

						if (rlen == KEX_CONNECT_RESPONSE_PACKET_SIZE)
						{
							qsms_packet_header_deserialize(brsp, &resp);
							qerr = qsms_header_validate(cns, &resp, qsms_flag_connect_request, qsms_flag_connect_response, cns->rxseq, KEX_CONNECT_RESPONSE_MESSAGE_SIZE);

							if (qerr == qsms_error_none)
							{
								qsc_memutils_clear(brqt, lrqt);

								/* create the exstart request packet */
								qerr = kex_simplex_client_exchange_request(kcs, cns, &resp, &reqt);
								qsms_packet_header_serialize(&reqt, brqt);
									
								if (qerr == qsms_error_none)
								{
									slen = qsc_socket_send(&cns->target, brqt, KEX_EXCHANGE_REQUEST_PACKET_SIZE, qsc_socket_send_flag_none);

									if (slen == KEX_EXCHANGE_REQUEST_PACKET_SIZE)
									{
										cns->txseq += 1U;
										qsc_memutils_clear(brsp, lrsp);
										resp.pmessage = brsp + QSMS_HEADER_SIZE;

										rlen = qsc_socket_receive(&cns->target, brsp, KEX_EXCHANGE_RESPONSE_PACKET_SIZE, qsc_socket_receive_flag_wait_all);

										if (rlen == KEX_EXCHANGE_RESPONSE_PACKET_SIZE)
										{
											qsms_packet_header_deserialize(brsp, &resp);
											qerr = qsms_header_validate(cns, &resp, qsms_flag_exchange_request, qsms_flag_exchange_response, cns->rxseq, KEX_EXCHANGE_RESPONSE_MESSAGE_SIZE);

											if (qerr == qsms_error_none)
											{
												/* verify the exchange  */
												qerr = kex_simplex_client_establish_verify(kcs, cns, &resp);
											}
											else
											{
												qerr = qsms_error_packet_unsequenced;
											}
										}
										else
										{
											qerr = qsms_error_receive_failure;
										}
									}
									else
									{
										qerr = qsms_error_transmit_failure;
									}
								}
							}
							else
							{
								qerr = qsms_error_packet_unsequenced;
							}
						}
						else
						{
							qerr = qsms_error_receive_failure;
						}

						qsc_memutils_secure_erase(brsp, lrsp);
						qsc_memutils_alloc_free(brsp);
					}
					else
					{
						qerr = qsms_error_memory_allocation;
					}
				}
				else
				{
					qerr = qsms_error_transmit_failure;
				}
			}

			qsc_memutils_secure_erase(brqt, lrqt);
			qsc_memutils_alloc_free(brqt);
		}
		else
		{
			qerr = qsms_error_memory_allocation;
		}

		kex_simplex_client_reset(kcs);

		if (qerr != qsms_error_none)
		{
			if (cns->target.connection_status == qsc_socket_state_connected)
			{
				kex_send_network_error(&cns->target, qerr);
				qsc_socket_shut_down(&cns->target, qsc_socket_shut_down_flag_both);
			}

			qsms_connection_state_dispose(cns);
		}
	}

	return qerr;
}

qsms_errors qsms_kex_simplex_server_key_exchange(qsms_kex_simplex_server_state* kss, qsms_connection_state* cns)
{
	QSMS_ASSERT(kss != NULL);
	QSMS_ASSERT(cns != NULL);

	qsms_network_packet reqt = { 0 };
	qsms_network_packet resp = { 0 };
	uint8_t* brqt;
	uint8_t* brsp;
	const size_t lrqt = KEX_EXCHANGE_REQUEST_PACKET_SIZE;
	const size_t lrsp = KEX_CONNECT_RESPONSE_PACKET_SIZE;
	size_t rlen;
	size_t slen;
	qsms_errors qerr;

	qerr = qsms_error_invalid_input;

	if (kss != NULL && cns != NULL)
	{
		brqt = qsc_memutils_malloc(lrqt);

		if (brqt != NULL)
		{
			qsc_memutils_clear(brqt, lrqt);
			reqt.pmessage = brqt + QSMS_HEADER_SIZE;

			/* blocking receive waits for client */
			rlen = qsc_socket_receive(&cns->target, brqt, KEX_CONNECT_REQUEST_PACKET_SIZE, qsc_socket_receive_flag_wait_all);

			if (rlen == KEX_CONNECT_REQUEST_PACKET_SIZE)
			{
				/* convert client request to packet */
				qsms_packet_header_deserialize(brqt, &reqt);
				qerr = qsms_header_validate(cns, &reqt, qsms_flag_none, qsms_flag_connect_request, cns->rxseq, KEX_CONNECT_REQUEST_MESSAGE_SIZE);

				if (qerr == qsms_error_none)
				{
					brsp = qsc_memutils_malloc(KEX_CONNECT_RESPONSE_PACKET_SIZE);

					if (brsp != NULL)
					{
						qsc_memutils_clear(brsp, lrsp);
						resp.pmessage = brsp + QSMS_HEADER_SIZE;

						/* create the connection response packet */
						qerr = kex_simplex_server_connect_response(kss, cns, &reqt, &resp);

						if (qerr == qsms_error_none)
						{
							qsms_packet_header_serialize(&resp, brsp);
							slen = qsc_socket_send(&cns->target, brsp, KEX_CONNECT_RESPONSE_PACKET_SIZE, qsc_socket_send_flag_none);

							if (slen == KEX_CONNECT_RESPONSE_PACKET_SIZE)
							{
								cns->txseq += 1U;
								qsc_memutils_clear(brqt, lrqt);

								/* wait for the exchange request */
								rlen = qsc_socket_receive(&cns->target, brqt, KEX_EXCHANGE_REQUEST_PACKET_SIZE, qsc_socket_receive_flag_wait_all);

								if (rlen == KEX_EXCHANGE_REQUEST_PACKET_SIZE)
								{
									qsms_packet_header_deserialize(brqt, &reqt);
									qerr = qsms_header_validate(cns, &reqt, qsms_flag_connect_response, qsms_flag_exchange_request, cns->rxseq, KEX_EXCHANGE_REQUEST_MESSAGE_SIZE);

									if (qerr == qsms_error_none)
									{
										qsc_memutils_clear(brsp, lrsp);

										/* create the exchange response packet */
										qerr = kex_simplex_server_exchange_response(kss, cns, &reqt, &resp);

										if (qerr == qsms_error_none)
										{
											qsms_packet_header_serialize(&resp, brsp);
											/* send the exchange response */
											slen = qsc_socket_send(&cns->target, brsp, KEX_EXCHANGE_RESPONSE_PACKET_SIZE, qsc_socket_send_flag_none);

											if (slen == KEX_EXCHANGE_RESPONSE_PACKET_SIZE)
											{
												cns->txseq += 1U;
											}
											else
											{
												qerr = qsms_error_transmit_failure;
											}
										}
									}
								}
								else
								{
									qerr = qsms_error_receive_failure;
								}
							}
							else
							{
								qerr = qsms_error_transmit_failure;
							}
						}

						qsc_memutils_secure_erase(brsp, lrsp);
						qsc_memutils_alloc_free(brsp);
					}
					else
					{
						qerr = qsms_error_memory_allocation;
					}
				}
				else
				{
					qerr = qsms_error_packet_unsequenced;
				}
			}
			else
			{
				qerr = qsms_error_receive_failure;
			}

			qsc_memutils_secure_erase(brqt, lrqt);
			qsc_memutils_alloc_free(brqt);
		}
		else
		{
			qerr = qsms_error_memory_allocation;
		}

		kex_simplex_server_reset(kss);

		if (qerr != qsms_error_none)
		{
			if (cns->target.connection_status == qsc_socket_state_connected)
			{
				kex_send_network_error(&cns->target, qerr);
				qsc_socket_shut_down(&cns->target, qsc_socket_shut_down_flag_both);
			}

			qsms_connection_state_dispose(cns);
		}
	}

	return qerr;
}

#if defined(QSMS_KEX_TEST_ENABLED)
bool qsms_kex_test(void)
{
	qsms_kex_simplex_client_state skcs = { 0 };
	qsms_kex_simplex_server_state skss = { 0 };
	qsms_connection_state cnc = { 0 };
	qsms_connection_state cns = { 0 };
	qsms_network_packet pckclt = { 0 };
	qsms_network_packet pcksrv = { 0 };
	uint8_t mclt[QSMS_HEADER_SIZE + QSMS_ASYMMETRIC_CIPHER_TEXT_SIZE + QSMS_ASYMMETRIC_PUBLIC_KEY_SIZE + QSMS_SIMPLEX_HASH_SIZE + QSMS_ASYMMETRIC_SIGNATURE_SIZE] = { 0U };
	uint8_t msrv[QSMS_HEADER_SIZE + QSMS_ASYMMETRIC_CIPHER_TEXT_SIZE + QSMS_ASYMMETRIC_PUBLIC_KEY_SIZE + QSMS_SIMPLEX_HASH_SIZE + QSMS_ASYMMETRIC_SIGNATURE_SIZE] = { 0U };
	qsms_errors qerr;
	bool res;

	res = false;
	pckclt.pmessage = mclt;
	pcksrv.pmessage = msrv;

	qsms_signature_generate_keypair(skss.verkey, skss.sigkey, qsc_acp_generate);
	qsc_memutils_copy(skcs.verkey, skss.verkey, QSMS_ASYMMETRIC_VERIFY_KEY_SIZE);

	skcs.expiration = qsc_timestamp_datetime_utc() + QSMS_PUBKEY_DURATION_SECONDS;
	skss.expiration = skcs.expiration;

	qerr = kex_simplex_client_connect_request(&skcs, &cnc, &pckclt);

	if (qerr == qsms_error_none)
	{
		qerr = kex_simplex_server_connect_response(&skss, &cns, &pckclt, &pcksrv);

		if (qerr == qsms_error_none)
		{
			qerr = kex_simplex_client_exchange_request(&skcs, &cnc, &pcksrv, &pckclt);

			if (qerr == qsms_error_none)
			{
				qerr = kex_simplex_server_exchange_response(&skss, &cns, &pckclt, &pcksrv);

				if (qerr == qsms_error_none)
				{
					qerr = kex_simplex_client_establish_verify(&skcs, &cnc, &pcksrv);

					if (qerr == qsms_error_none)
					{
						res = true;
					}
				}
			}
		}
	}

	return res;
}
#endif

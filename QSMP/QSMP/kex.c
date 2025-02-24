#include "kex.h"
#include "../../QSC/QSC/acp.h"
#include "../../QSC/QSC/encoding.h"
#include "../../QSC/QSC/intutils.h"
#include "../../QSC/QSC/memutils.h"
#include "../../QSC/QSC/rcs.h"
#include "../../QSC/QSC/sha3.h"
#include "../../QSC/QSC/socketserver.h"
#include "../../QSC/QSC/stringutils.h"
#include "../../QSC/QSC/timestamp.h"

#define KEX_SIMPLEX_CONNECT_REQUEST_MESSAGE_SIZE (QSMP_KEYID_SIZE + QSMP_CONFIG_SIZE)
#define KEX_SIMPLEX_CONNECT_REQUEST_PACKET_SIZE (QSMP_HEADER_SIZE + KEX_SIMPLEX_CONNECT_REQUEST_MESSAGE_SIZE)
#define KEX_SIMPLEX_CONNECT_RESPONSE_MESSAGE_SIZE (QSMP_ASYMMETRIC_PUBLIC_KEY_SIZE + QSMP_SIMPLEX_HASH_SIZE + QSMP_ASYMMETRIC_SIGNATURE_SIZE)
#define KEX_SIMPLEX_CONNECT_RESPONSE_PACKET_SIZE (QSMP_HEADER_SIZE + KEX_SIMPLEX_CONNECT_RESPONSE_MESSAGE_SIZE)

#define KEX_SIMPLEX_EXCHANGE_REQUEST_MESSAGE_SIZE (QSMP_ASYMMETRIC_CIPHER_TEXT_SIZE)
#define KEX_SIMPLEX_EXCHANGE_REQUEST_PACKET_SIZE (QSMP_HEADER_SIZE + KEX_SIMPLEX_EXCHANGE_REQUEST_MESSAGE_SIZE)
#define KEX_SIMPLEX_EXCHANGE_RESPONSE_MESSAGE_SIZE (0)
#define KEX_SIMPLEX_EXCHANGE_RESPONSE_PACKET_SIZE (QSMP_HEADER_SIZE + KEX_SIMPLEX_EXCHANGE_RESPONSE_MESSAGE_SIZE)

#define KEX_DUPLEX_CONNECT_REQUEST_MESSAGE_SIZE (QSMP_KEYID_SIZE + QSMP_CONFIG_SIZE + QSMP_DUPLEX_HASH_SIZE + QSMP_ASYMMETRIC_SIGNATURE_SIZE)
#define KEX_DUPLEX_CONNECT_REQUEST_PACKET_SIZE (QSMP_HEADER_SIZE + KEX_DUPLEX_CONNECT_REQUEST_MESSAGE_SIZE)
#define KEX_DUPLEX_CONNECT_RESPONSE_MESSAGE_SIZE (QSMP_ASYMMETRIC_PUBLIC_KEY_SIZE + QSMP_DUPLEX_HASH_SIZE + QSMP_ASYMMETRIC_SIGNATURE_SIZE)
#define KEX_DUPLEX_CONNECT_RESPONSE_PACKET_SIZE (QSMP_HEADER_SIZE + KEX_DUPLEX_CONNECT_RESPONSE_MESSAGE_SIZE)

#define KEX_DUPLEX_EXCHANGE_REQUEST_MESSAGE_SIZE (QSMP_ASYMMETRIC_CIPHER_TEXT_SIZE + QSMP_ASYMMETRIC_PUBLIC_KEY_SIZE + QSMP_DUPLEX_HASH_SIZE + QSMP_ASYMMETRIC_SIGNATURE_SIZE)
#define KEX_DUPLEX_EXCHANGE_REQUEST_PACKET_SIZE (QSMP_HEADER_SIZE + KEX_DUPLEX_EXCHANGE_REQUEST_MESSAGE_SIZE)
#define KEX_DUPLEX_EXCHANGE_RESPONSE_MESSAGE_SIZE (QSMP_ASYMMETRIC_CIPHER_TEXT_SIZE + QSMP_DUPLEX_HASH_SIZE + QSMP_ASYMMETRIC_SIGNATURE_SIZE)
#define KEX_DUPLEX_EXCHANGE_RESPONSE_PACKET_SIZE (QSMP_HEADER_SIZE + KEX_DUPLEX_EXCHANGE_RESPONSE_MESSAGE_SIZE)

#define KEX_DUPLEX_ESTABLISH_REQUEST_MESSAGE_SIZE (QSMP_DUPLEX_SCHASH_SIZE + QSMP_DUPLEX_MACTAG_SIZE)
#define KEX_DUPLEX_ESTABLISH_REQUEST_PACKET_SIZE (QSMP_HEADER_SIZE + KEX_DUPLEX_ESTABLISH_REQUEST_MESSAGE_SIZE)
#define KEX_DUPLEX_ESTABLISH_RESPONSE_MESSAGE_SIZE (QSMP_DUPLEX_SCHASH_SIZE + QSMP_DUPLEX_MACTAG_SIZE)
#define KEX_DUPLEX_ESTABLISH_RESPONSE_PACKET_SIZE (QSMP_HEADER_SIZE + KEX_DUPLEX_ESTABLISH_RESPONSE_MESSAGE_SIZE)

static void kex_subheader_serialize(uint8_t* pstream, const qsmp_network_packet* packetin)
{
	qsc_intutils_le64to8(pstream, packetin->sequence);
	qsc_intutils_le64to8(pstream + sizeof(uint64_t), packetin->utctime);
}

static void kex_send_network_error(const qsc_socket* sock, qsmp_errors error)
{
	assert(sock != NULL);

	if (qsc_socket_is_connected(sock) == true)
	{
		qsmp_network_packet resp = { 0 };
		uint8_t spct[QSMP_HEADER_SIZE + QSMP_ERROR_MESSAGE_SIZE] = { 0 };

		resp.pmessage = spct + QSMP_HEADER_SIZE;
		qsmp_packet_error_message(&resp, error);
		qsmp_packet_header_serialize(&resp, spct);
		qsc_socket_send(sock, spct, sizeof(spct), qsc_socket_send_flag_none);
	}
}

static void kex_duplex_client_reset(qsmp_kex_duplex_client_state* kcs)
{
	assert(kcs != NULL);

	if (kcs != NULL)
	{
		qsc_memutils_clear(kcs->keyid, QSMP_KEYID_SIZE);
		qsc_memutils_clear(kcs->schash, QSMP_DUPLEX_SCHASH_SIZE);
		qsc_memutils_clear(kcs->prikey, QSMP_ASYMMETRIC_PRIVATE_KEY_SIZE);
		qsc_memutils_clear(kcs->pubkey, QSMP_ASYMMETRIC_PUBLIC_KEY_SIZE);
		qsc_memutils_clear(kcs->verkey, QSMP_ASYMMETRIC_VERIFY_KEY_SIZE);
		qsc_memutils_clear(kcs->sigkey, QSMP_ASYMMETRIC_SIGNING_KEY_SIZE);
		qsc_memutils_clear(kcs->ssec, QSMP_SECRET_SIZE);
#if !defined(QSMP_ASYMMETRIC_RATCHET)
		qsc_memutils_clear(kcs->rverkey, QSMP_ASYMMETRIC_VERIFY_KEY_SIZE);
#endif
		kcs->expiration = 0;
	}
}

static void kex_duplex_server_reset(qsmp_kex_duplex_server_state* kss)
{
	assert(kss != NULL);

	if (kss != NULL)
	{
		qsc_memutils_clear(kss->keyid, QSMP_KEYID_SIZE);
		qsc_memutils_clear(kss->schash, QSMP_DUPLEX_SCHASH_SIZE);
		qsc_memutils_clear(kss->prikey, QSMP_ASYMMETRIC_PRIVATE_KEY_SIZE);
		qsc_memutils_clear(kss->pubkey, QSMP_ASYMMETRIC_PUBLIC_KEY_SIZE);
		qsc_memutils_clear(kss->sigkey, QSMP_ASYMMETRIC_SIGNING_KEY_SIZE);
#if !defined(QSMP_ASYMMETRIC_RATCHET)
		qsc_memutils_clear(kss->rverkey, QSMP_ASYMMETRIC_VERIFY_KEY_SIZE);
#endif
		qsc_memutils_clear(kss->verkey, QSMP_ASYMMETRIC_VERIFY_KEY_SIZE);
		kss->expiration = 0;
	}
}

static void kex_simplex_client_reset(qsmp_kex_simplex_client_state* kcs)
{
	assert(kcs != NULL);

	if (kcs != NULL)
	{
		qsc_memutils_clear(kcs->keyid, QSMP_KEYID_SIZE);
		qsc_memutils_clear(kcs->schash, QSMP_SIMPLEX_SCHASH_SIZE);
		qsc_memutils_clear(kcs->verkey, QSMP_ASYMMETRIC_VERIFY_KEY_SIZE);
		kcs->expiration = 0;
	}
}

static bool kex_simplex_server_keyid_verify(const uint8_t* keyid, const uint8_t* message)
{
	bool res;

	res = (qsc_intutils_verify(keyid, message, QSMP_KEYID_SIZE) == 0);

	return res;
}

static void kex_simplex_server_reset(qsmp_kex_simplex_server_state* kss)
{
	assert(kss != NULL);

	if (kss != NULL)
	{
		qsc_memutils_clear(kss->keyid, QSMP_KEYID_SIZE);
		qsc_memutils_clear(kss->schash, QSMP_SIMPLEX_SCHASH_SIZE);
		qsc_memutils_clear(kss->prikey, QSMP_ASYMMETRIC_PRIVATE_KEY_SIZE);
		qsc_memutils_clear(kss->pubkey, QSMP_ASYMMETRIC_PUBLIC_KEY_SIZE);
		qsc_memutils_clear(kss->sigkey, QSMP_ASYMMETRIC_SIGNING_KEY_SIZE);
		qsc_memutils_clear(kss->verkey, QSMP_ASYMMETRIC_VERIFY_KEY_SIZE);
		kss->expiration = 0;
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
Connect Request:
The client stores a hash of the configuration string, and both of the public asymmetric signature verification-keys,
which is used as a session cookie during the exchange.
sch := H(cfg || pvka || pvkb)
The client hashes the key identity string, the configuration string, and the serialized packet header, and signs the hash.
sm := Ssk(H(kid || cfg || sph))
The client sends the kid, the config, and the signed hash to the server.
C{ kid || cfg || sm }->S
*/
static qsmp_errors kex_duplex_client_connect_request(qsmp_kex_duplex_client_state* kcs, qsmp_connection_state* cns, qsmp_network_packet* packetout)
{
	assert(kcs != NULL);
	assert(packetout != NULL);

	qsc_keccak_state kstate = { 0 };
	qsmp_errors qerr;
	uint64_t tm;

	if (kcs != NULL && packetout != NULL)
	{
		tm = qsc_timestamp_datetime_utc();
		
		if (tm <= kcs->expiration)
		{
			uint8_t phash[QSMP_DUPLEX_HASH_SIZE] = { 0 };
			uint8_t shdr[QSMP_HEADER_SIZE] = { 0 };
			size_t mlen;

			/* copy the key-id and configuration string to the message */
			qsc_memutils_copy(packetout->pmessage, kcs->keyid, QSMP_KEYID_SIZE);
			qsc_memutils_copy(((uint8_t*)packetout->pmessage + QSMP_KEYID_SIZE), QSMP_CONFIG_STRING, QSMP_CONFIG_SIZE);
			/* assemble the connection-request packet */
			qsmp_header_create(packetout, qsmp_flag_connect_request, cns->txseq, KEX_DUPLEX_CONNECT_REQUEST_MESSAGE_SIZE);

			/* version 1.3 serialize header, then hash/sign the header and message */
			qsmp_packet_header_serialize(packetout, shdr);
			qsc_sha3_initialize(&kstate);
			qsc_sha3_update(&kstate, qsc_keccak_rate_512, shdr, QSMP_HEADER_SIZE);
			qsc_sha3_update(&kstate, qsc_keccak_rate_512, packetout->pmessage, QSMP_KEYID_SIZE + QSMP_CONFIG_SIZE);
			qsc_sha3_finalize(&kstate, qsc_keccak_rate_512, phash);

			/* sign the hash and add it to the message */
			mlen = 0;
			qsmp_signature_sign(packetout->pmessage + QSMP_KEYID_SIZE + QSMP_CONFIG_SIZE, &mlen, phash, QSMP_DUPLEX_HASH_SIZE, kcs->sigkey, qsc_acp_generate);

			/* store a hash of the configuration string, and the public signature keys: pkh = H(cfg || pvka || pvkb) */
			qsc_memutils_clear(kcs->schash, QSMP_DUPLEX_SCHASH_SIZE);
			qsc_sha3_initialize(&kstate);
			qsc_sha3_update(&kstate, qsc_keccak_rate_512, (const uint8_t*)QSMP_CONFIG_STRING, QSMP_CONFIG_SIZE);
			qsc_sha3_update(&kstate, qsc_keccak_rate_512, kcs->keyid, QSMP_KEYID_SIZE);
			qsc_sha3_update(&kstate, qsc_keccak_rate_512, kcs->verkey, QSMP_ASYMMETRIC_VERIFY_KEY_SIZE);
			qsc_sha3_update(&kstate, qsc_keccak_rate_512, kcs->rverkey, QSMP_ASYMMETRIC_VERIFY_KEY_SIZE);
			qsc_sha3_finalize(&kstate, qsc_keccak_rate_512, kcs->schash);

			cns->exflag = qsmp_flag_connect_request;
			qerr = qsmp_error_none;
		}
		else
		{
			cns->exflag = qsmp_flag_none;
			qerr = qsmp_error_key_expired;
		}
	}
	else
	{
		cns->exflag = qsmp_flag_none;
		qerr = qsmp_error_invalid_input;
	}

	return qerr;
}

/*
Exchange Request:
The client verifies the flag, sequence number, valid-time timestamp, and message size of the connect response packet.
The client verifies the signature of the hash, then generates its own hash of the public key and serialized packet header, 
and compares it with the one contained in the message. 
If the hash matches, the client uses the public-key to encapsulate a shared secret. 
If the hash does not match, the key exchange is aborted.
cond := Vpk(H(pk || sh)) = (true ?= pk : 0)
cpta, seca := Epk(seca)
The client stores the shared secret (seca), which along with a second shared secret and the session cookie, 
which will be used to generate the session keys.
The client generates an asymmetric encryption key-pair, stores the private key, 
hashes the public encapsulation key, cipher-text, and serialized packet header, 
and then signs the hash using its asymmetric signature key.
pk, sk := G(cfg)
kch := H(pk || cpta || sh)
skch := Ssk(kch)
The client sends a response message containing the signed hash of its encapsulation-key and 
cipher-text and serialized header, and a copy of the cipher-text and encapsulation key.
C{ cpta || pk || skch }-> S
*/
static qsmp_errors kex_duplex_client_exchange_request(qsmp_kex_duplex_client_state* kcs, qsmp_connection_state* cns, const qsmp_network_packet* packetin, qsmp_network_packet* packetout)
{
	assert(kcs != NULL);
	assert(packetin != NULL);
	assert(packetout != NULL);

	uint8_t khash[QSMP_DUPLEX_SCHASH_SIZE] = { 0 };
	size_t mlen;
	size_t slen;
	qsmp_errors qerr;

	if (kcs != NULL && packetin != NULL && packetout != NULL)
	{
		slen = 0;
		mlen = QSMP_ASYMMETRIC_SIGNATURE_SIZE + QSMP_DUPLEX_HASH_SIZE;

		/* verify the asymmetric signature */
		if (qsmp_signature_verify(khash, &slen, packetin->pmessage, mlen, kcs->rverkey) == true)
		{
			qsc_keccak_state kstate = { 0 };
			uint8_t phash[QSMP_DUPLEX_HASH_SIZE] = { 0 };
			uint8_t shdr[QSMP_HEADER_SIZE] = { 0 };
			const uint8_t* pubk = packetin->pmessage + mlen;

			/* version 1.3 hash the public encapsulation key and header */
			qsmp_packet_header_serialize(packetin, shdr);
			qsc_sha3_initialize(&kstate);
			qsc_sha3_update(&kstate, qsc_keccak_rate_512, shdr, QSMP_HEADER_SIZE);
			qsc_sha3_update(&kstate, qsc_keccak_rate_512, pubk, QSMP_ASYMMETRIC_PUBLIC_KEY_SIZE);
			qsc_sha3_finalize(&kstate, qsc_keccak_rate_512, phash);

			/* verify the public key hash */
			if (qsc_intutils_verify(phash, khash, QSMP_DUPLEX_HASH_SIZE) == 0)
			{
				/* generate, and encapsulate the secret */

				/* store the cipher-text in the message */
				qsmp_cipher_encapsulate(kcs->ssec, packetout->pmessage, pubk, qsc_acp_generate);

				/* generate the asymmetric encryption key-pair */
				qsmp_cipher_generate_keypair(kcs->pubkey, kcs->prikey, qsc_acp_generate);

				/* copy the public key to the message */
				qsc_memutils_copy(packetout->pmessage + QSMP_ASYMMETRIC_CIPHER_TEXT_SIZE, kcs->pubkey, QSMP_ASYMMETRIC_PUBLIC_KEY_SIZE);
					
				/* assemble the exchange-request packet */
				qsmp_header_create(packetout, qsmp_flag_exchange_request, cns->txseq, KEX_DUPLEX_EXCHANGE_REQUEST_MESSAGE_SIZE);

				/* version 1.3 hash the public encapsulation key and packet header */
				qsmp_packet_header_serialize(packetout, shdr);
				qsc_sha3_initialize(&kstate);
				qsc_sha3_update(&kstate, qsc_keccak_rate_512, shdr, QSMP_HEADER_SIZE);
				/* hash the public encapsulation key and cipher-text */
				qsc_sha3_update(&kstate, qsc_keccak_rate_512, packetout->pmessage, QSMP_ASYMMETRIC_CIPHER_TEXT_SIZE + QSMP_ASYMMETRIC_PUBLIC_KEY_SIZE);
				qsc_sha3_finalize(&kstate, qsc_keccak_rate_512, phash);

				/* sign the hash and add it to the message */
				mlen = 0;
				qsmp_signature_sign(packetout->pmessage + QSMP_ASYMMETRIC_CIPHER_TEXT_SIZE + QSMP_ASYMMETRIC_PUBLIC_KEY_SIZE, &mlen, phash, QSMP_DUPLEX_HASH_SIZE, kcs->sigkey, qsc_acp_generate);

				qerr = qsmp_error_none;
				cns->exflag = qsmp_flag_exchange_request;
			}
			else
			{
				cns->exflag = qsmp_flag_none;
				qerr = qsmp_error_verify_failure;
			}
		}
		else
		{
			cns->exflag = qsmp_flag_none;
			qerr = qsmp_error_authentication_failure;
		}
	}
	else
	{
		cns->exflag = qsmp_flag_none;
		qerr = qsmp_error_invalid_input;
	}

	return qerr;
}

/*
The client verifies the flag, sequence number, valid-time timestamp, and message size of the exchange response packet.
The client verifies the signature of the hash, then generates its own hash of the cipher-text and packet header, 
and compares it with the one contained in the message. 
If the hash matches, the client decapsulates the shared secret (secb). If the hash comparison fails,
the key exchange is aborted.
cond := Vpk(H(cptb)) = (true ?= cptb : 0)
secb := -Esk(cptb)
The client combines both secrets and the session cookie to create the session keys, 
and two unique nonce, one for each channel of the communications stream.
k1, k2, n1, n2 := KDF(seca, secb, sch)
The receive and transmit channel ciphers are initialized.
cprrx(k2, n2)
cprtx(k1, n1)
The client encrypts the session cookie with the tx cipher, adding the serialized packet header 
to the additional data of the cipher MAC.
cm := Ek(sch, sh)
In the event of an error, the client sends an error message to the server, 
aborting the exchange and terminating the connection on both hosts.
C{ cm }-> S
*/
static qsmp_errors kex_duplex_client_establish_request(const qsmp_kex_duplex_client_state* kcs, qsmp_connection_state* cns, const qsmp_network_packet* packetin, qsmp_network_packet* packetout)
{
	assert(kcs != NULL);
	assert(packetin != NULL);
	assert(packetout != NULL);

	qsmp_errors qerr;
	uint8_t khash[QSMP_DUPLEX_HASH_SIZE] = { 0 };
	size_t mlen;
	size_t slen;

	if (kcs != NULL && packetin != NULL && packetout != NULL)
	{
		slen = 0;
		mlen = QSMP_ASYMMETRIC_SIGNATURE_SIZE + QSMP_DUPLEX_HASH_SIZE;

		/* verify the asymmetric signature */
		if (qsmp_signature_verify(khash, &slen, packetin->pmessage + QSMP_ASYMMETRIC_CIPHER_TEXT_SIZE, mlen, kcs->rverkey) == true)
		{
			qsc_keccak_state kstate = { 0 };
			uint8_t phash[QSMP_DUPLEX_HASH_SIZE] = { 0 };
			uint8_t secb[QSMP_SECRET_SIZE] = { 0 };
			uint8_t shdr[QSMP_HEADER_SIZE] = { 0 };

			/* version 1.3 hash the public encapsulation key and header */
			qsmp_packet_header_serialize(packetin, shdr);
			qsc_sha3_initialize(&kstate);
			qsc_sha3_update(&kstate, qsc_keccak_rate_512, shdr, QSMP_HEADER_SIZE);
			qsc_sha3_update(&kstate, qsc_keccak_rate_512, packetin->pmessage, QSMP_ASYMMETRIC_CIPHER_TEXT_SIZE);
			qsc_sha3_finalize(&kstate, qsc_keccak_rate_512, phash);

			/* verify the cipher-text hash */
			if (qsc_intutils_verify(phash, khash, QSMP_DUPLEX_HASH_SIZE) == 0)
			{
				if (qsmp_cipher_decapsulate(secb, packetin->pmessage, kcs->prikey) == true)
				{
					uint8_t prnd[(QSC_KECCAK_512_RATE * 3)] = { 0 };

					/* initialize cSHAKE k = H(seca, secb, pkh) */
					qsc_cshake_initialize(&kstate, qsc_keccak_rate_512, kcs->ssec, QSMP_SECRET_SIZE, kcs->schash, QSMP_DUPLEX_SCHASH_SIZE, secb, sizeof(secb));
					qsc_cshake_squeezeblocks(&kstate, qsc_keccak_rate_512, prnd, 3);
					/* permute the state so we are not storing the current key */
					qsc_keccak_permute(&kstate, QSC_KECCAK_PERMUTATION_ROUNDS);
					/* copy as next key */
					qsc_memutils_copy(cns->rtcs, (uint8_t*)kstate.state, QSMP_DUPLEX_SYMMETRIC_KEY_SIZE);

					/* initialize the symmetric cipher, and raise client channel-1 tx */
					qsc_rcs_keyparams kp1 = { 0 };
					kp1.key = prnd;
					kp1.keylen = QSMP_DUPLEX_SYMMETRIC_KEY_SIZE;
					kp1.nonce = prnd + QSMP_DUPLEX_SYMMETRIC_KEY_SIZE;
					kp1.info = NULL;
					kp1.infolen = 0;
					qsc_rcs_initialize(&cns->txcpr, &kp1, true);

					/* initialize the symmetric cipher, and raise client channel-1 rx */
					qsc_rcs_keyparams kp2 = { 0 };
					kp2.key = prnd + QSMP_DUPLEX_SYMMETRIC_KEY_SIZE + QSMP_NONCE_SIZE;
					kp2.keylen = QSMP_DUPLEX_SYMMETRIC_KEY_SIZE;
					kp2.nonce = prnd + QSMP_DUPLEX_SYMMETRIC_KEY_SIZE + QSMP_NONCE_SIZE + QSMP_DUPLEX_SYMMETRIC_KEY_SIZE;
					kp2.info = NULL;
					kp2.infolen = 0;
					qsc_rcs_initialize(&cns->rxcpr, &kp2, false);

					/* assemble the establish-request packet */
					qsmp_header_create(packetout, qsmp_flag_establish_request, cns->txseq, KEX_DUPLEX_ESTABLISH_REQUEST_MESSAGE_SIZE);

					/* version 1.3 protocol change: encrypt and add schash to establish request */
					qsmp_packet_header_serialize(packetout, shdr);
					qsc_rcs_set_associated(&cns->txcpr, shdr, QSMP_HEADER_SIZE);
					qsc_rcs_transform(&cns->txcpr, packetout->pmessage, kcs->schash, QSMP_DUPLEX_SCHASH_SIZE);

					qerr = qsmp_error_none;
					cns->exflag = qsmp_flag_establish_request;
				}
				else
				{
					cns->exflag = qsmp_flag_none;
					qerr = qsmp_error_decapsulation_failure;
				}
			}
			else
			{
				cns->exflag = qsmp_flag_none;
				qerr = qsmp_error_verify_failure;
			}
		}
		else
		{
			cns->exflag = qsmp_flag_none;
			qerr = qsmp_error_authentication_failure;
		}
	}
	else
	{
		cns->exflag = qsmp_flag_none;
		qerr = qsmp_error_invalid_input;
	}

	return qerr;
}

/*
Establish Verify:
The client verifies the packet flag, sequence number, valid-time timestamp, and message size of the establish response packet.
The client uses the rx cipher instance, adding the serialized establish response packet header to the AD and decrypting the ciphertext.
The session cookie is hashed, and the hash is compared to the decrypted message for equivalence.
If the hahs matches, both sides have confirmed that the encrypted tunnel has been established.
Otherwise the tunnel is in an error state indicated by the message, 
and the tunnel is torn down on both sides. 
The client sets the operational state to session established, and is now ready to process data.
*/
static qsmp_errors kex_duplex_client_establish_verify(const qsmp_kex_duplex_client_state* kcs, qsmp_connection_state* cns, const qsmp_network_packet* packetin)
{
	assert(kcs != NULL);
	assert(packetin != NULL);

	qsmp_errors qerr;

	if (kcs != NULL && packetin != NULL)
	{
		uint8_t phash[QSMP_DUPLEX_SCHASH_SIZE];
		uint8_t shdr[QSMP_HEADER_SIZE] = { 0 };

		/* version 1.3 protocol change: decrypt and verify the server schash */
		qsmp_packet_header_serialize(packetin, shdr);
		qsc_rcs_set_associated(&cns->rxcpr, shdr, QSMP_HEADER_SIZE);

		if (qsc_rcs_transform(&cns->rxcpr, phash, packetin->pmessage, QSMP_DUPLEX_SCHASH_SIZE) == true)
		{
			uint8_t shash[QSMP_DUPLEX_SCHASH_SIZE];

			qsc_sha3_compute512(shash, kcs->schash, QSMP_DUPLEX_SCHASH_SIZE);

			/* verify the server schash */
			if (qsc_intutils_verify(phash, shash, QSMP_DUPLEX_SCHASH_SIZE) == 0)
			{
				cns->exflag = qsmp_flag_session_established;
				qerr = qsmp_error_none;
			}
			else
			{
				qerr = qsmp_error_verify_failure;
			}
		}
		else
		{
			qerr = qsmp_error_decryption_failure;
		}
	}
	else
	{
		qerr = qsmp_error_invalid_input;
	}

	return qerr;
}

/*
The server verifies the packet flag, sequence number, valid-time timestamp, and message size of the connect request packet.
The server responds with either an error message, or a connect response packet.
Any error during the key exchange will generate an error-packet sent to the remote host, 
which will trigger a tear down of the exchange, and the network connection on both sides.
The server first checks the packet header including the valid-time timestamp.
The server then verifies that it has the requested asymmetric signature verification key,
corresponding to the kid sent by the client. The server verifies that it has a compatible protocol configuration. 
The server loads the client's signature verification key, and checks the signature of the message:
mh = Vpk(sm)
If the signature is verified, the server hashes the message kid, config string, and serialized packet header
and compares the signed hash:
m ?= H(kid || cfg || sph)
The server stores a hash of the configuration string, key identity, and both public signature verification-keys, 
to create the public key hash, which is used as a session cookie.
sch := H(cfg || kid || pvka || pvkb)
The server then generates an asymmetric encryption key-pair, stores the private key, 
hashes the public encapsulation key, and then signs the hash of the public encapsulation key and the serialized 
packet header using the asymmetric signature key.
The public signature verification key can itself be signed by a ‘chain of trust' model, 
like X.509, using a signature verification extension to this protocol.
pk,sk := G(cfg)
pkh := H(pk || sph)
spkh := Ssk(pkh)
The server sends a connect response message containing a signed hash of the public asymmetric encapsulation-key, 
and a copy of that key.
S{ spkh || pk }-> C
*/
static qsmp_errors kex_duplex_server_connect_response(qsmp_kex_duplex_server_state* kss, qsmp_connection_state* cns, const qsmp_network_packet* packetin, qsmp_network_packet* packetout)
{
	assert(cns != NULL);
	assert(kss != NULL);
	assert(packetin != NULL);
	assert(packetout != NULL);

	qsmp_errors qerr;

	qerr = qsmp_error_none;

	if (cns != NULL && kss != NULL && packetin != NULL && packetout != NULL)
	{
		const uint8_t* pkid = packetin->pmessage;

		/* compare the kid in the message, to stored kids through the interface */
		if (kss->key_query(kss->rverkey, pkid) == true)
		{
			uint64_t tm;

			tm = qsc_timestamp_datetime_utc();

			/* check the keys expiration date */
			if (tm <= kss->expiration)
			{
				char confs[QSMP_CONFIG_SIZE + sizeof(char)] = { 0 };

				/* get a copy of the configuration string */
				qsc_memutils_copy(confs, packetin->pmessage + QSMP_KEYID_SIZE, QSMP_CONFIG_SIZE);

				/* compare the state configuration string to the message configuration string */
				if (qsc_stringutils_compare_strings(confs, QSMP_CONFIG_STRING, QSMP_CONFIG_SIZE) == true)
				{
					uint8_t phash[QSMP_DUPLEX_HASH_SIZE] = { 0 };
					size_t mlen;
					size_t slen;

					slen = 0;
					mlen = QSMP_ASYMMETRIC_SIGNATURE_SIZE + QSMP_DUPLEX_HASH_SIZE;

					/* verify the asymmetric signature */
					if (qsmp_signature_verify(phash, &slen, packetin->pmessage + QSMP_KEYID_SIZE + QSMP_CONFIG_SIZE, mlen, kss->rverkey) == true)
					{
						qsc_keccak_state kstate = { 0 };
						uint8_t shash[QSMP_DUPLEX_HASH_SIZE] = { 0 };
						uint8_t shdr[QSMP_HEADER_SIZE] = { 0 };

						/* version 1.3 serialize header, then hash/sign the header and message */
						qsmp_packet_header_serialize(packetin, shdr);
						qsc_sha3_initialize(&kstate);
						qsc_sha3_update(&kstate, qsc_keccak_rate_512, shdr, QSMP_HEADER_SIZE);
						qsc_sha3_update(&kstate, qsc_keccak_rate_512, packetin->pmessage, QSMP_KEYID_SIZE + QSMP_CONFIG_SIZE);
						qsc_sha3_finalize(&kstate, qsc_keccak_rate_512, shash);

						/* verify the message hash */
						if (qsc_intutils_verify(phash, shash, QSMP_DUPLEX_HASH_SIZE) == 0)
						{
							/* store a hash of the session token, the configuration string,
								and the public signature key: sch = H(stok || cfg || pvk) */
							qsc_memutils_clear(kss->schash, QSMP_DUPLEX_SCHASH_SIZE);
							qsc_sha3_initialize(&kstate);
							qsc_sha3_update(&kstate, qsc_keccak_rate_512, (const uint8_t*)QSMP_CONFIG_STRING, QSMP_CONFIG_SIZE);
							qsc_sha3_update(&kstate, qsc_keccak_rate_512, kss->keyid, QSMP_KEYID_SIZE);
							qsc_sha3_update(&kstate, qsc_keccak_rate_512, kss->rverkey, QSMP_ASYMMETRIC_VERIFY_KEY_SIZE);
							qsc_sha3_update(&kstate, qsc_keccak_rate_512, kss->verkey, QSMP_ASYMMETRIC_VERIFY_KEY_SIZE);
							qsc_sha3_finalize(&kstate, qsc_keccak_rate_512, kss->schash);

							/* initialize the packet and asymmetric encryption keys */
							qsc_memutils_clear(kss->pubkey, QSMP_ASYMMETRIC_PUBLIC_KEY_SIZE);
							qsc_memutils_clear(kss->prikey, QSMP_ASYMMETRIC_PRIVATE_KEY_SIZE);

							/* generate the asymmetric encryption key-pair */
							qsmp_cipher_generate_keypair(kss->pubkey, kss->prikey, qsc_acp_generate);

							/* assemble the connection-response packet */
							qsmp_header_create(packetout, qsmp_flag_connect_response, cns->txseq, KEX_DUPLEX_CONNECT_RESPONSE_MESSAGE_SIZE);

							/* version 1.3 hash the public encapsulation key and header */
							qsmp_packet_header_serialize(packetout, shdr);
							qsc_sha3_initialize(&kstate);
							qsc_sha3_update(&kstate, qsc_keccak_rate_512, shdr, QSMP_HEADER_SIZE);
							qsc_sha3_update(&kstate, qsc_keccak_rate_512, kss->pubkey, QSMP_ASYMMETRIC_PUBLIC_KEY_SIZE);
							qsc_sha3_finalize(&kstate, qsc_keccak_rate_512, phash);

							/* sign the hash and add it to the message */
							mlen = 0;
							qsmp_signature_sign(packetout->pmessage, &mlen, phash, QSMP_DUPLEX_HASH_SIZE, kss->sigkey, qsc_acp_generate);

							/* copy the public key to the message */
							qsc_memutils_copy(((uint8_t*)packetout->pmessage + mlen), kss->pubkey, QSMP_ASYMMETRIC_PUBLIC_KEY_SIZE);

							qerr = qsmp_error_none;
							cns->exflag = qsmp_flag_connect_response;
						}
						else
						{
							cns->exflag = qsmp_flag_none;
							qerr = qsmp_error_verify_failure;
						}
					}
					else
					{
						cns->exflag = qsmp_flag_none;
						qerr = qsmp_error_authentication_failure;
					}
				}
				else
				{
					cns->exflag = qsmp_flag_none;
					qerr = qsmp_error_unknown_protocol;
				}
			}
			else
			{
				cns->exflag = qsmp_flag_none;
				qerr = qsmp_error_key_expired;
			}
		}
		else
		{
			cns->exflag = qsmp_flag_none;
			qerr = qsmp_error_key_unrecognized;
		}
	}
	else
	{
		cns->exflag = qsmp_flag_none;
		qerr = qsmp_error_invalid_input;
	}

	return qerr;
}

/*
Exchange Response:
The server verifies the packet flag, sequence number, valid-time timestamp, and message size of the exchange request packet.
The server verifies the signature of the hash, then generates its own hash of the public key and cipher-text and serialized header, 
and compares it with the one contained in the message.
If the hash matches, the server uses the private-key to decapsulate the shared secret.
If the hash comparison fails, the key exchange is aborted.
cond := Vpk(H(pk || cpta)) = (true ?= cph : 0)
The server decapsulates the second shared-secret, and stores the secret (seca).
seca := -Esk(cpta)
The server generates a cipher-text and the second shared secret (secb) using the clients public encapsulation key.
cptb, secb := Epk(secb)
The server combines both secrets and the session cookie to create two session keys, and two unique nonce, 
one for each channel of the communications stream.
k1, k2, n1, n2 := Exp(seca || secb || sch)
The receive and transmit channel ciphers are initialized.
cprrx(k1,n1)
cprtx(k2,n2)
The server hashes the cipher-text and serialized packet header, and signs the hash.
cpth := H(cptb || sh)
scph := Ssk(cpth)
The server sends the signed hash of the cipher-text, and the cipher-text to the client.
S{ scph || cptb }-> C
*/
static qsmp_errors kex_duplex_server_exchange_response(const qsmp_kex_duplex_server_state* kss, qsmp_connection_state* cns, const qsmp_network_packet* packetin, qsmp_network_packet* packetout)
{
	assert(kss != NULL);
	assert(packetin != NULL);
	assert(packetout != NULL);

	qsmp_errors qerr;

	if (kss != NULL && packetin != NULL && packetout != NULL)
	{
		uint8_t khash[QSMP_DUPLEX_SCHASH_SIZE] = { 0 };
		size_t mlen;
		size_t slen;

		slen = 0;
		mlen = QSMP_ASYMMETRIC_SIGNATURE_SIZE + QSMP_DUPLEX_HASH_SIZE;

		/* verify the asymmetric signature */
		if (qsmp_signature_verify(khash, &slen, packetin->pmessage + QSMP_ASYMMETRIC_CIPHER_TEXT_SIZE + QSMP_ASYMMETRIC_PUBLIC_KEY_SIZE, mlen, kss->rverkey) == true)
		{
			qsc_keccak_state kstate = { 0 };
			uint8_t phash[QSMP_DUPLEX_HASH_SIZE] = { 0 };
			uint8_t shdr[QSMP_HEADER_SIZE] = { 0 };

			/* version 1.3 hash the public encapsulation key and header */
			qsmp_packet_header_serialize(packetin, shdr);
			qsc_sha3_initialize(&kstate);
			qsc_sha3_update(&kstate, qsc_keccak_rate_512, shdr, QSMP_HEADER_SIZE);
			qsc_sha3_update(&kstate, qsc_keccak_rate_512, packetin->pmessage, QSMP_ASYMMETRIC_CIPHER_TEXT_SIZE + QSMP_ASYMMETRIC_PUBLIC_KEY_SIZE);
			qsc_sha3_finalize(&kstate, qsc_keccak_rate_512, phash);

			/* verify the public key hash */
			if (qsc_intutils_verify(phash, khash, QSMP_DUPLEX_HASH_SIZE) == 0)
			{
				uint8_t seca[QSMP_SECRET_SIZE] = { 0 };
				uint8_t secb[QSMP_SECRET_SIZE] = { 0 };

				if (qsmp_cipher_decapsulate(seca, packetin->pmessage, kss->prikey) == true)
				{
					uint8_t prnd[(QSC_KECCAK_512_RATE * 3)] = { 0 };

					/* generate, and encapsulate the secret and store the cipher-text in the message */
					qsmp_cipher_encapsulate(secb, packetout->pmessage, packetin->pmessage + QSMP_ASYMMETRIC_CIPHER_TEXT_SIZE, qsc_acp_generate);

					/* assemble the exstart-request packet */
					qsmp_header_create(packetout, qsmp_flag_exchange_response, cns->txseq, KEX_DUPLEX_EXCHANGE_RESPONSE_MESSAGE_SIZE);
					
					/* version 1.3 hash the public encapsulation key and header */
					qsmp_packet_header_serialize(packetout, shdr);
					qsc_sha3_initialize(&kstate);
					qsc_sha3_update(&kstate, qsc_keccak_rate_512, shdr, QSMP_HEADER_SIZE);
					qsc_sha3_update(&kstate, qsc_keccak_rate_512, packetout->pmessage, QSMP_ASYMMETRIC_CIPHER_TEXT_SIZE);
					qsc_sha3_finalize(&kstate, qsc_keccak_rate_512, phash);

					/* sign the hash and add it to the message */
					mlen = 0;
					qsmp_signature_sign(packetout->pmessage + QSMP_ASYMMETRIC_CIPHER_TEXT_SIZE, &mlen, phash, QSMP_DUPLEX_HASH_SIZE, kss->sigkey, qsc_acp_generate);

					/* initialize cSHAKE k = H(seca, secb, pkh) */
					qsc_cshake_initialize(&kstate, qsc_keccak_rate_512, seca, sizeof(seca), kss->schash, QSMP_DUPLEX_SCHASH_SIZE, secb, sizeof(secb));
					qsc_cshake_squeezeblocks(&kstate, qsc_keccak_rate_512, prnd, 3);
					/* permute the state so we are not storing the current key */
					qsc_keccak_permute(&kstate, QSC_KECCAK_PERMUTATION_ROUNDS);
					/* copy as next key */
					qsc_memutils_copy(cns->rtcs, (uint8_t*)kstate.state, QSMP_DUPLEX_SYMMETRIC_KEY_SIZE);

					/* initialize the symmetric cipher, and raise client channel-1 tx */
					qsc_rcs_keyparams kp1 = { 0 };
					kp1.key = prnd;
					kp1.keylen = QSMP_DUPLEX_SYMMETRIC_KEY_SIZE;
					kp1.nonce = prnd + QSMP_DUPLEX_SYMMETRIC_KEY_SIZE;
					kp1.info = NULL;
					kp1.infolen = 0;
					qsc_rcs_initialize(&cns->rxcpr, &kp1, false);

					/* initialize the symmetric cipher, and raise client channel-1 rx */
					qsc_rcs_keyparams kp2 = { 0 };
					kp2.key = prnd + QSMP_DUPLEX_SYMMETRIC_KEY_SIZE + QSMP_NONCE_SIZE;
					kp2.keylen = QSMP_DUPLEX_SYMMETRIC_KEY_SIZE;
					kp2.nonce = prnd + QSMP_DUPLEX_SYMMETRIC_KEY_SIZE + QSMP_NONCE_SIZE + QSMP_DUPLEX_SYMMETRIC_KEY_SIZE;
					kp2.info = NULL;
					kp2.infolen = 0;
					qsc_rcs_initialize(&cns->txcpr, &kp2, true);

					qerr = qsmp_error_none;
					cns->exflag = qsmp_flag_exchange_response;
				}
				else
				{
					cns->exflag = qsmp_flag_none;
					qerr = qsmp_error_decapsulation_failure;
				}
			}
			else
			{
				cns->exflag = qsmp_flag_none;
				qerr = qsmp_error_hash_invalid;
			}
		}
		else
		{
			cns->exflag = qsmp_flag_none;
			qerr = qsmp_error_authentication_failure;
		}
	}
	else
	{
		cns->exflag = qsmp_flag_none;
		qerr = qsmp_error_invalid_input;
	}

	return qerr;
}

/*
Establish Response:
The server verifies the packet flag, sequence number, valid-time timestamp, and message size of the establish request packet.
If the flag is set to establish request, the server sends an empty message back to the client 
with the establish response flag set. 
Otherwise the tunnel is in an error state indicated in the message, and the tunnel is torn down on both sides. 
The server sets the operational state to session established, and is now ready to process data.
The server uses the rx cipher to decrypt the message, adding the serialized packet header to the additional data of the cipher MAC. 
The decrypted session cookie is compared to the local session cookie for equivalence. 
If the cookie is verified, the server hashes the session cookie, and encrypts it with the tx cipher,
adding the serialized establish response packet header to the AD of the tx cipher.
hsch = H(sch)
cm := Ek(hsch, sh)
S{ cm }-> C
*/
static qsmp_errors kex_duplex_server_establish_response(const qsmp_kex_duplex_server_state* kss, qsmp_connection_state* cns, const qsmp_network_packet* packetin, qsmp_network_packet* packetout)
{
	assert(cns != NULL);
	assert(packetin != NULL);
	assert(packetout != NULL);
	
	qsmp_errors qerr;

	qerr = qsmp_error_invalid_input;

	if (cns != NULL && packetin != NULL && packetout != NULL)
	{
		uint8_t phash[QSMP_DUPLEX_SCHASH_SIZE];
		uint8_t shdr[QSMP_HEADER_SIZE] = { 0 };

		/* version 1.3 protocol change: decrypt and verify the schash */
		qsmp_packet_header_serialize(packetin, shdr);
		qsc_rcs_set_associated(&cns->rxcpr, shdr, QSMP_HEADER_SIZE);

		if (qsc_rcs_transform(&cns->rxcpr, phash, packetin->pmessage, QSMP_DUPLEX_SCHASH_SIZE) == true)
		{
			/* verify the schash */
			if (qsc_intutils_verify(phash, kss->schash, QSMP_DUPLEX_SCHASH_SIZE) == 0)
			{
				/* assemble the establish-response packet */
				qsmp_header_create(packetout, qsmp_flag_establish_response, cns->txseq, KEX_DUPLEX_ESTABLISH_RESPONSE_MESSAGE_SIZE);

				/* version 1.3 protocol change: hash the schash and send it in the establish response message */
				qsc_memutils_clear(phash, QSMP_DUPLEX_SCHASH_SIZE);
				qsc_sha3_compute512(phash, kss->schash, QSMP_DUPLEX_SCHASH_SIZE);

				qsmp_packet_header_serialize(packetout, shdr);
				qsc_rcs_set_associated(&cns->txcpr, shdr, QSMP_HEADER_SIZE);
				qsc_rcs_transform(&cns->txcpr, packetout->pmessage, phash, QSMP_DUPLEX_SCHASH_SIZE);

				qerr = qsmp_error_none;
				cns->exflag = qsmp_flag_session_established;
			}
			else
			{
				cns->exflag = qsmp_flag_none;
				qerr = qsmp_error_verify_failure;
			}
		}
		else
		{
			cns->exflag = qsmp_flag_none;
			qerr = qsmp_error_decryption_failure;
		}
	}

	return qerr;
}

qsmp_errors qsmp_kex_duplex_client_key_exchange(qsmp_kex_duplex_client_state* kcs, qsmp_connection_state* cns)
{
	assert(kcs != NULL);
	assert(cns != NULL);

	qsmp_network_packet reqt = { 0 };
	qsmp_network_packet resp = { 0 };
	uint8_t* rbuf;
	uint8_t* sbuf;
	size_t rlen;
	size_t slen;
	qsmp_errors qerr;

	rbuf = (uint8_t*)qsc_memutils_malloc(QSC_SOCKET_TERMINATOR_SIZE);
	sbuf = (uint8_t*)qsc_memutils_malloc(KEX_DUPLEX_CONNECT_REQUEST_PACKET_SIZE);

	if (kcs != NULL && cns != NULL && rbuf != NULL && sbuf != NULL)
	{
		/* 1. connect stage */
		qsc_memutils_clear(sbuf, KEX_DUPLEX_CONNECT_REQUEST_PACKET_SIZE);
		reqt.pmessage = sbuf + QSMP_HEADER_SIZE;

		/* create the connection request packet */
		qerr = kex_duplex_client_connect_request(kcs, cns, &reqt);

		if (qerr == qsmp_error_none)
		{
			qsmp_packet_header_serialize(&reqt, sbuf);
			/* send the connection request */
			slen = qsc_socket_send(&cns->target, sbuf, KEX_DUPLEX_CONNECT_REQUEST_PACKET_SIZE, qsc_socket_send_flag_none);

			/* check the size sent */
			if (slen == KEX_DUPLEX_CONNECT_REQUEST_PACKET_SIZE)
			{
				/* increment the transmit sequence counter */
				cns->txseq += 1;
				/* reallocate to the message connect response buffer size */
				rbuf = (uint8_t*)qsc_memutils_realloc(rbuf, KEX_DUPLEX_CONNECT_RESPONSE_PACKET_SIZE);

				if (rbuf != NULL)
				{
					/* allocated memory must be set to zero per MISRA */
					qsc_memutils_clear(rbuf, KEX_DUPLEX_CONNECT_RESPONSE_PACKET_SIZE);
					resp.pmessage = rbuf + QSMP_HEADER_SIZE;

					/* blocking receive waits for connect response */
					rlen = qsc_socket_receive(&cns->target, rbuf, KEX_DUPLEX_CONNECT_RESPONSE_PACKET_SIZE, qsc_socket_receive_flag_wait_all);

					if (rlen == KEX_DUPLEX_CONNECT_RESPONSE_PACKET_SIZE)
					{
						/* convert server response to packet */
						qsmp_packet_header_deserialize(rbuf, &resp);
						/* validate the packet header including the timestamp */
						qerr = qsmp_header_validate(cns, &resp, qsmp_flag_connect_request, qsmp_flag_connect_response, cns->rxseq, KEX_DUPLEX_CONNECT_RESPONSE_MESSAGE_SIZE);
					}
					else
					{
						qerr = qsmp_error_receive_failure;
					}
				}
				else
				{
					qerr = qsmp_error_memory_allocation;
				}
			}
			else
			{
				qerr = qsmp_error_transmit_failure;
			}
		}

		/* 2. exchange stage */
		if (qerr == qsmp_error_none)
		{
			sbuf = (uint8_t*)qsc_memutils_realloc(sbuf, KEX_DUPLEX_EXCHANGE_REQUEST_PACKET_SIZE);

			if (sbuf != NULL)
			{
				qsc_memutils_clear(sbuf, KEX_DUPLEX_EXCHANGE_REQUEST_PACKET_SIZE);
				reqt.pmessage = sbuf + QSMP_HEADER_SIZE;

				/* create the exchange request packet */
				qerr = kex_duplex_client_exchange_request(kcs, cns, &resp, &reqt);

				if (qerr == qsmp_error_none)
				{
					/* serialize the packet header to the buffer */
					qsmp_packet_header_serialize(&reqt, sbuf);

					/* send exchange request */
					slen = qsc_socket_send(&cns->target, sbuf, KEX_DUPLEX_EXCHANGE_REQUEST_PACKET_SIZE, qsc_socket_send_flag_none);

					if (slen == KEX_DUPLEX_EXCHANGE_REQUEST_PACKET_SIZE)
					{
						cns->txseq += 1;
						rbuf = (uint8_t*)qsc_memutils_realloc(rbuf, KEX_DUPLEX_EXCHANGE_RESPONSE_PACKET_SIZE);

						if (rbuf != NULL)
						{
							qsc_memutils_clear(rbuf, KEX_DUPLEX_EXCHANGE_RESPONSE_PACKET_SIZE);
							resp.pmessage = rbuf + QSMP_HEADER_SIZE;

							/* wait for exchange response */
							rlen = qsc_socket_receive(&cns->target, rbuf, KEX_DUPLEX_EXCHANGE_RESPONSE_PACKET_SIZE, qsc_socket_receive_flag_wait_all);

							/* check the received size */
							if (rlen == KEX_DUPLEX_EXCHANGE_RESPONSE_PACKET_SIZE)
							{
								/* convert server response to packet */
								qsmp_packet_header_deserialize(rbuf, &resp);
								/* validate the header and timestamp */
								qerr = qsmp_header_validate(cns, &resp, qsmp_flag_exchange_request, qsmp_flag_exchange_response, cns->rxseq, KEX_DUPLEX_EXCHANGE_RESPONSE_MESSAGE_SIZE);
							}
							else
							{
								qerr = qsmp_error_receive_failure;
							}
						}
						else
						{
							qerr = qsmp_error_memory_allocation;
						}
					}
					else
					{
						qerr = qsmp_error_transmit_failure;
					}
				}
			}
			else
			{
				qerr = qsmp_error_memory_allocation;
			}
		}

		/* 3. establish stage */
		if (qerr == qsmp_error_none)
		{
			sbuf = (uint8_t*)qsc_memutils_realloc(sbuf, KEX_DUPLEX_ESTABLISH_REQUEST_PACKET_SIZE);

			if (sbuf != NULL)
			{
				qsc_memutils_clear(sbuf, KEX_DUPLEX_ESTABLISH_REQUEST_PACKET_SIZE);
				reqt.pmessage = sbuf + QSMP_HEADER_SIZE;

				/* create the establish request packet */
				qerr = kex_duplex_client_establish_request(kcs, cns, &resp, &reqt);

				if (qerr == qsmp_error_none)
				{
					qsmp_packet_header_serialize(&reqt, sbuf);

					/* send the establish request packet */
					slen = qsc_socket_send(&cns->target, sbuf, KEX_DUPLEX_ESTABLISH_REQUEST_PACKET_SIZE, qsc_socket_send_flag_none);
					/* clear the send buffer */
					qsc_memutils_clear(sbuf, KEX_DUPLEX_ESTABLISH_REQUEST_PACKET_SIZE);

					if (slen == KEX_DUPLEX_ESTABLISH_REQUEST_PACKET_SIZE)
					{
						cns->txseq += 1;
						rbuf = (uint8_t*)qsc_memutils_realloc(rbuf, KEX_DUPLEX_ESTABLISH_RESPONSE_PACKET_SIZE);

						if (rbuf != NULL)
						{
							qsc_memutils_clear(rbuf, KEX_DUPLEX_ESTABLISH_RESPONSE_PACKET_SIZE);
							resp.pmessage = rbuf + QSMP_HEADER_SIZE;

							/* wait for the establish response */
							rlen = qsc_socket_receive(&cns->target, rbuf, KEX_DUPLEX_ESTABLISH_RESPONSE_PACKET_SIZE, qsc_socket_receive_flag_wait_all);

							if (rlen == KEX_DUPLEX_ESTABLISH_RESPONSE_PACKET_SIZE)
							{
								qsmp_packet_header_deserialize(rbuf, &resp);
								/* validate the header */
								qerr = qsmp_header_validate(cns, &resp, qsmp_flag_establish_request, qsmp_flag_establish_response, cns->rxseq, KEX_DUPLEX_ESTABLISH_RESPONSE_MESSAGE_SIZE);

								if (qerr == qsmp_error_none)
								{
									/* verify the exchange  */
									qerr = kex_duplex_client_establish_verify(kcs, cns, &resp);
									/* clear receive buffer */
									qsc_memutils_clear(rbuf, KEX_DUPLEX_ESTABLISH_RESPONSE_PACKET_SIZE);
								}
								else
								{
									qerr = qsmp_error_packet_unsequenced;
								}
							}
							else
							{
								qerr = qsmp_error_receive_failure;
							}
						}
						else
						{
							qerr = qsmp_error_memory_allocation;
						}
					}
					else
					{
						qerr = qsmp_error_transmit_failure;
					}
				}
			}
			else
			{
				qerr = qsmp_error_memory_allocation;
			}
		}

		kex_duplex_client_reset(kcs);

		if (qerr != qsmp_error_none)
		{
			if (cns->target.connection_status == qsc_socket_state_connected)
			{
				kex_send_network_error(&cns->target, qerr);
				qsc_socket_shut_down(&cns->target, qsc_socket_shut_down_flag_both);
			}

			qsmp_connection_state_dispose(cns);
		}

		qsc_memutils_alloc_free(rbuf);
		qsc_memutils_alloc_free(sbuf);
	}
	else
	{
		qerr = qsmp_error_invalid_input;
	}

	return qerr;
}

qsmp_errors qsmp_kex_duplex_server_key_exchange(qsmp_kex_duplex_server_state* kss, qsmp_connection_state* cns)
{
	assert(kss != NULL);
	assert(cns != NULL);

	qsmp_network_packet reqt = { 0 };
	qsmp_network_packet resp = { 0 };
	uint8_t* rbuf;
	uint8_t* sbuf;
	size_t rlen;
	size_t slen;
	qsmp_errors qerr;

	rbuf = (uint8_t*)qsc_memutils_malloc(KEX_DUPLEX_CONNECT_REQUEST_PACKET_SIZE);
	sbuf = (uint8_t*)qsc_memutils_malloc(QSC_SOCKET_TERMINATOR_SIZE);

	if (kss != NULL && cns != NULL && rbuf != NULL && sbuf != NULL)
	{
		/* 1. connect stage */
		qsc_memutils_clear(rbuf, KEX_DUPLEX_CONNECT_REQUEST_PACKET_SIZE);
		resp.pmessage = rbuf + QSMP_HEADER_SIZE;

		/* blocking receive waits for client connect request */
		rlen = qsc_socket_receive(&cns->target, rbuf, KEX_DUPLEX_CONNECT_REQUEST_PACKET_SIZE, qsc_socket_receive_flag_wait_all);

		if (rlen == KEX_DUPLEX_CONNECT_REQUEST_PACKET_SIZE)
		{
			/* convert server response to packet */
			qsmp_packet_header_deserialize(rbuf, &resp);
			qerr = qsmp_header_validate(cns, &resp, qsmp_flag_none, qsmp_flag_connect_request, cns->rxseq, KEX_DUPLEX_CONNECT_REQUEST_MESSAGE_SIZE);

			if (qerr == qsmp_error_none)
			{
				sbuf = (uint8_t*)qsc_memutils_realloc(sbuf, KEX_DUPLEX_CONNECT_RESPONSE_PACKET_SIZE);

				if (sbuf != NULL)
				{
					qsc_memutils_clear(sbuf, KEX_DUPLEX_CONNECT_RESPONSE_PACKET_SIZE);
					reqt.pmessage = sbuf + QSMP_HEADER_SIZE;

					/* create the connection request packet */
					qerr = kex_duplex_server_connect_response(kss, cns, &resp, &reqt);

					if (qerr == qsmp_error_none)
					{
						qsmp_packet_header_serialize(&reqt, sbuf);
						slen = qsc_socket_send(&cns->target, sbuf, KEX_DUPLEX_CONNECT_RESPONSE_PACKET_SIZE, qsc_socket_send_flag_none);

						if (slen == KEX_DUPLEX_CONNECT_RESPONSE_PACKET_SIZE)
						{
							cns->txseq += 1;
						}
						else
						{
							qerr = qsmp_error_transmit_failure;
						}
					}
				}
				else
				{
					qerr = qsmp_error_memory_allocation;
				}
			}
		}
		else
		{
			qerr = qsmp_error_receive_failure;
		}

		/* 2. exchange stage */
		if (qerr == qsmp_error_none)
		{
			rbuf = (uint8_t*)qsc_memutils_realloc(rbuf, KEX_DUPLEX_EXCHANGE_REQUEST_PACKET_SIZE);

			if (rbuf != NULL)
			{
				qsc_memutils_clear(rbuf, KEX_DUPLEX_EXCHANGE_REQUEST_PACKET_SIZE);
				resp.pmessage = rbuf + QSMP_HEADER_SIZE;

				/* wait for the exchange request */
				rlen = qsc_socket_receive(&cns->target, rbuf, KEX_DUPLEX_EXCHANGE_REQUEST_PACKET_SIZE, qsc_socket_receive_flag_wait_all);

				if (rlen == KEX_DUPLEX_EXCHANGE_REQUEST_PACKET_SIZE)
				{
					qsmp_packet_header_deserialize(rbuf, &resp);
					qerr = qsmp_header_validate(cns, &resp, qsmp_flag_connect_response, qsmp_flag_exchange_request, cns->rxseq, KEX_DUPLEX_EXCHANGE_REQUEST_MESSAGE_SIZE);

					if (qerr == qsmp_error_none)
					{
						sbuf = (uint8_t*)qsc_memutils_realloc(sbuf, KEX_DUPLEX_EXCHANGE_RESPONSE_PACKET_SIZE);

						if (sbuf != NULL)
						{
							qsc_memutils_clear(sbuf, KEX_DUPLEX_EXCHANGE_RESPONSE_PACKET_SIZE);
							reqt.pmessage = sbuf + QSMP_HEADER_SIZE;

							/* create the exchange response packet */
							qerr = kex_duplex_server_exchange_response(kss, cns, &resp, &reqt);

							if (qerr == qsmp_error_none)
							{
								qsmp_packet_header_serialize(&reqt, sbuf);
								slen = qsc_socket_send(&cns->target, sbuf, KEX_DUPLEX_EXCHANGE_RESPONSE_PACKET_SIZE, qsc_socket_send_flag_none);

								if (slen == KEX_DUPLEX_EXCHANGE_RESPONSE_PACKET_SIZE)
								{
									cns->txseq += 1;
								}
								else
								{
									qerr = qsmp_error_transmit_failure;
								}
							}
						}
						else
						{
							qerr = qsmp_error_memory_allocation;
						}
					}
				}
				else
				{
					qerr = qsmp_error_receive_failure;
				}
			}
			else
			{
				qerr = qsmp_error_memory_allocation;
			}
		}

		/* 3. establish stage */
		if (qerr == qsmp_error_none)
		{
			rbuf = (uint8_t*)qsc_memutils_realloc(rbuf, KEX_DUPLEX_ESTABLISH_REQUEST_PACKET_SIZE);

			if (rbuf != NULL)
			{
				qsc_memutils_clear(rbuf, KEX_DUPLEX_ESTABLISH_REQUEST_PACKET_SIZE);
				resp.pmessage = rbuf + QSMP_HEADER_SIZE;

				/* wait for the establish request */
				rlen = qsc_socket_receive(&cns->target, rbuf, KEX_DUPLEX_ESTABLISH_REQUEST_PACKET_SIZE, qsc_socket_receive_flag_wait_all);

				if (rlen == KEX_DUPLEX_ESTABLISH_REQUEST_PACKET_SIZE)
				{
					qsmp_packet_header_deserialize(rbuf, &resp);
					qerr = qsmp_header_validate(cns, &resp, qsmp_flag_exchange_response, qsmp_flag_establish_request, cns->rxseq, KEX_DUPLEX_ESTABLISH_REQUEST_MESSAGE_SIZE);

					if (qerr == qsmp_error_none)
					{
						sbuf = (uint8_t*)qsc_memutils_realloc(sbuf, KEX_DUPLEX_ESTABLISH_RESPONSE_PACKET_SIZE);

						if (sbuf != NULL)
						{
							qsc_memutils_clear(sbuf, KEX_DUPLEX_ESTABLISH_RESPONSE_PACKET_SIZE);
							reqt.pmessage = sbuf + QSMP_HEADER_SIZE;

							/* create the establish response packet */
							qerr = kex_duplex_server_establish_response(kss, cns, &resp, &reqt);

							/* erase the receive buffer */
							qsc_memutils_clear(rbuf, KEX_DUPLEX_ESTABLISH_REQUEST_PACKET_SIZE);

							if (qerr == qsmp_error_none)
							{
								qsmp_packet_header_serialize(&reqt, sbuf);
								slen = qsc_socket_send(&cns->target, sbuf, KEX_DUPLEX_ESTABLISH_RESPONSE_PACKET_SIZE, qsc_socket_send_flag_none);

								/* erase the transmit buffer */
								qsc_memutils_clear(sbuf, KEX_DUPLEX_ESTABLISH_RESPONSE_PACKET_SIZE);

								if (slen == KEX_DUPLEX_ESTABLISH_RESPONSE_PACKET_SIZE)
								{
									cns->txseq += 1;
								}
								else
								{
									qerr = qsmp_error_transmit_failure;
								}
							}
						}
						else
						{
							qerr = qsmp_error_memory_allocation;
						}
					}
				}
				else
				{
					qerr = qsmp_error_receive_failure;
				}
			}
			else
			{
				qerr = qsmp_error_memory_allocation;
			}
		}

		qsc_memutils_alloc_free(rbuf);
		qsc_memutils_alloc_free(sbuf);
	}
	else
	{
		qerr = qsmp_error_invalid_input;
	}

	kex_duplex_server_reset(kss);

	if (qerr != qsmp_error_none)
	{
		if (cns->target.connection_status == qsc_socket_state_connected)
		{
			kex_send_network_error(&cns->target, qerr);
			qsc_socket_shut_down(&cns->target, qsc_socket_shut_down_flag_both);
		}

		qsmp_connection_state_dispose(cns);
	}

	return qerr;
}

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
static qsmp_errors kex_simplex_client_connect_request(qsmp_kex_simplex_client_state* kcs, qsmp_connection_state* cns, qsmp_network_packet* packetout)
{
	assert(kcs != NULL);
	assert(cns != NULL);
	assert(packetout != NULL);

	qsc_keccak_state kstate = { 0 };
	qsmp_errors qerr;
	uint64_t tm;

	if (kcs != NULL && packetout != NULL)
	{
		tm = qsc_timestamp_datetime_utc();

		if (tm <= kcs->expiration)
		{
			/* copy the key-id and configuration string to the message */
			qsc_memutils_copy(packetout->pmessage, kcs->keyid, QSMP_KEYID_SIZE);
			qsc_memutils_copy(((uint8_t*)packetout->pmessage + QSMP_KEYID_SIZE), QSMP_CONFIG_STRING, QSMP_CONFIG_SIZE);
			/* assemble the connection-request packet */
			qsmp_header_create(packetout, qsmp_flag_connect_request, cns->txseq, KEX_SIMPLEX_CONNECT_REQUEST_MESSAGE_SIZE);

			/* store a hash of the configuration string, and the public signature key: pkh = H(cfg || pvk) */
			qsc_memutils_clear(kcs->schash, QSMP_SIMPLEX_SCHASH_SIZE);
			qsc_sha3_initialize(&kstate);
			qsc_sha3_update(&kstate, qsc_keccak_rate_256, (const uint8_t*)QSMP_CONFIG_STRING, QSMP_CONFIG_SIZE);
			qsc_sha3_update(&kstate, qsc_keccak_rate_256, kcs->keyid, QSMP_KEYID_SIZE);
			qsc_sha3_update(&kstate, qsc_keccak_rate_256, kcs->verkey, QSMP_ASYMMETRIC_VERIFY_KEY_SIZE);
			qsc_sha3_finalize(&kstate, qsc_keccak_rate_256, kcs->schash);

			qerr = qsmp_error_none;
			cns->exflag = qsmp_flag_connect_request;
		}
		else
		{
			cns->exflag = qsmp_flag_none;
			qerr = qsmp_error_key_expired;
		}
	}
	else
	{
		cns->exflag = qsmp_flag_none;
		qerr = qsmp_error_invalid_input;
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
static qsmp_errors kex_simplex_client_exchange_request(const qsmp_kex_simplex_client_state* kcs, qsmp_connection_state* cns, const qsmp_network_packet* packetin, qsmp_network_packet* packetout)
{
	assert(kcs != NULL);
	assert(cns != NULL);
	assert(packetin != NULL);
	assert(packetout != NULL);

	uint8_t khash[QSMP_SIMPLEX_SCHASH_SIZE] = { 0 };
	size_t mlen;
	size_t slen;
	qsmp_errors qerr;

	if (kcs != NULL && packetin != NULL && packetout != NULL)
	{
		slen = 0;
		mlen = QSMP_ASYMMETRIC_SIGNATURE_SIZE + QSMP_SIMPLEX_HASH_SIZE;

		/* verify the asymmetric signature */
		if (qsmp_signature_verify(khash, &slen, packetin->pmessage, mlen, kcs->verkey) == true)
		{
			qsc_keccak_state kstate = { 0 };
			uint8_t phash[QSMP_SIMPLEX_HASH_SIZE] = { 0 };
			uint8_t shdr[QSMP_HEADER_SIZE] = { 0 };
			uint8_t ssec[QSMP_SECRET_SIZE] = { 0 };
			const uint8_t* pubk = packetin->pmessage + mlen;

			qsmp_packet_header_serialize(packetin, shdr);

			/* version 1.2 hash the header and public encapsulation key */
			qsc_sha3_initialize(&kstate);
			qsc_sha3_update(&kstate, qsc_keccak_rate_256, shdr, QSMP_HEADER_SIZE);
			qsc_sha3_update(&kstate, qsc_keccak_rate_256, pubk, QSMP_ASYMMETRIC_PUBLIC_KEY_SIZE);
			qsc_sha3_finalize(&kstate, qsc_keccak_rate_256, phash);

			//qsc_sha3_compute256(phash, pubk, QSMP_ASYMMETRIC_PUBLIC_KEY_SIZE);

			/* verify the public key hash */
			if (qsc_intutils_verify(phash, khash, QSMP_SIMPLEX_HASH_SIZE) == 0)
			{
				uint8_t prnd[(QSC_KECCAK_256_RATE * 2)] = { 0 };

				/* generate, and encapsulate the secret */

				/* store the cipher-text in the message */
				qsmp_cipher_encapsulate(ssec, packetout->pmessage, pubk, qsc_acp_generate);

				/* assemble the exchange-request packet */
				qsmp_header_create(packetout, qsmp_flag_exchange_request, cns->txseq, KEX_SIMPLEX_EXCHANGE_REQUEST_MESSAGE_SIZE);

				/* initialize cSHAKE k = H(sec, sch) */
				qsc_cshake_initialize(&kstate, qsc_keccak_rate_256, ssec, QSMP_SECRET_SIZE, kcs->schash, QSMP_SIMPLEX_SCHASH_SIZE, NULL, 0);
				qsc_cshake_squeezeblocks(&kstate, qsc_keccak_rate_256, prnd, 2);
				/* permute the state so we are not storing the current key */
				qsc_keccak_permute(&kstate, QSC_KECCAK_PERMUTATION_ROUNDS);
				/* copy as next key */
				qsc_memutils_copy(cns->rtcs, (uint8_t*)kstate.state, QSMP_DUPLEX_SYMMETRIC_KEY_SIZE);

				/* initialize the symmetric cipher, and raise client channel-1 tx */
				qsc_rcs_keyparams kp1 = { 0 };
				kp1.key = prnd;
				kp1.keylen = QSMP_SIMPLEX_SYMMETRIC_KEY_SIZE;
				kp1.nonce = prnd + QSMP_SIMPLEX_SYMMETRIC_KEY_SIZE;
				kp1.info = NULL;
				kp1.infolen = 0;
				qsc_rcs_initialize(&cns->txcpr, &kp1, true);

				/* initialize the symmetric cipher, and raise client channel-1 rx */
				qsc_rcs_keyparams kp2 = { 0 };
				kp2.key = prnd + QSMP_SIMPLEX_SYMMETRIC_KEY_SIZE + QSMP_NONCE_SIZE;
				kp2.keylen = QSMP_SIMPLEX_SYMMETRIC_KEY_SIZE;
				kp2.nonce = prnd + QSMP_SIMPLEX_SYMMETRIC_KEY_SIZE + QSMP_NONCE_SIZE + QSMP_SIMPLEX_SYMMETRIC_KEY_SIZE;
				kp2.info = NULL;
				kp2.infolen = 0;
				qsc_rcs_initialize(&cns->rxcpr, &kp2, false);

				cns->exflag = qsmp_flag_exchange_request;
				qerr = qsmp_error_none;
			}
			else
			{
				cns->exflag = qsmp_flag_none;
				qerr = qsmp_error_hash_invalid;
			}
		}
		else
		{
			cns->exflag = qsmp_flag_none;
			qerr = qsmp_error_authentication_failure;
		}
	}
	else
	{
		cns->exflag = qsmp_flag_none;
		qerr = qsmp_error_invalid_input;
	}

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
static qsmp_errors kex_simplex_client_establish_verify(const qsmp_kex_simplex_client_state* kcs, qsmp_connection_state* cns, const qsmp_network_packet* packetin)
{
	assert(kcs != NULL);
	assert(cns != NULL);
	assert(packetin != NULL);

	qsmp_errors qerr;

	if (kcs != NULL && packetin != NULL)
	{
		cns->exflag = qsmp_flag_session_established;
		qerr = qsmp_error_none;
	}
	else
	{
		cns->exflag = qsmp_flag_none;
		qerr = qsmp_error_invalid_input;
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
static qsmp_errors kex_simplex_server_connect_response(qsmp_kex_simplex_server_state* kss, qsmp_connection_state* cns, const qsmp_network_packet* packetin, qsmp_network_packet* packetout)
{
	assert(kss != NULL);
	assert(cns != NULL);
	assert(packetin != NULL);
	assert(packetout != NULL);

	char confs[QSMP_CONFIG_SIZE + 1] = { 0 };
	uint8_t phash[QSMP_SIMPLEX_HASH_SIZE] = { 0 };
	qsc_keccak_state kstate = { 0 };
	qsmp_errors qerr;
	uint64_t tm;
	size_t mlen;

	qerr = qsmp_error_invalid_input;

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
				qsc_memutils_copy(confs, (packetin->pmessage + QSMP_KEYID_SIZE), QSMP_CONFIG_SIZE);

				/* compare the state configuration string to the message configuration string */
				if (qsc_stringutils_compare_strings(confs, QSMP_CONFIG_STRING, QSMP_CONFIG_SIZE) == true)
				{
					uint8_t shdr[QSMP_HEADER_SIZE] = { 0 };

					qsc_memutils_clear(kss->schash, QSMP_SIMPLEX_SCHASH_SIZE);

					/* store a hash of the configuration string, and the public signature key: sch = H(cfg || pvk) */
					qsc_sha3_initialize(&kstate);
					qsc_sha3_update(&kstate, qsc_keccak_rate_256, (const uint8_t*)QSMP_CONFIG_STRING, QSMP_CONFIG_SIZE);
					qsc_sha3_update(&kstate, qsc_keccak_rate_256, kss->keyid, QSMP_KEYID_SIZE);
					qsc_sha3_update(&kstate, qsc_keccak_rate_256, kss->verkey, QSMP_ASYMMETRIC_VERIFY_KEY_SIZE);
					qsc_sha3_finalize(&kstate, qsc_keccak_rate_256, kss->schash);

					/* initialize the packet and asymmetric encryption keys */
					qsc_memutils_clear(kss->pubkey, QSMP_ASYMMETRIC_PUBLIC_KEY_SIZE);
					qsc_memutils_clear(kss->prikey, QSMP_ASYMMETRIC_PRIVATE_KEY_SIZE);

					/* generate the asymmetric encryption key-pair */
					qsmp_cipher_generate_keypair(kss->pubkey, kss->prikey, qsc_acp_generate);

					/* assemble the connection-response packet */
					qsmp_header_create(packetout, qsmp_flag_connect_response, cns->txseq, KEX_SIMPLEX_CONNECT_RESPONSE_MESSAGE_SIZE);
					qsmp_packet_header_serialize(packetout, shdr);

					/* version 1.2 hash the header and public encapsulation key */
					qsc_sha3_initialize(&kstate);
					qsc_sha3_update(&kstate, qsc_keccak_rate_256, shdr, QSMP_HEADER_SIZE);
					qsc_sha3_update(&kstate, qsc_keccak_rate_256, kss->pubkey, QSMP_ASYMMETRIC_PUBLIC_KEY_SIZE);
					qsc_sha3_finalize(&kstate, qsc_keccak_rate_256, phash);

					/* sign the hash and add it to the message */
					mlen = 0;
					qsmp_signature_sign(packetout->pmessage, &mlen, phash, QSMP_SIMPLEX_HASH_SIZE, kss->sigkey, qsc_acp_generate);

					/* copy the public key to the message */
					qsc_memutils_copy(((uint8_t*)packetout->pmessage + mlen), kss->pubkey, QSMP_ASYMMETRIC_PUBLIC_KEY_SIZE);

					qerr = qsmp_error_none;
					cns->exflag = qsmp_flag_connect_response;
				}
				else
				{
					qerr = qsmp_error_unknown_protocol;
				}
			}
			else
			{
				qerr = qsmp_error_key_expired;
			}
		}
		else
		{
			qerr = qsmp_error_key_unrecognized;
		}
	}

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
static qsmp_errors kex_simplex_server_exchange_response(const qsmp_kex_simplex_server_state* kss, qsmp_connection_state* cns, const qsmp_network_packet* packetin, qsmp_network_packet* packetout)
{
	assert(kss != NULL);
	assert(cns != NULL);
	assert(packetin != NULL);
	assert(packetout != NULL);

	qsmp_errors qerr;

	if (kss != NULL && packetin != NULL && packetout != NULL)
	{
		uint8_t ssec[QSMP_SECRET_SIZE] = { 0 };

		/* decapsulate the shared secret */
		if (qsmp_cipher_decapsulate(ssec, packetin->pmessage, kss->prikey) == true)
		{
			qsc_keccak_state kstate = { 0 };
			uint8_t prnd[(QSC_KECCAK_256_RATE * 2)] = { 0 };

			/* initialize cSHAKE k = H(ssec, sch) */
			qsc_cshake_initialize(&kstate, qsc_keccak_rate_256, ssec, sizeof(ssec), kss->schash, QSMP_SIMPLEX_SCHASH_SIZE, NULL, 0);
			qsc_cshake_squeezeblocks(&kstate, qsc_keccak_rate_256, prnd, 2);
			/* permute the state so we are not storing the current key */
			qsc_keccak_permute(&kstate, QSC_KECCAK_PERMUTATION_ROUNDS);
			/* copy as next key */
			qsc_memutils_copy(cns->rtcs, (uint8_t*)kstate.state, QSMP_DUPLEX_SYMMETRIC_KEY_SIZE);

			/* initialize the symmetric cipher, and raise client channel-1 tx */
			qsc_rcs_keyparams kp1 = { 0 };
			kp1.key = prnd;
			kp1.keylen = QSMP_SIMPLEX_SYMMETRIC_KEY_SIZE;
			kp1.nonce = prnd + QSMP_SIMPLEX_SYMMETRIC_KEY_SIZE;
			kp1.info = NULL;
			kp1.infolen = 0;
			qsc_rcs_initialize(&cns->rxcpr, &kp1, false);

			/* initialize the symmetric cipher, and raise client channel-1 rx */
			qsc_rcs_keyparams kp2 = { 0 };
			kp2.key = prnd + QSMP_SIMPLEX_SYMMETRIC_KEY_SIZE + QSMP_NONCE_SIZE;
			kp2.keylen = QSMP_SIMPLEX_SYMMETRIC_KEY_SIZE;
			kp2.nonce = prnd + QSMP_SIMPLEX_SYMMETRIC_KEY_SIZE + QSMP_NONCE_SIZE + QSMP_SIMPLEX_SYMMETRIC_KEY_SIZE;
			kp2.info = NULL;
			kp2.infolen = 0;
			qsc_rcs_initialize(&cns->txcpr, &kp2, true);

			/* assemble the exchange-response packet */
			qsmp_header_create(packetout, qsmp_flag_exchange_response, cns->txseq, KEX_SIMPLEX_EXCHANGE_RESPONSE_MESSAGE_SIZE);

			qerr = qsmp_error_none;
			cns->exflag = qsmp_flag_session_established;
		}
		else
		{
			qerr = qsmp_error_decapsulation_failure;
			cns->exflag = qsmp_flag_none;
		}
	}
	else
	{
		cns->exflag = qsmp_flag_none;
		qerr = qsmp_error_invalid_input;
	}

	return qerr;
}

qsmp_errors qsmp_kex_simplex_client_key_exchange(qsmp_kex_simplex_client_state* kcs, qsmp_connection_state* cns)
{
	assert(kcs != NULL);
	assert(cns != NULL);

	uint8_t* rbuf;
	uint8_t* sbuf;
	size_t rlen;
	size_t slen;
	qsmp_errors qerr;

	if (kcs != NULL && cns != NULL)
	{
		sbuf = qsc_memutils_malloc(KEX_SIMPLEX_CONNECT_REQUEST_PACKET_SIZE);

		if (sbuf != NULL)
		{
			qsmp_network_packet reqt = { 0 };

			/* create the connection request packet */
			qsc_memutils_clear(sbuf, KEX_SIMPLEX_CONNECT_REQUEST_PACKET_SIZE);
			reqt.pmessage = sbuf + QSMP_HEADER_SIZE;

			qerr = kex_simplex_client_connect_request(kcs, cns, &reqt);
			qsmp_packet_header_serialize(&reqt, sbuf);

			if (qerr == qsmp_error_none)
			{
				/* send the connection request */
				slen = qsc_socket_send(&cns->target, sbuf, KEX_SIMPLEX_CONNECT_REQUEST_PACKET_SIZE, qsc_socket_send_flag_none);

				if (slen == KEX_SIMPLEX_CONNECT_REQUEST_PACKET_SIZE)
				{
					cns->txseq += 1;
					rbuf = qsc_memutils_malloc(KEX_SIMPLEX_CONNECT_RESPONSE_PACKET_SIZE);

					if (rbuf != NULL)
					{
						qsmp_network_packet resp = { 0 };

						qsc_memutils_clear(rbuf, KEX_SIMPLEX_CONNECT_RESPONSE_PACKET_SIZE);
						resp.pmessage = rbuf + QSMP_HEADER_SIZE;

						/* blocking receive waits for server */
						rlen = qsc_socket_receive(&cns->target, rbuf, KEX_SIMPLEX_CONNECT_RESPONSE_PACKET_SIZE, qsc_socket_receive_flag_wait_all);

						if (rlen == KEX_SIMPLEX_CONNECT_RESPONSE_PACKET_SIZE)
						{
							qsmp_packet_header_deserialize(rbuf, &resp);
							qerr = qsmp_header_validate(cns, &resp, qsmp_flag_connect_request, qsmp_flag_connect_response, cns->rxseq, KEX_SIMPLEX_CONNECT_RESPONSE_MESSAGE_SIZE);

							if (qerr == qsmp_error_none)
							{
								sbuf = qsc_memutils_realloc(sbuf, KEX_SIMPLEX_EXCHANGE_REQUEST_PACKET_SIZE);

								if (sbuf != NULL)
								{
									/* clear the request packet */
									qsc_memutils_clear(sbuf, KEX_SIMPLEX_EXCHANGE_REQUEST_PACKET_SIZE);
									reqt.pmessage = sbuf + QSMP_HEADER_SIZE;

									/* create the exstart request packet */
									qerr = kex_simplex_client_exchange_request(kcs, cns, &resp, &reqt);
									qsmp_packet_header_serialize(&reqt, sbuf);
									
									if (qerr == qsmp_error_none)
									{
										slen = qsc_socket_send(&cns->target, sbuf, KEX_SIMPLEX_EXCHANGE_REQUEST_PACKET_SIZE, qsc_socket_send_flag_none);
										/* clear the transmit buffer */
										qsc_memutils_clear(sbuf, KEX_SIMPLEX_EXCHANGE_REQUEST_PACKET_SIZE);

										if (slen == KEX_SIMPLEX_EXCHANGE_REQUEST_PACKET_SIZE)
										{
											cns->txseq += 1;
											rbuf = qsc_memutils_realloc(rbuf, KEX_SIMPLEX_EXCHANGE_RESPONSE_PACKET_SIZE);

											if (rbuf != NULL)
											{
												qsc_memutils_clear(rbuf, KEX_SIMPLEX_EXCHANGE_RESPONSE_PACKET_SIZE);
												resp.pmessage = rbuf + QSMP_HEADER_SIZE;

												rlen = qsc_socket_receive(&cns->target, rbuf, KEX_SIMPLEX_EXCHANGE_RESPONSE_PACKET_SIZE, qsc_socket_receive_flag_wait_all);

												if (rlen == KEX_SIMPLEX_EXCHANGE_RESPONSE_PACKET_SIZE)
												{
													qsmp_packet_header_deserialize(rbuf, &resp);
													qerr = qsmp_header_validate(cns, &resp, qsmp_flag_exchange_request, qsmp_flag_exchange_response, cns->rxseq, KEX_SIMPLEX_EXCHANGE_RESPONSE_MESSAGE_SIZE);

													if (qerr == qsmp_error_none)
													{
														/* verify the exchange  */
														qerr = kex_simplex_client_establish_verify(kcs, cns, &resp);
														/* clear the transmit buffer */
														qsc_memutils_clear(rbuf, KEX_SIMPLEX_EXCHANGE_RESPONSE_PACKET_SIZE);
													}
													else
													{
														qerr = qsmp_error_packet_unsequenced;
													}
												}
												else
												{
													qerr = qsmp_error_receive_failure;
												}
											}
											else
											{
												qerr = qsmp_error_memory_allocation;
											}
										}
										else
										{
											qerr = qsmp_error_transmit_failure;
										}
									}
								}
								else
								{
									qerr = qsmp_error_memory_allocation;
								}
							}
							else
							{
								qerr = qsmp_error_packet_unsequenced;
							}
						}
						else
						{
							qerr = qsmp_error_receive_failure;
						}

						qsc_memutils_alloc_free(rbuf);
					}
					else
					{
						qerr = qsmp_error_memory_allocation;
					}
				}
				else
				{
					qerr = qsmp_error_transmit_failure;
				}
			}

			qsc_memutils_alloc_free(sbuf);
		}
		else
		{
			qerr = qsmp_error_memory_allocation;
		}

		kex_simplex_client_reset(kcs);

		if (qerr != qsmp_error_none)
		{
			if (cns->target.connection_status == qsc_socket_state_connected)
			{
				kex_send_network_error(&cns->target, qerr);
				qsc_socket_shut_down(&cns->target, qsc_socket_shut_down_flag_both);
			}

			qsmp_connection_state_dispose(cns);
		}
	}
	else
	{
		qerr = qsmp_error_invalid_input;
	}

	return qerr;
}

qsmp_errors qsmp_kex_simplex_server_key_exchange(qsmp_kex_simplex_server_state* kss, qsmp_connection_state* cns)
{
	assert(kss != NULL);
	assert(cns != NULL);

	uint8_t* rbuf;
	uint8_t* sbuf;
	size_t rlen;
	size_t slen;
	qsmp_errors qerr;

	rbuf = qsc_memutils_malloc(KEX_SIMPLEX_CONNECT_REQUEST_PACKET_SIZE);

	if (rbuf != NULL)
	{
		qsmp_network_packet reqt = { 0 };

		qsc_memutils_clear(rbuf, KEX_SIMPLEX_CONNECT_REQUEST_PACKET_SIZE);
		reqt.pmessage = rbuf + QSMP_HEADER_SIZE;

		/* blocking receive waits for client */
		rlen = qsc_socket_receive(&cns->target, rbuf, KEX_SIMPLEX_CONNECT_REQUEST_PACKET_SIZE, qsc_socket_receive_flag_wait_all);

		if (rlen == KEX_SIMPLEX_CONNECT_REQUEST_PACKET_SIZE)
		{
			/* convert client request to packet */
			qsmp_packet_header_deserialize(rbuf, &reqt);
			qerr = qsmp_header_validate(cns, &reqt, qsmp_flag_none, qsmp_flag_connect_request, cns->rxseq, KEX_SIMPLEX_CONNECT_REQUEST_MESSAGE_SIZE);

			if (qerr == qsmp_error_none)
			{
				qsmp_network_packet resp = { 0 };

				sbuf = qsc_memutils_malloc(KEX_SIMPLEX_CONNECT_RESPONSE_PACKET_SIZE);

				if (sbuf != NULL)
				{
					qsc_memutils_clear(sbuf, KEX_SIMPLEX_CONNECT_RESPONSE_PACKET_SIZE);
					resp.pmessage = sbuf + QSMP_HEADER_SIZE;

					/* create the connection response packet */
					qerr = kex_simplex_server_connect_response(kss, cns, &reqt, &resp);

					if (qerr == qsmp_error_none)
					{
						qsmp_packet_header_serialize(&resp, sbuf);
						slen = qsc_socket_send(&cns->target, sbuf, KEX_SIMPLEX_CONNECT_RESPONSE_PACKET_SIZE, qsc_socket_send_flag_none);

						if (slen == KEX_SIMPLEX_CONNECT_RESPONSE_PACKET_SIZE)
						{
							cns->txseq += 1;
							rbuf = qsc_memutils_realloc(rbuf, KEX_SIMPLEX_EXCHANGE_REQUEST_PACKET_SIZE);

							if (rbuf != NULL)
							{
								qsc_memutils_clear(rbuf, KEX_SIMPLEX_EXCHANGE_REQUEST_PACKET_SIZE);
								reqt.pmessage = rbuf + QSMP_HEADER_SIZE;

								/* wait for the exchange request */
								rlen = qsc_socket_receive(&cns->target, rbuf, KEX_SIMPLEX_EXCHANGE_REQUEST_PACKET_SIZE, qsc_socket_receive_flag_wait_all);

								if (rlen == KEX_SIMPLEX_EXCHANGE_REQUEST_PACKET_SIZE)
								{
									qsmp_packet_header_deserialize(rbuf, &reqt);
									qerr = qsmp_header_validate(cns, &reqt, qsmp_flag_connect_response, qsmp_flag_exchange_request, cns->rxseq, KEX_SIMPLEX_EXCHANGE_REQUEST_MESSAGE_SIZE);

									if (qerr == qsmp_error_none)
									{
										qsc_memutils_clear(sbuf, KEX_SIMPLEX_EXCHANGE_RESPONSE_PACKET_SIZE);
										/* create the exchange response packet */
										qerr = kex_simplex_server_exchange_response(kss, cns, &reqt, &resp);
										/* clear the receive buffer */
										qsc_memutils_clear(rbuf, KEX_SIMPLEX_EXCHANGE_REQUEST_PACKET_SIZE);

										if (qerr == qsmp_error_none)
										{
											qsmp_packet_header_serialize(&resp, sbuf);
											/* send the exchange response */
											slen = qsc_socket_send(&cns->target, sbuf, KEX_SIMPLEX_EXCHANGE_RESPONSE_PACKET_SIZE, qsc_socket_send_flag_none);
											/* clear the transmit buffer */
											qsc_memutils_clear(sbuf, KEX_SIMPLEX_EXCHANGE_RESPONSE_PACKET_SIZE);

											if (slen == KEX_SIMPLEX_EXCHANGE_RESPONSE_PACKET_SIZE)
											{
												cns->txseq += 1;
											}
											else
											{
												qerr = qsmp_error_transmit_failure;
											}
										}
									}
								}
								else
								{
									qerr = qsmp_error_receive_failure;
								}
							}
							else
							{
								qerr = qsmp_error_memory_allocation;
							}
						}
						else
						{
							qerr = qsmp_error_transmit_failure;
						}
					}

					qsc_memutils_alloc_free(sbuf);
				}
				else
				{
					qerr = qsmp_error_memory_allocation;
				}
			}
			else
			{
				qerr = qsmp_error_packet_unsequenced;
			}
		}
		else
		{
			qerr = qsmp_error_receive_failure;
		}

		qsc_memutils_alloc_free(rbuf);
	}
	else
	{
		qerr = qsmp_error_memory_allocation;
	}

	kex_simplex_server_reset(kss);

	if (qerr != qsmp_error_none)
	{
		if (cns->target.connection_status == qsc_socket_state_connected)
		{
			kex_send_network_error(&cns->target, qerr);
			qsc_socket_shut_down(&cns->target, qsc_socket_shut_down_flag_both);
		}

		qsmp_connection_state_dispose(cns);
	}

	return qerr;
}

bool qsmp_kex_test()
{
	qsmp_kex_simplex_client_state skcs = { 0 };
	qsmp_kex_simplex_server_state skss = { 0 };
	qsmp_kex_duplex_client_state dkcs = { 0 };
	qsmp_kex_duplex_server_state dkss = { 0 };
	qsmp_connection_state cnc = { 0 };
	qsmp_connection_state cns = { 0 };
	qsmp_network_packet pckclt = { 0 };
	qsmp_network_packet pcksrv = { 0 };
	uint8_t mclt[QSMP_HEADER_SIZE + QSMP_ASYMMETRIC_CIPHER_TEXT_SIZE + QSMP_ASYMMETRIC_PUBLIC_KEY_SIZE + QSMP_DUPLEX_HASH_SIZE + QSMP_ASYMMETRIC_SIGNATURE_SIZE] = { 0 };
	uint8_t msrv[QSMP_HEADER_SIZE + QSMP_ASYMMETRIC_CIPHER_TEXT_SIZE + QSMP_ASYMMETRIC_PUBLIC_KEY_SIZE + QSMP_DUPLEX_HASH_SIZE + QSMP_ASYMMETRIC_SIGNATURE_SIZE] = { 0 };
	qsmp_errors qerr;
	bool res;

	pckclt.pmessage = mclt;
	pcksrv.pmessage = msrv;
	qsmp_signature_generate_keypair(dkcs.verkey, dkcs.sigkey, qsc_acp_generate);
	qsmp_signature_generate_keypair(dkss.verkey, dkss.sigkey, qsc_acp_generate);
	qsc_memutils_copy(dkcs.rverkey, dkss.verkey, QSMP_ASYMMETRIC_VERIFY_KEY_SIZE);
	qsc_memutils_copy(dkss.rverkey, dkcs.verkey, QSMP_ASYMMETRIC_VERIFY_KEY_SIZE);

	dkcs.expiration = qsc_timestamp_datetime_utc() + QSMP_PUBKEY_DURATION_SECONDS;
	dkss.expiration = dkcs.expiration;

	res = false;
	qerr = kex_duplex_client_connect_request(&dkcs, &cnc, &pckclt);

	if (qerr == qsmp_error_none)
	{
		qerr = kex_duplex_server_connect_response(&dkss, &cns, &pckclt, &pcksrv);

		if (qerr == qsmp_error_none)
		{
			qerr = kex_duplex_client_exchange_request(&dkcs, &cnc, &pcksrv, &pckclt);

			if (qerr == qsmp_error_none)
			{
				qerr = kex_duplex_server_exchange_response(&dkss, &cns, &pckclt, &pcksrv);

				if (qerr == qsmp_error_none)
				{
					qerr = kex_duplex_client_establish_request(&dkcs, &cnc, &pcksrv, &pckclt);

					if (qerr == qsmp_error_none)
					{
						qerr = kex_duplex_server_establish_response(&dkss, &cns, &pckclt, &pcksrv);

						if (qerr == qsmp_error_none)
						{
							qerr = kex_duplex_client_establish_verify(&dkcs, &cnc, &pcksrv);

							if (qerr == qsmp_error_none)
							{
								res = true;
							}
						}
					}
				}
			}
		}
	}

	if (res == true)
	{
		qsmp_signature_generate_keypair(skss.verkey, skss.sigkey, qsc_acp_generate);
		qsc_memutils_copy(skcs.verkey, skss.verkey, QSMP_ASYMMETRIC_VERIFY_KEY_SIZE);

		skcs.expiration = qsc_timestamp_datetime_utc() + QSMP_PUBKEY_DURATION_SECONDS;
		skss.expiration = skcs.expiration;

		qerr = kex_simplex_client_connect_request(&skcs, &cnc, &pckclt);

		if (qerr == qsmp_error_none)
		{
			qerr = kex_simplex_server_connect_response(&skss, &cns, &pckclt, &pcksrv);

			if (qerr == qsmp_error_none)
			{
				qerr = kex_simplex_client_exchange_request(&skcs, &cnc, &pcksrv, &pckclt);

				if (qerr == qsmp_error_none)
				{
					qerr = kex_simplex_server_exchange_response(&skss, &cns, &pckclt, &pcksrv);

					if (qerr == qsmp_error_none)
					{
						qerr = kex_simplex_client_establish_verify(&skcs, &cnc, &pcksrv);

						if (qerr == qsmp_error_none)
						{
							res = true;
						}
					}
				}
			}
		}
	}

	return res;
}


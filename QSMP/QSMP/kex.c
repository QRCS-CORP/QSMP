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

static void kex_client_send_error(const qsc_socket* sock, qsmp_errors err)
{
	assert(sock != NULL);

	qsmp_packet resp = { 0 };
	
	size_t plen;

	if (sock != NULL)
	{
		if (qsc_socket_is_connected(sock) == true)
		{
			uint8_t spct[QSMP_HEADER_SIZE + sizeof(uint8_t)] = { 0 };
			uint8_t pmsg[sizeof(uint8_t)] = { 0 };

			resp.pmessage = pmsg;
			resp.flag = qsmp_flag_error_condition;
			resp.sequence = 0xFF;
			resp.msglen = 1;
			resp.pmessage[0] = (uint8_t)err;
			plen = qsmp_packet_to_stream(&resp, spct);
			qsc_socket_send(sock, spct, plen, qsc_socket_send_flag_none);
		}
	}
}

static void kex_server_send_error(const qsc_socket* sock, qsmp_errors error)
{
	assert(sock != NULL);

	if (qsc_socket_is_connected(sock) == true)
	{
		qsmp_packet resp = { 0 };
		uint8_t spct[QSMP_HEADER_SIZE + sizeof(uint8_t)] = { 0 };
		uint8_t pmsg[sizeof(uint8_t)] = { 0 };
		size_t plen;

		resp.pmessage = pmsg;
		qsmp_packet_error_message(&resp, error);
		plen = qsmp_packet_to_stream(&resp, spct);
		qsc_socket_send(sock, spct, plen, qsc_socket_send_flag_none);
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
<-, ->		-Assignment operators
:=, !=, ?=	-Equality operators; equals, not equals, evaluate
C			-The client host, initiates the exchange
S			-The server host, listens for a connection
AG			-The asymmetric cipher key generator function
-AEsk		-The asymmetric decapsulation function and secret key
AEpk		-The asymmetric encapsulation function and public key
ASsk		-Sign data with the secret signature key
AVpk		-Verify a signature the public verification key
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
spkh		-The signed hash of the asymmetric public encapsulation-key
*/

/*
Connect Request:
The client stores a hash of the configuration string, and both of the public asymmetric signature verification-keys,
which is used as a session cookie during the exchange.
sch <- H(cfg || pvka || pvkb)
The client sends the key identity string, and the configuration string to the server.
C{ kid, cfg }->S
*/
static qsmp_errors kex_duplex_client_connect_request(qsmp_kex_duplex_client_state* kcs, qsmp_connection_state* cns, qsmp_packet* packetout)
{
	assert(kcs != NULL);
	assert(packetout != NULL);

	qsc_keccak_state kstate = { 0 };
	qsmp_errors qerr;
	uint64_t tm;

	if (kcs != NULL && packetout != NULL)
	{
		tm = qsc_timestamp_epochtime_seconds();

		if (tm <= kcs->expiration)
		{
			/* copy the key-id and configuration string to the message */
			qsc_memutils_copy(packetout->pmessage, kcs->keyid, QSMP_KEYID_SIZE);
			qsc_memutils_copy(((uint8_t*)packetout->pmessage + QSMP_KEYID_SIZE), QSMP_CONFIG_STRING, QSMP_CONFIG_SIZE);
			/* assemble the connection-request packet */
			packetout->msglen = QSMP_KEYID_SIZE + QSMP_CONFIG_SIZE;
			packetout->flag = qsmp_flag_connect_request;
			packetout->sequence = cns->txseq;

			/* store a hash of the configuration string, and the public signature keys: pkh = H(cfg || pvka || pvkb) */
			qsc_memutils_clear(kcs->schash, QSMP_DUPLEX_SCHASH_SIZE);
			qsc_sha3_initialize(&kstate);
			qsc_sha3_update(&kstate, qsc_keccak_rate_512, (const uint8_t*)QSMP_CONFIG_STRING, QSMP_CONFIG_SIZE);
			qsc_sha3_update(&kstate, qsc_keccak_rate_512, kcs->keyid, QSMP_KEYID_SIZE);
			qsc_sha3_update(&kstate, qsc_keccak_rate_512, kcs->verkey, QSMP_ASYMMETRIC_VERIFY_KEY_SIZE);
			qsc_sha3_update(&kstate, qsc_keccak_rate_512, kcs->rverkey, QSMP_ASYMMETRIC_VERIFY_KEY_SIZE);
			qsc_sha3_finalize(&kstate, qsc_keccak_rate_512, kcs->schash);

			qerr = qsmp_error_none;
			cns->exflag = qsmp_flag_connect_request;
		}
		else
		{
			qerr = qsmp_error_key_expired;
			cns->exflag = qsmp_flag_none;
		}
	}
	else
	{
		qerr = qsmp_error_invalid_input;
	}

	return qerr;
}

/*
Exchange Request:
The client verifies the signature of the hash, then generates its own hash of the public key, 
and compares it with the one contained in the message. 
If the hash matches, the client uses the public-key to encapsulate a shared secret. 
If the hash does not match, the key exchange is aborted.
cond <- AVpk(H(pk)) = (true ?= pk : 0)
cpta, seca -> AEpk(seca)
The client stores the shared secret (seca), which along with a second shared secret and the session cookie, 
will be used to generate the session keys.
The client generates an asymmetric encryption key-pair, stores the private key, 
hashes the public encapsulation key and cipher-text, and then signs the hash using its asymmetric signature key.
pk, sk <- AG(cfg)
kch <- H(pk || cpta)
skch <- ASsk(kch)
The client sends a response message containing the signed hash of its public asymmetric encapsulation-key and cipher-text, 
and a copy of the cipher-text and encapsulation key.
C{ cpta, pk, skch } -> S
*/
static qsmp_errors kex_duplex_client_exchange_request(qsmp_kex_duplex_client_state* kcs, qsmp_connection_state* cns, const qsmp_packet* packetin, qsmp_packet* packetout)
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
		if (cns->exflag == qsmp_flag_connect_request && packetin->flag == qsmp_flag_connect_response)
		{
			slen = 0;

#if defined(QSMP_FALCON_SIGNATURE)
			const size_t FLCDLM = 42;
			/* Note: accounts for a signature encoding length variance in falcon signature size,
			by decoding the signature size directly from the raw signature */
			mlen = ((size_t)packetin->pmessage[0] << 8) | (size_t)packetin->pmessage[1] + FLCDLM + QSMP_DUPLEX_HASH_SIZE;
#else
			mlen = QSMP_ASYMMETRIC_SIGNATURE_SIZE + QSMP_DUPLEX_HASH_SIZE;
#endif

			/* verify the asymmetric signature */
			if (qsmp_signature_verify(khash, &slen, packetin->pmessage, mlen, kcs->rverkey) == true)
			{
				uint8_t phash[QSMP_DUPLEX_HASH_SIZE] = { 0 };
				uint8_t pubk[QSMP_ASYMMETRIC_PUBLIC_KEY_SIZE] = { 0 };

				qsc_memutils_copy(pubk, (packetin->pmessage + mlen), QSMP_ASYMMETRIC_PUBLIC_KEY_SIZE);

				/* verify the public key hash */
				qsc_sha3_compute512(phash, pubk, QSMP_ASYMMETRIC_PUBLIC_KEY_SIZE);

				if (qsc_intutils_verify(phash, khash, QSMP_DUPLEX_HASH_SIZE) == 0)
				{
					/* generate, and encapsulate the secret */
					qsc_memutils_clear(packetout->pmessage, QSMP_MESSAGE_MAX);
					/* store the cipher-text in the message */
					qsmp_cipher_encapsulate(kcs->ssec, packetout->pmessage, pubk, qsc_acp_generate);

					/* generate the asymmetric encryption key-pair */
					qsmp_cipher_generate_keypair(kcs->pubkey, kcs->prikey, qsc_acp_generate);
					/* copy the public key to the message */
					qsc_memutils_copy(((uint8_t*)packetout->pmessage + QSMP_ASYMMETRIC_CIPHER_TEXT_SIZE), kcs->pubkey, QSMP_ASYMMETRIC_PUBLIC_KEY_SIZE);

					/* hash the public encapsulation key and cipher-text */
					qsc_sha3_compute512(phash, packetout->pmessage, QSMP_ASYMMETRIC_CIPHER_TEXT_SIZE + QSMP_ASYMMETRIC_PUBLIC_KEY_SIZE);

					/* sign the hash and add it to the message */
					mlen = 0;
					qsmp_signature_sign(packetout->pmessage + QSMP_ASYMMETRIC_CIPHER_TEXT_SIZE + QSMP_ASYMMETRIC_PUBLIC_KEY_SIZE, &mlen, phash, QSMP_DUPLEX_HASH_SIZE, kcs->sigkey, qsc_acp_generate);

					/* assemble the exchange-request packet */
					packetout->flag = qsmp_flag_exchange_request;
					packetout->msglen = QSMP_ASYMMETRIC_CIPHER_TEXT_SIZE + QSMP_ASYMMETRIC_PUBLIC_KEY_SIZE + QSMP_DUPLEX_HASH_SIZE + QSMP_ASYMMETRIC_SIGNATURE_SIZE;
					packetout->sequence = cns->txseq;

					qerr = qsmp_error_none;
					cns->exflag = qsmp_flag_exchange_request;
				}
				else
				{
					qerr = qsmp_error_hash_invalid;
					cns->exflag = qsmp_flag_none;
				}
			}
			else
			{
				qerr = qsmp_error_authentication_failure;
				cns->exflag = qsmp_flag_none;
			}
		}
		else
		{
			qerr = qsmp_error_invalid_request;
			cns->exflag = qsmp_flag_none;
		}
	}
	else
	{
		qerr = qsmp_error_invalid_input;
	}

	return qerr;
}

/*
The client verifies the signature of the hash, then generates its own hash of the cipher-text, 
and compares it with the one contained in the message. 
If the hash matches, the client decapsulates the shared secret (secb). If the hash comparison fails,
the key exchange is aborted.
cond <- AVpk(H(cptb)) = (true ?= cptb : 0)
secb <- -AEsk(cptb)
The client combines both secrets and the session cookie to create the session keys, 
and two unique nonce, one for each channel of the communications stream.
k1, k2, n1, n2 <- KDF(seca, secb, sch)
The receive and transmit channel ciphers are initialized.
cprrx(k2,n2)
cprtx(k1,n1)
An optional tweak value can be added to the cipher’s initialization function. 
This tweak is mixed with the key using the internal key derivation function. 
This tweak can be a tertiary key provided by the server, or a hash of multiple keys from a list of trusted key holders;
t <- H(s1, s2, ..., sn)
cpr(k, n, t)
The client sends an empty message with the establish request flag, 
indicating that both encrypted channels of the tunnel have been raised, 
and that the tunnel is in the operational state. 
In the event of an error, the client sends an error message to the server, 
aborting the exchange and terminating the connection on both hosts.
C{ f } -> S
*/
static qsmp_errors kex_duplex_client_establish_request(const qsmp_kex_duplex_client_state* kcs, qsmp_connection_state* cns, const qsmp_packet* packetin, qsmp_packet* packetout)
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
		if (cns->exflag == qsmp_flag_exchange_request && packetin->flag == qsmp_flag_exchange_response)
		{
			slen = 0;

#if defined(QSMP_FALCON_SIGNATURE)
			const size_t FLCDLM = 42;
			/* Note: accounts for a signature encoding length variance in falcon signature size,
			by decoding the signature size directly from the raw signature */
			mlen = ((size_t)packetin->pmessage[0] << 8) | (size_t)packetin->pmessage[1] + FLCDLM + QSMP_DUPLEX_HASH_SIZE;
#else
			mlen = QSMP_ASYMMETRIC_SIGNATURE_SIZE + QSMP_DUPLEX_HASH_SIZE;
#endif

			/* verify the asymmetric signature */
			if (qsmp_signature_verify(khash, &slen, packetin->pmessage + QSMP_ASYMMETRIC_CIPHER_TEXT_SIZE, mlen, kcs->rverkey) == true)
			{
				uint8_t phash[QSMP_DUPLEX_HASH_SIZE] = { 0 };
				uint8_t secb[QSMP_SECRET_SIZE] = { 0 };

				/* verify the cipher-text hash */
				qsc_sha3_compute512(phash, packetin->pmessage, QSMP_ASYMMETRIC_CIPHER_TEXT_SIZE);

				if (qsc_intutils_verify(phash, khash, QSMP_DUPLEX_HASH_SIZE) == 0)
				{
					if (qsmp_cipher_decapsulate(secb, packetin->pmessage, kcs->prikey) == true)
					{
						qsc_keccak_state kstate = { 0 };
						uint8_t hdr[QSMP_HEADER_SIZE] = { 0 };
						uint8_t prnd[(QSC_KECCAK_512_RATE * 3)] = { 0 };

						/* initialize cSHAKE k = H(seca, secb, pkh) */
						qsc_cshake_initialize(&kstate, qsc_keccak_rate_512, kcs->ssec, QSMP_SECRET_SIZE, kcs->schash, QSMP_DUPLEX_SCHASH_SIZE, secb, sizeof(secb));
						qsc_cshake_squeezeblocks(&kstate, qsc_keccak_rate_512, prnd, 3);
						/* permute the state so we are not storing the current key */
						qsc_keccak_permute(&kstate, QSC_KECCAK_PERMUTATION_ROUNDS);
						/* copy as next key */
						qsc_memutils_copy(cns->rtcs, (uint8_t*)kstate.state, QSMP_DUPLEX_SYMMETRIC_KEY_SIZE);

						/* initialize the symmetric cipher, and raise client channel-1 tx */
						qsc_rcs_keyparams kp1;
						kp1.key = prnd;
						kp1.keylen = QSMP_DUPLEX_SYMMETRIC_KEY_SIZE;
						kp1.nonce = prnd + QSMP_DUPLEX_SYMMETRIC_KEY_SIZE;
						kp1.info = NULL;
						kp1.infolen = 0;
						qsc_rcs_initialize(&cns->txcpr, &kp1, true);

						/* initialize the symmetric cipher, and raise client channel-1 rx */
						qsc_rcs_keyparams kp2;
						kp2.key = prnd + QSMP_DUPLEX_SYMMETRIC_KEY_SIZE + QSMP_NONCE_SIZE;
						kp2.keylen = QSMP_DUPLEX_SYMMETRIC_KEY_SIZE;
						kp2.nonce = prnd + QSMP_DUPLEX_SYMMETRIC_KEY_SIZE + QSMP_NONCE_SIZE + QSMP_DUPLEX_SYMMETRIC_KEY_SIZE;
						kp2.info = NULL;
						kp2.infolen = 0;
						qsc_rcs_initialize(&cns->rxcpr, &kp2, false);

						/* assemble the establish-request packet */
						packetout->flag = qsmp_flag_establish_request;
						packetout->msglen = 0;
						packetout->sequence = cns->txseq;

						/* serialize the packet header and add it to the associated data */
						qsmp_packet_header_serialize(packetout, hdr);

						qerr = qsmp_error_none;
						cns->exflag = qsmp_flag_establish_request;
					}
					else
					{
						qerr = qsmp_error_decapsulation_failure;
						cns->exflag = qsmp_flag_none;
					}
				}
				else
				{
					qerr = qsmp_error_hash_invalid;
					cns->exflag = qsmp_flag_none;
				}
			}
			else
			{
				qerr = qsmp_error_authentication_failure;
				cns->exflag = qsmp_flag_none;
			}
		}
		else
		{
			qerr = qsmp_error_invalid_request;
			cns->exflag = qsmp_flag_none;
		}
	}
	else
	{
		qerr = qsmp_error_invalid_input;
	}

	return qerr;
}

/*
Establish Verify:
The client checks the flag of the establish response packet sent by the server. 
If the flag is set to establish response, the client tunnel is established and in an operational state. 
Otherwise the tunnel is in an error state indicated by the message, 
and the tunnel is torn down on both sides. The client sets the operational state to session established, 
and is now ready to process data.
*/
static qsmp_errors kex_duplex_client_establish_verify(const qsmp_kex_duplex_client_state* kcs, qsmp_connection_state* cns, const qsmp_packet* packetin)
{
	assert(kcs != NULL);
	assert(packetin != NULL);

	qsmp_errors qerr;

	if (kcs != NULL && packetin != NULL)
	{
		if (cns->exflag == qsmp_flag_establish_request && packetin->flag == qsmp_flag_establish_response)
		{
			cns->exflag = qsmp_flag_session_established;
			qerr = qsmp_error_none;
		}
		else
		{
			qerr = qsmp_error_invalid_request;
			cns->exflag = qsmp_flag_none;
		}
	}
	else
	{
		qerr = qsmp_error_invalid_input;
	}

	return qerr;
}

/*
The server responds with either an error message, or a connect response packet.
Any error during the key exchange will generate an error-packet sent to the remote host, 
which will trigger a tear down of the exchange, and the network connection on both sides.
The server first checks that it has the requested asymmetric signature verification key,
corresponding to that host using the key-identity array, 
then verifies that it has a compatible protocol configuration. 
The server stores a hash of the configuration string, key identity, and both public signature verification-keys, 
to create the public key hash, which is used as a session cookie.
sch <- H(cfg || kid || pvka || pvkb)
The server then generates an asymmetric encryption key-pair, stores the private key, 
hashes the public encapsulation key, and then signs the hash of the public encapsulation key using the asymmetric signature key.
The public signature verification key can itself be signed by a ‘chain of trust’ model, 
like X.509, using a signature verification extension to this protocol.
pk,sk <- AG(cfg)
pkh <- H(pk)
spkh <- ASsk(pkh)
The server sends a connect response message containing a signed hash of the public asymmetric encapsulation-key, 
and a copy of that key.
S{ spkh, pk } -> C
*/
static qsmp_errors kex_duplex_server_connect_response(qsmp_kex_duplex_server_state* kss, qsmp_connection_state* cns, const qsmp_packet* packetin, qsmp_packet* packetout)
{
	assert(cns != NULL);
	assert(kss != NULL);
	assert(packetin != NULL);
	assert(packetout != NULL);

	char confs[QSMP_CONFIG_SIZE + 1] = { 0 };
	uint8_t phash[QSMP_DUPLEX_HASH_SIZE] = { 0 };
	qsc_keccak_state kstate = { 0 };
	qsmp_errors qerr;
	uint64_t tm;
	size_t mlen;

	qerr = qsmp_error_invalid_input;

	if (cns != NULL && kss != NULL && packetin != NULL && packetout != NULL)
	{
		if (packetin->flag == qsmp_flag_connect_request)
		{
			uint8_t keyid[QSMP_KEYID_SIZE] = { 0 };

			qsc_memutils_copy(keyid, packetin->pmessage, sizeof(keyid));
			
			/* compare the kid in the message, to stored kids through the interface */
			if (kss->key_query(kss->rverkey, keyid) == true)
			{
				tm = qsc_timestamp_epochtime_seconds();

				/* check the keys expiration date */
				if (tm <= kss->expiration)
				{
					/* get a copy of the configuration string */
					qsc_memutils_copy(confs, packetin->pmessage + QSMP_KEYID_SIZE, QSMP_CONFIG_SIZE);

					/* compare the state configuration string to the message configuration string */
					if (qsc_stringutils_compare_strings(confs, QSMP_CONFIG_STRING, QSMP_CONFIG_SIZE) == true)
					{
						/* store a hash of the session token, the configuration string,
						   and the public signature key: pkh = H(stok || cfg || pvk) */
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

						/* hash the public encapsulation key */
						qsc_sha3_compute512(phash, kss->pubkey, QSMP_ASYMMETRIC_PUBLIC_KEY_SIZE);

						/* sign the hash and add it to the message */
						mlen = 0;
						qsmp_signature_sign(packetout->pmessage, &mlen, phash, QSMP_DUPLEX_HASH_SIZE, kss->sigkey, qsc_acp_generate);

						/* copy the public key to the message */
						qsc_memutils_copy(((uint8_t*)packetout->pmessage + mlen), kss->pubkey, QSMP_ASYMMETRIC_PUBLIC_KEY_SIZE);

						/* assemble the connection-response packet */
						packetout->flag = qsmp_flag_connect_response;
						packetout->msglen = QSMP_DUPLEX_HASH_SIZE + QSMP_ASYMMETRIC_SIGNATURE_SIZE + QSMP_ASYMMETRIC_PUBLIC_KEY_SIZE;
						packetout->sequence = cns->txseq;

						qerr = qsmp_error_none;
						cns->exflag = qsmp_flag_connect_response;
					}
					else
					{
						qerr = qsmp_error_unknown_protocol;
						cns->exflag = qsmp_flag_none;
					}
				}
				else
				{
					qerr = qsmp_error_key_expired;
					cns->exflag = qsmp_flag_none;
				}
			}
			else
			{
				qerr = qsmp_error_key_unrecognized;
				cns->exflag = qsmp_flag_none;
			}
		}
		else
		{
			qerr = qsmp_error_invalid_request;
			cns->exflag = qsmp_flag_none;
		}
	}

	return qerr;
}

/*
Exchange Response:
The server verifies the signature of the hash, then generates its own hash of the public key and cipher-text, 
and compares it with the one contained in the message.
If the hash matches, the server uses the public-key to decapsulate the shared secret.
If the hash comparison fails, the key exchange is aborted.
cond <- AVpk(H(pk || cpta)) = (true ?= cph : 0)
The server decapsulates the second shared-secret, and stores the secret (seca).
seca <- -AEsk(cpta)
The server generates a cipher-text and the second shared secret (secb) using the clients public encapsulation key.
cptb, secb <- AEpk(secb)
The server combines both secrets and the session cookie to create two session keys, and two unique nonce, 
one for each channel of the communications stream.
k1, k2, n1, n2 <- Exp(seca, secb, sch)
The receive and transmit channel ciphers are initialized.
cprrx(k1,n1)
cprtx(k2,n2)
An optional tweak value can be added to the ciphers initialization function. 
The tweak is mixed with the key using the internal KDF function. 
The tweak can be a tertiary key provided by the server, or a hash of multiple keys from a list of trusted key holders.
t <- H(s1, s2, ..., sn)
cpr(k,n,t)
The server then hashes the cipher-text, and signs the hash.
cpth <- H(cptb)
scph <- ASsk(cpth)
The server sends the signed hash of the cipher-text, and the cipher-text to the client.
S{ scph, cptb } -> C
*/
static qsmp_errors kex_duplex_server_exchange_response(const qsmp_kex_duplex_server_state* kss, qsmp_connection_state* cns, const qsmp_packet* packetin, qsmp_packet* packetout)
{
	assert(kss != NULL);
	assert(packetin != NULL);
	assert(packetout != NULL);

	uint8_t khash[QSMP_DUPLEX_SCHASH_SIZE] = { 0 };
	size_t mlen;
	size_t slen;
	qsmp_errors qerr;

	if (kss != NULL && packetin != NULL && packetout != NULL)
	{
		if (cns->exflag == qsmp_flag_connect_response && packetin->flag == qsmp_flag_exchange_request)
		{
			slen = 0;

#if defined(QSMP_FALCON_SIGNATURE)
			const size_t FLCDLM = 42;
			/* Note: accounts for a signature encoding length variance in falcon signature size,
			by decoding the signature size directly from the raw signature */
			mlen = ((size_t)packetin->pmessage[0] << 8) | (size_t)packetin->pmessage[1] + FLCDLM + QSMP_DUPLEX_HASH_SIZE;
#else
			mlen = QSMP_ASYMMETRIC_SIGNATURE_SIZE + QSMP_DUPLEX_HASH_SIZE;
#endif

			/* verify the asymmetric signature */
			if (qsmp_signature_verify(khash, &slen, packetin->pmessage + QSMP_ASYMMETRIC_CIPHER_TEXT_SIZE + QSMP_ASYMMETRIC_PUBLIC_KEY_SIZE, mlen, kss->rverkey) == true)
			{
				uint8_t phash[QSMP_DUPLEX_HASH_SIZE] = { 0 };
				uint8_t seca[QSMP_SECRET_SIZE] = { 0 };
				uint8_t secb[QSMP_SECRET_SIZE] = { 0 };

				/* verify the public key hash */
				qsc_sha3_compute512(phash, packetin->pmessage, QSMP_ASYMMETRIC_CIPHER_TEXT_SIZE + QSMP_ASYMMETRIC_PUBLIC_KEY_SIZE);

				if (qsc_intutils_verify(phash, khash, QSMP_DUPLEX_HASH_SIZE) == 0)
				{
					if (qsmp_cipher_decapsulate(seca, packetin->pmessage, kss->prikey) == true)
					{
						qsc_keccak_state kstate = { 0 };
						uint8_t prnd[(QSC_KECCAK_512_RATE * 3)] = { 0 };

						/* generate, and encapsulate the secret and store the cipher-text in the message */
						qsmp_cipher_encapsulate(secb, packetout->pmessage, packetin->pmessage + QSMP_ASYMMETRIC_CIPHER_TEXT_SIZE, qsc_acp_generate);

						/* hash the cipher-text */
						qsc_sha3_compute512(phash, packetout->pmessage, QSMP_ASYMMETRIC_CIPHER_TEXT_SIZE);

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
						qsc_rcs_keyparams kp1;
						kp1.key = prnd;
						kp1.keylen = QSMP_DUPLEX_SYMMETRIC_KEY_SIZE;
						kp1.nonce = prnd + QSMP_DUPLEX_SYMMETRIC_KEY_SIZE;
						kp1.info = NULL;
						kp1.infolen = 0;
						qsc_rcs_initialize(&cns->rxcpr, &kp1, false);

						/* initialize the symmetric cipher, and raise client channel-1 rx */
						qsc_rcs_keyparams kp2;
						kp2.key = prnd + QSMP_DUPLEX_SYMMETRIC_KEY_SIZE + QSMP_NONCE_SIZE;
						kp2.keylen = QSMP_DUPLEX_SYMMETRIC_KEY_SIZE;
						kp2.nonce = prnd + QSMP_DUPLEX_SYMMETRIC_KEY_SIZE + QSMP_NONCE_SIZE + QSMP_DUPLEX_SYMMETRIC_KEY_SIZE;
						kp2.info = NULL;
						kp2.infolen = 0;
						qsc_rcs_initialize(&cns->txcpr, &kp2, true);

						/* assemble the exstart-request packet */
						packetout->flag = qsmp_flag_exchange_response;
						packetout->msglen = QSMP_ASYMMETRIC_CIPHER_TEXT_SIZE + QSMP_DUPLEX_HASH_SIZE + QSMP_ASYMMETRIC_SIGNATURE_SIZE;
						packetout->sequence = cns->txseq;

						qerr = qsmp_error_none;
						cns->exflag = qsmp_flag_exchange_response;
					}
					else
					{
						qerr = qsmp_error_decapsulation_failure;
						cns->exflag = qsmp_flag_none;
					}
				}
				else
				{
					qerr = qsmp_error_hash_invalid;
					cns->exflag = qsmp_flag_none;
				}
			}
			else
			{
				qerr = qsmp_error_authentication_failure;
				cns->exflag = qsmp_flag_none;
			}
		}
		else
		{
			qerr = qsmp_error_invalid_request;
			cns->exflag = qsmp_flag_none;
		}
	}
	else
	{
		qerr = qsmp_error_invalid_input;
	}

	return qerr;
}

/*
Establish Response:
The server checks the packet flag for the operational status of the client. 
If the flag is set to establish request, the server sends an empty message back to the client 
with the establish response flag set. 
Otherwise the tunnel is in an error state indicated in the message, and the tunnel is torn down on both sides. 
The server sets the operational state to session established, and is now ready to process data.
S{ f } -> C
*/
static qsmp_errors kex_duplex_server_establish_response(const qsmp_kex_duplex_server_state* kss, qsmp_connection_state* cns, const qsmp_packet* packetin, qsmp_packet* packetout)
{
	assert(cns != NULL);
	assert(packetin != NULL);
	assert(packetout != NULL);
	
	qsmp_errors qerr;

	qerr = qsmp_error_invalid_input;

	if (cns != NULL && packetin != NULL && packetout != NULL)
	{
		if (cns->exflag == qsmp_flag_exchange_response && packetin->flag == qsmp_flag_establish_request)
		{	
			/* assemble the establish-response packet */
			packetout->flag = qsmp_flag_establish_response;
			packetout->msglen = 0;
			packetout->sequence = cns->txseq;

			qerr = qsmp_error_none;
			cns->exflag = qsmp_flag_session_established;
		}
		else
		{
			qerr = qsmp_error_invalid_request;
			cns->exflag = qsmp_flag_none;
		}
	}

	return qerr;
}

qsmp_errors qsmp_kex_duplex_client_key_exchange(qsmp_kex_duplex_client_state* kcs, qsmp_connection_state* cns)
{
	assert(kcs != NULL);
	assert(cns != NULL);

	uint8_t mresp[QSMP_MESSAGE_MAX] = { 0 };
	uint8_t mreqt[QSMP_MESSAGE_MAX] = { 0 };
	uint8_t spct[QSMP_MESSAGE_MAX + 1] = { 0 };
	qsmp_packet reqt = { 0 };
	qsmp_packet resp = { 0 };
	qsmp_errors qerr;
	size_t plen;
	size_t rlen;
	size_t slen;

	if (kcs != NULL && cns != NULL)
	{
		reqt.pmessage = mreqt;
		/* create the connection request packet */
		qerr = kex_duplex_client_connect_request(kcs, cns, &reqt);

		if (qerr == qsmp_error_none)
		{
			/* convert the packet to bytes */
			plen = qsmp_packet_to_stream(&reqt, spct);
			/* send the connection request */
			slen = qsc_socket_send(&cns->target, spct, plen, qsc_socket_send_flag_none);
			qsc_memutils_clear(spct, plen + 1);

			if (slen == plen + QSC_SOCKET_TERMINATOR_SIZE)
			{
				const size_t CONLEN = QSMP_DUPLEX_HASH_SIZE + QSMP_ASYMMETRIC_SIGNATURE_SIZE + QSMP_ASYMMETRIC_PUBLIC_KEY_SIZE + QSMP_HEADER_SIZE + QSC_SOCKET_TERMINATOR_SIZE;

				cns->txseq += 1;

				/* blocking receive waits for server */
				rlen = qsc_socket_receive(&cns->target, spct, CONLEN, qsc_socket_receive_flag_wait_all);

				if (rlen == CONLEN)
				{
					/* convert server response to packet */
					resp.pmessage = mresp;
					qsmp_stream_to_packet(spct, &resp);
					qsc_memutils_clear(spct, sizeof(spct));

					if (resp.sequence == cns->rxseq)
					{
						cns->rxseq += 1;

						if (resp.flag == qsmp_flag_connect_response)
						{
							/* clear the request packet */
							qsmp_packet_clear(&reqt);
							/* create the exstart request packet */
							qerr = kex_duplex_client_exchange_request(kcs, cns, &resp, &reqt);
						}
						else
						{
							/* if we receive an error, set the error flag from the packet */
							if (resp.flag == qsmp_flag_error_condition)
							{
								qerr = (qsmp_errors)resp.pmessage[0];
							}
							else
							{
								qerr = qsmp_error_connect_failure;
							}
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
			}
			else
			{
				qerr = qsmp_error_transmit_failure;
			}
		}

		if (qerr == qsmp_error_none)
		{
			qsmp_packet_clear(&resp);
			plen = qsmp_packet_to_stream(&reqt, spct);
			/* send exchange request */
			slen = qsc_socket_send(&cns->target, spct, plen, qsc_socket_send_flag_none);
			qsc_memutils_clear(spct, plen + 1);

			if (slen == plen + QSC_SOCKET_TERMINATOR_SIZE)
			{
				const size_t EXCLEN = QSMP_ASYMMETRIC_CIPHER_TEXT_SIZE + QSMP_DUPLEX_HASH_SIZE + QSMP_ASYMMETRIC_SIGNATURE_SIZE + QSMP_HEADER_SIZE + QSC_SOCKET_TERMINATOR_SIZE;

				cns->txseq += 1;

				/* wait for exstart response */
				rlen = qsc_socket_receive(&cns->target, spct, EXCLEN, qsc_socket_receive_flag_wait_all);

				if (rlen == EXCLEN)
				{
					qsmp_stream_to_packet(spct, &resp);
					qsc_memutils_clear(spct, sizeof(spct));

					if (resp.sequence == cns->rxseq)
					{
						cns->rxseq += 1;

						if (resp.flag == qsmp_flag_exchange_response)
						{
							qsmp_packet_clear(&reqt);
							/* create the exchange request packet */
							qerr = kex_duplex_client_establish_request(kcs, cns, &resp, &reqt);
						}
						else
						{
							if (resp.flag == qsmp_flag_error_condition)
							{
								qerr = (qsmp_errors)resp.pmessage[0];
							}
							else
							{
								qerr = qsmp_error_establish_failure;
							}
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
			}
			else
			{
				qerr = qsmp_error_transmit_failure;
			}
		}

		if (qerr == qsmp_error_none)
		{
			qsmp_packet_clear(&resp);
			plen = qsmp_packet_to_stream(&reqt, spct);
			slen = qsc_socket_send(&cns->target, spct, plen, qsc_socket_send_flag_none);
			qsc_memutils_clear(spct, plen + 1);

			if (slen == plen + QSC_SOCKET_TERMINATOR_SIZE)
			{
				const size_t ESTLEN = QSMP_HEADER_SIZE + QSC_SOCKET_TERMINATOR_SIZE;

				cns->txseq += 1;
				rlen = qsc_socket_receive(&cns->target, spct, ESTLEN, qsc_socket_receive_flag_wait_all);
				qsmp_stream_to_packet(spct, &resp);
				qsc_memutils_clear(spct, sizeof(spct));

				if (rlen == ESTLEN)
				{
					if (resp.sequence == cns->rxseq)
					{
						cns->rxseq += 1;

						if (resp.flag == qsmp_flag_establish_response)
						{
							/* verify the exchange  */
							qerr = kex_duplex_client_establish_verify(kcs, cns, &resp);
						}
						else
						{
							if (resp.flag == qsmp_flag_error_condition)
							{
								qerr = (qsmp_errors)resp.pmessage[0];
							}
							else
							{
								qerr = qsmp_error_establish_failure;
							}
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
			}
			else
			{
				qerr = qsmp_error_transmit_failure;
			}
		}

		kex_duplex_client_reset(kcs);

		if (qerr != qsmp_error_none)
		{
			if (cns->target.connection_status == qsc_socket_state_connected)
			{
				kex_client_send_error(&cns->target, qerr);
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

qsmp_errors qsmp_kex_duplex_server_key_exchange(qsmp_kex_duplex_server_state* kss, qsmp_connection_state* cns)
{
	assert(kss != NULL);
	assert(cns != NULL);

	uint8_t spct[QSMP_MESSAGE_MAX + 1] = { 0 };
	uint8_t mreqt[QSMP_MESSAGE_MAX + 1] = { 0 };
	uint8_t mresp[QSMP_MESSAGE_MAX + 1] = { 0 };
	qsmp_packet reqt = { 0 };
	qsmp_packet resp = { 0 };
	qsmp_errors qerr;
	size_t plen;
	size_t rlen;
	size_t slen;
	const size_t CONLEN = QSMP_KEYID_SIZE + QSMP_CONFIG_SIZE + QSMP_HEADER_SIZE + QSC_SOCKET_TERMINATOR_SIZE;

	/* blocking receive waits for client */
	rlen = qsc_socket_receive(&cns->target, spct, CONLEN, qsc_socket_receive_flag_wait_all);

	if (rlen == CONLEN)
	{
		/* convert server response to packet */
		resp.pmessage = mresp;
		qsmp_stream_to_packet(spct, &resp);
		qsc_memutils_clear(spct, sizeof(spct));

		if (resp.sequence == cns->rxseq)
		{
			cns->rxseq += 1;

			if (resp.flag == qsmp_flag_connect_request)
			{
				/* clear the request packet */
				reqt.pmessage = mreqt;
				qsmp_packet_clear(&reqt);
				/* create the connection request packet */
				qerr = kex_duplex_server_connect_response(kss, cns, &resp, &reqt);
			}
			else
			{
				if (resp.flag == qsmp_flag_error_condition)
				{
					qerr = (qsmp_errors)resp.pmessage[0];
				}
				else
				{
					qerr = qsmp_error_connect_failure;
				}
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

	if (qerr == qsmp_error_none)
	{
		plen = qsmp_packet_to_stream(&reqt, spct);
		slen = qsc_socket_send(&cns->target, spct, plen, qsc_socket_send_flag_none);
		qsc_memutils_clear(spct, plen + 1);

		if (slen == plen + QSC_SOCKET_TERMINATOR_SIZE)
		{
			const size_t EXCLEN = QSMP_ASYMMETRIC_CIPHER_TEXT_SIZE + QSMP_ASYMMETRIC_PUBLIC_KEY_SIZE + QSMP_DUPLEX_HASH_SIZE + QSMP_ASYMMETRIC_SIGNATURE_SIZE + QSMP_HEADER_SIZE + QSC_SOCKET_TERMINATOR_SIZE;
			cns->txseq += 1;
			rlen = qsc_socket_receive(&cns->target, spct, EXCLEN, qsc_socket_receive_flag_wait_all);

			if (rlen == EXCLEN)
			{
				qsmp_stream_to_packet(spct, &resp);
				qsc_memutils_clear(spct, sizeof(spct));

				if (resp.sequence == cns->rxseq)
				{
					cns->rxseq += 1;

					if (resp.flag == qsmp_flag_exchange_request)
					{
						qsmp_packet_clear(&reqt);
						/* create the exchange response packet */
						qerr = kex_duplex_server_exchange_response(kss, cns, &resp, &reqt);
					}
					else
					{
						if (resp.flag == qsmp_flag_error_condition)
						{
							qerr = (qsmp_errors)resp.pmessage[0];
						}
						else
						{
							qerr = qsmp_error_exchange_failure;
						}
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
		}
		else
		{
			qerr = qsmp_error_transmit_failure;
		}
	}

	if (qerr == qsmp_error_none)
	{
		plen = qsmp_packet_to_stream(&reqt, spct);
		slen = qsc_socket_send(&cns->target, spct, plen, qsc_socket_send_flag_none);
		qsc_memutils_clear(spct, plen + 1);

		if (slen == plen + QSC_SOCKET_TERMINATOR_SIZE)
		{
			const size_t ESTLEN = QSMP_HEADER_SIZE + QSC_SOCKET_TERMINATOR_SIZE;
			cns->txseq += 1;
			rlen = qsc_socket_receive(&cns->target, spct, ESTLEN, qsc_socket_receive_flag_wait_all);

			if (rlen == ESTLEN)
			{
				cns->rxseq += 1;
				qsmp_stream_to_packet(spct, &resp);
				qsc_memutils_clear(spct, sizeof(spct));

				if (resp.flag == qsmp_flag_establish_request)
				{
					qsmp_packet_clear(&reqt);
					/* create the establish response packet */
					qerr = kex_duplex_server_establish_response(kss, cns, &resp, &reqt);

					if (qerr == qsmp_error_none)
					{
						plen = qsmp_packet_to_stream(&reqt, spct);
						slen = qsc_socket_send(&cns->target, spct, plen, qsc_socket_send_flag_none);
						qsc_memutils_clear(spct, plen + 1);

						if (slen == plen + QSC_SOCKET_TERMINATOR_SIZE)
						{
							cns->txseq += 1;
						}
						else
						{
							qerr = qsmp_error_transmit_failure;
						}
					}
					else
					{
						qerr = qsmp_error_establish_failure;
					}
				}
				else
				{
					if (resp.flag == qsmp_flag_error_condition)
					{
						qerr = (qsmp_errors)resp.pmessage[0];
					}
					else
					{
						qerr = qsmp_error_establish_failure;
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
			qerr = qsmp_error_transmit_failure;
		}
	}

	kex_duplex_server_reset(kss);

	if (qerr != qsmp_error_none)
	{
		if (cns->target.connection_status == qsc_socket_state_connected)
		{
			kex_server_send_error(&cns->target, qerr);
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
The client stores a hash of the configuration string, the key id, 
and of the servers public asymmetric signature verification-key, which is used as a session cookie during the exchange.
sch <- H(cfg || kid || pvk)
The client sends the key identity string, and the configuration string to the server.
C{ kid, cfg } -> S
*/
static qsmp_errors kex_simplex_client_connect_request(qsmp_kex_simplex_client_state* kcs, qsmp_connection_state* cns, qsmp_packet* packetout)
{
	assert(kcs != NULL);
	assert(cns != NULL);
	assert(packetout != NULL);

	qsc_keccak_state kstate = { 0 };
	qsmp_errors qerr;
	uint64_t tm;

	if (kcs != NULL && packetout != NULL)
	{
		tm = qsc_timestamp_epochtime_seconds();

		if (tm <= kcs->expiration)
		{
			/* copy the key-id and configuration string to the message */
			qsc_memutils_copy(packetout->pmessage, kcs->keyid, QSMP_KEYID_SIZE);
			qsc_memutils_copy(((uint8_t*)packetout->pmessage + QSMP_KEYID_SIZE), QSMP_CONFIG_STRING, QSMP_CONFIG_SIZE);
			/* assemble the connection-request packet */
			packetout->msglen = QSMP_KEYID_SIZE + QSMP_CONFIG_SIZE;
			packetout->flag = qsmp_flag_connect_request;
			packetout->sequence = cns->txseq;

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
			qerr = qsmp_error_key_expired;
			cns->exflag = qsmp_flag_none;
		}
	}
	else
	{
		qerr = qsmp_error_invalid_input;
	}

	return qerr;
}

/*
Exchange Request:
The client verifies the signature of the hash, then generates its own hash of the public key, 
and compares it with the one contained in the message. 
If the hash matches, the client uses the public-key to encapsulate a shared secret.
cond <- AVpk(H(pk)) = (true ?= pk : 0)
cpt, sec <- AEpk(sec)
The client combines the secret and the session cookie to create the session keys, and two unique nonce, 
one key-nonce pair for each channel of the communications stream.
k1, k2, n1, n2 <- KDF(sec, sch)
The receive and transmit channel ciphers are initialized.
cprrx(k2,n2)
cprtx(k1,n1)
The client sends the cipher-text to the server.
C{ cpt } -> S
*/
static qsmp_errors kex_simplex_client_exchange_request(const qsmp_kex_simplex_client_state* kcs, qsmp_connection_state* cns, const qsmp_packet* packetin, qsmp_packet* packetout)
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
		if (cns->exflag == qsmp_flag_connect_request && packetin->flag == qsmp_flag_connect_response)
		{
			slen = 0;

#if defined(QSMP_FALCON_SIGNATURE)
			const size_t FLCDLM = 42;
			/* Note: accounts for a signature encoding length variance in falcon signature size,
			by decoding the signature size directly from the raw signature */
			mlen = ((size_t)packetin->pmessage[0] << 8) | (size_t)packetin->pmessage[1] + FLCDLM + QSMP_SIMPLEX_HASH_SIZE;
#else
			mlen = QSMP_ASYMMETRIC_SIGNATURE_SIZE + QSMP_SIMPLEX_HASH_SIZE;
#endif

			/* verify the asymmetric signature */
			if (qsmp_signature_verify(khash, &slen, packetin->pmessage, mlen, kcs->verkey) == true)
			{
				uint8_t phash[QSMP_SIMPLEX_HASH_SIZE] = { 0 };
				uint8_t pubk[QSMP_ASYMMETRIC_PUBLIC_KEY_SIZE] = { 0 };
				uint8_t ssec[QSMP_SECRET_SIZE] = { 0 };

				qsc_memutils_copy(pubk, (packetin->pmessage + mlen), QSMP_ASYMMETRIC_PUBLIC_KEY_SIZE);

				/* verify the public key hash */
				qsc_sha3_compute256(phash, pubk, QSMP_ASYMMETRIC_PUBLIC_KEY_SIZE);

				if (qsc_intutils_verify(phash, khash, QSMP_SIMPLEX_HASH_SIZE) == 0)
				{
					qsc_keccak_state kstate = { 0 };
					uint8_t prnd[(QSC_KECCAK_256_RATE * 2)] = { 0 };

					/* generate, and encapsulate the secret */
					qsc_memutils_clear(packetout->pmessage, QSMP_MESSAGE_MAX);
					/* store the cipher-text in the message */
					qsmp_cipher_encapsulate(ssec, packetout->pmessage, pubk, qsc_acp_generate);

					/* assemble the exchange-request packet */
					packetout->flag = qsmp_flag_exchange_request;
					packetout->msglen = QSMP_ASYMMETRIC_CIPHER_TEXT_SIZE;
					packetout->sequence = cns->txseq;

					/* initialize cSHAKE k = H(sec, sch) */
					qsc_cshake_initialize(&kstate, qsc_keccak_rate_256, ssec, QSMP_SECRET_SIZE, kcs->schash, QSMP_SIMPLEX_SCHASH_SIZE, NULL, 0);
					qsc_cshake_squeezeblocks(&kstate, qsc_keccak_rate_256, prnd, 2);
					/* permute the state so we are not storing the current key */
					qsc_keccak_permute(&kstate, QSC_KECCAK_PERMUTATION_ROUNDS);
					/* copy as next key */
					qsc_memutils_copy(cns->rtcs, (uint8_t*)kstate.state, QSMP_DUPLEX_SYMMETRIC_KEY_SIZE);

					/* initialize the symmetric cipher, and raise client channel-1 tx */
					qsc_rcs_keyparams kp1;
					kp1.key = prnd;
					kp1.keylen = QSMP_SIMPLEX_SYMMETRIC_KEY_SIZE;
					kp1.nonce = prnd + QSMP_SIMPLEX_SYMMETRIC_KEY_SIZE;
					kp1.info = NULL;
					kp1.infolen = 0;
					qsc_rcs_initialize(&cns->txcpr, &kp1, true);

					/* initialize the symmetric cipher, and raise client channel-1 rx */
					qsc_rcs_keyparams kp2;
					kp2.key = prnd + QSMP_SIMPLEX_SYMMETRIC_KEY_SIZE + QSMP_NONCE_SIZE;
					kp2.keylen = QSMP_SIMPLEX_SYMMETRIC_KEY_SIZE;
					kp2.nonce = prnd + QSMP_SIMPLEX_SYMMETRIC_KEY_SIZE + QSMP_NONCE_SIZE + QSMP_SIMPLEX_SYMMETRIC_KEY_SIZE;
					kp2.info = NULL;
					kp2.infolen = 0;
					qsc_rcs_initialize(&cns->rxcpr, &kp2, false);

					qerr = qsmp_error_none;
					cns->exflag = qsmp_flag_exchange_request;
				}
				else
				{
					qerr = qsmp_error_hash_invalid;
					cns->exflag = qsmp_flag_none;
				}
			}
			else
			{
				qerr = qsmp_error_authentication_failure;
				cns->exflag = qsmp_flag_none;
			}
		}
		else
		{
			qerr = qsmp_error_invalid_request;
			cns->exflag = qsmp_flag_none;
		}
	}
	else
	{
		qerr = qsmp_error_invalid_input;
	}

	return qerr;
}

/*
Establish Verify:
The client checks the flag of the exchange response packet sent by the server. 
If the flag is set to indicate an error state, the tunnel is torn down on both sides,
otherwise the client tunnel is established and in an operational state.
The client sets the operational state to session established, and is now ready to process data.
*/
static qsmp_errors kex_simplex_client_establish_verify(const qsmp_kex_simplex_client_state* kcs, qsmp_connection_state* cns, const qsmp_packet* packetin)
{
	assert(kcs != NULL);
	assert(cns != NULL);
	assert(packetin != NULL);

	qsmp_errors qerr;

	if (kcs != NULL && packetin != NULL)
	{
		if (cns->exflag == qsmp_flag_exchange_request && packetin->flag == qsmp_flag_exchange_response)
		{
			cns->exflag = qsmp_flag_session_established;
			qerr = qsmp_error_none;
		}
		else
		{
			qerr = qsmp_error_invalid_request;
			cns->exflag = qsmp_flag_none;
		}
	}
	else
	{
		qerr = qsmp_error_invalid_input;
	}

	return qerr;
}

/*
Connect Response:
The server responds with either an error message, or a response packet. 
Any error during the key exchange will generate an error-packet sent to the remote host, 
which will trigger a tear down of the session, and network connection on both sides.
The server first checks that it has the requested asymmetric signature verification key corresponding to that host 
using the key-identity array, then verifies that it has a compatible protocol configuration. 
The server stores a hash of the configuration string, key id, and the public signature verification-key, to create the session cookie hash.
sch <- H(cfg || kid || pvk)
The server then generates an asymmetric encryption key-pair, stores the private key, hashes the public encapsulation key, and then signs the hash of the public encapsulation key using the asymmetric signature key. The public signature verification key can itself be signed by a ‘chain of trust’ model, like X.509, using a signature verification extension to this protocol. 
pk, sk <- AG(cfg)
pkh <- H(pk)
spkh <- ASsk(pkh)
The server sends a connect response message containing a signed hash of the public asymmetric encapsulation-key, and a copy of that key.
S{ spkh, pk } -> C
*/
static qsmp_errors kex_simplex_server_connect_response(qsmp_kex_simplex_server_state* kss, qsmp_connection_state* cns, const qsmp_packet* packetin, qsmp_packet* packetout)
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
		if (packetin->flag == qsmp_flag_connect_request)
		{
			/* compare the state key-id to the id in the message */
			if (kex_simplex_server_keyid_verify(kss->keyid, packetin->pmessage) == true)
			{
				tm = qsc_timestamp_epochtime_seconds();

				/* check the keys expiration date */
				if (tm <= kss->expiration)
				{
					/* get a copy of the configuration string */
					qsc_memutils_copy(confs, (packetin->pmessage + QSMP_KEYID_SIZE), QSMP_CONFIG_SIZE);

					/* compare the state configuration string to the message configuration string */
					if (qsc_stringutils_compare_strings(confs, QSMP_CONFIG_STRING, QSMP_CONFIG_SIZE) == true)
					{
						/* store a hash of the configuration string, and the public signature key: sch = H(cfg || pvk) */
						qsc_memutils_clear(kss->schash, QSMP_SIMPLEX_SCHASH_SIZE);
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

						/* hash the public encapsulation key */
						qsc_sha3_compute256(phash, kss->pubkey, QSMP_ASYMMETRIC_PUBLIC_KEY_SIZE);

						/* sign the hash and add it to the message */
						mlen = 0;
						qsc_memutils_clear(packetout->pmessage, QSMP_MESSAGE_MAX);
						qsmp_signature_sign(packetout->pmessage, &mlen, phash, QSMP_SIMPLEX_HASH_SIZE, kss->sigkey, qsc_acp_generate);

						/* copy the public key to the message */
						qsc_memutils_copy(((uint8_t*)packetout->pmessage + mlen), kss->pubkey, QSMP_ASYMMETRIC_PUBLIC_KEY_SIZE);

						/* assemble the connection-response packet */
						packetout->flag = qsmp_flag_connect_response;
						packetout->msglen = QSMP_ASYMMETRIC_SIGNATURE_SIZE + QSMP_SIMPLEX_HASH_SIZE + QSMP_ASYMMETRIC_PUBLIC_KEY_SIZE;
						packetout->sequence = cns->txseq;

						qerr = qsmp_error_none;
						cns->exflag = qsmp_flag_connect_response;
					}
					else
					{
						qerr = qsmp_error_unknown_protocol;
						cns->exflag = qsmp_flag_none;
					}
				}
				else
				{
					qerr = qsmp_error_key_expired;
					cns->exflag = qsmp_flag_none;
				}
			}
			else
			{
				qerr = qsmp_error_key_unrecognized;
				cns->exflag = qsmp_flag_none;
			}
		}
		else
		{
			qerr = qsmp_error_invalid_request;
			cns->exflag = qsmp_flag_none;
		}
	}

	return qerr;
}

/*
Exchange Response:
The server decapsulates the shared-secret.
sec <- -AEsk(cpt)
The server combines the shared secret and the session cookie hash to create two session keys, 
and two unique nonce, one key-nonce pair for each channel of the communications stream.
k1, k2, n1, n2 <- KDF(sec, sch)
The receive and transmit channel ciphers are initialized.
cprrx(k1,n1)
cprtx(k2,n2)
The server sets the packet flag to exchange response, indicating that the encrypted channels have been raised, 
and sends the notification to the client. The server sets the operational state to session established, 
and is now ready to process data.
S{ f } -> C
*/
static qsmp_errors kex_simplex_server_exchange_response(const qsmp_kex_simplex_server_state* kss, qsmp_connection_state* cns, const qsmp_packet* packetin, qsmp_packet* packetout)
{
	assert(kss != NULL);
	assert(cns != NULL);
	assert(packetin != NULL);
	assert(packetout != NULL);

	qsmp_errors qerr;

	if (kss != NULL && packetin != NULL && packetout != NULL)
	{
		if (cns->exflag == qsmp_flag_connect_response && packetin->flag == qsmp_flag_exchange_request)
		{
			uint8_t ssec[QSMP_SECRET_SIZE] = { 0 };

				/* decapsulate the shared secret */
			if (qsmp_cipher_decapsulate(ssec, packetin->pmessage, kss->prikey) == true)
			{
				qsc_keccak_state kstate = { 0 };
				uint8_t prnd[(QSC_KECCAK_256_RATE * 2)] = { 0 };

				qsc_memutils_clear(packetout->pmessage, QSMP_MESSAGE_MAX);

				/* initialize cSHAKE k = H(ssec, sch) */
				qsc_cshake_initialize(&kstate, qsc_keccak_rate_256, ssec, sizeof(ssec), kss->schash, QSMP_SIMPLEX_SCHASH_SIZE, NULL, 0);
				qsc_cshake_squeezeblocks(&kstate, qsc_keccak_rate_256, prnd, 2);
				/* permute the state so we are not storing the current key */
				qsc_keccak_permute(&kstate, QSC_KECCAK_PERMUTATION_ROUNDS);
				/* copy as next key */
				qsc_memutils_copy(cns->rtcs, (uint8_t*)kstate.state, QSMP_DUPLEX_SYMMETRIC_KEY_SIZE);

				/* initialize the symmetric cipher, and raise client channel-1 tx */
				qsc_rcs_keyparams kp1;
				kp1.key = prnd;
				kp1.keylen = QSMP_SIMPLEX_SYMMETRIC_KEY_SIZE;
				kp1.nonce = prnd + QSMP_SIMPLEX_SYMMETRIC_KEY_SIZE;
				kp1.info = NULL;
				kp1.infolen = 0;
				qsc_rcs_initialize(&cns->rxcpr, &kp1, false);

				/* initialize the symmetric cipher, and raise client channel-1 rx */
				qsc_rcs_keyparams kp2;
				kp2.key = prnd + QSMP_SIMPLEX_SYMMETRIC_KEY_SIZE + QSMP_NONCE_SIZE;
				kp2.keylen = QSMP_SIMPLEX_SYMMETRIC_KEY_SIZE;
				kp2.nonce = prnd + QSMP_SIMPLEX_SYMMETRIC_KEY_SIZE + QSMP_NONCE_SIZE + QSMP_SIMPLEX_SYMMETRIC_KEY_SIZE;
				kp2.info = NULL;
				kp2.infolen = 0;
				qsc_rcs_initialize(&cns->txcpr, &kp2, true);

				/* assemble the exchange-response packet */
				packetout->flag = qsmp_flag_exchange_response;
				packetout->msglen = 0;
				packetout->sequence = cns->txseq;

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
			qerr = qsmp_error_invalid_request;
			cns->exflag = qsmp_flag_none;
		}
	}
	else
	{
		qerr = qsmp_error_invalid_input;
	}

	return qerr;
}

qsmp_errors qsmp_kex_simplex_client_key_exchange(qsmp_kex_simplex_client_state* kcs, qsmp_connection_state* cns)
{
	assert(kcs != NULL);
	assert(cns != NULL);

	uint8_t spct[QSMP_MESSAGE_MAX + 1] = { 0 };
	uint8_t mreqt[QSMP_MESSAGE_MAX + 1] = { 0 };
	uint8_t mresp[QSMP_MESSAGE_MAX + 1] = { 0 };
	qsmp_packet reqt = { 0 };
	qsmp_packet resp = { 0 };
	qsmp_errors qerr;
	size_t plen;
	size_t rlen;
	size_t slen;

	if (kcs != NULL && cns != NULL)
	{
		/* create the connection request packet */
		reqt.pmessage = mreqt;
		qerr = kex_simplex_client_connect_request(kcs, cns, &reqt);

		if (qerr == qsmp_error_none)
		{
			/* convert the packet to bytes */
			plen = qsmp_packet_to_stream(&reqt, spct);
			/* send the connection request */
			slen = qsc_socket_send(&cns->target, spct, plen, qsc_socket_send_flag_none);
			qsc_memutils_clear(spct, plen + 1);

			if (slen == plen + QSC_SOCKET_TERMINATOR_SIZE)
			{
				const size_t CONLEN = QSMP_ASYMMETRIC_SIGNATURE_SIZE + QSMP_SIMPLEX_HASH_SIZE + QSMP_ASYMMETRIC_PUBLIC_KEY_SIZE + QSMP_HEADER_SIZE + QSC_SOCKET_TERMINATOR_SIZE;

				cns->txseq += 1;

				/* blocking receive waits for server */
				rlen = qsc_socket_receive(&cns->target, spct, CONLEN, qsc_socket_receive_flag_wait_all);

				if (rlen == CONLEN)
				{
					/* convert server response to packet */
					resp.pmessage = mresp;
					qsmp_stream_to_packet(spct, &resp);
					qsc_memutils_clear(spct, sizeof(spct));

					if (resp.sequence == cns->rxseq)
					{
						cns->rxseq += 1;

						if (resp.flag == qsmp_flag_connect_response)
						{
							/* clear the request packet */
							qsmp_packet_clear(&reqt);
							/* create the exstart request packet */
							qerr = kex_simplex_client_exchange_request(kcs, cns, &resp, &reqt);
						}
						else
						{
							/* if we receive an error, set the error flag from the packet */
							if (resp.flag == qsmp_flag_error_condition)
							{
								qerr = (qsmp_errors)resp.pmessage[0];
							}
							else
							{
								qerr = qsmp_error_connect_failure;
							}
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
			}
			else
			{
				qerr = qsmp_error_transmit_failure;
			}
		}

		if (qerr == qsmp_error_none)
		{
			qsmp_packet_clear(&resp);
			plen = qsmp_packet_to_stream(&reqt, spct);
			slen = qsc_socket_send(&cns->target, spct, plen, qsc_socket_send_flag_none);
			qsc_memutils_clear(spct, plen + 1);

			if (slen == plen + QSC_SOCKET_TERMINATOR_SIZE)
			{
				const size_t EXCLEN = QSMP_HEADER_SIZE + QSC_SOCKET_TERMINATOR_SIZE;

				cns->txseq += 1;
				rlen = qsc_socket_receive(&cns->target, spct, EXCLEN, qsc_socket_receive_flag_wait_all);
				qsmp_stream_to_packet(spct, &resp);
				qsc_memutils_clear(spct, sizeof(spct));

				if (rlen == EXCLEN)
				{
					if (resp.sequence == cns->rxseq)
					{
						cns->rxseq += 1;

						if (resp.flag == qsmp_flag_exchange_response)
						{
							/* verify the exchange  */
							qerr = kex_simplex_client_establish_verify(kcs, cns, &resp);
						}
						else
						{
							if (resp.flag == qsmp_flag_error_condition)
							{
								qerr = (qsmp_errors)resp.pmessage[0];
							}
							else
							{
								qerr = qsmp_error_establish_failure;
							}
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
			}
			else
			{
				qerr = qsmp_error_transmit_failure;
			}
		}

		kex_simplex_client_reset(kcs);

		if (qerr != qsmp_error_none)
		{
			if (cns->target.connection_status == qsc_socket_state_connected)
			{
				kex_client_send_error(&cns->target, qerr);
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

	uint8_t spct[QSMP_MESSAGE_MAX + 1] = { 0 };
	uint8_t mreqt[QSMP_MESSAGE_MAX + 1] = { 0 };
	uint8_t mresp[QSMP_MESSAGE_MAX + 1] = { 0 };
	qsmp_packet reqt = { 0 };
	qsmp_packet resp = { 0 };
	qsmp_errors qerr;
	size_t plen;
	size_t rlen;
	size_t slen;
	const size_t CONLEN = QSMP_KEYID_SIZE + QSMP_CONFIG_SIZE + QSMP_HEADER_SIZE + QSC_SOCKET_TERMINATOR_SIZE;

	/* blocking receive waits for client */
	rlen = qsc_socket_receive(&cns->target, spct, CONLEN, qsc_socket_receive_flag_wait_all);

	if (rlen == CONLEN)
	{
		/* convert server response to packet */
		resp.pmessage = mresp;
		qsmp_stream_to_packet(spct, &resp);
		qsc_memutils_clear(spct, sizeof(spct));

		if (resp.sequence == cns->rxseq)
		{
			cns->rxseq += 1;

			if (resp.flag == qsmp_flag_connect_request)
			{
				/* clear the request packet */
				reqt.pmessage = mreqt;
				qsmp_packet_clear(&reqt);
				/* create the connection request packet */
				qerr = kex_simplex_server_connect_response(kss, cns, &resp, &reqt);
			}
			else
			{
				if (resp.flag == qsmp_flag_error_condition)
				{
					qerr = (qsmp_errors)resp.pmessage[0];
				}
				else
				{
					qerr = qsmp_error_connect_failure;
				}
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

	if (qerr == qsmp_error_none)
	{
		plen = qsmp_packet_to_stream(&reqt, spct);
		slen = qsc_socket_send(&cns->target, spct, plen, qsc_socket_send_flag_none);
		qsc_memutils_clear(spct, plen + 1);

		if (slen == plen + QSC_SOCKET_TERMINATOR_SIZE)
		{
			const size_t EXCLEN = QSMP_ASYMMETRIC_CIPHER_TEXT_SIZE + QSMP_HEADER_SIZE + QSC_SOCKET_TERMINATOR_SIZE;
			cns->txseq += 1;
			rlen = qsc_socket_receive(&cns->target, spct, EXCLEN, qsc_socket_receive_flag_wait_all);

			if (rlen == EXCLEN)
			{
				qsmp_stream_to_packet(spct, &resp);
				qsc_memutils_clear(spct, sizeof(spct));

				if (resp.sequence == cns->rxseq)
				{
					cns->rxseq += 1;

					if (resp.flag == qsmp_flag_exchange_request)
					{
						qsmp_packet_clear(&reqt);
						/* create the exchange response packet */
						qerr = kex_simplex_server_exchange_response(kss, cns, &resp, &reqt);
					}
					else
					{
						if (resp.flag == qsmp_flag_error_condition)
						{
							qerr = (qsmp_errors)resp.pmessage[0];
						}
						else
						{
							qerr = qsmp_error_exchange_failure;
						}
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
		}
		else
		{
			qerr = qsmp_error_transmit_failure;
		}
	}

	if (qerr == qsmp_error_none)
	{
		plen = qsmp_packet_to_stream(&reqt, spct);
		slen = qsc_socket_send(&cns->target, spct, plen, qsc_socket_send_flag_none);
		qsc_memutils_clear(spct, plen + 1);

		if (slen == plen + QSC_SOCKET_TERMINATOR_SIZE)
		{
			cns->txseq += 1;
		}
		else
		{
			qerr = qsmp_error_transmit_failure;
		}
	}

	kex_simplex_server_reset(kss);

	if (qerr != qsmp_error_none)
	{
		if (cns->target.connection_status == qsc_socket_state_connected)
		{
			kex_server_send_error(&cns->target, qerr);
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
	qsmp_packet pckclt = { 0 };
	qsmp_packet pcksrv = { 0 };
	uint8_t mclt[QSMP_MESSAGE_MAX + 1] = { 0 };
	uint8_t msrv[QSMP_MESSAGE_MAX + 1] = { 0 };
	qsmp_errors qerr;
	bool res;

	pckclt.pmessage = mclt;
	pcksrv.pmessage = msrv;
	qsmp_signature_generate_keypair(dkcs.verkey, dkcs.sigkey, qsc_acp_generate);
	qsmp_signature_generate_keypair(dkss.verkey, dkss.sigkey, qsc_acp_generate);
	qsc_memutils_copy(dkcs.rverkey, dkss.verkey, QSMP_ASYMMETRIC_VERIFY_KEY_SIZE);
	qsc_memutils_copy(dkss.rverkey, dkcs.verkey, QSMP_ASYMMETRIC_VERIFY_KEY_SIZE);

	dkcs.expiration = qsc_timestamp_epochtime_seconds() + QSMP_PUBKEY_DURATION_SECONDS;
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

		skcs.expiration = qsc_timestamp_epochtime_seconds() + QSMP_PUBKEY_DURATION_SECONDS;
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
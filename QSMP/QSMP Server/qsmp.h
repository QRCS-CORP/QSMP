/* 2021 Digital Freedom Defense Incorporated
 * All Rights Reserved.
 *
 * NOTICE:  All information contained herein is, and remains
 * the property of Digital Freedom Defense Incorporated.
 * The intellectual and technical concepts contained
 * herein are proprietary to Digital Freedom Defense Incorporated
 * and its suppliers and may be covered by U.S. and Foreign Patents,
 * patents in process, and are protected by trade secret or copyright law.
 * Dissemination of this information or reproduction of this material
 * is strictly forbidden unless prior written permission is obtained
 * from Digital Freedom Defense Incorporated.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */

/**
* \file qsmp.h
* \brief <b>QSMP support header</b> \n
* Common parameters and functions of the qsmp client and server implementations.
*
* \author		John G. Underhill
* \version		1.0.0.0a
* \date			February 1, 2021
* \updated		May 24, 2021
* \contact:		develop@vtdev.com
* \copyright	GPL version 3 license (GPLv3)
*
* \remarks
* \section Param Sets:
* kyber-dilithium-rcs256-shake256
* mceliece-sphincs-rcs256-shake256
*
* \section Overview
* Legend:
* C	-The client host
* S	-The server host
* cng	-The cryptographic configuration string
* cprrx	-A receive channels symmetric cipher instance
* cprtx	-A transmit channels symmetric cipher instance
* cpt	-The symmetric ciphers cipher-text
* cpta	-The asymmetric ciphers cipher-text
* kid	-The public keys unique identity string
* pekh	-The public asymmetric encryption key hash
* psk	-The public signature verification key
* sec	-The shared secret derived from asymmetric encapsulation and decapsulation
* spkh	-The signed hash of the asymmetric public encapsulation-key
* sth	-The session hash token, a hash of the session token, the configuration string, and the public signature verification-key
* stok	-A random string used as the session-token in the key exchange
* DAsk	-The asymmetric encapsulation function and public key
* EAsk	-The asymmetric decapsulation function and secret key
* Dk	-The symmetric decryption function and key
* Ek	-The symmetric encryption function and key
* Exp	-The key expansion function: cSHAKE
* H		-The hash function: sha3
* Mmk	-The MAC function and key: KMAC
* SAsk	-Sign with the secret signature key
* VApk	-Verify a signature the public signature key
*
* Key Exchange Sequence
* 7.1 Connect Request:
* The client first checks the expiration date on the public key, if invalid, 
* it queries the server for a new public verification key.
* The client sends a connection request with its configuration string, 
* key identity, and a random session token. 
* The key identity (kid) is a multi-part 16-byte address and key identification string, 
* used to identify the intended target server and corresponding key.
* The client stores a hash of the session token, the configuration string, 
* and the public asymmetric signature verification-key.
* sth = H(stok || cfg || psk)
* The client then sends the public-key identity string, configuration string, 
* and the session token to the server.
* C{kid, cfg, stok}->S
*
* Connect Response:
* The server responds with either an error message, or a response packet. 
* The error message can be busy, unrecognized, or unauthorized. 
* Any error during the key exchange will generate an error-packet sent to the remote host, 
* which will trigger a tear down of the connection on both sides.
* The server first checks that it has the requested public signature verification-key,
* using the key-identity string, then verifies that it has a compatible protocol configuration. 
* The server stores a hash of the session token, the configuration string, 
* and the public signature verification-key to create the session token hash.
* sth = H(stok || cfg || psk)
* The server then generates an asymmetric encryption key-pair, stores the secret key, 
* hashes the public key, and then signs the hash of the public encryption key using the asymmetric signature scheme. 
* This signed hash can itself be signed by a ‘chain of trust’ model, like PGP or X509, 
* using a signature verification extension to this protocol.
* pekh = H(pke)
* spkh = Ssk(pekh)
* The server sends a response message containing a signed hash of a public asymmetric encryption-key, 
* and a copy of that key.
* S{spkh, pke}->C
*
* Exstart Request:
* The client verifies the signature of the public encryption keys hash, 
* then generates its own hash of the public key, and compares them. 
* If the hash matches, the client uses the public-key to encapsulate a shared secret.
* cph = Vsk(H(pk)) cph := ph
* cpta = EApk(sec)
* The client then expands the shared secret and session token hash, 
* and uses the output to key the clients transmit-channel symmetric cipher.
* k,n = Exp(sec || sth)
* cprtx(k,n)
* The client transmits the cipher-text to the server.
* C{cpta}->S
*
* Exstart Response:
* The server decapsulates the shared-secret, combines it with the session token hash, 
* and keys the servers receive-channel cipher. The channel-1 VPN is now established.
* sec = DApk(cpta)
* k,n = Exp(sec, sth)
* cprrx(k,n)
* The server sends the client an established message for the first channel.
* S{m}->C
*
* Exchange Request:
* The client generates and stores an asymmetric cipher key-pair. 
* The client generates a MAC key and stores it to state. 
* The server then encrypts the MAC key and the asymmetric encapsulation-key using the channel-1 VPN, 
* and sends the encrypted MAC and encapsulation keys to the server.
* pk,sk = G(cfg)
* cpt = Ek(pk)
* C{mk,cpt}->S
*
* Exchange Response:
* The server decrypts the MAC and encapsulation keys, 
* and uses the encapsulation-key to encapsulate a shared-secret for channel 2. 
* The server then uses the MAC key received from the client, 
* to MAC the ciphertext, appending a MAC code to the message.
* mk,pk = Dk(cpt)
* cpta = EApk(sec)
* The server then expands the shared secret and session token hash, 
* and creates the symmetric ciphers key and nonce.
* k,n = Exp(sec, sth)
* The MAC function is keyed with the MAC key sent by the client, 
* the ciphertext is added to the MAC, and the output code is prepended to the message.
* cc = Mmk(cpta)
* The server’s channel-2 transmission channel is initialized, 
* and the authenticated cipher-text is sent to the client.
* cprtx(k,n)
* S{cc, cpta}->C
*
* Established Request:
* The client uses the stored MAC key to key the MAC function, 
* then adds the ciphertext to the hash. 
* The client compares the hash code appended to the ciphertext with the one generated with the MAC function,
* before decapsulation the shared key.
* mc = Mmk(cpta), mc := cc
* The client then decapsulates the shared secret, combines it with the session token hash, and expands it.
* sec = DAsk(cpta)
* k,n = Exp(sec, sth)
* The client then keys the clients receive channel, 
* the second VPN is established, and the client sends an established message.
* cprrx(k,n)
* C{m}->S
*
* Established Response:
* The server sends the client an established message, acknowledging both channels are established.
* S{m}->C
*
* Transmission:
* The host, client or server, transmitting a message, first encrypts the message, 
* updates the MAC function with the cipher-text, and appends a MAC code to the end of the cipher-text.
* The serialized packet header, including the message size, key identity, 
* and sequence number, is added to the MAC state through the additional-data parameter,
* of the authenticated stream cipher RCS. 
* This unique data is added to the MAC function with every packet, along with the encrypted cipher-text.
* (cpt || mc) = Ek(sh, m)
* The packet is decrypted by serializing the packet header and adding it to the MAC state, 
* then finalizing the MAC on the cipher-text and comparing the output code with the code appended to the cipher-text. 
* If the code matches, the cipher-text is decrypted, and the message passed up to the application.
* m = Dk(sh, cpt) == 0 ? m : NULL
*/

#ifndef QSC_QSMP_H
#define QSC_QSMP_H

/*!
* \def QSC_QSMP_PUBKEY_SPHINCS
* \brief Sets the asymmetric cryptographic primitive-set to Sphincs+/McEliece, default is Dilithium/Kyber.
* Note: You may have to increase the stack reserve size on both projects, McEliece and Sphincs+ use a lot of resources.
*/
#if !defined(QSC_QSMP_PUBKEY_SPHINCS)
//#	define QSC_QSMP_PUBKEY_SPHINCS
#endif

#include "common.h"
#if defined(QSC_QSMP_PUBKEY_SPHINCS)
#	include "../QSC/mceliece.h"
#	include "../QSC/sphincsplus.h"
#else
#	include "../QSC/dilithium.h"
#	include "../QSC/kyber.h"
#endif

/*!
* \def QSC_QSMP_SERVER_PORT
* \brief The default server port address
*/
#define QSC_QSMP_SERVER_PORT 2101

/*!
* \def QSC_QSMP_CONFIG_SIZE
* \brief The size of the protocol configuration string
*/
#define QSC_QSMP_CONFIG_SIZE 40

#if defined(QSC_QSMP_PUBKEY_SPHINCS)
static const char QSC_QSMP_CONFIG_STRING[QSC_QSMP_CONFIG_SIZE] = "sphincs-s2_mceliece-s2_rcs-256_sha3-256";
#else
static const char QSC_QSMP_CONFIG_STRING[QSC_QSMP_CONFIG_SIZE] = "dilithium-s2_kyber-s2_sha3-256_rcs-256 ";
#endif

#if defined(QSC_QSMP_PUBKEY_SPHINCS)
/*!
* \def QSC_QSMP_CIPHERTEXT_SIZE
* \brief The byte size of the cipher-text array
*/
#	define QSC_QSMP_CIPHERTEXT_SIZE (QSC_MCELIECE_CIPHERTEXT_SIZE)
/*!
* \def QSC_QSMP_PRIVATEKEY_SIZE
* \brief The byte size of the asymmetric cipher private-key array
*/
#	define QSC_QSMP_PRIVATEKEY_SIZE (QSC_MCELIECE_PRIVATEKEY_SIZE)
/*!
* \def QSC_QSMP_PUBLICKEY_SIZE
* \brief The byte size of the asymmetric cipher public-key array
*/
#	define QSC_QSMP_PUBLICKEY_SIZE (QSC_MCELIECE_PUBLICKEY_SIZE)
/*!
* \def QSC_QSMP_SIGNKEY_SIZE
* \brief The byte size of the asymmetric signature signing-key array
*/
#	define QSC_QSMP_SIGNKEY_SIZE (QSC_SPHINCSPLUS_PRIVATEKEY_SIZE)
/*!
* \def QSC_QSMP_VERIFYKEY_SIZE
* \brief The byte size of the asymmetric signature verification-key array
*/
#	define QSC_QSMP_VERIFYKEY_SIZE (QSC_SPHINCSPLUS_PUBLICKEY_SIZE)
/*!
* \def QSC_QSMP_SIGNATURE_SIZE
* \brief The byte size of the asymmetric signature array
*/
#	define QSC_QSMP_SIGNATURE_SIZE (QSC_SPHINCSPLUS_SIGNATURE_SIZE)
/*!
* \def QSC_QSMP_PUBKEY_ENCODING_SIZE
* \brief The byte size of the encoded QSMP public-key
*/
#	define QSC_QSMP_PUBKEY_ENCODING_SIZE 44
/*!
* \def QSC_QSMP_PUBKEY_STRING_SIZE
* \brief The string size of the serialized QSMP client-key structure
*/
#	define QSC_QSMP_PUBKEY_STRING_SIZE 272
#else
/*!
* \def QSC_QSMP_CIPHERTEXT_SIZE
* \brief The byte size of the asymmetric cipher-text array
*/
#	define QSC_QSMP_CIPHERTEXT_SIZE (QSC_KYBER_CIPHERTEXT_SIZE)
/*!
* \def QSC_QSMP_PRIVATEKEY_SIZE
* \brief The byte size of the asymmetric cipher private-key array
*/
#	define QSC_QSMP_PRIVATEKEY_SIZE (QSC_KYBER_PRIVATEKEY_SIZE)
/*!
* \def QSC_QSMP_PUBLICKEY_SIZE
* \brief The byte size of the asymmetric cipher public-key array
*/
#	define QSC_QSMP_PUBLICKEY_SIZE (QSC_KYBER_PUBLICKEY_SIZE)
/*!
* \def QSC_QSMP_SIGNKEY_SIZE
* \brief The byte size of the asymmetric signature signing-key array
*/
#	define QSC_QSMP_SIGNKEY_SIZE (QSC_DILITHIUM_PRIVATEKEY_SIZE)
/*!
* \def QSC_QSMP_VERIFYKEY_SIZE
* \brief The byte size of the asymmetric signature verification-key array
*/
#	define QSC_QSMP_VERIFYKEY_SIZE (QSC_DILITHIUM_PUBLICKEY_SIZE)
/*!
* \def QSC_QSMP_SIGNATURE_SIZE
* \brief The byte size of the asymmetric signature array
*/
#	define QSC_QSMP_SIGNATURE_SIZE (QSC_DILITHIUM_SIGNATURE_SIZE)
/*!
* \def QSC_QSMP_PUBKEY_ENCODING_SIZE
* \brief The byte size of the encoded QSMP public-key
*/
#	define QSC_QSMP_PUBKEY_ENCODING_SIZE 1964
/*!
* \def QSC_QSMP_PUBKEY_STRING_SIZE
* \brief The string size of the serialized QSMP client-key structure
*/
#	define QSC_QSMP_PUBKEY_STRING_SIZE 2222
#endif

/*!
* \def QSC_QSMP_HASH_SIZE
* \brief The size of the hash function output
*/
#define QSC_QSMP_HASH_SIZE 32
/*!
* \def QSC_QSMP_HEADER_SIZE
* \brief The QSMP packet header size
*/
#define QSC_QSMP_HEADER_SIZE 13
/*!
* \def QSC_QSMP_KEEPALIVE_STRING
* \brief The keep alive string size
*/
#define QSC_QSMP_KEEPALIVE_STRING 20
/*!
* \def QSC_QSMP_KEEPALIVE_TIMEOUT
* \brief The keep alive timeout in milliseconds (5 minutes)
*/
#define QSC_QSMP_KEEPALIVE_TIMEOUT (300 * 1000)
/*!
* \def QSC_QSMP_KEYID_SIZE
* \brief The QSMP key identity size
*/
#define QSC_QSMP_KEYID_SIZE 16
/*!
* \def QSC_QSMP_MACKEY_SIZE
* \brief The QSMP mac key size
*/
#define QSC_QSMP_MACKEY_SIZE 32
/*!
* \def QSC_QSMP_MACTAG_SIZE
* \brief The size of the mac function output
*/
#define QSC_QSMP_MACTAG_SIZE 32
/*!
* \def QSC_QSMP_TIMESTAMP_SIZE
* \brief The key expiration timestamp size
*/
#define QSC_QSMP_TIMESTAMP_SIZE 8
/*!
* \def QSC_QSMP_MESSAGE_MAX
* \brief The maximum message size used during the key exchange (may exceed mtu)
*/
#define QSC_QSMP_MESSAGE_MAX (QSC_QSMP_SIGNATURE_SIZE + QSC_QSMP_PUBLICKEY_SIZE + QSC_QSMP_HASH_SIZE + QSC_QSMP_HEADER_SIZE)
/*!
* \def QSC_QSMP_PKCODE_SIZE
* \brief The size of the session token hash
*/
#define QSC_QSMP_PKCODE_SIZE 32
/*!
* \def QSC_QSMP_PUBKEY_DURATION_DAYS
* \brief The number of days a public key remains valid
*/
#define QSC_QSMP_PUBKEY_DURATION_DAYS 365
/*!
* \def QSC_QSMP_PUBKEY_DURATION_SECONDS
* \brief The number of seconds a public key remains valid
*/
#define QSC_QSMP_PUBKEY_DURATION_SECONDS (QSC_QSMP_PUBKEY_DURATION_DAYS * 24 * 60 * 60)
/*!
* \def QSC_QSMP_PUBKEY_LINE_LENGTH
* \brief The line length of the printed QSMP public key
*/
#define QSC_QSMP_PUBKEY_LINE_LENGTH 64
/*!
* \def QSC_QSMP_SECRET_SIZE
* \brief The size of the shared secret for each channel
*/
#define QSC_QSMP_SECRET_SIZE 32
/*!
* \def QSC_QSMP_STOKEN_SIZE
* \brief The session token size
*/
#define QSC_QSMP_STOKEN_SIZE 32
/*!
* \def QSC_QSMP_SIGKEY_ENCODED_SIZE
* \brief The secret signature key size
*/
#define QSC_QSMP_SIGKEY_ENCODED_SIZE (QSC_QSMP_KEYID_SIZE + QSC_QSMP_TIMESTAMP_SIZE + QSC_QSMP_CONFIG_SIZE + QSC_QSMP_SIGNKEY_SIZE + QSC_QSMP_VERIFYKEY_SIZE)
/*!
* \def QSC_QSMP_SEQUENCE_TERMINATOR
* \brief The sequence number of a packet that closes a connection
*/
#define QSC_QSMP_SEQUENCE_TERMINATOR 0xFFFFFFFF
/*!
* \def QSC_QSMP_CONNECT_REQUEST_SIZE
* \brief The key-exchange connect stage request packet size
*/
#define QSC_QSMP_CONNECT_REQUEST_SIZE (QSC_QSMP_KEYID_SIZE + QSC_QSMP_STOKEN_SIZE + QSC_QSMP_CONFIG_SIZE + QSC_QSMP_HEADER_SIZE)
/*!
* \def QSC_QSMP_EXSTART_REQUEST_SIZE
* \brief The key-exchange exstart stage request packet size
*/
#define QSC_QSMP_EXSTART_REQUEST_SIZE (QSC_QSMP_CIPHERTEXT_SIZE + QSC_QSMP_HEADER_SIZE)
/*!
* \def QSC_QSMP_EXCHANGE_REQUEST_SIZE
* \brief The key-exchange exchange stage request packet size
*/
#define QSC_QSMP_EXCHANGE_REQUEST_SIZE (QSC_QSMP_MACKEY_SIZE + QSC_QSMP_PUBLICKEY_SIZE + QSC_QSMP_MACTAG_SIZE + QSC_QSMP_HEADER_SIZE)
/*!
* \def QSC_QSMP_ESTABLISH_REQUEST_SIZE
* \brief The key-exchange establish stage request packet size
*/
#define QSC_QSMP_ESTABLISH_REQUEST_SIZE (QSC_QSMP_HEADER_SIZE)
/*!
* \def QSC_QSMP_CONNECT_RESPONSE_SIZE
* \brief The key-exchange connect stage response packet size
*/
#define QSC_QSMP_CONNECT_RESPONSE_SIZE (QSC_QSMP_SIGNATURE_SIZE + QSC_QSMP_HASH_SIZE + QSC_QSMP_PUBLICKEY_SIZE + QSC_QSMP_HEADER_SIZE)
/*!
* \def QSC_QSMP_EXSTART_RESPONSE_SIZE
* \brief The key-exchange exstart stage response packet size
*/
#define QSC_QSMP_EXSTART_RESPONSE_SIZE (QSC_QSMP_HEADER_SIZE + 1)
/*!
* \def QSC_QSMP_EXCHANGE_RESPONSE_SIZE
* \brief The key-exchange exchange stage response packet size
*/
#define QSC_QSMP_EXCHANGE_RESPONSE_SIZE (QSC_QSMP_CIPHERTEXT_SIZE + QSC_QSMP_MACTAG_SIZE + QSC_QSMP_HEADER_SIZE)
/*!
* \def QSC_QSMP_ESTABLISH_RESPONSE_SIZE
* \brief The key-exchange establish stage response packet size
*/
#define QSC_QSMP_ESTABLISH_RESPONSE_SIZE (QSC_QSMP_HEADER_SIZE + 1)

/* public key encoding constants */

static const char QSC_QSMP_PUBKEY_HEADER[] = "------BEGIN QSMP PUBLIC KEY BLOCK------";
static const char QSC_QSMP_PUBKEY_VERSION[] = "Version: QSMP v1.0";
static const char QSC_QSMP_PUBKEY_CONFIG_PREFIX[] = "Configuration: ";
static const char QSC_QSMP_PUBKEY_KEYID_PREFIX[] = "Host ID: ";
static const char QSC_QSMP_PUBKEY_EXPIRATION_PREFIX[] = "Expiration: ";
static const char QSC_QSMP_PUBKEY_FOOTER[] = "------END QSMP PUBLIC KEY BLOCK------";

/* error code strings */

#define QSMP_ERROR_STRING_DEPTH 20
#define QSMP_ERROR_STRING_WIDTH 128

static const char QSMP_ERROR_STRINGS[QSMP_ERROR_STRING_DEPTH][QSMP_ERROR_STRING_WIDTH] =
{
	"No error was detected.",
	"The symmetric cipher had an authentication failure.",
	"The random generator has failed.",
	"The QSMP public key has expired.",
	"The packet flag was unexpected.",
	"The asymmetric cipher failed to decapsulate the shared secret.",
	"The communications channel has failed.",
	"The public-key hash is invalid.",
	"The expected input was invalid.",
	"The receiver failed at the network layer.",
	"The transmitter failed at the network layer.",
	"The device could not make a connnection to the remote host.",
	"The transmission failed at the kex connection phase.",
	"The transmission failed at the kex exstart phase.",
	"The transmission failed at the kex exchange phase.",
	"The transmission failed at the kex establish phase.",
	"The protocol string was not recognized.",
	"The packet was received out of sequence.",
	"The keep alive check failed.",
	"The keep alive has expired with no response",
};

/*!
* \enum qsc_qsmp_configuration
* \brief The cryptographic asymmetric primitive configuration
*/
QSC_EXPORT_API typedef enum qsc_qsmp_configuration
{
	qsc_qsmp_configuration_none = 0,				/*!< No configuration was specified */
	qsc_qsmp_configuration_sphincs_mceliece = 1,	/*!< The Sphincs+ and McEliece configuration */
	qsc_qsmp_configuration_dilithium_kyber = 2,		/*!< The Dilithium and Kyber configuration */
} qsc_qsmp_configuration;

/*!
* \enum qsc_qsmp_errors
* \brief The QSMP error values
*/
QSC_EXPORT_API typedef enum qsc_qsmp_errors
{
	qsc_qsmp_error_none = 0x00,						/*!< No error was detected */
	qsc_qsmp_error_auth_failure = 0x01,				/*!< The symmetric cipher had an authentication failure */
	qsc_qsmp_error_random_failure = 0x02,			/*!< The random generator has failed */
	qsc_qsmp_error_key_expired = 0x03,				/*!< The QSMP public key has expired  */
	qsc_qsmp_error_invalid_request = 0x04,			/*!< The packet flag was unexpected */
	qsc_qsmp_error_decapsulation_failure = 0x05,	/*!< The asymmetric cipher failed to decapsulate the shared secret */
	qsc_qsmp_error_channel_down = 0x06,				/*!< The communications channel has failed */
	qsc_qsmp_error_hash_invalid = 0x07,				/*!< The public-key hash is invalid */
	qsc_qsmp_error_invalid_input = 0x08,			/*!< The expected input was invalid */
	qsc_qsmp_error_receive_failure = 0x09,			/*!< The receiver failed at the network layer */
	qsc_qsmp_error_transmit_failure = 0x0A,			/*!< The transmitter failed at the network layer */
	qsc_qsmp_error_connection_failure = 0x0B,		/*!< The device could not make a connnection to the remote host */
	qsc_qsmp_error_connect_failure = 0x0C,			/*!< The transmission failed at the kex connection phase */
	qsc_qsmp_error_exstart_failure = 0x0D,			/*!< The transmission failed at the kex exstart phase */
	qsc_qsmp_error_exchange_failure = 0x0E,			/*!< The transmission failed at the kex exchange phase */
	qsc_qsmp_error_establish_failure = 0x0F,		/*!< The transmission failed at the kex establish phase */
	qsc_qsmp_error_unknown_protocol = 0x10,			/*!< The protocol string was not recognized */
	qsc_qsmp_error_packet_unsequenced = 0x11,		/*!< The packet was received out of sequence */
	qsc_qsmp_error_bad_keep_alive = 0x12,			/*!< The keep alive check failed */
	qsc_qsmp_error_keep_alive_expired = 0x13,		/*!< The keep alive has expired with no response */
} qsc_qsmp_errors;

/*!
* \enum qsc_qsmp_flags
* \brief The QSMP packet flags
*/
QSC_EXPORT_API typedef enum qsc_qsmp_flags
{
	qsc_qsmp_message_none = 0x00,					/*!< No flag was specified */
	qsc_qsmp_message_connect_request = 0x01,		/*!< The QSMP key-exchange client connection request flag  */
	qsc_qsmp_message_connect_response = 0x02,		/*!< The QSMP key-exchange server connection response flag */
	qsc_qsmp_message_exstart_request = 0x03,		/*!< The QSMP key-exchange client exstart request flag */
	qsc_qsmp_message_exstart_response = 0x04,		/*!< The QSMP key-exchange server exstart response flag */
	qsc_qsmp_message_exchange_request = 0x05,		/*!< The QSMP key-exchange client exchange request flag */
	qsc_qsmp_message_exchange_response = 0x06,		/*!< The QSMP key-exchange server exchange response flag */
	qsc_qsmp_message_establish_request = 0x07,		/*!< The QSMP key-exchange client establish request flag */
	qsc_qsmp_message_establish_response = 0x08,		/*!< The QSMP key-exchange server establish response flag */
	qsc_qsmp_message_remote_connected = 0x09,		/*!< The remote host is connected to the VPN */
	qsc_qsmp_message_remote_terminated = 0x0A,		/*!< The remote host has terminated the connection */
	qsc_qsmp_message_session_established = 0x0B,	/*!< The VPN is in the established state */
	qsc_qsmp_message_encrypted_message = 0x0C,		/*!< The message has been encrypted by the VPN */
	qsc_qsmp_message_connection_terminate = 0x0D,	/*!< The connection is to be terminated */
	qsc_qsmp_message_unrecognized_protocol = 0x0E,	/*!< The protocol string is not recognized */
	qsc_qsmp_message_keep_alive_request = 0x0F,		/*!< The packet contains a keep alive request */
	qsc_qsmp_message_error_condition = 0xFF,		/*!< The connection experienced an error */
} qsc_qsmp_flags;

/*!
* \struct qsc_qsmp_packet
* \brief The QSMP packet structure
*/
QSC_EXPORT_API typedef struct qsc_qsmp_packet
{
	uint8_t flag;									/*!< The packet flag */
	uint32_t msglen;								/*!< The packets message length */
	uint64_t sequence;								/*!< The packet sequence number */
	uint8_t message[QSC_QSMP_MESSAGE_MAX];			/*!< The packets message data */
} qsc_qsmp_packet;

/*!
* \struct qsc_qsmp_client_key
* \brief The QSMP client key structure
*/
QSC_EXPORT_API typedef struct qsc_qsmp_client_key
{
	uint64_t expiration;							/*!< The expiration time, in seconds from epoch */
	uint8_t config[QSC_QSMP_CONFIG_SIZE];			/*!< The primitive configuration string */
	uint8_t keyid[QSC_QSMP_KEYID_SIZE];				/*!< The key identity string */
	uint8_t verkey[QSC_QSMP_VERIFYKEY_SIZE];		/*!< The asymmetric signatures verification-key */
} qsc_qsmp_client_key;

/*!
* \struct qsmp_keep_alive_state
* \brief The QSMP keep alive state structure
*/
QSC_EXPORT_API typedef struct qsmp_keep_alive_state
{
	uint64_t etime;										/*!< The keep alive epoch time  */
	uint64_t seqctr;									/*!< The keep alive packet sequence number  */
	bool recd;											/*!< The keep alive response received status  */
} qsmp_keep_alive_state;


/**
* \brief Populate a packet structure with an error message
*
* \param packet: A pointer to the packet structure
* \param error: The error type
*/
QSC_EXPORT_API void qsc_qsmp_packet_clear(qsc_qsmp_packet* packet);

/**
* \brief Return a pointer to a string description of an error code
*
* \param error: The error type
* \return Returns a pointer to an error string, or NULL if not recognized
*/
QSC_EXPORT_API const char* qsc_qsmp_error_to_string(qsc_qsmp_errors error);

/**
* \brief Populate a packet structure with an error message
*
* \param packet: A pointer to the packet structure
* \param error: The error type
*/
QSC_EXPORT_API void qsc_qsmp_packet_error_message(qsc_qsmp_packet* packet, qsc_qsmp_errors error);

/**
* \brief Deserialize a byte array to a packet header
*
* \param packet: The header byte array to deserialize
* \param header: A pointer to the packet structure
*/
QSC_EXPORT_API void qsc_qsmp_packet_header_deserialize(const uint8_t* header, qsc_qsmp_packet* packet);

/**
* \brief Serialize a packet header to a byte array
*
* \param packet: A pointer to the packet structure to serialize
* \param header: The header byte array
*/
QSC_EXPORT_API void qsc_qsmp_packet_header_serialize(const qsc_qsmp_packet* packet, uint8_t* header);

/**
* \brief Serialize a packet to a byte array
*
* \param packet: The header byte array to deserialize
* \param pstream: A pointer to the packet structure
* \return Returns the size of the byte stream
*/
QSC_EXPORT_API size_t qsc_qsmp_packet_to_stream(const qsc_qsmp_packet* packet, uint8_t* pstream);

/**
* \brief Deserialize a byte array to a packet
*
* \param pstream: The header byte array to deserialize
* \param packet: A pointer to the packet structure
*/
QSC_EXPORT_API void qsc_qsmp_stream_to_packet(const uint8_t* pstream, qsc_qsmp_packet* packet);

#endif
// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/ssl.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509v3.h>

#include "testrunnerswitcher.h"
#include "azure_c_shared_utility/tlsio.h"
#include "azure_c_shared_utility/tlsio_openssl.h"
#include "azure_c_shared_utility/shared_util_options.h"
#include "azure_c_shared_utility/threadapi.h"

#ifdef _WIN32
typedef SOCKET TEST_SOCKET;
#define INVALID_TEST_SOCKET INVALID_SOCKET
#define close_test_socket closesocket
#else
typedef int TEST_SOCKET;
#define INVALID_TEST_SOCKET (-1)
#define close_test_socket close
#endif

typedef struct TLS_SERVER_TAG
{
    TEST_SOCKET listener;
    SSL_CTX* context;
    THREAD_HANDLE thread;
    int port;
    int accepted;
} TLS_SERVER;

typedef struct OPEN_RESULT_TAG
{
    int completed;
    IO_OPEN_RESULT result;
} OPEN_RESULT;

static EVP_PKEY* test_ca_key;
static X509* test_ca;

static EVP_PKEY* generate_key(void)
{
    EVP_PKEY* key = NULL;
    EVP_PKEY_CTX* context = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (context != NULL)
    {
        if (EVP_PKEY_keygen_init(context) != 1 ||
            EVP_PKEY_CTX_set_rsa_keygen_bits(context, 2048) != 1 ||
            EVP_PKEY_keygen(context, &key) != 1)
        {
            EVP_PKEY_free(key);
            key = NULL;
        }
        EVP_PKEY_CTX_free(context);
    }
    return key;
}

static int add_extension(X509* certificate, X509* issuer, int nid, const char* value)
{
    X509V3_CTX context;
    X509_EXTENSION* extension;
    int result = 0;

    X509V3_set_ctx(&context, issuer, certificate, NULL, NULL, 0);
    extension = X509V3_EXT_conf_nid(NULL, &context, nid, (char*)value);
    if (extension != NULL)
    {
        result = X509_add_ext(certificate, extension, -1);
        X509_EXTENSION_free(extension);
    }
    return result == 1;
}

static X509* generate_certificate(EVP_PKEY* key, X509* issuer, EVP_PKEY* issuer_key, const char* san)
{
    X509* certificate = X509_new();
    X509_NAME* subject;
    int is_ca = (issuer == NULL);

    if (certificate == NULL || X509_set_version(certificate, 2) != 1 ||
        ASN1_INTEGER_set(X509_get_serialNumber(certificate), is_ca ? 1 : 2) != 1 ||
        X509_gmtime_adj(X509_get_notBefore(certificate), -60) == NULL ||
        X509_gmtime_adj(X509_get_notAfter(certificate), 3600) == NULL ||
        X509_set_pubkey(certificate, key) != 1)
    {
        goto error;
    }
    subject = X509_get_subject_name(certificate);
    if (X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC,
        (const unsigned char*)(is_ca ? "isolated test CA" : "test server"), -1, -1, 0) != 1 ||
        X509_set_issuer_name(certificate, is_ca ? subject : X509_get_subject_name(issuer)) != 1 ||
        !add_extension(certificate, is_ca ? certificate : issuer, NID_basic_constraints,
            is_ca ? "critical,CA:TRUE" : "critical,CA:FALSE") ||
        !add_extension(certificate, is_ca ? certificate : issuer, NID_key_usage,
            is_ca ? "critical,keyCertSign,cRLSign" : "critical,digitalSignature,keyEncipherment") ||
        (!is_ca && (!add_extension(certificate, issuer, NID_ext_key_usage, "serverAuth") ||
                    !add_extension(certificate, issuer, NID_subject_alt_name, san))) ||
        X509_sign(certificate, is_ca ? key : issuer_key, EVP_sha256()) <= 0)
    {
        goto error;
    }
    return certificate;

error:
    X509_free(certificate);
    return NULL;
}

static char* certificate_pem(X509* certificate)
{
    BIO* memory = BIO_new(BIO_s_mem());
    char* result = NULL;
    BUF_MEM* buffer;

    if (memory != NULL && PEM_write_bio_X509(memory, certificate) == 1)
    {
        BIO_get_mem_ptr(memory, &buffer);
        result = (char*)malloc(buffer->length + 1);
        if (result != NULL)
        {
            memcpy(result, buffer->data, buffer->length);
            result[buffer->length] = '\0';
        }
    }
    BIO_free(memory);
    return result;
}

static int has_valid_ca_chain(X509* certificate)
{
    int result = 0;
    X509_STORE* store = X509_STORE_new();
    X509_STORE_CTX* verification = X509_STORE_CTX_new();

    if (store != NULL && verification != NULL &&
        X509_STORE_add_cert(store, test_ca) == 1 &&
        X509_STORE_CTX_init(verification, store, certificate, NULL) == 1)
    {
        result = X509_verify_cert(verification) == 1;
    }
    X509_STORE_CTX_free(verification);
    X509_STORE_free(store);
    return result;
}

static int server_thread(void* context)
{
    TLS_SERVER* server = (TLS_SERVER*)context;
    struct timeval timeout = { 5, 0 };
    fd_set readable;
    TEST_SOCKET connection = INVALID_TEST_SOCKET;
    SSL* ssl = NULL;

    FD_ZERO(&readable);
    FD_SET(server->listener, &readable);
    if (select((int)server->listener + 1, &readable, NULL, NULL, &timeout) == 1)
    {
        connection = accept(server->listener, NULL, NULL);
        if (connection != INVALID_TEST_SOCKET)
        {
            server->accepted = 1;
#ifdef _WIN32
            {
                DWORD milliseconds = 5000;
                (void)setsockopt(connection, SOL_SOCKET, SO_RCVTIMEO, (const char*)&milliseconds, sizeof(milliseconds));
            }
#else
            (void)setsockopt(connection, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
#endif
            ssl = SSL_new(server->context);
            if (ssl != NULL && SSL_set_fd(ssl, (int)connection) == 1)
            {
                (void)SSL_accept(ssl);
            }
        }
    }
    SSL_free(ssl);
    if (connection != INVALID_TEST_SOCKET)
    {
        (void)close_test_socket(connection);
    }
    return 0;
}

static int start_server(TLS_SERVER* server, X509* certificate, EVP_PKEY* key)
{
    struct sockaddr_in6 address;
#ifdef _WIN32
    int address_size = sizeof(address);
#else
    socklen_t address_size = sizeof(address);
#endif
    int ipv6_only = 1;

    memset(server, 0, sizeof(*server));
    server->listener = INVALID_TEST_SOCKET;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    server->context = SSL_CTX_new(SSLv23_server_method());
#else
    server->context = SSL_CTX_new(TLS_server_method());
#endif
    if (server->context == NULL ||
        SSL_CTX_use_certificate(server->context, certificate) != 1 ||
        SSL_CTX_use_PrivateKey(server->context, key) != 1)
    {
        return 0;
    }
    server->listener = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (server->listener == INVALID_TEST_SOCKET)
    {
        return 0;
    }
    (void)setsockopt(server->listener, IPPROTO_IPV6, IPV6_V6ONLY,
        (const char*)&ipv6_only, sizeof(ipv6_only));
    memset(&address, 0, sizeof(address));
    address.sin6_family = AF_INET6;
    address.sin6_addr.s6_addr[15] = 1;
    if (bind(server->listener, (const struct sockaddr*)&address, sizeof(address)) != 0 ||
        getsockname(server->listener, (struct sockaddr*)&address, &address_size) != 0 ||
        listen(server->listener, 1) != 0)
    {
        return 0;
    }
    server->port = ntohs(address.sin6_port);
    return ThreadAPI_Create(&server->thread, server_thread, server) == THREADAPI_OK;
}

static void stop_server(TLS_SERVER* server)
{
    if (server->thread != NULL)
    {
        int thread_result;
        (void)ThreadAPI_Join(server->thread, &thread_result);
    }
    if (server->listener != INVALID_TEST_SOCKET)
    {
        (void)close_test_socket(server->listener);
    }
    SSL_CTX_free(server->context);
}

static void open_complete(void* context, IO_OPEN_RESULT_DETAILED result)
{
    OPEN_RESULT* state = (OPEN_RESULT*)context;
    state->completed = 1;
    state->result = result.result;
}

static int handshake_result(CONCRETE_IO_HANDLE io, OPEN_RESULT* state)
{
    time_t deadline = time(NULL) + 8;
    memset(state, 0, sizeof(*state));
    if (tlsio_openssl_open(io, open_complete, state, NULL, NULL, NULL, NULL) != 0)
    {
        return 0;
    }
    while (!state->completed && time(NULL) < deadline)
    {
        tlsio_openssl_dowork(io);
        ThreadAPI_Sleep(1);
    }
    return state->completed;
}

static int run_handshake(const char* hostname, const char* server_san, IO_OPEN_RESULT expected)
{
    int ok = 0;
    int started = 0;
    EVP_PKEY* server_key = NULL;
    X509* leaf = NULL;
    char* trusted_ca = NULL;
    CONCRETE_IO_HANDLE io = NULL;
    TLS_SERVER server;
    TLSIO_CONFIG config = { 0 };
    OPEN_RESULT outcome;
    const bool isolate_trust = true;
    const bool disable_crl_check = true;

    memset(&server, 0, sizeof(server));
    server.listener = INVALID_TEST_SOCKET;
#ifdef _WIN32
    {
        WSADATA winsock;
        if (WSAStartup(MAKEWORD(2, 2), &winsock) != 0)
        {
            return 0;
        }
    }
#endif
    server_key = generate_key();
    if (server_key == NULL || test_ca == NULL || test_ca_key == NULL ||
        (leaf = generate_certificate(server_key, test_ca, test_ca_key, server_san)) == NULL ||
        !has_valid_ca_chain(leaf) ||
        (trusted_ca = certificate_pem(test_ca)) == NULL ||
        !start_server(&server, leaf, server_key))
    {
        goto cleanup;
    }
    started = 1;
    config.hostname = hostname;
    config.port = server.port;
    config.enable_ipv6 = 1;
    io = tlsio_openssl_create(&config);
    if (io == NULL ||
        tlsio_openssl_setoption(io, OPTION_DISABLE_DEFAULT_VERIFY_PATHS, &isolate_trust) != 0 ||
        // These ephemeral certificates have no CRL; this does not disable peer or IP SAN verification.
        tlsio_openssl_setoption(io, OPTION_DISABLE_CRL_CHECK, &disable_crl_check) != 0 ||
        tlsio_openssl_setoption(io, OPTION_TRUSTED_CERT, trusted_ca) != 0)
    {
        goto cleanup;
    }
    ok = handshake_result(io, &outcome) && outcome.result == expected && server.accepted;

cleanup:
    if (io != NULL)
    {
        tlsio_openssl_destroy(io);
    }
    stop_server(&server);
    free(trusted_ca);
    X509_free(leaf);
    EVP_PKEY_free(server_key);
#ifdef _WIN32
    (void)WSACleanup();
#endif
    return started && ok;
}

BEGIN_TEST_SUITE(tlsio_openssl_ut)

TEST_SUITE_INITIALIZE(initialize_ca)
{
    test_ca_key = generate_key();
    ASSERT_IS_NOT_NULL(test_ca_key);
    test_ca = generate_certificate(test_ca_key, NULL, NULL, NULL);
    ASSERT_IS_NOT_NULL(test_ca);
}

TEST_SUITE_CLEANUP(cleanup_ca)
{
    X509_free(test_ca);
    EVP_PKEY_free(test_ca_key);
}

TEST_FUNCTION(create_rejects_null_hostname)
{
    TLSIO_CONFIG config = {0};
    config.port = 443;

    ASSERT_IS_NULL(tlsio_openssl_create(&config));
}

TEST_FUNCTION(trusted_ca_and_matching_ipv6_ip_san_complete_handshake)
{
    ASSERT_IS_TRUE(run_handshake("::1", "IP:::1", IO_OPEN_OK));
}

TEST_FUNCTION(trusted_ca_and_wrong_ipv6_ip_san_reject_handshake)
{
    ASSERT_IS_TRUE(run_handshake("::1", "IP:::2", IO_OPEN_ERROR));
}

TEST_FUNCTION(scoped_ipv6_loopback_matches_unscoped_ip_san)
{
    ASSERT_IS_TRUE(run_handshake("::1%1", "IP:::1", IO_OPEN_OK));
}

END_TEST_SUITE(tlsio_openssl_ut)

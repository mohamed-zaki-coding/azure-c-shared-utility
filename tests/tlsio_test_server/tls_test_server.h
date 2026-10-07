// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#ifndef TLS_TEST_SERVER_H
#define TLS_TEST_SERVER_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct TLS_TEST_CA_TAG TLS_TEST_CA;
typedef struct TLS_TEST_SERVER_TAG TLS_TEST_SERVER;

// The CA and server private keys never leave this test fixture or touch disk.
TLS_TEST_CA* tls_test_ca_create(void);
void tls_test_ca_destroy(TLS_TEST_CA* ca);

// Caller frees the returned public certificate with free(). DER is suitable
// for a disposable Windows runner's temporary CurrentUser Root installation.
char* tls_test_ca_pem(const TLS_TEST_CA* ca);
unsigned char* tls_test_ca_der(const TLS_TEST_CA* ca, int* length);

// Binds ::1 on an ephemeral port and accepts one TLS connection. The SAN is
// an OpenSSL X509V3 value such as "IP:::1" or "IP:::2".
TLS_TEST_SERVER* tls_test_server_start(TLS_TEST_CA* ca, const char* san);
int tls_test_server_port(const TLS_TEST_SERVER* server);

// Joins the server thread and returns 1 if it accepted a connection, 0 if
// none arrived, or -1 if the thread could not be joined. Frees the server
// after a successful join; a failed join must not free a live thread's state.
int tls_test_server_stop(TLS_TEST_SERVER* server);

#ifdef __cplusplus
}
#endif

#endif

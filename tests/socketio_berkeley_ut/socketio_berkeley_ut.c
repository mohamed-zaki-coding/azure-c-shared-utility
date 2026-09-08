// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include "testrunnerswitcher.h"

static void* test_malloc(size_t size)
{
    return malloc(size);
}

static void test_free(void* pointer)
{
    free(pointer);
}

#define ENABLE_MOCKS
#include "azure_c_shared_utility/gballoc.h"
#include "azure_c_shared_utility/optionhandler.h"
#include "azure_c_shared_utility/singlylinkedlist.h"
#undef ENABLE_MOCKS

#include "azure_c_shared_utility/shared_util_options.h"
#include "azure_c_shared_utility/socketio.h"
#include "umock_c.h"

#define TEST_HOSTNAME "dual-stack.example"
#define TEST_PORT 443
#define TEST_SOCKET 42
#define TEST_ANY_NONZERO_CODE (-1)
#define TEST_POLL_TIMEOUT_MS 10000

typedef struct SYSTEM_CALL_STATE_TAG
{
    int getaddrinfo_result;
    struct addrinfo* resolved_addresses;
    size_t getaddrinfo_calls;
    char node[64];
    char service[16];
    struct addrinfo hints;

    int socket_result;
    int socket_errno;
    size_t socket_calls;
    int socket_family;
    int socket_type;
    int socket_protocol;

    int fcntl_get_result;
    int fcntl_get_errno;
    int fcntl_set_result;
    int fcntl_set_errno;
    size_t fcntl_calls;
    int fcntl_commands[2];
    int fcntl_arguments[2];

    int connect_result;
    int connect_errno;
    size_t connect_calls;
    int connect_socket;
    const struct sockaddr* connect_address;
    socklen_t connect_address_length;

    int poll_result;
    int poll_errno;
    size_t poll_calls;
    int poll_socket;
    short poll_events;
    int poll_timeout;

    int getsockopt_result;
    int getsockopt_errno;
    int socket_error;
    size_t getsockopt_calls;

    int ioctl_result;
    int ioctl_errno;
    size_t ioctl_fail_on_call;
    size_t ioctl_calls;
    int ioctl_socket;
    unsigned long ioctl_request;

    size_t freeaddrinfo_calls;
    struct addrinfo* freed_addresses;
    size_t close_calls;
    int closed_socket;
} SYSTEM_CALL_STATE;

static SYSTEM_CALL_STATE system_calls;
static bool intercept_system_calls;
static struct sockaddr_storage ipv4_address_storage;
static struct sockaddr_in6 ipv6_address;
static struct addrinfo first_address;
static struct addrinfo second_address;

static size_t open_complete_calls;
static void* open_complete_context;
static IO_OPEN_RESULT_DETAILED open_complete_result;
static int callback_context;
static TEST_MUTEX_HANDLE test_mutex;

int __real_getaddrinfo(const char* node, const char* service, const struct addrinfo* hints, struct addrinfo** result);
void __real_freeaddrinfo(struct addrinfo* result);
int __real_socket(int domain, int type, int protocol);
int __real_close(int fd);
int __real_fcntl(int fd, int command, ...);
int __real_connect(int fd, const struct sockaddr* address, socklen_t address_length);
int __real_poll(struct pollfd* fds, nfds_t count, int timeout);
int __real_getsockopt(int fd, int level, int option_name, void* option_value, socklen_t* option_length);
int __real_ioctl(int fd, unsigned long request, ...);

int __wrap_getaddrinfo(const char* node, const char* service, const struct addrinfo* hints, struct addrinfo** result)
{
    if (!intercept_system_calls)
    {
        return __real_getaddrinfo(node, service, hints, result);
    }

    system_calls.getaddrinfo_calls++;
    (void)snprintf(system_calls.node, sizeof(system_calls.node), "%s", (node == NULL) ? "<null>" : node);
    (void)snprintf(system_calls.service, sizeof(system_calls.service), "%s", (service == NULL) ? "<null>" : service);
    if (hints != NULL)
    {
        system_calls.hints = *hints;
    }
    *result = (system_calls.getaddrinfo_result == 0) ? system_calls.resolved_addresses : NULL;
    return system_calls.getaddrinfo_result;
}

void __wrap_freeaddrinfo(struct addrinfo* result)
{
    if (!intercept_system_calls)
    {
        __real_freeaddrinfo(result);
    }
    else
    {
        system_calls.freeaddrinfo_calls++;
        system_calls.freed_addresses = result;
    }
}

int __wrap_socket(int domain, int type, int protocol)
{
    if (!intercept_system_calls)
    {
        return __real_socket(domain, type, protocol);
    }

    system_calls.socket_calls++;
    system_calls.socket_family = domain;
    system_calls.socket_type = type;
    system_calls.socket_protocol = protocol;
    if (system_calls.socket_result < 0)
    {
        errno = system_calls.socket_errno;
    }
    return system_calls.socket_result;
}

int __wrap_close(int fd)
{
    if (!intercept_system_calls)
    {
        return __real_close(fd);
    }

    system_calls.close_calls++;
    system_calls.closed_socket = fd;
    return 0;
}

int __wrap_fcntl(int fd, int command, ...)
{
    int argument = 0;

    if (command != F_GETFL)
    {
        va_list arguments;
        va_start(arguments, command);
        argument = va_arg(arguments, int);
        va_end(arguments);
    }

    if (!intercept_system_calls)
    {
        return (command == F_GETFL) ? __real_fcntl(fd, command) : __real_fcntl(fd, command, argument);
    }

    (void)fd;
    if (system_calls.fcntl_calls < 2)
    {
        system_calls.fcntl_commands[system_calls.fcntl_calls] = command;
        system_calls.fcntl_arguments[system_calls.fcntl_calls] = argument;
    }
    system_calls.fcntl_calls++;

    if (command == F_GETFL)
    {
        if (system_calls.fcntl_get_result < 0)
        {
            errno = system_calls.fcntl_get_errno;
        }
        return system_calls.fcntl_get_result;
    }
    else
    {
        if (system_calls.fcntl_set_result < 0)
        {
            errno = system_calls.fcntl_set_errno;
        }
        return system_calls.fcntl_set_result;
    }
}

int __wrap_connect(int fd, const struct sockaddr* address, socklen_t address_length)
{
    if (!intercept_system_calls)
    {
        return __real_connect(fd, address, address_length);
    }

    system_calls.connect_calls++;
    system_calls.connect_socket = fd;
    system_calls.connect_address = address;
    system_calls.connect_address_length = address_length;
    if (system_calls.connect_result != 0)
    {
        errno = system_calls.connect_errno;
    }
    return system_calls.connect_result;
}

int __wrap_poll(struct pollfd* fds, nfds_t count, int timeout)
{
    if (!intercept_system_calls)
    {
        return __real_poll(fds, count, timeout);
    }

    system_calls.poll_calls++;
    if ((fds != NULL) && (count > 0))
    {
        system_calls.poll_socket = fds[0].fd;
        system_calls.poll_events = fds[0].events;
    }
    system_calls.poll_timeout = timeout;
    if (system_calls.poll_result < 0)
    {
        errno = system_calls.poll_errno;
    }
    return system_calls.poll_result;
}

int __wrap_getsockopt(int fd, int level, int option_name, void* option_value, socklen_t* option_length)
{
    if (!intercept_system_calls)
    {
        return __real_getsockopt(fd, level, option_name, option_value, option_length);
    }

    (void)fd;
    (void)level;
    (void)option_name;
    (void)option_length;
    system_calls.getsockopt_calls++;
    if (system_calls.getsockopt_result != 0)
    {
        errno = system_calls.getsockopt_errno;
    }
    else
    {
        *(int*)option_value = system_calls.socket_error;
    }
    return system_calls.getsockopt_result;
}

int __wrap_ioctl(int fd, unsigned long request, ...)
{
    va_list arguments;
    void* argument;

    va_start(arguments, request);
    argument = va_arg(arguments, void*);
    va_end(arguments);

    if (!intercept_system_calls)
    {
        return __real_ioctl(fd, request, argument);
    }

    system_calls.ioctl_calls++;
    system_calls.ioctl_socket = fd;
    system_calls.ioctl_request = request;
    if ((system_calls.ioctl_result != 0) &&
        ((system_calls.ioctl_fail_on_call == 0) || (system_calls.ioctl_calls == system_calls.ioctl_fail_on_call)))
    {
        errno = system_calls.ioctl_errno;
        return system_calls.ioctl_result;
    }
    else if ((request == SIOCGIFCONF) && (argument != NULL))
    {
        struct ifconf* interface_config = (struct ifconf*)argument;
        struct ifreq* interface_request = interface_config->ifc_req;
        (void)memset(interface_request, 0, sizeof(*interface_request));
        (void)snprintf(interface_request->ifr_name, sizeof(interface_request->ifr_name), "%s", "eth-test");
        interface_config->ifc_len = sizeof(*interface_request);
    }

    return 0;
}

static void on_open_complete(void* context, IO_OPEN_RESULT_DETAILED result)
{
    open_complete_calls++;
    open_complete_context = context;
    open_complete_result = result;
}

static void on_bytes_received(void* context, const unsigned char* buffer, size_t size)
{
    (void)context;
    (void)buffer;
    (void)size;
}

static void on_io_error(void* context)
{
    (void)context;
}

static void on_umock_c_error(UMOCK_C_ERROR_CODE error_code)
{
    (void)error_code;
    ASSERT_FAIL("umock_c reported an error");
}

static CONCRETE_IO_HANDLE create_client(void)
{
    SOCKETIO_CONFIG config = { TEST_HOSTNAME, TEST_PORT, NULL };
    CONCRETE_IO_HANDLE result = socketio_create(&config);
    ASSERT_IS_NOT_NULL(result);
    return result;
}

static int open_client(CONCRETE_IO_HANDLE client)
{
    return socketio_open(client, on_open_complete, &callback_context,
        on_bytes_received, &callback_context, on_io_error, &callback_context);
}

static void assert_resolver_request(void)
{
    ASSERT_ARE_EQUAL(size_t, 1, system_calls.getaddrinfo_calls);
    ASSERT_ARE_EQUAL(char_ptr, TEST_HOSTNAME, system_calls.node);
    ASSERT_ARE_EQUAL(char_ptr, "443", system_calls.service);
    ASSERT_ARE_EQUAL(int, 0, system_calls.hints.ai_flags);
    ASSERT_ARE_EQUAL(int, AF_UNSPEC, system_calls.hints.ai_family);
    ASSERT_ARE_EQUAL(int, SOCK_STREAM, system_calls.hints.ai_socktype);
    ASSERT_ARE_EQUAL(int, 0, system_calls.hints.ai_protocol);
}

static void assert_open_complete(IO_OPEN_RESULT expected_result, int expected_code)
{
    ASSERT_ARE_EQUAL(size_t, 1, open_complete_calls);
    ASSERT_ARE_EQUAL(void_ptr, &callback_context, open_complete_context);
    ASSERT_ARE_EQUAL(int, (int)expected_result, (int)open_complete_result.result);
    if (expected_code == TEST_ANY_NONZERO_CODE)
    {
        ASSERT_ARE_NOT_EQUAL(int, 0, open_complete_result.code);
    }
    else
    {
        ASSERT_ARE_EQUAL(int, expected_code, open_complete_result.code);
    }
}

static void assert_rejected_resolved_address(CONCRETE_IO_HANDLE client, int expected_code)
{
    int result = open_client(client);

    ASSERT_ARE_EQUAL(int, 0, result);
    assert_resolver_request();
    ASSERT_ARE_EQUAL(size_t, 0, system_calls.socket_calls);
    ASSERT_ARE_EQUAL(size_t, 0, system_calls.fcntl_calls);
    ASSERT_ARE_EQUAL(size_t, 0, system_calls.connect_calls);
    ASSERT_ARE_EQUAL(size_t, 0, system_calls.close_calls);
    ASSERT_ARE_EQUAL(size_t, 1, system_calls.freeaddrinfo_calls);
    ASSERT_ARE_EQUAL(void_ptr, &first_address, system_calls.freed_addresses);
    assert_open_complete(IO_OPEN_ERROR, expected_code);
}

static void assert_created_socket_was_cleaned_up(void)
{
    ASSERT_ARE_EQUAL(size_t, 1, system_calls.close_calls);
    ASSERT_ARE_EQUAL(int, TEST_SOCKET, system_calls.closed_socket);
    ASSERT_ARE_EQUAL(size_t, 1, system_calls.freeaddrinfo_calls);
    ASSERT_ARE_EQUAL(void_ptr, &first_address, system_calls.freed_addresses);
}

static void assert_nonblocking_setup(void)
{
    ASSERT_ARE_EQUAL(size_t, 2, system_calls.fcntl_calls);
    ASSERT_ARE_EQUAL(int, F_GETFL, system_calls.fcntl_commands[0]);
    ASSERT_ARE_EQUAL(int, F_SETFL, system_calls.fcntl_commands[1]);
    ASSERT_ARE_EQUAL(int, system_calls.fcntl_get_result | O_NONBLOCK, system_calls.fcntl_arguments[1]);
}

BEGIN_TEST_SUITE(socketio_berkeley_unittests)

TEST_SUITE_INITIALIZE(suite_init)
{
    test_mutex = TEST_MUTEX_CREATE();
    ASSERT_IS_NOT_NULL(test_mutex);
    ASSERT_ARE_EQUAL(int, 0, umock_c_init(on_umock_c_error));

    REGISTER_UMOCK_ALIAS_TYPE(SINGLYLINKEDLIST_HANDLE, void*);
    REGISTER_UMOCK_ALIAS_TYPE(LIST_ITEM_HANDLE, void*);
    REGISTER_GLOBAL_MOCK_HOOK(gballoc_malloc, test_malloc);
    REGISTER_GLOBAL_MOCK_HOOK(gballoc_free, test_free);
    REGISTER_GLOBAL_MOCK_RETURN(singlylinkedlist_create, (SINGLYLINKEDLIST_HANDLE)(uintptr_t)0x4242);
    REGISTER_GLOBAL_MOCK_RETURN(singlylinkedlist_get_head_item, NULL);
    REGISTER_GLOBAL_MOCK_RETURN(singlylinkedlist_remove, 0);
}

TEST_SUITE_CLEANUP(suite_cleanup)
{
    umock_c_deinit();
    TEST_MUTEX_DESTROY(test_mutex);
}

TEST_FUNCTION_INITIALIZE(method_init)
{
    struct sockaddr_in* ipv4_address = (struct sockaddr_in*)&ipv4_address_storage;

    ASSERT_ARE_EQUAL(int, 0, TEST_MUTEX_ACQUIRE(test_mutex));
    umock_c_reset_all_calls();
    (void)memset(&system_calls, 0, sizeof(system_calls));
    system_calls.resolved_addresses = &first_address;
    system_calls.socket_result = TEST_SOCKET;
    system_calls.socket_errno = EMFILE;
    system_calls.fcntl_get_result = O_RDWR;
    system_calls.fcntl_get_errno = EIO;
    system_calls.fcntl_set_result = 0;
    system_calls.fcntl_set_errno = EACCES;
    system_calls.connect_result = 0;
    system_calls.connect_errno = ECONNREFUSED;
    system_calls.poll_result = 1;
    system_calls.poll_errno = EIO;
    system_calls.getsockopt_result = 0;
    system_calls.getsockopt_errno = ENOPROTOOPT;
    system_calls.socket_error = 0;
    system_calls.ioctl_result = 0;
    system_calls.ioctl_errno = ENODEV;

    (void)memset(&ipv4_address_storage, 0, sizeof(ipv4_address_storage));
    ipv4_address->sin_family = AF_INET;
    ipv4_address->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    (void)memset(&ipv6_address, 0, sizeof(ipv6_address));
    ipv6_address.sin6_family = AF_INET6;
    ipv6_address.sin6_addr = in6addr_loopback;

    (void)memset(&first_address, 0, sizeof(first_address));
    first_address.ai_family = AF_INET;
    first_address.ai_socktype = SOCK_STREAM;
    first_address.ai_protocol = IPPROTO_TCP;
    first_address.ai_addrlen = sizeof(struct sockaddr_in);
    first_address.ai_addr = (struct sockaddr*)&ipv4_address_storage;

    (void)memset(&second_address, 0, sizeof(second_address));
    second_address.ai_family = AF_INET6;
    second_address.ai_socktype = SOCK_STREAM;
    second_address.ai_protocol = IPPROTO_TCP;
    second_address.ai_addrlen = sizeof(ipv6_address);
    second_address.ai_addr = (struct sockaddr*)&ipv6_address;

    open_complete_calls = 0;
    open_complete_context = NULL;
    open_complete_result.result = IO_OPEN_ERROR;
    open_complete_result.code = 0;
    intercept_system_calls = true;
}

TEST_FUNCTION_CLEANUP(method_cleanup)
{
    intercept_system_calls = false;
    TEST_MUTEX_RELEASE(test_mutex);
}

TEST_FUNCTION(socketio_open_rejects_empty_hostname_before_resolution)
{
    SOCKETIO_CONFIG config = { "", TEST_PORT, NULL };
    CONCRETE_IO_HANDLE client = socketio_create(&config);
    ASSERT_IS_NOT_NULL(client);

    int result = open_client(client);

    ASSERT_ARE_EQUAL(int, 0, result);
    ASSERT_ARE_EQUAL(size_t, 0, system_calls.getaddrinfo_calls);
    ASSERT_ARE_EQUAL(size_t, 0, system_calls.socket_calls);
    ASSERT_ARE_EQUAL(size_t, 0, system_calls.close_calls);
    assert_open_complete(IO_OPEN_ERROR, TEST_ANY_NONZERO_CODE);
    socketio_destroy(client);
}

TEST_FUNCTION(socketio_open_requests_system_ordered_IPv4_and_IPv6_stream_addresses)
{
    CONCRETE_IO_HANDLE client = create_client();

    int result = open_client(client);

    ASSERT_ARE_EQUAL(int, 0, result);
    assert_resolver_request();
    assert_open_complete(IO_OPEN_OK, 0);
    socketio_destroy(client);
}

TEST_FUNCTION(socketio_open_resolver_failure_does_not_create_or_close_a_socket)
{
    CONCRETE_IO_HANDLE client = create_client();
    system_calls.getaddrinfo_result = EAI_AGAIN;
    system_calls.socket_result = -1;

    int result = open_client(client);

    ASSERT_ARE_EQUAL(int, 0, result);
    assert_resolver_request();
    ASSERT_ARE_EQUAL(size_t, 0, system_calls.socket_calls);
    ASSERT_ARE_EQUAL(size_t, 0, system_calls.connect_calls);
    ASSERT_ARE_EQUAL(size_t, 0, system_calls.close_calls);
    ASSERT_ARE_EQUAL(size_t, 0, system_calls.freeaddrinfo_calls);
    assert_open_complete(IO_OPEN_ERROR, EAI_AGAIN);
    socketio_destroy(client);
}

TEST_FUNCTION(socketio_open_resolver_success_with_NULL_result_does_not_create_or_close_a_socket)
{
    CONCRETE_IO_HANDLE client = create_client();
    system_calls.resolved_addresses = NULL;
    system_calls.socket_result = -1;

    int result = open_client(client);

    ASSERT_ARE_EQUAL(int, 0, result);
    assert_resolver_request();
    ASSERT_ARE_EQUAL(size_t, 0, system_calls.socket_calls);
    ASSERT_ARE_EQUAL(size_t, 0, system_calls.connect_calls);
    ASSERT_ARE_EQUAL(size_t, 0, system_calls.close_calls);
    ASSERT_ARE_EQUAL(size_t, 0, system_calls.freeaddrinfo_calls);
    assert_open_complete(IO_OPEN_ERROR, EAI_FAIL);
    socketio_destroy(client);
}

TEST_FUNCTION(socketio_open_rejects_NULL_resolved_address)
{
    CONCRETE_IO_HANDLE client = create_client();
    first_address.ai_addr = NULL;

    assert_rejected_resolved_address(client, EAI_FAIL);

    socketio_destroy(client);
}

TEST_FUNCTION(socketio_open_rejects_short_IPv4_address)
{
    CONCRETE_IO_HANDLE client = create_client();
    first_address.ai_addr = (struct sockaddr*)(uintptr_t)1;
    first_address.ai_addrlen = sizeof(struct sockaddr_in) - 1;

    assert_rejected_resolved_address(client, EINVAL);

    socketio_destroy(client);
}

TEST_FUNCTION(socketio_open_rejects_short_IPv6_address)
{
    CONCRETE_IO_HANDLE client = create_client();
    first_address.ai_family = AF_INET6;
    first_address.ai_addrlen = sizeof(struct sockaddr_in6) - 1;
    first_address.ai_addr = (struct sockaddr*)&ipv6_address;

    assert_rejected_resolved_address(client, EINVAL);

    socketio_destroy(client);
}

TEST_FUNCTION(socketio_open_rejects_unsupported_address_family)
{
    CONCRETE_IO_HANDLE client = create_client();
    first_address.ai_family = AF_UNIX;
    first_address.ai_addr->sa_family = AF_UNIX;

    assert_rejected_resolved_address(client, EAFNOSUPPORT);

    socketio_destroy(client);
}

TEST_FUNCTION(socketio_open_rejects_mismatched_address_family)
{
    CONCRETE_IO_HANDLE client = create_client();
    first_address.ai_family = AF_INET6;
    first_address.ai_addrlen = sizeof(ipv6_address);
    first_address.ai_addr = (struct sockaddr*)&ipv6_address;
    ipv6_address.sin6_family = AF_INET;

    assert_rejected_resolved_address(client, EINVAL);

    socketio_destroy(client);
}

TEST_FUNCTION(socketio_open_socket_failure_uses_returned_fields_and_frees_address_once)
{
    CONCRETE_IO_HANDLE client = create_client();
    first_address.ai_socktype = SOCK_SEQPACKET;
    first_address.ai_protocol = IPPROTO_UDP;
    system_calls.socket_result = -1;
    system_calls.socket_errno = EMFILE;

    int result = open_client(client);

    ASSERT_ARE_EQUAL(int, 0, result);
    assert_resolver_request();
    ASSERT_ARE_EQUAL(size_t, 1, system_calls.socket_calls);
    ASSERT_ARE_EQUAL(int, AF_INET, system_calls.socket_family);
    ASSERT_ARE_EQUAL(int, SOCK_SEQPACKET, system_calls.socket_type);
    ASSERT_ARE_EQUAL(int, IPPROTO_UDP, system_calls.socket_protocol);
    ASSERT_ARE_EQUAL(size_t, 0, system_calls.fcntl_calls);
    ASSERT_ARE_EQUAL(size_t, 0, system_calls.connect_calls);
    ASSERT_ARE_EQUAL(size_t, 0, system_calls.close_calls);
    ASSERT_ARE_EQUAL(size_t, 1, system_calls.freeaddrinfo_calls);
    assert_open_complete(IO_OPEN_ERROR, EMFILE);
    socketio_destroy(client);
    ASSERT_ARE_EQUAL(size_t, 0, system_calls.close_calls);
}

TEST_FUNCTION(socketio_open_target_interface_failure_occurs_after_socket_creation_and_cleans_up)
{
    CONCRETE_IO_HANDLE client = create_client();
    system_calls.ioctl_result = -1;
    system_calls.ioctl_errno = ENODEV;
    system_calls.ioctl_fail_on_call = 2;
    ASSERT_ARE_EQUAL(int, 0, socketio_setoption(client, OPTION_NET_INT_MAC_ADDRESS, "01:02:03:04:05:06"));

    int result = open_client(client);

    ASSERT_ARE_EQUAL(int, 0, result);
    assert_resolver_request();
    ASSERT_ARE_EQUAL(size_t, 1, system_calls.socket_calls);
    ASSERT_ARE_EQUAL(size_t, 2, system_calls.ioctl_calls);
    ASSERT_ARE_EQUAL(int, TEST_SOCKET, system_calls.ioctl_socket);
    ASSERT_ARE_EQUAL(size_t, 0, system_calls.fcntl_calls);
    ASSERT_ARE_EQUAL(size_t, 0, system_calls.connect_calls);
    assert_created_socket_was_cleaned_up();
    assert_open_complete(IO_OPEN_ERROR, TEST_ANY_NONZERO_CODE);
    socketio_destroy(client);
    ASSERT_ARE_EQUAL(size_t, 1, system_calls.close_calls);
}

TEST_FUNCTION(socketio_open_F_GETFL_failure_closes_socket_and_frees_address_once)
{
    CONCRETE_IO_HANDLE client = create_client();
    system_calls.fcntl_get_result = -1;
    system_calls.fcntl_get_errno = EIO;

    int result = open_client(client);

    ASSERT_ARE_EQUAL(int, 0, result);
    ASSERT_ARE_EQUAL(size_t, 1, system_calls.fcntl_calls);
    ASSERT_ARE_EQUAL(int, F_GETFL, system_calls.fcntl_commands[0]);
    ASSERT_ARE_EQUAL(size_t, 0, system_calls.connect_calls);
    assert_created_socket_was_cleaned_up();
    assert_open_complete(IO_OPEN_ERROR, EIO);
    socketio_destroy(client);
    ASSERT_ARE_EQUAL(size_t, 1, system_calls.close_calls);
}

TEST_FUNCTION(socketio_open_F_SETFL_failure_closes_socket_and_frees_address_once)
{
    CONCRETE_IO_HANDLE client = create_client();
    system_calls.fcntl_set_result = -1;
    system_calls.fcntl_set_errno = EACCES;

    int result = open_client(client);

    ASSERT_ARE_EQUAL(int, 0, result);
    assert_nonblocking_setup();
    ASSERT_ARE_EQUAL(size_t, 0, system_calls.connect_calls);
    assert_created_socket_was_cleaned_up();
    assert_open_complete(IO_OPEN_ERROR, EACCES);
    socketio_destroy(client);
    ASSERT_ARE_EQUAL(size_t, 1, system_calls.close_calls);
}

TEST_FUNCTION(socketio_open_immediate_connect_failure_uses_only_first_result_and_cleans_up_once)
{
    CONCRETE_IO_HANDLE client = create_client();
    first_address.ai_next = &second_address;
    first_address.ai_socktype = SOCK_SEQPACKET;
    first_address.ai_protocol = IPPROTO_UDP;
    first_address.ai_addrlen = sizeof(struct sockaddr_in) + 3;
    system_calls.connect_result = -1;
    system_calls.connect_errno = ECONNREFUSED;

    int result = open_client(client);

    ASSERT_ARE_EQUAL(int, 0, result);
    ASSERT_ARE_EQUAL(size_t, 1, system_calls.socket_calls);
    ASSERT_ARE_EQUAL(int, AF_INET, system_calls.socket_family);
    ASSERT_ARE_EQUAL(int, SOCK_SEQPACKET, system_calls.socket_type);
    ASSERT_ARE_EQUAL(int, IPPROTO_UDP, system_calls.socket_protocol);
    assert_nonblocking_setup();
    ASSERT_ARE_EQUAL(size_t, 1, system_calls.connect_calls);
    ASSERT_ARE_EQUAL(void_ptr, &ipv4_address_storage, system_calls.connect_address);
    ASSERT_ARE_EQUAL(size_t, sizeof(struct sockaddr_in) + 3, (size_t)system_calls.connect_address_length);
    assert_created_socket_was_cleaned_up();
    assert_open_complete(IO_OPEN_ERROR, ECONNREFUSED);
    socketio_destroy(client);
    ASSERT_ARE_EQUAL(size_t, 1, system_calls.close_calls);
}

TEST_FUNCTION(socketio_open_immediate_IPv4_success_uses_first_result_exactly)
{
    CONCRETE_IO_HANDLE client = create_client();
    first_address.ai_next = &second_address;
    first_address.ai_socktype = SOCK_SEQPACKET;
    first_address.ai_protocol = IPPROTO_UDP;
    first_address.ai_addrlen = sizeof(struct sockaddr_in) + 3;

    int result = open_client(client);

    ASSERT_ARE_EQUAL(int, 0, result);
    assert_resolver_request();
    ASSERT_ARE_EQUAL(size_t, 1, system_calls.socket_calls);
    ASSERT_ARE_EQUAL(int, AF_INET, system_calls.socket_family);
    ASSERT_ARE_EQUAL(int, SOCK_SEQPACKET, system_calls.socket_type);
    ASSERT_ARE_EQUAL(int, IPPROTO_UDP, system_calls.socket_protocol);
    assert_nonblocking_setup();
    ASSERT_ARE_EQUAL(size_t, 1, system_calls.connect_calls);
    ASSERT_ARE_EQUAL(int, TEST_SOCKET, system_calls.connect_socket);
    ASSERT_ARE_EQUAL(void_ptr, &ipv4_address_storage, system_calls.connect_address);
    ASSERT_ARE_EQUAL(size_t, sizeof(struct sockaddr_in) + 3, (size_t)system_calls.connect_address_length);
    ASSERT_ARE_EQUAL(size_t, 0, system_calls.poll_calls);
    ASSERT_ARE_EQUAL(size_t, 0, system_calls.getsockopt_calls);
    ASSERT_ARE_EQUAL(size_t, 0, system_calls.close_calls);
    ASSERT_ARE_EQUAL(size_t, 1, system_calls.freeaddrinfo_calls);
    assert_open_complete(IO_OPEN_OK, 0);
    socketio_destroy(client);
}

TEST_FUNCTION(socketio_open_immediate_IPv6_success_uses_first_result_exactly)
{
    CONCRETE_IO_HANDLE client = create_client();
    first_address.ai_family = AF_INET6;
    first_address.ai_socktype = SOCK_DGRAM;
    first_address.ai_protocol = IPPROTO_UDP;
    first_address.ai_addrlen = sizeof(ipv6_address);
    first_address.ai_addr = (struct sockaddr*)&ipv6_address;
    first_address.ai_next = &second_address;
    second_address.ai_family = AF_INET;
    second_address.ai_addrlen = sizeof(struct sockaddr_in);
    second_address.ai_addr = (struct sockaddr*)&ipv4_address_storage;

    int result = open_client(client);

    ASSERT_ARE_EQUAL(int, 0, result);
    ASSERT_ARE_EQUAL(size_t, 1, system_calls.socket_calls);
    ASSERT_ARE_EQUAL(int, AF_INET6, system_calls.socket_family);
    ASSERT_ARE_EQUAL(int, SOCK_DGRAM, system_calls.socket_type);
    ASSERT_ARE_EQUAL(int, IPPROTO_UDP, system_calls.socket_protocol);
    ASSERT_ARE_EQUAL(size_t, 1, system_calls.connect_calls);
    ASSERT_ARE_EQUAL(void_ptr, &ipv6_address, system_calls.connect_address);
    ASSERT_ARE_EQUAL(size_t, sizeof(ipv6_address), (size_t)system_calls.connect_address_length);
    ASSERT_ARE_EQUAL(size_t, 1, system_calls.freeaddrinfo_calls);
    ASSERT_ARE_EQUAL(size_t, 0, system_calls.close_calls);
    assert_open_complete(IO_OPEN_OK, 0);
    socketio_destroy(client);
}

TEST_FUNCTION(socketio_open_EINPROGRESS_poll_timeout_reports_timeout_and_cleans_up)
{
    CONCRETE_IO_HANDLE client = create_client();
    system_calls.connect_result = -1;
    system_calls.connect_errno = EINPROGRESS;
    system_calls.poll_result = 0;

    int result = open_client(client);

    ASSERT_ARE_EQUAL(int, 0, result);
    ASSERT_ARE_EQUAL(size_t, 1, system_calls.poll_calls);
    ASSERT_ARE_EQUAL(int, TEST_SOCKET, system_calls.poll_socket);
    ASSERT_ARE_EQUAL(int, POLLOUT, system_calls.poll_events);
    ASSERT_ARE_EQUAL(int, TEST_POLL_TIMEOUT_MS, system_calls.poll_timeout);
    ASSERT_ARE_EQUAL(size_t, 0, system_calls.getsockopt_calls);
    assert_created_socket_was_cleaned_up();
    assert_open_complete(IO_OPEN_ERROR, ETIMEDOUT);
    socketio_destroy(client);
    ASSERT_ARE_EQUAL(size_t, 1, system_calls.close_calls);
}

TEST_FUNCTION(socketio_open_EINPROGRESS_poll_error_reports_errno_and_cleans_up)
{
    CONCRETE_IO_HANDLE client = create_client();
    system_calls.connect_result = -1;
    system_calls.connect_errno = EINPROGRESS;
    system_calls.poll_result = -1;
    system_calls.poll_errno = EIO;

    int result = open_client(client);

    ASSERT_ARE_EQUAL(int, 0, result);
    ASSERT_ARE_EQUAL(size_t, 1, system_calls.poll_calls);
    ASSERT_ARE_EQUAL(size_t, 0, system_calls.getsockopt_calls);
    assert_created_socket_was_cleaned_up();
    assert_open_complete(IO_OPEN_ERROR, EIO);
    socketio_destroy(client);
    ASSERT_ARE_EQUAL(size_t, 1, system_calls.close_calls);
}

TEST_FUNCTION(socketio_open_EINPROGRESS_getsockopt_failure_reports_errno_and_cleans_up)
{
    CONCRETE_IO_HANDLE client = create_client();
    system_calls.connect_result = -1;
    system_calls.connect_errno = EINPROGRESS;
    system_calls.poll_result = 1;
    system_calls.getsockopt_result = -1;
    system_calls.getsockopt_errno = ENOPROTOOPT;

    int result = open_client(client);

    ASSERT_ARE_EQUAL(int, 0, result);
    ASSERT_ARE_EQUAL(size_t, 1, system_calls.poll_calls);
    ASSERT_ARE_EQUAL(size_t, 1, system_calls.getsockopt_calls);
    assert_created_socket_was_cleaned_up();
    assert_open_complete(IO_OPEN_ERROR, ENOPROTOOPT);
    socketio_destroy(client);
    ASSERT_ARE_EQUAL(size_t, 1, system_calls.close_calls);
}

TEST_FUNCTION(socketio_open_EINPROGRESS_nonzero_SO_ERROR_reports_error_and_cleans_up)
{
    CONCRETE_IO_HANDLE client = create_client();
    system_calls.connect_result = -1;
    system_calls.connect_errno = EINPROGRESS;
    system_calls.poll_result = 1;
    system_calls.socket_error = EHOSTUNREACH;

    int result = open_client(client);

    ASSERT_ARE_EQUAL(int, 0, result);
    ASSERT_ARE_EQUAL(size_t, 1, system_calls.getsockopt_calls);
    assert_created_socket_was_cleaned_up();
    assert_open_complete(IO_OPEN_ERROR, EHOSTUNREACH);
    socketio_destroy(client);
    ASSERT_ARE_EQUAL(size_t, 1, system_calls.close_calls);
}

TEST_FUNCTION(socketio_open_EINPROGRESS_zero_SO_ERROR_opens_and_frees_address_once)
{
    CONCRETE_IO_HANDLE client = create_client();
    system_calls.connect_result = -1;
    system_calls.connect_errno = EINPROGRESS;
    system_calls.poll_result = 1;
    system_calls.socket_error = 0;

    int result = open_client(client);

    ASSERT_ARE_EQUAL(int, 0, result);
    ASSERT_ARE_EQUAL(size_t, 1, system_calls.poll_calls);
    ASSERT_ARE_EQUAL(size_t, 1, system_calls.getsockopt_calls);
    ASSERT_ARE_EQUAL(size_t, 0, system_calls.close_calls);
    ASSERT_ARE_EQUAL(size_t, 1, system_calls.freeaddrinfo_calls);
    assert_open_complete(IO_OPEN_OK, 0);
    socketio_destroy(client);
}

TEST_FUNCTION(socketio_open_accepted_socket_bypasses_resolution_and_client_setup)
{
    int accepted_socket = TEST_SOCKET;
    SOCKETIO_CONFIG config = { NULL, TEST_PORT, &accepted_socket };
    CONCRETE_IO_HANDLE client = socketio_create(&config);
    ASSERT_IS_NOT_NULL(client);

    int result = open_client(client);

    ASSERT_ARE_EQUAL(int, 0, result);
    ASSERT_ARE_EQUAL(size_t, 0, system_calls.getaddrinfo_calls);
    ASSERT_ARE_EQUAL(size_t, 0, system_calls.socket_calls);
    ASSERT_ARE_EQUAL(size_t, 0, system_calls.fcntl_calls);
    ASSERT_ARE_EQUAL(size_t, 0, system_calls.connect_calls);
    ASSERT_ARE_EQUAL(size_t, 0, system_calls.freeaddrinfo_calls);
    ASSERT_ARE_EQUAL(size_t, 0, system_calls.close_calls);
    assert_open_complete(IO_OPEN_OK, 0);

    socketio_destroy(client);
    ASSERT_ARE_EQUAL(size_t, 1, system_calls.close_calls);
    ASSERT_ARE_EQUAL(int, TEST_SOCKET, system_calls.closed_socket);
}

END_TEST_SUITE(socketio_berkeley_unittests)

// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#ifdef __cplusplus
#include <cstdint>
#else
#include <stdint.h>
#endif
#include <limits.h>

#include "testrunnerswitcher.h"

#undef DECLSPEC_IMPORT

#pragma warning(disable: 4273)

#include <winsock2.h>
#include <mstcpip.h>
#include <winsock2.h>
#include <ws2tcpip.h>

static size_t currentmalloc_call;
static size_t whenShallmalloc_fail;

void* my_gballoc_malloc(size_t size)
{
    void* result;
    currentmalloc_call++;
    if (whenShallmalloc_fail > 0)
    {
        if (currentmalloc_call == whenShallmalloc_fail)
        {
            result = NULL;
        }
        else
        {
            result = malloc(size);
        }
    }
    else
    {
        result = malloc(size);
    }
    return result;
}

void my_gballoc_free(void* ptr)
{
    free(ptr);
}

#define ENABLE_MOCKS
#include "azure_c_shared_utility/optionhandler.h"
#undef ENABLE_MOCKS

#include "azure_c_shared_utility/optimize_size.h"
#include "azure_c_shared_utility/socketio.h"

#define ENABLE_MOCKS

#include "umock_c.h"
#include "umocktypes_charptr.h"
#include "azure_c_shared_utility/singlylinkedlist.h"
static int g_addrinfo_result;
static bool g_addrinfo_returns_null;
//static int g_socket_send_size_value;
static int g_socket_recv_size_value;

static const SINGLYLINKEDLIST_HANDLE TEST_SINGLYLINKEDLIST_HANDLE = (SINGLYLINKEDLIST_HANDLE)0x4242;
static const LIST_ITEM_HANDLE TEST_LIST_ITEM_HANDLE = (LIST_ITEM_HANDLE)0x11;
static const void** list_items = NULL;
static size_t list_item_count = 0;
static SOCKET test_socket = (SOCKET)0x4243;
static SOCKET g_socket_result;
static size_t list_head_count = 0;
static bool singlylinkedlist_add_called = false;
static size_t callbackContext = 11;
static struct sockaddr_in test_ipv4_addr;
static struct sockaddr_in6 test_ipv6_addr;
static ADDRINFO TEST_ADDR_INFO;
static ADDRINFO TEST_ADDR_INFO_SECOND;
static PADDRINFOA g_addrinfo_result_list;
static size_t getaddrinfo_call_count;
static ADDRINFO captured_addr_hints;
static const char* captured_node_name;
static char captured_service_name[16];
static size_t socket_call_count;
static int captured_socket_family;
static int captured_socket_type;
static int captured_socket_protocol;
static size_t connect_call_count;
static SOCKET captured_connect_socket;
static const struct sockaddr* captured_connect_address;
static int captured_connect_address_length;
static size_t closesocket_call_count;
static SOCKET captured_closed_socket;
static size_t freeaddrinfo_call_count;
static PADDRINFOA captured_freed_addrinfo;
static size_t open_complete_call_count;
static void* open_complete_context;
static IO_OPEN_RESULT_DETAILED open_complete_result;

static const char* TEST_BUFFER_VALUE = "test_buffer_value";

#define PORT_NUM 80
#define HOSTNAME_ARG "hostname"

#define TEST_BUFFER_SIZE    17
#define TEST_CALLBACK_CONTEXT   0x951753

static struct tcp_keepalive persisted_tcp_keepalive;

MOCK_FUNCTION_WITH_CODE(WSAAPI, SOCKET, socket, int, af, int, type, int, protocol)
    socket_call_count++;
    captured_socket_family = af;
    captured_socket_type = type;
    captured_socket_protocol = protocol;
MOCK_FUNCTION_END(g_socket_result)
MOCK_FUNCTION_WITH_CODE(WSAAPI, int, closesocket, SOCKET, s)
    closesocket_call_count++;
    captured_closed_socket = s;
MOCK_FUNCTION_END(0)
MOCK_FUNCTION_WITH_CODE(WSAAPI, int, connect, SOCKET, s, const struct sockaddr*, name, int, namelen)
    connect_call_count++;
    captured_connect_socket = s;
    captured_connect_address = name;
    captured_connect_address_length = namelen;
MOCK_FUNCTION_END(0)
MOCK_FUNCTION_WITH_CODE(WSAAPI, int, recv, SOCKET, s, char*, buf, int, len, int, flags)
    if (g_socket_recv_size_value >= 0)
    {
        len = g_socket_recv_size_value;
    }
MOCK_FUNCTION_END(-1)
MOCK_FUNCTION_WITH_CODE(WSAAPI, int, send, SOCKET, s, const char*, buf, int, len, int, flags)
/*if (g_socket_send_size_value >= 0)
{
len = g_socket_send_size_value;
}*/
MOCK_FUNCTION_END(len)
MOCK_FUNCTION_WITH_CODE(WSAAPI, INT, getaddrinfo, PCSTR, pNodeName, PCSTR, pServiceName, const ADDRINFOA*, pHints, PADDRINFOA*, ppResult)
    getaddrinfo_call_count++;
    captured_node_name = pNodeName;
    (void)snprintf(captured_service_name, sizeof(captured_service_name), "%s", pServiceName);
    captured_addr_hints = *pHints;
    *ppResult = ((g_addrinfo_result == 0) && !g_addrinfo_returns_null) ? g_addrinfo_result_list : NULL;
MOCK_FUNCTION_END(g_addrinfo_result)
MOCK_FUNCTION_WITH_CODE(WSAAPI, void, freeaddrinfo, PADDRINFOA, pResult)
    freeaddrinfo_call_count++;
    captured_freed_addrinfo = pResult;
MOCK_FUNCTION_END()
MOCK_FUNCTION_WITH_CODE(WSAAPI, int, WSAGetLastError)
MOCK_FUNCTION_END(0)
MOCK_FUNCTION_WITH_CODE(WSAAPI, int, ioctlsocket, SOCKET, s, long, cmd, u_long FAR*, argp)
MOCK_FUNCTION_END(0)
int WSAAPI setsockopt(SOCKET s, int level, int optname, const char* optval, int optlen)
{
    (void)s;
    (void)level;
    (void)optname;
    (void)optval;
    (void)optlen;
    return 0;
}

PCSTR WSAAPI inet_ntop(INT Family, const VOID* pAddr, PSTR pStringBuf, size_t StringBufSize)
{
    (void)Family;
    (void)pAddr;
    (void)pStringBuf;
    (void)StringBufSize;
    return NULL;
}
MOCK_FUNCTION_WITH_CODE(WSAAPI, int, WSAIoctl, SOCKET, s, DWORD, dwIoControlCode, LPVOID, lpvInBuffer, DWORD, cbInBuffer, LPVOID, lpvOutBuffer, DWORD, cbOutBuffer, LPDWORD, lpcbBytesReturned, LPWSAOVERLAPPED, lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE, lpCompletionRoutine)
(void)memcpy(&persisted_tcp_keepalive, lpvInBuffer, sizeof(struct tcp_keepalive));
MOCK_FUNCTION_END(0)

LIST_ITEM_HANDLE my_singlylinkedlist_get_head_item(SINGLYLINKEDLIST_HANDLE list)
{
    LIST_ITEM_HANDLE listHandle = NULL;
    (void)list;
    if (list_item_count > 0)
    {
        listHandle = (LIST_ITEM_HANDLE)list_items[0];
        list_item_count--;
    }
    return listHandle;
}

LIST_ITEM_HANDLE my_singlylinkedlist_add(SINGLYLINKEDLIST_HANDLE list, const void* item)
{
    const void** items = (const void**)realloc((void*)list_items, (list_item_count + 1) * sizeof(item));
    (void)list;
    if (items != NULL)
    {
        list_items = items;
        list_items[list_item_count++] = item;
    }
    singlylinkedlist_add_called = true;
    return (LIST_ITEM_HANDLE)list_item_count;
}

const void* my_singlylinkedlist_item_get_value(LIST_ITEM_HANDLE item_handle)
{
    const void* resultPtr = NULL;
    if (singlylinkedlist_add_called)
    {
        resultPtr = item_handle;
    }

    return (const void*)resultPtr;
}

LIST_ITEM_HANDLE my_singlylinkedlist_find(SINGLYLINKEDLIST_HANDLE handle, LIST_MATCH_FUNCTION match_function, const void* match_context)
{
    size_t i;
    const void* found_item = NULL;
    (void)handle;
    for (i = 0; i < list_item_count; i++)
    {
        if (match_function((LIST_ITEM_HANDLE)list_items[i], match_context))
        {
            found_item = list_items[i];
            break;
        }
    }

    return (LIST_ITEM_HANDLE)found_item;
}

void my_singlylinkedlist_destroy(SINGLYLINKEDLIST_HANDLE handle)
{
    (void)handle;
    free((void*)list_items);
    list_items = NULL;
}

static void test_on_bytes_received(void* context, const unsigned char* buffer, size_t size)
{
    (void)context;
    (void)buffer;
    (void)size;
}

static void test_on_io_open_complete(void* context, IO_OPEN_RESULT_DETAILED open_result)
{
    open_complete_call_count++;
    open_complete_context = context;
    open_complete_result = open_result;
}

static void assert_open_complete(IO_OPEN_RESULT expected_result, int expected_code)
{
    ASSERT_ARE_EQUAL(size_t, 1, open_complete_call_count);
    ASSERT_ARE_EQUAL(void_ptr, &callbackContext, open_complete_context);
    ASSERT_ARE_EQUAL(int, expected_result, open_complete_result.result);
    ASSERT_ARE_EQUAL(int, expected_code, open_complete_result.code);
}

static void assert_resolver_request(void)
{
    ASSERT_ARE_EQUAL(size_t, 1, getaddrinfo_call_count);
    ASSERT_ARE_EQUAL(char_ptr, HOSTNAME_ARG, captured_node_name);
    ASSERT_ARE_EQUAL(char_ptr, "80", captured_service_name);
    ASSERT_ARE_EQUAL(int, 0, captured_addr_hints.ai_flags);
    ASSERT_ARE_EQUAL(int, AF_UNSPEC, captured_addr_hints.ai_family);
    ASSERT_ARE_EQUAL(int, SOCK_STREAM, captured_addr_hints.ai_socktype);
    ASSERT_ARE_EQUAL(int, 0, captured_addr_hints.ai_protocol);
}

static void test_on_io_error(void* context);

static void assert_open_rejects_resolved_address(CONCRETE_IO_HANDLE io_handle, int expected_code)
{
    umock_c_reset_all_calls();
    EXPECTED_CALL(getaddrinfo(IGNORED_PTR_ARG, IGNORED_PTR_ARG, &TEST_ADDR_INFO, IGNORED_PTR_ARG)).IgnoreArgument_pHints();
    EXPECTED_CALL(freeaddrinfo(&TEST_ADDR_INFO)).IgnoreArgument_pResult();

    int result = socketio_open(io_handle, test_on_io_open_complete, &callbackContext, test_on_bytes_received, &callbackContext, test_on_io_error, &callbackContext);

    ASSERT_ARE_EQUAL(int, 0, result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
    assert_resolver_request();
    ASSERT_ARE_EQUAL(size_t, 0, socket_call_count);
    ASSERT_ARE_EQUAL(size_t, 0, connect_call_count);
    ASSERT_ARE_EQUAL(size_t, 0, closesocket_call_count);
    ASSERT_ARE_EQUAL(size_t, 1, freeaddrinfo_call_count);
    ASSERT_ARE_EQUAL(void_ptr, &TEST_ADDR_INFO, captured_freed_addrinfo);
    assert_open_complete(IO_OPEN_ERROR, expected_code);
}

static void test_on_io_close_complete(void* context)
{
    (void)context;
}

static void test_on_io_error(void* context)
{
    (void)context;
}

char* umocktypes_stringify_const_ADDRINFOA_ptr(const ADDRINFOA** value)
{
    char* result = NULL;
    char temp_buffer[256];
    int length;

    length = sprintf(temp_buffer, "{ ai_flags = %d, ai_family = %d, ai_socktype = %d, ai_protocol = %d, ai_addrlen = %u, ai_canonname = %s", (*value)->ai_flags, (*value)->ai_family, (*value)->ai_socktype, (*value)->ai_protocol, (unsigned int)((*value)->ai_addrlen), (*value)->ai_canonname);
    if (length > 0)
    {
        result = (char*)malloc(strlen(temp_buffer) + 1);
        if (result != NULL)
        {
            (void)memcpy(result, temp_buffer, strlen(temp_buffer) + 1);
        }
    }

    return result;
}

int umocktypes_are_equal_const_ADDRINFOA_ptr(const ADDRINFOA** left, const ADDRINFOA** right)
{
    int result = 1;
    if (((*left)->ai_flags != (*right)->ai_flags) ||
        ((*left)->ai_family != (*right)->ai_family) ||
        ((*left)->ai_socktype != (*right)->ai_socktype) ||
        ((*left)->ai_protocol != (*right)->ai_protocol) ||
        ((((*left)->ai_canonname == NULL) || ((*right)->ai_canonname == NULL)) && ((*left)->ai_canonname != (*right)->ai_canonname)) ||
        (strcmp((*left)->ai_canonname, (*right)->ai_canonname) != 0))
    {
        result = 0;
    }

    return result;
}

int umocktypes_copy_const_ADDRINFOA_ptr(ADDRINFOA** destination, const ADDRINFOA** source)
{
    int result;

    *destination = (ADDRINFOA*)malloc(sizeof(ADDRINFOA));
    if (*destination == NULL)
    {
        result = __FAILURE__;
    }
    else
    {
        (*destination)->ai_flags = (*source)->ai_flags;
        (*destination)->ai_family = (*source)->ai_family;
        (*destination)->ai_socktype = (*source)->ai_socktype;
        (*destination)->ai_protocol = (*source)->ai_protocol;
        (*destination)->ai_canonname = (*source)->ai_canonname;

        result = 0;
    }

    return result;
}

void umocktypes_free_const_ADDRINFOA_ptr(ADDRINFOA** value)
{
    free(*value);
}

char* umocktypes_stringify_const_struct_sockaddr_ptr(const struct sockaddr** value)
{
    char* result = NULL;
    char temp_buffer[256];
    int length;

    length = sprintf(temp_buffer, "{ sa_family = %u, sa_data = ... }", (unsigned int)((*value)->sa_family));
    if (length > 0)
    {
        result = (char*)malloc(strlen(temp_buffer) + 1);
        if (result != NULL)
        {
            (void)memcpy(result, temp_buffer, strlen(temp_buffer) + 1);
        }
    }

    return result;
}

int umocktypes_are_equal_const_struct_sockaddr_ptr(const struct sockaddr** left, const struct sockaddr** right)
{
    int result = 1;
    if (((*left)->sa_family != (*left)->sa_family) ||
        (memcmp((*left)->sa_data, (*right)->sa_data, sizeof((*left)->sa_data) != 0)))
    {
        result = 0;
    }

    return result;
}

int umocktypes_copy_const_struct_sockaddr_ptr(struct sockaddr** destination, const struct sockaddr** source)
{
    int result;

    *destination = (struct sockaddr*)malloc(sizeof(struct sockaddr));
    if (*destination == NULL)
    {
        result = __FAILURE__;
    }
    else
    {
        (*destination)->sa_family = (*source)->sa_family;
        (void)memcpy((*destination)->sa_data, (*source)->sa_data, sizeof((*source)->sa_data));

        result = 0;
    }

    return result;
}

void umocktypes_free_const_struct_sockaddr_ptr(struct sockaddr** value)
{
    free(*value);
}

/* after this point malloc is gballoc */
#include "azure_c_shared_utility/gballoc.h"

static TEST_MUTEX_HANDLE g_testByTest;
static TEST_MUTEX_HANDLE g_dllByDll;

DEFINE_ENUM_STRINGS(UMOCK_C_ERROR_CODE, UMOCK_C_ERROR_CODE_VALUES)

static void on_umock_c_error(UMOCK_C_ERROR_CODE error_code)
{
    char temp_str[256];
    (void)snprintf(temp_str, sizeof(temp_str), "umock_c reported error :%s", ENUM_TO_STRING(UMOCK_C_ERROR_CODE, error_code));
    ASSERT_FAIL(temp_str);
}

BEGIN_TEST_SUITE(socketio_win32_unittests)

TEST_SUITE_INITIALIZE(suite_init)
{
    int result;
    TEST_INITIALIZE_MEMORY_DEBUG(g_dllByDll);
    g_testByTest = TEST_MUTEX_CREATE();
    ASSERT_IS_NOT_NULL(g_testByTest);

    umock_c_init(on_umock_c_error);

    result = umocktypes_charptr_register_types();
    ASSERT_ARE_EQUAL(int, 0, result);

    REGISTER_UMOCK_ALIAS_TYPE(CONCRETE_IO_HANDLE, void*);
    REGISTER_UMOCK_ALIAS_TYPE(SINGLYLINKEDLIST_HANDLE, void*);
    REGISTER_UMOCK_ALIAS_TYPE(LIST_ITEM_HANDLE, void*);
    REGISTER_UMOCK_ALIAS_TYPE(SOCKET, void*);
    REGISTER_UMOCK_ALIAS_TYPE(PCSTR, char*);
    REGISTER_TYPE(const ADDRINFOA*, const_ADDRINFOA_ptr);
    REGISTER_UMOCK_ALIAS_TYPE(PADDRINFOA, const ADDRINFOA*);
    REGISTER_UMOCK_ALIAS_TYPE(DWORD, unsigned long);
    REGISTER_UMOCK_ALIAS_TYPE(LPVOID, void*);
    REGISTER_UMOCK_ALIAS_TYPE(LPDWORD, void*);
    REGISTER_UMOCK_ALIAS_TYPE(LPWSAOVERLAPPED, void*);
    REGISTER_UMOCK_ALIAS_TYPE(LPWSAOVERLAPPED_COMPLETION_ROUTINE, void*);

    REGISTER_GLOBAL_MOCK_RETURN(singlylinkedlist_remove, 0);
    REGISTER_GLOBAL_MOCK_RETURN(singlylinkedlist_create, TEST_SINGLYLINKEDLIST_HANDLE);
    REGISTER_GLOBAL_MOCK_HOOK(gballoc_malloc, my_gballoc_malloc);
    REGISTER_GLOBAL_MOCK_HOOK(gballoc_free, my_gballoc_free);
    REGISTER_GLOBAL_MOCK_HOOK(singlylinkedlist_get_head_item, my_singlylinkedlist_get_head_item);
    REGISTER_GLOBAL_MOCK_HOOK(singlylinkedlist_add, my_singlylinkedlist_add);
    REGISTER_GLOBAL_MOCK_HOOK(singlylinkedlist_item_get_value, my_singlylinkedlist_item_get_value);
    REGISTER_GLOBAL_MOCK_HOOK(singlylinkedlist_find, my_singlylinkedlist_find);
    REGISTER_GLOBAL_MOCK_HOOK(singlylinkedlist_destroy, my_singlylinkedlist_destroy);
}

TEST_SUITE_CLEANUP(suite_cleanup)
{
    umock_c_deinit();

    TEST_MUTEX_DESTROY(g_testByTest);
    TEST_DEINITIALIZE_MEMORY_DEBUG(g_dllByDll);
}

TEST_FUNCTION_INITIALIZE(method_init)
{
    if (TEST_MUTEX_ACQUIRE(g_testByTest))
    {
        ASSERT_FAIL("Could not acquire test serialization mutex.");
    }

    umock_c_reset_all_calls();

    currentmalloc_call = 0;
    whenShallmalloc_fail = 0;
    list_head_count = 0;
    singlylinkedlist_add_called = false;
    g_addrinfo_result = 0;
    g_addrinfo_returns_null = false;
    //g_socket_send_size_value = -1;
    g_socket_recv_size_value = -1;

    (void)memset(&test_ipv4_addr, 0, sizeof(test_ipv4_addr));
    test_ipv4_addr.sin_family = AF_INET;
    test_ipv4_addr.sin_addr.S_un.S_addr = 0x0100007F;
    (void)memset(&test_ipv6_addr, 0, sizeof(test_ipv6_addr));
    test_ipv6_addr.sin6_family = AF_INET6;
    test_ipv6_addr.sin6_addr.u.Byte[15] = 1;

    (void)memset(&TEST_ADDR_INFO, 0, sizeof(TEST_ADDR_INFO));
    TEST_ADDR_INFO.ai_family = AF_INET;
    TEST_ADDR_INFO.ai_socktype = SOCK_STREAM;
    TEST_ADDR_INFO.ai_protocol = IPPROTO_TCP;
    TEST_ADDR_INFO.ai_addrlen = sizeof(test_ipv4_addr);
    TEST_ADDR_INFO.ai_addr = (struct sockaddr*)&test_ipv4_addr;
    (void)memset(&TEST_ADDR_INFO_SECOND, 0, sizeof(TEST_ADDR_INFO_SECOND));
    TEST_ADDR_INFO_SECOND.ai_family = AF_INET6;
    TEST_ADDR_INFO_SECOND.ai_socktype = SOCK_STREAM;
    TEST_ADDR_INFO_SECOND.ai_protocol = IPPROTO_TCP;
    TEST_ADDR_INFO_SECOND.ai_addrlen = sizeof(test_ipv6_addr);
    TEST_ADDR_INFO_SECOND.ai_addr = (struct sockaddr*)&test_ipv6_addr;
    g_addrinfo_result_list = &TEST_ADDR_INFO;

    getaddrinfo_call_count = 0;
    (void)memset(&captured_addr_hints, 0, sizeof(captured_addr_hints));
    captured_node_name = NULL;
    captured_service_name[0] = '\0';
    g_socket_result = test_socket;
    socket_call_count = 0;
    captured_socket_family = 0;
    captured_socket_type = 0;
    captured_socket_protocol = 0;
    connect_call_count = 0;
    captured_connect_socket = INVALID_SOCKET;
    captured_connect_address = NULL;
    captured_connect_address_length = 0;
    closesocket_call_count = 0;
    captured_closed_socket = INVALID_SOCKET;
    freeaddrinfo_call_count = 0;
    captured_freed_addrinfo = NULL;
    open_complete_call_count = 0;
    open_complete_context = NULL;
    open_complete_result.result = IO_OPEN_ERROR;
    open_complete_result.code = 0;
}

TEST_FUNCTION_CLEANUP(method_cleanup)
{
    TEST_MUTEX_RELEASE(g_testByTest);
}

static void OnSendComplete(void* context, IO_SEND_RESULT send_result)
{
    (void)context;
    (void)send_result;
}

/* socketio_win32_create */
TEST_FUNCTION(socketio_create_io_create_parameters_NULL_fails)
{
    // arrange

    // act
    CONCRETE_IO_HANDLE ioHandle = socketio_create(NULL);

    // assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
    ASSERT_IS_NULL(ioHandle);
}

TEST_FUNCTION(socketio_create_singlylinkedlist_create_fails)
{
    // arrange
    SOCKETIO_CONFIG socketConfig = { HOSTNAME_ARG, PORT_NUM, NULL };
    CONCRETE_IO_HANDLE ioHandle;

    EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    EXPECTED_CALL(singlylinkedlist_create()).SetReturn((SINGLYLINKEDLIST_HANDLE)NULL);
    EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));

    // act
    ioHandle = socketio_create(&socketConfig);

    // assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
    ASSERT_IS_NULL(ioHandle);
}

TEST_FUNCTION(socketio_create_succeeds)
{
    // arrange
    SOCKETIO_CONFIG socketConfig = { HOSTNAME_ARG, PORT_NUM, NULL };
    CONCRETE_IO_HANDLE ioHandle;

    EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    EXPECTED_CALL(singlylinkedlist_create());
    EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));

    // act
    ioHandle = socketio_create(&socketConfig);

    // assert
    ASSERT_IS_NOT_NULL(ioHandle);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    socketio_destroy(ioHandle);
}

// socketio_win32_destroy 
TEST_FUNCTION(socketio_destroy_socket_io_NULL_succeeds)
{
    // arrange

    // act
    socketio_destroy(NULL);

    // assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
}

TEST_FUNCTION(socketio_destroy_socket_succeeds)
{
    // arrange
    SOCKETIO_CONFIG socketConfig = { HOSTNAME_ARG, PORT_NUM, NULL };
    CONCRETE_IO_HANDLE ioHandle = socketio_create(&socketConfig);
    socketio_open(ioHandle, test_on_io_open_complete, &callbackContext, test_on_bytes_received, &callbackContext, test_on_io_error, &callbackContext);

    umock_c_reset_all_calls();
    EXPECTED_CALL(singlylinkedlist_get_head_item(IGNORED_PTR_ARG));
    EXPECTED_CALL(send(IGNORED_NUM_ARG, IGNORED_PTR_ARG, IGNORED_NUM_ARG, IGNORED_NUM_ARG))
        .SetReturn(0);
    EXPECTED_CALL(WSAGetLastError())
        .SetReturn(WSAEWOULDBLOCK);
    (void)socketio_send(ioHandle, TEST_BUFFER_VALUE, TEST_BUFFER_SIZE, OnSendComplete, (void*)TEST_CALLBACK_CONTEXT);

    umock_c_reset_all_calls();

    EXPECTED_CALL(closesocket(IGNORED_NUM_ARG));
    EXPECTED_CALL(singlylinkedlist_get_head_item(IGNORED_PTR_ARG));
    EXPECTED_CALL(singlylinkedlist_item_get_value(IGNORED_PTR_ARG));
    EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));
    EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));
    EXPECTED_CALL(singlylinkedlist_remove(IGNORED_PTR_ARG, IGNORED_PTR_ARG));
    EXPECTED_CALL(singlylinkedlist_get_head_item(IGNORED_PTR_ARG));
    EXPECTED_CALL(singlylinkedlist_destroy(IGNORED_PTR_ARG));
    EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));
    EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));

    // act
    socketio_destroy(ioHandle);

    // assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
}

TEST_FUNCTION(socketio_open_socket_io_NULL_fails)
{
    // arrange

    // act
    int result = socketio_open(NULL, test_on_io_open_complete, &callbackContext, test_on_bytes_received, &callbackContext, test_on_io_error, &callbackContext);

    // assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
    ASSERT_ARE_EQUAL(int, 0, result);
    ASSERT_ARE_EQUAL(size_t, 1, open_complete_call_count);
    ASSERT_ARE_EQUAL(void_ptr, &callbackContext, open_complete_context);
    ASSERT_ARE_EQUAL(int, IO_OPEN_ERROR, open_complete_result.result);
    ASSERT_ARE_NOT_EQUAL(int, 0, open_complete_result.code);
}

TEST_FUNCTION(socketio_open_getaddrinfo_failure_does_not_create_or_close_a_socket)
{
    // arrange
    SOCKETIO_CONFIG socketConfig = { HOSTNAME_ARG, PORT_NUM, NULL };
    CONCRETE_IO_HANDLE ioHandle = socketio_create(&socketConfig);
    g_addrinfo_result = WSAHOST_NOT_FOUND;
    g_socket_result = INVALID_SOCKET; /* Prevent stale socket-first code from reaching DNS. */

    umock_c_reset_all_calls();
    EXPECTED_CALL(getaddrinfo(IGNORED_PTR_ARG, IGNORED_PTR_ARG, &TEST_ADDR_INFO, IGNORED_PTR_ARG)).IgnoreArgument_pHints();

    // act
    int result = socketio_open(ioHandle, test_on_io_open_complete, &callbackContext, test_on_bytes_received, &callbackContext, test_on_io_error, &callbackContext);

    // assert
    ASSERT_ARE_EQUAL(int, 0, result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
    assert_resolver_request();
    ASSERT_ARE_EQUAL(size_t, 0, socket_call_count);
    ASSERT_ARE_EQUAL(size_t, 0, connect_call_count);
    ASSERT_ARE_EQUAL(size_t, 0, closesocket_call_count);
    ASSERT_ARE_EQUAL(size_t, 0, freeaddrinfo_call_count);
    assert_open_complete(IO_OPEN_ERROR, WSAHOST_NOT_FOUND);

    // cleanup
    socketio_destroy(ioHandle);
}

TEST_FUNCTION(socketio_open_getaddrinfo_success_with_NULL_result_does_not_create_or_close_a_socket)
{
    // arrange
    SOCKETIO_CONFIG socketConfig = { HOSTNAME_ARG, PORT_NUM, NULL };
    CONCRETE_IO_HANDLE ioHandle = socketio_create(&socketConfig);
    g_addrinfo_returns_null = true;
    g_socket_result = INVALID_SOCKET; /* Prevent stale socket-first code from dereferencing NULL. */

    umock_c_reset_all_calls();
    EXPECTED_CALL(getaddrinfo(IGNORED_PTR_ARG, IGNORED_PTR_ARG, &TEST_ADDR_INFO, IGNORED_PTR_ARG)).IgnoreArgument_pHints();

    // act
    int result = socketio_open(ioHandle, test_on_io_open_complete, &callbackContext, test_on_bytes_received, &callbackContext, test_on_io_error, &callbackContext);

    // assert
    ASSERT_ARE_EQUAL(int, 0, result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
    assert_resolver_request();
    ASSERT_ARE_EQUAL(size_t, 0, socket_call_count);
    ASSERT_ARE_EQUAL(size_t, 0, connect_call_count);
    ASSERT_ARE_EQUAL(size_t, 0, closesocket_call_count);
    ASSERT_ARE_EQUAL(size_t, 0, freeaddrinfo_call_count);
    assert_open_complete(IO_OPEN_ERROR, WSAHOST_NOT_FOUND);

    // cleanup
    socketio_destroy(ioHandle);
}

TEST_FUNCTION(socketio_open_rejects_NULL_resolved_address)
{
    // arrange
    SOCKETIO_CONFIG socketConfig = { HOSTNAME_ARG, PORT_NUM, NULL };
    CONCRETE_IO_HANDLE ioHandle = socketio_create(&socketConfig);
    TEST_ADDR_INFO.ai_addr = NULL;

    // act and assert
    assert_open_rejects_resolved_address(ioHandle, WSAEINVAL);

    // cleanup
    socketio_destroy(ioHandle);
}

TEST_FUNCTION(socketio_open_short_length_does_not_dereference_address)
{
    // arrange
    SOCKETIO_CONFIG socketConfig = { HOSTNAME_ARG, PORT_NUM, NULL };
    CONCRETE_IO_HANDLE ioHandle = socketio_create(&socketConfig);
    bool access_violation = false;
    int result = __FAILURE__;
    TEST_ADDR_INFO.ai_addr = (struct sockaddr*)(uintptr_t)1;
    TEST_ADDR_INFO.ai_addrlen = 0;

    umock_c_reset_all_calls();
    EXPECTED_CALL(getaddrinfo(IGNORED_PTR_ARG, IGNORED_PTR_ARG, &TEST_ADDR_INFO, IGNORED_PTR_ARG)).IgnoreArgument_pHints();
    EXPECTED_CALL(freeaddrinfo(&TEST_ADDR_INFO)).IgnoreArgument_pResult();

    // act
    __try
    {
        result = socketio_open(ioHandle, test_on_io_open_complete, &callbackContext, test_on_bytes_received, &callbackContext, test_on_io_error, &callbackContext);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        access_violation = true;
    }

    if (access_violation)
    {
        umock_c_reset_all_calls();
        socketio_destroy(ioHandle);
    }

    // assert
    ASSERT_IS_FALSE(access_violation);
    ASSERT_ARE_EQUAL(int, 0, result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
    assert_resolver_request();
    ASSERT_ARE_EQUAL(size_t, 0, socket_call_count);
    ASSERT_ARE_EQUAL(size_t, 0, connect_call_count);
    ASSERT_ARE_EQUAL(size_t, 0, closesocket_call_count);
    ASSERT_ARE_EQUAL(size_t, 1, freeaddrinfo_call_count);
    ASSERT_ARE_EQUAL(void_ptr, &TEST_ADDR_INFO, captured_freed_addrinfo);
    assert_open_complete(IO_OPEN_ERROR, WSAEINVAL);

    // cleanup
    socketio_destroy(ioHandle);
}

TEST_FUNCTION(socketio_open_rejects_zero_length_IPv4_address)
{
    // arrange
    SOCKETIO_CONFIG socketConfig = { HOSTNAME_ARG, PORT_NUM, NULL };
    CONCRETE_IO_HANDLE ioHandle = socketio_create(&socketConfig);
    TEST_ADDR_INFO.ai_addrlen = 0;

    // act and assert
    assert_open_rejects_resolved_address(ioHandle, WSAEINVAL);

    // cleanup
    socketio_destroy(ioHandle);
}

TEST_FUNCTION(socketio_open_rejects_short_IPv4_address)
{
    // arrange
    SOCKETIO_CONFIG socketConfig = { HOSTNAME_ARG, PORT_NUM, NULL };
    CONCRETE_IO_HANDLE ioHandle = socketio_create(&socketConfig);
    TEST_ADDR_INFO.ai_addrlen = sizeof(test_ipv4_addr) - 1;

    // act and assert
    assert_open_rejects_resolved_address(ioHandle, WSAEINVAL);

    // cleanup
    socketio_destroy(ioHandle);
}

TEST_FUNCTION(socketio_open_rejects_short_IPv6_address)
{
    // arrange
    SOCKETIO_CONFIG socketConfig = { HOSTNAME_ARG, PORT_NUM, NULL };
    CONCRETE_IO_HANDLE ioHandle = socketio_create(&socketConfig);
    TEST_ADDR_INFO.ai_family = AF_INET6;
    TEST_ADDR_INFO.ai_addr = (struct sockaddr*)&test_ipv6_addr;
    TEST_ADDR_INFO.ai_addrlen = sizeof(test_ipv6_addr) - 1;

    // act and assert
    assert_open_rejects_resolved_address(ioHandle, WSAEINVAL);

    // cleanup
    socketio_destroy(ioHandle);
}

TEST_FUNCTION(socketio_open_rejects_unsupported_address_family)
{
    // arrange
    SOCKETIO_CONFIG socketConfig = { HOSTNAME_ARG, PORT_NUM, NULL };
    CONCRETE_IO_HANDLE ioHandle = socketio_create(&socketConfig);
    TEST_ADDR_INFO.ai_family = AF_UNSPEC;

    // act and assert
    assert_open_rejects_resolved_address(ioHandle, WSAEAFNOSUPPORT);

    // cleanup
    socketio_destroy(ioHandle);
}

TEST_FUNCTION(socketio_open_rejects_mismatched_address_family)
{
    // arrange
    SOCKETIO_CONFIG socketConfig = { HOSTNAME_ARG, PORT_NUM, NULL };
    CONCRETE_IO_HANDLE ioHandle = socketio_create(&socketConfig);
    test_ipv6_addr.sin6_family = AF_INET;
    TEST_ADDR_INFO.ai_family = AF_INET6;
    TEST_ADDR_INFO.ai_addr = (struct sockaddr*)&test_ipv6_addr;
    TEST_ADDR_INFO.ai_addrlen = sizeof(test_ipv6_addr);

    // act and assert
    assert_open_rejects_resolved_address(ioHandle, WSAEINVAL);

    // cleanup
    socketio_destroy(ioHandle);
}

TEST_FUNCTION(socketio_open_rejects_address_length_that_does_not_fit_connect)
{
    // arrange
    SOCKETIO_CONFIG socketConfig = { HOSTNAME_ARG, PORT_NUM, NULL };
    CONCRETE_IO_HANDLE ioHandle = socketio_create(&socketConfig);
    TEST_ADDR_INFO.ai_addrlen = (size_t)INT_MAX + 1;

    umock_c_reset_all_calls();
    EXPECTED_CALL(getaddrinfo(IGNORED_PTR_ARG, IGNORED_PTR_ARG, &TEST_ADDR_INFO, IGNORED_PTR_ARG)).IgnoreArgument_pHints();
    EXPECTED_CALL(freeaddrinfo(&TEST_ADDR_INFO)).IgnoreArgument_pResult();

    // act
    int result = socketio_open(ioHandle, test_on_io_open_complete, &callbackContext, test_on_bytes_received, &callbackContext, test_on_io_error, &callbackContext);

    // assert
    ASSERT_ARE_EQUAL(int, 0, result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
    assert_resolver_request();
    ASSERT_ARE_EQUAL(size_t, 0, socket_call_count);
    ASSERT_ARE_EQUAL(size_t, 0, connect_call_count);
    ASSERT_ARE_EQUAL(size_t, 0, closesocket_call_count);
    ASSERT_ARE_EQUAL(size_t, 1, freeaddrinfo_call_count);
    ASSERT_ARE_EQUAL(void_ptr, &TEST_ADDR_INFO, captured_freed_addrinfo);
    assert_open_complete(IO_OPEN_ERROR, WSAEINVAL);

    // cleanup
    socketio_destroy(ioHandle);
}

TEST_FUNCTION(socketio_open_socket_failure_frees_addrinfo_without_closing_a_socket)
{
    // arrange
    SOCKETIO_CONFIG socketConfig = { HOSTNAME_ARG, PORT_NUM, NULL };
    CONCRETE_IO_HANDLE ioHandle = socketio_create(&socketConfig);
    TEST_ADDR_INFO.ai_socktype = SOCK_RDM;
    TEST_ADDR_INFO.ai_protocol = IPPROTO_UDP;
    g_socket_result = INVALID_SOCKET;

    umock_c_reset_all_calls();
    EXPECTED_CALL(getaddrinfo(IGNORED_PTR_ARG, IGNORED_PTR_ARG, &TEST_ADDR_INFO, IGNORED_PTR_ARG)).IgnoreArgument_pHints();
    EXPECTED_CALL(socket(AF_INET, SOCK_RDM, IPPROTO_UDP)).SetReturn(INVALID_SOCKET);
    EXPECTED_CALL(WSAGetLastError()).SetReturn(WSAEMFILE);
    EXPECTED_CALL(freeaddrinfo(&TEST_ADDR_INFO)).IgnoreArgument_pResult();

    // act
    int result = socketio_open(ioHandle, test_on_io_open_complete, &callbackContext, test_on_bytes_received, &callbackContext, test_on_io_error, &callbackContext);

    // assert
    ASSERT_ARE_EQUAL(int, 0, result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
    assert_resolver_request();
    ASSERT_ARE_EQUAL(size_t, 1, socket_call_count);
    ASSERT_ARE_EQUAL(int, AF_INET, captured_socket_family);
    ASSERT_ARE_EQUAL(int, SOCK_RDM, captured_socket_type);
    ASSERT_ARE_EQUAL(int, IPPROTO_UDP, captured_socket_protocol);
    ASSERT_ARE_EQUAL(size_t, 0, connect_call_count);
    ASSERT_ARE_EQUAL(size_t, 0, closesocket_call_count);
    ASSERT_ARE_EQUAL(size_t, 1, freeaddrinfo_call_count);
    ASSERT_ARE_EQUAL(void_ptr, &TEST_ADDR_INFO, captured_freed_addrinfo);
    assert_open_complete(IO_OPEN_ERROR, WSAEMFILE);

    // cleanup
    socketio_destroy(ioHandle);
}

TEST_FUNCTION(socketio_open_connect_failure_uses_only_first_result_and_cleans_up_once)
{
    // arrange
    SOCKETIO_CONFIG socketConfig = { HOSTNAME_ARG, PORT_NUM, NULL };
    CONCRETE_IO_HANDLE ioHandle = socketio_create(&socketConfig);
    TEST_ADDR_INFO.ai_socktype = SOCK_RDM;
    TEST_ADDR_INFO.ai_protocol = IPPROTO_UDP;
    TEST_ADDR_INFO.ai_next = &TEST_ADDR_INFO_SECOND;

    umock_c_reset_all_calls();
    EXPECTED_CALL(getaddrinfo(IGNORED_PTR_ARG, IGNORED_PTR_ARG, &TEST_ADDR_INFO, IGNORED_PTR_ARG)).IgnoreArgument_pHints();
    EXPECTED_CALL(socket(AF_INET, SOCK_RDM, IPPROTO_UDP));
    EXPECTED_CALL(connect(test_socket, (struct sockaddr*)&test_ipv4_addr, sizeof(test_ipv4_addr))).IgnoreArgument_name().SetReturn(SOCKET_ERROR);
    EXPECTED_CALL(WSAGetLastError()).SetReturn(WSAECONNREFUSED);
    EXPECTED_CALL(closesocket(test_socket));
    EXPECTED_CALL(freeaddrinfo(&TEST_ADDR_INFO)).IgnoreArgument_pResult();

    // act
    int result = socketio_open(ioHandle, test_on_io_open_complete, &callbackContext, test_on_bytes_received, &callbackContext, test_on_io_error, &callbackContext);

    // assert
    ASSERT_ARE_EQUAL(int, 0, result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
    assert_resolver_request();
    ASSERT_ARE_EQUAL(size_t, 1, socket_call_count);
    ASSERT_ARE_EQUAL(size_t, 1, connect_call_count);
    ASSERT_ARE_EQUAL(void_ptr, &test_ipv4_addr, captured_connect_address);
    ASSERT_ARE_EQUAL(int, sizeof(test_ipv4_addr), captured_connect_address_length);
    ASSERT_ARE_EQUAL(size_t, 1, closesocket_call_count);
    ASSERT_ARE_EQUAL(size_t, (size_t)test_socket, (size_t)captured_closed_socket);
    ASSERT_ARE_EQUAL(size_t, 1, freeaddrinfo_call_count);
    ASSERT_ARE_EQUAL(void_ptr, &TEST_ADDR_INFO, captured_freed_addrinfo);
    assert_open_complete(IO_OPEN_ERROR, WSAECONNREFUSED);

    // cleanup
    socketio_destroy(ioHandle);
}

TEST_FUNCTION(socketio_open_ioctlsocket_failure_closes_socket_and_frees_addrinfo_once)
{
    // arrange
    SOCKETIO_CONFIG socketConfig = { HOSTNAME_ARG, PORT_NUM, NULL };
    CONCRETE_IO_HANDLE ioHandle = socketio_create(&socketConfig);

    umock_c_reset_all_calls();
    EXPECTED_CALL(getaddrinfo(IGNORED_PTR_ARG, IGNORED_PTR_ARG, &TEST_ADDR_INFO, IGNORED_PTR_ARG)).IgnoreArgument_pHints();
    EXPECTED_CALL(socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));
    EXPECTED_CALL(connect(test_socket, (struct sockaddr*)&test_ipv4_addr, sizeof(test_ipv4_addr))).IgnoreArgument_name();
    EXPECTED_CALL(ioctlsocket(test_socket, FIONBIO, IGNORED_PTR_ARG)).SetReturn(SOCKET_ERROR);
    EXPECTED_CALL(WSAGetLastError()).SetReturn(WSAENETDOWN);
    EXPECTED_CALL(closesocket(test_socket));
    EXPECTED_CALL(freeaddrinfo(&TEST_ADDR_INFO)).IgnoreArgument_pResult();

    // act
    int result = socketio_open(ioHandle, test_on_io_open_complete, &callbackContext, test_on_bytes_received, &callbackContext, test_on_io_error, &callbackContext);

    // assert
    ASSERT_ARE_EQUAL(int, 0, result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
    assert_resolver_request();
    ASSERT_ARE_EQUAL(size_t, 1, socket_call_count);
    ASSERT_ARE_EQUAL(size_t, 1, connect_call_count);
    ASSERT_ARE_EQUAL(size_t, 1, closesocket_call_count);
    ASSERT_ARE_EQUAL(size_t, (size_t)test_socket, (size_t)captured_closed_socket);
    ASSERT_ARE_EQUAL(size_t, 1, freeaddrinfo_call_count);
    ASSERT_ARE_EQUAL(void_ptr, &TEST_ADDR_INFO, captured_freed_addrinfo);
    assert_open_complete(IO_OPEN_ERROR, WSAENETDOWN);

    // cleanup
    socketio_destroy(ioHandle);
}

TEST_FUNCTION(socketio_open_ipv4_first_result_uses_returned_socket_fields_and_ignores_ipv6_second)
{
    // arrange
    SOCKETIO_CONFIG socketConfig = { HOSTNAME_ARG, PORT_NUM, NULL };
    CONCRETE_IO_HANDLE ioHandle = socketio_create(&socketConfig);
    TEST_ADDR_INFO.ai_socktype = SOCK_RDM;
    TEST_ADDR_INFO.ai_protocol = IPPROTO_UDP;
    TEST_ADDR_INFO.ai_next = &TEST_ADDR_INFO_SECOND;

    umock_c_reset_all_calls();
    EXPECTED_CALL(getaddrinfo(IGNORED_PTR_ARG, IGNORED_PTR_ARG, &TEST_ADDR_INFO, IGNORED_PTR_ARG)).IgnoreArgument_pHints();
    EXPECTED_CALL(socket(AF_INET, SOCK_RDM, IPPROTO_UDP));
    EXPECTED_CALL(connect(test_socket, (struct sockaddr*)&test_ipv4_addr, sizeof(test_ipv4_addr))).IgnoreArgument_name();
    EXPECTED_CALL(ioctlsocket(test_socket, FIONBIO, IGNORED_PTR_ARG));
    EXPECTED_CALL(freeaddrinfo(&TEST_ADDR_INFO)).IgnoreArgument_pResult();

    // act
    int result = socketio_open(ioHandle, test_on_io_open_complete, &callbackContext, test_on_bytes_received, &callbackContext, test_on_io_error, &callbackContext);

    // assert
    ASSERT_ARE_EQUAL(int, 0, result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
    assert_resolver_request();
    ASSERT_ARE_EQUAL(size_t, 1, socket_call_count);
    ASSERT_ARE_EQUAL(int, AF_INET, captured_socket_family);
    ASSERT_ARE_EQUAL(int, SOCK_RDM, captured_socket_type);
    ASSERT_ARE_EQUAL(int, IPPROTO_UDP, captured_socket_protocol);
    ASSERT_ARE_EQUAL(size_t, 1, connect_call_count);
    ASSERT_ARE_EQUAL(size_t, (size_t)test_socket, (size_t)captured_connect_socket);
    ASSERT_ARE_EQUAL(void_ptr, &test_ipv4_addr, captured_connect_address);
    ASSERT_ARE_EQUAL(int, sizeof(test_ipv4_addr), captured_connect_address_length);
    ASSERT_ARE_EQUAL(size_t, 0, closesocket_call_count);
    ASSERT_ARE_EQUAL(size_t, 1, freeaddrinfo_call_count);
    ASSERT_ARE_EQUAL(void_ptr, &TEST_ADDR_INFO, captured_freed_addrinfo);
    assert_open_complete(IO_OPEN_OK, 0);

    // cleanup
    socketio_destroy(ioHandle);
}

TEST_FUNCTION(socketio_open_ipv6_first_result_uses_returned_socket_fields_and_ignores_ipv4_second)
{
    // arrange
    SOCKETIO_CONFIG socketConfig = { HOSTNAME_ARG, PORT_NUM, NULL };
    CONCRETE_IO_HANDLE ioHandle = socketio_create(&socketConfig);
    TEST_ADDR_INFO.ai_family = AF_INET6;
    TEST_ADDR_INFO.ai_socktype = SOCK_SEQPACKET;
    TEST_ADDR_INFO.ai_protocol = IPPROTO_IPV6;
    TEST_ADDR_INFO.ai_addrlen = sizeof(test_ipv6_addr);
    TEST_ADDR_INFO.ai_addr = (struct sockaddr*)&test_ipv6_addr;
    TEST_ADDR_INFO.ai_next = &TEST_ADDR_INFO_SECOND;
    TEST_ADDR_INFO_SECOND.ai_family = AF_INET;
    TEST_ADDR_INFO_SECOND.ai_addrlen = sizeof(test_ipv4_addr);
    TEST_ADDR_INFO_SECOND.ai_addr = (struct sockaddr*)&test_ipv4_addr;

    umock_c_reset_all_calls();
    EXPECTED_CALL(getaddrinfo(IGNORED_PTR_ARG, IGNORED_PTR_ARG, &TEST_ADDR_INFO, IGNORED_PTR_ARG)).IgnoreArgument_pHints();
    EXPECTED_CALL(socket(AF_INET6, SOCK_SEQPACKET, IPPROTO_IPV6));
    EXPECTED_CALL(connect(test_socket, (struct sockaddr*)&test_ipv6_addr, sizeof(test_ipv6_addr))).IgnoreArgument_name();
    EXPECTED_CALL(ioctlsocket(test_socket, FIONBIO, IGNORED_PTR_ARG));
    EXPECTED_CALL(freeaddrinfo(&TEST_ADDR_INFO)).IgnoreArgument_pResult();

    // act
    int result = socketio_open(ioHandle, test_on_io_open_complete, &callbackContext, test_on_bytes_received, &callbackContext, test_on_io_error, &callbackContext);

    // assert
    ASSERT_ARE_EQUAL(int, 0, result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
    assert_resolver_request();
    ASSERT_ARE_EQUAL(size_t, 1, socket_call_count);
    ASSERT_ARE_EQUAL(int, AF_INET6, captured_socket_family);
    ASSERT_ARE_EQUAL(int, SOCK_SEQPACKET, captured_socket_type);
    ASSERT_ARE_EQUAL(int, IPPROTO_IPV6, captured_socket_protocol);
    ASSERT_ARE_EQUAL(size_t, 1, connect_call_count);
    ASSERT_ARE_EQUAL(size_t, (size_t)test_socket, (size_t)captured_connect_socket);
    ASSERT_ARE_EQUAL(void_ptr, &test_ipv6_addr, captured_connect_address);
    ASSERT_ARE_EQUAL(int, sizeof(test_ipv6_addr), captured_connect_address_length);
    ASSERT_ARE_EQUAL(size_t, 0, closesocket_call_count);
    ASSERT_ARE_EQUAL(size_t, 1, freeaddrinfo_call_count);
    ASSERT_ARE_EQUAL(void_ptr, &TEST_ADDR_INFO, captured_freed_addrinfo);
    assert_open_complete(IO_OPEN_OK, 0);

    // cleanup
    socketio_destroy(ioHandle);
}

TEST_FUNCTION(socketio_open_accepted_socket_bypasses_resolution_and_socket_creation)
{
    // arrange
    SOCKET accepted_socket = (SOCKET)0x9876;
    SOCKETIO_CONFIG socketConfig = { NULL, PORT_NUM, &accepted_socket };
    CONCRETE_IO_HANDLE ioHandle = socketio_create(&socketConfig);
    umock_c_reset_all_calls();

    // act
    int result = socketio_open(ioHandle, test_on_io_open_complete, &callbackContext, test_on_bytes_received, &callbackContext, test_on_io_error, &callbackContext);

    // assert
    ASSERT_ARE_EQUAL(int, 0, result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
    ASSERT_ARE_EQUAL(size_t, 0, getaddrinfo_call_count);
    ASSERT_ARE_EQUAL(size_t, 0, socket_call_count);
    ASSERT_ARE_EQUAL(size_t, 0, connect_call_count);
    ASSERT_ARE_EQUAL(size_t, 0, freeaddrinfo_call_count);
    assert_open_complete(IO_OPEN_OK, 0);

    umock_c_reset_all_calls();
    EXPECTED_CALL(closesocket(accepted_socket));
    result = socketio_close(ioHandle, NULL, NULL);
    ASSERT_ARE_EQUAL(int, 0, result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    socketio_destroy(ioHandle);
}

TEST_FUNCTION(socketio_close_socket_io_NULL_fails)
{
    // arrange
    // act
    int result = socketio_close(NULL, test_on_io_close_complete, (void*)0x4242);

    // assert
    ASSERT_ARE_NOT_EQUAL(int, 0, result);
}

TEST_FUNCTION(socketio_close_Succeeds)
{
    // arrange
    SOCKETIO_CONFIG socketConfig = { HOSTNAME_ARG, PORT_NUM, NULL };
    CONCRETE_IO_HANDLE ioHandle = socketio_create(&socketConfig);
    static ADDRINFO addrInfo = { AI_PASSIVE, AF_INET, SOCK_STREAM, IPPROTO_TCP, 128, NULL, (struct sockaddr*)0x11, NULL };

    int result = socketio_open(ioHandle, test_on_io_open_complete, &callbackContext, test_on_bytes_received, &callbackContext, test_on_io_error, &callbackContext);

    umock_c_reset_all_calls();

    EXPECTED_CALL(closesocket(IGNORED_NUM_ARG));

    // act
    result = socketio_close(ioHandle, test_on_io_close_complete, (void*)0x4242);

    // assert
    ASSERT_ARE_EQUAL(int, 0, result);

    // cleanup
    socketio_destroy(ioHandle);
}

TEST_FUNCTION(socketio_send_socket_io_fails)
{
    // arrange

    // act
    int result = socketio_send(NULL, (const void*)TEST_BUFFER_VALUE, TEST_BUFFER_SIZE, OnSendComplete, (void*)TEST_CALLBACK_CONTEXT);

    // assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
    ASSERT_ARE_NOT_EQUAL(int, 0, result);
}

TEST_FUNCTION(socketio_send_buffer_NULL_fails)
{
    // arrange
    SOCKETIO_CONFIG socketConfig = { HOSTNAME_ARG, PORT_NUM, NULL };
    CONCRETE_IO_HANDLE ioHandle = socketio_create(&socketConfig);
    static ADDRINFO addrInfo = { AI_PASSIVE, AF_INET, SOCK_STREAM, IPPROTO_TCP, 128, NULL, (struct sockaddr*)0x11, NULL };

    int result = socketio_open(ioHandle, test_on_io_open_complete, &callbackContext, test_on_bytes_received, &callbackContext, test_on_io_error, &callbackContext);

    umock_c_reset_all_calls();

    // act
    result = socketio_send(ioHandle, NULL, TEST_BUFFER_SIZE, OnSendComplete, (void*)TEST_CALLBACK_CONTEXT);

    // assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
    ASSERT_ARE_NOT_EQUAL(int, 0, result);

    // cleanup
    socketio_destroy(ioHandle);
}

TEST_FUNCTION(socketio_send_size_zero_fails)
{
    // arrange
    SOCKETIO_CONFIG socketConfig = { HOSTNAME_ARG, PORT_NUM, NULL };
    CONCRETE_IO_HANDLE ioHandle = socketio_create(&socketConfig);
    static ADDRINFO addrInfo = { AI_PASSIVE, AF_INET, SOCK_STREAM, IPPROTO_TCP, 128, NULL, (struct sockaddr*)0x11, NULL };

    int result = socketio_open(ioHandle, test_on_io_open_complete, &callbackContext, test_on_bytes_received, &callbackContext, test_on_io_error, &callbackContext);

    umock_c_reset_all_calls();

    // act
    result = socketio_send(ioHandle, (const void*)TEST_BUFFER_VALUE, 0, OnSendComplete, (void*)TEST_CALLBACK_CONTEXT);

    // assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
    ASSERT_ARE_NOT_EQUAL(int, 0, result);

    // cleanup
    socketio_destroy(ioHandle);
}

TEST_FUNCTION(socketio_send_succeeds)
{
    // arrange
    SOCKETIO_CONFIG socketConfig = { HOSTNAME_ARG, PORT_NUM, NULL };
    CONCRETE_IO_HANDLE ioHandle = socketio_create(&socketConfig);
    static ADDRINFO addrInfo = { AI_PASSIVE, AF_INET, SOCK_STREAM, IPPROTO_TCP, 128, NULL, (struct sockaddr*)0x11, NULL };

    int result = socketio_open(ioHandle, test_on_io_open_complete, &callbackContext, test_on_bytes_received, &callbackContext, test_on_io_error, &callbackContext);

    umock_c_reset_all_calls();

    EXPECTED_CALL(singlylinkedlist_get_head_item(IGNORED_PTR_ARG));
    EXPECTED_CALL(send(IGNORED_NUM_ARG, IGNORED_PTR_ARG, IGNORED_NUM_ARG, IGNORED_NUM_ARG));

    // act
    result = socketio_send(ioHandle, (const void*)TEST_BUFFER_VALUE, TEST_BUFFER_SIZE, OnSendComplete, (void*)TEST_CALLBACK_CONTEXT);

    // assert
    ASSERT_ARE_EQUAL(int, 0, result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    socketio_destroy(ioHandle);
}

TEST_FUNCTION(socketio_send_returns_1_succeeds)
{
    // arrange
    SOCKETIO_CONFIG socketConfig = { HOSTNAME_ARG, PORT_NUM, NULL };
    CONCRETE_IO_HANDLE ioHandle = socketio_create(&socketConfig);
    static ADDRINFO addrInfo = { AI_PASSIVE, AF_INET, SOCK_STREAM, IPPROTO_TCP, 128, NULL, (struct sockaddr*)0x11, NULL };

    int result = socketio_open(ioHandle, test_on_io_open_complete, &callbackContext, test_on_bytes_received, &callbackContext, test_on_io_error, &callbackContext);

    umock_c_reset_all_calls();

    EXPECTED_CALL(singlylinkedlist_get_head_item(IGNORED_PTR_ARG));
    EXPECTED_CALL(send(IGNORED_NUM_ARG, IGNORED_PTR_ARG, IGNORED_NUM_ARG, IGNORED_NUM_ARG)).SetReturn(1);
    EXPECTED_CALL(WSAGetLastError()).SetReturn(WSAEWOULDBLOCK);
    EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));
    EXPECTED_CALL(singlylinkedlist_add(IGNORED_PTR_ARG, IGNORED_PTR_ARG));

    // act
    result = socketio_send(ioHandle, (const void*)TEST_BUFFER_VALUE, TEST_BUFFER_SIZE, OnSendComplete, (void*)TEST_CALLBACK_CONTEXT);

    // assert
    ASSERT_ARE_EQUAL(int, 0, result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    list_head_count = list_item_count;
    socketio_destroy(ioHandle);
}

TEST_FUNCTION(socketio_dowork_socket_io_NULL_fails)
{
    // arrange

    // act
    socketio_dowork(NULL);

    // assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
}

TEST_FUNCTION(socketio_dowork_succeeds)
{
    // arrange
    SOCKETIO_CONFIG socketConfig = { HOSTNAME_ARG, PORT_NUM, NULL };
    CONCRETE_IO_HANDLE ioHandle = socketio_create(&socketConfig);

    (void)socketio_open(ioHandle, test_on_io_open_complete, &callbackContext, test_on_bytes_received, &callbackContext, test_on_io_error, &callbackContext);

    umock_c_reset_all_calls();

    EXPECTED_CALL(singlylinkedlist_get_head_item(IGNORED_PTR_ARG));
    EXPECTED_CALL(recv(IGNORED_NUM_ARG, IGNORED_PTR_ARG, IGNORED_NUM_ARG, IGNORED_NUM_ARG));
    EXPECTED_CALL(WSAGetLastError());

    // act
    socketio_dowork(ioHandle);

    // assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    socketio_destroy(ioHandle);
}

TEST_FUNCTION(socketio_dowork_recv_bytes_succeeds)
{
    // arrange
    SOCKETIO_CONFIG socketConfig = { HOSTNAME_ARG, PORT_NUM, NULL };
    CONCRETE_IO_HANDLE ioHandle = socketio_create(&socketConfig);

    (void)socketio_open(ioHandle, test_on_io_open_complete, &callbackContext, test_on_bytes_received, &callbackContext, test_on_io_error, &callbackContext);

    umock_c_reset_all_calls();

    EXPECTED_CALL(singlylinkedlist_get_head_item(IGNORED_PTR_ARG));
    EXPECTED_CALL(recv(IGNORED_NUM_ARG, IGNORED_PTR_ARG, IGNORED_NUM_ARG, IGNORED_NUM_ARG))
        .CopyOutArgumentBuffer(2, "t", 1)
        .SetReturn(1);
    EXPECTED_CALL(recv(IGNORED_NUM_ARG, IGNORED_PTR_ARG, IGNORED_NUM_ARG, IGNORED_NUM_ARG));
    EXPECTED_CALL(WSAGetLastError());

    // act
    socketio_dowork(ioHandle);

    // assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    socketio_destroy(ioHandle);
}

// socketio_setoption tests

static CONCRETE_IO_HANDLE setup_socket()
{
    SOCKETIO_CONFIG socketConfig = { HOSTNAME_ARG, PORT_NUM, NULL };
    CONCRETE_IO_HANDLE ioHandle = socketio_create(&socketConfig);
    int result = socketio_open(ioHandle, test_on_io_open_complete, &callbackContext, test_on_bytes_received, &callbackContext, test_on_io_error, &callbackContext);
    ASSERT_ARE_EQUAL(int, 0, result);
    return ioHandle;
}

static CONCRETE_IO_HANDLE setup_socket_and_expect_WSAIoctl()
{
    CONCRETE_IO_HANDLE ioHandle = setup_socket();

    umock_c_reset_all_calls();

    STRICT_EXPECTED_CALL(WSAIoctl(*(SOCKET*)ioHandle, SIO_KEEPALIVE_VALS, IGNORED_PTR_ARG,
        sizeof(struct tcp_keepalive), NULL, 0, IGNORED_PTR_ARG, NULL, NULL))
        .IgnoreArgument_lpvInBuffer()
        .IgnoreArgument_lpcbBytesReturned();

    memset(&persisted_tcp_keepalive, 0, sizeof(struct tcp_keepalive));

    return ioHandle;
}

static void verify_mocks_and_destroy_socket(CONCRETE_IO_HANDLE ioHandle)
{
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
    socketio_destroy(ioHandle);
}

TEST_FUNCTION(socketio_setoption_fails_when_handle_is_null)
{
    // arrange
    int irrelevant = 1;

    // act
    int result = socketio_setoption(NULL, "tcp_keepalive", &irrelevant);

    // assert
    ASSERT_ARE_NOT_EQUAL(int, 0, result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
}

TEST_FUNCTION(socketio_setoption_fails_when_option_name_is_null)
{
    // arrange
    int irrelevant = 1;
    int result;

    CONCRETE_IO_HANDLE ioHandle = setup_socket();

    umock_c_reset_all_calls();

    // act
    result = socketio_setoption(ioHandle, NULL, &irrelevant);

    // assert
    ASSERT_ARE_NOT_EQUAL(int, 0, result);

    verify_mocks_and_destroy_socket(ioHandle);
}

TEST_FUNCTION(socketio_setoption_fails_when_value_is_null)
{
    // arrange
    int result;
    CONCRETE_IO_HANDLE ioHandle = setup_socket();

    umock_c_reset_all_calls();

    // act
    result = socketio_setoption(ioHandle, "tcp_keepalive", NULL);

    // assert
    ASSERT_ARE_NOT_EQUAL(int, 0, result);

    verify_mocks_and_destroy_socket(ioHandle);
}

TEST_FUNCTION(socketio_setoption_fails_when_it_receives_an_unsupported_option)
{
    // arrange
    int irrelevant = 1;
    int result;

    CONCRETE_IO_HANDLE ioHandle = setup_socket();

    umock_c_reset_all_calls();

    // act
    result = socketio_setoption(ioHandle, "unsupported_option_name", &irrelevant);

    // assert
    ASSERT_ARE_NOT_EQUAL(int, 0, result);

    verify_mocks_and_destroy_socket(ioHandle);
}

TEST_FUNCTION(calling_socketio_setoption_with_tcp_keepalive_does_not_impact_the_other_two_options)
{
    // arrange
    int irrelevant = 1;
    CONCRETE_IO_HANDLE ioHandle = setup_socket_and_expect_WSAIoctl();

    // act
    int result = socketio_setoption(ioHandle, "tcp_keepalive", &irrelevant);
    ASSERT_ARE_EQUAL(int, 0, result);

    // assert
    ASSERT_ARE_EQUAL(int, 0, persisted_tcp_keepalive.keepalivetime);
    ASSERT_ARE_EQUAL(int, 0, persisted_tcp_keepalive.keepaliveinterval);

    verify_mocks_and_destroy_socket(ioHandle);
}

TEST_FUNCTION(calling_socketio_setoption_for_option_tcp_keepalive_time_does_not_impact_the_other_two)
{
    // arrange
    int irrelevant = 1;
    CONCRETE_IO_HANDLE ioHandle = setup_socket_and_expect_WSAIoctl();

    // act
    int result = socketio_setoption(ioHandle, "tcp_keepalive_time", &irrelevant);
    ASSERT_ARE_EQUAL(int, 0, result);

    // assert
    ASSERT_ARE_EQUAL(int, 0, persisted_tcp_keepalive.onoff);
    ASSERT_ARE_EQUAL(int, 0, persisted_tcp_keepalive.keepaliveinterval);

    verify_mocks_and_destroy_socket(ioHandle);
}

TEST_FUNCTION(calling_socketio_setoption_for_option_tcp_keepalive_interval_does_not_impact_the_other_two)
{
    // arrange
    int irrelevant = 1;
    CONCRETE_IO_HANDLE ioHandle = setup_socket_and_expect_WSAIoctl();

    // act
    int result = socketio_setoption(ioHandle, "tcp_keepalive_interval", &irrelevant);
    ASSERT_ARE_EQUAL(int, 0, result);

    // assert
    ASSERT_ARE_EQUAL(int, 0, persisted_tcp_keepalive.onoff);
    ASSERT_ARE_EQUAL(int, 0, persisted_tcp_keepalive.keepalivetime);

    verify_mocks_and_destroy_socket(ioHandle);
}

TEST_FUNCTION(tcp_keepalive_time_arg_to_socketio_setoption_is_converted_to_milliseconds)
{
    // arrange
    int result;
    CONCRETE_IO_HANDLE ioHandle = setup_socket_and_expect_WSAIoctl();

    int time = 3;

    // act
    result = socketio_setoption(ioHandle, "tcp_keepalive_time", &time);
    ASSERT_ARE_EQUAL(int, 0, result);

    // assert
    ASSERT_ARE_EQUAL(int, time * 1000, persisted_tcp_keepalive.keepalivetime);

    verify_mocks_and_destroy_socket(ioHandle);
}

TEST_FUNCTION(tcp_keepalive_interval_arg_to_socketio_setoption_is_converted_to_milliseconds)
{
    // arrange
    int result;
    CONCRETE_IO_HANDLE ioHandle = setup_socket_and_expect_WSAIoctl();

    int interval = 15;

    // act
    result = socketio_setoption(ioHandle, "tcp_keepalive_interval", &interval);
    ASSERT_ARE_EQUAL(int, 0, result);

    // assert
    ASSERT_ARE_EQUAL(int, interval * 1000, persisted_tcp_keepalive.keepaliveinterval);

    verify_mocks_and_destroy_socket(ioHandle);
}

TEST_FUNCTION(tcp_keepalive_arg_is_not_modified_by_socketio_setoption)
{
    // arrange
    int result;
    CONCRETE_IO_HANDLE ioHandle = setup_socket_and_expect_WSAIoctl();

    int onoff = -42;

    // act
    result = socketio_setoption(ioHandle, "tcp_keepalive", &onoff);
    ASSERT_ARE_EQUAL(int, 0, result);

    // assert
    ASSERT_ARE_EQUAL(int, onoff, persisted_tcp_keepalive.onoff);

    verify_mocks_and_destroy_socket(ioHandle);
}

TEST_FUNCTION(socketio_setoption_does_not_persist_keepalive_values_if_WSAIoctl_fails)
{
    // arrange
    int irrelevant = 1;
    int result;

    CONCRETE_IO_HANDLE ioHandle = setup_socket();

    umock_c_reset_all_calls();

    STRICT_EXPECTED_CALL(WSAIoctl(*(SOCKET*)ioHandle, SIO_KEEPALIVE_VALS, IGNORED_PTR_ARG,
        sizeof(struct tcp_keepalive), NULL, 0, IGNORED_PTR_ARG, NULL, NULL))
        .IgnoreArgument_lpvInBuffer()
        .IgnoreArgument_lpcbBytesReturned()
        .SetReturn(1); // 1st call fails, keepalive changes should be discarded
    STRICT_EXPECTED_CALL(WSAIoctl(*(SOCKET*)ioHandle, SIO_KEEPALIVE_VALS, IGNORED_PTR_ARG,
        sizeof(struct tcp_keepalive), NULL, 0, IGNORED_PTR_ARG, NULL, NULL))
        .IgnoreArgument_lpvInBuffer()
        .IgnoreArgument_lpcbBytesReturned()
        .SetReturn(0); // purpose of 2nd call is just to see the keepalive state after the 1st call

    memset(&persisted_tcp_keepalive, 0, sizeof(struct tcp_keepalive));

    // act
    result = socketio_setoption(ioHandle, "tcp_keepalive", &irrelevant);
    ASSERT_ARE_NOT_EQUAL(int, 0, result);

    result = socketio_setoption(ioHandle, "tcp_keepalive_time", &irrelevant); // use different option for 2nd call so we don't overwrite the value from the 1st
    ASSERT_ARE_EQUAL(int, 0, result);

    // assert
    ASSERT_ARE_EQUAL(int, 0, persisted_tcp_keepalive.onoff);

    verify_mocks_and_destroy_socket(ioHandle);
}

END_TEST_SUITE(socketio_win32_unittests)

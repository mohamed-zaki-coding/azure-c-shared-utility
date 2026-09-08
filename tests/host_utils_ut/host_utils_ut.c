// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include <stddef.h>

#include "testrunnerswitcher.h"
#include "../../src/host_utils.h"

#define ASSERT_EQUAL(type, expected, actual) CTEST_ASSERT_ARE_EQUAL_WITH_MSG(type, expected, actual, "")
#define ASSERT_NOT_EQUAL(type, expected, actual) CTEST_ASSERT_ARE_NOT_EQUAL_WITH_MSG(type, expected, actual, "")

BEGIN_TEST_SUITE(host_utils_ut)

TEST_FUNCTION(authority_host_length_and_format_host_for_authority_with_dns_host_leave_it_unchanged)
{
    // arrange
    const char* host = "example.azure-devices.net";
    char output[sizeof("example.azure-devices.net")];

    // act
    size_t length = authority_host_length(host);
    int result = format_host_for_authority(host, output, sizeof(output));

    // assert
    ASSERT_ARE_EQUAL_WITH_MSG(size_t, sizeof("example.azure-devices.net") - 1, length, "Unexpected formatted length");
    ASSERT_EQUAL(int, 0, result);
    ASSERT_EQUAL(char_ptr, "example.azure-devices.net", output);
}

TEST_FUNCTION(authority_host_length_and_format_host_for_authority_with_ipv4_host_leave_it_unchanged)
{
    // arrange
    const char* host = "192.168.0.1";
    char output[sizeof("192.168.0.1")];

    // act
    size_t length = authority_host_length(host);
    int result = format_host_for_authority(host, output, sizeof(output));

    // assert
    ASSERT_EQUAL(size_t, sizeof("192.168.0.1") - 1, length);
    ASSERT_EQUAL(int, 0, result);
    ASSERT_EQUAL(char_ptr, "192.168.0.1", output);
}

TEST_FUNCTION(authority_host_length_and_format_host_for_authority_with_global_ipv6_host_add_brackets)
{
    // arrange
    const char* host = "2001:db8::1";
    char output[sizeof("[2001:db8::1]")];

    // act
    size_t length = authority_host_length(host);
    int result = format_host_for_authority(host, output, sizeof(output));

    // assert
    ASSERT_EQUAL(size_t, sizeof("[2001:db8::1]") - 1, length);
    ASSERT_EQUAL(int, 0, result);
    ASSERT_EQUAL(char_ptr, "[2001:db8::1]", output);
}

TEST_FUNCTION(authority_host_length_and_format_host_for_authority_with_named_ipv6_zone_escape_percent)
{
    // arrange
    const char* host = "fe80::1%eth0";
    char output[sizeof("[fe80::1%25eth0]")];

    // act
    size_t length = authority_host_length(host);
    int result = format_host_for_authority(host, output, sizeof(output));

    // assert
    ASSERT_EQUAL(size_t, sizeof("[fe80::1%25eth0]") - 1, length);
    ASSERT_EQUAL(int, 0, result);
    ASSERT_EQUAL(char_ptr, "[fe80::1%25eth0]", output);
}

TEST_FUNCTION(authority_host_length_and_format_host_for_authority_with_numeric_ipv6_zone_escape_percent)
{
    // arrange
    const char* host = "fe80::1%3";
    char output[sizeof("[fe80::1%253]")];

    // act
    size_t length = authority_host_length(host);
    int result = format_host_for_authority(host, output, sizeof(output));

    // assert
    ASSERT_EQUAL(size_t, sizeof("[fe80::1%253]") - 1, length);
    ASSERT_EQUAL(int, 0, result);
    ASSERT_EQUAL(char_ptr, "[fe80::1%253]", output);
}

TEST_FUNCTION(format_host_for_authority_with_exact_size_buffer_succeeds)
{
    // arrange
    char output[sizeof("[fe80::1%25eth0]")];

    // act
    int result = format_host_for_authority("fe80::1%eth0", output, sizeof(output));

    // assert
    ASSERT_EQUAL(int, 0, result);
    ASSERT_EQUAL(char_ptr, "[fe80::1%25eth0]", output);
}

TEST_FUNCTION(format_host_for_authority_with_too_small_buffer_fails)
{
    // arrange
    char output[sizeof("[2001:db8::1]") - 1];

    // act
    int result = format_host_for_authority("2001:db8::1", output, sizeof(output));

    // assert
    ASSERT_NOT_EQUAL(int, 0, result);
}

TEST_FUNCTION(authority_host_length_and_format_host_for_authority_with_null_arguments_fail)
{
    // arrange
    char output[1];

    // act
    size_t length = authority_host_length(NULL);
    int null_host_result = format_host_for_authority(NULL, output, sizeof(output));
    int null_output_result = format_host_for_authority("example.com", NULL, 0);

    // assert
    ASSERT_EQUAL(size_t, 0, length);
    ASSERT_NOT_EQUAL(int, 0, null_host_result);
    ASSERT_NOT_EQUAL(int, 0, null_output_result);
}

TEST_FUNCTION(authority_host_length_and_format_host_for_authority_with_empty_host_leave_it_empty)
{
    // arrange
    char output[1];

    // act
    size_t length = authority_host_length("");
    int result = format_host_for_authority("", output, sizeof(output));

    // assert
    ASSERT_EQUAL(size_t, 0, length);
    ASSERT_EQUAL(int, 0, result);
    ASSERT_EQUAL(char_ptr, "", output);
}

TEST_FUNCTION(authority_host_length_and_format_host_for_authority_with_named_ipv6_zone_escape_non_unreserved_bytes)
{
    // arrange
    const char* host = "fe80::1%Ethernet 2";
    char output[sizeof("[fe80::1%25Ethernet%202]")];

    // act
    size_t length = authority_host_length(host);
    int result = format_host_for_authority(host, output, sizeof(output));

    // assert
    ASSERT_EQUAL(size_t, sizeof("[fe80::1%25Ethernet%202]") - 1, length);
    ASSERT_EQUAL(int, 0, result);
    ASSERT_EQUAL(char_ptr, "[fe80::1%25Ethernet%202]", output);
}

TEST_FUNCTION(format_host_for_authority_with_exact_size_buffer_for_escaped_named_ipv6_zone_succeeds)
{
    // arrange
    char output[sizeof("[fe80::1%25Ethernet%202]")];

    // act
    int result = format_host_for_authority("fe80::1%Ethernet 2", output, sizeof(output));

    // assert
    ASSERT_EQUAL(int, 0, result);
    ASSERT_EQUAL(char_ptr, "[fe80::1%25Ethernet%202]", output);
}

TEST_FUNCTION(format_host_for_authority_with_short_buffer_for_escaped_named_ipv6_zone_fails)
{
    // arrange
    char output[sizeof("[fe80::1%25Ethernet%202]") - 1];

    // act
    int result = format_host_for_authority("fe80::1%Ethernet 2", output, sizeof(output));

    // assert
    ASSERT_NOT_EQUAL(int, 0, result);
}

TEST_FUNCTION(authority_host_length_and_format_host_for_authority_escape_literal_percent_within_ipv6_zone)
{
    // arrange
    const char* host = "fe80::1%eth%0";
    char output[sizeof("[fe80::1%25eth%250]")];

    // act
    size_t length = authority_host_length(host);
    int result = format_host_for_authority(host, output, sizeof(output));

    // assert
    ASSERT_EQUAL(size_t, sizeof("[fe80::1%25eth%250]") - 1, length);
    ASSERT_EQUAL(int, 0, result);
    ASSERT_EQUAL(char_ptr, "[fe80::1%25eth%250]", output);
}

END_TEST_SUITE(host_utils_ut)

int main(void)
{
    size_t failed_test_count = 0;
    RUN_TEST_SUITE(host_utils_ut, failed_test_count);
    return (int)failed_test_count;
}

// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include "host_utils.h"

#include "azure_c_shared_utility/safe_math.h"

static int is_uri_unreserved(unsigned char character)
{
    return ((character >= 'A') && (character <= 'Z')) ||
        ((character >= 'a') && (character <= 'z')) ||
        ((character >= '0') && (character <= '9')) ||
        (character == '-') || (character == '.') || (character == '_') || (character == '~');
}

static char hex_digit(unsigned char value)
{
    return (char)((value < 10) ? ('0' + value) : ('A' + (value - 10)));
}

static int get_authority_host_info(const char* host, size_t* formatted_length, int* is_ipv6)
{
    int result;

    if ((host == NULL) || (formatted_length == NULL) || (is_ipv6 == NULL))
    {
        result = __LINE__;
    }
    else
    {
        const char* current = host;
        size_t length = 0;
        int contains_colon = 0;
        int is_in_zone = 0;

        while (*current != '\0')
        {
            if (*current == ':')
            {
                contains_colon = 1;
                break;
            }

            current++;
        }

        result = 0;
        current = host;
        while (*current != '\0')
        {
            size_t character_length;

            if ((contains_colon != 0) && (is_in_zone != 0))
            {
                character_length = is_uri_unreserved((unsigned char)*current) ? 1 : 3;
            }
            else if ((contains_colon != 0) && (*current == '%'))
            {
                character_length = 3;
                is_in_zone = 1;
            }
            else
            {
                character_length = 1;
            }

            length = safe_add_size_t(length, character_length);
            if (length == SIZE_MAX)
            {
                result = __LINE__;
                break;
            }

            current++;
        }

        if (result == 0)
        {
            if (contains_colon != 0)
            {
                length = safe_add_size_t(length, 2);
                if (length == SIZE_MAX)
                {
                    result = __LINE__;
                }
            }

            if (result == 0)
            {
                *formatted_length = length;
                *is_ipv6 = contains_colon;
            }
        }
    }

    return result;
}

size_t authority_host_length(const char* host)
{
    size_t result;
    int is_ipv6;

    if (get_authority_host_info(host, &result, &is_ipv6) != 0)
    {
        result = 0;
    }

    return result;
}

int format_host_for_authority(const char* host, char* output, size_t output_size)
{
    int result;
    size_t formatted_length;
    int is_ipv6;

    if ((host == NULL) || (output == NULL))
    {
        result = __LINE__;
    }
    else if (get_authority_host_info(host, &formatted_length, &is_ipv6) != 0)
    {
        result = __LINE__;
    }
    else if (output_size <= formatted_length)
    {
        result = __LINE__;
    }
    else
    {
        const char* current = host;
        size_t output_index = 0;
        int is_in_zone = 0;

        if (is_ipv6 != 0)
        {
            output[output_index++] = '[';
        }

        while (*current != '\0')
        {
            if ((is_ipv6 != 0) && (is_in_zone != 0) && is_uri_unreserved((unsigned char)*current))
            {
                output[output_index++] = *current;
            }
            else if ((is_ipv6 != 0) && (is_in_zone != 0))
            {
                unsigned char character = (unsigned char)*current;
                output[output_index++] = '%';
                output[output_index++] = hex_digit(character >> 4);
                output[output_index++] = hex_digit(character & 0x0F);
            }
            else if ((is_ipv6 != 0) && (*current == '%'))
            {
                output[output_index++] = '%';
                output[output_index++] = '2';
                output[output_index++] = '5';
                is_in_zone = 1;
            }
            else
            {
                output[output_index++] = *current;
            }

            current++;
        }

        if (is_ipv6 != 0)
        {
            output[output_index++] = ']';
        }

        output[output_index] = '\0';
        result = 0;
    }

    return result;
}

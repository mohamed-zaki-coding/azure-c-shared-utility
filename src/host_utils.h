// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#ifndef HOST_UTILS_H
#define HOST_UTILS_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

size_t authority_host_length(const char* host);
int format_host_for_authority(const char* host, char* output, size_t output_size);

#ifdef __cplusplus
}
#endif

#endif /* HOST_UTILS_H */

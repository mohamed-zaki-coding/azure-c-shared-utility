#Copyright (c) Microsoft. All rights reserved.
#Licensed under the MIT license. See LICENSE file in the project root for full license information.

cmake_minimum_required(VERSION 3.12)

# This suite uses GNU ld syscall wrapping and is intentionally Linux-only.
if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    return()
endif()

compileAsC99()
set(theseTestsName socketio_berkeley_ut)
set(${theseTestsName}_test_files
${theseTestsName}.c
)

set(${theseTestsName}_c_files
../../adapters/socketio_berkeley.c
)

set(${theseTestsName}_h_files
)

build_c_test_artifacts(${theseTestsName} ON "azure_c_shared_utility_tests")

if(TARGET ${theseTestsName}_exe)
    set_property(TARGET ${theseTestsName}_exe APPEND_STRING PROPERTY LINK_FLAGS
        " -Wl,--wrap=getaddrinfo -Wl,--wrap=freeaddrinfo -Wl,--wrap=socket -Wl,--wrap=close -Wl,--wrap=fcntl -Wl,--wrap=connect -Wl,--wrap=poll -Wl,--wrap=getsockopt -Wl,--wrap=ioctl")
endif()

cmake_minimum_required(VERSION 3.16)
project(cblicense
    VERSION 0.1.0
    DESCRIPTION "Async license-key activation for embedded + Linux devices"
    LANGUAGES C CXX)

option(CBL_BUILD_TESTS  "Build cblicense unit tests"   ON)
option(CBL_BUILD_TOOLS  "Build cblicense CLI tools"    ON)
option(CBL_BUILD_SHARED "Build cblicense as a shared library (default: static)" OFF)

set(CMAKE_C_STANDARD   11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD 17)

set(CBL_CORE_SRCS
    src/cbl_sha256.c
    src/cbl_hmac.c
    src/cbl_base32.c
    src/cbl_core.c
)

# Generic provider is always available (lets you skip platform-specific
# providers entirely if you're feeding bytes from an HSM or a test).
list(APPEND CBL_CORE_SRCS platforms/generic/cbl_fp_generic.c)

# Per-host-OS provider selection. ESP32 is built via PlatformIO; this
# CMake config targets the developer host + the Pi.
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    list(APPEND CBL_CORE_SRCS platforms/linux/cbl_fp_linux.c)
endif()
if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    list(APPEND CBL_CORE_SRCS platforms/macos/cbl_fp_macos.c)
endif()

if(CBL_BUILD_SHARED)
    add_library(cblicense SHARED ${CBL_CORE_SRCS})
else()
    add_library(cblicense STATIC ${CBL_CORE_SRCS})
endif()
add_library(cblicense::cblicense ALIAS cblicense)

target_include_directories(cblicense
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${CMAKE_CURRENT_SOURCE_DIR}/platforms/linux
        ${CMAKE_CURRENT_SOURCE_DIR}/platforms/macos
        ${CMAKE_CURRENT_SOURCE_DIR}/platforms/generic
)

target_compile_options(cblicense PRIVATE
    -Wall -Wextra -Wpedantic -Wshadow -Wstrict-prototypes
    -Wno-unused-parameter
    -Os -ffunction-sections -fdata-sections
)

# ---------- CLI tools ----------
if(CBL_BUILD_TOOLS)
    add_executable(cbl-fingerprint tools/cbl_fingerprint.c)
    target_link_libraries(cbl-fingerprint PRIVATE cblicense)

    add_executable(cbl-mint tools/cbl_mint.c)
    target_link_libraries(cbl-mint PRIVATE cblicense)

    add_executable(cbl-verify tools/cbl_verify.c)
    target_link_libraries(cbl-verify PRIVATE cblicense)
endif()

# ---------- Tests ----------
if(CBL_BUILD_TESTS)
    enable_testing()

    foreach(t IN ITEMS test_sha256 test_hmac test_base32 test_core test_fingerprint)
        add_executable(${t} tests/${t}.c)
        target_link_libraries(${t} PRIVATE cblicense)
        add_test(NAME ${t} COMMAND ${t})
    endforeach()
endif()

install(TARGETS cblicense
    EXPORT cblicense-targets
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib)
install(DIRECTORY include/ DESTINATION include)

cmake_minimum_required(VERSION 3.16)
project(jwks_server_cpp LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(ENABLE_COVERAGE "Enable coverage flags" OFF)

# OpenSSL is required for RSA key generation and JWT signing
find_package(OpenSSL REQUIRED)

# SQLite3 — link against the system library
find_library(SQLITE3_LIB sqlite3 REQUIRED)

# ── Main server executable ────────────────────────────────────────────────────
add_executable(jwks_server src/main.cpp)
target_include_directories(jwks_server PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/external
)
target_link_libraries(jwks_server PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
    ${SQLITE3_LIB}
)

# ── Test executable ───────────────────────────────────────────────────────────
add_executable(jwks_tests tests/test_server.cpp)
target_include_directories(jwks_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/external
)
target_link_libraries(jwks_tests PRIVATE
    ${SQLITE3_LIB}
)

if(ENABLE_COVERAGE)
    target_compile_options(jwks_tests PRIVATE
        -O0 -g -fprofile-instr-generate -fcoverage-mapping)
    target_link_options(jwks_tests PRIVATE
        -fprofile-instr-generate -fcoverage-mapping)
    target_compile_options(jwks_server PRIVATE
        -O0 -g -fprofile-instr-generate -fcoverage-mapping)
    target_link_options(jwks_server PRIVATE
        -fprofile-instr-generate -fcoverage-mapping)
endif()

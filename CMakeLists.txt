cmake_minimum_required(VERSION 3.22)
project(sentinel_boot VERSION 0.1.0 LANGUAGES C CXX)

option(SB_BUILD_TESTS "Build unit and integration tests" ON)
option(SB_BUILD_FUZZ "Build libFuzzer targets (requires clang)" OFF)
option(SB_BUILD_TOOLS "Build the host simulator CLI" ON)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include(FetchContent)

# --- Mbed TLS (crypto only), pinned to an exact release tarball -------------
set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)
set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
set(MBEDTLS_FATAL_WARNINGS OFF CACHE BOOL "" FORCE)
FetchContent_Declare(
  mbedtls
  URL https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-3.6.8/mbedtls-3.6.8.tar.bz2
  URL_HASH SHA256=bc54b818e87f49c0b3281dd85d24adaede0e63b4e822e3fbd49c005a38b9595b)
FetchContent_MakeAvailable(mbedtls)

set(SB_WARNINGS -Wall -Wextra -Werror -Wconversion -Wshadow -Wstrict-prototypes
                -Wmissing-prototypes -Wpedantic)

# --- Bootloader core: platform independent, no dynamic allocation -----------
add_library(sb_boot STATIC
  boot/crypto_port.c
  boot/manifest.c
  boot/state.c
  boot/verify.c
  boot/update.c
  boot/boot.c)
target_include_directories(sb_boot PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(sb_boot PRIVATE mbedcrypto)
target_compile_options(sb_boot PRIVATE ${SB_WARNINGS})

# --- Simulated HAL (RAM/file backed flash and OTP) ---------------------------
add_library(sb_hal_sim STATIC
  hal/flash_sim.c
  hal/otp_sim.c)
target_include_directories(sb_hal_sim PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_options(sb_hal_sim PRIVATE ${SB_WARNINGS})

if(SB_BUILD_TOOLS)
  add_executable(sentinel-sim tools/sim/main.c)
  target_link_libraries(sentinel-sim PRIVATE sb_boot sb_hal_sim)
  target_compile_options(sentinel-sim PRIVATE ${SB_WARNINGS})
endif()

if(SB_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()

if(SB_BUILD_FUZZ)
  add_subdirectory(tests/fuzz)
endif()

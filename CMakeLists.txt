cmake_minimum_required(VERSION 3.22)
project(sentinel_boot VERSION 0.1.0 LANGUAGES C)

option(SB_BUILD_TESTS "Build unit and integration tests" ON)
option(SB_BUILD_FUZZ "Build libFuzzer targets (requires clang)" OFF)
option(SB_BUILD_TOOLS "Build the host simulator CLI" ON)
option(SB_TARGET_QEMU "Cross-build the self-test firmware for QEMU mps2-an385 (Cortex-M3)" OFF)

if(SB_BUILD_TESTS OR SB_BUILD_FUZZ)
  enable_language(CXX)
endif()

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include(FetchContent)

if(SB_TARGET_QEMU)
  # Bare-metal Mbed TLS: no filesystem, network, time or persistent key store,
  # and a (demo-only) hardware entropy hook. See port/qemu_mps2/.
  string(APPEND CMAKE_C_FLAGS
    " -DMBEDTLS_USER_CONFIG_FILE=\\\"${CMAKE_SOURCE_DIR}/port/qemu_mps2/mbedtls_user_config.h\\\"")
endif()

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
# crypto_port.c keeps PSA operation structs inside opaque, 8-byte aligned
# buffers owned by the caller (no heap). That reinterpretation is not
# strict-aliasing clean, so this one file opts out.
set_source_files_properties(boot/crypto_port.c PROPERTIES COMPILE_OPTIONS -fno-strict-aliasing)

# --- Simulated HAL (RAM/file backed flash and OTP) ---------------------------
# Core models (no stdio, usable on a bare-metal target).
add_library(sb_hal_sim_core STATIC
  hal/flash_sim.c
  hal/otp_sim.c)
target_include_directories(sb_hal_sim_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_options(sb_hal_sim_core PRIVATE ${SB_WARNINGS})

# Host-only persistence on top of the models.
add_library(sb_hal_sim STATIC hal/sim_file.c)
target_link_libraries(sb_hal_sim PUBLIC sb_hal_sim_core)
target_compile_options(sb_hal_sim PRIVATE ${SB_WARNINGS})

if(SB_TARGET_QEMU)
  enable_testing()
  add_subdirectory(port/qemu_mps2)
endif()

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

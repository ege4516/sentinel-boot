if(NOT CMAKE_C_COMPILER_ID MATCHES "Clang")
  message(FATAL_ERROR "Fuzz targets need clang (libFuzzer). Use the host-fuzz preset.")
endif()

# Parser / verifier only: fast, pure C.
add_executable(fuzz_manifest fuzz_manifest.c)
target_link_libraries(fuzz_manifest PRIVATE sb_boot)
target_compile_options(fuzz_manifest PRIVATE ${SB_WARNINGS})
target_link_options(fuzz_manifest PRIVATE -fsanitize=fuzzer)

# Whole update path against a simulated device, with a security invariant.
add_executable(fuzz_update fuzz_update.cpp ${PROJECT_SOURCE_DIR}/tests/support/signer.cpp)
target_include_directories(fuzz_update PRIVATE ${PROJECT_SOURCE_DIR}/tests)
target_link_libraries(fuzz_update PRIVATE sb_boot sb_hal_sim mbedcrypto)
target_compile_options(fuzz_update PRIVATE -Wall -Wextra -Werror)
target_link_options(fuzz_update PRIVATE -fsanitize=fuzzer)

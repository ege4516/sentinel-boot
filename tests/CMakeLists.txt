set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
set(BUILD_GMOCK OFF CACHE BOOL "" FORCE)
FetchContent_Declare(
  googletest
  URL https://github.com/google/googletest/archive/refs/tags/v1.17.0.tar.gz
  URL_HASH SHA256=65fab701d9829d38cb77c14acdc431d2108bfdbf8979e40eb8ae567edf10b27c)
FetchContent_MakeAvailable(googletest)

add_executable(sb_tests
  support/signer.cpp
  unit/test_crypto.cpp
  unit/test_manifest.cpp
  unit/test_merkle.cpp
  unit/test_log.cpp
  unit/test_hal.cpp
  unit/test_boot.cpp
  unit/test_powerfail.cpp)
target_include_directories(sb_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(sb_tests PRIVATE sb_boot sb_hal_sim mbedcrypto GTest::gtest_main)
target_compile_options(sb_tests PRIVATE -Wall -Wextra -Werror)

include(GoogleTest)
gtest_discover_tests(sb_tests DISCOVERY_TIMEOUT 60)

# Cross-implementation check: packages produced by the Python signing tool
# must be accepted by the C bootloader (run through the simulator CLI).
find_package(Python3 COMPONENTS Interpreter)
if(Python3_FOUND AND SB_BUILD_TOOLS)
  add_test(NAME interop_python_signer
           COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/interop_test.py
                   --sim $<TARGET_FILE:sentinel-sim>
                   --signer ${PROJECT_SOURCE_DIR}/tools/sentinel_sign.py)
endif()

# Self-test firmware for QEMU mps2-an385 (Cortex-M3). Built only by the
# qemu-mps2 preset; see README.
find_package(Python3 REQUIRED COMPONENTS Interpreter)

set(SB_FIXTURES ${CMAKE_CURRENT_BINARY_DIR}/fixtures.h)
add_custom_command(
  OUTPUT ${SB_FIXTURES}
  COMMAND ${Python3_EXECUTABLE} ${PROJECT_SOURCE_DIR}/tools/gen_fixture.py ${SB_FIXTURES}
  DEPENDS ${PROJECT_SOURCE_DIR}/tools/gen_fixture.py ${PROJECT_SOURCE_DIR}/tools/sentinel_sign.py
  COMMENT "Generating test fixtures (fresh test keys)")

add_executable(sb_selftest startup.c demo_entropy.c selftest.c ${SB_FIXTURES})
target_include_directories(sb_selftest PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(sb_selftest PRIVATE sb_boot sb_hal_sim_core mbedcrypto)
target_compile_options(sb_selftest PRIVATE ${SB_WARNINGS})
target_link_options(sb_selftest PRIVATE
  -T${CMAKE_CURRENT_SOURCE_DIR}/link.ld -nostartfiles --specs=rdimon.specs
  -Wl,--gc-sections -Wl,--print-memory-usage
  -Wl,-Map=${CMAKE_CURRENT_BINARY_DIR}/sb_selftest.map)
set_target_properties(sb_selftest PROPERTIES SUFFIX ".elf"
  LINK_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/link.ld)

find_program(QEMU_ARM qemu-system-arm)
if(QEMU_ARM)
  set(SB_QEMU_ARGS ${QEMU_ARM} -M mps2-an385 -cpu cortex-m3 -nographic -monitor none
      -serial none -semihosting-config enable=on,target=native
      -kernel $<TARGET_FILE:sb_selftest>)
  add_test(NAME qemu_selftest COMMAND ${SB_QEMU_ARGS})
  set_tests_properties(qemu_selftest PROPERTIES TIMEOUT 600
    PASS_REGULAR_EXPRESSION "SELFTEST PASSED")
  add_custom_target(run-qemu COMMAND ${SB_QEMU_ARGS} DEPENDS sb_selftest USES_TERMINAL)
endif()

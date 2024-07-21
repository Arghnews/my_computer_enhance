install(
    TARGETS part_1_1_instruction_decode_x86_exe
    RUNTIME COMPONENT part_1_1_instruction_decode_x86_Runtime
)

if(PROJECT_IS_TOP_LEVEL)
  include(CPack)
endif()

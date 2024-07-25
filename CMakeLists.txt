cmake_minimum_required(VERSION 3.25)

include(cmake/install_vcpkg.cmake)

include(cmake/prelude.cmake)

project(
    part_1_1_instruction_decode_x86
    LANGUAGES CXX
)

include(cmake/project-is-top-level.cmake)
include(cmake/variables.cmake)

# ---- Declare executable ----

add_executable(part_1_1_instruction_decode_x86_exe source/main.cpp)
add_executable(part_1_1_instruction_decode_x86::exe ALIAS part_1_1_instruction_decode_x86_exe)

find_package(fmt CONFIG REQUIRED)
find_package(libassert REQUIRED)

set_property(TARGET part_1_1_instruction_decode_x86_exe PROPERTY OUTPUT_NAME part_1_1_instruction_decode_x86)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=undefined -Wall -Wextra -pedantic -g")
target_compile_features(part_1_1_instruction_decode_x86_exe PRIVATE cxx_std_20)
target_link_libraries(part_1_1_instruction_decode_x86_exe PRIVATE fmt::fmt libassert::assert)

add_custom_command(TARGET part_1_1_instruction_decode_x86_exe POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E create_symlink
        ${CMAKE_SOURCE_DIR}/x86_resources
        $<TARGET_FILE_DIR:part_1_1_instruction_decode_x86_exe>/x86_resources
        COMMAND ${CMAKE_SOURCE_DIR}/assemble_and_copy_nasms.sh ARGS ${CMAKE_SOURCE_DIR}/x86_resources
    )
#target_link_libraries(part_1_1_instruction_decode_x86_exe PRIVATE part_1_1_instruction_decode_x86_lib)

# ---- Install rules ----

if(NOT CMAKE_SKIP_INSTALL_RULES)
  include(cmake/install-rules.cmake)
endif()

# ---- Developer mode ----

if(NOT part_1_1_instruction_decode_x86_DEVELOPER_MODE)
  return()
elseif(NOT PROJECT_IS_TOP_LEVEL)
  message(
      AUTHOR_WARNING
      "Developer mode is intended for developers of part_1_1_instruction_decode_x86"
  )
endif()

include(cmake/dev-mode.cmake)

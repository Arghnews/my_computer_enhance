# Parent project does not export its library target, so this CML implicitly
# depends on being added from it, i.e. the testing is done only from the build
# tree and is not feasible from an install location

project(part_1_1_instruction_decode_x86Tests LANGUAGES CXX)

# ---- Tests ----

add_executable(part_1_1_instruction_decode_x86_test source/part_1_1_instruction_decode_x86_test.cpp)
target_link_libraries(part_1_1_instruction_decode_x86_test PRIVATE part_1_1_instruction_decode_x86_lib)
target_compile_features(part_1_1_instruction_decode_x86_test PRIVATE cxx_std_20)

add_test(NAME part_1_1_instruction_decode_x86_test COMMAND part_1_1_instruction_decode_x86_test)

# ---- End-of-file commands ----

add_folders(Test)

#include "lib.hpp"

auto main() -> int
{
  auto const lib = library {};

  return lib.name == "part_1_1_instruction_decode_x86" ? 0 : 1;
}

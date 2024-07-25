#include <array>
#include <bit>
#include <bitset>
#include <cassert>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iomanip>
#include <ios>
#include <iostream>
#include <map>
#include <optional>
#include <ranges>
#include <source_location>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <cxxopts.hpp>
#include <fmt/format.h>
#include <fmt/ranges.h>
#include <fmt/std.h>
#include <libassert/assert.hpp>

std::vector<uint8_t> read_file(const char *filename) {
  // open the file:
  DEBUG_ASSERT(std::filesystem::exists(filename));
  std::streampos file_size;
  std::ifstream file(filename, std::ios::binary);
  DEBUG_ASSERT(file);
  DEBUG_ASSERT(file);
  file.unsetf(std::ios::skipws);

  // get its size:
  file.seekg(0, std::ios::end);
  file_size = file.tellg();
  file.seekg(0, std::ios::beg);

  // read the data:
  std::vector<uint8_t> file_data(file_size);
  file.read(reinterpret_cast<char *>(file_data.data()), file_size);
  return file_data;
}

template <typename OutRange>
  requires std::ranges::output_range<OutRange, typename OutRange::value_type>
void write_file(const std::filesystem::path &filename, const OutRange &data) {
  std::ofstream file(filename, std::ios::trunc | std::ios::binary);
  file.write(reinterpret_cast<const char *>(data.data()), static_cast<std::streamsize>(data.size()));
}

std::string_view reg_field_to_reg_name(const bool w_bit, uint8_t reg_field) {
  DEBUG_ASSERT(reg_field < 0b1000, reg_field);
  reg_field |= w_bit << 3U;
  constexpr std::array<const char *, 16> values{
      "al", "cl", "dl", "bl", "ah", "ch", "dh", "bh", "ax", "cx", "dx", "bx", "sp", "bp", "si", "di",
  };
  return values[reg_field];
}

// Returns empty string for DIRECT_ADDRESS which caller must handle
std::string_view reg_or_rm_to_register_name(const uint8_t reg_byte, const bool direct_address) {
  DEBUG_ASSERT(reg_byte < 8);
  std::string_view reg;
  switch (reg_byte) {
  case 0: {
    reg = "bx + si";
    break;
  }
  case 1: {
    reg = "bx + di";
    break;
  }
  case 2: {
    reg = "bp + si";
    break;
  }
  case 3: {
    reg = "bp + di";
    break;
  }
  case 4: {
    reg = "si";
    break;
  }
  case 5: {
    reg = "di";
    break;
  }
  case 6: {
    reg = direct_address ? "" : "bp";
    break;
  } // DIRECT_ADDRESS
  case 7: {
    reg = "bx";
    break;
  }
  }
  return reg;
}

struct DecodeResult {
  std::span<const uint8_t> source;
  std::string result;
  size_t bytes_decoded{};
  std::source_location source_loc;
};
struct ProgramDecodeResult {
  std::vector<uint8_t> source_bytes;
  std::vector<DecodeResult> decode_results;
  std::vector<std::string> decode_results_lines;
};

struct Disassembler {
  struct ReturnInfo {
    std::string disassembly;
    std::source_location source_loc = std::source_location::current();
  };

  // MOV register/memory to/from register
  ReturnInfo process_mov_reg_reg(const std::span<const uint8_t> data, size_t &i) {
    DEBUG_ASSERT(!data.empty());
    const uint8_t val = data[0];
    if ((val >> 2U) != 0b100010) // MOV
    {
      return {""};
    }
    const bool d_bit = val & 0b00000010; // 0: source in REG, 1: dest in REG
    const bool w_bit = val & 0b00000001; // 0: byte, 1: word

    DEBUG_ASSERT(data.size() >= 1);
    const uint8_t val1 = data[1];
    const uint8_t mod_byte = val1 >> 6U;                // Size 2, reg mode/memory displacement length
    const uint8_t reg_byte = (val1 & 0b00111000) >> 3U; // Size 3, reg operand/extension of opcode
    const uint8_t rm_byte = val1 & 0b00000111;          // Size 3, reg operand/registers in ea calc
    DEBUG_ASSERT(mod_byte < 4);
    DEBUG_ASSERT(reg_byte < 8);
    DEBUG_ASSERT(rm_byte < 8);

    if (mod_byte == 0) {
      // mod_byte == 0 -> memory mode, operands in memory
      std::string_view reg0 = reg_field_to_reg_name(w_bit, reg_byte);
      std::string reg1 = fmt::format("[{}]", reg_or_rm_to_register_name(rm_byte, true));
      if (rm_byte == 6) // DIRECT_ADDRESS
      {
        const uint16_t val2 = data[3] << 8 | data[2];
        i += 4;
        return {d_bit ? fmt::format("MOV {}, [{}]", reg0, val2) : fmt::format("MOV [{}], {}", val2, reg0)};
      }
      i += 2;
      return {d_bit ? fmt::format("MOV {}, {}", reg0, reg1) : fmt::format("MOV {}, {}", reg1, reg0)};
    } else if (mod_byte == 1 || mod_byte == 2) // 1 -> 8 bit displacement, 2 -> 16 bit displacement
    {
      // Displacement being offset from address
      DEBUG_ASSERT(mod_byte == 1 && data.size() >= 3 || mod_byte == 2 && data.size() >= 4);
      const std::string_view reg0 = reg_field_to_reg_name(w_bit, reg_byte);

      const std::string_view reg1 = reg_or_rm_to_register_name(rm_byte, false);
      // If mod_byte == 1 (so just one data value) need to sign extend
      u_int16_t val2;
      if (mod_byte == 2) {
        val2 = data[3] << 8 | data[2];
      } else {
        // Sign extend if first bit is 1, then paste 1s into upper byte
        val2 = (data[2] & 0x80) ? 0xff00 | data[2] : data[2];
      }
      // Source address calc
      auto deref_expr =
          val2 != 0 ? fmt::format("[{} + {}]", reg1, static_cast<int16_t>(val2)) : fmt::format("[{}]", reg1);
      i += mod_byte == 1 ? 3 : 4;
      return {d_bit ? fmt::format("MOV {}, {}", reg0, deref_expr) : fmt::format("MOV {}, {}", deref_expr, reg0)};
    }

    // mod_byte == 11
    std::string_view reg0 = reg_field_to_reg_name(w_bit, reg_byte);
    std::string_view reg1 = reg_field_to_reg_name(w_bit, rm_byte);
    i += 2; // Consumed 2
    return {d_bit ? fmt::format("MOV {}, {}", reg0, reg1) : fmt::format("MOV {}, {}", reg1, reg0)};
  }

  // MOV immediate to register/memory
  ReturnInfo process_immediate_to_register_or_memory(const std::span<const uint8_t> data, size_t &i) {
    DEBUG_ASSERT(!data.empty());
    const uint8_t val = data[0];
    if ((val >> 1U) != 0b1100011) // MOV
    {
      return {""};
    }
    const bool w_bit = val & 1; // 0: byte, 1: word

    DEBUG_ASSERT(data.size() >= 1);
    const uint8_t val1 = data[1];
    const uint8_t mod_byte = val1 >> 6U; // Size 2, reg mode/memory displacement length
    // reg_byte is all zeroes
    const uint8_t rm_byte = val1 & 0b00000111; // Size 3, reg operand/registers in ea calc
    DEBUG_ASSERT(mod_byte < 4);
    DEBUG_ASSERT(rm_byte < 8);

    if (mod_byte == 0) {
      // mod_byte == 0 -> memory mode, operands in memory
      const std::string_view reg = reg_or_rm_to_register_name(rm_byte, true);
      DEBUG_ASSERT(data.size() >= 3);
      if (rm_byte == 6) // DIRECT_ADDRESS
      {
        DEBUG_ASSERT(data.size() >= 4);
        const uint16_t direct_address = data[3] << 8 | data[2];
        const uint16_t val2 = w_bit ? data[5] << 8 | data[4] : data[4];
        DEBUG_ASSERT(0, "Unimplemented/untested");
      }
      uint16_t val2 = w_bit ? data[3] << 8 | data[2] : data[2];
      i += 3 + w_bit;
      return {fmt::format("MOV [{}], {} {}", reg, w_bit ? "word" : "byte", val2)};
    }

    if (mod_byte == 0b10) {
      // mod_byte == 0 -> memory mode, operands in memory
      const std::string_view reg = reg_or_rm_to_register_name(rm_byte, false);
      DEBUG_ASSERT(data.size() >= 6);
      const uint16_t displacement = data[3] << 8 | data[2];
      const uint16_t data_val = data[5] << 8 | data[4];
      i += 6;
      return {fmt::format("MOV [{} + {}], {} {}", reg, displacement, "word", data_val)};
    }

    if (mod_byte == 0b11) {
      // We can use same table
      reg_field_to_reg_name(w_bit, mod_byte);
      DEBUG_ASSERT(0, "unimplemented");
      return {};
    }

    DEBUG_ASSERT(0, "unimplemented");
    return {};
  }

  // MOV Immediate to register
  ReturnInfo process_immediate_to_register(const std::span<const uint8_t> data, size_t &i) {
    DEBUG_ASSERT(!data.empty());
    const uint8_t val = data[0];
    if ((val >> 4U) != 0b1011) {
      return {""};
    }
    const bool w_bit = val & 0b0000'1000;         // 0: byte, 1: word
    const uint8_t reg_byte = (val & 0b0000'0111); // Size 3, reg operand/extension of opcode
    DEBUG_ASSERT(data.size() >= 1);
    const uint8_t data0 = data[1];
    const auto reg_name = reg_field_to_reg_name(w_bit, reg_byte);
    if (!w_bit) {
      i += 2;
      return {fmt::format("MOV {}, {}", reg_name, static_cast<int8_t>(data0))};
    }
    DEBUG_ASSERT(data.size() >= 2);
    const uint8_t data1 = data[2];
    uint16_t data_full = data1 << 8 | data0;
    i += 3;
    return {fmt::format("MOV {}, {}", reg_name, static_cast<int16_t>(data_full))};
  }

  // MOV memory to accumulator
  ReturnInfo process_memory_to_accumulator(const std::span<const uint8_t> data, size_t &i) {
    DEBUG_ASSERT(!data.empty());
    const uint8_t val = data[0];
    if ((val >> 1U) != 0b1010000) {
      return {""};
    }
    const bool w_bit = val & 1; // 0: byte, 1: word
    DEBUG_ASSERT(w_bit ? data.size() >= 2 : data.size() >= 3);
    const uint16_t addr = (w_bit ? data[2] << 8 : 0) | data[1];
    i += 2 + w_bit;
    return {fmt::format("MOV ax, [{}]", static_cast<int16_t>(addr))};
  }

  // MOV accumulator to memory
  ReturnInfo process_accumulator_to_memory(const std::span<const uint8_t> data, size_t &i) {
    DEBUG_ASSERT(!data.empty());
    const uint8_t val = data[0];
    if ((val >> 1U) != 0b1010001) {
      return {""};
    }
    const bool w_bit = val & 1; // 0: byte, 1: word
    DEBUG_ASSERT(w_bit ? data.size() >= 2 : data.size() >= 3);
    const uint16_t addr = (w_bit ? data[2] << 8 : 0) | data[1];
    i += 2 + w_bit;
    return {fmt::format("MOV [{}], ax", static_cast<int16_t>(addr))};
  }

  template <class T> DecodeResult do_worker_functions(T &&functions, std::span<const uint8_t> data, size_t &i) {
    DecodeResult output{};
    for (auto &&f : functions) {
      const size_t i_before = i;
      ReturnInfo out = std::invoke(f, this, data, i);
      if (!out.disassembly.empty()) {
        output.result = out.disassembly;
        output.source_loc = out.source_loc;
        output.bytes_decoded = i - i_before;
        output.source = data.subspan(i_before, output.bytes_decoded);
        break;
      }
    }
    return output;
  }

  ProgramDecodeResult process(const std::span<const uint8_t> full_data_in, const bool debugging) {
    ProgramDecodeResult program_result;
    std::copy(full_data_in.begin(), full_data_in.end(), std::back_inserter(program_result.source_bytes));
    const std::span<const uint8_t> full_data = program_result.source_bytes;

    for (size_t i = 0; i < full_data.size();) {
      auto data = std::span<const uint8_t>{full_data.begin() + static_cast<ptrdiff_t>(i), full_data.end()};
      const size_t i_before = i;
      auto arr = std::array{&Disassembler::process_mov_reg_reg, &Disassembler::process_immediate_to_register,
                            &Disassembler::process_memory_to_accumulator, &Disassembler::process_accumulator_to_memory,
                            &Disassembler::process_immediate_to_register_or_memory};
      const DecodeResult result = do_worker_functions(arr, data, i);
      const auto &output = result.result;
      const size_t bytes_consumed = i - i_before;
      if (output.empty()) {
        const size_t bytes_not_consumed = std::min(size_t{10}, full_data.size() - i);
        //            fmt::println("bac {} {} {}", i, bytes_not_consumed,
        //            full_data.size() );
        const auto next_bytes = full_data.subspan(i, bytes_not_consumed);
        DEBUG_ASSERT(!output.empty(), fmt::format("Unhandled/unknown instruction: Index: {}, "
                                                  "full_size: {}, {::#010b}",
                                                  i, full_data.size(), next_bytes));
      }
      if (debugging) {
        fmt::println("Consumed {}bytes, {::#010b}, i:[{},{})", bytes_consumed,
                     full_data.subspan(i_before, bytes_consumed), i_before, i);
      }
      fmt::println("{}", output);
      program_result.decode_results.push_back(result);
      DEBUG_ASSERT(output.size() && bytes_consumed > 0, "Did you forget to increment i or output something");
    }
    for (const auto &r : program_result.decode_results) {
      program_result.decode_results_lines.push_back(r.result);
    }
    return program_result;
  }
};

std::string join_with_newlines(const std::vector<std::string> &v) {
  std::string s;
  for (const auto &e : v) {
    s.append(e);
    s.append("\n");
  }
  return s;
}

std::vector<std::filesystem::path> get_asm_files(const std::filesystem::path &resources_dir) {
  namespace fs = std::filesystem;
  DEBUG_ASSERT(fs::exists(resources_dir));
  std::vector<fs::path> paths;
  for (const auto &entry : fs::directory_iterator(resources_dir)) {
    paths.push_back(entry);
  }
  std::sort(paths.begin(), paths.end());
  std::vector<fs::path> asm_files;
  size_t path_count = 0;
  for (const auto &path : paths) {
    // Expect filename and filename.asm
    if (path.string().ends_with(".asm")) {
      auto p = path.string();
      p.erase(p.size() - 4);
      DEBUG_ASSERT(fs::exists(p), fmt::format("Could not find binary for asm file: {}", path.string()));
      asm_files.emplace_back(path);
      ++path_count;
    } else if (!path.string().ends_with(".swp")) {
      ++path_count;
    }
  }
  DEBUG_ASSERT(path_count == asm_files.size() * 2, fmt::format("paths: {}, asm_files: {}", paths, asm_files));
  return asm_files;
}

auto main(int argc, char **argv) -> int {
  cxxopts::Options options("MyProgram", "One line description of MyProgram");
  options.add_options()("v,verbose", "Enable debugging output",
                        cxxopts::value<bool>()->default_value("false")) // a bool parameter
      ("file", "File", cxxopts::value<std::string>())("test-mode", "Test mode, expects x86_resources folder",
                                                      cxxopts::value<std::string>())
      //      ("i,integer", "Int param", cxxopts::value<int>())
      //      ("f,file", "File name", cxxopts::value<std::string>())
      //      ("v,verbose", "Verbose output",
      //      cxxopts::value<bool>()->default_value("false"))
      ;
  options.parse_positional({"file"});
  auto result = options.parse(argc, argv);
  bool debugging = result["verbose"].as<bool>();
  if (debugging) {
    fmt::println("Output enabled");
  }
  std::string file;
  bool test_mode = result.count("test_mode");
  if (result.count("file")) {
    file = result["file"].as<std::string>();
  } else {
    debugging = true;
    //        file = "x86_resources/listing_0039_more_movs";
    file = "x86_resources/listing_0040_challenge_movs";
    test_mode = true;
  }

  std::vector<uint8_t> full_data = read_file(file.data());
  Disassembler disassembler{};

  //    if (debugging) {
  //        for (size_t i = 0; i < full_data.size(); i += 6) {
  //            const size_t length = std::min(size_t{6}, full_data.size() - i);
  //            const auto data = std::span<const uint8_t>{full_data.begin() +
  //            static_cast<ptrdiff_t>(i), length}; fmt::println("{::#010b},
  //            i:{} -> {}", data, i, i + length);
  //        }
  //    }

  if (test_mode) {
    namespace fs = std::filesystem;
    const fs::path resources_dir = "x86_resources";
    fmt::println("Test mode, running tests in {}", fs::canonical(resources_dir).string());
    std::vector<fs::path> asm_files = get_asm_files(resources_dir);
    fmt::println("Current working dir: {}", fs::current_path().string());
    for (const std::string asm_file : asm_files) {
      fmt::println("\nasm_file: {}", asm_file);
      const auto binary_file_path = asm_file.substr(0, asm_file.size() - 4);
      fmt::println("binary_file_path: {}", binary_file_path);
      // Read in the test binary file
      const std::vector<uint8_t> binary_data = read_file(binary_file_path.data());
      // Run this x86 disassembler on it
      const ProgramDecodeResult program_decode_result = disassembler.process(binary_data, debugging);
      const std::vector<std::string> output_lines = program_decode_result.decode_results_lines;
      fmt::println("Output_lines: {}", output_lines);
      // Write our output to a file
      const auto my_asm_data = join_with_newlines(output_lines);
      const auto my_asm_filename = "my_asm_data.asm";
      write_file(my_asm_filename, my_asm_data);
      // Assemble my_asm_data
      const auto cmd = fmt::format("nasm {} -o nasm_test.out", my_asm_filename);
      // Check the written file matches the original input
      const auto ret = std::system(cmd.data());
      DEBUG_ASSERT(ret == 0);
      // Read in nasm_test.out
      const auto my_assembled_result = read_file("nasm_test.out");
      // Diff the result of assembling using this program vs the correct
      // binary_data
      if (binary_data != my_assembled_result) {
        size_t offset = 0;
        const std::span<const uint8_t> binary_data_span = binary_data;
        const std::span<const uint8_t> my_binary_data_span = my_assembled_result;
        fmt::println("ERROR, difference in binary data of size {} vs my binary "
                     "data of size {}, file: {}",
                     binary_data_span.size(), my_binary_data_span.size(), asm_file);
        for (const DecodeResult &decode_result : program_decode_result.decode_results) {
          std::span<const uint8_t> correct_binary = binary_data_span.subspan(offset, decode_result.bytes_decoded);
          std::span<const uint8_t> my_binary = my_binary_data_span.subspan(offset, decode_result.bytes_decoded);
          if (!std::equal(correct_binary.begin(), correct_binary.end(), my_binary.begin(), my_binary.end())) {
            // fmt::println("Consumed {}bytes, {::#010b}, i:[{},{})",
            // bytes_consumed, full_data.subspan(i_before, bytes_consumed),
            // i_before, i);
            fmt::println("Expected {::#010b}", correct_binary);
            fmt::println("Got      {::#010b}", my_binary);
            fmt::println("Decode output: {}", decode_result.result);
            fmt::println("At {}, decoded {}bytes", offset, decode_result.bytes_decoded);
            fmt::println("At location: {}", decode_result.source_loc);
            DEBUG_ASSERT(0, "failed");
          }
          offset += decode_result.bytes_decoded;
        }
      }
      DEBUG_ASSERT(binary_data == my_assembled_result,
                   fmt::format("Error, non matching assembled result for {}", asm_file));
    }
  }
}
#include <iostream>
#include <array>
#include <fstream>
#include <bitset>
#include <bit>
#include <ios>
#include <iomanip>
#include <string>
#include <span>
#include <vector>
#include <cassert>
#include <string_view>
#include <iostream>
#include <optional>

#include <fmt/format.h>
#include <fmt/ranges.h>
#include <libassert/assert.hpp>
#include <cxxopts.hpp>

std::vector<uint8_t> read_file(const char* filename)
{
    // open the file:
    std::streampos file_size;
    std::ifstream file(filename, std::ios::binary);
    DEBUG_ASSERT(file);
    file.unsetf(std::ios::skipws);

    // get its size:
    file.seekg(0, std::ios::end);
    file_size = file.tellg();
//  std::cout << file_size << "\n";
    file.seekg(0, std::ios::beg);

    // read the data:
    std::vector<uint8_t> file_data(file_size);
    file.read(reinterpret_cast<char*>(file_data.data()), file_size);
    return file_data;
}

std::string_view reg_field_to_reg_name(const bool w_bit, uint8_t reg_field)
{
    DEBUG_ASSERT(reg_field < 0b1000, reg_field);
    reg_field |= w_bit << 3U;
    constexpr std::array<const char*,16> values{
            "al", "cl", "dl", "bl", "ah", "ch", "dh", "bh",
            "ax", "cx", "dx", "bx", "sp", "bp", "si", "di",
    };
    return values[reg_field];
}

// Returns empty string for DIRECT_ADDRESS which caller must handle
std::string_view reg_or_rm_to_register_name(const uint8_t reg_byte, const bool direct_address)
{
    DEBUG_ASSERT(reg_byte < 8);
    std::string_view reg;
    switch (reg_byte)
    {
        case 0: { reg = "bx + si"; break; }
        case 1: { reg = "bx + di"; break; }
        case 2: { reg = "bp + si"; break; }
        case 3: { reg = "bp + di"; break; }
        case 4: { reg = "si"; break; }
        case 5: { reg = "di"; break; }
        case 6: { reg = direct_address ? "" : "bp"; break; } // DIRECT_ADDRESS
        case 7: { reg = "bx"; break; }
    }
    return reg;
}

// MOV register/memory to/from register
std::string process_mov_reg_reg(const std::span<uint8_t> data, size_t& i)
{
    DEBUG_ASSERT(!data.empty());
    const uint8_t val = data[0];
    if ( (val >> 2U) != 0b100010 ) // MOV
    {
        return "";
    }
    const bool d_bit = val & 0b00000010; // 0: source in REG, 1: dest in REG
    const bool w_bit = val & 0b00000001; // 0: byte, 1: word

    DEBUG_ASSERT(data.size() >= 1);
    const uint8_t val1 = data[1];
    const uint8_t mod_byte = val1 >> 6U; // Size 2, reg mode/memory displacement length
    const uint8_t reg_byte = (val1 & 0b00111000) >> 3U; // Size 3, reg operand/extension of opcode
    const uint8_t rm_byte = val1 & 0b00000111; // Size 3, reg operand/registers in ea calc
    DEBUG_ASSERT(mod_byte < 4);
    DEBUG_ASSERT(reg_byte < 8);
    DEBUG_ASSERT(rm_byte < 8);

    if (mod_byte == 0)
    {
        // mod_byte == 0 -> memory mode, operands in memory
        std::string_view reg0 = reg_field_to_reg_name(w_bit, reg_byte);
        std::string reg1 = fmt::format("[{}]", reg_or_rm_to_register_name(rm_byte, true));
        if ( rm_byte == 6 ) // DIRECT_ADDRESS
        {
            const uint16_t val2 = data[3] << 8 | data[2];
            i += 4;
            return d_bit ? fmt::format("MOV {}, [{}]", reg0, val2) : fmt::format("MOV [{}], {}", val2, reg0);
        }
        i += 2;
        return d_bit ? fmt::format("MOV {}, {}", reg1, reg0) : fmt::format("MOV {}, {}", reg0, reg1);
    }
    else if (mod_byte == 1 || mod_byte == 2) // 1 -> 8 bit displacement, 2 -> 16 bit displacement
    {
        // Displacement being offset from address
        DEBUG_ASSERT(mod_byte == 1 && data.size() >= 3 || mod_byte == 2 && data.size() >= 4);
        const std::string_view reg0 = reg_field_to_reg_name(w_bit, reg_byte);
        const std::string_view reg1 = reg_or_rm_to_register_name(rm_byte, false);
        // If mod_byte == 1 (so just one data value) need to sign extend
        u_int16_t val2;
        if ( mod_byte == 2) {
            val2 = data[3] << 8 | data[2];
        }
        else
        {
            // Sign extend if first bit is 1, then paste 1s into upper byte
            val2 = (data[2] & 0x80) ? 0xff00 | data[2] : data[2];
        }
        // Source address calc
        auto deref_expr = val2 != 0 ? fmt::format("[{} + {}]", reg1, static_cast<int16_t>(val2)) : fmt::format("[{}]", reg1);
        i += mod_byte == 1 ? 3 : 4;
        return d_bit ? fmt::format("MOV {}, {}", reg0, deref_expr) : fmt::format("MOV {}, {}", deref_expr, reg0);
    }

    // mod_byte == 11
    std::string_view reg0 = reg_field_to_reg_name(w_bit, reg_byte);
    std::string_view reg1 = reg_field_to_reg_name(w_bit, rm_byte);
    i += 2; // Consumed 2
    return d_bit ? fmt::format("MOV {}, {}", reg0, reg1) : fmt::format("MOV {}, {}", reg1, reg0);
}

// MOV immediate to register/memory
std::string process_immediate_to_register_or_memory(const std::span<uint8_t> data, size_t& i)
{
    DEBUG_ASSERT(!data.empty());
    const uint8_t val = data[0];
    if ((val >> 1U) != 0b1100011) // MOV
    {
        return "";
    }
    const bool w_bit = val & 1; // 0: byte, 1: word

    DEBUG_ASSERT(data.size() >= 1);
    const uint8_t val1 = data[1];
    const uint8_t mod_byte = val1 >> 6U; // Size 2, reg mode/memory displacement length
    // reg_byte is all zeroes
    const uint8_t rm_byte = val1 & 0b00000111; // Size 3, reg operand/registers in ea calc
    DEBUG_ASSERT(mod_byte < 4);
    DEBUG_ASSERT(rm_byte < 8);

    if (mod_byte == 0)
    {
        // mod_byte == 0 -> memory mode, operands in memory
        const std::string_view reg = reg_or_rm_to_register_name(rm_byte, true);
        DEBUG_ASSERT(data.size() >= 3);
        if ( rm_byte == 6 ) // DIRECT_ADDRESS
        {
            DEBUG_ASSERT(data.size() >= 4);
            const uint16_t direct_address = data[3] << 8 | data[2];
            const uint16_t val2 = w_bit ? data[5] << 8 | data[4] : data[4];
            DEBUG_ASSERT(0, "Unimplemented/untested");
        }
        uint16_t val2 = w_bit ? data[3] << 8 | data[2] : data[2];
        i += 3 + w_bit;
        return fmt::format("MOV [{}], {} {}", reg, w_bit ? "word" : "byte", val2);
    }

    if (mod_byte == 0b10)
    {
        // mod_byte == 0 -> memory mode, operands in memory
        const std::string_view reg = reg_or_rm_to_register_name(rm_byte, false);
        DEBUG_ASSERT(data.size() >= 6);
        const uint16_t displacement = data[3] << 8 | data[2];
        const uint16_t data_val = data[5] << 8 | data[4];
        i += 6;
        return fmt::format("MOV [{} + {}], {} {}", reg, displacement, "word", data_val);
    }

    if (mod_byte == 0b11)
    {
        // We can use same table
        reg_field_to_reg_name(w_bit, mod_byte);
        DEBUG_ASSERT(0, "unimplemented");
        return {};
    }

    return {};
}

// MOV Immediate to register
std::string process_immediate_to_register(const std::span<uint8_t> data, size_t& i)
{
    DEBUG_ASSERT(!data.empty());
    const uint8_t val = data[0];
    if ( (val >> 4U) != 0b1011 ) { return ""; }
    const bool w_bit = val & 0b0000'1000; // 0: byte, 1: word
    const uint8_t reg_byte = (val & 0b0000'0111); // Size 3, reg operand/extension of opcode
    DEBUG_ASSERT(data.size() >= 1);
    const uint8_t data0 = data[1];
    const auto reg_name = reg_field_to_reg_name(w_bit, reg_byte);
    if (!w_bit)
    {
        i += 2;
        return fmt::format("MOV {}, {}", reg_name, static_cast<int8_t>(data0));
    }
    DEBUG_ASSERT(data.size() >= 2);
    const uint8_t data1 = data[2];
    uint16_t data_full = data1 << 8 | data0;
    i += 3;
    return fmt::format("MOV {}, {}", reg_name, static_cast<int16_t>(data_full));
}

// MOV memory to accumulator
std::string process_memory_to_accumulator(const std::span<uint8_t> data, size_t& i)
{
    DEBUG_ASSERT(!data.empty());
    const uint8_t val = data[0];
    if ( (val >> 1U) != 0b1010000 ) { return ""; }
    const bool w_bit = val & 1; // 0: byte, 1: word
    DEBUG_ASSERT(w_bit ? data.size() >= 2 : data.size() >= 3 );
    const uint16_t addr = (w_bit ? data[2] << 8 : 0) | data[1];
    i += 2 + w_bit;
    return fmt::format("MOV ax, [{}]", static_cast<int16_t>(addr));
}

// MOV accumulator to memory
std::string process_accumulator_to_memory(const std::span<uint8_t> data, size_t& i)
{
    DEBUG_ASSERT(!data.empty());
    const uint8_t val = data[0];
    if ( (val >> 1U) != 0b1010001 ) { return ""; }
    const bool w_bit = val & 1; // 0: byte, 1: word
    DEBUG_ASSERT(w_bit ? data.size() >= 2 : data.size() >= 3 );
    const uint16_t addr = (w_bit ? data[2] << 8 : 0) | data[1];
    i += 2 + w_bit;
    return fmt::format("MOV [{}], ax", static_cast<int16_t>(addr));
}

template<class T>
std::string do_worker_functions(T&& functions, std::span<uint8_t> data, size_t& i)
{
    std::string output;
    for (auto&& f : functions)
    {
        output = f(data, i);
        if (!output.empty()) break;
    }
    return output;
}

auto main(int argc, char** argv) -> int
{
    cxxopts::Options options("MyProgram", "One line description of MyProgram");
    options.add_options()
            ("v,verbose", "Enable debugging output", cxxopts::value<bool>()->default_value("false")) // a bool parameter
            ("file", "File", cxxopts::value<std::string>())
//      ("i,integer", "Int param", cxxopts::value<int>())
//      ("f,file", "File name", cxxopts::value<std::string>())
//      ("v,verbose", "Verbose output", cxxopts::value<bool>()->default_value("false"))
            ;
    options.parse_positional({"file"});
    auto result = options.parse(argc, argv);
    bool debugging = result["verbose"].as<bool>();
    if (debugging) {
        fmt::println("Output enabled");
    }
    std::string file;
    if ( result.count("file") )
    {
        file = result["file"].as<std::string>();
    } else
    {
        debugging = true;
//        file = "x86_resources/listing_0039_more_movs";
        file = "x86_resources/listing_0040_challenge_movs";
    }

    std::vector<uint8_t> full_data = read_file(file.data());

    if (debugging) {
        for (size_t i = 0; i < full_data.size(); i += 6) {
            const size_t length = std::min(size_t{6}, full_data.size() - i);
            const auto data = std::span<uint8_t>{full_data.begin() + static_cast<ptrdiff_t>(i), length};
            fmt::println("{::#010b}, i:{} -> {}", data, i, i + length);
        }
    }

    const std::span<uint8_t> full_data_span{full_data};
    for (size_t i = 0; i < full_data.size(); )
    {
        auto data = std::span<uint8_t>{full_data.begin() + static_cast<ptrdiff_t>(i), full_data.end()};
        const size_t i_before = i;
//        using F = std::add_pointer_t<decltype(process_mov_reg_reg)>;
        auto arr = std::array{ process_mov_reg_reg, process_immediate_to_register, process_memory_to_accumulator,
                               process_accumulator_to_memory, process_immediate_to_register_or_memory };
        const std::string output = do_worker_functions(arr, data, i);
        const size_t bytes_consumed = i - i_before;
        if (output.empty())
        {
            const size_t bytes_not_consumed = std::min(size_t{10}, full_data.size() - i);
//            fmt::println("bac {} {} {}", i, bytes_not_consumed, full_data.size() );
            const auto next_bytes = full_data_span.subspan(i, bytes_not_consumed);
            DEBUG_ASSERT(!output.empty(), fmt::format("Index: {}, full_size: {}, {::#b}", i, full_data.size(), next_bytes));
        }
        if (debugging) {
            fmt::println("Consumed {}bytes, {::#010b}, i:[{},{})", bytes_consumed, full_data_span.subspan(i_before, bytes_consumed), i_before, i);
        }
        fmt::println("{}", output);
        DEBUG_ASSERT(output.size() && bytes_consumed > 0, "Did you forget to increment i or output something");
    }
}

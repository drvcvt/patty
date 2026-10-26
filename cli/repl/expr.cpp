#include "expr.h"

#include <cctype>
#include <charconv>
#include <cstdio>
#include <string>

namespace patty::cli {

namespace {

class Parser {
public:
    Parser(std::string_view text, const ExprContext& context) : m_text(text), m_context(context) {}

    uint64_t parse() {
        const uint64_t value = sum();
        skip_space();
        if (m_pos != m_text.size())
            fail("unexpected '" + std::string(1, m_text[m_pos]) + "'");
        return value;
    }

private:
    uint64_t sum() {
        uint64_t value = product();
        while (true) {
            if (accept('+'))
                value += product();
            else if (accept('-'))
                value -= product();
            else
                return value;
        }
    }

    uint64_t product() {
        uint64_t value = unary();
        while (true) {
            if (accept('*')) {
                value *= unary();
            } else if (accept('/')) {
                const uint64_t divisor = unary();
                if (divisor == 0)
                    fail("division by zero");
                value /= divisor;
            } else {
                return value;
            }
        }
    }

    uint64_t unary() {
        if (accept('-'))
            return uint64_t{0} - unary();
        return primary();
    }

    uint64_t primary() {
        skip_space();
        if (m_pos >= m_text.size())
            fail("expression ends too early");
        const char c = m_text[m_pos];

        if (accept('(')) {
            const uint64_t value = sum();
            expect(')');
            return value;
        }
        if (accept('[')) {
            const size_t at = m_pos;
            const uint64_t address = sum();
            expect(']');
            if (!m_context.target)
                fail("no target to read from", at);
            const auto pointer = m_context.target->read_pointer(static_cast<uintptr_t>(address));
            if (!pointer)
                fail("cannot read a pointer at " + hex(address), at);
            return *pointer;
        }
        if (c == '$')
            return history();
        if (std::isdigit(static_cast<unsigned char>(c)))
            return number();
        const size_t start = m_pos;
        if (c == '\'' || c == '"')
            return module(quoted(), start);
        if (std::isalpha(static_cast<unsigned char>(c)) || c == '_')
            return module(identifier(), start);
        fail("unexpected '" + std::string(1, c) + "'");
    }

    uint64_t number() {
        const size_t start = m_pos;
        int base = 10;
        if (m_text.substr(m_pos, 2) == "0x" || m_text.substr(m_pos, 2) == "0X") {
            base = 16;
            m_pos += 2;
        }
        uint64_t value = 0;
        const auto [end, error] = std::from_chars(m_text.data() + m_pos, m_text.data() + m_text.size(), value, base);
        if (error != std::errc() || end == m_text.data() + m_pos)
            fail("bad number", start);
        m_pos = static_cast<size_t>(end - m_text.data());
        if (m_pos < m_text.size() && std::isalnum(static_cast<unsigned char>(m_text[m_pos])))
            fail(base == 10 ? "bad number (hex needs 0x)" : "bad hex number", start);
        return value;
    }

    uint64_t history() {
        const size_t start = m_pos++;
        size_t index = 0;
        bool digits = false;
        while (m_pos < m_text.size() && std::isdigit(static_cast<unsigned char>(m_text[m_pos]))) {
            index = index * 10 + static_cast<size_t>(m_text[m_pos++] - '0');
            digits = true;
        }
        const auto& values = m_context.values;
        if (values.empty())
            fail("no values yet ($ refers to printed results)", start);
        if (!digits)
            return values.back();
        if (index == 0 || index > values.size())
            fail("$" + std::to_string(index) + " does not exist (have $1..$" + std::to_string(values.size()) + ")",
                 start);
        return values[index - 1];
    }

    std::string identifier() {
        const size_t start = m_pos;
        while (m_pos < m_text.size() &&
               (std::isalnum(static_cast<unsigned char>(m_text[m_pos])) || m_text[m_pos] == '_' ||
                m_text[m_pos] == '.'))
            ++m_pos;
        return std::string(m_text.substr(start, m_pos - start));
    }

    std::string quoted() {
        const char quote = m_text[m_pos++];
        const size_t start = m_pos;
        const auto end = m_text.find(quote, m_pos);
        if (end == std::string_view::npos)
            fail("missing closing quote", start - 1);
        m_pos = end + 1;
        return std::string(m_text.substr(start, end - start));
    }

    uint64_t module(const std::string& name, size_t at) {
        if (!m_context.target)
            fail("no target, so no module \"" + name + "\"", at);
        const auto module = m_context.target->module(name);
        if (!module) {
            std::string message = "no module named \"" + name + "\"";
            if (name.find_first_not_of("0123456789abcdefABCDEF") == std::string::npos)
                message += " (hex numbers need 0x)";
            fail(message, at);
        }
        return module->base;
    }

    void skip_space() {
        while (m_pos < m_text.size() && std::isspace(static_cast<unsigned char>(m_text[m_pos])))
            ++m_pos;
    }

    bool accept(char c) {
        skip_space();
        if (m_pos < m_text.size() && m_text[m_pos] == c) {
            ++m_pos;
            return true;
        }
        return false;
    }

    void expect(char c) {
        if (!accept(c))
            fail(std::string("expected '") + c + "'");
    }

    static std::string hex(uint64_t value) {
        char buffer[24];
        std::snprintf(buffer, sizeof(buffer), "0x%llX", static_cast<unsigned long long>(value));
        return buffer;
    }

    [[noreturn]] void fail(const std::string& message) { fail(message, m_pos); }
    [[noreturn]] void fail(const std::string& message, size_t at) {
        throw Error(message + " at column " + std::to_string(at + 1) + " of \"" + std::string(m_text) + "\"");
    }

    std::string_view m_text;
    const ExprContext& m_context;
    size_t m_pos = 0;
};

} // namespace

uint64_t evaluate(std::string_view text, const ExprContext& context) {
    return Parser(text, context).parse();
}

} // namespace patty::cli

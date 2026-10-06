#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <stdexcept>
#include <cstdint>
namespace nae {
struct Error : std::runtime_error {
    DWORD code;
    explicit Error(const std::string& message, DWORD value = ERROR_INVALID_PARAMETER) : std::runtime_error(message), code(value) {}
};
struct Handle {
    HANDLE value = INVALID_HANDLE_VALUE;
    explicit Handle(HANDLE h = INVALID_HANDLE_VALUE) : value(h) {}
    ~Handle() { if (value != INVALID_HANDLE_VALUE && value != nullptr) CloseHandle(value); }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
};
struct Local {
    void* value = nullptr;
    ~Local() { if (value) LocalFree(value); }
    Local() = default;
    Local(const Local&) = delete;
    Local& operator=(const Local&) = delete;
};
struct Ace {
    unsigned index = 0, type = 0, flags = 0;
    DWORD mask = 0, mapped = 0;
    std::string kind, sid, relevance;
    bool supported = false, mask_known = false;
};
struct Report {
    std::string target, object_type, owner, group, principal, context, token_integrity;
    std::string dacl_state, integrity_status;
    bool protected_dacl = false, authoritative = false, token_elevated = false;
    DWORD granted = 0, authz_error = 0;
    std::vector<Ace> aces, integrity_aces;
    std::vector<std::string> warnings, limitations, findings;
};
std::string utf8(const std::wstring& text);
std::string sid_text(PSID sid);
DWORD mapped_mask(DWORD mask);
std::vector<std::string> rights(DWORD mask, bool directory);
std::string hex(DWORD value);
std::string quote(const std::string& value);
// Input must be a bounded self-relative descriptor, never an absolute descriptor.
Report describe(const std::vector<unsigned char>& descriptor, bool directory, PSID explicit_sid = nullptr);
Report inspect(const std::wstring& path, const std::wstring& principal = L"");
std::string json(const Report& report);
std::string human(const Report& report);
}

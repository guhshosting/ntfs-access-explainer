#include "core.hpp"
#include <sddl.h>
#include <aclapi.h>
#include <winioctl.h>
#include <filesystem>
#include <iostream>
#include <fstream>
#include <functional>
#include <cstring>
#include <cstdio>
#include <memory>
namespace {
int checks = 0;
void require(bool value, const char* message) { ++checks; if (!value) throw std::runtime_error(message); }
std::vector<unsigned char> descriptor(const wchar_t* sddl) {
    nae::Local sd; ULONG size = 0;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &sd.value, &size)) throw nae::Error("Test SDDL", GetLastError());
    auto* p = static_cast<unsigned char*>(sd.value); return {p, p + size};
}
void rejects(const std::function<void()>& f, DWORD expected = 0) {
    try { f(); } catch (const nae::Error& e) { require(!expected || e.code == expected, "unexpected error code"); return; }
    throw std::runtime_error("Expected failure");
}
struct Fixture {
    std::filesystem::path root;
    Fixture() : root(std::filesystem::current_path() / (L"nae-tests-" + std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(GetTickCount64()))) {
        if (!std::filesystem::create_directory(root)) throw std::runtime_error("Fixture creation");
    }
    ~Fixture() { try { std::error_code ignored; std::filesystem::remove_all(root, ignored); } catch (...) { std::fputs("Fixture cleanup failed during unwinding\n", stderr); } }
    void clean() { std::filesystem::remove_all(root); require(!std::filesystem::exists(root), "fixture cleanup"); }
};
struct RestoreDacl {
    nae::Handle handle;
    std::vector<unsigned char> sd;
    explicit RestoreDacl(const std::filesystem::path& file) : handle(CreateFileW(file.c_str(), READ_CONTROL | WRITE_DAC, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, 0, nullptr)), sd(descriptor(L"D:P(A;;FA;;;WD)")) {
        require(handle.value != INVALID_HANDLE_VALUE, "fixture restoration handle");
    }
    DWORD restore() {
        BOOL present = FALSE, defaulted = FALSE; PACL acl = nullptr;
        if (!GetSecurityDescriptorDacl(sd.data(), &present, &acl, &defaulted)) return GetLastError();
        return SetSecurityInfo(handle.value, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, nullptr, nullptr, acl, nullptr);
    }
    ~RestoreDacl() { restore(); }
};
std::filesystem::path junction_fixture(const Fixture& fixture, const std::filesystem::path& target) {
    const auto link = fixture.root / L"junction";
    std::filesystem::create_directory(link);
    nae::Handle h(CreateFileW(link.c_str(), GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, nullptr));
    require(h.value != INVALID_HANDLE_VALUE, "junction fixture handle");
    const std::wstring substitute = L"\\??\\" + target.wstring();
    const auto print = target.wstring();
    struct Junction { DWORD tag = 0; WORD length = 0, reserved = 0, substitute_offset = 0, substitute_length = 0, print_offset = 0, print_length = 0; wchar_t path[32768]{}; };
    auto data = std::make_unique<Junction>();
    data->tag = IO_REPARSE_TAG_MOUNT_POINT;
    data->substitute_length = static_cast<WORD>(substitute.size() * sizeof(wchar_t));
    data->print_offset = static_cast<WORD>((substitute.size() + 1) * sizeof(wchar_t));
    data->print_length = static_cast<WORD>(print.size() * sizeof(wchar_t));
    std::memcpy(data->path, substitute.c_str(), (substitute.size() + 1) * sizeof(wchar_t));
    std::memcpy(reinterpret_cast<unsigned char*>(data->path) + data->print_offset, print.c_str(), (print.size() + 1) * sizeof(wchar_t));
    data->length = static_cast<WORD>(8 + data->print_offset + data->print_length + sizeof(wchar_t));
    DWORD returned = 0;
    if (!DeviceIoControl(h.value, FSCTL_SET_REPARSE_POINT, data.get(), 8UL + data->length, nullptr, 0, &returned, nullptr)) throw nae::Error("Create junction fixture", GetLastError());
    return link;
}
void set_fixture_dacl(const std::filesystem::path& path, const wchar_t* sddl) {
    const auto sd = descriptor(sddl);
    BOOL present = FALSE, defaulted = FALSE; PACL acl = nullptr;
    if (!GetSecurityDescriptorDacl(const_cast<unsigned char*>(sd.data()), &present, &acl, &defaulted)) throw std::runtime_error("Fixture descriptor");
    const auto error = SetNamedSecurityInfoW(const_cast<wchar_t*>(path.c_str()), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, nullptr, nullptr, acl, nullptr);
    if (error) throw nae::Error("Fixture ACL", error);
}
void compare_accesscheck(const std::vector<unsigned char>& sd, DWORD actual) {
    HANDLE process = nullptr, duplicated = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &process)) throw std::runtime_error("Test token");
    nae::Handle p(process);
    if (!DuplicateToken(process, SecurityImpersonation, &duplicated)) throw std::runtime_error("Test DuplicateToken");
    nae::Handle t(duplicated);
    GENERIC_MAPPING mapping{FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_GENERIC_EXECUTE, FILE_ALL_ACCESS};
    std::vector<unsigned char> privileges(4096); DWORD size = static_cast<DWORD>(privileges.size()), granted = 0; BOOL status = FALSE;
    if (!AccessCheck(const_cast<unsigned char*>(sd.data()), duplicated, MAXIMUM_ALLOWED, &mapping, reinterpret_cast<PRIVILEGE_SET*>(privileges.data()), &size, &granted, &status)) throw nae::Error("Independent AccessCheck", GetLastError());
    require((granted & FILE_ALL_ACCESS) == actual, "Authz versus AccessCheck mismatch");
}
}
int wmain() {
    try {
        auto allow = descriptor(L"O:SYG:SYD:P(A;;FR;;;WD)");
        auto r = nae::describe(allow, false);
        require(r.authoritative && (r.granted & FILE_READ_DATA), "allow/Authz");
        require(r.owner == "S-1-5-18" && r.protected_dacl, "owner/protected");
        require(r.aces.size() == 1 && !(r.aces[0].flags & INHERITED_ACE), "explicit");
        compare_accesscheck(allow, r.granted);
        auto deny = descriptor(L"O:SYG:SYD:(D;;FW;;;WD)(A;;FA;;;WD)");
        r = nae::describe(deny, false);
        require(!(r.granted & FILE_WRITE_DATA) && (r.granted & FILE_READ_DATA), "deny/Authz");
        compare_accesscheck(deny, r.granted);
        r = nae::describe(descriptor(L"O:SYG:SYD:(A;ID;FR;;;WD)"), true);
        require((r.aces[0].flags & INHERITED_ACE) != 0, "inherited");
        r = nae::describe(descriptor(L"O:SYG:SYD:"), false);
        require(r.dacl_state == "empty" && !(r.granted & FILE_READ_DATA), "empty DACL");
        auto null_sd = descriptor(L"O:SYG:SYD:NO_ACCESS_CONTROL");
        r = nae::describe(null_sd, false);
        require(r.dacl_state == "null" && (r.granted & FILE_READ_DATA), "null DACL");
        require(nae::rights(FILE_READ_DATA, false)[0] == "read-data" && nae::rights(FILE_READ_DATA, true)[0] == "list-directory", "file/directory");
        require(nae::mapped_mask(GENERIC_READ) == FILE_GENERIC_READ && nae::mapped_mask(GENERIC_ALL) == FILE_ALL_ACCESS, "generic mapping");
        auto generic = descriptor(L"O:SYG:SYD:(A;;GR;;;WD)");
        require((nae::describe(generic, false).granted & FILE_GENERIC_READ) == FILE_GENERIC_READ, "Authz mapped generic");
        auto unknown = allow;
        const auto* relative = reinterpret_cast<const SECURITY_DESCRIPTOR_RELATIVE*>(unknown.data());
        unknown[relative->Dacl + sizeof(ACL)] = 0x7f;
        r = nae::describe(unknown, false);
        require(!r.authoritative && r.aces[0].kind == "unknown", "unknown ACE safe withholding");
        r = nae::describe(descriptor(L"O:SYG:SYD:(OA;;FR;00112233-4455-6677-8899-aabbccddeeff;;WD)"), false);
        require(!r.authoritative && !r.aces[0].sid.empty(), "object ACE safely decoded");
        r = nae::describe(descriptor(L"O:SYG:SYD:(A;IOCI;FR;;;WD)"), true);
        require(!(r.granted & FILE_READ_DATA) && r.aces[0].relevance.find("inherit-only") != std::string::npos, "inherit-only");
        nae::Local sid;
        require(ConvertStringSidToSidW(L"S-1-1-0", &sid.value) != FALSE, "test SID");
        r = nae::describe(allow, false, sid.value);
        require(!r.authoritative && r.aces[0].relevance.find("exact SID") != std::string::npos, "SID inspection only");
        rejects([] { nae::describe({}, false); });
        for (size_t i = 0; i < allow.size(); ++i) {
            std::vector<unsigned char> truncated(allow.begin(), allow.begin() + static_cast<std::ptrdiff_t>(i));
            rejects([&] { nae::describe(truncated, false); });
        }
        auto corrupt = allow;
        reinterpret_cast<SECURITY_DESCRIPTOR_RELATIVE*>(corrupt.data())->Dacl = 0xfffffff0;
        rejects([&] { nae::describe(corrupt, false); });
        require(nae::quote("a\n\"\\") == "\"a\\u000a\\\"\\\\\"", "JSON escape");
        Fixture fixture;
        const auto file = fixture.root / L"权限-Δ-file.txt";
        { std::ofstream f(file); f << "fixture"; }
        const auto before = std::filesystem::last_write_time(file);
        set_fixture_dacl(file, L"D:P(A;;FA;;;WD)");
        r = nae::inspect(file.wstring());
        require(r.authoritative && (r.granted & FILE_WRITE_DATA) && r.target.find("权限") != std::string::npos, "Unicode/fixture");
        // Filesystem metadata is external mutable state, not a pure function.
        // cppcheck-suppress knownConditionTrueFalse
        require(std::filesystem::last_write_time(file) == before, "read-only write timestamp");
        const auto dir = fixture.root / L"directory";
        std::filesystem::create_directory(dir);
        set_fixture_dacl(dir, L"D:P(A;;FA;;;WD)");
        require(nae::inspect(dir.wstring()).object_type == "directory", "directory fixture");
        const auto link = junction_fixture(fixture, dir);
        rejects([&] { nae::inspect(link.wstring()); }, ERROR_REPARSE_TAG_INVALID);
        rejects([&] { nae::inspect((link / L"child").wstring()); }, ERROR_REPARSE_TAG_INVALID);
        require(RemoveDirectoryW(link.c_str()) != FALSE, "junction cleanup");
        rejects([&] { nae::inspect((fixture.root / L"missing").wstring()); }, ERROR_FILE_NOT_FOUND);
        rejects([&] { nae::inspect(L"\\\\server\\share\\missing"); });
        rejects([&] { nae::inspect(L"\\\\?\\C:\\missing"); });
        rejects([&] { nae::inspect(file.wstring() + L":stream"); });
        rejects([&] { nae::inspect(file.wstring(), L"Administrator"); });
        // The owner can restore this disposable fixture without privilege enablement.
        {
        RestoreDacl restore(file);
        set_fixture_dacl(file, L"D:P(D;;RC;;;OW)(D;;RC;;;WD)(A;;FA;;;WD)");
        rejects([&] { nae::inspect(file.wstring()); }, ERROR_ACCESS_DENIED);
        require(restore.restore() == ERROR_SUCCESS, "restore fixture ACL");
        }
        // Independent parser consumes these artifacts outside the test process.
        std::vector<wchar_t> artifacts(32768);
        if (GetEnvironmentVariableW(L"NAE_TEST_ARTIFACTS", artifacts.data(), static_cast<DWORD>(artifacts.size()))) {
            std::filesystem::path out(artifacts.data());
            std::ofstream(out / L"report.json", std::ios::binary) << nae::json(r);
            std::ofstream(out / L"sid-report.json", std::ios::binary) << nae::json(nae::inspect(file.wstring(), L"S-1-1-0"));
        }
        fixture.clean();
        std::cout << "Passed " << checks << " checks; process token elevated=" << (r.token_elevated ? "yes" : "no") << "; controlled disposable fixtures cleaned.\n";
        return 0;
    } catch (const nae::Error& e) { std::cerr << "FAIL: " << e.what() << " Win32=" << e.code << '\n'; return 1;
    } catch (const std::exception& e) { std::cerr << "FAIL: " << e.what() << '\n'; return 1; }
}

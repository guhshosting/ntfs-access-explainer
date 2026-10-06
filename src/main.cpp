#include "core.hpp"
#include <iostream>
#include <io.h>
#include <fcntl.h>
namespace {
void output(const std::string& text) {
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    if (GetConsoleMode(h, &mode)) {
        const int length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), nullptr, 0);
        std::wstring wide(static_cast<size_t>(length), L'\0');
        MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), wide.data(), length);
        DWORD written = 0;
        WriteConsoleW(h, wide.data(), static_cast<DWORD>(wide.size()), &written, nullptr);
    } else { std::cout << text; }
}
}
int wmain(int argc, wchar_t** argv) {
    bool as_json = false;
    // Recognize JSON even when another argument fails, so errors remain machine readable.
    for (int i = 1; i < argc; ++i) if (std::wstring(argv[i]) == L"--json") as_json = true;
    try {
        std::wstring path, principal;
        bool positional = false;
        for (int i = 1; i < argc; ++i) {
            const std::wstring arg(argv[i]);
            if (!positional && arg == L"--") { positional = true; continue; }
            if (!positional && arg == L"--help") {
                output("ntfs-access-explainer 1.0.0\nUsage: ntfs-access-explainer [--json] [--principal S-1-...] [--] <path>\nRead-only local NTFS inspection. Default: current process token, Authz DACL evaluation.\nExplicit principal: numeric SID only; ACE inspection, no effective-access result.\nUNC, device paths, alternate streams and reparse points are rejected.\nNo account lookup, network lookup, privilege enablement or permission changes.\n--help  --version\n"); return 0;
            }
            if (!positional && arg == L"--version") { output("1.0.0\n"); return 0; }
            if (!positional && arg == L"--json") continue;
            if (!positional && arg == L"--principal") {
                if (!principal.empty() || i + 1 >= argc) throw nae::Error("--principal requires one numeric SID");
                principal = argv[++i];
                if (principal.empty()) throw nae::Error("--principal requires a nonempty numeric SID");
                continue;
            }
            if (!positional && !arg.empty() && arg[0] == L'-') throw nae::Error("Unknown option");
            if (!path.empty()) throw nae::Error("Exactly one path is required");
            path = arg;
        }
        if (path.empty()) throw nae::Error("A path is required; use --help");
        const auto report = nae::inspect(path, principal);
        output(as_json ? nae::json(report) + "\n" : nae::human(report));
        return 0;
    } catch (const nae::Error& e) {
        output(as_json ? "{\"schema_version\":\"1.0\",\"error\":{\"message\":" + nae::quote(e.what()) + ",\"win32_code\":" + std::to_string(e.code) + "}}\n" : "Error: " + std::string(e.what()) + " (Win32 " + std::to_string(e.code) + ")\n");
        return 2;
    } catch (const std::exception& e) {
        output(as_json ? "{\"schema_version\":\"1.0\",\"error\":{\"message\":" + nae::quote(e.what()) + ",\"win32_code\":8}}\n" : "Error: " + std::string(e.what()) + "\n");
        return 2;
    }
}

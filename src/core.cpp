#include "core.hpp"
#include <aclapi.h>
#include <sddl.h>
#include <authz.h>
#include <algorithm>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <memory>
#include <limits>
namespace nae {
namespace {
[[noreturn]] void fail(const char* what) { throw Error(what, GetLastError()); }
template<class T> T read(const unsigned char* p) { T value{}; std::memcpy(&value, p, sizeof(T)); return value; }
void bound(size_t offset, size_t length, size_t size) {
    if (offset > size || length > size - offset) throw Error("Malformed security descriptor", ERROR_INVALID_SECURITY_DESCR);
}
PSID checked_sid(unsigned char* data, size_t size, size_t offset) {
    bound(offset, 8, size);
    const auto count = data[offset + 1];
    bound(offset, 8 + static_cast<size_t>(count) * 4, size);
    auto sid = static_cast<PSID>(data + offset);
    if (!IsValidSid(sid)) throw Error("Malformed SID", ERROR_INVALID_SID);
    return sid;
}
void checked_acl(unsigned char* data, size_t size, DWORD offset) {
    if (!offset) return;
    if (offset < sizeof(SECURITY_DESCRIPTOR_RELATIVE) || offset % 4) throw Error("Invalid ACL offset", ERROR_INVALID_SECURITY_DESCR);
    bound(offset, sizeof(ACL), size);
    const ACL acl = read<ACL>(data + offset);
    if (acl.AclSize < sizeof(ACL)) throw Error("Malformed ACL", ERROR_INVALID_ACL);
    bound(offset, acl.AclSize, size);
    size_t cursor = sizeof(ACL);
    for (unsigned i = 0; i < acl.AceCount; ++i) {
        bound(cursor, sizeof(ACE_HEADER), acl.AclSize);
        const auto header = read<ACE_HEADER>(data + offset + cursor);
        if (header.AceSize < sizeof(ACE_HEADER) || header.AceSize % 4 != 0) throw Error("Malformed ACE", ERROR_INVALID_ACL);
        bound(cursor, header.AceSize, acl.AclSize);
        cursor += header.AceSize;
    }
    if (acl.AclRevision != ACL_REVISION && acl.AclRevision != ACL_REVISION_DS) throw Error("Unsupported ACL revision", ERROR_INVALID_ACL);
}
std::vector<unsigned char> token_info(HANDLE token, TOKEN_INFORMATION_CLASS cls) {
    DWORD size = 0;
    GetTokenInformation(token, cls, nullptr, 0, &size);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) fail("GetTokenInformation size failed");
    std::vector<unsigned char> result(size);
    if (!GetTokenInformation(token, cls, result.data(), size, &size)) fail("GetTokenInformation failed");
    return result;
}
struct Matching { PSID selected; HANDLE token; };
std::string relevance(PSID sid, const Ace& ace, const Matching& context) {
    const auto type = ace.type;
    const auto flags = ace.flags;
    const auto selected = context.selected;
    const auto token = context.token;
    if (!sid) return "unknown ACE semantics";
    if (flags & INHERIT_ONLY_ACE) return "inherit-only; does not apply to this object";
    if (selected) return EqualSid(sid, selected) ? "exact SID match only; token membership unknown" : "different SID; group membership unknown";
    if (!ace.supported) return "SID decoded; this ACE's authorization semantics are not evaluated";
    const auto user = token_info(token, TokenUser);
    if (EqualSid(sid, reinterpret_cast<const TOKEN_USER*>(user.data())->User.Sid)) return "token user SID match; candidate ACE, not proof of contribution";
    const auto groups = token_info(token, TokenGroups);
    const auto* g = reinterpret_cast<const TOKEN_GROUPS*>(groups.data());
    for (DWORD i = 0; i < g->GroupCount; ++i) {
        if (!EqualSid(sid, g->Groups[i].Sid)) continue;
        if (g->Groups[i].Attributes & SE_GROUP_USE_FOR_DENY_ONLY) return type == ACCESS_DENIED_ACE_TYPE ? "deny-only token group match; candidate deny ACE" : "deny-only token group; cannot grant access";
        if (g->Groups[i].Attributes & SE_GROUP_ENABLED) return "enabled token group match; candidate ACE, not proof of contribution";
        return "disabled token group; ordinary allow/deny does not apply";
    }
    return "no ordinary token SID match; special SIDs/restricted contexts may have other semantics";
}
std::vector<Ace> decode_acl(unsigned char* data, DWORD offset, PSID selected, HANDLE token, bool& supported) {
    std::vector<Ace> result;
    if (!offset) return result;
    const ACL acl = read<ACL>(data + offset);
    size_t cursor = sizeof(ACL);
    for (unsigned i = 0; i < acl.AceCount; ++i) {
        auto* raw = data + offset + cursor;
        const auto h = read<ACE_HEADER>(raw);
        Ace a; a.index = i; a.type = h.AceType; a.flags = h.AceFlags;
        size_t sid_offset = 0;
        switch (h.AceType) {
        case ACCESS_ALLOWED_ACE_TYPE: a.kind = "allow"; a.supported = true; sid_offset = 8; break;
        case ACCESS_DENIED_ACE_TYPE: a.kind = "deny"; a.supported = true; sid_offset = 8; break;
        case SYSTEM_AUDIT_ACE_TYPE: a.kind = "audit"; sid_offset = 8; break;
        case SYSTEM_MANDATORY_LABEL_ACE_TYPE: a.kind = "mandatory-label"; sid_offset = 8; break;
        case ACCESS_ALLOWED_CALLBACK_ACE_TYPE: a.kind = "callback-allow"; sid_offset = 8; break;
        case ACCESS_DENIED_CALLBACK_ACE_TYPE: a.kind = "callback-deny"; sid_offset = 8; break;
        case ACCESS_ALLOWED_OBJECT_ACE_TYPE:
        case ACCESS_DENIED_OBJECT_ACE_TYPE:
        case ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE:
        case ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE: {
            a.kind = "object-or-callback-object";
            bound(0, 12, h.AceSize);
            const DWORD f = read<DWORD>(raw + 8);
            sid_offset = 12 + ((f & ACE_OBJECT_TYPE_PRESENT) ? sizeof(GUID) : 0) + ((f & ACE_INHERITED_OBJECT_TYPE_PRESENT) ? sizeof(GUID) : 0);
            break;
        }
        default: a.kind = "unknown"; break;
        }
        PSID sid = nullptr;
        if (sid_offset) {
            bound(0, 8, h.AceSize); a.mask_known = true; a.mask = read<DWORD>(raw + 4); a.mapped = mapped_mask(a.mask);
            sid = checked_sid(raw, h.AceSize, sid_offset); a.sid = sid_text(sid);
            if (a.supported && sid_offset + GetLengthSid(sid) != h.AceSize) a.supported = false;
        }
        a.relevance = token || selected ? relevance(sid, a, Matching{selected, token}) : "integrity information only";
        supported = supported && a.supported;
        result.push_back(a); cursor += h.AceSize;
    }
    return result;
}
struct Authz {
    AUTHZ_RESOURCE_MANAGER_HANDLE manager = nullptr;
    AUTHZ_CLIENT_CONTEXT_HANDLE context = nullptr;
    ~Authz() { if (context) AuthzFreeContext(context); if (manager) AuthzFreeResourceManager(manager); }
};
void evaluate(Report& report, std::vector<unsigned char>& sd, HANDLE token) {
    auto* relative = reinterpret_cast<SECURITY_DESCRIPTOR_RELATIVE*>(sd.data());
    if (relative->Dacl) {
        auto* acl = reinterpret_cast<ACL*>(sd.data() + relative->Dacl);
        for (DWORD i = 0; i < acl->AceCount; ++i) {
            void* raw = nullptr;
            if (!GetAce(acl, i, &raw)) fail("GetAce failed");
            auto* ace = static_cast<ACCESS_ALLOWED_ACE*>(raw);
            ace->Mask = mapped_mask(ace->Mask);
        }
    }
    // Deliberately DACL-only. No CAP lookup, auditing, or remote resource manager.
    relative->Sacl = 0;
    relative->Control = static_cast<SECURITY_DESCRIPTOR_CONTROL>(static_cast<unsigned>(relative->Control) & ~static_cast<unsigned>(SE_SACL_PRESENT));
    Authz authz;
    if (!AuthzInitializeResourceManager(AUTHZ_RM_FLAG_NO_AUDIT | AUTHZ_RM_FLAG_NO_CENTRAL_ACCESS_POLICIES, nullptr, nullptr, nullptr, L"ntfs-access-explainer", &authz.manager)) fail("Authz resource manager failed");
    const LUID id{};
    if (!AuthzInitializeContextFromToken(0, token, authz.manager, nullptr, id, nullptr, &authz.context)) fail("Authz token context failed");
    AUTHZ_ACCESS_REQUEST request{}; request.DesiredAccess = MAXIMUM_ALLOWED;
    AUTHZ_ACCESS_REPLY reply{}; reply.ResultListLength = 1;
    reply.GrantedAccessMask = &report.granted; reply.Error = &report.authz_error;
    if (!AuthzAccessCheck(0, authz.context, &request, nullptr, sd.data(), nullptr, 0, &reply, nullptr)) fail("AuthzAccessCheck failed");
    if (report.authz_error != ERROR_SUCCESS && report.authz_error != ERROR_ACCESS_DENIED) throw Error("Authz result failed", report.authz_error);
    report.granted &= FILE_ALL_ACCESS;
    report.authoritative = true;
}
std::string strings(const std::vector<std::string>& values) {
    std::string result = "[";
    for (size_t i = 0; i < values.size(); ++i) { if (i) result += ','; result += quote(values[i]); }
    return result + "]";
}
std::vector<std::string> ace_rights(const Ace& a, bool dir) {
    if (!a.mask_known) return {};
    if (a.kind != "mandatory-label") return rights(a.mapped, dir);
    std::vector<std::string> values;
    if (a.mask & SYSTEM_MANDATORY_LABEL_NO_WRITE_UP) values.emplace_back("no-write-up");
    if (a.mask & SYSTEM_MANDATORY_LABEL_NO_READ_UP) values.emplace_back("no-read-up");
    if (a.mask & SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP) values.emplace_back("no-execute-up");
    if (a.mask & ~7UL) values.push_back("unknown-policy-bits:" + hex(a.mask & ~7UL));
    return values;
}
std::string ace_json(const std::vector<Ace>& aces, bool dir) {
    std::string result = "[";
    for (const auto& a : aces) {
        if (result.size() > 1) result += ',';
        result += "{\"index\":" + std::to_string(a.index) + ",\"type\":" + std::to_string(a.type) + ",\"kind\":" + quote(a.kind) + ",\"flags\":" + std::to_string(a.flags) + ",\"inherited\":" + ((a.flags & INHERITED_ACE) ? "true" : "false") + ",\"object_inherit\":" + ((a.flags & OBJECT_INHERIT_ACE) ? "true" : "false") + ",\"container_inherit\":" + ((a.flags & CONTAINER_INHERIT_ACE) ? "true" : "false") + ",\"no_propagate\":" + ((a.flags & NO_PROPAGATE_INHERIT_ACE) ? "true" : "false") + ",\"inherit_only\":" + ((a.flags & INHERIT_ONLY_ACE) ? "true" : "false") + ",\"sid\":" + (a.sid.empty() ? "null" : quote(a.sid)) + ",\"mask\":" + (a.mask_known ? quote(hex(a.mask)) : "null") + ",\"mapped_mask\":" + (a.mask_known ? quote(hex(a.mapped)) : "null") + ",\"rights\":" + strings(ace_rights(a, dir)) + ",\"supported_for_evaluation\":" + (a.supported ? "true" : "false") + ",\"relevance\":" + quote(a.relevance) + "}";
    }
    return result + "]";
}
}
std::string utf8(const std::wstring& text) {
    if (text.empty()) return {};
    if (text.size() > static_cast<size_t>((std::numeric_limits<int>::max)())) throw Error("String too long");
    const int count = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
    if (!count) fail("Invalid Unicode");
    std::string result(static_cast<size_t>(count), '\0');
    if (!WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), result.data(), count, nullptr, nullptr)) fail("Unicode conversion failed");
    return result;
}
std::string sid_text(PSID sid) {
    if (!sid) return "";
    Local value;
    if (!ConvertSidToStringSidW(sid, reinterpret_cast<LPWSTR*>(&value.value))) fail("SID formatting failed");
    return utf8(static_cast<wchar_t*>(value.value));
}
DWORD mapped_mask(DWORD mask) {
    GENERIC_MAPPING mapping{FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_GENERIC_EXECUTE, FILE_ALL_ACCESS};
    MapGenericMask(&mask, &mapping); return mask;
}
std::vector<std::string> rights(DWORD mask, bool dir) {
    const std::pair<DWORD, const char*> bits[] = {
        {FILE_READ_DATA, dir ? "list-directory" : "read-data"}, {FILE_WRITE_DATA, dir ? "add-file" : "write-data"},
        {FILE_APPEND_DATA, dir ? "add-subdirectory" : "append-data"}, {FILE_READ_EA, "read-extended-attributes"},
        {FILE_WRITE_EA, "write-extended-attributes"}, {FILE_EXECUTE, dir ? "traverse" : "execute"},
        {FILE_DELETE_CHILD, "delete-child"}, {FILE_READ_ATTRIBUTES, "read-attributes"}, {FILE_WRITE_ATTRIBUTES, "write-attributes"},
        {DELETE, "delete"}, {READ_CONTROL, "read-control"}, {WRITE_DAC, "write-dacl"}, {WRITE_OWNER, "write-owner"},
        {SYNCHRONIZE, "synchronize"}, {ACCESS_SYSTEM_SECURITY, "access-system-security"},
        {GENERIC_READ, "generic-read"}, {GENERIC_WRITE, "generic-write"}, {GENERIC_EXECUTE, "generic-execute"}, {GENERIC_ALL, "generic-all"}};
    std::vector<std::string> result;
    DWORD known = 0;
    for (const auto& bit : bits) { known |= bit.first; if (mask & bit.first) result.emplace_back(bit.second); }
    if (mask & ~known) result.push_back("unknown-bits:" + hex(mask & ~known));
    return result;
}
std::string hex(DWORD value) { std::ostringstream s; s << "0x" << std::hex << std::uppercase << std::setw(8) << std::setfill('0') << value; return s.str(); }
std::string quote(const std::string& value) {
    std::string result = "\"";
    for (const unsigned char c : value) {
        if (c == '"' || c == '\\') { result += '\\'; result += static_cast<char>(c); }
        else if (c < 32) { const char digits[] = "0123456789abcdef"; result += "\\u00"; result += digits[static_cast<unsigned>(c) >> 4U]; result += digits[static_cast<unsigned>(c) & 15U]; }
        else result += static_cast<char>(c);
    }
    return result + '"';
}
Report describe(const std::vector<unsigned char>& descriptor, bool directory, PSID selected) {
    auto sd = descriptor;
    bound(0, sizeof(SECURITY_DESCRIPTOR_RELATIVE), sd.size());
    const auto header = read<SECURITY_DESCRIPTOR_RELATIVE>(sd.data());
    if (header.Revision != SECURITY_DESCRIPTOR_REVISION || !(header.Control & SE_SELF_RELATIVE)) throw Error("Expected self-relative security descriptor", ERROR_INVALID_SECURITY_DESCR);
    for (const DWORD offset : {header.Owner, header.Group}) {
        if (!offset) continue;
        if (offset < sizeof(SECURITY_DESCRIPTOR_RELATIVE) || offset % 4) throw Error("Invalid SID offset", ERROR_INVALID_SECURITY_DESCR);
        checked_sid(sd.data(), sd.size(), offset);
    }
    checked_acl(sd.data(), sd.size(), header.Dacl); checked_acl(sd.data(), sd.size(), header.Sacl);
    Report r; r.object_type = directory ? "directory" : "file";
    r.owner = header.Owner ? sid_text(sd.data() + header.Owner) : "";
    r.group = header.Group ? sid_text(sd.data() + header.Group) : "";
    r.protected_dacl = (header.Control & SE_DACL_PROTECTED) != 0;
    r.dacl_state = !(header.Control & SE_DACL_PRESENT) ? "absent" : !header.Dacl ? "null" : read<ACL>(sd.data() + header.Dacl).AceCount == 0 ? "empty" : "present";
    HANDLE raw_token = nullptr;
    if (!selected && !OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw_token)) fail("Cannot open process token");
    Handle token(raw_token);
    if (selected) { r.principal = sid_text(selected); r.context = "sid-inspection-only"; }
    else {
        const auto user = token_info(token.value, TokenUser);
        r.principal = sid_text(reinterpret_cast<const TOKEN_USER*>(user.data())->User.Sid);
        const auto il = token_info(token.value, TokenIntegrityLevel);
        r.token_integrity = sid_text(reinterpret_cast<const TOKEN_MANDATORY_LABEL*>(il.data())->Label.Sid);
        r.context = "current-process-token";
        TOKEN_ELEVATION elevation{}; DWORD elevation_size = sizeof(elevation);
        if (!GetTokenInformation(token.value, TokenElevation, &elevation, sizeof(elevation), &elevation_size)) fail("Token elevation query failed");
        r.token_elevated = elevation.TokenIsElevated != 0;
        const auto restricted = token_info(token.value, TokenRestrictedSids);
        if (reinterpret_cast<const TOKEN_GROUPS*>(restricted.data())->GroupCount) r.warnings.push_back("Restricted token: ordinary group matches do not describe the additional restricted SID check.");
    }
    bool supported = true;
    if (header.Control & SE_DACL_PRESENT) r.aces = decode_acl(sd.data(), header.Dacl, selected, token.value, supported);
    if (!selected && supported) {
        if (!IsValidSecurityDescriptor(sd.data())) throw Error("Invalid security descriptor", ERROR_INVALID_SECURITY_DESCR);
        evaluate(r, sd, token.value);
    } else if (!selected) r.warnings.push_back("Effective access withheld: object, callback, unknown or extended ACE semantics require context beyond this evaluator.");
    if (selected) r.limitations.push_back("A SID alone has no complete group, privilege, claims or restricted-token state. No effective access is calculated, even if this SID equals the current user.");
    r.limitations.push_back("Authz is authoritative only for the reported DACL-only, MAXIMUM_ALLOWED evaluation using the current process token and mapped filesystem rights. It does not predict every CreateFile call.");
    r.limitations.push_back("Mandatory integrity, privileges used by filesystem operations, central access policy/resource claims, filesystem filters, object state, parent delete-child rights and application behavior can change operation outcomes. Full SACL is not requested; central policy evaluation is disabled to avoid lookup.");
    r.limitations.push_back("Remote resources and SMB share permissions are out of scope. SID display names are intentionally unresolved; there are no account or domain lookups.");
    r.limitations.push_back("ACE relevance is candidate matching, not an Authz execution trace or per-ACE causal attribution. Order, owner rights, special SIDs and restricted-token rules remain Windows decisions.");
    if (r.dacl_state == "null" || r.dacl_state == "absent") r.findings.push_back("No restrictive DACL is present; other security mechanisms may still restrict operations.");
    if (r.dacl_state == "empty") r.findings.push_back("An empty DACL contains no grants; implicit owner rights and token privileges require Windows evaluation.");
    r.findings.push_back(r.protected_dacl ? "DACL is protected from inherited ACE updates." : "DACL protection is off; inherited ACEs may be present. This does not prove parent permissions or future inheritance.");
    r.findings.push_back("Ownership is not unrestricted access. Windows handles implicit owner rights and OWNER RIGHTS ACEs.");
    return r;
}
Report inspect(const std::wstring& input, const std::wstring& principal) {
    Local selected;
    if (!principal.empty()) {
        if (principal.rfind(L"S-1-", 0) != 0 || principal.find_first_not_of(L"S-0123456789") != std::wstring::npos) throw Error("--principal accepts numeric SID strings only; account-name lookup is disabled");
        if (!ConvertStringSidToSidW(principal.c_str(), &selected.value)) fail("Invalid principal SID");
    }
    // Reject namespace forms before any filesystem/security probing.
    if (input.empty() || input[0] == L'\\' || input[0] == L'/' || input.find(L'/') != std::wstring::npos || input.find(L'\0') != std::wstring::npos) throw Error("UNC, rooted/device namespaces and forward slash paths are unsupported");
    if (input.size() >= 2 && input[1] == L':' && (input.size() < 3 || input[2] != L'\\')) throw Error("Drive-relative paths are unsupported");
    std::vector<wchar_t> buffer(32768);
    const DWORD count = GetFullPathNameW(input.c_str(), static_cast<DWORD>(buffer.size()), buffer.data(), nullptr);
    if (!count || count >= buffer.size()) throw Error("Cannot normalize path", ERROR_INVALID_NAME);
    std::wstring path(buffer.data(), count);
    if (path.size() < 3 || path[1] != L':' || path[2] != L'\\' || !((path[0] >= L'A' && path[0] <= L'Z') || (path[0] >= L'a' && path[0] <= L'z')) || path.find(L':', 2) != std::wstring::npos) throw Error("Only local DOS drive paths without alternate streams are supported");
    while (path.size() > 3 && path.back() == L'\\') path.pop_back();
    std::wstring drive = path.substr(0, 2);
    std::vector<wchar_t> device(32768);
    if (!QueryDosDeviceW(drive.c_str(), device.data(), static_cast<DWORD>(device.size()))) fail("Cannot classify drive mapping");
    const std::wstring mapping(device.data());
    const std::wstring prefix = L"\\Device\\HarddiskVolume";
    if (mapping.rfind(prefix, 0) != 0 || mapping.size() == prefix.size() || mapping.find_first_not_of(L"0123456789", prefix.size()) != std::wstring::npos) throw Error("Drive is not a directly mapped local disk volume; network, SUBST and device mappings rejected");
    const std::wstring root = path.substr(0, 3);
    const UINT drive_type = GetDriveTypeW(root.c_str());
    if (drive_type != DRIVE_FIXED && drive_type != DRIVE_REMOVABLE) throw Error("Only fixed/removable local disk volumes are supported");
    std::vector<std::unique_ptr<Handle>> handles;
    // Hold every ancestor without FILE_SHARE_DELETE to prevent replacement during inspection.
    size_t end = 3;
    for (;;) {
        const std::wstring part = path.substr(0, end);
        const bool final = end == path.size();
        const DWORD desired = FILE_READ_ATTRIBUTES | (final ? READ_CONTROL : 0);
        // Pin the classified volume namespace, avoiding a drive-remapping race.
        const std::wstring physical = L"\\\\?\\GLOBALROOT" + mapping + L"\\" + part.substr(3);
        HANDLE h = CreateFileW(physical.c_str(), desired, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        if (h == INVALID_HANDLE_VALUE) fail("Cannot open target or ancestor for read-only inspection");
        handles.push_back(std::make_unique<Handle>(h));
        FILE_ATTRIBUTE_TAG_INFO attrs{};
        if (!GetFileInformationByHandleEx(h, FileAttributeTagInfo, &attrs, sizeof(attrs))) fail("Cannot query object attributes");
        if (attrs.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) throw Error("Reparse point in target or ancestor rejected", ERROR_REPARSE_TAG_INVALID);
        if (!final && !(attrs.FileAttributes & FILE_ATTRIBUTE_DIRECTORY)) throw Error("Ancestor is not a directory", ERROR_DIRECTORY);
        if (handles.size() == 1) {
            wchar_t fs[32]{};
            if (!GetVolumeInformationByHandleW(h, nullptr, 0, nullptr, nullptr, nullptr, fs, static_cast<DWORD>(std::size(fs)))) fail("Cannot query local volume");
            if (std::wstring(fs) != L"NTFS") throw Error("v1.0.0 supports NTFS volumes only");
        }
        if (final) break;
        const size_t next = path.find(L'\\', end + (end == 3 ? 0 : 1));
        end = next == std::wstring::npos ? path.size() : next;
        if (end > 3 && (path[end - 1] == L'.' || path[end - 1] == L' ')) throw Error("Trailing-dot/space components rejected");
    }
    HANDLE h = handles.back()->value;
    FILE_ATTRIBUTE_TAG_INFO attrs{};
    if (!GetFileInformationByHandleEx(h, FileAttributeTagInfo, &attrs, sizeof(attrs))) fail("Cannot query target attributes");
    Local security;
    DWORD err = GetSecurityInfo(h, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, nullptr, nullptr, nullptr, nullptr, reinterpret_cast<PSECURITY_DESCRIPTOR*>(&security.value));
    if (err != ERROR_SUCCESS) throw Error("Cannot read object security descriptor", err);
    const DWORD size = GetSecurityDescriptorLength(security.value);
    const auto* raw = static_cast<unsigned char*>(security.value);
    auto r = describe(std::vector<unsigned char>(raw, raw + size), (attrs.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0, selected.value);
    r.target = utf8(path);
    Local label;
    err = GetSecurityInfo(h, SE_FILE_OBJECT, LABEL_SECURITY_INFORMATION, nullptr, nullptr, nullptr, nullptr, reinterpret_cast<PSECURITY_DESCRIPTOR*>(&label.value));
    r.integrity_status = err == ERROR_SUCCESS ? "queried-label-only" : "unavailable";
    if (err == ERROR_SUCCESS) {
        BOOL present = FALSE, defaulted = FALSE; PACL sacl = nullptr;
        if (!GetSecurityDescriptorSacl(label.value, &present, &sacl, &defaulted)) fail("Cannot decode integrity descriptor");
        if (present && sacl) {
            bool ignored = true;
            auto* base = static_cast<unsigned char*>(label.value);
            const auto offset = static_cast<DWORD>(reinterpret_cast<unsigned char*>(sacl) - base);
            checked_acl(base, GetSecurityDescriptorLength(label.value), offset);
            r.integrity_aces = decode_acl(base, offset, nullptr, nullptr, ignored);
        }
        if (r.integrity_aces.empty()) r.findings.push_back("No explicit integrity label was returned; Windows default integrity policy may apply.");
    } else r.warnings.push_back("Integrity label unavailable (Win32 " + std::to_string(err) + "); DACL analysis remains available.");
    return r;
}
std::string json(const Report& r) {
    return "{\"schema_version\":\"1.0\",\"tool_version\":\"1.0.0\",\"target\":" + quote(r.target) + ",\"object_type\":" + quote(r.object_type) + ",\"owner\":{\"sid\":" + (r.owner.empty() ? "null" : quote(r.owner)) + "},\"group\":{\"sid\":" + (r.group.empty() ? "null" : quote(r.group)) + "},\"dacl\":{\"state\":" + quote(r.dacl_state) + ",\"protected\":" + (r.protected_dacl ? "true" : "false") + "},\"aces\":" + ace_json(r.aces, r.object_type == "directory") + ",\"principal\":{\"sid\":" + quote(r.principal) + ",\"context\":" + quote(r.context) + ",\"token_integrity_sid\":" + (r.token_integrity.empty() ? "null" : quote(r.token_integrity)) + "},\"effective_access\":{\"status\":" + quote(r.authoritative ? "evaluated" : "not-calculated") + ",\"scope\":\"Authz DACL-only MAXIMUM_ALLOWED; not an operation prediction\",\"authoritative\":" + (r.authoritative ? "true" : "false") + ",\"granted_mask\":" + (r.authoritative ? quote(hex(r.granted)) : "null") + ",\"win32_result\":" + (r.authoritative ? std::to_string(r.authz_error) : "null") + ",\"rights\":" + strings(r.authoritative ? rights(r.granted, r.object_type == "directory") : std::vector<std::string>{}) + "},\"integrity\":{\"status\":" + quote(r.integrity_status) + ",\"aces\":" + ace_json(r.integrity_aces, false) + "},\"findings\":" + strings(r.findings) + ",\"limitations\":" + strings(r.limitations) + ",\"warnings\":" + strings(r.warnings) + "}";
}
std::string human(const Report& r) {
    std::ostringstream s;
    s << "Target: " << r.target << "\nObject: " << r.object_type << "\nOwner SID: " << r.owner << "\nGroup SID: " << r.group << "\nDACL: " << r.dacl_state << "; protection " << (r.protected_dacl ? "on" : "off") << "\nPrincipal: " << r.principal << " (" << r.context << ")\nToken integrity SID: " << r.token_integrity << "\nACEs in stored order:\n";
    for (const auto& a : r.aces) {
        s << "  [" << a.index << "] " << a.kind << " type=" << a.type << ' ' << ((a.flags & INHERITED_ACE) ? "inherited" : "explicit") << " SID=" << a.sid << " mask=" << (a.mask_known ? hex(a.mask) : "unknown") << " flags=" << hex(a.flags);
        if (a.flags & OBJECT_INHERIT_ACE) s << " object-inherit";
        if (a.flags & CONTAINER_INHERIT_ACE) s << " container-inherit";
        if (a.flags & NO_PROPAGATE_INHERIT_ACE) s << " no-propagate";
        if (a.flags & INHERIT_ONLY_ACE) s << " inherit-only";
        s << "\n    "; for (const auto& name : rights(a.mapped, r.object_type == "directory")) s << name << ' ';
        s << "\n    " << a.relevance << "\n";
    }
    if (r.context == "current-process-token") s << "Process token elevated: " << (r.token_elevated ? "yes" : "no") << '\n';
    s << "Effective access (Authz DACL-only): ";
    if (r.authoritative) { s << hex(r.granted) << " (Win32 result " << r.authz_error << ")\n  "; for (const auto& name : rights(r.granted, r.object_type == "directory")) s << name << ' '; s << '\n'; }
    else s << "not calculated\n";
    s << "Integrity label: " << r.integrity_status << '\n';
    for (const auto& a : r.integrity_aces) s << "  SID=" << a.sid << " policy=" << hex(a.mask) << " (1=no-write-up, 2=no-read-up, 4=no-execute-up)\n";
    for (const auto& f : r.findings) s << "Finding: " << f << '\n';
    for (const auto& w : r.warnings) s << "Warning: " << w << '\n';
    for (const auto& l : r.limitations) s << "Limitation: " << l << '\n';
    return s.str();
}
}

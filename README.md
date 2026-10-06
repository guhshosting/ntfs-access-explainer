# ntfs-access-explainer 1.0.0

> Runtime prerequisite for the exact qualified EXE: Microsoft Visual C++ x64 Redistributable is required when the imported runtime DLLs are absent. This supersedes any static-CRT/no-redistributable description of a source build below.


> Release context: see [qualified platforms, runtime requirements and package scope](RELEASE-QUALIFICATION.md).


A native Unicode Windows CLI that explains a local NTFS object's security
descriptor and calculates **current-process-token, DACL-only access using Windows
Authz**. It never edits permissions or tests access by writing.

```text
ntfs-access-explainer C:\data\report.txt
ntfs-access-explainer --json C:\data
ntfs-access-explainer --principal S-1-5-21-123-456-789-1001 C:\data
ntfs-access-explainer --help
ntfs-access-explainer --version
```

Quote paths containing spaces. `--` ends option parsing. Relative paths are
expanded against the working directory; absolute `C:\...` paths are recommended.
Exit code 0 means the inspection completed, including SID-only inspections and
withheld effective-access results. Exit code 2 means invalid arguments or an
inspection/API error. Inspect `effective_access.status` before using a JSON mask.
Help and version always emit plain text, even with `--json`.

## What is authoritative?

In default mode, `OpenProcessToken(TOKEN_QUERY)` obtains the existing process
token. `AuthzInitializeContextFromToken` constructs the authorization context;
`AuthzAccessCheck(MAXIMUM_ALLOWED)` evaluates the descriptor using Windows
authorization rules. Generic ACE masks are mapped on a private descriptor copy
with `MapGenericMask` and the Windows `FILE_GENERIC_*` mapping. The reported
mask is restricted to `FILE_ALL_ACCESS` filesystem bits. The descriptor on disk
is never changed. A successful call may return `ERROR_ACCESS_DENIED` and zero
rights; that is an evaluated denial, not a CLI failure.

This is authoritative **for this explicitly bounded DACL evaluation**, not a
prediction of every future filesystem operation. It uses the process token,
including its group/restricted-token state; it does not select a thread
impersonation token, refresh group membership, or impersonate another identity.
The token at execution time matters: elevated, filtered and restricted tokens
can yield different results. No privileges are enabled by the program.

Ordinary allow/deny ACEs are supported for evaluation. Object-specific,
callback/conditional, unknown, or extended ACE forms are inspected conservatively
and cause the effective-access calculation to be **withheld**. No ad hoc callback
logic or object GUID context is invented. Windows owns the access decision;
the program does not sum allows and subtract denies.

Central access policy evaluation is explicitly disabled on the Authz resource
manager to prevent policy lookup. Full SACL, resource claims and central policy
information are not acquired. Their absence from the output does not prove
their absence from the object. Authz receives a DACL-only descriptor.

## Principals and no-network policy

`--principal` accepts **numeric SID strings only** (`S-1-...`). Account names,
SDDL aliases such as `BA`, domain names and credentials are rejected. No account
names are resolved, including owner/group and ACE display names. This avoids
Windows account lookup APIs that can consult domain infrastructure.

Explicit SID mode is inspection only. Exact SID equality is reported, but a SID
does not reveal group memberships, deny-only groups, restricted SIDs, privileges,
logon identity or claims. **No effective-access mask is calculated in SID mode**,
even when the supplied SID is the current user's SID. There is no
`AuthzInitializeContextFromSid` fallback or arbitrary-user impersonation.

UNC, rooted namespace paths, device paths, forward slash paths, drive-relative
paths, alternate streams, SUBST drives and network drive mappings are rejected.
The local DOS drive mapping must point directly to `\Device\HarddiskVolumeN`
and the volume must be local fixed/removable NTFS. Classification precedes object
probing. The classified physical volume namespace is used internally to avoid
a DOS drive-remapping race. User-supplied GLOBALROOT/device paths are rejected.
Unconventional local volume mappings are deliberately unsupported.

There are no sockets, RPC, remote Authz resource managers, account lookups,
domain-controller queries, child processes, or shell commands in the production
executable. OS components, antivirus and filesystem filters are outside this
process's control; this is a no-intentional-network design, not a promise that
the entire Windows machine emits no packets. Builds and developer validation
are distinct from production execution.

## Reparse points and read-only behavior

Every path component is opened with `OPEN_EXISTING`,
`FILE_FLAG_OPEN_REPARSE_POINT` and `FILE_FLAG_BACKUP_SEMANTICS`. Reparse points
(links, junctions, cloud placeholders, mount points, or other tags) in either the
target or an ancestor are rejected. Ancestor handles remain open without delete
sharing to prevent replacement during inspection. The program does not recurse
through a tree. It may fail conservatively when an ancestor is inaccessible or
another open handle conflicts with sharing. Concurrent ACL changes are still
possible; the descriptor is a snapshot, not a filesystem transaction.

Ancestors require `FILE_READ_ATTRIBUTES`; the final object requires
`FILE_READ_ATTRIBUTES | READ_CONTROL`. The handle is reused for descriptor and
label reads. No `ACCESS_SYSTEM_SECURITY` access is requested. There is no
auto-elevation, ownership change, ACL setter, privilege adjustment, file creation,
deletion, write probe or remediation in production. Basic operation does not
require administrator membership; it requires the caller's existing read access.

## Reading the explanation

A DACL is an ordered list of access control entries (ACEs). Each ordinary ACE
contains an allow or deny type, trustee SID, access mask and inheritance flags.
Windows compares these with the authorization context. ACE order, enabled and
deny-only groups, restricted tokens, owner rights, generic mapping, special SIDs,
and other ACE forms make manual allow-minus-deny arithmetic unreliable.

Output preserves stored ACE order and distinguishes explicit and inherited ACEs.
`OBJECT_INHERIT` passes entries to files, `CONTAINER_INHERIT` to directories,
`NO_PROPAGATE` limits propagation, and `INHERIT_ONLY` excludes the entry from
the object itself. DACL protection blocks inheritance updates; protection off
does not prove that any ACE is inherited or that future parent changes will
produce a particular descriptor. Parents are not audited.

An absent or null DACL supplies no discretionary restriction. An empty DACL
supplies no ACE grants. Owner and privilege rules can still affect Windows
evaluation. Ownership is **not unrestricted access**: implicit owner
read-control/write-DACL rights and OWNER RIGHTS ACEs have specific semantics.

ACE relevance is explanatory candidate matching. It distinguishes user SID,
enabled group, disabled group, deny-only group, inherit-only entries, and exact
SID equality. It does not claim Windows consumed each candidate, attribute the
result to a single ACE, or reconstruct Authz's execution trace. Special SIDs and
restricted-token checks may matter even without an ordinary token SID match.

Filesystem bits are decoded with file/directory meanings: read-data/list-directory,
write-data/add-file, append-data/add-subdirectory, execute/traverse, extended
attributes, ordinary attributes, delete-child, delete, read-control, write-DACL,
write-owner and synchronize. Raw and mapped masks are both reported. Unknown
mask bits remain visible. Unknown ACE types retain type/flags but have null masks
and SID when their layout cannot safely be decoded.

## Integrity and operational limits

`LABEL_SECURITY_INFORMATION` is attempted separately through the existing
read-control handle. Failure produces a warning, never a loss of basic DACL
analysis. Returned mandatory label SIDs and no-write-up/no-read-up/no-execute-up
policy bits are reported. The process token's integrity SID is also reported.
No explicit label returned is not equivalent to no mandatory integrity policy:
Windows defaults may apply. No complete SACL is requested and no
`SeSecurityPrivilege` or other privilege is enabled.

The reported discretionary mask does not include a separate mandatory-integrity
decision. Actual operations can also depend on privileges, central policies,
parent directory delete-child access, traversal behavior, object sharing/locks,
read-only attributes, filesystem behavior, filters, and application choices.
Network shares and SMB share permissions are excluded. This tool is not an ACL
editor, repair utility, credential tool, recursive auditor or mass scanner.

## JSON

Redirected output is UTF-8. Console text uses Unicode Windows console output.
`--json` emits one document with `schema_version: "1.0"` and
`tool_version: "1.0.0"`. The schema is [docs/schema-v1.json](docs/schema-v1.json).
It includes target, file/directory type, owner/group SIDs, DACL state/protection,
ordered ACEs, principal/context, effective-access status/mask/rights, integrity
information, findings, limitations and warnings. Masks are eight-digit
hexadecimal strings; unavailable masks/SIDs are JSON null. ACE flags/type are
integers. Errors use the schema's separate `error` variant with a Win32 code.

`authoritative: true` must always be interpreted with `scope` and `limitations`.
Do not interpret `not-calculated` as denied access or an empty grant.

## Build, test and install

Requirements: Windows, MSVC C++17, Windows SDK, CMake 3.24+, and Ninja (or a
Visual Studio CMake generator). No third-party runtime libraries are required.
Use an x64 Visual Studio Developer Command Prompt:

```text
cmake -S . -B build-debug -G Ninja -DCMAKE_BUILD_TYPE=Debug
cmake --build build-debug
ctest --test-dir build-debug --output-on-failure
cmake -S . -B build-release -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build-release
ctest --test-dir build-release --output-on-failure
cmake --install build-release --prefix install-test
```

`NAE_ANALYZE=ON` enables MSVC `/analyze`; `/W4 /WX` is always enabled.
`NAE_ASAN=ON` enables MSVC AddressSanitizer; use RelWithDebInfo or Release
(Debug `/RTC` is incompatible with ASan). Run ASan tests with the MSVC runtime
directory on PATH (or copy the matching runtime DLL beside the ASan executables).
CMake's compile database supports clang-tidy; Cppcheck can
inspect the Win32 sources independently. The validation report documents the
actual configurations and findings rather than assuming tool availability.

Tests build synthetic descriptors and compare selected Authz results with
independent Windows `AccessCheck`. Integration tests create uniquely named
temporary directories **inside the test working directory**, apply controlled
ACLs only there, retain a restoration handle for the denied-access fixture,
restore it, and clean up. Test binaries intentionally mutate only their own
disposable fixtures. This is distinct from the strictly read-only production
executable. Run tests from a writable local NTFS area. Use
`NAE_TEST_ARTIFACTS` to an existing directory to preserve JSON reports for an
independent parser. `tools/validate-json.ps1` validates them with PowerShell's
independent JSON/schema parser; the application never invokes PowerShell.

Supported design targets: Windows 10, Windows 11 and corresponding Windows
Server 2016/2019/2022/2025 generations still supported by Microsoft. Primary
validation is Windows Server 2025 x64. See [VALIDATION.md](VALIDATION.md) for
measured coverage and platform gaps. Install the appropriate Microsoft Visual
C++ runtime on deployment machines. License: [MIT](LICENSE).

## Windows API references

- [AuthzInitializeContextFromToken](https://learn.microsoft.com/en-us/windows/win32/api/authz/nf-authz-authzinitializecontextfromtoken)
- [Authz access checks](https://learn.microsoft.com/en-us/windows/win32/secauthz/checking-access-with-authz-api)
- [How DACLs control access](https://learn.microsoft.com/en-us/windows/win32/secauthz/how-dacls-control-access-to-an-object)
- [Security information and required rights](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-information)
- [AuthzInitializeResourceManagerEx and central-policy flags](https://learn.microsoft.com/en-us/windows/win32/api/authz/nf-authz-authzinitializeresourcemanagerex)

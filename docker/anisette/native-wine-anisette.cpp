// Modified by Alex Mextner on 2026-10-30: split `main` into loadRuntime, ensureProvisioned and anisetteJson (behaviour unchanged).
// Based on hinatamaxxx/AltServer-Linux anisette/icloud-wine (AGPL-3.0, commit 6272cce175413ee64d0baead62683b2b9ba0f83c).
// Standalone native iCloud anisette helper for an isolated Wine prefix.
// ABI reference: AltServer-Windows AnisetteDataManager.cpp, iCloud_main 261.7.0.49.
// No account credentials, binary patching, or client-identity swizzling.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winver.h>
#include <wincrypt.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iterator>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>

using Object = void*;
using GetClass = Object(__cdecl*)(const char*);
using GetSelector = Object(__cdecl*)(const char*);
using Message = Object(__cdecl*)(Object, Object);
static GetClass getClass;
static GetSelector selector;
static Message message;

// Export-relative offsets for iCloud_main.dll 261.7.0.49 (anchor: PL_FreeArenaPool).
static const uintptr_t kCopyAnisette = 0x241ee0 - 0x1aa2a0;
static const uintptr_t kProvision = 0x245ef0 - 0x1aaea0;
static const uintptr_t kDeviceId = 0x23d8b0 - 0x1aa2a0;
static const uintptr_t kLocalUserId = 0x23db30 - 0x1aa2a0;
static const uintptr_t kClientInfo = 0x23e730 - 0x1aa2a0;

static Object send(Object obj, const char* name) {
    if (!obj) throw std::runtime_error("null_object");
    return message(obj, selector(name));
}
static Object stringObject(const char* text) {
    using Function = Object(__cdecl*)(Object, Object, const char*);
    return reinterpret_cast<Function>(message)(getClass("NSString"), selector("stringWithUTF8String:"), text);
}
static std::string text(Object obj) {
    using Function = const char*(__cdecl*)(Object, Object);
    if (!obj) throw std::runtime_error("missing_value");
    const char* value = reinterpret_cast<Function>(message)(obj, selector("UTF8String"));
    if (!value) throw std::runtime_error("missing_utf8_value");
    size_t length = strnlen(value, 16385);
    if (!length || length > 16384) throw std::runtime_error("invalid_value_size");
    return std::string(value, length);
}
static Object item(Object dict, const char* key) {
    using Function = Object(__cdecl*)(Object, Object, Object);
    return reinterpret_cast<Function>(message)(dict, selector("objectForKey:"), stringObject(key));
}
static int code(Object error) {
    using Function = int(__cdecl*)(Object, Object);
    return reinterpret_cast<Function>(message)(error, selector("code"));
}
static std::string quote(const std::string& value) {
    std::string result = "\"";
    for (unsigned char character : value) {
        if (character == '"' || character == '\\') { result += '\\'; result += character; }
        else if (character < 32) {
            char escaped[8]; std::snprintf(escaped, sizeof(escaped), "\\u%04x", character); result += escaped;
        } else result += character;
    }
    return result + '"';
}
static void requireVersion(const std::string& path) {
    DWORD unused = 0, length = GetFileVersionInfoSizeA(path.c_str(), &unused);
    if (!length) throw std::runtime_error("missing_dll_version");
    std::vector<char> data(length);
    VS_FIXEDFILEINFO* info = nullptr; UINT size = 0;
    if (!GetFileVersionInfoA(path.c_str(), 0, length, data.data()) ||
        !VerQueryValueA(data.data(), "\\", reinterpret_cast<void**>(&info), &size) ||
        !info || info->dwFileVersionMS != ((261u << 16) | 7u) || info->dwFileVersionLS != 49u)
        throw std::runtime_error("unsupported_icloud_dll_version");
}
static void importRoot(const char* path) {
    // Apple's GSA endpoints chain to Apple's own root; verification stays enabled.
    std::ifstream file(path, std::ios::binary);
    std::vector<unsigned char> certificate((std::istreambuf_iterator<char>(file)), {});
    if (certificate.empty() || certificate.size() > 20000)
        throw std::runtime_error("apple_certificate_unavailable");
    HCERTSTORE certificates = CertOpenSystemStoreA(0, "ROOT");
    if (!certificates || !CertAddEncodedCertificateToStore(certificates, X509_ASN_ENCODING,
            certificate.data(), static_cast<DWORD>(certificate.size()), CERT_STORE_ADD_USE_EXISTING, nullptr))
        throw std::runtime_error("apple_certificate_import_failed");
    CertCloseStore(certificates, 0);
}
static void reportProvisioningError(Object error) {
    for (int depth = 0; error && depth < 4; ++depth) {
        std::string domain = text(send(error, "domain"));
        bool safe = domain.size() <= 128;
        for (unsigned char c : domain)
            safe = safe && ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                            (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-');
        // Domain/code are fixed identifiers; localized descriptions stay hidden.
        if (safe) std::fprintf(stderr, "Native provisioning error: domain=%s code=%d\n", domain.c_str(), code(error));
        error = item(send(error, "userInfo"), "NSUnderlyingError");
    }
}

// Loads Apple's libraries from `root` and returns the address of the PL_FreeArenaPool export
// that every private offset above is relative to.
static uintptr_t loadRuntime(const std::string& root) {
    std::string support = root + "\\Apple Application Support";
    std::string internet = root + "\\Internet Services";
    std::string mainPath = internet + "\\iCloud_main.dll";
    requireVersion(mainPath);
    if (!SetCurrentDirectoryA(support.c_str()) || !SetDllDirectoryA(support.c_str()))
        throw std::runtime_error("dll_directory_unavailable");
    HMODULE objc = LoadLibraryA((support + "\\objc.dll").c_str());
    HMODULE foundation = LoadLibraryA((support + "\\Foundation.dll").c_str());
    HMODULE aos = LoadLibraryA((internet + "\\AOSKit.dll").c_str());
    HMODULE mainDll = LoadLibraryA(mainPath.c_str());
    if (!objc || !foundation || !aos || !mainDll) throw std::runtime_error("apple_dll_load_failed");
    if (!LoadLibraryA((support + "\\CoreADI.dll").c_str())) {
        std::fprintf(stderr, "Native loader error: code=%lu\n", GetLastError());
        throw std::runtime_error("coreadi_dll_load_failed");
    }
    getClass = reinterpret_cast<GetClass>(reinterpret_cast<void*>(GetProcAddress(objc, "objc_getClass")));
    selector = reinterpret_cast<GetSelector>(reinterpret_cast<void*>(GetProcAddress(objc, "sel_registerName")));
    message = reinterpret_cast<Message>(reinterpret_cast<void*>(GetProcAddress(objc, "objc_msgSend")));
    auto anchor = reinterpret_cast<uintptr_t>(GetProcAddress(mainDll, "PL_FreeArenaPool"));
    if (!getClass || !selector || !message || !anchor) throw std::runtime_error("missing_dll_export");
    return anchor;
}

// Makes sure this Wine prefix holds a provisioned ADI identity, provisioning it once if it does not.
static void ensureProvisioned(uintptr_t anchor) {
    using Copy = Object(__cdecl*)(void*, int, Object*);
    using Provision = unsigned char(__cdecl*)(Object, Object*);
    Object error = nullptr;
    Object provisioned = reinterpret_cast<Copy>(anchor + kCopyAnisette)(nullptr, 1, &error);
    if (!provisioned && error) {
        Object underlying = item(send(error, "userInfo"), "NSUnderlyingError");
        if (underlying && text(send(underlying, "domain")) == "AKUnderlyingADIErrors" && code(underlying) == -45061) {
            // A clean prefix is not provisioned yet (ADI -45061). The native Copy
            // routine skips initial provisioning without iCloud preferences, so call
            // the provisioning routine (x86 cdecl, two arguments) directly once.
            error = nullptr;
            if (reinterpret_cast<Provision>(anchor + kProvision)(nullptr, &error)) {
                error = nullptr;
                provisioned = reinterpret_cast<Copy>(anchor + kCopyAnisette)(nullptr, 1, &error);
            }
        }
    }
    if (!provisioned) {
        reportProvisioningError(error);
        throw std::runtime_error("native_provisioning_failed");
    }
}

static std::string anisetteJson(uintptr_t anchor) {
    using Info = Object(__cdecl*)(Object);
    using Hardware = Object(__cdecl*)();
    using FetchHeaders = Object(__cdecl*)(Object, Object, Object);
    Object headers = reinterpret_cast<FetchHeaders>(message)(getClass("AOSUtilities"),
        selector("retrieveOTPHeadersForDSID:"), stringObject("-2"));
    if (!headers) throw std::runtime_error("native_headers_missing");
    std::map<std::string, std::string> values = {
        {"X-Apple-I-MD-M", text(item(headers, "X-Apple-MD-M"))},
        {"X-Apple-I-MD", text(item(headers, "X-Apple-MD"))},
        {"X-Apple-I-MD-LU", text(reinterpret_cast<Hardware>(anchor + kLocalUserId)())},
        {"X-Mme-Device-Id", text(reinterpret_cast<Hardware>(anchor + kDeviceId)())},
        {"X-MMe-Client-Info", text(reinterpret_cast<Info>(anchor + kClientInfo)(nullptr))},
        // Official Windows AltServer's fixed values (verified against its response).
        {"X-Apple-I-MD-RINFO", "84215040"}, {"X-Apple-I-SRL-NO", "C02LKHBBFD57"},
        {"X-Apple-Locale", "en_US"}, {"X-Apple-I-TimeZone", "UTC"}
    };
    SYSTEMTIME now; GetSystemTime(&now); char date[32];
    std::snprintf(date, sizeof(date), "%04u-%02u-%02uT%02u:%02u:%02uZ", now.wYear, now.wMonth, now.wDay,
                  now.wHour, now.wMinute, now.wSecond);
    values["X-Apple-I-Client-Time"] = date;
    std::string json = "{"; bool first = true;
    for (const auto& entry : values) {
        if (!first) json += ',';
        first = false;
        json += quote(entry.first) + ':' + quote(entry.second);
    }
    return json + '}';
}

int main(int argc, char** argv) {
    try {
        if (argc < 2 || argc > 3) throw std::runtime_error("apple_root_argument_required");
        if (argc == 3) importRoot(argv[2]);
        uintptr_t anchor = loadRuntime(argv[1]);
        Object pool = send(send(getClass("NSAutoreleasePool"), "alloc"), "init");
        ensureProvisioned(anchor);
        std::string json = anisetteJson(anchor);
        // The caller consumes stdout privately; never redirect it into service logs.
        std::fputs(json.c_str(), stdout); std::fputc('\n', stdout);
        send(pool, "drain");
        return 0;
    } catch (const std::exception& error) {
        std::fprintf(stderr, "Native anisette failure: %s\n", error.what());
        return 1;
    }
}

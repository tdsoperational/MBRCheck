#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <winioctl.h>
#include <stdint.h>
#include <sysinfoapi.h>
#include <wbemidl.h>
#include <comdef.h>

#pragma comment(lib, "wbemuuid.lib")

#define MBR_SIZE 512

typedef struct {
    uint32_t h[8];
    uint32_t total[2];
    uint32_t buflen;
    uint8_t buffer[128];
} sha256_context;

void shainit(sha256_context *ctx);
void shaupd(sha256_context *ctx, const uint8_t *data, size_t len);
void finalsha(sha256_context *ctx, uint8_t hash[32]);

static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static void shatrans(sha256_context *ctx, const uint8_t data[64]) {
    uint32_t a, b, c, d, e, f, g, h, s0, s1, T1, T2, W[64];
    int i;

    for (i = 0; i < 16; ++i) {
        W[i] = (uint32_t)data[4 * i] << 24;
        W[i] |= (uint32_t)data[4 * i + 1] << 16;
        W[i] |= (uint32_t)data[4 * i + 2] << 8;
        W[i] |= (uint32_t)data[4 * i + 3];
    }

    for (; i < 64; ++i) {
        s0 = (W[i - 15] >> 7 | W[i - 15] << (32 - 7)) ^ (W[i - 15] >> 18 | W[i - 15] << (32 - 18)) ^ (W[i - 15] >> 3);
        s1 = (W[i - 2] >> 17 | W[i - 2] << (32 - 17)) ^ (W[i - 2] >> 19 | W[i - 2] << (32 - 19)) ^ (W[i - 2] >> 10);
        W[i] = W[i - 16] + s0 + W[i - 7] + s1;
    }

    a = ctx->h[0];
    b = ctx->h[1];
    c = ctx->h[2];
    d = ctx->h[3];
    e = ctx->h[4];
    f = ctx->h[5];
    g = ctx->h[6];
    h = ctx->h[7];

    for (i = 0; i < 64; ++i) {
        s1 = (e >> 6 | e << (32 - 6)) ^ (e >> 11 | e << (32 - 11)) ^ (e >> 25 | e << (32 - 25));
        T1 = h + s1 + ((e & f) ^ (~e & g)) + K[i] + W[i];
        s0 = (a >> 2 | a << (32 - 2)) ^ (a >> 13 | a << (32 - 13)) ^ (a >> 22 | a << (32 - 22));
        T2 = s0 + ((a & b) ^ (a & c) ^ (b & c));
        h = g;
        g = f;
        f = e;
        e = d + T1;
        d = c;
        c = b;
        b = a;
        a = T1 + T2;
    }

    ctx->h[0] += a;
    ctx->h[1] += b;
    ctx->h[2] += c;
    ctx->h[3] += d;
    ctx->h[4] += e;
    ctx->h[5] += f;
    ctx->h[6] += g;
    ctx->h[7] += h;
}

void shainit(sha256_context *ctx) {
    ctx->h[0] = 0x6a09e667;
    ctx->h[1] = 0xbb67ae85;
    ctx->h[2] = 0x3c6ef372;
    ctx->h[3] = 0xa54ff53a;
    ctx->h[4] = 0x510e527f;
    ctx->h[5] = 0x9b05688c;
    ctx->h[6] = 0x1f83d9ab;
    ctx->h[7] = 0x5be0cd19;

    ctx->total[0] = ctx->total[1] = 0;
    ctx->buflen = 0;
}

void shaupd(sha256_context *ctx, const uint8_t *data, size_t len) {
    size_t fill = 64 - ctx->buflen;
    ctx->total[0] += len;
    if (ctx->total[0] < len) ctx->total[1]++;
    if (ctx->buflen && len >= fill) {
        memcpy(ctx->buffer + ctx->buflen, data, fill);
        shatrans(ctx, ctx->buffer);
        data += fill;
        len -= fill;
        ctx->buflen = 0;
    }
    while (len >= 64) {
        shatrans(ctx, data);
        data += 64;
        len -= 64;
    }
    if (len) {
        memcpy(ctx->buffer + ctx->buflen, data, len);
        ctx->buflen += len;
    }
}

void finalsha(sha256_context *ctx, uint8_t hash[32]) {
    static const uint8_t pad[64] = { 0x80 };
    uint8_t msglen[8];
    uint32_t high = (ctx->total[0] >> 29) | (ctx->total[1] << 3);
    uint32_t low = ctx->total[0] << 3;

    msglen[0] = (uint8_t)(high >> 24);
    msglen[1] = (uint8_t)(high >> 16);
    msglen[2] = (uint8_t)(high >> 8);
    msglen[3] = (uint8_t)(high);
    msglen[4] = (uint8_t)(low >> 24);
    msglen[5] = (uint8_t)(low >> 16);
    msglen[6] = (uint8_t)(low >> 8);
    msglen[7] = (uint8_t)(low);

    shaupd(ctx, pad, 1 + ((119 - (ctx->total[0] % 64)) % 64));
    shaupd(ctx, msglen, 8);

    for (int i = 0; i < 8; i++) {
        hash[i * 4] = (uint8_t)(ctx->h[i] >> 24);
        hash[i * 4 + 1] = (uint8_t)(ctx->h[i] >> 16);
        hash[i * 4 + 2] = (uint8_t)(ctx->h[i] >> 8);
        hash[i * 4 + 3] = (uint8_t)(ctx->h[i]);
    }
}

void mrbhash(const uint8_t hash[32]) {
    for (int i = 0; i < 32; i++)
        printf("%02x", hash[i]);
    printf("\n");
}

void sysinfo() {
    SYSTEM_INFO siSysInfo;
    GetSystemInfo(&siSysInfo);

    printf("Hardware information: \n");
    printf("  Number of processors: %u\n", siSysInfo.dwNumberOfProcessors);
    printf("  Page size: %u\n", siSysInfo.dwPageSize);
    printf("  Processor type: %u\n", siSysInfo.dwProcessorType);
    printf("  Active processor mask: %u\n", siSysInfo.dwActiveProcessorMask);

    OSVERSIONINFOEX osvi;
    ZeroMemory(&osvi, sizeof(OSVERSIONINFOEX));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);

    if (GetVersionEx((OSVERSIONINFO*)&osvi)) {
        printf("Operating System Information:\n");
        printf("  OS Version: %u.%u\n", osvi.dwMajorVersion, osvi.dwMinorVersion);
        printf("  Build Number: %u\n", osvi.dwBuildNumber);
    } else {
        printf("Unable to retrieve OS information.\n");
    }

    HRESULT hres;
    hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres)) {
        printf("Failed to init COM library. Error code = 0x%X\n", hres);
        return;
    }

    hres = CoInitializeSecurity(
        NULL,
        -1,
        NULL,
        NULL,
        RPC_C_AUTHN_LEVEL_DEFAULT,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL,
        EOAC_NONE,
        NULL
    );

    if (FAILED(hres)) {
        printf("Failed to init security. Error code = 0x%X\n", hres);
        CoUninitialize();
        return;
    }

    IWbemLocator *pLoc = NULL;
    hres = CoCreateInstance(
        CLSID_WbemLocator,
        0,
        CLSCTX_INPROC_SERVER,
        IID_IWbemLocator, (LPVOID *)&pLoc);

    if (FAILED(hres)) {
        printf("Failed to create IWbemLocator object. Error code = 0x%X\n", hres);
        CoUninitialize();
        return;
    }

    IWbemServices *pSvc = NULL;
    hres = pLoc->ConnectServer(
        _bstr_t(L"ROOT\\CIMV2"),
        NULL,
        NULL,
        0,
        NULL,
        0,
        0,
        &pSvc
    );

    if (FAILED(hres)) {
        printf("Could not connect ffs. Error code = 0x%X\n", hres);
        pLoc->Release();
        CoUninitialize();
        return;
    }

    hres = CoSetProxyBlanket(
        pSvc,
        RPC_C_AUTHN_WINNT,
        RPC_C_AUTHZ_NONE,
        NULL,
        RPC_C_AUTHN_LEVEL_CALL,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL,
        EOAC_NONE
    );

    if (FAILED(hres)) {
        printf("Could not set proxy blanket... guess you gotta sleep in the cold. Error code = 0x%X\n", hres);
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return;
    }

    IEnumWbemClassObject* pEnumerator = NULL;
    hres = pSvc->ExecQuery(
        bstr_t("WQL"),
        bstr_t("SELECT Manufacturer, Name, Version FROM Win32_BIOS"),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &pEnumerator);

    if (FAILED(hres)) {
        printf("Query for BIOS info failed. Error code = 0x%X\n", hres);
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return;
    }

    IWbemClassObject *pclsObj = NULL;
    ULONG uReturn = 0;

    while (pEnumerator) {
        HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);

        if (0 == uReturn) {
            break;
        }

        VARIANT vtProp;

        hr = pclsObj->Get(L"Manufacturer", 0, &vtProp, 0, 0);
        wprintf(L"BIOS Manufacturer: %s\n", vtProp.bstrVal);
        VariantClear(&vtProp);

        hr = pclsObj->Get(L"Name", 0, &vtProp, 0, 0);
        wprintf(L"BIOS Name: %s\n", vtProp.bstrVal);
        VariantClear(&vtProp);

        hr = pclsObj->Get(L"Version", 0, &vtProp, 0, 0);
        wprintf(L"BIOS Version: %s\n", vtProp.bstrVal);
        VariantClear(&vtProp);

        pclsObj->Release();
    }

    pSvc->Release();
    pLoc->Release();
    pEnumerator->Release();
    CoUninitialize();
}


int main() {
    char drive_path[256];
    DWORD bytes_read;
    uint8_t mbr[MBR_SIZE];
    uint8_t hash[32];
    HANDLE drive_handle;
    sha256_context ctx;
    int drivenum = 0;

    while (1) {
        snprintf(drive_path, sizeof(drive_path), "\\\\.\\PhysicalDrive%d", drivenum);
        drive_handle = CreateFileA(drive_path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
        if (drive_handle == INVALID_HANDLE_VALUE) {
            if (GetLastError() == ERROR_FILE_NOT_FOUND) {
                break;
            } else {
                fprintf(stderr, "Couldn't open drive %s. Did you give the program admin?\n", drive_path);
                drivenum++;
                continue;
            }
        }

        if (!ReadFile(drive_handle, mbr, MBR_SIZE, &bytes_read, NULL) || bytes_read != MBR_SIZE) {
            fprintf(stderr, "Couldn't read MBR from drive %s\n", drive_path);
            CloseHandle(drive_handle);
            drivenum++;
            continue;
        }

        CloseHandle(drive_handle);

        shainit(&ctx);
        shaupd(&ctx, mbr, MBR_SIZE);
        finalsha(&ctx, hash);

        printf("SHA-256 of MBR on %s: ", drive_path);
        mrbhash(hash);

        drivenum++;
    }

    sysinfo();

    return 0;
}
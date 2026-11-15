#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#include <winhttp.h>
#include "openssl/evp.h"
#include <vector>
#include <string>
#include <fstream>
#include <cstring>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "winhttp.lib")

bool host_download_url_to_file(const char* url, const char* dest_path, unsigned int* out_hr)
{
    if (out_hr) *out_hr = 0;
    int wlen = MultiByteToWideChar(CP_UTF8, 0, url, -1, nullptr, 0);
    if (wlen <= 0) return false;
    std::wstring wurl(wlen - 1, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, url, -1, wurl.data(), wlen);

    URL_COMPONENTS uc{};
    uc.dwStructSize = sizeof(uc);
    wchar_t host[256] = {};
    wchar_t path[1024] = {};
    uc.lpszHostName = host;
    uc.dwHostNameLength = 255;
    uc.lpszUrlPath = path;
    uc.dwUrlPathLength = 1023;
    if (!WinHttpCrackUrl(wurl.c_str(), static_cast<DWORD>(wurl.size()), 0, &uc))
    {
        if (out_hr) *out_hr = GetLastError();
        return false;
    }

    HINTERNET hSession = WinHttpOpen(L"Microsoft-Symbol-Server/10.0.0.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) { if (out_hr) *out_hr = GetLastError(); return false; }

    HINTERNET hConnect = WinHttpConnect(hSession, host, uc.nPort, 0);
    if (!hConnect) { if (out_hr) *out_hr = GetLastError(); WinHttpCloseHandle(hSession); return false; }

    DWORD flags = (uc.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hReq = WinHttpOpenRequest(hConnect, L"GET", path, nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hReq) { if (out_hr) *out_hr = GetLastError(); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return false; }

    bool ok = false;
    if (WinHttpSendRequest(hReq, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) &&
        WinHttpReceiveResponse(hReq, nullptr))
    {
        DWORD status = 0, sz = sizeof(status);
        WinHttpQueryHeaders(hReq, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &status, &sz, WINHTTP_NO_HEADER_INDEX);
        if (status == 200)
        {
            std::ofstream ofs(dest_path, std::ios::binary);
            if (ofs.good())
            {
                std::vector<char> buf(65536);
                DWORD read = 0;
                ok = true;
                while (WinHttpReadData(hReq, buf.data(), static_cast<DWORD>(buf.size()), &read) && read > 0)
                {
                    ofs.write(buf.data(), read);
                }
            }
        }
        else if (out_hr)
        {
            *out_hr = status;
        }
    }
    else if (out_hr)
    {
        *out_hr = GetLastError();
    }

    WinHttpCloseHandle(hReq);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return ok;
}

struct EVP_MD
{
    const wchar_t* alg_id;
    std::size_t digest_size;
};

struct EVP_MD_CTX
{
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    std::vector<std::uint8_t> obj;
    std::size_t digest_size = 0;
};

struct EVP_CIPHER
{
    std::size_t key_bytes;
    bool cbc;
};

struct EVP_CIPHER_CTX
{
    const EVP_CIPHER* cipher = nullptr;
    std::vector<std::uint8_t> key;
    std::vector<std::uint8_t> iv;
    std::vector<std::uint8_t> buf;
    bool encrypt = true;
    bool padding = true;
};

const EVP_MD* EVP_md5()    { static const EVP_MD m{ BCRYPT_MD5_ALGORITHM, 16 }; return &m; }
const EVP_MD* EVP_sha1()   { static const EVP_MD m{ BCRYPT_SHA1_ALGORITHM, 20 }; return &m; }
const EVP_MD* EVP_sha256() { static const EVP_MD m{ BCRYPT_SHA256_ALGORITHM, 32 }; return &m; }
const EVP_MD* EVP_sha384() { static const EVP_MD m{ BCRYPT_SHA384_ALGORITHM, 48 }; return &m; }
const EVP_MD* EVP_sha512() { static const EVP_MD m{ BCRYPT_SHA512_ALGORITHM, 64 }; return &m; }

std::size_t EVP_MD_get_size(const EVP_MD* md) { return md ? md->digest_size : 0; }

EVP_MD_CTX* EVP_MD_CTX_new() { return new EVP_MD_CTX(); }

void EVP_MD_CTX_free(EVP_MD_CTX* ctx)
{
    if (!ctx) return;
    if (ctx->hHash) BCryptDestroyHash(ctx->hHash);
    if (ctx->hAlg) BCryptCloseAlgorithmProvider(ctx->hAlg, 0);
    delete ctx;
}

int EVP_DigestInit_ex(EVP_MD_CTX* ctx, const EVP_MD* type, void*)
{
    if (!ctx || !type) return 0;
    if (ctx->hHash) { BCryptDestroyHash(ctx->hHash); ctx->hHash = nullptr; }
    if (ctx->hAlg) { BCryptCloseAlgorithmProvider(ctx->hAlg, 0); ctx->hAlg = nullptr; }
    if (BCryptOpenAlgorithmProvider(&ctx->hAlg, type->alg_id, nullptr, 0) != 0) return 0;
    DWORD objLen = 0, resLen = 0;
    BCryptGetProperty(ctx->hAlg, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&objLen), sizeof(objLen), &resLen, 0);
    ctx->obj.resize(objLen ? objLen : 512);
    ctx->digest_size = type->digest_size;
    if (BCryptCreateHash(ctx->hAlg, &ctx->hHash, ctx->obj.data(), static_cast<ULONG>(ctx->obj.size()), nullptr, 0, 0) != 0) return 0;
    return 1;
}

int EVP_DigestUpdate(EVP_MD_CTX* ctx, const void* d, std::size_t cnt)
{
    if (!ctx || !ctx->hHash) return 0;
    if (cnt == 0) return 1;
    return BCryptHashData(ctx->hHash, reinterpret_cast<PUCHAR>(const_cast<void*>(d)), static_cast<ULONG>(cnt), 0) == 0 ? 1 : 0;
}

int EVP_DigestFinal_ex(EVP_MD_CTX* ctx, unsigned char* md, unsigned int* s)
{
    if (!ctx || !ctx->hHash || !md) return 0;
    if (BCryptFinishHash(ctx->hHash, md, static_cast<ULONG>(ctx->digest_size), 0) != 0) return 0;
    if (s) *s = static_cast<unsigned int>(ctx->digest_size);
    return 1;
}

int EVP_Digest(const void* data, std::size_t count, unsigned char* md, unsigned int* size, const EVP_MD* type, void*)
{
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    int ok = EVP_DigestInit_ex(ctx, type, nullptr) && EVP_DigestUpdate(ctx, data, count) && EVP_DigestFinal_ex(ctx, md, size);
    EVP_MD_CTX_free(ctx);
    return ok;
}

const EVP_CIPHER* EVP_aes_128_cbc() { static const EVP_CIPHER c{ 16, true }; return &c; }
const EVP_CIPHER* EVP_aes_128_ecb() { static const EVP_CIPHER c{ 16, false }; return &c; }
const EVP_CIPHER* EVP_aes_192_cbc() { static const EVP_CIPHER c{ 24, true }; return &c; }
const EVP_CIPHER* EVP_aes_192_ecb() { static const EVP_CIPHER c{ 24, false }; return &c; }
const EVP_CIPHER* EVP_aes_256_cbc() { static const EVP_CIPHER c{ 32, true }; return &c; }
const EVP_CIPHER* EVP_aes_256_ecb() { static const EVP_CIPHER c{ 32, false }; return &c; }

EVP_CIPHER_CTX* EVP_CIPHER_CTX_new() { return new EVP_CIPHER_CTX(); }
void EVP_CIPHER_CTX_free(EVP_CIPHER_CTX* ctx) { delete ctx; }

int EVP_CipherInit_ex(EVP_CIPHER_CTX* ctx, const EVP_CIPHER* cipher, void*, const unsigned char* key, const unsigned char* iv, int enc)
{
    if (!ctx || !cipher || !key) return 0;
    ctx->cipher = cipher;
    ctx->key.assign(key, key + cipher->key_bytes);
    if (iv && cipher->cbc) ctx->iv.assign(iv, iv + 16);
    else ctx->iv.assign(16, 0);
    ctx->buf.clear();
    ctx->encrypt = (enc != 0);
    ctx->padding = true;
    return 1;
}

int EVP_CIPHER_CTX_set_padding(EVP_CIPHER_CTX* ctx, int pad)
{
    if (!ctx) return 0;
    ctx->padding = (pad != 0);
    return 1;
}

int EVP_CipherUpdate(EVP_CIPHER_CTX* ctx, unsigned char* out, int* outl, const unsigned char* in, int inl)
{
    if (!ctx || !outl) return 0;
    *outl = 0;
    if (in && inl > 0) ctx->buf.insert(ctx->buf.end(), in, in + inl);
    (void)out;
    return 1;
}

int EVP_CipherFinal_ex(EVP_CIPHER_CTX* ctx, unsigned char* outm, int* outl)
{
    if (!ctx || !ctx->cipher || !outl) return 0;
    *outl = 0;
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0) != 0) return 0;
    const wchar_t* mode = ctx->cipher->cbc ? BCRYPT_CHAIN_MODE_CBC : BCRYPT_CHAIN_MODE_ECB;
    BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(mode)), static_cast<ULONG>((wcslen(mode) + 1) * sizeof(wchar_t)), 0);
    BCRYPT_KEY_HANDLE hKey = nullptr;
    DWORD objLen = 0, resLen = 0;
    BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&objLen), sizeof(objLen), &resLen, 0);
    std::vector<std::uint8_t> keyObj(objLen ? objLen : 512);
    if (BCryptGenerateSymmetricKey(hAlg, &hKey, keyObj.data(), static_cast<ULONG>(keyObj.size()), ctx->key.data(), static_cast<ULONG>(ctx->key.size()), 0) != 0)
    {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return 0;
    }
    ULONG flags = ctx->padding ? BCRYPT_BLOCK_PADDING : 0;
    ULONG written = 0;
    std::vector<std::uint8_t> ivCopy = ctx->iv;
    PUCHAR ivPtr = ctx->cipher->cbc ? ivCopy.data() : nullptr;
    ULONG ivLen = ctx->cipher->cbc ? static_cast<ULONG>(ivCopy.size()) : 0;
    NTSTATUS st = ctx->encrypt
        ? BCryptEncrypt(hKey, ctx->buf.data(), static_cast<ULONG>(ctx->buf.size()), nullptr, ivPtr, ivLen, outm, static_cast<ULONG>(ctx->buf.size() + 32), &written, flags)
        : BCryptDecrypt(hKey, ctx->buf.data(), static_cast<ULONG>(ctx->buf.size()), nullptr, ivPtr, ivLen, outm, static_cast<ULONG>(ctx->buf.size() + 32), &written, flags);
    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    if (st != 0) return 0;
    *outl = static_cast<int>(written);
    return 1;
}

#pragma once
#include <cstdint>
#include <cstddef>

#define EVP_MAX_BLOCK_LENGTH 32

struct EVP_MD;
struct EVP_MD_CTX;
struct EVP_CIPHER;
struct EVP_CIPHER_CTX;

const EVP_MD* EVP_md5();
const EVP_MD* EVP_sha1();
const EVP_MD* EVP_sha256();
const EVP_MD* EVP_sha384();
const EVP_MD* EVP_sha512();

std::size_t EVP_MD_get_size(const EVP_MD* md);

EVP_MD_CTX* EVP_MD_CTX_new();
void EVP_MD_CTX_free(EVP_MD_CTX* ctx);
int EVP_DigestInit_ex(EVP_MD_CTX* ctx, const EVP_MD* type, void* impl);
int EVP_DigestUpdate(EVP_MD_CTX* ctx, const void* d, std::size_t cnt);
int EVP_DigestFinal_ex(EVP_MD_CTX* ctx, unsigned char* md, unsigned int* s);
int EVP_Digest(const void* data, std::size_t count, unsigned char* md, unsigned int* size, const EVP_MD* type, void* impl);

const EVP_CIPHER* EVP_aes_128_cbc();
const EVP_CIPHER* EVP_aes_128_ecb();
const EVP_CIPHER* EVP_aes_192_cbc();
const EVP_CIPHER* EVP_aes_192_ecb();
const EVP_CIPHER* EVP_aes_256_cbc();
const EVP_CIPHER* EVP_aes_256_ecb();

EVP_CIPHER_CTX* EVP_CIPHER_CTX_new();
void EVP_CIPHER_CTX_free(EVP_CIPHER_CTX* ctx);
int EVP_CipherInit_ex(EVP_CIPHER_CTX* ctx, const EVP_CIPHER* cipher, void* impl, const unsigned char* key, const unsigned char* iv, int enc);
int EVP_CIPHER_CTX_set_padding(EVP_CIPHER_CTX* ctx, int pad);
int EVP_CipherUpdate(EVP_CIPHER_CTX* ctx, unsigned char* out, int* outl, const unsigned char* in, int inl);
int EVP_CipherFinal_ex(EVP_CIPHER_CTX* ctx, unsigned char* outm, int* outl);

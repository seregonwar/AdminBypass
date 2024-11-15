
#include <windows.h>
#include <wincrypt.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "crypt32.lib")

typedef struct _CipherContext {
    HCRYPTPROV hProv;
    HCRYPTKEY hKey;
    BYTE* iv;
    DWORD mode;
} CipherContext;

__declspec(dllexport) CipherContext* __stdcall InitCipher(BYTE* key, DWORD keySize, BYTE* iv, DWORD mode) {
    CipherContext* ctx = (CipherContext*)malloc(sizeof(CipherContext));
    if (!ctx) return NULL;
    
    if (!CryptAcquireContext(&ctx->hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        free(ctx);
        return NULL;
    }
    
    HCRYPTHASH hHash;
    if (!CryptCreateHash(ctx->hProv, CALG_SHA_256, 0, 0, &hHash)) {
        CryptReleaseContext(ctx->hProv, 0);
        free(ctx);
        return NULL;
    }
    
    if (!CryptHashData(hHash, key, keySize, 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(ctx->hProv, 0);
        free(ctx);
        return NULL;
    }
    
    if (!CryptDeriveKey(ctx->hProv, CALG_AES_256, hHash, 0, &ctx->hKey)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(ctx->hProv, 0);
        free(ctx);
        return NULL;
    }
    
    CryptDestroyHash(hHash);
    
    if (iv) {
        ctx->iv = (BYTE*)malloc(16);
        memcpy(ctx->iv, iv, 16);
    } else {
        ctx->iv = NULL;
    }
    
    ctx->mode = mode;
    return ctx;
}

__declspec(dllexport) BYTE* __stdcall EncryptBlock(CipherContext* ctx, BYTE* data, DWORD size) {
    if (!ctx || !ctx->hKey) return NULL;
    
    BYTE* encrypted = (BYTE*)malloc(size);
    if (!encrypted) return NULL;
    
    memcpy(encrypted, data, size);
    DWORD encLen = size;
    
    if (ctx->mode == 1 && ctx->iv) { // CBC mode
        if (!CryptSetKeyParam(ctx->hKey, KP_IV, ctx->iv, 0)) {
            free(encrypted);
            return NULL;
        }
    }
    
    if (!CryptEncrypt(ctx->hKey, 0, TRUE, 0, encrypted, &encLen, size)) {
        free(encrypted);
        return NULL;
    }
    
    return encrypted;
}

__declspec(dllexport) BYTE* __stdcall DecryptBlock(CipherContext* ctx, BYTE* data, DWORD size) {
    if (!ctx || !ctx->hKey) return NULL;
    
    BYTE* decrypted = (BYTE*)malloc(size);
    if (!decrypted) return NULL;
    
    memcpy(decrypted, data, size);
    DWORD decLen = size;
    
    if (ctx->mode == 1 && ctx->iv) { // CBC mode
        if (!CryptSetKeyParam(ctx->hKey, KP_IV, ctx->iv, 0)) {
            free(decrypted);
            return NULL;
        }
    }
    
    if (!CryptDecrypt(ctx->hKey, 0, TRUE, 0, decrypted, &decLen)) {
        free(decrypted);
        return NULL;
    }
    
    return decrypted;
}

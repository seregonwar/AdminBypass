
#include <windows.h>
#include <wincrypt.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "crypt32.lib")

typedef struct _HashContext {
    HCRYPTPROV hProv;
    HCRYPTHASH hHash;
    DWORD algorithm;
} HashContext;

__declspec(dllexport) HashContext* __stdcall InitHash(DWORD algorithm) {
    HashContext* ctx = (HashContext*)malloc(sizeof(HashContext));
    if (!ctx) return NULL;
    
    if (!CryptAcquireContext(&ctx->hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        free(ctx);
        return NULL;
    }
    
    DWORD algId;
    switch(algorithm) {
        case 1: algId = CALG_MD5; break;
        case 2: algId = CALG_SHA1; break;
        case 3: algId = CALG_SHA_256; break;
        default: 
            CryptReleaseContext(ctx->hProv, 0);
            free(ctx);
            return NULL;
    }
    
    if (!CryptCreateHash(ctx->hProv, algId, 0, 0, &ctx->hHash)) {
        CryptReleaseContext(ctx->hProv, 0);
        free(ctx);
        return NULL;
    }
    
    ctx->algorithm = algorithm;
    return ctx;
}

__declspec(dllexport) BOOL __stdcall UpdateHash(HashContext* ctx, BYTE* data, DWORD length) {
    if (!ctx || !ctx->hHash) return FALSE;
    return CryptHashData(ctx->hHash, data, length, 0);
}

__declspec(dllexport) BYTE* __stdcall FinalizeHash(HashContext* ctx) {
    if (!ctx || !ctx->hHash) return NULL;
    
    DWORD hashLen;
    DWORD paramLen = sizeof(DWORD);
    CryptGetHashParam(ctx->hHash, HP_HASHSIZE, (BYTE*)&hashLen, &paramLen, 0);
    
    BYTE* hash = (BYTE*)malloc(hashLen);
    if (!hash) return NULL;
    
    if (!CryptGetHashParam(ctx->hHash, HP_HASHVAL, hash, &hashLen, 0)) {
        free(hash);
        return NULL;
    }
    
    CryptDestroyHash(ctx->hHash);
    CryptReleaseContext(ctx->hProv, 0);
    free(ctx);
    
    return hash;
}

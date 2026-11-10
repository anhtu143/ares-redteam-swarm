#include <stdio.h>
#include <stdint.h>

static uint32_t djb2(const char* s) {
    uint32_t h = 5381;
    while (*s) h = ((h << 5) + h) + (unsigned char)*s++;
    return h;
}

int main() {
    const char* names[] = {
        "WinHttpOpen", "WinHttpConnect", "WinHttpOpenRequest",
        "WinHttpSendRequest", "WinHttpReceiveResponse",
        "WinHttpQueryDataAvailable", "WinHttpReadData",
        "WinHttpCloseHandle", "WinHttpSetOption",
        "WinHttpAddRequestHeaders", "WinHttpQueryHeaders",
        "CryptUnprotectData", "CryptStringToBinaryA",
        "BCryptOpenAlgorithmProvider", "BCryptSetProperty",
        "BCryptGenerateSymmetricKey", "BCryptDecrypt",
        "BCryptDestroyKey", "BCryptCloseAlgorithmProvider",
        "EtwEventWrite",
        NULL
    };
    for (int i = 0; names[i]; i++) {
        printf("#define H_%-35s 0x%08x\n", names[i], djb2(names[i]));
    }
    return 0;
}

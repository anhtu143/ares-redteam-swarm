#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
int main(void) {
    DWORD pid = 0;
    HANDLE s = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W pe = { sizeof(pe) };
    if (Process32FirstW(s, &pe)) do {
        if (_wcsicmp(pe.szExeFile, L"chrome.exe") == 0 && (!pid || pe.th32ProcessID < pid))
            pid = pe.th32ProcessID;
    } while (Process32NextW(s, &pe));
    CloseHandle(s);
    printf("PID: %lu\n", pid);
    HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY bsp = {0};
    if (GetProcessMitigationPolicy(h, ProcessSignaturePolicy, &bsp, sizeof(bsp))) {
        printf("MSOnly: %d, StoreOnly: %d, OptIn: %d, Flags: 0x%08lX\n",
            bsp.MicrosoftSignedOnly, bsp.StoreSignedOnly, bsp.MitigationOptIn, bsp.Flags);
        if (bsp.MicrosoftSignedOnly || bsp.MitigationOptIn)
            printf("[!] CIG ENABLED\n");
        else
            printf("[+] CIG NOT enforced\n");
    } else printf("Policy err: %lu\n", GetLastError());
    CloseHandle(h); return 0;
}

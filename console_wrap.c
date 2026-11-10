#include <windows.h>
#include <stdio.h>

extern int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int);

int main(int argc, char** argv) {
    printf("[ARES] Starting in console debug mode...\n");
    fflush(stdout);
    int ret = WinMain(GetModuleHandleA(NULL), NULL, "", SW_HIDE);
    printf("[ARES] WinMain returned: %d\n", ret);
    return ret;
}

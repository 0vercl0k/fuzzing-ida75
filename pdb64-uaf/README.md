# Use-after-free in pdb64

Reproduction steps:
```
mklink /H pdb-test.pdb crash-EXCEPTION_ACCESS_VIOLATION_READ-5dbe92d5
windbgx -g "c:\Program Files\IDA Pro 7.5\ida64.exe" -B pdb-test.exe
```

Output from windbg:
```
pdb64+0x392d5:
00000000`572092d5 837a5400        cmp     dword ptr [rdx+54h],0 ds:0000016c`cfca39ec=????????

0:000> !heap -p -a 0000016c`cfca39ec
    address 0000016ccfca39ec found in
    _DPH_HEAP_ROOT @ 16cbd651000
    in free-ed allocation (  DPH_HEAP_BLOCK:         VirtAddr         VirtSize)
                                16ccf50fa28:      16ccfca2000             2000
    00007ffd87c05204 ntdll!RtlDebugFreeHeap+0x000000000000003c
    00007ffd87bb56b0 ntdll!RtlpFreeHeap+0x0000000000073d50
    00007ffd87b40810 ntdll!RtlpFreeHeapInternal+0x0000000000000790
    00007ffd87b3fc11 ntdll!RtlFreeHeap+0x0000000000000051
    00007ffd859414cb ucrtbase!_free_base+0x000000000000001b
    0000000058204302 ida64!vshow_hex_file+0x0000000000021912
    000000005817bda1 ida64!process_zipfile+0x00000000000000e1
    00000000581c58ec ida64!hexplace_t__touval+0x000000000000351c
    00000000581c4d95 ida64!hexplace_t__touval+0x00000000000029c5
    00000000581c75a2 ida64!idt_open+0x0000000000000052
    000000005810132e ida64!user2str+0x000000000000229e
    000000005810614f ida64!import_module+0x000000000000002f
    00007ffd4af56ec0 pe64+0x0000000000006ec0
    00007ffd4af5e252 pe64+0x000000000000e252
    00007ffd4af51a1b pe64+0x0000000000001a1b
    00000000581023a4 ida64!user2str+0x0000000000003314
    000000005810229e ida64!user2str+0x000000000000320e
    00000000581027a4 ida64!user2str+0x0000000000003714
    0000000058106200 ida64!load_nonbinary_file+0x0000000000000030
    00007ff6c7cf3f8d ida64_exe+0x0000000000173f8d
    00007ff6c7cf4563 ida64_exe+0x0000000000174563
    00007ff6c7bd3a9b ida64_exe+0x0000000000053a9b
    000000005801130a ida64!init_database+0x0000000000000a9a
    00007ff6c7cfa37f ida64_exe+0x000000000017a37f
    00007ff6c7cfb989 ida64_exe+0x000000000017b989
    00007ff6c7cfae1a ida64_exe+0x000000000017ae1a
    00007ff6c7cfaf52 ida64_exe+0x000000000017af52
    00007ff6c7cfaf7c ida64_exe+0x000000000017af7c
    00007ff6c7cfbccd ida64_exe+0x000000000017bccd
    00007ff6c7cfbe5f ida64_exe+0x000000000017be5f
    00007ff6c7da95e2 ida64_exe+0x00000000002295e2
    00007ffd86967bd4 kernel32!BaseThreadInitThunk+0x0000000000000014
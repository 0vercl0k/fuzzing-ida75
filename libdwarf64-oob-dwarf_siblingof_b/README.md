# Out-of-bounds in libdwarf64!dwarf_siblingof_b

Reproduction steps:
```
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ida64.exe" /v "GlobalFlag" /t REG_SZ /d "0x2000000" /f
windbgx -g "C:\Program Files\IDA Pro 7.5\ida64.exe" -B crash-EXCEPTION_ACCESS_VIOLATION-7ffe468a36b0
```

Output from windbg:
```
0:000> r
rax=0000000000000000 rbx=0000022352d7e000 rcx=0000000000000001
rdx=0000000000000000 rsi=0000022352d7a730 rdi=0000000000000001
rip=00007ffa8e0a36b0 rsp=000000f8971f6dc0 rbp=0000022352d7dfff
 r8=0000000000000000  r9=0000022350b58cef r10=0000000000000001
r11=000000f8971f6d68 r12=0000022351940fe0 r13=000000f8971f6e80
r14=000002234ceaafb0 r15=000002234ceaafc8
iopl=0         nv up ei pl nz na pe nc
cs=0033  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00010202
libdwarf64!dwarf_siblingof_b+0x1d0:
00007ffa`8e0a36b0 803b00          cmp     byte ptr [rbx],0 ds:00000223`52d7e000=??

0:000> !heap -p -a @rbx
    address 0000022352d7e000 found in
    _DPH_HEAP_ROOT @ 22327241000
    in busy allocation (  DPH_HEAP_BLOCK:         UserAddr         UserSize -         VirtAddr         VirtSize)
                             22348085750:      22352d7a730             38d0 -      22352d7a000             5000
    00007ffacdee4807 ntdll!RtlDebugAllocateHeap+0x000000000000003f
    00007ffacde949d6 ntdll!RtlpAllocateHeap+0x0000000000077ae6
    00007ffacde1babb ntdll!RtlpAllocateHeapInternal+0x00000000000001cb
    00007ffacaf22596 ucrtbase!_malloc_base+0x0000000000000036
    000000007030ef60 ida64!qalloc+0x0000000000000030
    00007ffa8e0fb03f dwarf64+0x000000000001b03f
    00007ffa8e106e02 dwarf64+0x0000000000026e02
    00007ffa8e0e27e5 dwarf64+0x00000000000027e5
    00007ffa8e0a9566 libdwarf64!dwarf_set_harmless_error_list_size+0x0000000000000176
    00007ffa8e0b6986 libdwarf64!dwarf_types_dealloc+0x00000000000007e6
    00007ffa8e0a3029 libdwarf64!dwarf_next_cu_header_c+0x0000000000000199
    00007ffa8e0a2efc libdwarf64!dwarf_next_cu_header_c+0x000000000000006c
    00007ffa8e114ce4 dwarf64+0x0000000000034ce4
    00007ffa8e130ac7 dwarf64+0x0000000000050ac7
    00007ffa8e1199dd dwarf64+0x00000000000399dd
    00007ffa8e0fb8f4 dwarf64+0x000000000001b8f4
    00007ffa8e12c4f9 dwarf64+0x000000000004c4f9
    00000000702dc809 ida64!user2bin+0x00000000000069b9
    000000006f377ea5 dbg64+0x0000000000007ea5
    00000000702dc809 ida64!user2bin+0x00000000000069b9
    00007ff70d9eeb90 ida64_exe+0x000000000018eb90
    00007ff70d92ce41 ida64_exe+0x00000000000cce41
    00007ff70d8b5729 ida64_exe+0x0000000000055729
    00007ffa8e19e27c elf64+0x000000000002e27c
    00007ffa8e1880de elf64+0x00000000000180de
    00000000702423a4 ida64!user2str+0x0000000000003314
    000000007024229e ida64!user2str+0x000000000000320e
    00000000702427a4 ida64!user2str+0x0000000000003714
    0000000070246200 ida64!load_nonbinary_file+0x0000000000000030
    00007ff70d9d3f8d ida64_exe+0x0000000000173f8d
    00007ff70d9d4563 ida64_exe+0x0000000000174563
    00007ff70d8b3a9b ida64_exe+0x0000000000053a9b

0:000> kc
 # Call Site
00 libdwarf64!dwarf_siblingof_b
01 dwarf64
02 dwarf64
03 dwarf64
04 dwarf64
05 dwarf64
06 dwarf64
07 dwarf64
08 dwarf64
09 dwarf64
0a dwarf64
0b dwarf64
0c dwarf64
0d dwarf64
0e dwarf64
0f dwarf64
10 dwarf64
```
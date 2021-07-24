# Out-of-bounds in libdwarf64!dwarf_srclines_dealloc

Reproduction steps:
```
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ida64.exe" /v "GlobalFlag" /t REG_SZ /d "0x2000000" /f
windbgx -g "C:\Program Files\IDA Pro 7.5\ida64.exe" -B crash-EXCEPTION_ACCESS_VIOLATION-7ffe552a1311
```

Output from windbg:
```
0:000> r
rax=000000f08f5f8280 rbx=0000000000000012 rcx=00007ffabc411371
rdx=000002254ff9e000 rsi=000002254ff9dff0 rdi=0000022550058fb0
rip=00007ffabc411371 rsp=000000f08f5f8258 rbp=ffffffffffffffff
 r8=0000000000000002  r9=00007ffabc410000 r10=000002254ff9e000
r11=000000f08f5f8280 r12=d000000000000000 r13=0000000000000008
r14=d0d0d0d0d0d0d0d0 r15=0000000000000026
iopl=0         nv up ei pl nz na po nc
cs=0033  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00010206
VCRUNTIME140!memcpy+0x81:
00007ffa`bc411371 0fb70a          movzx   ecx,word ptr [rdx] ds:00000225`4ff9e000=????

0:000> !heap -p -a @rdx-1
    address 000002254ff9dfff found in
    _DPH_HEAP_ROOT @ 22523b81000
    in busy allocation (  DPH_HEAP_BLOCK:         UserAddr         UserSize -         VirtAddr         VirtSize)
                             225484e6958:      2254ff9c450             1ba7 -      2254ff9c000             3000
    00007ffacdee4807 ntdll!RtlDebugAllocateHeap+0x000000000000003f
    00007ffacde949d6 ntdll!RtlpAllocateHeap+0x0000000000077ae6
    00007ffacde1babb ntdll!RtlpAllocateHeapInternal+0x00000000000001cb
    00007ffacaf22596 ucrtbase!_malloc_base+0x0000000000000036
    000000007030ef60 ida64!qalloc+0x0000000000000030
    00007ffa93e3b03f dwarf64+0x000000000001b03f
    00007ffa93e46e02 dwarf64+0x0000000000026e02
    00007ffa93e227e5 dwarf64+0x00000000000027e5
    00007ffa93de9566 libdwarf64!dwarf_set_harmless_error_list_size+0x0000000000000176
    00007ffa93dedbf3 libdwarf64!dwarf_loclist_n+0x0000000000000113
    00007ffa93e59733 dwarf64+0x0000000000039733
    00007ffa93e5c394 dwarf64+0x000000000003c394
    00007ffa93e5b972 dwarf64+0x000000000003b972
    00007ffa93e7729a dwarf64+0x000000000005729a
    00007ffa93e4535f dwarf64+0x000000000002535f
    00007ffa93e62f1f dwarf64+0x0000000000042f1f
    00007ffa93e735c8 dwarf64+0x00000000000535c8
    00007ffa93e700c3 dwarf64+0x00000000000500c3
    00007ffa93e703b6 dwarf64+0x00000000000503b6
    00007ffa93e66644 dwarf64+0x0000000000046644
    00007ffa93e6650c dwarf64+0x000000000004650c
    00007ffa93e3b9e6 dwarf64+0x000000000001b9e6
    00007ffa93e6c4f9 dwarf64+0x000000000004c4f9
    00000000702dc809 ida64!user2bin+0x00000000000069b9
    000000006f377ea5 dbg64+0x0000000000007ea5
    00000000702dc809 ida64!user2bin+0x00000000000069b9
    00007ff7d3d9eb90 ida64_exe+0x000000000018eb90
    00007ff7d3cdce41 ida64_exe+0x00000000000cce41
    00007ff7d3c65729 ida64_exe+0x0000000000055729
    00007ffa93ede27c elf64+0x000000000002e27c
    00007ffa93ec80de elf64+0x00000000000180de
    00000000702423a4 ida64!user2str+0x0000000000003314
 
0:000> kc
 # Call Site
00 VCRUNTIME140!memcpy
01 libdwarf64!dwarf_srclines_dealloc
02 libdwarf64!dwarf_loclist_n
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
11 dwarf64
12 dwarf64
13 dwarf64
14 dwarf64
15 dwarf64
16 ida64!user2bin
17 dbg64
18 ida64!user2bin
19 ida64_exe
1a ida64_exe
1b ida64_exe
1c elf64
1d elf64
1e ida64!user2str
1f ida64!user2str
20 ida64!user2str
21 ida64!load_nonbinary_file
22 ida64_exe
23 ida64_exe
24 ida64_exe
25 ida64!init_database
26 ida64_exe
27 ida64_exe
28 ida64_exe
29 ida64_exe
2a ida64_exe
2b ida64_exe
2c ida64_exe
2d ida64_exe
2e kernel32!BaseThreadInitThunk
2f ntdll!RtlUserThreadStart

--

0:000> r
rax=000000f9553f8a10 rbx=0000000000000012 rcx=00007ffabc411378
rdx=00000243977faffb rsi=00000243977faff3 rdi=00000243843f1fb0
rip=00007ffabc411378 rsp=000000f9553f8988 rbp=ffffffffffffffff
 r8=0000000000000008  r9=00007ffabc410000 r10=00000243977faffb
r11=000000f9553f8a10 r12=7491000200000000 r13=0000000000000008
r14=0000000000000000 r15=0000000000000003
iopl=0         nv up ei pl nz na po nc
cs=0033  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00010206
VCRUNTIME140!memcpy+0x88:
00007ffa`bc411378 488b0a          mov     rcx,qword ptr [rdx] ds:00000243`977faffb=????????????????

0:000> !heap -p -a @rdx-1
    address 00000243977faffa found in
    _DPH_HEAP_ROOT @ 243fedf1000
    in busy allocation (  DPH_HEAP_BLOCK:         UserAddr         UserSize -         VirtAddr         VirtSize)
                             2438aefba28:      243977fafa0               5a -      243977fa000             2000
    00007ffacdee4807 ntdll!RtlDebugAllocateHeap+0x000000000000003f
    00007ffacde949d6 ntdll!RtlpAllocateHeap+0x0000000000077ae6
    00007ffacde1babb ntdll!RtlpAllocateHeapInternal+0x00000000000001cb
    00007ffacaf22596 ucrtbase!_malloc_base+0x0000000000000036
    000000007030ef60 ida64!qalloc+0x0000000000000030
    00007ffa93e2b03f dwarf64+0x000000000001b03f
    00007ffa93e36e02 dwarf64+0x0000000000026e02
    00007ffa93e127e5 dwarf64+0x00000000000027e5
    00007ffa93dd9566 libdwarf64!dwarf_set_harmless_error_list_size+0x0000000000000176
    00007ffa93dddbf3 libdwarf64!dwarf_loclist_n+0x0000000000000113
    00007ffa93e49733 dwarf64+0x0000000000039733
    00007ffa93e4c394 dwarf64+0x000000000003c394
    00007ffa93e4b972 dwarf64+0x000000000003b972
    00007ffa93e6729a dwarf64+0x000000000005729a
    00007ffa93e3535f dwarf64+0x000000000002535f
    00007ffa93e63a51 dwarf64+0x0000000000053a51
    00007ffa93e6004a dwarf64+0x000000000005004a
    00007ffa93e531e6 dwarf64+0x00000000000431e6
    00007ffa93e635c8 dwarf64+0x00000000000535c8
    00007ffa93e6004a dwarf64+0x000000000005004a
    00007ffa93e603b6 dwarf64+0x00000000000503b6
    00007ffa93e56644 dwarf64+0x0000000000046644
    00007ffa93e5650c dwarf64+0x000000000004650c
    00007ffa93e2b9e6 dwarf64+0x000000000001b9e6
    00007ffa93e5c4f9 dwarf64+0x000000000004c4f9
    00000000702dc809 ida64!user2bin+0x00000000000069b9
    000000006f377ea5 dbg64+0x0000000000007ea5
    00000000702dc809 ida64!user2bin+0x00000000000069b9
    00007ff7d3d9eb90 ida64_exe+0x000000000018eb90
    00007ff7d3cdce41 ida64_exe+0x00000000000cce41
    00007ff7d3c65729 ida64_exe+0x0000000000055729
    00007ffa93ece27c elf64+0x000000000002e27c
 
0:000> kc
 # Call Site
00 VCRUNTIME140!memcpy
01 libdwarf64!dwarf_srclines_dealloc
02 libdwarf64!dwarf_loclist_n
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
11 dwarf64
12 ida64!user2bin
13 dbg64
14 ida64!user2bin
15 ida64_exe
16 ida64_exe
17 ida64_exe
18 elf64
19 elf64
1a ida64!user2str
1b ida64!user2str
1c ida64!user2str
1d ida64!load_nonbinary_file
1e ida64_exe
1f ida64_exe
20 ida64_exe
21 ida64!init_database
22 ida64_exe
23 ida64_exe
24 ida64_exe
25 ida64_exe
26 ida64_exe
27 ida64_exe
28 ida64_exe
29 ida64_exe
2a kernel32!BaseThreadInitThunk
2b ntdll!RtlUserThreadStart

--

0:000> r
rax=00000036b6ff8670 rbx=000000000000000a rcx=00007ffabc4113b8
rdx=0000018cb8648fff rsi=0000018cb8648ffb rdi=0000018cc5ad8fb0
rip=00007ffabc4113b8 rsp=00000036b6ff85e8 rbp=ffffffffffffffff
 r8=0000000000000004  r9=00007ffabc410000 r10=0000018cb8648fff
r11=00000036b6ff8670 r12=0000000000000000 r13=0000000000000004
r14=0000000000000000 r15=0000000000000006
iopl=0         nv up ei pl nz na po nc
cs=0033  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00010206
VCRUNTIME140!memcpy+0xc8:
00007ffa`bc4113b8 8b0a            mov     ecx,dword ptr [rdx] ds:0000018c`b8648fff=????????

0:000> !heap -p -a @rdx-1
    address 0000018cb8648ffe found in
    _DPH_HEAP_ROOT @ 18c9c071000
    in busy allocation (  DPH_HEAP_BLOCK:         UserAddr         UserSize -         VirtAddr         VirtSize)
                             18cb1f59478:      18cb8648f60               9d -      18cb8648000             2000
    00007ffacdee4807 ntdll!RtlDebugAllocateHeap+0x000000000000003f
    00007ffacde949d6 ntdll!RtlpAllocateHeap+0x0000000000077ae6
    00007ffacde1babb ntdll!RtlpAllocateHeapInternal+0x00000000000001cb
    00007ffacaf22596 ucrtbase!_malloc_base+0x0000000000000036
    000000007030ef60 ida64!qalloc+0x0000000000000030
    00007ffa93e3b03f dwarf64+0x000000000001b03f
    00007ffa93e46e02 dwarf64+0x0000000000026e02
    00007ffa93e227e5 dwarf64+0x00000000000027e5
    00007ffa93de9566 libdwarf64!dwarf_set_harmless_error_list_size+0x0000000000000176
    00007ffa93dedbf3 libdwarf64!dwarf_loclist_n+0x0000000000000113
    00007ffa93e59733 dwarf64+0x0000000000039733
    00007ffa93e62b6a dwarf64+0x0000000000042b6a
    00007ffa93e735c8 dwarf64+0x00000000000535c8
    00007ffa93e700c3 dwarf64+0x00000000000500c3
    00007ffa93e703b6 dwarf64+0x00000000000503b6
    00007ffa93e66644 dwarf64+0x0000000000046644
    00007ffa93e6650c dwarf64+0x000000000004650c
    00007ffa93e3b9e6 dwarf64+0x000000000001b9e6
    00007ffa93e6c4f9 dwarf64+0x000000000004c4f9
    00000000702dc809 ida64!user2bin+0x00000000000069b9
    000000006f377ea5 dbg64+0x0000000000007ea5
    00000000702dc809 ida64!user2bin+0x00000000000069b9
    00007ff7d3d9eb90 ida64_exe+0x000000000018eb90
    00007ff7d3cdce41 ida64_exe+0x00000000000cce41
    00007ff7d3c65729 ida64_exe+0x0000000000055729
    00007ffa93ede27c elf64+0x000000000002e27c
    00007ffa93ec80de elf64+0x00000000000180de
    00000000702423a4 ida64!user2str+0x0000000000003314
    000000007024229e ida64!user2str+0x000000000000320e
    00000000702427a4 ida64!user2str+0x0000000000003714
    0000000070246200 ida64!load_nonbinary_file+0x0000000000000030
    00007ff7d3d83f8d ida64_exe+0x0000000000173f8d

0:000> kc
 # Call Site
00 VCRUNTIME140!memcpy
01 libdwarf64!dwarf_srclines_dealloc
02 libdwarf64!dwarf_loclist_n
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
11 dwarf64
12 ida64!user2bin
13 dbg64
14 ida64!user2bin
15 ida64_exe
16 ida64_exe
17 ida64_exe
18 elf64
19 elf64
1a ida64!user2str
1b ida64!user2str
1c ida64!user2str
1d ida64!load_nonbinary_file
1e ida64_exe
1f ida64_exe
20 ida64_exe
21 ida64!init_database
22 ida64_exe
23 ida64_exe
24 ida64_exe
25 ida64_exe
26 ida64_exe
27 ida64_exe
28 ida64_exe
29 ida64_exe
2a kernel32!BaseThreadInitThunk
2b ntdll!RtlUserThreadStart
```
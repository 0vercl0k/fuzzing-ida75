# Out-of-bounds in libdwarf64!dwarf_types_dealloc

Reproduction steps:
```
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ida64.exe" /v "GlobalFlag" /t REG_SZ /d "0x2000000" /f
windbgx -g "C:\Program Files\IDA Pro 7.5\ida64.exe" -B crash-EXCEPTION_ACCESS_VIOLATION-7ffe468b6a2c
```

Output from windbg:
```
0:000> r
rax=00000000000000d0 rbx=000000b8f51f7e70 rcx=000000b8f51f7e70
rdx=0000025cb5e68ffe rsi=0000025cb5e68ffa rdi=0000025cab5b2fb0
rip=00007ffa93d66a2c rsp=000000b8f51f7dc0 rbp=ffffffffffffffff
 r8=0000000000000004  r9=000000b8f51f7eb4 r10=0000025ca4584fc0
r11=0000025ca4584fc0 r12=0000000001a00001 r13=0000000000000004
r14=0000000000000000 r15=0000000000000008
iopl=0         nv up ei pl zr na po nc
cs=0033  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00010246
libdwarf64!dwarf_types_dealloc+0x88c:
00007ffa`93d66a2c 0fb64202        movzx   eax,byte ptr [rdx+2] ds:0000025c`b5e69000=??

0:000> !heap -p -a @rdx
    address 0000025cb5e68ffe found in
    _DPH_HEAP_ROOT @ 25c938c1000
    in busy allocation (  DPH_HEAP_BLOCK:         UserAddr         UserSize -         VirtAddr         VirtSize)
                             25ca375ca90:      25cb5e67d90             126e -      25cb5e67000             3000
    00007ffacdee4807 ntdll!RtlDebugAllocateHeap+0x000000000000003f
    00007ffacde949d6 ntdll!RtlpAllocateHeap+0x0000000000077ae6
    00007ffacde1babb ntdll!RtlpAllocateHeapInternal+0x00000000000001cb
    00007ffacaf22596 ucrtbase!_malloc_base+0x0000000000000036
    000000007030ef60 ida64!qalloc+0x0000000000000030
    00007ffa93dab03f dwarf64+0x000000000001b03f
    00007ffa93db6e02 dwarf64+0x0000000000026e02
    00007ffa93d927e5 dwarf64+0x00000000000027e5
    00007ffa93d59566 libdwarf64!dwarf_set_harmless_error_list_size+0x0000000000000176
    00007ffa93d5dbf3 libdwarf64!dwarf_loclist_n+0x0000000000000113
    00007ffa93dc9733 dwarf64+0x0000000000039733
    00007ffa93dcc394 dwarf64+0x000000000003c394
    00007ffa93dcb972 dwarf64+0x000000000003b972
    00007ffa93de729a dwarf64+0x000000000005729a
    00007ffa93db535f dwarf64+0x000000000002535f
    00007ffa93dd2f1f dwarf64+0x0000000000042f1f
    00007ffa93de35c8 dwarf64+0x00000000000535c8
    00007ffa93de00c3 dwarf64+0x00000000000500c3
    00007ffa93de03b6 dwarf64+0x00000000000503b6
    00007ffa93dd6644 dwarf64+0x0000000000046644
    00007ffa93dd650c dwarf64+0x000000000004650c
    00007ffa93dab9e6 dwarf64+0x000000000001b9e6
    00007ffa93ddc4f9 dwarf64+0x000000000004c4f9
    00000000702dc809 ida64!user2bin+0x00000000000069b9
    000000006f5b7ea5 dbg64+0x0000000000007ea5
    00000000702dc809 ida64!user2bin+0x00000000000069b9
    00007ff7d3d9eb90 ida64_exe+0x000000000018eb90
    00007ff7d3cdce41 ida64_exe+0x00000000000cce41
    00007ff7d3c65729 ida64_exe+0x0000000000055729
    00007ffa93e9e27c elf64+0x000000000002e27c
    00007ffa93e880de elf64+0x00000000000180de
    00000000702423a4 ida64!user2str+0x0000000000003314
 
0:000> kc
 # Call Site
00 libdwarf64!dwarf_types_dealloc
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
16 dwarf64
17 dwarf64
18 ida64!user2bin
19 dbg64
1a ida64!user2bin
1b ida64_exe
1c ida64_exe
1d ida64_exe
1e elf64
1f elf64
20 ida64!user2str
21 ida64!user2str
22 ida64!user2str
23 ida64!load_nonbinary_file
24 ida64_exe
25 ida64_exe
26 ida64_exe
27 ida64!init_database
28 ida64_exe
29 ida64_exe
2a ida64_exe
2b ida64_exe
2c ida64_exe
2d ida64_exe
2e ida64_exe
2f ida64_exe
30 kernel32!BaseThreadInitThunk
31 ntdll!RtlUserThreadStart

--

0:000> r
rax=0000000000000000 rbx=0000005b97bf8550 rcx=0000005b97bf8550
rdx=0000015ca2a0d000 rsi=0000015ca2a0cff8 rdi=0000015c94c9efb0
rip=00007ffa93d66a8d rsp=0000005b97bf8500 rbp=ffffffffffffffff
 r8=0000000000000002  r9=0000005b97bf85f4 r10=0000015ca4d40fc0
r11=0000015ca4d40fc0 r12=0000000003000002 r13=0000000000000004
r14=00000000b20e00d0 r15=0000000000000001
iopl=0         nv up ei pl zr na po nc
cs=0033  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00010246
libdwarf64!dwarf_types_dealloc+0x8ed:
00007ffa`93d66a8d 0fb602          movzx   eax,byte ptr [rdx] ds:0000015c`a2a0d000=??

0:000> !heap -p -a @rdx
    address 0000015ca2a0d000 found in
    _DPH_HEAP_ROOT @ 15cfab51000
    in busy allocation (  DPH_HEAP_BLOCK:         UserAddr         UserSize -         VirtAddr         VirtSize)
                             15c9f7764e0:      15ca2a0c220              ddf -      15ca2a0c000             2000
    00007ffacdee4807 ntdll!RtlDebugAllocateHeap+0x000000000000003f
    00007ffacde949d6 ntdll!RtlpAllocateHeap+0x0000000000077ae6
    00007ffacde1babb ntdll!RtlpAllocateHeapInternal+0x00000000000001cb
    00007ffacaf22596 ucrtbase!_malloc_base+0x0000000000000036
    000000007030ef60 ida64!qalloc+0x0000000000000030
    00007ffa93dab03f dwarf64+0x000000000001b03f
    00007ffa93db6e02 dwarf64+0x0000000000026e02
    00007ffa93d927e5 dwarf64+0x00000000000027e5
    00007ffa93d59566 libdwarf64!dwarf_set_harmless_error_list_size+0x0000000000000176
    00007ffa93d5dbf3 libdwarf64!dwarf_loclist_n+0x0000000000000113
    00007ffa93dc9733 dwarf64+0x0000000000039733
    00007ffa93dcc394 dwarf64+0x000000000003c394
    00007ffa93dcb972 dwarf64+0x000000000003b972
    00007ffa93de729a dwarf64+0x000000000005729a
    00007ffa93db535f dwarf64+0x000000000002535f
    00007ffa93dd2f1f dwarf64+0x0000000000042f1f
    00007ffa93de35c8 dwarf64+0x00000000000535c8
    00007ffa93de00c3 dwarf64+0x00000000000500c3
    00007ffa93de03b6 dwarf64+0x00000000000503b6
    00007ffa93dd6644 dwarf64+0x0000000000046644
    00007ffa93dd650c dwarf64+0x000000000004650c
    00007ffa93dab9e6 dwarf64+0x000000000001b9e6
    00007ffa93ddc4f9 dwarf64+0x000000000004c4f9
    00000000702dc809 ida64!user2bin+0x00000000000069b9
    000000006f5b7ea5 dbg64+0x0000000000007ea5
    00000000702dc809 ida64!user2bin+0x00000000000069b9
    00007ff7d3d9eb90 ida64_exe+0x000000000018eb90
    00007ff7d3cdce41 ida64_exe+0x00000000000cce41
    00007ff7d3c65729 ida64_exe+0x0000000000055729
    00007ffa93e9e27c elf64+0x000000000002e27c
    00007ffa93e880de elf64+0x00000000000180de
    00000000702423a4 ida64!user2str+0x0000000000003314

0:000> kc
 # Call Site
00 libdwarf64!dwarf_types_dealloc
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
10 ida64!user2bin
11 dbg64
12 ida64!user2bin
13 ida64_exe
14 ida64_exe
15 ida64_exe
16 elf64
17 elf64
18 ida64!user2str
19 ida64!user2str
1a ida64!user2str
1b ida64!load_nonbinary_file
1c ida64_exe
1d ida64_exe
1e ida64_exe
1f ida64!init_database
20 ida64_exe
21 ida64_exe
22 ida64_exe
23 ida64_exe
24 ida64_exe
25 ida64_exe
26 ida64_exe
27 ida64_exe
28 kernel32!BaseThreadInitThunk
29 ntdll!RtlUserThreadStart

--

0:000> r
rax=00000000000000d0 rbx=00000038f6bf8870 rcx=00000038f6bf8870
rdx=00000146d9226fff rsi=00000146d9226ffb rdi=00000146d709efb0
rip=00007ffa93d46a25 rsp=00000038f6bf87c0 rbp=ffffffffffffffff
 r8=0000000000000004  r9=00000038f6bf88b4 r10=00000146d93e9fc0
r11=00000146d93e9fc0 r12=00000000dc010f05 r13=0000000000000004
r14=0000000000000000 r15=0000000000000004
iopl=0         nv up ei pl zr na po nc
cs=0033  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00010246
libdwarf64!dwarf_types_dealloc+0x885:
00007ffa`93d46a25 0fb64201        movzx   eax,byte ptr [rdx+1] ds:00000146`d9227000=??

0:000> !heap -p -a @rdx
    address 00000146d9226fff found in
    _DPH_HEAP_ROOT @ 146ad321000
    in busy allocation (  DPH_HEAP_BLOCK:         UserAddr         UserSize -         VirtAddr         VirtSize)
                             146d86fb9c0:      146d9226220              ddf -      146d9226000             2000
    00007ffacdee4807 ntdll!RtlDebugAllocateHeap+0x000000000000003f
    00007ffacde949d6 ntdll!RtlpAllocateHeap+0x0000000000077ae6
    00007ffacde1babb ntdll!RtlpAllocateHeapInternal+0x00000000000001cb
    00007ffacaf22596 ucrtbase!_malloc_base+0x0000000000000036
    000000007030ef60 ida64!qalloc+0x0000000000000030
    00007ffa93d8b03f dwarf64+0x000000000001b03f
    00007ffa93d96e02 dwarf64+0x0000000000026e02
    00007ffa93d727e5 dwarf64+0x00000000000027e5
    00007ffa93d39566 libdwarf64!dwarf_set_harmless_error_list_size+0x0000000000000176
    00007ffa93d3dbf3 libdwarf64!dwarf_loclist_n+0x0000000000000113
    00007ffa93da9733 dwarf64+0x0000000000039733
    00007ffa93dac394 dwarf64+0x000000000003c394
    00007ffa93dab972 dwarf64+0x000000000003b972
    00007ffa93dc729a dwarf64+0x000000000005729a
    00007ffa93d9535f dwarf64+0x000000000002535f
    00007ffa93db2f1f dwarf64+0x0000000000042f1f
    00007ffa93dc35c8 dwarf64+0x00000000000535c8
    00007ffa93dc00c3 dwarf64+0x00000000000500c3
    00007ffa93dc03b6 dwarf64+0x00000000000503b6
    00007ffa93db6644 dwarf64+0x0000000000046644
    00007ffa93db650c dwarf64+0x000000000004650c
    00007ffa93d8b9e6 dwarf64+0x000000000001b9e6
    00007ffa93dbc4f9 dwarf64+0x000000000004c4f9
    00000000702dc809 ida64!user2bin+0x00000000000069b9
    000000006f5b7ea5 dbg64+0x0000000000007ea5
    00000000702dc809 ida64!user2bin+0x00000000000069b9
    00007ff7d3d9eb90 ida64_exe+0x000000000018eb90
    00007ff7d3cdce41 ida64_exe+0x00000000000cce41
    00007ff7d3c65729 ida64_exe+0x0000000000055729
    00007ffa93e7e27c elf64+0x000000000002e27c
    00007ffa93e680de elf64+0x00000000000180de
    00000000702423a4 ida64!user2str+0x0000000000003314

0:000> kc
 # Call Site
00 libdwarf64!dwarf_types_dealloc
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
10 ida64!user2bin
11 dbg64
12 ida64!user2bin
13 ida64_exe
14 ida64_exe
15 ida64_exe
16 elf64
17 elf64
18 ida64!user2str
19 ida64!user2str
1a ida64!user2str
1b ida64!load_nonbinary_file
1c ida64_exe
1d ida64_exe
1e ida64_exe
1f ida64!init_database
20 ida64_exe
21 ida64_exe
22 ida64_exe
23 ida64_exe
24 ida64_exe
25 ida64_exe
26 ida64_exe
27 ida64_exe
28 kernel32!BaseThreadInitThunk
29 ntdll!RtlUserThreadStart

--

0:000> r
rax=00000000000000d0 rbx=000000e74f1f8ab0 rcx=000000e74f1f8ab0
rdx=00000287821c2fff rsi=00000287821c2ff7 rdi=00000287f415bfb0
rip=00007ffa93d66a93 rsp=000000e74f1f8a60 rbp=ffffffffffffffff
 r8=0000000000000002  r9=000000e74f1f8b54 r10=000002878ea5afe0
r11=000000e74f1f8b30 r12=0000000000045300 r13=0000000000000004
r14=0000000000000000 r15=0000000000000004
iopl=0         nv up ei pl zr na po nc
cs=0033  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00010246
libdwarf64!dwarf_types_dealloc+0x8f3:
00007ffa`93d66a93 0fb64201        movzx   eax,byte ptr [rdx+1] ds:00000287`821c3000=??

0:000> !heap -p -a @rdx
    address 00000287821c2fff found in
    _DPH_HEAP_ROOT @ 287e1bb1000
    in busy allocation (  DPH_HEAP_BLOCK:         UserAddr         UserSize -         VirtAddr         VirtSize)
                             28781066a90:      287821c2220              ddf -      287821c2000             2000
    00007ffacdee4807 ntdll!RtlDebugAllocateHeap+0x000000000000003f
    00007ffacde949d6 ntdll!RtlpAllocateHeap+0x0000000000077ae6
    00007ffacde1babb ntdll!RtlpAllocateHeapInternal+0x00000000000001cb
    00007ffacaf22596 ucrtbase!_malloc_base+0x0000000000000036
    000000007030ef60 ida64!qalloc+0x0000000000000030
    00007ffa93dab03f dwarf64+0x000000000001b03f
    00007ffa93db6e02 dwarf64+0x0000000000026e02
    00007ffa93d927e5 dwarf64+0x00000000000027e5
    00007ffa93d59566 libdwarf64!dwarf_set_harmless_error_list_size+0x0000000000000176
    00007ffa93d5dbf3 libdwarf64!dwarf_loclist_n+0x0000000000000113
    00007ffa93dc9733 dwarf64+0x0000000000039733
    00007ffa93dcc394 dwarf64+0x000000000003c394
    00007ffa93dcb972 dwarf64+0x000000000003b972
    00007ffa93de729a dwarf64+0x000000000005729a
    00007ffa93db535f dwarf64+0x000000000002535f
    00007ffa93dd2f1f dwarf64+0x0000000000042f1f
    00007ffa93de35c8 dwarf64+0x00000000000535c8
    00007ffa93de00c3 dwarf64+0x00000000000500c3
    00007ffa93de03b6 dwarf64+0x00000000000503b6
    00007ffa93dd6644 dwarf64+0x0000000000046644
    00007ffa93dd650c dwarf64+0x000000000004650c
    00007ffa93dab9e6 dwarf64+0x000000000001b9e6
    00007ffa93ddc4f9 dwarf64+0x000000000004c4f9
    00000000702dc809 ida64!user2bin+0x00000000000069b9
    000000006f5b7ea5 dbg64+0x0000000000007ea5
    00000000702dc809 ida64!user2bin+0x00000000000069b9
    00007ff7d3d9eb90 ida64_exe+0x000000000018eb90
    00007ff7d3cdce41 ida64_exe+0x00000000000cce41
    00007ff7d3c65729 ida64_exe+0x0000000000055729
    00007ffa93e9e27c elf64+0x000000000002e27c
    00007ffa93e880de elf64+0x00000000000180de
    00000000702423a4 ida64!user2str+0x0000000000003314

0:000> kc
 # Call Site
00 libdwarf64!dwarf_types_dealloc
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
10 ida64!user2bin
11 dbg64
12 ida64!user2bin
13 ida64_exe
14 ida64_exe
15 ida64_exe
16 elf64
17 elf64
18 ida64!user2str
19 ida64!user2str
1a ida64!user2str
1b ida64!load_nonbinary_file
1c ida64_exe
1d ida64_exe
1e ida64_exe
1f ida64!init_database
20 ida64_exe
21 ida64_exe
22 ida64_exe
23 ida64_exe
24 ida64_exe
25 ida64_exe
26 ida64_exe
27 ida64_exe
28 kernel32!BaseThreadInitThunk
29 ntdll!RtlUserThreadStart

--

0:000> r
rax=0000000000000009 rbx=0000013c8078f000 rcx=0000013ced7b2fe0
rdx=0000000000000008 rsi=0000013cfad52fe0 rdi=0000000000000000
rip=00007ffa938a6444 rsp=0000000e835f9510 rbp=0000000000000049
 r8=00007ffa93891c00  r9=0000000000000000 r10=0000013cfad52fd0
r11=0000013cfad52fd0 r12=0000000000000001 r13=0000013cef3d0fc0
r14=0000013ced7b0ff0 r15=0000013c8078efff
iopl=0         nv up ei pl nz na pe nc
cs=0033  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00010202
libdwarf64!dwarf_types_dealloc+0x2a4:
00007ffa`938a6444 0fb603          movzx   eax,byte ptr [rbx] ds:0000013c`8078f000=??

0:000> !heap -p -a @rbx
    address 0000013c8078f000 found in
    _DPH_HEAP_ROOT @ 13cdd781000
    in busy allocation (  DPH_HEAP_BLOCK:         UserAddr         UserSize -         VirtAddr         VirtSize)
                             13c80044af8:      13c8078ef10               f0 -      13c8078e000             2000
    00007ffacdee4807 ntdll!RtlDebugAllocateHeap+0x000000000000003f
    00007ffacde949d6 ntdll!RtlpAllocateHeap+0x0000000000077ae6
    00007ffacde1babb ntdll!RtlpAllocateHeapInternal+0x00000000000001cb
    00007ffacaf22596 ucrtbase!_malloc_base+0x0000000000000036
    000000007030ef60 ida64!qalloc+0x0000000000000030
    00007ffa938eb03f dwarf64+0x000000000001b03f
    00007ffa938f6e02 dwarf64+0x0000000000026e02
    00007ffa938d27e5 dwarf64+0x00000000000027e5
    00007ffa93899566 libdwarf64!dwarf_set_harmless_error_list_size+0x0000000000000176
    00007ffa938a6970 libdwarf64!dwarf_types_dealloc+0x00000000000007d0
    00007ffa93893029 libdwarf64!dwarf_next_cu_header_c+0x0000000000000199
    00007ffa93892efc libdwarf64!dwarf_next_cu_header_c+0x000000000000006c
    00007ffa93904ce4 dwarf64+0x0000000000034ce4
    00007ffa93920ac7 dwarf64+0x0000000000050ac7
    00007ffa939099dd dwarf64+0x00000000000399dd
    00007ffa938eb8f4 dwarf64+0x000000000001b8f4
    00007ffa9391c4f9 dwarf64+0x000000000004c4f9
    00000000702dc809 ida64!user2bin+0x00000000000069b9
    000000006f377ea5 dbg64+0x0000000000007ea5
    00000000702dc809 ida64!user2bin+0x00000000000069b9
    00007ff7d3d9eb90 ida64_exe+0x000000000018eb90
    00007ff7d3cdce41 ida64_exe+0x00000000000cce41
    00007ff7d3c65729 ida64_exe+0x0000000000055729
    00007ffa9398e27c elf64+0x000000000002e27c
    00007ffa939780de elf64+0x00000000000180de
    00000000702423a4 ida64!user2str+0x0000000000003314
    000000007024229e ida64!user2str+0x000000000000320e
    00000000702427a4 ida64!user2str+0x0000000000003714
    0000000070246200 ida64!load_nonbinary_file+0x0000000000000030
    00007ff7d3d83f8d ida64_exe+0x0000000000173f8d
    00007ff7d3d84563 ida64_exe+0x0000000000174563
    00007ff7d3c63a9b ida64_exe+0x0000000000053a9b

0:000> kc
 # Call Site
00 libdwarf64!dwarf_types_dealloc
01 libdwarf64!dwarf_siblingof_b
02 dwarf64
03 dwarf64
04 dwarf64
05 dwarf64
06 dwarf64
07 ida64!user2bin
08 dbg64
09 ida64!user2bin
0a ida64_exe
0b ida64_exe
0c ida64_exe
0d elf64
0e elf64
0f ida64!user2str
10 ida64!user2str
11 ida64!user2str
12 ida64!load_nonbinary_file
13 ida64_exe
14 ida64_exe
15 ida64_exe
16 ida64!init_database
17 ida64_exe
18 ida64_exe
19 ida64_exe
1a ida64_exe
1b ida64_exe
1c ida64_exe
1d ida64_exe
1e ida64_exe
1f kernel32!BaseThreadInitThunk
20 ntdll!RtlUserThreadStart
```
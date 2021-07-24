# Out-of-bounds in libdwarf64!dwarf_set_stringcheck

Reproduction steps:
```
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ida64.exe" /v "GlobalFlag" /t REG_SZ /d "0x2000000" /f
windbgx -g "C:\Program Files\IDA Pro 7.5\ida64.exe" -B crash-EXCEPTION_ACCESS_VIOLATION-7ffe468aab5f
```

Output from windbg:
```
0:000> r
rax=0000001c419f97c4 rbx=0000016cbd0cafff rcx=0000016cbd0cafff
rdx=00000000000000d0 rsi=0000016cbde84fe0 rdi=0000000000000000
rip=00007ffa9369ab5f rsp=0000001c419f9798 rbp=000000000000005f
 r8=0000000000000000  r9=0000016cbd0cafff r10=0000000000000001
r11=0000001c419f96d0 r12=0000000000000001 r13=0000016cc70e3fc0
r14=0000016cc0f32ff0 r15=0000016cbd0caffe
iopl=0         nv up ei ng nz na pe nc
cs=0033  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00010282
libdwarf64!dwarf_set_stringcheck+0xdaf:
00007ffa`9369ab5f 80790100        cmp     byte ptr [rcx+1],0 ds:0000016c`bd0cb000=??

0:000> !heap -p -a @rcx
    address 0000016cbd0cafff found in
    _DPH_HEAP_ROOT @ 16c9c0c1000
    in busy allocation (  DPH_HEAP_BLOCK:         UserAddr         UserSize -         VirtAddr         VirtSize)
                             16cba787d00:      16cbd0caef0              10f -      16cbd0ca000             2000
          unknown!printable
    00007ffacdee4807 ntdll!RtlDebugAllocateHeap+0x000000000000003f
    00007ffacde949d6 ntdll!RtlpAllocateHeap+0x0000000000077ae6
    00007ffacde1babb ntdll!RtlpAllocateHeapInternal+0x00000000000001cb
    00007ffacaf22596 ucrtbase!_malloc_base+0x0000000000000036
    000000007030ef60 ida64!qalloc+0x0000000000000030
    00007ffa936eb03f dwarf64+0x000000000001b03f
    00007ffa936f6e02 dwarf64+0x0000000000026e02
    00007ffa936d27e5 dwarf64+0x00000000000027e5
    00007ffa93699566 libdwarf64!dwarf_set_harmless_error_list_size+0x0000000000000176
    00007ffa936a6970 libdwarf64!dwarf_types_dealloc+0x00000000000007d0
    00007ffa93693029 libdwarf64!dwarf_next_cu_header_c+0x0000000000000199
    00007ffa93692efc libdwarf64!dwarf_next_cu_header_c+0x000000000000006c
    00007ffa93704ce4 dwarf64+0x0000000000034ce4
    00007ffa93720ac7 dwarf64+0x0000000000050ac7
    00007ffa937099dd dwarf64+0x00000000000399dd
    00007ffa936eb8f4 dwarf64+0x000000000001b8f4
    00007ffa9371c4f9 dwarf64+0x000000000004c4f9
    00000000702dc809 ida64!user2bin+0x00000000000069b9
    000000006f377ea5 dbg64+0x0000000000007ea5
    00000000702dc809 ida64!user2bin+0x00000000000069b9
    00007ff7d3d9eb90 ida64_exe+0x000000000018eb90
    00007ff7d3cdce41 ida64_exe+0x00000000000cce41
    00007ff7d3c65729 ida64_exe+0x0000000000055729
    00007ffa9378e27c elf64+0x000000000002e27c
    00007ffa937780de elf64+0x00000000000180de
    00000000702423a4 ida64!user2str+0x0000000000003314
    000000007024229e ida64!user2str+0x000000000000320e
    00000000702427a4 ida64!user2str+0x0000000000003714
    0000000070246200 ida64!load_nonbinary_file+0x0000000000000030
    00007ff7d3d83f8d ida64_exe+0x0000000000173f8d
    00007ff7d3d84563 ida64_exe+0x0000000000174563
    00007ff7d3c63a9b ida64_exe+0x0000000000053a9b
 
0:000> db @rcx l10
0000016c`bd0cafff  d0 ?? ?? ?? ?? ?? ?? ??-?? ?? ?? ?? ?? ?? ?? ??  .???????????????

--

0:000> r
rax=0000005ea9bf9404 rbx=0000016eade75ffe rcx=0000016eade75ffe
rdx=00000000000000d0 rsi=0000016eb03e6fe0 rdi=0000000000000000
rip=00007ffa96afab85 rsp=0000005ea9bf93d8 rbp=000000000000005a
 r8=00007ffa96af1c00  r9=0000016eade75ffe r10=0000000000000001
r11=0000016eb03e6fd0 r12=0000000000000001 r13=0000016eb02e9fc0
r14=0000016ea54f2ff0 r15=0000016eade75ffd
iopl=0         nv up ei ng nz na pe nc
cs=0033  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00010282
libdwarf64!dwarf_set_stringcheck+0xdd5:
00007ffa`96afab85 80790200        cmp     byte ptr [rcx+2],0 ds:0000016e`ade76000=??

0:000> !heap -p -a @rcx
    address 0000016eade75ffe found in
    _DPH_HEAP_ROOT @ 16e80001000
    in busy allocation (  DPH_HEAP_BLOCK:         UserAddr         UserSize -         VirtAddr         VirtSize)
                             16eaaf07b60:      16eade74d70             128e -      16eade74000             3000
          unknown!printable
    00007ffacdee4807 ntdll!RtlDebugAllocateHeap+0x000000000000003f
    00007ffacde949d6 ntdll!RtlpAllocateHeap+0x0000000000077ae6
    00007ffacde1babb ntdll!RtlpAllocateHeapInternal+0x00000000000001cb
    00007ffacaf22596 ucrtbase!_malloc_base+0x0000000000000036
    000000007030ef60 ida64!qalloc+0x0000000000000030
    00007ffa96b4b03f dwarf64+0x000000000001b03f
    00007ffa96b56e02 dwarf64+0x0000000000026e02
    00007ffa96b327e5 dwarf64+0x00000000000027e5
    00007ffa96af9566 libdwarf64!dwarf_set_harmless_error_list_size+0x0000000000000176
    00007ffa96b06970 libdwarf64!dwarf_types_dealloc+0x00000000000007d0
    00007ffa96af3029 libdwarf64!dwarf_next_cu_header_c+0x0000000000000199
    00007ffa96af2efc libdwarf64!dwarf_next_cu_header_c+0x000000000000006c
    00007ffa96b64ce4 dwarf64+0x0000000000034ce4
    00007ffa96b80ac7 dwarf64+0x0000000000050ac7
    00007ffa96b699dd dwarf64+0x00000000000399dd
    00007ffa96b4b8f4 dwarf64+0x000000000001b8f4
    00007ffa96b7c4f9 dwarf64+0x000000000004c4f9
    00000000702dc809 ida64!user2bin+0x00000000000069b9
    000000006f5b7ea5 dbg64+0x0000000000007ea5
    00000000702dc809 ida64!user2bin+0x00000000000069b9
    00007ff7d3d9eb90 ida64_exe+0x000000000018eb90
    00007ff7d3cdce41 ida64_exe+0x00000000000cce41
    00007ff7d3c65729 ida64_exe+0x0000000000055729
    00007ffa9388e27c elf64+0x000000000002e27c
    00007ffa938780de elf64+0x00000000000180de
    00000000702423a4 ida64!user2str+0x0000000000003314
    000000007024229e ida64!user2str+0x000000000000320e
    00000000702427a4 ida64!user2str+0x0000000000003714
    0000000070246200 ida64!load_nonbinary_file+0x0000000000000030
    00007ff7d3d83f8d ida64_exe+0x0000000000173f8d
    00007ff7d3d84563 ida64_exe+0x0000000000174563
    00007ff7d3c63a9b ida64_exe+0x0000000000053a9b
 
0:000> kc
 # Call Site
00 libdwarf64!dwarf_set_stringcheck
01 libdwarf64!dwarf_types_dealloc
02 libdwarf64!dwarf_siblingof_b
03 dwarf64
04 dwarf64
05 dwarf64
06 dwarf64
07 dwarf64
08 ida64!user2bin
09 dbg64
0a ida64!user2bin
0b ida64_exe
0c ida64_exe
0d ida64_exe
0e elf64
0f elf64
10 ida64!user2str
11 ida64!user2str
12 ida64!user2str
13 ida64!load_nonbinary_file
14 ida64_exe
15 ida64_exe
16 ida64_exe
17 ida64!init_database
18 ida64_exe
19 ida64_exe
1a ida64_exe
1b ida64_exe
1c ida64_exe
1d ida64_exe
1e ida64_exe
1f ida64_exe
20 kernel32!BaseThreadInitThunk
21 ntdll!RtlUserThreadStart

--

0:000> r
rax=00000003133f9024 rbx=0000018d55178ff1 rcx=0000000000000062
rdx=0000014000000000 rsi=0000018d6029efe0 rdi=0000000000000000
rip=00007ffa93cfac10 rsp=00000003133f8ff8 rbp=0000000000000003
 r8=00000000000000d0  r9=0000018d55178fff r10=000000000000000f
r11=50a143c78f1e3c50 r12=0000000000000003 r13=0000018d4787dfc0
r14=0000018d593a8ff0 r15=0000018d55178ff0
iopl=0         nv up ei ng nz na pe nc
cs=0033  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00010282
libdwarf64!dwarf_set_stringcheck+0xe60:
00007ffa`93cfac10 450fb64101      movzx   r8d,byte ptr [r9+1] ds:0000018d`55179000=??

0:000> !heap -p -a @r9
    address 0000018d55178fff found in
    _DPH_HEAP_ROOT @ 18d36bc1000
    in busy allocation (  DPH_HEAP_BLOCK:         UserAddr         UserSize -         VirtAddr         VirtSize)
                             18d4a5b8270:      18d55178fc0               31 -      18d55178000             2000
    00007ffacdee4807 ntdll!RtlDebugAllocateHeap+0x000000000000003f
    00007ffacde949d6 ntdll!RtlpAllocateHeap+0x0000000000077ae6
    00007ffacde1babb ntdll!RtlpAllocateHeapInternal+0x00000000000001cb
    00007ffacaf22596 ucrtbase!_malloc_base+0x0000000000000036
    000000007030ef60 ida64!qalloc+0x0000000000000030
    00007ffa93d4b03f dwarf64+0x000000000001b03f
    00007ffa93d56e02 dwarf64+0x0000000000026e02
    00007ffa93d327e5 dwarf64+0x00000000000027e5
    00007ffa93cf9566 libdwarf64!dwarf_set_harmless_error_list_size+0x0000000000000176
    00007ffa93d06970 libdwarf64!dwarf_types_dealloc+0x00000000000007d0
    00007ffa93cf3029 libdwarf64!dwarf_next_cu_header_c+0x0000000000000199
    00007ffa93cf2efc libdwarf64!dwarf_next_cu_header_c+0x000000000000006c
    00007ffa93d64ce4 dwarf64+0x0000000000034ce4
    00007ffa93d80ac7 dwarf64+0x0000000000050ac7
    00007ffa93d699dd dwarf64+0x00000000000399dd
    00007ffa93d4b8f4 dwarf64+0x000000000001b8f4
    00007ffa93d7c4f9 dwarf64+0x000000000004c4f9
    00000000702dc809 ida64!user2bin+0x00000000000069b9
    000000006f377ea5 dbg64+0x0000000000007ea5
    00000000702dc809 ida64!user2bin+0x00000000000069b9
    00007ff7d3d9eb90 ida64_exe+0x000000000018eb90
    00007ff7d3cdce41 ida64_exe+0x00000000000cce41
    00007ff7d3c65729 ida64_exe+0x0000000000055729
    00007ffa93dee27c elf64+0x000000000002e27c
    00007ffa93dd80de elf64+0x00000000000180de
    00000000702423a4 ida64!user2str+0x0000000000003314
    000000007024229e ida64!user2str+0x000000000000320e
    00000000702427a4 ida64!user2str+0x0000000000003714
    0000000070246200 ida64!load_nonbinary_file+0x0000000000000030
    00007ff7d3d83f8d ida64_exe+0x0000000000173f8d
    00007ff7d3d84563 ida64_exe+0x0000000000174563
    00007ff7d3c63a9b ida64_exe+0x0000000000053a9b

0:000> kc
 # Call Site
00 libdwarf64!dwarf_set_stringcheck
01 libdwarf64!dwarf_types_dealloc
02 libdwarf64!dwarf_siblingof_b
03 dwarf64
04 dwarf64
05 dwarf64
06 dwarf64
07 dwarf64
08 dwarf64
09 dwarf64
0a dwarf64
0b ida64!user2bin
0c dbg64
0d ida64!user2bin
0e ida64_exe
0f ida64_exe
10 ida64_exe
11 elf64
12 elf64
13 ida64!user2str
14 ida64!user2str
15 ida64!user2str
16 ida64!load_nonbinary_file
17 ida64_exe
18 ida64_exe
19 ida64_exe
1a ida64!init_database
1b ida64_exe
1c ida64_exe
1d ida64_exe
1e ida64_exe
1f ida64_exe
20 ida64_exe
21 ida64_exe
22 ida64_exe
23 kernel32!BaseThreadInitThunk
24 ntdll!RtlUserThreadStart
```
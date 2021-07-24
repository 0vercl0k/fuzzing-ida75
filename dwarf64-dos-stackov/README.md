# Stack-overflow in dwarf64

Reproduction steps:
```
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ida64.exe" /v "GlobalFlag" /t REG_SZ /d "0x2000000" /f
windbgx -g "C:\Program Files\IDA Pro 7.5\ida64.exe" -B crash-EXCEPTION_STACK_OVERFLOW-7ffe460e362f
```

Output from windbg:
```
0:000> r
rax=0000002e26c04028 rbx=0000002e26c04158 rcx=00007ffaa4bc27e7
rdx=0000002e26c04158 rsi=0000000000000005 rdi=00007ffaa4bc27e7
rip=00007ffacddfe6aa rsp=0000002e26c04000 rbp=0000002e26c04790
 r8=0000002e26c04108  r9=0000000000000003 r10=00007ffacdde0000
r11=0000000000001131 r12=00007ffacdf57e00 r13=0000002e26c04760
r14=0000000000000025 r15=0000002e26c04790
iopl=0         nv up ei ng nz na po cy
cs=0033  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00010287
ntdll!RtlpxLookupFunctionTable+0xa:
00007ffa`cddfe6aa 4156            push    r14

0:000> kpffff
 #   Memory  Child-SP          RetAddr               Call Site
00           0000002e`26c04000 00007ffa`cde0048c     ntdll!RtlpxLookupFunctionTable+0xa
01        30 0000002e`26c04030 00007ffa`cddff95b     ntdll!RtlpLookupFunctionEntryForStackWalks+0x14c
02        70 0000002e`26c040a0 00007ffa`cde542ea     ntdll!RtlpWalkFrameChain+0x3eb
03       660 0000002e`26c04700 00007ffa`cde54262     ntdll!RtlWalkFrameChain+0x2a
04        30 0000002e`26c04730 00007ffa`cdedaff4     ntdll!RtlCaptureStackBackTrace+0x42
05        30 0000002e`26c04760 00007ffa`a4bc27e7     ntdll!RtlStdLogStackTrace+0x24
06       140 0000002e`26c048a0 00007ffa`a4bc4070     verifier!AVrfpDphPlaceOnBusyList+0x3f
07        30 0000002e`26c048d0 00007ffa`cdee4807     verifier!AVrfDebugPageHeapAllocate+0x290
08        90 0000002e`26c04960 00007ffa`cde949d6     ntdll!RtlDebugAllocateHeap+0x3f
09        60 0000002e`26c049c0 00007ffa`cde1babb     ntdll!RtlpAllocateHeap+0x77ae6
0a       1e0 0000002e`26c04ba0 00007ffa`caf22596     ntdll!RtlpAllocateHeapInternal+0x1cb
0b       110 0000002e`26c04cb0 00007ffa`933f1994     ucrtbase!_malloc_base+0x36
0c        30 0000002e`26c04ce0 00007ffa`933f33de     libdwarf64!dwarf_get_abbrev_tag+0x3a4
0d        40 0000002e`26c04d20 00007ffa`934c05b8     libdwarf64!dwarf_offdie_b+0x18e
0e        60 0000002e`26c04d80 00007ffa`9348efc4     dwarf64+0x505b8
0f       1c0 0000002e`26c04f40 00007ffa`934c417d     dwarf64+0x1efc4
10       430 0000002e`26c05370 00007ffa`934c0642     dwarf64+0x5417d
11       160 0000002e`26c054d0 00007ffa`9348efc4     dwarf64+0x50642
12       1c0 0000002e`26c05690 00007ffa`93499681     dwarf64+0x1efc4
13       430 0000002e`26c05ac0 00007ffa`93491b81     dwarf64+0x29681
14        80 0000002e`26c05b40 00007ffa`934967b1     dwarf64+0x21b81
15       340 0000002e`26c05e80 00007ffa`93491bc5     dwarf64+0x267b1
...
162a       270 0000002e`26ff29d0 00007ffa`934967b1     dwarf64+0x21bc5
162b       340 0000002e`26ff2d10 00007ffa`93491bc5     dwarf64+0x267b1
162c       270 0000002e`26ff2f80 00007ffa`934967b1     dwarf64+0x21bc5
162d       340 0000002e`26ff32c0 00007ffa`93491bc5     dwarf64+0x267b1
162e       270 0000002e`26ff3530 00007ffa`934967b1     dwarf64+0x21bc5
162f       340 0000002e`26ff3870 00007ffa`93491bc5     dwarf64+0x267b1
1630       270 0000002e`26ff3ae0 00007ffa`934967b1     dwarf64+0x21bc5
1631       340 0000002e`26ff3e20 00007ffa`93491bc5     dwarf64+0x267b1
1632       270 0000002e`26ff4090 00007ffa`934967b1     dwarf64+0x21bc5
1633       340 0000002e`26ff43d0 00007ffa`93491bc5     dwarf64+0x267b1
1634       270 0000002e`26ff4640 00007ffa`934967b1     dwarf64+0x21bc5
1635       340 0000002e`26ff4980 00007ffa`93491bc5     dwarf64+0x267b1
1636       270 0000002e`26ff4bf0 00007ffa`934967b1     dwarf64+0x21bc5
1637       340 0000002e`26ff4f30 00007ffa`93491bc5     dwarf64+0x267b1
1638       270 0000002e`26ff51a0 00007ffa`934967b1     dwarf64+0x21bc5
1639       340 0000002e`26ff54e0 00007ffa`93491bc5     dwarf64+0x267b1
163a       270 0000002e`26ff5750 00007ffa`934967b1     dwarf64+0x21bc5
163b       340 0000002e`26ff5a90 00007ffa`93491bc5     dwarf64+0x267b1
163c       270 0000002e`26ff5d00 00007ffa`934967b1     dwarf64+0x21bc5
163d       340 0000002e`26ff6040 00007ffa`93491bc5     dwarf64+0x267b1
163e       270 0000002e`26ff62b0 00007ffa`934967b1     dwarf64+0x21bc5
163f       340 0000002e`26ff65f0 00007ffa`93491bc5     dwarf64+0x267b1
1640       270 0000002e`26ff6860 00007ffa`934967b1     dwarf64+0x21bc5
1641       340 0000002e`26ff6ba0 00007ffa`93491bc5     dwarf64+0x267b1
1642       270 0000002e`26ff6e10 00007ffa`934967b1     dwarf64+0x21bc5
1643       340 0000002e`26ff7150 00007ffa`93491bc5     dwarf64+0x267b1
1644       270 0000002e`26ff73c0 00007ffa`934967b1     dwarf64+0x21bc5
1645       340 0000002e`26ff7700 00007ffa`93491bc5     dwarf64+0x267b1
1646       270 0000002e`26ff7970 00007ffa`934967b1     dwarf64+0x21bc5
1647       340 0000002e`26ff7cb0 00007ffa`93491bc5     dwarf64+0x267b1
1648       270 0000002e`26ff7f20 00007ffa`934967b1     dwarf64+0x21bc5
1649       340 0000002e`26ff8260 00007ffa`93491bc5     dwarf64+0x267b1
164a       270 0000002e`26ff84d0 00007ffa`934967b1     dwarf64+0x21bc5
164b       340 0000002e`26ff8810 00007ffa`93491bc5     dwarf64+0x267b1
164c       270 0000002e`26ff8a80 00007ffa`934967b1     dwarf64+0x21bc5
164d       340 0000002e`26ff8dc0 00007ffa`934c466c     dwarf64+0x267b1
164e       270 0000002e`26ff9030 00007ffa`934c00c3     dwarf64+0x5466c
164f        60 0000002e`26ff9090 00007ffa`934c00e8     dwarf64+0x500c3
1650       290 0000002e`26ff9320 00007ffa`934c03b6     dwarf64+0x500e8
1651       290 0000002e`26ff95b0 00007ffa`934b6e83     dwarf64+0x503b6
1652        60 0000002e`26ff9610 00007ffa`934b63d9     dwarf64+0x46e83
1653       100 0000002e`26ff9710 00007ffa`9348b9e6     dwarf64+0x463d9
1654        d0 0000002e`26ff97e0 00007ffa`934bc4f9     dwarf64+0x1b9e6
1655      2b50 0000002e`26ffc330 00000000`702dc809     dwarf64+0x4c4f9
1656       8a0 0000002e`26ffcbd0 00000000`6f5b7ea5     ida64!user2bin+0x69b9
1657        a0 0000002e`26ffcc70 00000000`702dc809     dbg64+0x7ea5
1658       5d0 0000002e`26ffd240 00007ff7`d3d9eb90     ida64!user2bin+0x69b9
1659        a0 0000002e`26ffd2e0 00007ff7`d3cdce41     ida64_exe+0x18eb90
165a        70 0000002e`26ffd350 00007ff7`d3c65729     ida64_exe+0xcce41
165b       200 0000002e`26ffd550 00007ffa`9355e27c     ida64_exe+0x55729
165c       470 0000002e`26ffd9c0 00007ffa`935480de     elf64+0x2e27c
165d       6e0 0000002e`26ffe0a0 00000000`702423a4     elf64+0x180de
165e       260 0000002e`26ffe300 00000000`7024229e     ida64!user2str+0x3314
165f        40 0000002e`26ffe340 00000000`702427a4     ida64!user2str+0x320e
1660       2e0 0000002e`26ffe620 00000000`70246200     ida64!user2str+0x3714
1661        80 0000002e`26ffe6a0 00007ff7`d3d83f8d     ida64!load_nonbinary_file+0x30
1662        40 0000002e`26ffe6e0 00007ff7`d3d84563     ida64_exe+0x173f8d
1663       500 0000002e`26ffebe0 00007ff7`d3c63a9b     ida64_exe+0x174563
1664       180 0000002e`26ffed60 00000000`7015130a     ida64_exe+0x53a9b
1665       470 0000002e`26fff1d0 00007ff7`d3d8a37f     ida64!init_database+0xa9a
1666       410 0000002e`26fff5e0 00007ff7`d3d8b989     ida64_exe+0x17a37f
1667        80 0000002e`26fff660 00007ff7`d3d8ae1a     ida64_exe+0x17b989
1668        40 0000002e`26fff6a0 00007ff7`d3d8af52     ida64_exe+0x17ae1a
1669        b0 0000002e`26fff750 00007ff7`d3d8af7c     ida64_exe+0x17af52
166a        40 0000002e`26fff790 00007ff7`d3d8bccd     ida64_exe+0x17af7c
166b        40 0000002e`26fff7d0 00007ff7`d3d8be5f     ida64_exe+0x17bccd
166c       2a0 0000002e`26fffa70 00007ff7`d3e395e2     ida64_exe+0x17be5f
166d        50 0000002e`26fffac0 00007ffa`cd207bd4     ida64_exe+0x2295e2
166e        40 0000002e`26fffb00 00007ffa`cde4ced1     kernel32!BaseThreadInitThunk+0x14
166f        30 0000002e`26fffb30 00000000`00000000     ntdll!RtlUserThreadStart+0x21
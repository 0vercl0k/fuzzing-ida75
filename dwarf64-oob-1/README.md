# Out-of-bounds in dwarf64

Reproduction steps:
```
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ida64.exe" /v "GlobalFlag" /t REG_SZ /d "0x2000000" /f
windbgx -g "C:\Program Files\IDA Pro 7.5\ida64.exe" -B crash-EXCEPTION_ACCESS_VIOLATION_READ-7ff92bf28e13
```

Output from windbg:
```
This dump file has an exception of interest stored in it.
The stored exception information can be accessed via .ecxr.
(ebc.f10): Access violation - code c0000005 (first/second chance not available)
For analysis of this file, run !analyze -v
dwarf64+0x28e13:
00007fff`bff18e13 488b6cc1f8      mov     rbp,qword ptr [rcx+rax*8-8] ds:ffffffff`fffffff8=????????????????

0:000> kp
 # Child-SP          RetAddr               Call Site
00 000000a6`751f9110 00007fff`bff2c0d0     dwarf64+0x28e13
01 000000a6`751f9190 00007fff`bff14eeb     dwarf64+0x3c0d0
02 000000a6`751f9200 00007fff`bff40857     dwarf64+0x24eeb
03 000000a6`751f93e0 00007fff`bff40b96     dwarf64+0x50857
04 000000a6`751f9660 00007fff`bff36e57     dwarf64+0x50b96
05 000000a6`751f96c0 00007fff`bff36b9a     dwarf64+0x46e57
06 000000a6`751f97b0 00007fff`bff0bba6     dwarf64+0x46b9a
07 000000a6`751f9880 00007fff`bff3ccd9     dwarf64+0x1bba6
08 000000a6`751fc3d0 00000000`74cac809     dwarf64+0x4ccd9
09 000000a6`751fcc70 00000000`73d67ea5     ida64!user2bin+0x69b9
0a 000000a6`751fcd10 00000000`74cac809     dbg64+0x7ea5
0b 000000a6`751fd2e0 00007ff7`758feb90     ida64!user2bin+0x69b9
0c 000000a6`751fd380 00007ff7`7583ce41     ida64_exe+0x18eb90
0d 000000a6`751fd3f0 00007ff7`757c5729     ida64_exe+0xcce41
0e 000000a6`751fd5f0 00007fff`cb49e27c     ida64_exe+0x55729
0f 000000a6`751fda60 00007fff`cb4880de     elf64+0x2e27c
10 000000a6`751fe140 00000000`74c123a4     elf64+0x180de
11 000000a6`751fe3a0 00000000`74c1229e     ida64!user2str+0x3314
12 000000a6`751fe3e0 00000000`74c127a4     ida64!user2str+0x320e
13 000000a6`751fe6c0 00000000`74c16200     ida64!user2str+0x3714
14 000000a6`751fe740 00007ff7`758e3f8d     ida64!load_nonbinary_file+0x30
15 000000a6`751fe780 00007ff7`758e4563     ida64_exe+0x173f8d
16 000000a6`751fec80 00007ff7`757c3a9b     ida64_exe+0x174563
17 000000a6`751fee00 00000000`74b2130a     ida64_exe+0x53a9b
18 000000a6`751ff270 00007ff7`758ea37f     ida64!init_database+0xa9a
19 000000a6`751ff680 00007ff7`758eb989     ida64_exe+0x17a37f
1a 000000a6`751ff700 00007ff7`758eae1a     ida64_exe+0x17b989
1b 000000a6`751ff740 00007ff7`758eaf52     ida64_exe+0x17ae1a
1c 000000a6`751ff7f0 00007ff7`758eaf7c     ida64_exe+0x17af52
1d 000000a6`751ff830 00007ff7`758ebccd     ida64_exe+0x17af7c
1e 000000a6`751ff870 00007ff7`758ebe5f     ida64_exe+0x17bccd
1f 000000a6`751ffb10 00007ff7`759995e2     ida64_exe+0x17be5f
20 000000a6`751ffb60 00007fff`f5967bd4     ida64_exe+0x2295e2
21 000000a6`751ffba0 00007fff`f6c8ced1     kernel32!BaseThreadInitThunk+0x14
22 000000a6`751ffbd0 00000000`00000000     ntdll!RtlUserThreadStart+0x21
```
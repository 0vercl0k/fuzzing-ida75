# Division by zero in elf64

Reproduction steps:
```
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ida64.exe" /v "GlobalFlag" /t REG_SZ /d "0x2000000" /f
windbgx -g "C:\Program Files\IDA Pro 7.5\ida64.exe" -B crash-EXCEPTION_INT_DIVIDE_BY_ZERO-7ffe5057a888
```

Output from windbg:
```
0:000> r
rax=0000000000000018 rbx=0000000000000000 rcx=0000000000000000
rdx=0000000000000000 rsi=0000000000000000 rdi=0000017574878e80
rip=00007ffa9353d39a rsp=0000003da09fc990 rbp=0000003da09fca31
 r8=0000000000000002  r9=000000000001060c r10=00000000ffffffef
r11=0000003da09fc8a0 r12=0000000000000001 r13=0000000000010680
r14=0000000000000015 r15=0000000000010654
iopl=0         nv up ei pl zr na po nc
cs=0033  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00010246
elf64+0xd39a:
00007ffa`9353d39a 48f7f1          div     rax,rcx

0:000> kp
 # Child-SP          RetAddr               Call Site
00 0000003d`a09fc990 00007ffa`9356a5cb     elf64+0xd39a
01 0000003d`a09fca90 00007ffa`9356aefb     elf64+0x3a5cb
02 0000003d`a09fd3e0 00007ffa`9356685b     elf64+0x3aefb
03 0000003d`a09fd550 00007ffa`9355d770     elf64+0x3685b
04 0000003d`a09fd670 00007ffa`935480de     elf64+0x2d770
05 0000003d`a09fdd50 00000000`702423a4     elf64+0x180de
06 0000003d`a09fdfb0 00000000`7024229e     ida64!user2str+0x3314
07 0000003d`a09fdff0 00000000`702427a4     ida64!user2str+0x320e
08 0000003d`a09fe2d0 00000000`70246200     ida64!user2str+0x3714
09 0000003d`a09fe350 00007ff7`d3d83f8d     ida64!load_nonbinary_file+0x30
0a 0000003d`a09fe390 00007ff7`d3d84563     ida64_exe+0x173f8d
0b 0000003d`a09fe890 00007ff7`d3c63a9b     ida64_exe+0x174563
0c 0000003d`a09fea10 00000000`7015130a     ida64_exe+0x53a9b
0d 0000003d`a09fee80 00007ff7`d3d8a37f     ida64!init_database+0xa9a
0e 0000003d`a09ff290 00007ff7`d3d8b989     ida64_exe+0x17a37f
0f 0000003d`a09ff310 00007ff7`d3d8ae1a     ida64_exe+0x17b989
10 0000003d`a09ff350 00007ff7`d3d8af52     ida64_exe+0x17ae1a
11 0000003d`a09ff400 00007ff7`d3d8af7c     ida64_exe+0x17af52
12 0000003d`a09ff440 00007ff7`d3d8bccd     ida64_exe+0x17af7c
13 0000003d`a09ff480 00007ff7`d3d8be5f     ida64_exe+0x17bccd
14 0000003d`a09ff720 00007ff7`d3e395e2     ida64_exe+0x17be5f
15 0000003d`a09ff770 00007ffa`cd207bd4     ida64_exe+0x2295e2
16 0000003d`a09ff7b0 00007ffa`cde4ced1     kernel32!BaseThreadInitThunk+0x14
17 0000003d`a09ff7e0 00000000`00000000     ntdll!RtlUserThreadStart+0x21
```
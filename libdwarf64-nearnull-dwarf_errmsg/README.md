# Near null dereference in libdwarf64

Reproduction steps:
```
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ida64.exe" /v "GlobalFlag" /t REG_SZ /d "0x2000000" /f
windbgx -g "C:\Program Files\IDA Pro 7.5\ida64.exe" -B crash-EXCEPTION_ACCESS_VIOLATION-7ffe468a3a4d
```

Output from windbg:
```
0:000> r
rax=00000253215a0d60 rbx=000000000000000b rcx=000000000000000b
rdx=0000000000000004 rsi=00007ffa936549f8 rdi=0000000000000096
rip=00007ffa935b3a4d rsp=000000c3bc3f8b68 rbp=000000c3bc3f8c30
 r8=0000000000000010  r9=00007ffacaf10000 r10=00007ffa9366b410
r11=0000025313da6fe2 r12=000000c3bc3f8d20 r13=0000000000000000
r14=000000c3bc3f9250 r15=0000000000000000
iopl=0         nv up ei pl nz na pe nc
cs=0033  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00010202
libdwarf64!dwarf_errmsg+0xd:
00007ffa`935b3a4d 486301          movsxd  rax,dword ptr [rcx] ds:00000000`0000000b=????????

0:000> kc
 # Call Site
00 libdwarf64!dwarf_errmsg
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
0d ida64!user2bin
0e dbg64
0f ida64!user2bin
10 ida64_exe
11 ida64_exe
12 ida64_exe
13 elf64
14 elf64
15 ida64!user2str
16 ida64!user2str
17 ida64!user2str
18 ida64!load_nonbinary_file
19 ida64_exe
1a ida64_exe
1b ida64_exe
1c ida64!init_database
1d ida64_exe
1e ida64_exe
1f ida64_exe
20 ida64_exe
21 ida64_exe
22 ida64_exe
23 ida64_exe
24 ida64_exe
25 kernel32!BaseThreadInitThunk
26 ntdll!RtlUserThreadStart

--

0:000> r
rax=00000278b93bed60 rbx=0000000000000008 rcx=0000000000000008
rdx=0000000000000004 rsi=00007ffa936849f8 rdi=0000000000000096
rip=00007ffa935e3a4d rsp=000000cf87bf90f8 rbp=000000cf87bf91c0
 r8=0000000000000010  r9=00007ffacaf10000 r10=00007ffa9369b410
r11=00000278c23a9fe2 r12=000000cf87bf92b0 r13=0000000000000000
r14=000000cf87bf97e0 r15=0000000000000000
iopl=0         nv up ei pl nz na pe nc
cs=0033  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00010202
libdwarf64!dwarf_errmsg+0xd:
00007ffa`935e3a4d 486301          movsxd  rax,dword ptr [rcx] ds:00000000`00000008=????????

0:000> kc
 # Call Site
00 libdwarf64!dwarf_errmsg
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
0d ida64!user2bin
0e dbg64
0f ida64!user2bin
10 ida64_exe
11 ida64_exe
12 ida64_exe
13 elf64
14 elf64
15 ida64!user2str
16 ida64!user2str
17 ida64!user2str
18 ida64!load_nonbinary_file
19 ida64_exe
1a ida64_exe
1b ida64_exe
1c ida64!init_database
1d ida64_exe
1e ida64_exe
1f ida64_exe
20 ida64_exe
21 ida64_exe
22 ida64_exe
23 ida64_exe
24 ida64_exe
25 kernel32!BaseThreadInitThunk
26 ntdll!RtlUserThreadStart
```
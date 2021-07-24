# Use-after-free write in dwarf64

Reproduction steps:
```
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ida64.exe" /v "GlobalFlag" /t REG_SZ /d "0x2000000" /f
windbgx -g "C:\Program Files\IDA Pro 7.5\ida64.exe" -B 87b9295bf9e3c00d6d1ef7c75b31c25db70caeef
```

Output from windbg:
```
This dump file has an exception of interest stored in it.
The stored exception information can be accessed via .ecxr.
(1538.1144): Access violation - code c0000005 (first/second chance not available)
For analysis of this file, run !analyze -v
dwarf64+0xfcb5:
00000000`6189fcb5 83680801        sub     dword ptr [rax+8],1 ds:000001ed`9dc54fe8=????????

0:000> kp
 # Child-SP          RetAddr               Call Site
00 000000d1`1bff72a0 00007ffd`76f61030     dwarf64+0xfcb5
01 000000d1`1bff72e0 00007ffd`76f635c6     VCRUNTIME140!_CallSettingFrame(void)+0x20 [d:\agent\_work\1\s\src\vctools\crt\vcruntime\src\eh\amd64\handlers.asm @ 50] 
02 000000d1`1bff7310 00007ffd`76f6c454     VCRUNTIME140!__FrameHandler3::FrameUnwindToState(unsigned int64 * pRN = 0x000000d1`1bff73c8, struct _xDISPATCHER_CONTEXT * pDC = 0x00000000`0005b880, struct _s_FuncInfo * pFuncInfo = 0x00000000`618efb00, int targetState = 0n-1)+0x112 [d:\agent\_work\1\s\src\vctools\crt\vcruntime\src\eh\frame.cpp @ 1178] 
03 000000d1`1bff7380 00007ffd`76f63021     VCRUNTIME140!__FrameHandler3::FrameUnwindToEmptyState(unsigned int64 * pRN = <Value unavailable error>, struct _xDISPATCHER_CONTEXT * pDC = 0x000000d1`1bff7a50, struct _s_FuncInfo * pFuncInfo = 0x00000000`618efb00)+0x54 [d:\agent\_work\1\s\src\vctools\crt\vcruntime\src\eh\risctrnsctrl.cpp @ 241] 
04 000000d1`1bff73b0 00007ffd`76f6c8f1     VCRUNTIME140!__InternalCxxFrameHandler<__FrameHandler3>(struct EHExceptionRecord * pExcept = 0x000000d1`1bff7bd0, unsigned int64 * pRN = 0x000000d1`1bff7460, struct _CONTEXT * pContext = 0x000000d1`1bff7ff0, struct _xDISPATCHER_CONTEXT * pDC = 0x000000d1`1bff7a50, struct _s_FuncInfo * pFuncInfo = 0x00000000`618efb00, int CatchDepth = 0n0, unsigned int64 * pMarkerRN = 0x00000000`00000000, unsigned char recursive = 0x00 '')+0x111 [d:\agent\_work\1\s\src\vctools\crt\vcruntime\src\eh\frame.cpp @ 325] 
05 000000d1`1bff7410 00007ffd`9d68127f     VCRUNTIME140!__CxxFrameHandler3(struct EHExceptionRecord * pExcept = 0x000000d1`1bff7bd0, unsigned int64 RN = <Value unavailable error>, struct _CONTEXT * pContext = 0x000000d1`1bff7ff0, struct _xDISPATCHER_CONTEXT * pDC = 0x000000d1`1bff7a50)+0x71 [d:\agent\_work\1\s\src\vctools\crt\vcruntime\src\eh\risctrnsctrl.cpp @ 267] 
06 000000d1`1bff7460 00007ffd`9d5fda32     ntdll!RtlpExecuteHandlerForUnwind+0xf
07 000000d1`1bff7490 00007ffd`76f6c75e     ntdll!RtlUnwindEx+0x522
08 000000d1`1bff7ba0 00007ffd`76f626a9     VCRUNTIME140!__FrameHandler3::UnwindNestedFrames(unsigned int64 * pFrame = <Value unavailable error>, struct EHExceptionRecord * pExcept = <Value unavailable error>, struct _CONTEXT * pContext = <Value unavailable error>, unsigned int64 * pEstablisher = <Value unavailable error>, void * Handler = 0x00000000`618ea325, struct _s_FuncInfo * pFuncInfo = 0x00000000`618ef128, int TargetUnwindState = 0n13, int __formal = 0n21, struct _s_HandlerType * __formal = 0x000000d1`1bff7e28, struct _xDISPATCHER_CONTEXT * pDC = 0x000000d1`1bff8540, unsigned char recursive = 0x00 '')+0xee [d:\agent\_work\1\s\src\vctools\crt\vcruntime\src\eh\risctrnsctrl.cpp @ 730] 
09 000000d1`1bff7c90 00007ffd`76f62a01     VCRUNTIME140!CatchIt<__FrameHandler3>(struct EHExceptionRecord * pExcept = 0x000000d1`1bff8bb0, unsigned int64 * pRN = 0x000000d1`1bff7f50, struct _CONTEXT * pContext = 0x000000d1`1bff86c0, struct _xDISPATCHER_CONTEXT * pDC = 0x000000d1`1bff8540, struct _s_FuncInfo * pFuncInfo = 0x00000000`618ef128, struct _s_HandlerType * pCatch = 0x000000d1`1bff7e28, struct _s_CatchableType * pConv = 0x00000000`61909400, struct _s_TryBlockMapEntry * pEntry = 0x000000d1`1bff7dd0, int CatchDepth = 0n0, unsigned int64 * pMarkerRN = 0x00000000`00000000, unsigned char IsRethrow = 0x00 '', unsigned char recursive = 0x00 '')+0xb9 [d:\agent\_work\1\s\src\vctools\crt\vcruntime\src\eh\frame.cpp @ 1321] 
0a 000000d1`1bff7d30 00007ffd`76f63127     VCRUNTIME140!FindHandler<__FrameHandler3>(struct EHExceptionRecord * pExcept = 0x000000d1`1bff8bb0, unsigned int64 * pRN = 0x000000d1`1bff7f50, struct _CONTEXT * pContext = 0x000000d1`1bff86c0, struct _xDISPATCHER_CONTEXT * pDC = 0x000000d1`1bff8540, struct _s_FuncInfo * pFuncInfo = 0x00000000`618ef128, unsigned char recursive = 0x00 '', int CatchDepth = 0n0, unsigned int64 * pMarkerRN = 0x00000000`00000000)+0x33d [d:\agent\_work\1\s\src\vctools\crt\vcruntime\src\eh\frame.cpp @ 627] 
0b 000000d1`1bff7ea0 00007ffd`76f6c8f1     VCRUNTIME140!__InternalCxxFrameHandler<__FrameHandler3>(struct EHExceptionRecord * pExcept = 0x000000d1`1bff8bb0, unsigned int64 * pRN = 0x000000d1`1bff7f50, struct _CONTEXT * pContext = 0x000000d1`1bff86c0, struct _xDISPATCHER_CONTEXT * pDC = 0x000000d1`1bff8540, struct _s_FuncInfo * pFuncInfo = 0x00000000`618ef128, int CatchDepth = 0n0, unsigned int64 * pMarkerRN = 0x00000000`00000000, unsigned char recursive = 0x00 '')+0x217 [d:\agent\_work\1\s\src\vctools\crt\vcruntime\src\eh\frame.cpp @ 356] 
0c 000000d1`1bff7f00 00000000`618e8228     VCRUNTIME140!__CxxFrameHandler3(struct EHExceptionRecord * pExcept = 0x000000d1`1bff8bb0, unsigned int64 RN = <Value unavailable error>, struct _CONTEXT * pContext = 0x000000d1`1bff86c0, struct _xDISPATCHER_CONTEXT * pDC = 0x000000d1`1bff8540)+0x71 [d:\agent\_work\1\s\src\vctools\crt\vcruntime\src\eh\risctrnsctrl.cpp @ 267] 
0d 000000d1`1bff7f50 00007ffd`9d6811ff     dwarf64+0x58228
0e 000000d1`1bff7f80 00007ffd`9d64a289     ntdll!RtlpExecuteHandlerForException+0xf
0f 000000d1`1bff7fb0 00007ffd`9d67fe6e     ntdll!RtlDispatchException+0x219
10 000000d1`1bff86c0 00007ffd`9a5aa839     ntdll!KiUserExceptionDispatch+0x2e
11 000000d1`1bff8e70 00007ffd`76f64880     KERNELBASE!RaiseException+0x69
12 000000d1`1bff8f50 00000000`618df97f     VCRUNTIME140!_CxxThrowException(void * pExceptionObject = 0x000000d1`1bff9000, struct _s__ThrowInfo * pThrowInfo = <Value unavailable error>)+0x90 [d:\agent\_work\1\s\src\vctools\crt\vcruntime\src\eh\throw.cpp @ 75] 
13 000000d1`1bff8fb0 00000000`618ce30e     dwarf64+0x4f97f
14 000000d1`1bff9050 00000000`618e009f     dwarf64+0x3e30e
15 000000d1`1bff90d0 00000000`618ca2a5     dwarf64+0x5009f
16 000000d1`1bff9360 00000000`618da546     dwarf64+0x3a2a5
17 000000d1`1bff9450 00000000`618e0dbd     dwarf64+0x4a546
18 000000d1`1bff9480 00000000`618c99ad     dwarf64+0x50dbd
19 000000d1`1bff9540 00000000`618ab864     dwarf64+0x399ad
1a 000000d1`1bff95a0 00000000`618dc4e9     dwarf64+0x1b864
*** WARNING: Unable to verify checksum for ida64.dll
1b 000000d1`1bffc0f0 00000000`6288c809     dwarf64+0x4c4e9
1c 000000d1`1bffc990 00000000`61927ea5     ida64!user2bin+0x69b9
1d 000000d1`1bffca30 00000000`6288c809     dbg64+0x7ea5
1e 000000d1`1bffd000 00007ff6`940deb90     ida64!user2bin+0x69b9
1f 000000d1`1bffd0a0 00007ff6`9401ce41     ida64_exe+0x18eb90
20 000000d1`1bffd110 00007ff6`93fa5729     ida64_exe+0xcce41
*** WARNING: Unable to verify checksum for elf64.dll
21 000000d1`1bffd310 00007ffd`65e4e27c     ida64_exe+0x55729
22 000000d1`1bffd780 00007ffd`65e380de     elf64+0x2e27c
23 000000d1`1bffde60 00000000`627f23a4     elf64+0x180de
24 000000d1`1bffe0c0 00000000`627f229e     ida64!user2str+0x3314
25 000000d1`1bffe100 00000000`627f27a4     ida64!user2str+0x320e
26 000000d1`1bffe3e0 00000000`627f6200     ida64!user2str+0x3714
27 000000d1`1bffe460 00007ff6`940c3f8d     ida64!load_nonbinary_file+0x30
28 000000d1`1bffe4a0 00007ff6`940c4563     ida64_exe+0x173f8d
29 000000d1`1bffe9a0 00007ff6`93fa3a9b     ida64_exe+0x174563
2a 000000d1`1bffeb20 00000000`6270130a     ida64_exe+0x53a9b
2b 000000d1`1bffef90 00007ff6`940ca37f     ida64!init_database+0xa9a
2c 000000d1`1bfff3a0 00007ff6`940cb989     ida64_exe+0x17a37f
2d 000000d1`1bfff420 00007ff6`940cae1a     ida64_exe+0x17b989
2e 000000d1`1bfff460 00007ff6`940caf52     ida64_exe+0x17ae1a
2f 000000d1`1bfff510 00007ff6`940caf7c     ida64_exe+0x17af52
30 000000d1`1bfff550 00007ff6`940cbccd     ida64_exe+0x17af7c
31 000000d1`1bfff590 00007ff6`940cbe5f     ida64_exe+0x17bccd
32 000000d1`1bfff830 00007ff6`941795e2     ida64_exe+0x17be5f
33 000000d1`1bfff880 00007ffd`9c9f7bd4     ida64_exe+0x2295e2
34 000000d1`1bfff8c0 00007ffd`9d64ced1     kernel32!BaseThreadInitThunk+0x14
35 000000d1`1bfff8f0 00000000`00000000     ntdll!RtlUserThreadStart+0x21
```
# interr 76C1 in dwarf64

Reproduction steps:
```
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ida64.exe" /v "GlobalFlag" /t REG_SZ /d "0x2000000" /f
windbgx -g "C:\Program Files\IDA Pro 7.5\ida64.exe" -B crash-EXCEPTION_BREAKPOINT-7ff92bf36317
```
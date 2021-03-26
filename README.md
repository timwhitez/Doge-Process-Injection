![Doge-Process-Injection](https://socialify.git.ci/timwhitez/Doge-Process-Injection/image?description=1&font=Raleway&forks=1&issues=1&language=1&logo=https%3A%2F%2Favatars1.githubusercontent.com%2Fu%2F36320909&owner=1&pattern=Circuit%20Board&stargazers=1&theme=Light)

- 🐸Frog For Automatic Scan

- 🐶Doge For Defense Evasion&Offensive Security

# 🐶Doge-Process-Injection
Demo of process injection, using ntdll.dll, direct syscall, etc.

## goinjection
Process injection demo by golang

Using BananaPhone for direct syscalls
## Usage
### Build
go build main.go

### Run
./main.exe processName1 processName2 ....

it will sequential search the exist process

## Todo
Different injection ways. 

## Reference
### Project Reference
- [OwOwningTheWinAPI](https://github.com/secfurry/OwOwningTheWinAPI)
- [BananaPhone](https://github.com/C-Sto/BananaPhone)
- [runsc](https://github.com/mjwhitta/runsc)
- [go-procinject](https://github.com/neox41/go-procinject)
- [go-shellcode](https://github.com/Ne0nd0g/go-shellcode)

### Windows API Function Reference
- [NtAllocateVirtualMemory](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntallocatevirtualmemory)
- [NtWriteVirtualMemory](http://www.codewarrior.cn/ntdoc/winnt/mm/NtWriteVirtualMemory.htm)
- [NtCreateThreadEx](https://securityxploded.com/ntcreatethreadex.php)
- [NtOpenProcess](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-ntopenprocess)

## 🚀Star Trend
[![Stargazers over time](https://starchart.cc/timwhitez/Doge-Process-Injection.svg)](https://starchart.cc/timwhitez/Doge-Process-Injection)


## etc
1. 开源的样本大部分可能已经失效,需要自行修改

2. 我认为基础核心代码的开源能够帮助想学习的人
 
3. 本人从github大佬项目中学到了很多
 
4. 若用本人项目去进行：HW演练/红蓝对抗/APT/黑产/恶意行为/违法行为/割韭菜，等行为，本人概不负责，也与本人无关

5. 本人已不参与大小HW活动的攻击方了，若溯源到timwhite id与本人无关

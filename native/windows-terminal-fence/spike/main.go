// Feasibility spike: run commands inside a Windows AppContainer with no
// capabilities, and serve a named pipe that only that container may open.
//
//	spike sid  <name>                    print the container SID (creating the profile)
//	spike run  <name> <cwd> <cmdline>    run cmdline in the container, inherit stdio
//	spike pipe <name> <pipe> <seconds>   serve \\.\pipe\<pipe> for the container; echo one line back
//	spike delete <name>                  remove the container profile
package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"syscall"
	"time"
	"unsafe"
)

var (
	userenv  = syscall.NewLazyDLL("userenv.dll")
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	advapi32 = syscall.NewLazyDLL("advapi32.dll")

	pCreateProfile = userenv.NewProc("CreateAppContainerProfile")
	pDeriveSid     = userenv.NewProc("DeriveAppContainerSidFromAppContainerName")
	pDeleteProfile = userenv.NewProc("DeleteAppContainerProfile")
	pInitAttr      = kernel32.NewProc("InitializeProcThreadAttributeList")
	pUpdateAttr    = kernel32.NewProc("UpdateProcThreadAttribute")
	pCreatePipe    = kernel32.NewProc("CreateNamedPipeW")
	pConnectPipe   = kernel32.NewProc("ConnectNamedPipe")
	pSidToString   = advapi32.NewProc("ConvertSidToStringSidW")
	pSddlToSD      = advapi32.NewProc("ConvertStringSecurityDescriptorToSecurityDescriptorW")
)

type securityCapabilities struct {
	AppContainerSid uintptr
	Capabilities    uintptr
	CapabilityCount uint32
	Reserved        uint32
}

type startupInfoEx struct {
	syscall.StartupInfo
	AttributeList uintptr
}

const (
	attrSecurityCapabilities = 0x00020009
	extendedStartupInfo      = 0x00080000
	alreadyExists            = 0x800700B7
)

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "spike: "+format+"\n", args...)
	os.Exit(70)
}

func utf16(s string) *uint16 { p, _ := syscall.UTF16PtrFromString(s); return p }

func containerSid(name string) uintptr {
	var sid uintptr
	n := utf16(name)
	hr, _, _ := pCreateProfile.Call(uintptr(unsafe.Pointer(n)), uintptr(unsafe.Pointer(n)), uintptr(unsafe.Pointer(n)), 0, 0, uintptr(unsafe.Pointer(&sid)))
	if hr == 0 {
		return sid
	}
	if uint32(hr) != alreadyExists {
		fail("CreateAppContainerProfile 0x%x", uint32(hr))
	}
	if hr, _, _ = pDeriveSid.Call(uintptr(unsafe.Pointer(n)), uintptr(unsafe.Pointer(&sid))); hr != 0 {
		fail("DeriveAppContainerSidFromAppContainerName 0x%x", uint32(hr))
	}
	return sid
}

func sidString(sid uintptr) string {
	var p *uint16
	if r, _, _ := pSidToString.Call(sid, uintptr(unsafe.Pointer(&p))); r == 0 {
		fail("ConvertSidToStringSid failed")
	}
	chars := []uint16{}
	for i := 0; ; i++ {
		c := *(*uint16)(unsafe.Pointer(uintptr(unsafe.Pointer(p)) + uintptr(i)*2))
		if c == 0 {
			break
		}
		chars = append(chars, c)
	}
	return syscall.UTF16ToString(chars)
}

func inherit(h syscall.Handle) syscall.Handle {
	_ = syscall.SetHandleInformation(h, syscall.HANDLE_FLAG_INHERIT, syscall.HANDLE_FLAG_INHERIT)
	return h
}

func run(name, cwd, cmdline string) int {
	caps := securityCapabilities{AppContainerSid: containerSid(name)}
	var size uintptr
	pInitAttr.Call(0, 1, 0, uintptr(unsafe.Pointer(&size)))
	list := make([]byte, size)
	if r, _, e := pInitAttr.Call(uintptr(unsafe.Pointer(&list[0])), 1, 0, uintptr(unsafe.Pointer(&size))); r == 0 {
		fail("InitializeProcThreadAttributeList: %v", e)
	}
	if r, _, e := pUpdateAttr.Call(uintptr(unsafe.Pointer(&list[0])), 0, attrSecurityCapabilities,
		uintptr(unsafe.Pointer(&caps)), unsafe.Sizeof(caps), 0, 0); r == 0 {
		fail("UpdateProcThreadAttribute: %v", e)
	}
	var si startupInfoEx
	si.Cb = uint32(unsafe.Sizeof(si))
	si.Flags = syscall.STARTF_USESTDHANDLES
	si.StdInput = inherit(syscall.Handle(os.Stdin.Fd()))
	si.StdOutput = inherit(syscall.Handle(os.Stdout.Fd()))
	si.StdErr = inherit(syscall.Handle(os.Stderr.Fd()))
	si.AttributeList = uintptr(unsafe.Pointer(&list[0]))
	var pi syscall.ProcessInformation
	if err := syscall.CreateProcess(nil, utf16(cmdline), nil, nil, true, extendedStartupInfo, nil, utf16(cwd), &si.StartupInfo, &pi); err != nil {
		fmt.Fprintf(os.Stderr, "spike: CreateProcess: %v\n", err)
		return 71
	}
	defer syscall.CloseHandle(pi.Process)
	defer syscall.CloseHandle(pi.Thread)
	if ev, _ := syscall.WaitForSingleObject(pi.Process, 120000); ev != syscall.WAIT_OBJECT_0 {
		syscall.TerminateProcess(pi.Process, 124)
		return 124
	}
	var code uint32
	syscall.GetExitCodeProcess(pi.Process, &code)
	return int(code)
}

// The pipe admits the owner (this user) and the container SID only.
func pipe(name, pipeName string, seconds int) {
	sddl := "D:P(A;;GA;;;OW)(A;;GA;;;SY)(A;;GRGW;;;" + sidString(containerSid(name)) + ")"
	var sd uintptr
	if r, _, e := pSddlToSD.Call(uintptr(unsafe.Pointer(utf16(sddl))), 1, uintptr(unsafe.Pointer(&sd)), 0); r == 0 {
		fail("security descriptor: %v", e)
	}
	sa := syscall.SecurityAttributes{Length: uint32(unsafe.Sizeof(syscall.SecurityAttributes{})), SecurityDescriptor: sd}
	h, _, e := pCreatePipe.Call(uintptr(unsafe.Pointer(utf16(`\\.\pipe\`+pipeName))), 3 /*DUPLEX*/, 0, 1, 4096, 4096, 0, uintptr(unsafe.Pointer(&sa)))
	if syscall.Handle(h) == syscall.InvalidHandle {
		fail("CreateNamedPipe: %v", e)
	}
	go func() { time.Sleep(time.Duration(seconds) * time.Second); fmt.Println("pipe: no client"); os.Exit(3) }()
	fmt.Println("pipe: listening")
	pConnectPipe.Call(h, 0)
	f := os.NewFile(h, "pipe")
	line, _ := bufio.NewReader(f).ReadString('\n')
	fmt.Fprintf(f, "host-pipe-ok %s", line)
	fmt.Printf("pipe: client said %q\n", line)
	f.Close()
}

func main() {
	if len(os.Args) < 3 {
		fail("usage: sid|run|pipe")
	}
	switch os.Args[1] {
	case "sid":
		fmt.Println(sidString(containerSid(os.Args[2])))
	case "run":
		if len(os.Args) != 5 {
			fail("run <name> <cwd> <cmdline>")
		}
		cmdline := os.Args[4]
		if cmdline == "-" { // avoids PowerShell 5 re-splitting quoted native arguments
			cmdline = os.Getenv("SPIKE_CMD")
		}
		os.Exit(run(os.Args[2], os.Args[3], cmdline))
	case "delete":
		hr, _, _ := pDeleteProfile.Call(uintptr(unsafe.Pointer(utf16(os.Args[2]))))
		fmt.Printf("delete %s: 0x%x\n", os.Args[2], uint32(hr))
	case "pipe":
		seconds, _ := strconv.Atoi(os.Args[4])
		pipe(os.Args[2], os.Args[3], seconds)
	default:
		fail("unknown command")
	}
}

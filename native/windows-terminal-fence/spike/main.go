// Feasibility spike: run commands inside a Windows AppContainer with no
// capabilities, and serve a named pipe that only that container may open.
//
//	spike sid  <name>                    print the container SID (creating the profile)
//	spike run  <name> <cwd> <cmdline>    run cmdline in the container, inherit stdio
//	spike pipe <name> <pipe> <seconds>   serve \\.\pipe\<pipe> for the container; echo one line back
//	spike conpty <name> <cwd> <seconds>  interactive cmd.exe via ConPTY; types SPIKE_INPUT lines
//	spike conpty-user <user> <cwd> <seconds>  the same session as a local account (SPIKE_PASSWORD)
//	spike user-cmd <user> <cwd>          run SPIKE_CMD as a local account, no pseudoconsole
//	spike delete <name>                  remove the container profile
package main

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
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
	pCreatePseudo  = kernel32.NewProc("CreatePseudoConsole")
	pClosePseudo   = kernel32.NewProc("ClosePseudoConsole")
	advapi32Logon  = advapi32.NewProc("CreateProcessWithLogonW")
	pLogonUser     = advapi32.NewProc("LogonUserW")
	pWithToken     = advapi32.NewProc("CreateProcessWithTokenW")
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
	attrPseudoConsole        = 0x00020016
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

// conpty runs cmd.exe interactively in the container through a pseudoconsole,
// the way a terminal does, types each line of SPIKE_INPUT and prints the
// screen output with escape sequences removed.
func conpty(name, cwd string, seconds int) { conptyAs(name, "", cwd, seconds) }

// conptyAs with a user runs the session as that local account through
// CreateProcessWithLogonW (no container), password taken from SPIKE_PASSWORD.
func conptyAs(name, user, cwd string, seconds int) {
	var inR, inW, outR, outW syscall.Handle
	if err := syscall.CreatePipe(&inR, &inW, nil, 0); err != nil {
		fail("CreatePipe: %v", err)
	}
	if err := syscall.CreatePipe(&outR, &outW, nil, 0); err != nil {
		fail("CreatePipe: %v", err)
	}
	var hpc uintptr
	if hr, _, _ := pCreatePseudo.Call(uintptr(120)|uintptr(40)<<16, uintptr(inR), uintptr(outW), 0, uintptr(unsafe.Pointer(&hpc))); hr != 0 {
		fail("CreatePseudoConsole 0x%x", uint32(hr))
	}
	// "host" runs the same session outside any container, as a control.
	contained := name != "host" && user == ""
	count := uintptr(1)
	if contained {
		count = 2
	}
	var size uintptr
	pInitAttr.Call(0, count, 0, uintptr(unsafe.Pointer(&size)))
	list := make([]byte, size)
	if r, _, e := pInitAttr.Call(uintptr(unsafe.Pointer(&list[0])), count, 0, uintptr(unsafe.Pointer(&size))); r == 0 {
		fail("InitializeProcThreadAttributeList: %v", e)
	}
	var caps securityCapabilities
	if contained {
		caps.AppContainerSid = containerSid(name)
		if r, _, e := pUpdateAttr.Call(uintptr(unsafe.Pointer(&list[0])), 0, attrSecurityCapabilities, uintptr(unsafe.Pointer(&caps)), unsafe.Sizeof(caps), 0, 0); r == 0 {
			fail("security capabilities: %v", e)
		}
	}
	if r, _, e := pUpdateAttr.Call(uintptr(unsafe.Pointer(&list[0])), 0, attrPseudoConsole, hpc, unsafe.Sizeof(hpc), 0, 0); r == 0 {
		fail("pseudoconsole: %v", e)
	}
	var si startupInfoEx
	si.Cb = uint32(unsafe.Sizeof(si))
	// With redirected parent stdio the child would otherwise inherit those
	// handles instead of attaching to the pseudoconsole.
	si.Flags = syscall.STARTF_USESTDHANDLES
	si.AttributeList = uintptr(unsafe.Pointer(&list[0]))
	var pi syscall.ProcessInformation
	if user != "" && os.Getenv("SPIKE_VIA") == "token" {
		// LogonUser + CreateProcessWithTokenW (seclogon, needs SeImpersonate).
		var token uintptr
		if r, _, e := pLogonUser.Call(uintptr(unsafe.Pointer(utf16(user))), uintptr(unsafe.Pointer(utf16("."))), uintptr(unsafe.Pointer(utf16(os.Getenv("SPIKE_PASSWORD")))), 2, 0, uintptr(unsafe.Pointer(&token))); r == 0 {
			fail("LogonUser: %v", e)
		}
		if r, _, e := pWithToken.Call(token, 1, 0, uintptr(unsafe.Pointer(utf16("cmd.exe /Q"))), extendedStartupInfo, 0, uintptr(unsafe.Pointer(utf16(cwd))),
			uintptr(unsafe.Pointer(&si.StartupInfo)), uintptr(unsafe.Pointer(&pi))); r == 0 {
			fail("CreateProcessWithTokenW: %v", e)
		}
	} else if user != "" {
		const logonWithProfile = 1
		flags := uintptr(extendedStartupInfo)
		if os.Getenv("SPIKE_VIA") == "plain" { // no pseudoconsole: control for the API itself
			flags = 0
			si.Cb = uint32(unsafe.Sizeof(si.StartupInfo))
		}
		r, _, e := advapi32Logon.Call(uintptr(unsafe.Pointer(utf16(user))), uintptr(unsafe.Pointer(utf16("."))), uintptr(unsafe.Pointer(utf16(os.Getenv("SPIKE_PASSWORD")))),
			logonWithProfile, 0, uintptr(unsafe.Pointer(utf16("cmd.exe /Q"))), flags, 0, uintptr(unsafe.Pointer(utf16(cwd))),
			uintptr(unsafe.Pointer(&si.StartupInfo)), uintptr(unsafe.Pointer(&pi)))
		if r == 0 {
			fail("CreateProcessWithLogonW: %v", e)
		}
	} else if err := syscall.CreateProcess(nil, utf16("cmd.exe /Q"), nil, nil, false, extendedStartupInfo, nil, utf16(cwd), &si.StartupInfo, &pi); err != nil {
		fail("CreateProcess: %v", err)
	}
	syscall.CloseHandle(inR)
	syscall.CloseHandle(outW)
	output := make(chan []byte, 1024)
	go func() {
		buffer := make([]byte, 8192)
		for {
			var n uint32
			if err := syscall.ReadFile(outR, buffer, &n, nil); err != nil || n == 0 {
				close(output)
				return
			}
			output <- append([]byte(nil), buffer[:n]...)
		}
	}()
	var screen []byte
	drain := func(wait time.Duration) {
		deadline := time.After(wait)
		for {
			select {
			case chunk, ok := <-output:
				if !ok {
					return
				}
				screen = append(screen, chunk...)
			case <-deadline:
				return
			}
		}
	}
	drain(1500 * time.Millisecond)
	for _, line := range splitLines(os.Getenv("SPIKE_INPUT")) {
		var n uint32
		if err := syscall.WriteFile(inW, []byte(line+"\r\n"), &n, nil); err != nil {
			fmt.Fprintf(os.Stderr, "spike: input write failed: %v\n", err)
		}
		drain(time.Duration(seconds) * time.Second)
	}
	pClosePseudo.Call(hpc)
	syscall.TerminateProcess(pi.Process, 0)
	if os.Getenv("SPIKE_RAW") != "" {
		fmt.Printf("%q\n", string(screen))
		return
	}
	fmt.Print(stripEscapes(string(screen)))
}

func splitLines(text string) []string {
	lines := []string{}
	for _, line := range strings.Split(text, "\n") {
		if strings.TrimSpace(line) != "" {
			lines = append(lines, strings.TrimRight(line, "\r"))
		}
	}
	return lines
}

func stripEscapes(text string) string {
	csi := regexp.MustCompile("\x1b\\[[0-9;?]*[ -/]*[@-~]")
	osc := regexp.MustCompile("\x1b\\][^\x07\x1b]*(\x07|\x1b\\\\)")
	text = osc.ReplaceAllString(csi.ReplaceAllString(text, ""), "")
	return strings.ReplaceAll(regexp.MustCompile("\x1b[()][0-9A-B]|\x1b[=>]").ReplaceAllString(text, ""), "\r", "")
}

// userCommand runs SPIKE_CMD as a local account without a pseudoconsole
// (CreateProcessWithLogonW), waiting for it to finish.
func userCommand(user, cwd string) {
	var si syscall.StartupInfo
	si.Cb = uint32(unsafe.Sizeof(si))
	var pi syscall.ProcessInformation
	r, _, e := advapi32Logon.Call(uintptr(unsafe.Pointer(utf16(user))), uintptr(unsafe.Pointer(utf16("."))), uintptr(unsafe.Pointer(utf16(os.Getenv("SPIKE_PASSWORD")))),
		1, 0, uintptr(unsafe.Pointer(utf16(os.Getenv("SPIKE_CMD")))), 0x08000000 /*CREATE_NO_WINDOW*/, 0, uintptr(unsafe.Pointer(utf16(cwd))),
		uintptr(unsafe.Pointer(&si)), uintptr(unsafe.Pointer(&pi)))
	if r == 0 {
		fail("CreateProcessWithLogonW: %v", e)
	}
	syscall.WaitForSingleObject(pi.Process, 120000)
	var code uint32
	syscall.GetExitCodeProcess(pi.Process, &code)
	syscall.CloseHandle(pi.Process)
	syscall.CloseHandle(pi.Thread)
	os.Exit(int(code))
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
	case "conpty":
		seconds, _ := strconv.Atoi(os.Args[4])
		conpty(os.Args[2], os.Args[3], seconds)
	case "conpty-user":
		seconds, _ := strconv.Atoi(os.Args[4])
		conptyAs("", os.Args[2], os.Args[3], seconds)
	case "user-cmd":
		userCommand(os.Args[2], os.Args[3])
	case "pipe":
		seconds, _ := strconv.Atoi(os.Args[4])
		pipe(os.Args[2], os.Args[3], seconds)
	default:
		fail("unknown command")
	}
}

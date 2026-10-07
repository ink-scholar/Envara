//go:build windows

package host

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"os"
	"runtime"
	"sync"
	"time"
	"unsafe"

	"envara.io/windows-app-routing/internal/protocol"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
)

const pipeName = `\\.\pipe\EnvaraApplicationRouting-v1`
const serviceName = "EnvaraAppRouting"

var impersonatePipe = windows.NewLazySystemDLL("advapi32.dll").NewProc("ImpersonateNamedPipeClient")

func Call(request protocol.Request) protocol.Response {
	name, _ := windows.UTF16PtrFromString(pipeName)
	handle, err := windows.CreateFile(name, windows.FILE_READ_DATA|windows.FILE_WRITE_DATA|windows.SYNCHRONIZE, 0, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		if request.Method == "status" || request.Method == "setup" {
			return protocol.Success(request, protocol.MissingStatus("The signed Windows routing service and driver are not installed or available."))
		}
		return protocol.Failure(request, "ROUTING_NOT_READY", "The Windows routing service is unavailable; no application was started.")
	}
	file := os.NewFile(uintptr(handle), "envara-routing-pipe")
	defer file.Close()
	// Authenticate the server before sending even one credential-bearing byte.
	// A user-created pipe with the same name must never receive a route password.
	if trustedServer(handle) != nil {
		return protocol.Failure(request, "NATIVE_SERVER_UNTRUSTED", "The routing pipe is not owned by the installed Windows service.")
	}
	timer := time.AfterFunc(30*time.Second, func() { _ = file.Close() })
	defer timer.Stop()
	data, err := json.Marshal(request)
	if err != nil || writeFrame(file, data) != nil {
		return protocol.Failure(request, "NATIVE_TRANSPORT_FAILED", "Native routing communication failed.")
	}
	responseData, err := readFrame(file)
	var response protocol.Response
	if err != nil || json.Unmarshal(responseData, &response) != nil || response.Protocol != protocol.Name || response.Version != protocol.Version || response.ID != request.ID || (response.Result == nil && response.Error == nil) || (response.Result != nil && response.Error != nil) {
		return protocol.Failure(request, "NATIVE_TRANSPORT_FAILED", "Native routing response was invalid.")
	}
	return response
}

func trustedServer(pipe windows.Handle) error {
	var pid uint32
	if err := windows.GetNamedPipeServerProcessId(pipe, &pid); err != nil || pid == 0 {
		return errors.New("server identity unavailable")
	}
	manager, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return err
	}
	defer windows.CloseServiceHandle(manager)
	name, _ := windows.UTF16PtrFromString(serviceName)
	service, err := windows.OpenService(manager, name, windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return err
	}
	defer windows.CloseServiceHandle(service)
	var status windows.SERVICE_STATUS_PROCESS
	var needed uint32
	if err = windows.QueryServiceStatusEx(service, windows.SC_STATUS_PROCESS_INFO, (*byte)(unsafe.Pointer(&status)), uint32(unsafe.Sizeof(status)), &needed); err != nil {
		return err
	}
	if status.CurrentState != windows.SERVICE_RUNNING || status.ProcessId != pid {
		return errors.New("routing server is not the installed service")
	}
	return nil
}

func writeFrame(writer io.Writer, data []byte) error {
	if len(data) == 0 || len(data) > protocol.MaxMessage {
		return errors.New("frame size invalid")
	}
	var length [4]byte
	binary.LittleEndian.PutUint32(length[:], uint32(len(data)))
	for _, buffer := range [][]byte{length[:], data} {
		for len(buffer) > 0 {
			n, err := writer.Write(buffer)
			if err != nil {
				return err
			}
			if n == 0 {
				return io.ErrShortWrite
			}
			buffer = buffer[n:]
		}
	}
	return nil
}

func readFrame(reader io.Reader) ([]byte, error) {
	var length [4]byte
	if _, err := io.ReadFull(reader, length[:]); err != nil {
		return nil, err
	}
	size := binary.LittleEndian.Uint32(length[:])
	if size == 0 || size > protocol.MaxMessage {
		return nil, errors.New("frame size invalid")
	}
	data := make([]byte, size)
	_, err := io.ReadFull(reader, data)
	return data, err
}

type caller struct {
	sid          string
	token        windows.Token
	sessionID    uint32
	pid          uint32
	creationTime uint64
}

func authenticate(pipe windows.Handle) (caller, error) {
	// Named-pipe impersonation binds this request to the kernel-authenticated
	// client, never to a SID or PID claimed in the JSON body.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	result, _, err := impersonatePipe.Call(uintptr(pipe))
	if result == 0 {
		return caller{}, err
	}
	var token windows.Token
	openErr := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY|windows.TOKEN_DUPLICATE, true, &token)
	revertErr := windows.RevertToSelf()
	if revertErr != nil {
		os.Exit(1)
	} // Never continue service work under a leaked impersonation.
	if openErr != nil {
		return caller{}, openErr
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		return caller{}, err
	}
	var sessionID uint32
	var returned uint32
	if err = windows.GetTokenInformation(token, windows.TokenSessionId, (*byte)(unsafe.Pointer(&sessionID)), 4, &returned); err != nil {
		return caller{}, err
	}
	if sessionID == 0 {
		return caller{}, errors.New("interactive user required")
	}
	var primary windows.Token
	if err = windows.DuplicateTokenEx(token, windows.TOKEN_ALL_ACCESS, nil, windows.SecurityImpersonation, windows.TokenPrimary, &primary); err != nil {
		return caller{}, err
	}
	var pid uint32
	if err = windows.GetNamedPipeClientProcessId(pipe, &pid); err != nil || pid == 0 {
		primary.Close()
		return caller{}, errors.New("pipe process identity unavailable")
	}
	process, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		primary.Close()
		return caller{}, err
	}
	defer windows.CloseHandle(process)
	var creation, exit, kernel, userTime windows.Filetime
	if err = windows.GetProcessTimes(process, &creation, &exit, &kernel, &userTime); err != nil {
		primary.Close()
		return caller{}, err
	}
	return caller{sid: user.User.Sid.String(), token: primary, sessionID: sessionID, pid: pid, creationTime: uint64(creation.HighDateTime)<<32 | uint64(creation.LowDateTime)}, nil
}

type routingService struct{}

func RunService() error {
	isService, err := svc.IsWindowsService()
	if err != nil {
		return err
	}
	if !isService {
		return errors.New("SCM-managed service required")
	}
	return svc.Run(serviceName, routingService{})
}

func (routingService) Execute(_ []string, requests <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	changes <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	engine := newEngine()
	defer engine.close()
	server := &pipeServer{engine: engine}
	done := make(chan error, 1)
	go func() { done <- server.serve(ctx) }()
	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case request := <-requests:
			if request.Cmd == svc.Interrogate {
				changes <- request.CurrentStatus
			}
			if request.Cmd == svc.Stop || request.Cmd == svc.Shutdown {
				changes <- svc.Status{State: svc.StopPending}
				cancel()
				server.cancelPending()
				return false, 0
			}
		case <-done:
			return false, 1
		}
	}
}

type pipeServer struct {
	engine      *engine
	mu          sync.Mutex
	pending     windows.Handle
	connections sync.WaitGroup
}

func (server *pipeServer) cancelPending() {
	server.mu.Lock()
	defer server.mu.Unlock()
	if server.pending != 0 {
		_ = windows.CloseHandle(server.pending)
		server.pending = 0
	}
}

func (server *pipeServer) serve(ctx context.Context) error {
	// Interactive users may submit requests; each route/session is subsequently
	// scoped to its authenticated SID. Remote named-pipe clients are rejected.
	// Explicit data rights avoid GENERIC_WRITE granting FILE_CREATE_PIPE_INSTANCE
	// to interactive users, which would permit a same-name server impersonation.
	descriptor, err := windows.SecurityDescriptorFromString("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x00100003;;;IU)")
	if err != nil {
		return err
	}
	attributes := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: descriptor}
	name, _ := windows.UTF16PtrFromString(pipeName)
	first := true
	// Include the listening instance in this bound. A full pool waits for a
	// connection to finish; it must not turn ordinary load into service shutdown.
	slots := make(chan struct{}, 16)
	for {
		if ctx.Err() != nil {
			return nil
		}
		select {
		case slots <- struct{}{}:
		case <-ctx.Done():
			return nil
		}
		flags := uint32(windows.PIPE_ACCESS_DUPLEX)
		if first {
			flags |= windows.FILE_FLAG_FIRST_PIPE_INSTANCE
		}
		handle, err := windows.CreateNamedPipe(name, flags,
			windows.PIPE_TYPE_BYTE|windows.PIPE_READMODE_BYTE|windows.PIPE_WAIT|windows.PIPE_REJECT_REMOTE_CLIENTS,
			16, 65536, 65536, 10000, &attributes)
		if err != nil {
			<-slots
			return err
		}
		first = false
		server.mu.Lock()
		server.pending = handle
		server.mu.Unlock()
		err = windows.ConnectNamedPipe(handle, nil)
		server.mu.Lock()
		owned := server.pending == handle
		if owned {
			server.pending = 0
		}
		server.mu.Unlock()
		if !owned {
			<-slots
			return nil
		}
		if err != nil && err != windows.ERROR_PIPE_CONNECTED {
			_ = windows.CloseHandle(handle)
			<-slots
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		server.connections.Add(1)
		go func() {
			defer server.connections.Done()
			defer func() { <-slots }()
			server.handle(ctx, handle)
		}()
	}
}

func (server *pipeServer) handle(ctx context.Context, handle windows.Handle) {
	file := os.NewFile(uintptr(handle), "envara-routing-pipe")
	defer file.Close()
	timer := time.AfterFunc(30*time.Second, func() { _ = file.Close() })
	defer timer.Stop()
	data, err := readFrame(file)
	if err != nil {
		return
	}
	request, err := protocol.Decode(data)
	if err != nil {
		return
	}
	client, err := authenticate(handle)
	if err != nil {
		response := protocol.Failure(request, "USER_AUTHORIZATION_REQUIRED", "An authenticated interactive Windows user is required.")
		encoded, _ := json.Marshal(response)
		_ = writeFrame(file, encoded)
		return
	}
	defer client.token.Close()
	var response protocol.Response
	if ctx.Err() != nil {
		response = protocol.Failure(request, "SERVICE_STOPPING", "The Windows routing service is stopping.")
	} else {
		response = server.engine.dispatch(request, client)
	}
	encoded, err := json.Marshal(response)
	if err == nil {
		_ = writeFrame(file, encoded)
	}
}

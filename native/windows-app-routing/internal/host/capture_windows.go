//go:build windows

package host

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"unsafe"

	"envara.io/windows-app-routing/internal/protocol"
	"golang.org/x/sys/windows"
)

type captureEndpoint struct {
	Address  [16]byte
	Port     uint16
	Family   uint8
	Reserved uint8
}
type captureTuple struct {
	Source, Destination captureEndpoint
	Protocol            uint8
	Reserved            [7]byte
}
type captureIdentityRequest struct {
	Size, Version, PID, Reserved uint32
	CreationTime, ProcessHandle  uint64
}
type captureIdentityResult struct {
	Size, Version, Decision, Reserved uint32
	RouteTag, SessionTag, Generation  uint64
}
type captureConfig struct {
	Size, Version, RelayPort, HoldMilliseconds uint32
	ResolveIdentity, CallbackContext           uint64
}
type captureRelayQuery struct {
	Size, Version uint32
	Accepted      captureTuple
}
type captureRelayResult struct {
	Size, Version                                          uint32
	FlowID, RouteTag, SessionTag, Generation, CreationTime uint64
	PID, Reserved                                          uint32
	Original                                               captureTuple
}
type captureRevoke struct {
	Size, Version          uint32
	SessionTag, Generation uint64
}

type captureBundle struct {
	directory string
	files     []*os.File
	status    protocol.CaptureStatus
}

func (bundle *captureBundle) close() {
	for _, file := range bundle.files {
		_ = file.Close()
	}
	bundle.files = nil
}

// A status probe only opens files and reads metadata/hash bytes. Neither this
// function nor newEngine calls LoadLibrary, WinDivertOpen, an installer or SCM.
func inspectCaptureBundle() (*captureBundle, error) {
	bundle := &captureBundle{status: protocol.CaptureStatus{Engine: "windivert", ABI: captureABI, Architecture: "x64"}}
	if runtime.GOARCH != "amd64" {
		return bundle, errors.New("official bundled WinDivert capture is unavailable for this architecture")
	}
	executable, err := os.Executable()
	if err != nil || !filepath.IsAbs(executable) || strings.HasPrefix(executable, `\\`) {
		return bundle, errors.New("protected service directory unavailable")
	}
	bundle.directory = filepath.Dir(filepath.Clean(executable))
	if err = checkProtectedDirectory(bundle.directory); err != nil {
		return bundle, err
	}
	manifestFile, err := openProtectedFile(filepath.Join(bundle.directory, captureManifestName))
	if err != nil {
		return bundle, errors.New("capture provenance is unavailable or writable by an untrusted principal")
	}
	bundle.files = append(bundle.files, manifestFile)
	data, err := io.ReadAll(io.LimitReader(manifestFile, 32769))
	manifest, decodeErr := decodeCaptureManifest(data)
	if err != nil || decodeErr != nil {
		bundle.close()
		return bundle, errors.New("capture provenance contract invalid")
	}
	for _, artifact := range manifest.Files {
		file, err := openProtectedFile(filepath.Join(bundle.directory, artifact.Name))
		if err != nil {
			bundle.close()
			return bundle, errors.New("capture artifact is unavailable or writable by an untrusted principal")
		}
		bundle.files = append(bundle.files, file)
		if verifyCaptureHash(file, artifact.SHA256) != nil {
			bundle.close()
			return bundle, errors.New("capture artifact does not match installed provenance")
		}
	}
	bundle.status.ProvenanceVerified = true
	bundle.status.Reason = "Artifacts match protected installation provenance; capture is not activated and Windows/DNS acceptance is unverified."
	return bundle, nil
}

func trustedInstallationSID(sid *windows.SID) bool {
	if sid == nil {
		return false
	}
	switch sid.String() {
	case "S-1-5-18", "S-1-5-32-544", "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464":
		return true
	}
	return false
}

func checkProtectedACL(handle windows.Handle, full bool) error {
	sd, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return errors.New("installation access controls unavailable")
	}
	owner, _, err := sd.Owner()
	if err != nil || !trustedInstallationSID(owner) {
		return errors.New("installation owner is not privileged")
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil {
		return errors.New("installation has a permissive access control list")
	}
	mask := uint32(windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER | windows.GENERIC_ALL | windows.GENERIC_WRITE | 0x40) // FILE_DELETE_CHILD
	if full {
		mask |= windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA | windows.FILE_WRITE_EA | windows.FILE_WRITE_ATTRIBUTES
	}
	for index := uint32(0); index < uint32(acl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(acl, index, &ace) != nil || ace == nil {
			return errors.New("installation ACE unavailable")
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 || ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return errors.New("installation ACE type unsupported")
		}
		if uint32(ace.Mask)&mask != 0 && !trustedInstallationSID((*windows.SID)(unsafe.Pointer(&ace.SidStart))) {
			return errors.New("installation is writable by an untrusted principal")
		}
	}
	runtime.KeepAlive(sd)
	return nil
}

func checkProtectedDirectory(directory string) error {
	for current := directory; ; current = filepath.Dir(current) {
		name, err := windows.UTF16PtrFromString(current)
		if err != nil {
			return err
		}
		handle, err := windows.CreateFile(name, windows.READ_CONTROL, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
		if err != nil {
			return errors.New("installation directory unavailable")
		}
		var info windows.ByHandleFileInformation
		err = windows.GetFileInformationByHandle(handle, &info)
		if err == nil && info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			err = errors.New("installation directory contains a reparse point")
		}
		if err == nil {
			err = checkProtectedACL(handle, current == directory)
		}
		_ = windows.CloseHandle(handle)
		if err != nil {
			return err
		}
		if parent := filepath.Dir(current); parent == current {
			break
		}
	}
	return nil
}

func openProtectedFile(path string) (*os.File, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	// Deny write/delete sharing for the entire loaded module lifetime. The
	// protected parent prevents replacement between verification and loading.
	handle, err := windows.CreateFile(name, windows.GENERIC_READ|windows.READ_CONTROL, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, err
	}
	var info windows.ByHandleFileInformation
	err = windows.GetFileInformationByHandle(handle, &info)
	if err == nil && info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 {
		err = errors.New("capture artifact is not a regular installed file")
	}
	if err == nil {
		err = checkProtectedACL(handle, true)
	}
	if err != nil {
		_ = windows.CloseHandle(handle)
		return nil, err
	}
	return os.NewFile(uintptr(handle), path), nil
}

type captureDriver struct {
	dll                                                 *windows.DLL
	start, stop, revokeSession, lookupRelay, readStatus *windows.Proc
	bundle                                              *captureBundle
	callback                                            uintptr
	callMu                                              sync.RWMutex
	status                                              protocol.CaptureStatus
}

// Called only by an internal controlled capture lifecycle; it is deliberately
// unreachable from status/setup and the unverified public launch gate.
func loadCapture(resolve func(uintptr, *captureIdentityRequest, *captureIdentityResult) uintptr) (*captureDriver, error) {
	bundle, err := inspectCaptureBundle()
	if err != nil {
		return nil, err
	}
	path := filepath.Join(bundle.directory, "EnvaraCapture.dll")
	handle, err := windows.LoadLibraryEx(path, 0, windows.LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR|windows.LOAD_LIBRARY_SEARCH_DEFAULT_DIRS)
	if err != nil {
		bundle.close()
		return nil, errors.New("installed capture DLL could not be loaded")
	}
	driver := &captureDriver{dll: &windows.DLL{Name: path, Handle: handle}, bundle: bundle, status: bundle.status, callback: windows.NewCallback(resolve)}
	for name, destination := range map[string]**windows.Proc{"EnvaraCaptureStart": &driver.start, "EnvaraCaptureStop": &driver.stop, "EnvaraCaptureRevokeSession": &driver.revokeSession, "EnvaraCaptureLookupRelay": &driver.lookupRelay, "EnvaraCaptureStatusRead": &driver.readStatus} {
		proc, err := driver.dll.FindProc(name)
		if err != nil {
			_ = driver.dll.Release()
			bundle.close()
			return nil, errors.New("installed capture ABI exports missing")
		}
		*destination = proc
	}
	return driver, nil
}

func (driver *captureDriver) activate(port uint16) error {
	driver.callMu.Lock()
	defer driver.callMu.Unlock()
	config := captureConfig{Version: captureABI, RelayPort: uint32(port), HoldMilliseconds: 250, ResolveIdentity: uint64(driver.callback)}
	config.Size = uint32(unsafe.Sizeof(config))
	result, _, _ := driver.start.Call(uintptr(unsafe.Pointer(&config)))
	runtime.KeepAlive(config)
	if result != 0 {
		return fmt.Errorf("capture setup failed (ABI result %d)", result)
	}
	return nil
}
func (driver *captureDriver) refresh() error {
	driver.callMu.Lock()
	defer driver.callMu.Unlock()
	if driver.dll == nil {
		return errors.New("capture is closed")
	}
	var data [protocol.CaptureStatusSize]byte
	data[0] = byte(protocol.CaptureStatusSize)
	data[4] = captureABI
	result, _, _ := driver.readStatus.Call(uintptr(unsafe.Pointer(&data[0])))
	runtime.KeepAlive(data)
	if result != 0 {
		return errors.New("capture status unavailable")
	}
	status, err := protocol.DecodeCaptureStatus(data[:])
	if err != nil {
		return err
	}
	status.ProvenanceVerified = true
	driver.status = status
	return nil
}
func (driver *captureDriver) revoke(tag, generation uint64) error {
	driver.callMu.RLock()
	defer driver.callMu.RUnlock()
	if driver.dll == nil {
		return errors.New("capture is closed")
	}
	request := captureRevoke{Version: captureABI, SessionTag: tag, Generation: generation}
	request.Size = uint32(unsafe.Sizeof(request))
	result, _, _ := driver.revokeSession.Call(uintptr(unsafe.Pointer(&request)))
	runtime.KeepAlive(request)
	if result != 0 {
		return errors.New("capture session revocation failed")
	}
	return nil
}
func captureAddress(address *net.TCPAddr) (captureEndpoint, error) {
	var result captureEndpoint
	if address == nil || address.Port <= 0 || address.Port > 65535 || address.Zone != "" {
		return result, errors.New("relay endpoint invalid")
	}
	result.Port = uint16(address.Port)
	if ip := address.IP.To4(); ip != nil {
		copy(result.Address[:4], ip)
		result.Family = 4
	} else if ip := address.IP.To16(); ip != nil {
		copy(result.Address[:], ip)
		result.Family = 6
	} else {
		return result, errors.New("relay endpoint invalid")
	}
	return result, nil
}
func (driver *captureDriver) destination(conn *net.TCPConn) (captureRelayResult, error) {
	var result captureRelayResult
	peer, err := captureAddress(conn.RemoteAddr().(*net.TCPAddr))
	if err != nil {
		return result, err
	}
	local, err := captureAddress(conn.LocalAddr().(*net.TCPAddr))
	if err != nil {
		return result, err
	}
	query := captureRelayQuery{Version: captureABI, Accepted: captureTuple{Source: peer, Destination: local, Protocol: 6}}
	query.Size = uint32(unsafe.Sizeof(query))
	result.Size = uint32(unsafe.Sizeof(result))
	result.Version = captureABI
	driver.callMu.RLock()
	defer driver.callMu.RUnlock()
	if driver.dll == nil {
		return result, errors.New("capture is closed")
	}
	code, _, _ := driver.lookupRelay.Call(uintptr(unsafe.Pointer(&query)), uintptr(unsafe.Pointer(&result)))
	runtime.KeepAlive(query)
	runtime.KeepAlive(result)
	if code != 0 || result.Size != uint32(unsafe.Sizeof(result)) || result.Version != captureABI || result.Reserved != 0 || result.FlowID == 0 || result.RouteTag == 0 || result.SessionTag == 0 || result.Generation == 0 || result.PID == 0 || result.CreationTime == 0 || result.Original.Protocol != 6 || result.Original.Destination.Port == 0 || (result.Original.Destination.Family != 4 && result.Original.Destination.Family != 6) {
		return captureRelayResult{}, errors.New("connection lacks trusted capture flow context")
	}
	return result, nil
}
func (driver *captureDriver) close() {
	if driver == nil {
		return
	}
	driver.callMu.Lock()
	defer driver.callMu.Unlock()
	if driver.dll != nil {
		_, _, _ = driver.stop.Call()
		_ = driver.dll.Release()
		driver.dll = nil
	}
	driver.bundle.close()
}

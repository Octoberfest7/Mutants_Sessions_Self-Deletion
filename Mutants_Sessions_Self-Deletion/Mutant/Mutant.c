#include <Windows.h>
#include <stdio.h>
#include <TlHelp32.h>

unsigned int hash(const char* str) {
    unsigned int hash = 4712;
    int c;

    while (c = *str++)
        hash = ((hash << 5) + hash) + c;

    return hash;
}

DWORD find_process_by_name(const wchar_t* processname) //Find PID of specified process so that a handle may be opened.
{
    HANDLE hProcessSnap;
    PROCESSENTRY32W pe32;
    DWORD result;
    // Take a snapshot of all processes in the system.
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (INVALID_HANDLE_VALUE == hProcessSnap) return(FALSE);
    pe32.dwSize = sizeof(PROCESSENTRY32);

    // Retrieve information about the first process,
    // and exit if unsuccessful
    if (!Process32First(hProcessSnap, &pe32))
    {
        CloseHandle(hProcessSnap);          // clean the snapshot object
        return(NULL);
    }
    do
    {
        if (0 == wcscmp(processname, pe32.szExeFile))
        {
            result = pe32.th32ProcessID;
            break;
        }
    } while (Process32NextW(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);
    return result;
}

int main()
{
    char channel[255] = "HTTPS";
    //Username
    char username[255];
    DWORD username_len = 255;
    GetUserNameA(username, &username_len); 

    //Combine channel and username
    strcat_s(channel, sizeof(channel), username);

    //hash channelusername and convert to string, combine with Global\\ to create final mutex name
    unsigned int ihash = hash(channel);
    wchar_t wshash[255];
    swprintf(wshash, sizeof(wshash), L"%u", ihash);
    wchar_t mname[255] = L"Global\\";
    wcscat_s(mname, sizeof(mname), wshash);
    printf("Mutex name is %ls\n", wshash);
    //Finally call CreateMutexW with our unique name
    HANDLE mutanthandle = CreateMutexW(NULL, TRUE, mname);
    if (GetLastError() == ERROR_ALREADY_EXISTS) //Do not continue if mutant already exists
    {
        printf("Mutex already exists! Exiting!\n");
        return 0;
    }

    //Setup var's for PPID spoofing
    STARTUPINFOA si;
    STARTUPINFOEXA six;
    PROCESS_INFORMATION pi;
    size_t attrsize = 0;
    SECURITY_ATTRIBUTES lpa;
    SECURITY_ATTRIBUTES lta;
    ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
    ZeroMemory(&si, sizeof(STARTUPINFO));
    ZeroMemory(&six, sizeof(STARTUPINFOEX));
    six.StartupInfo.cb = sizeof(STARTUPINFOEX);
    ZeroMemory(&lpa, sizeof(SECURITY_ATTRIBUTES));
    ZeroMemory(&lta, sizeof(SECURITY_ATTRIBUTES));
    lpa.nLength = sizeof(SECURITY_ATTRIBUTES);
    lta.nLength = sizeof(SECURITY_ATTRIBUTES);
    HANDLE NewToken;

    //Initialize Process Thread Attribute List so we can edit and provide extended startup info
    InitializeProcThreadAttributeList(NULL, 1, 0, &attrsize);
    PPROC_THREAD_ATTRIBUTE_LIST pAttrList = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attrsize);
    InitializeProcThreadAttributeList(pAttrList, 1, 0, &attrsize);

    //Find PID of parent process selected by SetParentName()
    const wchar_t *parentname = L"explorer.exe";
    DWORD dwProcessId = find_process_by_name(parentname);

    //Get handle to parent process
    HANDLE hPProcess = OpenProcess(PROCESS_CREATE_PROCESS | PROCESS_DUP_HANDLE, FALSE, dwProcessId);

    //Open handle to current process, use DuplicateHandle to push Mutex handle to parent process
    HANDLE dupHandle;
    DuplicateHandle(GetCurrentProcess(), mutanthandle, hPProcess, &dupHandle, 0, TRUE, DUPLICATE_SAME_ACCESS | DUPLICATE_CLOSE_SOURCE);

    //Update ProcThreadAttributeList with PPID
    UpdateProcThreadAttribute(pAttrList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hPProcess, sizeof(HANDLE), NULL, NULL);

    //Update struct with attribute list
    six.lpAttributeList = pAttrList;

    //CreateProcess
    CreateProcessA(NULL, "c:\\windows\\system32\\notepad.exe", &lpa, &lta, TRUE, EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, &six.StartupInfo, &pi);
    
    //Remove mutex handle from parent process
    HANDLE ourHandle;
    DuplicateHandle(hPProcess, dupHandle, GetCurrentProcess(), &ourHandle, 0, FALSE, DUPLICATE_CLOSE_SOURCE);

    //Cleanup
    DeleteProcThreadAttributeList(pAttrList);
    CloseHandle(ourHandle);
    CloseHandle(dupHandle);
    CloseHandle(hPProcess);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    printf("Process Id: %d\n", pi.dwProcessId);
}
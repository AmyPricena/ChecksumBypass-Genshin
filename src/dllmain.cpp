#include "utils.h"
#include "debugger.h" //#akebi-contributors
#include <assert.h>
#include <vector>

static uint64_t UnityPlayer = reinterpret_cast<uint64_t>(GetModuleHandleA("UnityPlayer.dll"));

int RecordChecksumUserData_Hook(int type, char* out, int out_size)
{
	auto ret = CALL_ORIGIN(RecordChecksumUserData_Hook, type, out, out_size);
	Utils::ConsolePrint("RecordChecksumUserData with type %d and ret %d: %s\n", type, ret, out);

	const char* OSRel[] = {
		"eb8aeaf9f40c5bc5af2ac93ad1da07fa",
		"05acf5206fe08c10290357a414aecb7c24",
		"",
		""
	};

	const char* CNRel[] = {
		"64309cf5f6d6b7c427d3e15622636372",
		"c14bc8ce7252be4bd27e9a1866b688c226",
		"",
		""
	};

	std::vector<std::string> data;
	data.push_back(GetModuleHandleA("GenshinImpact.exe") ? *OSRel : *CNRel);

	assert(type < sizeof(data) / sizeof(const char*));
	for (auto& checksum : data)
	{
		ret = strlen(&checksum[type]);
		if (strcmp(&checksum[type], out) != 0)
			Utils::ConsolePrint("Hash mismatch, but required!\n");
		strncpy(out, &checksum[type], out_size);
	}
	return ret;
}

void ChecksumBypass()
{
#define ResolvePattern(instruction, sig) Resolve::##instruction(UnityPlayer, Utils::PatternScan(UnityPlayer, sig))
	auto RecordChecksumUserData = (int(*)(int, char*, int))(Utils::PatternScan(UnityPlayer, "55 41 57 41 56 41 55 41 54 56 57 53 48 81 ec ? ? ? ? 48 8d ac 24 ? ? ? ? 44 89 45 ? 48 89 55 ? 89 4d"));
	if (RecordChecksumUserData == nullptr)
		RecordChecksumUserData = (int(*)(int, char*, int))(ResolvePattern(JMP, "e8 ? ? ? ? 48 8b 4c 24 ? 89 01 48 8b 8c 24 ? ? ? ? 48 31 e1 e8 ? ? ? ? 48 81 c4 ? ? ? ? 5b"));
#undef ResolvePattern

	HookManager::install(RecordChecksumUserData, RecordChecksumUserData_Hook);
}

DWORD WINAPI Thread(LPVOID p)
{
	Utils::AttachConsole();
	DebuggerBypassPre();
	DebuggerBypassPost();

	while (true)
	{
		while (!(GetModuleHandleA("UnityPlayer.dll")))
			Sleep(1000);

		ChecksumBypass();
		Utils::CloseDriverHandleName(L"\\Device\\mhyprot2");

		Sleep(5000);
	}

	Utils::DetachConsole();
	FreeLibraryAndExitThread((HMODULE)p, 0);
	return 0;
}

BOOL WINAPI DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved)
{
	switch (dwReason)
	{
	case DLL_PROCESS_ATTACH:
		CloseHandle(CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)Thread, hModule, 0, nullptr));
		break;
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}
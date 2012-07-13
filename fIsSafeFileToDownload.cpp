#include <extdll.h>
#include <meta_api.h>
#include <comp_dep.h>

#include <fstream>
#include <vector>
#include <string>

#include "fIsSafeFileToDownload.h"

#if defined _WIN32
	engFunc is_safe_file = 
	{
		"\x55\x8B\xEC\x56\x8B\x75\x08\x85\xF6\x57\x0F\x84\xCA\x01\x00\x00\x6A\x04\x68\x4C\x4B\xE6\x01"
		"\x56\xE8\xD3\x57\xF9\xFF\x83\xC4\x0C\x85\xC0\x75\x09\x5F\xB8\x01\x00\x00\x00\x5E\x5D\xC3",

		"xxxxxxxxxxxx????xxx????xx????xxxxxxxxxxxxxxxx", 45, {}, {}, 0, (unsigned char *)IsSafeFile_HookHandler, "IsSafeFileToDownload", 0
	};
#else
	engFunc is_safe_file = 
	{
		"\x83\xEC\x14\x56\x53\x8B\x74\x24\x20\x85\xF6\x0F\x84\x2F\x02\x00\x00\x83\xC4\xFC"
		"\x6A\x04\x68\x24\x61\x0C\x00\x56\xE8\x7F\xF8\xFB\xFF\x83\xC4\x10\x85\xC0\x0F\x84"
		"\x0B\x02\x00\x00\x83\xC4\xF8\x68\xCF\x51\x0C\x00",

		"xxxxxxxxxxxxx????xxxxxx????xx????xxxxxxx????xxxx????", 52, {}, {}, 0, (unsigned char *)IsSafeFile_HookHandler, "IsSafeFileToDownload", 0
	};
#endif

std::vector <std::string *> goodexts;

void CacheFileExts()
{
	if (CVAR_GET_FLOAT("developer") != 0.0)
		ALERT(at_logged, "[Floodblocker]: Caching good extensions.\n");
	std::ifstream goodextsfile("cstrike/goodexts.txt");
	if (goodextsfile.is_open())
	{
		for(unsigned int i = 0; i < goodexts.size(); i++)
		{
			delete goodexts.at(i);
		}
		goodexts.clear();

		while (goodextsfile.good())
		{
			std::string *ext = new std::string;
			std::getline(goodextsfile, *ext);
			goodexts.push_back(ext);
		}
	}
}

void PrintGoodExts()
{
	if (goodexts.size() == 0)
	{
		SERVER_PRINT("[Floodblocker]: All extensions are forbidden.\n");
		return;
	}

	SERVER_PRINT("[Floodblocker]: List of good extensions:\n");
	for (unsigned int i = 0; i < goodexts.size(); i++)
	{
		SERVER_PRINT("    ");
		SERVER_PRINT(goodexts.at(i)->c_str());
		SERVER_PRINT("\n");
	}
}

C_DLLEXPORT DLLVISIBLE int IsSafeFile(char *filename)
{
	if (CVAR_GET_FLOAT("developer") != 0.0)
		ALERT(at_logged, "[Floodblocker]: Check next filename for downloading: %s\n", filename);
	for (unsigned int i = 0; i < goodexts.size(); i++)
	{
		if (strlen(filename)-goodexts.at(i)->size() > 0 && !strcasecmp(filename+strlen(filename)-goodexts.at(i)->size(), goodexts.at(i)->c_str()))
			return 1;
	}
	return 0;
}

#if defined _MSC_VER
	__declspec( naked ) 
#endif
void IsSafeFile_HookHandler()
{
#if defined _MSC_VER
	__asm
	{
		push dword ptr [esp+4]
		call IsSafeFile
		add esp, 4
		test eax, eax
		jnz good

		xor eax, eax
		retn

good:	push ebp
		mov ebp, esp
		push esi
		mov esi, dword ptr [ebp+8]

		mov ecx, is_safe_file.oFunc
		add ecx, 7
		jmp ecx
	}
#else
	__asm__ __volatile__ 
	(		
		"pushl 0x4(%%esp);"
		"movl IsSafeFile, %%eax;"
		"call *%%eax;"
		"addl $4, %%esp;"
		"test %%eax, %%eax;"
		"jnz good;"

		"xor %%eax, %%eax;"
		"ret;"

		"good: subl $0x14, %%esp;"
		"pushl %%esi;"
		"pushl %%ebx;"

		"movl %0, %%ecx;"
		"addl $5, %%ecx;"
		"jmp *%%ecx;"
		:
		:
		"m" (is_safe_file.oFunc)
	);
#endif
}
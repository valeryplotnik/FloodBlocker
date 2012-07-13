#include "engFunc.h"

#include <extdll.h>
#include <meta_api.h>

int				isBaseSet = false;
unsigned char*	swds_base;
size_t			swds_base_len;

#if defined _WIN32
BOOL FindEngineBase(void* func)
{
	MEMORY_BASIC_INFORMATION mem;
    VirtualQuery(func, &mem, sizeof(mem));
 
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER*)mem.AllocationBase;
    IMAGE_NT_HEADERS *pe = (IMAGE_NT_HEADERS*)((unsigned long)dos+(unsigned long)dos->e_lfanew);
 
    if(pe->Signature != IMAGE_NT_SIGNATURE) {
        swds_base = (unsigned char*)NULL;
		swds_base_len = 0;

		ALERT(at_logged, "[FloodBlocker]: Base search failed.\n");

		return (isBaseSet = FALSE);

	} else {
		swds_base = (unsigned char*)mem.AllocationBase;
		swds_base_len = (size_t)pe->OptionalHeader.SizeOfImage;

		return (isBaseSet = TRUE);
	}
}
#else
// Code derived from code from David Anderson
// You're going to help us, Mr. Anderson whether you want to or not. (c)
DLLINTERNAL long getBaseLen(void *baseAddress)
{
	pid_t pid = getpid();
	char file[255];
	char buffer[2048];
	snprintf(file, sizeof(file)-1, "/proc/%d/maps", pid);
	FILE *fp = fopen(file, "rt");
	if (fp)
	{
		long length = 0;

		void *start=NULL;
		void *end=NULL;

		while (!feof(fp))
		{
			if (fgets(buffer, sizeof(buffer)-1, fp) == NULL)
				return 0;

			sscanf(buffer, "%lx-%lx", reinterpret_cast< long unsigned int * > (&start), reinterpret_cast< long unsigned int * > (&end));

			if(start == baseAddress)
			{
				length = (unsigned long)end  - (unsigned long)start;

				char ignore[100];
				int value;

				while(!feof(fp))
				{
					if (fgets(buffer, sizeof(buffer)-1, fp) == NULL)
						return 0;

    				sscanf
    				(
    					buffer, 
    					"%lx-%lx %*s %*s %*s %d", 
    					reinterpret_cast< long unsigned int * > (&start), 
    					reinterpret_cast< long unsigned int * > (&end), 
    					&value
    				);

					if(!value)
					{		
						break;
					}
					else
					{
						length += (unsigned long)end  - (unsigned long)start;
					}
				}
				
				break;
			}
		}

		fclose(fp);

		return length;
	}

	return 0;
}

DLLINTERNAL int FindEngineBase(void* func)
{
	Dl_info info;

	if(!dladdr(func, &info) && !info.dli_fbase || !info.dli_fname)
	{
		swds_base = NULL;
		swds_base_len = 0;
		
		ALERT(at_logged, "[FloodBlocker]: Base search failed.\n");

		return (isBaseSet = 0);
	} else {
		swds_base = (unsigned char*)info.dli_fbase;
		swds_base_len = getBaseLen(swds_base);

		return (isBaseSet = 1);
	}
}
#endif

DLLINTERNAL void* FindFunction (const char *sig_str, const char *sig_mask, size_t sig_len)
{
	unsigned char* pBuff = swds_base;
	unsigned char* pEnd = swds_base+swds_base_len-sig_len;

	unsigned long i;
	while(pBuff < pEnd)
	{
		for(i = 0; i < sig_len; i++) {
			if((sig_mask[i] != '?') && ((unsigned char)(sig_str[i]) != pBuff[i]))
				break;
		}

		if(i == sig_len)
			return (void*)pBuff;

		pBuff++;
	}

    return NULL;
}

DLLINTERNAL void setHook(engFunc *func)
{
	if(AllowWriteToMemory(func->oFunc))
		memcpy(func->oFunc, func->pBytes, 5);
}

DLLINTERNAL void unsetHook(engFunc *func)
{
	if(AllowWriteToMemory(func->oFunc))
		memcpy(func->oFunc, func->oBytes, 5);
}

DLLINTERNAL int CreateFunctionHook(engFunc *func)
{
	if(0 == isBaseSet)
		return 0;

	if(0 != (func->oFunc = (unsigned char*)FindFunction(func->sig_str, func->sig_mask, func->sig_len)))
	{
		memcpy((void*)func->oBytes, (void*)func->oFunc, 5);
		
		func->pBytes[0]=0xE9;
		*(unsigned long *)&func->pBytes[1] = (unsigned long)func->hFunc-(unsigned long)func->oFunc-5;

		ALERT(at_logged, "[Floodblocker]: Function %s founded at 0x%08X\n", func->fn_name, (unsigned long)func->oFunc);
		
		return (func->done = 1);

	} else {
		ALERT(at_logged, "[FloodBlocker]: Function search failed(no function founded).\n");
		return (func->done = 0);
	}
}

DLLINTERNAL int AllowWriteToMemory(void *addr)
{
#if defined _WIN32
	DWORD OldProtection, NewProtection = PAGE_EXECUTE_READWRITE;
	if(VirtualProtect(addr, 5, NewProtection, &OldProtection))
#else
	void* alignedAddress = Align(addr);
	if(!mprotect(alignedAddress, sysconf(_SC_PAGESIZE), (PROT_READ | PROT_WRITE | PROT_EXEC)))
#endif
			return(TRUE);
	return(FALSE);
}
#include "engFunc.h"

#include <extdll.h>
#include <meta_api.h>

module swds = {NULL, 0, NULL};

#if defined _WIN32
int FindModuleByAddr (void *addr, module *lib)
{
	MEMORY_BASIC_INFORMATION mem;
    VirtualQuery(addr, &mem, sizeof(mem));
 
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER*)mem.AllocationBase;
    IMAGE_NT_HEADERS *pe = (IMAGE_NT_HEADERS*)((unsigned long)dos+(unsigned long)dos->e_lfanew);
 
    if(pe->Signature != IMAGE_NT_SIGNATURE)
    {
		return FALSE;
	}
	else
	{
		lib->base = mem.AllocationBase;
		lib->size = (size_t)pe->OptionalHeader.SizeOfImage;
		lib->handler = lib->base;

		return TRUE;
	}
}
#else
// Code derived from code from David Anderson
// You're going to help us, Mr. Anderson whether you want to or not. (c)
long getBaseLen(void *baseAddress)
{
	pid_t pid = getpid();
	char file[255];
	char buffer[2048];
	snprintf(file, sizeof(file)-1, "/proc/%d/maps", pid);
	FILE *fp = fopen(file, "rt");
	if (fp)
	{
		long length = 0;

		void *start = NULL;
		void *end = NULL;

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

int FindModuleByAddr (void *addr, module *lib)
{
	if (!lib)
		return FALSE;
	
	Dl_info info;

	if (!dladdr(addr, &info) && !info.dli_fbase || !info.dli_fname)
	{
		return FALSE;
	}
	else
	{
		lib->base = info.dli_fbase;
		lib->size = (size_t)getBaseLen(lib->base);
		lib->handler = dlopen(info.dli_fname, RTLD_NOW);

		return TRUE;
	}
}
#endif

void *FindFunction (module *lib, signature sig)
{
	if (!lib)
		return NULL;
	
	if (!sig.text || !sig.mask || sig.size == 0)
		return NULL;
	
	unsigned char *pBuff = (unsigned char *)lib->base;
	unsigned char *pEnd = (unsigned char *)lib->base+lib->size-sig.size;

	unsigned long i;
	while (pBuff < pEnd)
	{
		for (i = 0; i < sig.size; i++) {
			if ((sig.mask[i] != '?') && ((unsigned char)(sig.text[i]) != pBuff[i]))
				break;
		}

		if (i == sig.size)
			return (void*)pBuff;

		pBuff++;
	}

    return NULL;
}

void *FindFunction (module *lib, const char *name)
{
	if (!lib)
		return NULL;
	
	return DLSYM((DLHANDLE)lib->handler, name);
}

void *FindFunction (function *func)
{
	if (!func)
		return NULL;
	
	void *address = NULL;
	if (NULL == (address = FindFunction(func->lib, func->name)))
	{
		return FindFunction(func->lib, func->sig);
	}
	
	if (CVAR_GET_FLOAT("developer") != 0.0)
			ALERT(at_logged, "[Floodblocker]: Function %s founded by NAME\n", func->name);
	return address;
}

void SetHook(function *func)
{
	if(AllowWriteToMemory(func->address))
		memcpy(func->address, func->patch, 5);
}

void UnsetHook(function *func)
{
	if(AllowWriteToMemory(func->address))
		memcpy(func->address, func->origin, 5);
}

int CreateFunctionHook(function *func)
{
	if (!func)
		return 0;

	if (NULL != (func->address = (unsigned char*)FindFunction(func)))
	{
		memcpy(func->origin, func->address, 5);
		
		func->patch[0]=0xE9;
		*(unsigned long *)&func->patch[1] = (unsigned long)func->handler-(unsigned long)func->address-5;
		
		if (CVAR_GET_FLOAT("developer") != 0.0)
			ALERT(at_logged, "[Floodblocker]: Function %s founded at %08X\n", func->name, (unsigned long)func->address);
		
		return (func->done = TRUE);
	}
	else
		return (func->done = FALSE);
}

int AllowWriteToMemory(void *address)
{
#if defined _WIN32
	DWORD OldProtection, NewProtection = PAGE_EXECUTE_READWRITE;
	if (VirtualProtect(address, 5, NewProtection, &OldProtection))
#else
	void* alignedAddress = Align(address);
	if (!mprotect(alignedAddress, sysconf(_SC_PAGESIZE), (PROT_READ | PROT_WRITE | PROT_EXEC)))
#endif
		return TRUE;
	return FALSE;
}
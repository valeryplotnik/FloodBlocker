#ifndef _ENGINE_H
#define _ENGINE_H

#if defined _WIN32
	#include <windows.h>
	#include <psapi.h>
#else
	#include <dlfcn.h>
	#include <sys/types.h>
	#include <sys/stat.h>
	#include <sys/mman.h>
	#include <unistd.h>
	#define	PAGE_SIZE 4096
	#define Align(addr) (void*)((long)addr & ~(PAGE_SIZE-1))
#endif

struct module
{
	void             *base;
	size_t           size;
	void             *handler;
};

struct signature
{
	const char       *text;
	const char       *mask;
	size_t           size;
};

struct function
{
	const char       *name;
	
	module           *lib;
	
	signature        sig;
	
	void             *address;
	void             *handler;
	
	unsigned char    patch[5];
	unsigned char    origin[5];

	int              done;
};

int FindModuleByAddr (void *addr, module *lib);
void *FindFunction (module *lib, signature sig);
void *FindFunction (module *lib, const char *name);
void *FindFunction (function *func);

void SetHook (function *func);
void UnsetHook (function *func);

int CreateFunctionHook (function *func);
int AllowWriteToMemory (void *address);

extern module swds;

#endif // _ENGINE_H
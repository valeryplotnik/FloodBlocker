#ifndef _ENG_FUNC_H
#define _ENG_FUNC_H

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

struct engFunc
{
	const char       *sig_str;
	const char       *sig_mask;
	size_t           sig_len;
	
	unsigned char    pBytes[5];
	unsigned char    oBytes[5];

	unsigned char    *oFunc;
	unsigned char    *hFunc;

	const char       *fn_name;

	int              done;
};

extern unsigned char    *swds_base;
extern size_t           swds_base_len;
extern int              isBaseSet;

int FindEngineBase (void *addr);
void* FindFunction (const char *sig_str, const char *sig_mask, size_t sig_len);

void unsetHook (engFunc *func);
void setHook (engFunc *func);
int CreateFunctionHook (engFunc *func);
int AllowWriteToMemory (void *addr);

#endif // _ENG_FUNC_H
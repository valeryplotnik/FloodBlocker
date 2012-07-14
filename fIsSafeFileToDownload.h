#ifndef _IS_SAFE_FILE_H
#define _IS_SAFE_FILE_H

#include "engFunc.h"
extern function is_safe_file;

void IsSafeFile_HookHandler(const char* filename);
void CacheFileExts(void);
void PrintGoodExts(void);

#endif //_IS_SAFE_FILE_H
#include <extdll.h>
#include <meta_api.h>
#include <comp_dep.h>

#include <vector>
#include <string>

#include "core.h"

meta_globals_t	*gpMetaGlobals;
mutil_funcs_t	*gpMetaUtilFuncs;
globalvars_t	*gpGlobals;
enginefuncs_t    g_engfuncs;

extern std::vector <std::string *> goodexts;

void CmdGetBannedList();
void PrintGoodExts();
void CacheFileExts();

plugin_info_t info = {
	META_INTERFACE_VERSION,				// ifvers
	VNAME,								// name
	VVERSION,							// version
	VDATE,								// date
	VAUTHOR,							// author
	VURL,								// url
	VLOGTAG,							// logtag, all caps please
	PT_STARTUP,							// (when) loadable
	PT_NEVER							// (when) unloadable
};

static META_FUNCTIONS gMetaFunctionTable = 
{
	NULL,				// pfnGetEntityAPI				HL SDK; called before game DLL
	NULL,				// pfnGetEntityAPI_Post			META; called after game DLL
	NULL,				// pfnGetEntityAPI2				HL SDK2; called before game DLL
	NULL,				// pfnGetEntityAPI2_Post		META; called after game DLL
	NULL,				// pfnGetNewDLLFunctions		HL SDK2; called before game DLL
	NULL,				// pfnGetNewDLLFunctions_Post	META; called after game DLL
	NULL,				// pfnGetEngineFunctions		META; called before HL engine
	NULL				// pfnGetEngineFunctions_Post	META; called after HL engine
};

#if defined _MSC_VER
	#pragma comment(linker, "/EXPORT:GiveFnptrsToDll=_GiveFnptrsToDll@8")
#endif

C_DLLEXPORT DLLVISIBLE void WINAPI
GiveFnptrsToDll(enginefuncs_t* pengfuncsFromEngine, globalvars_t *pGlobals)
{
	memcpy(&g_engfuncs, pengfuncsFromEngine, sizeof(enginefuncs_t));
	gpGlobals = pGlobals;
}

C_DLLEXPORT DLLVISIBLE int Meta_Query(char *interfaceVersion, plugin_info_t **pinfo, mutil_funcs_t *pMetaUtilFuncs)
{
	*pinfo = &info;
	gpMetaUtilFuncs = pMetaUtilFuncs;
	return TRUE;
}

C_DLLEXPORT DLLVISIBLE int Meta_Attach(PLUG_LOADTIME now, META_FUNCTIONS *pFunctionTable, meta_globals_t *pMGlobals, gamedll_funcs_t *pGamedllFuncs)
{
	if(pFunctionTable == NULL)
	{
		return FALSE;
	}

	if(FindEngineBase((void*)g_engfuncs.pfnAlertMessage))
	{
		if(CreateFunctionHook(&sv_connect_client))
			setHook(&sv_connect_client);
		else
			return FALSE;

		if(CreateFunctionHook(&is_safe_file))
			setHook(&is_safe_file);
		else
			return FALSE;
	} 
	else
		return FALSE;

	memcpy(pFunctionTable, &gMetaFunctionTable, sizeof(META_FUNCTIONS));
	gpMetaGlobals = pMGlobals;

	goodexts.clear();
	CacheFileExts();

	REG_SVR_COMMAND("banlst", CmdGetBannedList);
	REG_SVR_COMMAND("goodexts", PrintGoodExts);
	REG_SVR_COMMAND("reloadexts", CacheFileExts);

	return TRUE;
}

C_DLLEXPORT DLLVISIBLE int Meta_Detach(PLUG_LOADTIME now, PL_UNLOAD_REASON reason)
{
	if (sv_connect_client.done)
		unsetHook(&sv_connect_client);
	if (is_safe_file.done)
		unsetHook(&is_safe_file);
	
	return TRUE;
}
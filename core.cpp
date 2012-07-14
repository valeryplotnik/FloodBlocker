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

extern module swds;
extern std::vector <std::string *> goodexts;

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
		
	if(FindModuleByAddr((void*)g_engfuncs.pfnAlertMessage, &swds))
	{
		if (CVAR_GET_FLOAT("developer") != 0.0)
			ALERT(at_logged, "[FloodBlocker]: Main engine module founded at %08X.\n", (unsigned long)swds.base);
		
		
		if(CreateFunctionHook(&sv_connect_client))
		{
			SetHook(&sv_connect_client);
		}
		else
		{
			if (CVAR_GET_FLOAT("developer") != 0.0)
				ALERT(at_logged, "[FloodBlocker]: Function SV_ConnectClient not founded.\n");
			
			return FALSE;
		}

		if(CreateFunctionHook(&is_safe_file))
		{
			SetHook(&is_safe_file);
		}
		else
		{
			if (CVAR_GET_FLOAT("developer") != 0.0)
				ALERT(at_logged, "[FloodBlocker]: Function IsSafeFileToDownload not founded.\n");
		
			return FALSE;
		}
	} 
	else
	{
		if (CVAR_GET_FLOAT("developer") != 0.0)
			ALERT(at_logged, "[FloodBlocker]: Engine base search failed.\n");
		
		return FALSE;
	}

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
		UnsetHook(&sv_connect_client);
	if (is_safe_file.done)
		UnsetHook(&is_safe_file);
	
	return TRUE;
}
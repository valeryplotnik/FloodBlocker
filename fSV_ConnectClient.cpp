#include <extdll.h>
#include <meta_api.h>
#include <comp_dep.h>

#include <ctime>
#include <map>
#include <utility>
#include <sstream>

#include "fSV_ConnectClient.h"

#if defined _WIN32
	function sv_connect_client = 
	{
		"SV_ConnectClient", //name
		&swds, //lib
		
		{
		
			"\x55\x8B\xEC\x81\xEC\x90\x0E\x00\x00\x53\x56\x57\xB9\x05\x00\x00\x00"
			"\xBE\x20\xD6\x56\x02\x8D\x7D\xDC\x33\xDB\x68\xE4\x56\xE6\x01\xF3\xA5",
			"xxxxx????xxxxxxxxx????xx?xxx????xx", 
			34
		}, //signature
		
		NULL, //address
		(void*)ConnectClient_HookHandler, //handler
		
		{}, {}, //bytes
		
		0 //done
	};
#else
	function sv_connect_client = 
	{
		"SV_ConnectClient", //name
		&swds, //lib
		
		{
			"\x55\x89\xE5\x81\xEC\xBC\x0E\x00\x00\x57\x56\x53\xC7\x85\x7C\xF1\xFF\xFF\x00\x00"
			"\x00\x00\xC7\x85\x84\xF1\xFF\xFF\xFF\xFF\xFF\xFF\xC7\x85\x74\xF1\xFF\xFF\x00\x00"
			"\x00\x00\x8D\x7D\xEC\xBE\x78\x74\x54\x00\xFC\xB9\x05\x00\x00\x00\xF3\xA5",
			"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx????xxxxxxxx", 
			58,
		}, //signature
		
		NULL, //address
		(void*)ConnectClient_HookHandler, //handler
		
		{}, {}, //bytes
		
		0 //done
	};
#endif

//key - ip address
//first pair value - connection count in 15 seconds, since
//second pair value - first connect time
std::map< int, std::pair<int,time_t> > connections;

enum netadrtype_t
{
  NA_UNUSED = 0x0,
  NA_LOOPBACK = 0x1,
  NA_BROADCAST = 0x2,
  NA_IP = 0x3,
  NA_IPX = 0x4,
  NA_BROADCAST_IPX = 0x5,
};

typedef struct netadr_s
{
  netadrtype_t address_type;
  int ipaddress;
  int protoid;
  short netadr_field4;
  short netadr_field5;
  short netadr_field6;
  unsigned short port;
} netadr_t;

netadr_t* net_from;

void CmdGetBannedList(void)
{
	if (connections.size() == 0)
	{
		SERVER_PRINT("[Floodblocker]: Banned IPs are missing.\n");
		return;
	}
	
	std::map< int, std::pair<int,time_t> >::iterator it;
	SERVER_PRINT("[FloodBlocker]: List of banned ips:\n");
	for (it = connections.begin(); it != connections.end(); ++it)
	{
		if (it->second.first > 5 && time(NULL) - it->second.second < 5*60*1000)
		{
			std::ostringstream ip;
			ip	<< ((it->first)&0x000000FF) 			<< '.'
				<< (((it->first)&0x0000FF00) >> 8)  	<< '.'
				<< (((it->first)&0x00FF0000) >> 16) 	<< '.'
				<< (((it->first)&0xFF000000) >> 24);
			SERVER_PRINT("    ");
			SERVER_PRINT(ip.str().c_str());
			SERVER_PRINT("\n");
		}
	}
}

C_DLLEXPORT DLLVISIBLE int IsConnectionAllowed(void)
{
	std::ostringstream ip;
	ip	<< ((net_from->ipaddress)&0x000000FF) 			<< '.'
		<< (((net_from->ipaddress)&0x0000FF00) >> 8)  	<< '.'
		<< (((net_from->ipaddress)&0x00FF0000) >> 16) 	<< '.'
		<< (((net_from->ipaddress)&0xFF000000) >> 24);
		
	if (CVAR_GET_FLOAT("developer") != 0.0)
		ALERT(at_logged, "[Floodblocker]: IP address %s connects %d time for last 15 seconds\n", ip.str().c_str(), connections[net_from->ipaddress].first+1);

	if(time(NULL)-connections[net_from->ipaddress].second > 15)
	{
		connections[net_from->ipaddress].first = 0;
		connections[net_from->ipaddress].second = time(NULL);
	}

	if(++connections[net_from->ipaddress].first > 5)
	{
		SERVER_PRINT("[Floodblocker]: IP address ");
		SERVER_PRINT(ip.str().c_str());
		SERVER_PRINT(" exceedes connection limit\nBanned for 5 minutes\n");
		
		std::ostringstream cmd;
		cmd << "addip 5 " << ip.str().c_str() << std::endl;
		SERVER_COMMAND((char*)cmd.str().c_str());

		return FALSE;
	}

	return TRUE;
}

#if defined _MSC_VER
	__declspec( naked ) 
#endif
void ConnectClient_HookHandler(void)
{
#if defined _MSC_VER
	__asm
	{
		mov eax, sv_connect_client.address
		mov eax, dword ptr [eax+18]
		mov net_from, eax

		call IsConnectionAllowed
		test eax, eax
		jnz good

		retn

good:	push ebp
		mov ebp, esp
		sub esp, 0E90h

		mov ecx, sv_connect_client.address
		add ecx, 9
		jmp ecx
	}
#else
	/*TODO: fix this shit
	__asm__ __volatile__ 
	(		
		"movl %1, %%eax;"
		"movl 0x2E(%%eax), %%eax;"
		"movl %%eax, %0;"

		"movl IsConnectionAllowed, %%eax;"
		"call *%%eax;"
		"test %%eax, %%eax;"
		"jnz good;"
		"ret;"

		"good: pushl %%ebp;"
		"mov %%esp, %%ebp;"
		"subl $0xEBC, %%esp;"

		"movl %2, %%eax;"
		"addl $9, %%eax;"
		"jmp *%%eax;"
		:
		"=m" (net_from)
		:
		"m" (sv_connect_client.address),
		"m" (sv_connect_client.address)
	);*/
	__asm__ __volatile__ 
	(		
		"movl %1, %%eax;"
		"movl 0x2E(%%eax), %%eax;"
		"movl %%eax, %0;"
		:"=m" (net_from)
		:"m" (sv_connect_client.address)
	);
	
	if (IsConnectionAllowed())
	{
		UnsetHook(&sv_connect_client);
		((void (*)(void))sv_connect_client.address)();
		SetHook(&sv_connect_client);
	}
	else
		return;
	
#endif
}
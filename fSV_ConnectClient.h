#ifndef _SV_CONNECT_CLIENT_H
#define _SV_CONNECT_CLIENT_H

#include "engFunc.h"
extern function sv_connect_client;

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

extern netadr_t* net_from;

void ConnectClient_HookHandler(void);
void CmdGetBannedList(void);

#endif //_SV_CONNECT_CLIENT_H
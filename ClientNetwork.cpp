// ClientNetwork.cpp
// DNS Proxy Filter Server
// Copyright (c) 2010-2019 Untangle, Inc.
// All Rights Reserved
// Written by Michael A. Hotz

#include "common.h"

/*
	The ClientNetwork class is responsible for handling all network
	communication with client workstations.  On startup, it
	enumerates all interfaces, opens and binds all sockets, and then
	uses the epoll mechanism to process network traffic.  When a
	query is received, a ProxyEntry object is allocated and stored
	in the ProxyTable.  This entry holds all information related to
	the query, including the grid and slot values we use to track the
	query through each step of our logic.  These values are then
	passed to the QueryFilter message queue for processing.  Other
	threads will later call our member function ForwardUDPReply to
	send the response back to the client.
*/

/*--------------------------------------------------------------------------*/
ClientNetwork::ClientNetwork(void)
{
// clear the network array and count
memset(&IPv4list,0,sizeof(IPv4list));
IPv4tot = 0;

memset(netface,0,sizeof(netface));

memset(tcplisten,0,sizeof(tcplisten));
memset(udplisten,0,sizeof(udplisten));
tcpactive = NULL;
pollsock = 0;
tcpcount = 0;
running = 1;
}
/*--------------------------------------------------------------------------*/
ClientNetwork::~ClientNetwork(void)
{
}
/*--------------------------------------------------------------------------*/
void* ClientNetwork::ThreadWorker(void)
{
epoll_event		*trigger;
netportal		*local;
time_t			lasttime,current;
int				iftot,evtot;
int				check;
int				ret;
int				x;

// build the list of interfaces and open all the sockets
EnumerateInterfaces();
iftot = SocketStartup();

	// not bound to any interfaces so clear running flag and return
	if (iftot == 0)
	{
	running = 0;
	return(NULL);
	}

// allocate a chunk of memory to hold events returned from epoll_wait
evtot = ((iftot * 2) + cfg_SessionLimit);
trigger = (epoll_event *)calloc(evtot,sizeof(struct epoll_event));

lasttime = time(NULL);

	for(;;)
	{
	current = time(NULL);

		// every second we clean the TCP session table
		if (current > lasttime)
		{
		SessionCleanup();
		lasttime = current;
		}

	// watch the thread signal for termination
	check = 0;
	ret = sem_getvalue(&ThreadSignal,&check);
	if (ret != 0) break;
	if (check != 0) break;

	// wait for one of the sockets to receive something
	ret = epoll_wait(pollsock,trigger,evtot,1000);
	if (ret == 0) continue;

	// ignore interrupted system call errors
	if ((ret < 0) && (errno == EINTR)) continue;

		// any other error is bad news so we bail
		if (ret < 0)
		{
		g_log->LogMessage(LOG_ERR,"Error %d returned from epoll_wait(client)\n",errno);
		break;
		}

		// process all the events that were returned
		for(x = 0;x < ret;x++)
		{
		// get pointer to the netportal object from the epoll event
		local = (netportal *)trigger[x].data.ptr;

		// use process and continue here because for a TCP event
		// the netportal object may be deleted while processing
		if (local->proto == IPPROTO_RAW) { ProcessTCPConnect(local); continue; }
		if (local->proto == IPPROTO_TCP) { ProcessTCPQuery(local); continue; }
		if (local->proto == IPPROTO_UDP) { ProcessUDPQuery(local); continue; }
		}
	}

// force cleanup any active TCP sessions
SessionCleanup(TRUE);

// cleanup and return
free(trigger);
SocketDestroy();
running = 0;

return(NULL);
}
/*--------------------------------------------------------------------------*/
void ClientNetwork::EnumerateInterfaces(void)
{
struct sockaddr_in	*ptr;
struct ifconf		info;
struct ifreq		*ifr;
unsigned int		special;
char				*databuff;
int					doff,len;
int					skip,x;
int					sock;

// allocate buffer to hold the interface information
databuff = (char *)calloc(1024,256);
if (databuff == NULL) return;

// setup the interface request buffer
memset(&info,0,sizeof(info));
info.ifc_ifcu.ifcu_buf = databuff;
info.ifc_len = (256 * 1024);

// grab info about all the network interfaces
sock = socket(PF_INET,SOCK_STREAM,0);
ioctl(sock,SIOCGIFCONF,&info);
close(sock);

doff = 0;

	// walk through each entry in the buffer
	while (doff < info.ifc_len)
	{
	ifr = (ifreq *)&databuff[doff];

#ifdef HAVE_SOCKADDR_SA_LEN

	len = sizeof(struct sockaddr);
	if (ifr->ifr_addr.sa_len > len) len = ifr->ifr_addr.sa_len;

#else

	len = sizeof(ifr->ifr_ifru);

#endif

	// adjust the working offset
	doff+=sizeof(ifr->ifr_name);
	doff+=len;

	// ignore interfaces we don't care about or that are down
	if (ifr->ifr_ifru.ifru_addr.sa_family != AF_INET) continue;
	ptr = (sockaddr_in *)&ifr->ifr_addr;
	if (ptr->sin_addr.s_addr == 0) continue;

	skip = 0;

		for(x = 0;x < cfg_NetFilterCount;x++)
		{
		special = (ptr->sin_addr.s_addr & cfg_NetFilterMask[x]);
		if (special == cfg_NetFilterAddr[x]) skip++;
		}

	if (skip != 0) continue;

	// save the address in our list
	IPv4list[IPv4tot] = ptr->sin_addr.s_addr;

	// save the interface address dotted quad string
	inet_ntop(AF_INET,&ptr->sin_addr,netface[IPv4tot],sizeof(netface[IPv4tot]));
	IPv4tot++;
	}

free(databuff);
}
/*--------------------------------------------------------------------------*/
int ClientNetwork::SocketStartup(void)
{
struct sockaddr_in		addr;
struct epoll_event		evt;
int						val,ret;
int						total;
int						x;

total = 0;

	for(x = 0;x < IPv4tot;x++)
	{
	// open a socket for the interface
	g_log->LogMessage(LOG_INFO,"ClientNetwork listening on %s:%d\n",netface[x],cfg_ServerPort);
	tcplisten[total].ifidx = x;
	tcplisten[total].proto = IPPROTO_RAW;
	tcplisten[total].sock = socket(PF_INET,SOCK_STREAM,0);

		if (tcplisten[total].sock == -1)
		{
		g_log->LogMessage(LOG_ERR,"Error %d returned from socket(client)\n",errno);
		return(0);
		}

	// allow binding even with old sockets in TIME_WAIT status
	val = 1;
	ret = setsockopt(tcplisten[total].sock,SOL_SOCKET,SO_REUSEADDR,(char *)&val,sizeof(val));

		if (ret == -1)
		{
		g_log->LogMessage(LOG_ERR,"Error %d returned from setsockopt(SO_REUSEADDR)\n",errno);
		return(0);
		}

	// set socket to nonblocking mode
	ret = fcntl(tcplisten[total].sock,F_SETFL,O_NONBLOCK);

		if (ret == -1)
		{
		g_log->LogMessage(LOG_ERR,"Error %d returned from fcntl(O_NONBLOCK)\n",errno);
		return(0);
		}

	// bind the socket to our server interface
	memset(&addr,0,sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(cfg_ServerPort);
	addr.sin_addr.s_addr = IPv4list[x];
	ret = bind(tcplisten[total].sock,(struct sockaddr *)&addr,sizeof(addr));

		if (ret == -1)
		{
		g_log->LogMessage(LOG_ERR,"Error %d returned from bind(client)\n",errno);
		return(0);
		}

	// listen for connections on the socket
	ret = listen(tcplisten[total].sock,cfg_ListenBacklog);

		if (ret == -1)
		{
		g_log->LogMessage(LOG_ERR,"Error %d returned from listen(client)\n",errno);
		return(0);
		}

	udplisten[total].ifidx = x;
	udplisten[total].proto = IPPROTO_UDP;
	udplisten[total].sock = socket(PF_INET,SOCK_DGRAM,0);

		if (udplisten[total].sock == -1)
		{
		g_log->LogMessage(LOG_ERR,"Error %d returned from socket(client)\n",errno);
		return(0);
		}

	// allow binding even with old sockets in TIME_WAIT status
	val = 1;
	ret = setsockopt(udplisten[total].sock,SOL_SOCKET,SO_REUSEADDR,(char *)&val,sizeof(val));

		if (ret == -1)
		{
		g_log->LogMessage(LOG_ERR,"Error %d returned from setsockopt(SO_REUSEADDR)\n",errno);
		return(0);
		}

	// set socket to nonblocking mode
	ret = fcntl(udplisten[total].sock,F_SETFL,O_NONBLOCK);

		if (ret == -1)
		{
		g_log->LogMessage(LOG_ERR,"Error %d returned from fcntl(O_NONBLOCK)\n",errno);
		return(0);
		}

	// bind the socket to our server interface
	memset(&addr,0,sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(cfg_ServerPort);
	addr.sin_addr.s_addr = inet_addr(netface[x]);
	ret = bind(udplisten[total].sock,(struct sockaddr *)&addr,sizeof(addr));

		if (ret == -1)
		{
		g_log->LogMessage(LOG_ERR,"Error %d returned from bind(client)\n",errno);
		return(0);
		}

	// increment number of active interfaces
	total++;
	}

g_log->LogMessage(LOG_DEBUG,"Setting up client epoll engine\n");

// allocate an epoll large enough to hold all interfaces
pollsock = epoll_create((total * 2) + cfg_SessionLimit);

	if (pollsock < 0)
	{
	g_log->LogMessage(LOG_ERR,"Error %d returned from epoll_create(client)\n",errno);
	return(0);
	}

	// add each TCP and UDP socket to the epoll
	for(x = 0;x < total;x++)
	{
	memset(&evt,0,sizeof(evt));
	evt.data.ptr = &tcplisten[x];
	evt.events = EPOLLIN;
	ret = epoll_ctl(pollsock,EPOLL_CTL_ADD,tcplisten[x].sock,&evt);

		if (ret != 0)
		{
		g_log->LogMessage(LOG_ERR,"Error %d returned from TCP epoll_ctl(client)\n",errno);
		return(0);
		}

	memset(&evt,0,sizeof(evt));
	evt.data.ptr = &udplisten[x];
	evt.events = EPOLLIN;
	ret = epoll_ctl(pollsock,EPOLL_CTL_ADD,udplisten[x].sock,&evt);

		if (ret != 0)
		{
		g_log->LogMessage(LOG_ERR,"Error %d returned from UDP epoll_ctl(client)\n",errno);
		return(0);
		}
	}

return(total);
}
/*--------------------------------------------------------------------------*/
void ClientNetwork::SocketDestroy(void)
{
int		x;

// close the epoll descriptor
g_log->LogMessage(LOG_DEBUG,"Shutting down client epoll engine\n");
close(pollsock);

	// shutdown and close all our sockets
	for(x = 0;x < IPv4tot;x++)
	{
	g_log->LogMessage(LOG_INFO,"Disconnecting ClientNetwork from %s:%d\n",netface[x],cfg_ServerPort);

		if (tcplisten[x].sock > 0)
		{
		shutdown(tcplisten[x].sock,SHUT_RDWR);
		close(tcplisten[x].sock);
		}

		if (udplisten[x].sock > 0)
		{
		shutdown(udplisten[x].sock,SHUT_RDWR);
		close(udplisten[x].sock);
		}
	}
}
/*--------------------------------------------------------------------------*/
int ClientNetwork::SessionCleanup(int argForce)
{
struct netportal	*item,*next;
time_t				current;
char				textaddr[32];
int					total;

// get the current time and initialize local variables
current = time(NULL);
item = tcpactive;
total = 0;

	// look at every item in the linked list
	while (item != NULL)
	{
	// save pointer to next
	next = item->next;

		// if the item is stale or force is set we delete
		if (((current - item->created) > cfg_SessionTimeout) || (argForce != 0))
		{
		inet_ntop(AF_INET,&item->addr.sin_addr,textaddr,sizeof(textaddr));
		g_log->LogMessage(LOG_DEBUG,"Removing stale client TCP session from %s:%d\n",textaddr,htons(item->addr.sin_port));
		RemoveSession(item);
		total++;
		}

	// adjust our working pointer
	item = next;
	}

return(total);
}
/*--------------------------------------------------------------------------*/
void ClientNetwork::RemoveSession(struct netportal *argPortal)
{
struct epoll_event	evt;
int					ret;

// remove the socket from the epoll - note that evt isn't used but
// we pass it to prevent a bug in case the kernel version < 2.3.9
memset(&evt,0,sizeof(evt));
ret = epoll_ctl(pollsock,EPOLL_CTL_DEL,argPortal->sock,&evt);

	// unexpected error so spew a message and clear the running flag
	if (ret != 0)
	{
	g_log->LogMessage(LOG_ERR,"Error %d returned from epoll_ctl(client)\n",errno);
	running = 0;
	}

// shutdown and close the socket
shutdown(argPortal->sock,SHUT_RDWR);
close(argPortal->sock);

// remove the netportal from the double linked list
if (argPortal->last != NULL) argPortal->last->next = argPortal->next;
if (argPortal->next != NULL) argPortal->next->last = argPortal->last;

// if the item we deleted was first in the list adjust the pointer
if (tcpactive == argPortal) tcpactive = argPortal->next;

// delete the object and decrement the session counter
delete(argPortal);
tcpcount--;
}
/*--------------------------------------------------------------------------*/
int ClientNetwork::ProcessTCPConnect(netportal *argPortal)
{
struct epoll_event	evt;
struct netportal	*network;
unsigned int		ret,len;
char				textaddr[32];

// if maximum number of sessions has been reached just return.
// the socket will stay in triggered status and we try again
// on the next epoll_wait attempt
if (tcpcount == cfg_SessionLimit) return(0);

// create new network object and accept the inbound connection
network = new netportal();
memset(network,0,sizeof(struct netportal));
len = sizeof(network->addr);
network->sock = accept(argPortal->sock,(struct sockaddr *)&network->addr,&len);

	if (network->sock == -1)
	{
	g_log->LogMessage(LOG_WARNING,"Error %d returned from accept(%s)\n",errno,netface[argPortal->ifidx]);
	delete(network);
	return(0);
	}

// extract the inbound address and do some logging
inet_ntop(AF_INET,&network->addr.sin_addr,textaddr,sizeof(textaddr));

g_log->LogMessage(LOG_DEBUG,"CLIENT CONNECT %s:%d from %s:%d\n",netface[argPortal->ifidx],cfg_ServerPort,textaddr,htons(network->addr.sin_port));

// add the new network objet to the double linked list
network->created = time(NULL);
network->proto = IPPROTO_TCP;
network->next = tcpactive;
network->length = 0;
network->next = NULL;
network->last = NULL;
if (tcpactive != NULL) tcpactive->last = network;
tcpactive = network;

// add the new socket to the epoll
memset(&evt,0,sizeof(evt));
evt.data.ptr = network;
evt.events = EPOLLIN;
ret = epoll_ctl(pollsock,EPOLL_CTL_ADD,network->sock,&evt);

	// unexpected error so spew a message and clear the running flag
	if (ret != 0)
	{
	g_log->LogMessage(LOG_ERR,"Error %d returned from epoll_ctl(client)\n",errno);
	running = 0;
	}

// increment the count of active TCP sessions
tcpcount++;

return(1);
}
/*--------------------------------------------------------------------------*/
int ClientNetwork::ProcessTCPQuery(netportal *argPortal)
{
ProxyEntry			*local;
unsigned short		prefix;
void				*buffer;
char				textaddr[32];
char				temp[256];
int					need,size,ret;

	// if we don't have the length yet we need to read that first
	if (argPortal->length == 0)
	{
	buffer = &prefix;
	need = sizeof(prefix);
	}

	// otherwise we know the length so now receive the data
	else
	{
	buffer = netbuffer;
	need = argPortal->length;
	}

// read the data from the socket
size = recv(argPortal->sock,buffer,need,MSG_DONTWAIT);

	// if we don't get exactly what we need for any reason, shut it down
	// this will pick up socket close and blatent protocol violations
	if (size != need)
	{
	RemoveSession(argPortal);
	return(0);
	}

	// if we just grabbed the length save it and return
	if (argPortal->length == 0)
	{
	// convert to host byte order
	argPortal->length = ntohs(prefix);
	return(1);
	}

// reset the length counter for the next iteration
argPortal->length = 0;

// extract the inbound address and do some logging
inet_ntop(AF_INET,&argPortal->addr.sin_addr,textaddr,sizeof(textaddr));

	if (cfg_LogClientBinary != 0)
	{
	sprintf(temp,"CLIENT TCP: %d bytes on %s:%d from %s:%d\n",size,netface[argPortal->ifidx],cfg_ServerPort,textaddr,htons(argPortal->addr.sin_port));
	g_log->LogBinary(LOG_DEBUG,temp,netbuffer,size);
	}

	// minimum size for a DNS query
	if (size < 17)
	{
	g_log->LogMessage(LOG_WARNING,"Incomplete TCP query received on %s from %s:%d\n",netface[argPortal->ifidx],textaddr,htons(argPortal->addr.sin_port));
	RemoveSession(argPortal);
	return(0);
	}

// allocate a new proxy entry object and insert the query
local = new ProxyEntry();
ret = local->InsertQuery(netbuffer,size,argPortal);

	// some error occurred while parsing the query
	if (ret == 0)
	{
	g_log->LogMessage(LOG_WARNING,"Invalid TCP query received on %s from %s:%d\n",netface[argPortal->ifidx],textaddr,htons(argPortal->addr.sin_port));
	delete(local);
	return(0);
	}

g_clientcount++;

// add the query to the proxy table and push to query filter queue
g_table->InsertObject(local);
g_log->LogMessage(LOG_DEBUG,"ClientNetwork created index %hu-%hu\n",local->mygrid,local->myslot);
g_qfilter->PushMessage(new ProxyMessage(local->mygrid,local->myslot));

return(size);
}
/*--------------------------------------------------------------------------*/
int ClientNetwork::ProcessUDPQuery(netportal *argPortal)
{
ProxyEntry			*local;
unsigned int		len;
char				textaddr[32];
char				temp[256];
int					size,ret;

// grab the packet from the socket
memset(&argPortal->addr,0,sizeof(argPortal->addr));
len = sizeof(argPortal->addr);
size = recvfrom(argPortal->sock,netbuffer,sizeof(netbuffer),0,(struct sockaddr *)&argPortal->addr,&len);
if (size == 0) return(0);

	if (size < 0)
	{
	g_log->LogMessage(LOG_WARNING,"Error %d returned from recvfrom(%s)\n",errno,netface[argPortal->ifidx]);
	return(0);
	}

// extract the inbound address and do some logging
inet_ntop(AF_INET,&argPortal->addr.sin_addr,textaddr,sizeof(textaddr));

	if (cfg_LogClientBinary != 0)
	{
	sprintf(temp,"CLIENT UDP: %d bytes on %s:%d from %s:%d\n",size,netface[argPortal->ifidx],cfg_ServerPort,textaddr,htons(argPortal->addr.sin_port));
	g_log->LogBinary(LOG_DEBUG,temp,netbuffer,size);
	}

	// minimum size for a DNS query
	if (size < 17)
	{
	g_log->LogMessage(LOG_WARNING,"Incomplete UDP query received on %s from %s:%d\n",netface[argPortal->ifidx],textaddr,htons(argPortal->addr.sin_port));
	return(0);
	}

// allocate a new proxy entry object and insert the query
local = new ProxyEntry();
ret = local->InsertQuery(netbuffer,size,argPortal);

	// some error occurred while parsing the query
	if (ret == 0)
	{
	g_log->LogMessage(LOG_WARNING,"Invalid UDP query received on %s from %s:%d\n",netface[argPortal->ifidx],netface,htons(argPortal->addr.sin_port));
	delete(local);
	return(0);
	}

g_clientcount++;

// add the query to the proxy table and push to query filter queue
g_table->InsertObject(local);
g_log->LogMessage(LOG_DEBUG,"ClientNetwork created index %hu-%hu\n",local->mygrid,local->myslot);
g_qfilter->PushMessage(new ProxyMessage(local->mygrid,local->myslot));

return(size);
}
/*--------------------------------------------------------------------------*/
int ClientNetwork::ForwardTCPReply(ProxyEntry *argEntry)
{
unsigned short		*qid;
unsigned short		prefix;
int					total;
int					ret;

// copy the packet size into the socket buffer
prefix = htons(argEntry->rawrsize);
memcpy(&netbuffer[0],&prefix,sizeof(prefix));
total = sizeof(prefix);

// copy the raw reply into the socket buffer
memcpy(&netbuffer[total],argEntry->rawreply,argEntry->rawrsize);
total+=argEntry->rawrsize;

// replace the inbound reply id with the original client query id
qid = (unsigned short *)&netbuffer[2];
*qid = htons(argEntry->q_header.qid);

// forward the reply to the original client
ret+=send(argEntry->netsocket,netbuffer,total,MSG_DONTWAIT);

g_log->LogMessage(LOG_DEBUG,"ClientNetwork TCP returned index %hu-%hu\n",argEntry->mygrid,argEntry->myslot);

return(ret);
}
/*--------------------------------------------------------------------------*/
int ClientNetwork::ForwardUDPReply(ProxyEntry *argEntry)
{
unsigned short	*qid;
int				ret;

// replace the inbound reply id with the original client query id
qid = (unsigned short *)&argEntry->rawreply[0];
*qid = htons(argEntry->q_header.qid);

// now forward the reply to the original client
g_log->LogMessage(LOG_DEBUG,"ClientNetwork UDP returned index %hu-%hu\n",argEntry->mygrid,argEntry->myslot);
ret = sendto(argEntry->netsocket,argEntry->rawreply,argEntry->rawrsize,0,(sockaddr *)&argEntry->origin,sizeof(argEntry->origin));

return(ret);
}
/*--------------------------------------------------------------------------*/


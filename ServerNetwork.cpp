// ServerNetwork.cpp
// DNS Proxy Filter Server
// Copyright (c) 2010-2019 Untangle, Inc.
// All Rights Reserved
// Written by Michael A. Hotz

#include "common.h"

/*
	The ServerNetwork class is responsible for handling all network
	communications with the external server to which we forward
	all queries for the actual DNS resolution.  On startup it
	binds one of our IP's to the number of ports specified in the
	configuration file.  This effectively sets the number of 64k
	query tracking tables available to manage outstanding client
	queries.  The public member function ForwardUDPQuery will
	be called from other threads to actually send the requests
	to the server.  The ThreadMaster function uses the epoll
	mechanism to wait for query responses.  When a reply is
	received, the 16 bit id value is extracted and used along
	with the socket index to lookup the corresponding entry in
	the ProxyTable.  This entry holds all information related
	to the outstanding client request.  Once we confirm that
	the reply actually matches up with the question we asked,
	the reply details are added to the ProxyEntry object, and
	the object then passed to the ReplyFilter message queue for
	the next stage of processing.
*/

/*--------------------------------------------------------------------------*/
ServerNetwork::ServerNetwork(void)
{
memset(udpsocket,0,sizeof(udpsocket));
tcpactive = NULL;
pollsock = 0;
tcpcount = 0;
running = 1;
}
/*--------------------------------------------------------------------------*/
ServerNetwork::~ServerNetwork(void)
{
}
/*--------------------------------------------------------------------------*/
void* ServerNetwork::ThreadWorker(void)
{
epoll_event		*trigger;
netportal		*local;
time_t			lasttime,current;
int				iftot,evtot;
int				check;
int				ret;
int				x;

// spin up the server sockets
iftot = SocketStartup();

	// something went haywire during socket startup so clear
	// the running flag and return
	if (iftot == 0)
	{
	running = 0;
	return(NULL);
	}

// allocate a chunk of memory to hold events returned from epoll_wait
evtot = (iftot + (cfg_SessionLimit * 2));
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
		g_log->LogMessage(LOG_ERR,"Error %d returned from epoll_wait(server)\n",errno);
		break;
		}

		// use process and continue here because for a TCP event
		// the netportal object may be deleted while processing
		for(x = 0;x < ret;x++)
		{
		local = (netportal *)trigger[x].data.ptr;
		if (local->proto == IPPROTO_TCP) { ProcessTCPReply(local); continue; }
		if (local->proto == IPPROTO_UDP) { ProcessUDPReply(local); continue; }
		}
	}

// force cleanup any active TCP sessions
SessionCleanup(TRUE);

free(trigger);
SocketDestroy();
running = 0;
return(NULL);
}
/*--------------------------------------------------------------------------*/
int ServerNetwork::SocketStartup(void)
{
struct sockaddr_in		addr;
struct epoll_event		evt;
int						val,ret;
int						x;

	for(x = 0;x < cfg_PushLocalCount;x++)
	{
	g_log->LogMessage(LOG_INFO,"ServerNetwork listening on %s:%d\n",cfg_PushLocalAddr,cfg_PushLocalPort+x);
	udpsocket[x].ifidx = x;
	udpsocket[x].proto = IPPROTO_UDP;
	udpsocket[x].sock = socket(PF_INET,SOCK_DGRAM,0);

		if (udpsocket[x].sock == -1)
		{
		g_log->LogMessage(LOG_ERR,"Error %d returned from socket(server)\n",errno);
		return(0);
		}

	// allow binding even with old sockets in TIME_WAIT status
	val = 1;
	ret = setsockopt(udpsocket[x].sock,SOL_SOCKET,SO_REUSEADDR,(char *)&val,sizeof(val));

		if (ret == -1)
		{
		g_log->LogMessage(LOG_ERR,"Error %d returned from setsockopt(SO_REUSEADDR)\n",errno);
		return(0);
		}

	// set socket to nonblocking mode
	ret = fcntl(udpsocket[x].sock,F_SETFL,O_NONBLOCK);

		if (ret == -1)
		{
		g_log->LogMessage(LOG_ERR,"Error %d returned from fcntl(O_NONBLOCK)\n",errno);
		return(0);
		}

	// bind the socket to our forwarding interface
	memset(&addr,0,sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(cfg_PushLocalPort+x);
	addr.sin_addr.s_addr = inet_addr(cfg_PushLocalAddr);
	ret = bind(udpsocket[x].sock,(struct sockaddr *)&addr,sizeof(addr));

		if (ret == -1)
		{
		g_log->LogMessage(LOG_ERR,"Error %d returned from bind(server)\n",errno);
		return(0);
		}
	}

g_log->LogMessage(LOG_DEBUG,"Setting up server epoll engine\n");

// allocate an epoll thingy large enough to hold all interfaces
pollsock = epoll_create(cfg_PushLocalCount + (cfg_SessionLimit * 2));

	if (pollsock < 0)
	{
	g_log->LogMessage(LOG_ERR,"Error %d returned from epoll_create(server)\n",errno);
	return(0);
	}

	// add each UDP socket to the epoll
	for(x = 0;x < cfg_PushLocalCount;x++)
	{
	memset(&evt,0,sizeof(evt));
	evt.data.ptr = &udpsocket[x];
	evt.events = EPOLLIN;
	epoll_ctl(pollsock,EPOLL_CTL_ADD,udpsocket[x].sock,&evt);
	}

return(1);
}
/*--------------------------------------------------------------------------*/
void ServerNetwork::SocketDestroy(void)
{
int		x;

// close the epoll thingy
g_log->LogMessage(LOG_DEBUG,"Shutting down server epoll engine\n");
close(pollsock);

	for(x = 0;x < cfg_PushLocalCount;x++)
	{
	g_log->LogMessage(LOG_INFO,"Disconnecting ServerNetwork from %s:%d\n",cfg_PushLocalAddr,cfg_PushLocalPort+x);

		if (udpsocket[x].sock > 0)
		{
		shutdown(udpsocket[x].sock,SHUT_RDWR);
		close(udpsocket[x].sock);
		}
	}
}
/*--------------------------------------------------------------------------*/
int ServerNetwork::SessionCleanup(int argForce)
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
		g_log->LogMessage(LOG_DEBUG,"Removing stale server TCP session for %s:%d\n",textaddr,htons(item->addr.sin_port));
		RemoveSession(item);
		total++;
		}

	// adjust our working pointer
	item = next;
	}

return(total);
}
/*--------------------------------------------------------------------------*/
void ServerNetwork::RemoveSession(struct netportal *argPortal)
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
	g_log->LogMessage(LOG_ERR,"Error %d returned from epoll_ctl(server)\n",errno);
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
int ServerNetwork::ForwardTCPQuery(ProxyEntry *argEntry)
{
struct epoll_event	evt;
struct netportal	*network;
unsigned short		prefix;
unsigned short		*qid;
sockaddr_in			source;
int					ret;
int					total;

// create new network object and initiate outbound connection
network = new netportal();
memset(network,0,sizeof(struct netportal));
network->sock = socket(PF_INET,SOCK_STREAM,0);

	if (network->sock == -1)
	{
	g_log->LogMessage(LOG_WARNING,"Error %d returned from socket(server)\n",errno);
	delete(network);
	return(0);
	}

// bind the socket to our forwarding interface
memset(&source,0,sizeof(source));
source.sin_family = AF_INET;
source.sin_port = 0;
source.sin_addr.s_addr = inet_addr(cfg_PushLocalAddr);
ret = bind(network->sock,(struct sockaddr *)&source,sizeof(source));

	if (ret == -1)
	{
	g_log->LogMessage(LOG_ERR,"Error %d returned from bind(server)\n",errno);
	delete(network);
	return(0);
	}

// establish a connection with the external server
memset(&network->addr,0,sizeof(network->addr));
network->addr.sin_family = AF_INET;
network->addr.sin_port = ntohs(cfg_PushServerPort);
network->addr.sin_addr.s_addr = inet_addr(cfg_PushServerAddr);
ret = connect(network->sock,(struct sockaddr *)&network->addr,sizeof(network->addr));

// replace the inbound query id with our index
qid = (unsigned short *)&argEntry->rawquery[0];
*qid = htons(argEntry->myslot);

// now forward the query to the external server
prefix = htons(argEntry->rawqsize);
memcpy(&netbuffer[0],&prefix,sizeof(prefix));
total = sizeof(prefix);
memcpy(&netbuffer[total],argEntry->rawquery,argEntry->rawqsize);
total+=argEntry->rawqsize;

g_log->LogMessage(LOG_DEBUG,"ServerNetwork TCP forwarding index %d-%d\n",argEntry->mygrid,argEntry->myslot);
send(network->sock,netbuffer,total,MSG_DONTWAIT);

// add the new network objet to the double linked list
network->created = time(NULL);
network->proto = IPPROTO_TCP;
network->next = tcpactive;
network->ifidx = argEntry->mygrid;
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
	g_log->LogMessage(LOG_ERR,"Error %d returned from epoll_ctl(server)\n",errno);
	running = 0;
	}

// increment the count of active TCP sessions
tcpcount++;

return(1);
}
/*--------------------------------------------------------------------------*/
int ServerNetwork::ForwardUDPQuery(ProxyEntry *argEntry)
{
sockaddr_in		target;
unsigned short	*qid;
int				ret;

// replace the inbound query id with our index
qid = (unsigned short *)&argEntry->rawquery[0];
*qid = htons(argEntry->myslot);

// now forward the query to the external server
g_log->LogMessage(LOG_DEBUG,"ServerNetwork UDP forwarding index %d-%d\n",argEntry->mygrid,argEntry->myslot);
memset(&target,0,sizeof(target));
target.sin_family = AF_INET;
target.sin_port = ntohs(cfg_PushServerPort);
target.sin_addr.s_addr = inet_addr(cfg_PushServerAddr);
ret = sendto(udpsocket[argEntry->mygrid].sock,argEntry->rawquery,argEntry->rawqsize,0,(sockaddr *)&target,sizeof(target));

return(ret);
}
/*--------------------------------------------------------------------------*/
int ServerNetwork::ProcessTCPReply(netportal *argPortal)
{
ProxyEntry			*local;
unsigned short		prefix;
unsigned short		index;
unsigned short		*qid;
void				*buffer;
char				textaddr[32];
char				temp[256];
int					need,size;

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

g_servercount++;

// extract the inbound address and do some logging
inet_ntop(AF_INET,&argPortal->addr.sin_addr,textaddr,sizeof(textaddr));

	if (cfg_LogServerBinary != 0)
	{
	sprintf(temp,"SERVER TCP: %d bytes on %s from %s:%d\n",size,cfg_PushLocalAddr,textaddr,htons(argPortal->addr.sin_port));
	g_log->LogBinary(LOG_DEBUG,temp,netbuffer,size);
	}

// grab the query id from the packet
qid = (unsigned short *)&netbuffer[0];
index = ntohs(*qid);

g_log->LogMessage(LOG_DEBUG,"ServerNetwork received index %d-%d\n",argPortal->ifidx,index);

// lookup the active query object
local = g_table->RetrieveObject(argPortal->ifidx,index);
if (local == NULL) return(0);

	// make sure the response is valid and matches the original question
	if (size < local->rawqsize)
	{
	g_log->LogMessage(LOG_WARNING,"Truncated query response received for %d-%d\n",argPortal->ifidx,index);
	return(0);
	}

// insert the server response and push to reply filter queue
local->InsertReply(netbuffer,size);
g_rfilter->PushMessage(new ProxyMessage(argPortal->ifidx,index));

RemoveSession(argPortal);
return(1);
}
/*--------------------------------------------------------------------------*/
int ServerNetwork::ProcessUDPReply(netportal *argPortal)
{
ProxyEntry			*local;
struct sockaddr_in	server;
unsigned short		index;
unsigned short		*qid;
unsigned int		len;
char				netface[32];
char				temp[256];
int					size;

// grab the packet from the socket
memset(&server,0,sizeof(server));
len = sizeof(server);
size = recvfrom(udpsocket[argPortal->ifidx].sock,netbuffer,sizeof(netbuffer),0,(struct sockaddr *)&server,&len);
if (size == 0) return(0);

	if (size < 0)
	{
	g_log->LogMessage(LOG_WARNING,"Error %d returned from recvfrom(%s)\n",errno,cfg_PushServerAddr);
	return(0);
	}

g_servercount++;

// extract the inbound address and do some logging
inet_ntop(AF_INET,&server.sin_addr,netface,sizeof(netface));

	if (cfg_LogServerBinary != 0)
	{
	sprintf(temp,"SERVER UDP: %d bytes on %s:%d from %s:%d\n",size,cfg_PushLocalAddr,cfg_PushLocalPort+argPortal->ifidx,netface,htons(server.sin_port));
	g_log->LogBinary(LOG_DEBUG,temp,netbuffer,size);
	}

// grab the query id from the packet
qid = (unsigned short *)&netbuffer[0];
index = ntohs(*qid);

g_log->LogMessage(LOG_DEBUG,"ServerNetwork received index %d-%d\n",argPortal->ifidx,index);

// lookup the active query object
local = g_table->RetrieveObject(argPortal->ifidx,index);
if (local == NULL) return(0);

	// make sure the response is valid and matches the original question
	if (size < local->rawqsize)
	{
	g_log->LogMessage(LOG_WARNING,"Truncated query response received for %d-%d\n",argPortal->ifidx,index);
	return(0);
	}

// insert the server response and push to reply filter queue
local->InsertReply(netbuffer,size);
g_rfilter->PushMessage(new ProxyMessage(argPortal->ifidx,index));

return(1);
}
/*--------------------------------------------------------------------------*/


// dnsproxy.cpp
// DNS Proxy Filter Server
// Copyright (c) 2010-2019 Untangle, Inc.
// All Rights Reserved
// Written by Michael A. Hotz

#define DATALOC
#include "common.h"
/*--------------------------------------------------------------------------*/
int main(int argc,char *argv[])
{
struct timespec		ts;
MessageFrame		*local;
timeval				tv;
fd_set				tester;
int					ret,x;

load_configuration();

	for(x = 1;x < argc;x++)
	{
	if (strncasecmp(argv[x],"-VCB",3) == 0) cfg_LogClientBinary++;
	if (strncasecmp(argv[x],"-VSB",3) == 0) cfg_LogServerBinary++;
	if (strncasecmp(argv[x],"-VDB",3) == 0) cfg_LogDatabase++;
	if (strncasecmp(argv[x],"-D",2) == 0) g_debug++;
	if (strncasecmp(argv[x],"-L",2) == 0) g_console++;
	}

	if (g_console == 0)
	{
	printf(";; DNS Proxy Filter Server Version %s\n",VERSION);
	ret = fork();

		if (ret > 0)
		{
		printf(";; Daemon %d started successfully\n\n",ret);
		return(0);
		}

		if (ret < 0)
		{
		printf(";; Error %d on fork daemon process\n\n",errno);
		delete(g_log);
		return(2);
		}

	// since we are forking we need to disconnect from the console
	freopen("/dev/null","r",stdin);
	freopen("/dev/null","w",stdout);
	freopen("/dev/null","w",stderr);
	}

pthread_key_create(&g_threadkey,NULL);

signal(SIGWINCH,sighandler);
signal(SIGALRM,sighandler);
signal(SIGTERM,sighandler);
signal(SIGQUIT,sighandler);
signal(SIGINT,sighandler);
signal(SIGHUP,sighandler);

signal(SIGSEGV,sighandler);
signal(SIGILL,sighandler);
signal(SIGFPE,sighandler);

// grab the profile itimer value for thread profiling support
getitimer(ITIMER_PROF,&g_itimer);

// allocate a global instance of the logger class
g_log = new Logger(argv[0],"DNSProxy",g_console);
g_log->BeginExecution(STARTWAIT);

g_log->LogMessage(LOG_NOTICE,"STARTUP DNSProxy Version %s Build %s\n",VERSION,BUILDID);

// spinup the MySQL library and allocate our admin database instance
mysql_library_init(0,NULL,NULL);
g_database = new Database();

// build the network lookup table
g_network = g_database->BuildNetworkTable();

// allocate global message queue so thread can talk to us
g_master = new MessageQueue();

// allocate the global proxy table
g_table = new ProxyTable(cfg_PushLocalCount);

// allocate the global query filter
g_qfilter = new QueryFilter(cfg_QueryThreads,cfg_QueryLimit);
g_qfilter->BeginExecution(STARTWAIT);

// allocate the global reply filter
g_rfilter = new ReplyFilter(cfg_ReplyThreads,cfg_ReplyLimit);
g_rfilter->BeginExecution(STARTWAIT);

// allocate the global server network
g_server = new ServerNetwork();
g_server->BeginExecution(STARTWAIT);

// allocate the global client network
g_client = new ClientNetwork();
g_client->BeginExecution(STARTWAIT);

if (g_console != 0) g_log->LogMessage(LOG_NOTICE,"=== Running on console - Use ENTER or CTRL+C to terminate ===\n");

	while (g_goodbye == 0)
	{
	// watch for errors in the client and server threads
	if (g_client->CheckStatus() == 0) break;
	if (g_server->CheckStatus() == 0) break;

		// if running on the console check for keyboard input
		if (g_console != 0)
		{
		FD_ZERO(&tester);
		FD_SET(fileno(stdin),&tester);
		tv.tv_sec = 0;
		tv.tv_usec = 0;
		ret = select(fileno(stdin)+1,&tester,NULL,NULL,&tv);
		if ((ret == 1) && (FD_ISSET(fileno(stdin),&tester) != 0)) break;
		}

	// wait for an object our message queue
	clock_gettime(CLOCK_REALTIME,&ts);
	ts.tv_sec++;
	ret = sem_timedwait(&g_master->MessageSignal,&ts);
	if (ret != 0) continue;

	local = g_master->GrabMessage();
	process_message(local);
	delete(local);
	}

if (g_client != NULL) delete(g_client);
if (g_server != NULL) delete(g_server);
if (g_rfilter != NULL) delete(g_rfilter);
if (g_qfilter != NULL) delete(g_qfilter);
if (g_table != NULL) delete(g_table);
if (g_master != NULL) delete(g_master);
if (g_network != NULL) delete(g_network);
if (g_database != NULL) delete(g_database);

mysql_library_end();

g_log->LogMessage(LOG_INFO,"CLIENT:%lld  QUERY:%lld  SERVER:%lld  REPLY:%lld  DIRTY:%lld\n",
	g_clientcount.val(),g_querycount.val(),g_servercount.val(),g_replycount.val(),g_dirtycount.val());

g_log->LogMessage(LOG_NOTICE,"GOODBYE DNSProxy Version %s Build %s\n",VERSION,BUILDID);

delete(g_log);

pthread_key_delete(g_threadkey);

return(0);
}
/*--------------------------------------------------------------------------*/
void process_message(const MessageFrame *message)
{
	switch(message->cmd)
	{
	case MSG_ADDQUERYTHREAD:
		g_qfilter->InsertThread(TRUE);
		break;

	case MSG_ADDREPLYTHREAD:
		g_rfilter->InsertThread(TRUE);
		break;
	}
}
/*--------------------------------------------------------------------------*/
void sighandler(int sigval)
{
ThreadLogic		*local;

	switch(sigval)
	{
	case SIGWINCH:
		signal(SIGWINCH,sighandler);
		local = (ThreadLogic *)pthread_getspecific(g_threadkey);
		if (local != NULL) local->ScramExecution();
		break;

	case SIGTERM:
	case SIGQUIT:
	case SIGINT:
		signal(sigval,sighandler);
		g_goodbye = 1;
		break;

	case SIGSEGV:
		g_goodbye = 2;
		abort();
		break;

	case SIGILL:
		g_goodbye = 2;
		abort();
		break;

	case SIGFPE:
		g_goodbye = 2;
		abort();
		break;
	}
}
/*--------------------------------------------------------------------------*/
char *newstr(const char *s)
{
char	*local;

local = (char *)malloc(strlen(s) + 1);
strcpy(local,s);
return(local);
}
/*--------------------------------------------------------------------------*/
void freestr(char *s)
{
if (s != NULL) free(s);
}
/*--------------------------------------------------------------------------*/
void load_configuration(void)
{
INIFile		*ini = NULL;
char		work[1024];
char		temp[32];
char		*mask;
int			total;
int			x;

	if (access("./dnsproxy.ini",R_OK) == 0)
	{
	printf("\n== DNSPROXY %s\n","Using ./dnsproxy.ini for configuration ==");
	ini = new INIFile("./dnsproxy.ini");
	}

	else if (access("/etc/dnsproxy.ini",R_OK) == 0)
	{
	printf("\n== DNSPROXY %s\n","Using /etc/dnsproxy.ini for configuration ==");
	ini = new INIFile("/etc/dnsproxy.ini");
	}

	else
	{
	printf("\n== DNSPROXY %s\n","Using default configuration ==");
	ini = new INIFile("/etc/dnsproxy.ini");
	}

ini->GetItem("General","LogFiles",cfg_LogFiles,"/tmp");
ini->GetItem("General","ServerPort",cfg_ServerPort,53);

ini->GetItem("TCP","SessionTimeout",cfg_SessionTimeout,5);
ini->GetItem("TCP","SessionLimit",cfg_SessionLimit,32);
ini->GetItem("TCP","ListenBacklog",cfg_ListenBacklog,8);

ini->GetItem("QueryFilter","StartThreads",cfg_QueryThreads,2);
ini->GetItem("QueryFilter","LimitThreads",cfg_QueryLimit,50);

ini->GetItem("ReplyFilter","StartThreads",cfg_ReplyThreads,2);
ini->GetItem("ReplyFilter","LimitThreads",cfg_ReplyLimit,50);

ini->GetItem("Forward","ServerAddr",cfg_PushServerAddr,"8.8.8.8");
ini->GetItem("Forward","ServerPort",cfg_PushServerPort,53);
ini->GetItem("Forward","LocalAddr",cfg_PushLocalAddr,"0.0.0.0");
ini->GetItem("Forward","LocalPort",cfg_PushLocalPort,5320);
ini->GetItem("Forward","LocalCount",cfg_PushLocalCount,10);

ini->GetItem("Blocking","ServerAddr",cfg_BlockServerAddr,"0.0.0.0");

ini->GetItem("Logging","ClientBinary",cfg_LogClientBinary,0);
ini->GetItem("Logging","ServerBinary",cfg_LogServerBinary,0);
ini->GetItem("Logging","Database",cfg_LogDatabase,0);

ini->GetItem("Database","Hostname",cfg_SQLhostname,NULL);
ini->GetItem("Database","Username",cfg_SQLusername,NULL);
ini->GetItem("Database","Password",cfg_SQLpassword,NULL);
ini->GetItem("Database","Database",cfg_SQLdatabase,NULL);
ini->GetItem("Database","Flags",cfg_SQLflags,0);
ini->GetItem("Database","Port",cfg_SQLport,0);

ini->GetItem("NetFilter","Total",total,0);
cfg_NetFilterCount = 0;

	for(x = 0;x < total;x++)
	{
	sprintf(temp,"%d",x+1);
	ini->GetItem("NetFilter",temp,work,NULL);
	if (strlen(work) == 0) continue;

	mask = strchr(work,'/');
	if (mask != NULL) *mask++=0;
	cfg_NetFilterAddr[cfg_NetFilterCount] = inet_addr(work);
	if (mask != NULL) cfg_NetFilterMask[cfg_NetFilterCount] = inet_addr(mask);
	else cfg_NetFilterMask[cfg_NetFilterCount] = inet_addr("255.255.255.255");

	cfg_NetFilterCount++;
	}

delete(ini);
}
/*--------------------------------------------------------------------------*/


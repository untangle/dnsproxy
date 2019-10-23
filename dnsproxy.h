// dnsproxy.h
// DNS Proxy Filter Server
// Copyright (c) 2010-2019 Untangle, Inc.
// All Rights Reserved
// Written by Michael A. Hotz

#ifndef VERSION
#define VERSION "TEST"
#endif

#ifndef BUILDID
#define BUILDID "0"
#endif

const int SOCKBUFFER = 0x10000;		// sets the size of the socet recv buffer
const int DNSBUFFER = 0x4000;		// sets the size of the dns packet buffer
const int STARTWAIT = 50000;		// microsecond wait time for thread startup
const int SOCKLIMIT = 1024;			// sets maximum number of listen sockets
const int POOLMAX = 1024;			// maximum number of threads in a pool

const int BLACKLIST = 'B';
const int WHITELIST = 'W';
const int FALSE = 0;
const int TRUE = 1;

const int MSG_ADDQUERYTHREAD = 0x11111111;
const int MSG_ADDREPLYTHREAD = 0x22222222;
/*--------------------------------------------------------------------------*/
struct netportal
{
	struct sockaddr_in		addr;
	int						ifidx;
	int						proto;
	int						sock;
	int						length;
	struct netportal		*next,*last;
	time_t					created;
};
/*--------------------------------------------------------------------------*/
struct category_info
{
	int				id;
	char			*name;
	char			*description;
};
/*--------------------------------------------------------------------------*/
union dnsflags
{
	unsigned short			value;

	struct
	{
	unsigned short	status		: 4;
	unsigned short	reserved	: 3;
	unsigned short	haverec		: 1;
	unsigned short	wantrec		: 1;
	unsigned short	truncate	: 1;
	unsigned short	authority	: 1;
	unsigned short	opcode		: 4;
	unsigned short	response	: 1;
	} pf;
};
/*--------------------------------------------------------------------------*/
struct header
{
	unsigned short			qid;
	union dnsflags			flags;
	unsigned short			qdcount;
	unsigned short			ancount;
	unsigned short			nscount;
	unsigned short			arcount;
};
/*--------------------------------------------------------------------------*/
struct qrec
{
	char					qname[260];
	unsigned short			qtype;
	unsigned short			qclass;
};
/*--------------------------------------------------------------------------*/
class arec
{
};
/*--------------------------------------------------------------------------*/
class CountDevice;
class SyncDevice;
class AtomicValue;
class ClientNetwork;
class MessageFrame;
class ThreadLogic;
class ServerNetwork;
class ProxyTable;
class ProxyEntry;
class ProxyMessage;
class MessageQueue;
class ThreadPool;
class ThreadItem;
class QueryFilter;
class ReplyFilter;
class LoggerInfo;
class Logger;
class Database;
class FilterManager;
class DNSPacket;
class HashTable;
class HashObject;
class NetworkEntry;
/*--------------------------------------------------------------------------*/
class CountDevice
{
public:

	inline CountDevice(void)		{ sem_init(&control,0,0); }
	inline ~CountDevice(void)		{ sem_destroy(&control); }

	inline int operator++(int)		{ return(sem_post(&control)); }
	inline int operator--(int)		{ return(sem_wait(&control)); }

	inline operator int()
	{
	int value;
	sem_getvalue(&control,&value);
	return(value);
	}

private:

	sem_t					control;
};
/*--------------------------------------------------------------------------*/
class SyncDevice
{
public:

	inline SyncDevice(void)			{ pthread_mutex_init(&control,NULL); }
	inline ~SyncDevice(void)		{ pthread_mutex_destroy(&control); }

	inline void Acquire(void)		{ pthread_mutex_lock(&control); }
	inline void Release(void)		{ pthread_mutex_unlock(&control); }

private:

	pthread_mutex_t			control;
};
/*--------------------------------------------------------------------------*/
class AtomicValue
{
public:

	inline AtomicValue(unsigned long long aValue = 0)	{ value = aValue; }
	inline ~AtomicValue(void)			{ }

	inline unsigned long long val(void)
	{
	control.Acquire();
	unsigned long long temp = value;
	control.Release();
	return(temp);
	}

	inline unsigned long long operator=(const unsigned long long aValue)
	{
	control.Acquire();
	value = aValue;
	control.Release();
	return(aValue);
	}

	inline unsigned long long operator++(int)
	{
	control.Acquire();
	unsigned long long temp = ++value;
	control.Release();
	return(temp);
	}

	inline unsigned long long operator++()
	{
	control.Acquire();
	unsigned long long temp = value++;
	control.Release();
	return(temp);
	}

	inline unsigned long long operator--(int)
	{
	control.Acquire();
	unsigned long long temp = --value;
	control.Release();
	return(temp);
	}

	inline unsigned long long operator--()
	{
	control.Acquire();
	unsigned long long temp = value--;
	control.Release();
	return(temp);
	}

	inline operator unsigned long long()
	{
	control.Acquire();
	unsigned long long temp = value;
	control.Release();
	return(temp);
	}

private:

	unsigned long long		value;
	SyncDevice				control;
};
/*--------------------------------------------------------------------------*/
class ThreadLogic
{
public:

	ThreadLogic(void);
	virtual ~ThreadLogic(void);

	void BeginExecution(int argWait = 0);
	void ScramExecution(void);

private:

	static void* ThreadMaster(void *aObject);
	virtual void* ThreadWorker(void) = 0;

protected:

	pthread_t				ThreadHandle;
	sem_t					ThreadSignal;
	int						ThreadNumber;
};
/*--------------------------------------------------------------------------*/
class MessageFrame
{
friend class MessageQueue;

public:

	MessageFrame(int argCmd = 0)	{ next = NULL; cmd = argCmd; }
	virtual ~MessageFrame(void)		{ }

	int						cmd;

private:

	MessageFrame			*next;
};
/*--------------------------------------------------------------------------*/
class ClientNetwork : public ThreadLogic
{
public:

	ClientNetwork(void);
	~ClientNetwork(void);
	int CheckStatus(void) { return(running); }

	int ForwardTCPReply(ProxyEntry *argEntry);
	int ForwardUDPReply(ProxyEntry *argEntry);

private:

	void* ThreadWorker(void);

	void RemoveSession(struct netportal *argPortal);
	void EnumerateInterfaces(void);
	void SocketDestroy(void);

	int ProcessTCPConnect(netportal *argPortal);
	int ProcessTCPQuery(netportal *argPortal);
	int ProcessUDPQuery(netportal *argPortal);
	int SessionCleanup(int argForce = 0);
	int SocketStartup(void);

	unsigned int			IPv4list[SOCKLIMIT];
	int						IPv4tot;

	char					netbuffer[SOCKBUFFER];

	char					netface[SOCKLIMIT][32];
	netportal				tcplisten[SOCKLIMIT];
	netportal				udplisten[SOCKLIMIT];
	netportal				*tcpactive;

	int						tcpcount;
	int						pollsock;
	int						running;
};
/*--------------------------------------------------------------------------*/
class ServerNetwork : public ThreadLogic
{
public:

	ServerNetwork(void);
	~ServerNetwork(void);
	int CheckStatus(void) { return(running); }

	int ForwardTCPQuery(ProxyEntry *argEntry);
	int ForwardUDPQuery(ProxyEntry *argEntry);

private:

	void* ThreadWorker(void);

	void RemoveSession(struct netportal *argPortal);
	void SocketDestroy(void);

	int ProcessUDPReply(netportal *argPortal);
	int ProcessTCPReply(netportal *argPortal);
	int SessionCleanup(int argForce = 0);
	int SocketStartup(void);

	char					netbuffer[SOCKBUFFER];

	netportal				udpsocket[SOCKLIMIT];
	netportal				*tcpactive;
	int						tcpcount;
	int						pollsock;
	int						running;
};
/*--------------------------------------------------------------------------*/
class ProxyTable
{
public:

	ProxyTable(int argSize);
	~ProxyTable(void);

	int InsertObject(ProxyEntry *argEntry);
	int RemoveObject(unsigned short argGrid,unsigned short argSlot);
	ProxyEntry *RetrieveObject(unsigned short argGrid,unsigned short argSlot);

private:

	ProxyEntry				***worktable;
	unsigned short			tablesize;
	unsigned short			slotindex;
	unsigned short			gridindex;
};
/*--------------------------------------------------------------------------*/
class ProxyEntry
{
public:

	ProxyEntry(void);
	~ProxyEntry(void);

	int InsertQuery(const char *argBuffer,int argSize,netportal *argPortal);
	int InsertReply(const char *argBuffer,int argSize);
	int InsertReply(DNSPacket *argPacket);

	struct sockaddr_in		origin;
	unsigned short			mygrid;
	unsigned short			myslot;

	int						netprotocol;
	int						netsocket;

	char					*rawquery;
	int						rawqsize;

	char					*rawreply;
	int						rawrsize;

	header					q_header;
	qrec					q_record;
};
/*--------------------------------------------------------------------------*/
class ProxyMessage : public MessageFrame
{
friend class MessageQueue;

public:

	ProxyMessage(unsigned short argGrid,unsigned short argSlot)		{ qgrid = argGrid; qslot = argSlot; }
	virtual ~ProxyMessage(void)										{ }

	unsigned short			qgrid;
	unsigned short			qslot;
};
/*--------------------------------------------------------------------------*/
class MessageQueue
{
public:

	MessageQueue(void);
	virtual ~MessageQueue(void);

	void PushMessage(MessageFrame *argObject);
	MessageFrame *GrabMessage(void);

	sem_t					MessageSignal;

private:

	SyncDevice				*ListLock;
	MessageFrame			*ListHead;
	MessageFrame			*ListTail;
};
/*--------------------------------------------------------------------------*/
class ThreadPool : public MessageQueue
{
public:

	ThreadPool(int aCount,int aLimit,const char *argName);
	virtual ~ThreadPool(void);

	void BeginExecution(int argWait = 0);
	void InsertThread(int argStart = 0);
	void RemoveThread(void);

	void EnterCallback(void);
	void LeaveCallback(void);

	virtual void ThreadCallback(MessageFrame *argMessage) = 0;
	virtual void ThreadSaturation(int argTotal) { }

	char					*PoolName;
	int						ThreadLimit;

private:

	AtomicValue				ThreadCounter;
	CountDevice				BusyCounter;
	ThreadItem				*ThreadList;
	int						ThreadTotal;
};
/*--------------------------------------------------------------------------*/
class ThreadItem : public ThreadLogic
{
friend class ThreadPool;

public:

	ThreadItem(ThreadPool *argParent,int argIndex);
	~ThreadItem(void);

private:

	void* ThreadWorker(void);

	ThreadPool				*Parent;
	ThreadItem				*last;
	ThreadItem				*next;
	int						ThreadNumber;
};
/*--------------------------------------------------------------------------*/
class QueryFilter : public ThreadPool
{
public:

	QueryFilter(int aCount,int aLimit);
	~QueryFilter(void);

private:

	void ThreadCallback(MessageFrame *argMessage);
	void ThreadSaturation(int argTotal);
	void TransmitBlockTarget(ProxyEntry *argEntry);

	Database				*database;
};
/*--------------------------------------------------------------------------*/
class ReplyFilter : public ThreadPool
{
public:

	ReplyFilter(int aCount,int aLimit);
	~ReplyFilter(void);

private:

	void ThreadCallback(MessageFrame *argMessage);
	void ThreadSaturation(int argTotal);
};
/*--------------------------------------------------------------------------*/
class LoggerInfo : public MessageFrame
{
friend class ThreadPool;
friend class Logger;

public:

	LoggerInfo(int aLevel,int aSize = 1024);
	~LoggerInfo(void);

	void Resize(int aSize);

private:

	int						level;
	int						bsize;
	const char				*prefix;
	char					*detail;
};
/*--------------------------------------------------------------------------*/
class Logger : public MessageQueue, public ThreadLogic
{
public:

	Logger(const char *aProgram,const char *aTitle,int aConsole);
	~Logger(void);

	void LogMessage(int level,const char *format,...);
	void LogBuffer(int level,int size,const char *prefix,const char *buffer);
	void LogBinary(int level,const char *info,const void *data,int length);

private:

	void* ThreadWorker(void);

	void WriteMessage(LoggerInfo *aMess);
	char *VALUEtoLEVEL(int value,char *dest);

	timeval					runtime;
	char					*ourprogram;
	char					*ourtitle;
	int						terminate;
	int						console;
};
/*--------------------------------------------------------------------------*/
class FilterManager : public MessageQueue, public ThreadLogic
{
public:

	FilterManager(void);
	~FilterManager(void);

private:

	void* ThreadWorker(void);
};
/*--------------------------------------------------------------------------*/
class Database
{
public:

	Database(void);
	~Database(void);

	HashTable *BuildNetworkTable(void);

	unsigned long ResultToValue(void);

	int CheckPolicyList(int list,NetworkEntry *network,const char *qname);

private:

	void HandleError(const char *function,const char *file,int line);

	MYSQL					context;
	char					querybuff[10240];
	int						error_flag;
};
/*--------------------------------------------------------------------------*/
class DNSPacket
{
friend class ProxyEntry;

public:

	DNSPacket(void);
	~DNSPacket(void);

	void Insert_Master(unsigned short aId,unsigned short aFlags,short qd,short an,short ns,short ar);
	void Update_Master(unsigned short aId,unsigned short aFlags,short qd,short an,short ns,short ar);
	void Insert_Question(const char *aName,int aType,int aClass);
	void Begin_Record(const char *aName,short aType,short aClass,long aLife);
	void Close_Record(void);

	void Insert_DNAME(const char *aData);
	void Insert_IPV4(const char *aData);
	void Insert_IPV6(const char *aData);
	void Insert_INT8(const char *aData);
	void Insert_INT8(char aValue);
	void Insert_INT16(const char *aData);
	void Insert_INT16(short aValue);
	void Insert_INT32(const char *aData);
	void Insert_INT32(long aValue);
	void Insert_STRING(const char *aData);
	void Insert_BINARY(const void *aData,int aSize);

	int Extract_DNAME(char *target,unsigned tlen);
	int Extract_IPV4(char *target,unsigned tlen);
	int Extract_INT8(char *target,unsigned tlen);
	int Extract_INT16(char *target,unsigned tlen);
	int Extract_INT32(char *target,unsigned tlen);
	int Extract_STRING(char *target,unsigned tlen);

	int Search_DNAME(const char *jungle,const char *needle);

private:

	unsigned short		*marker;
	unsigned short		offset;
	char				*buffer;
	int					length;
	int					prefix;

// TODO - do we really need all this stuff

	unsigned short		id;
	unsigned short		flags;
	unsigned short		qdcount;
	unsigned short		ancount;
	unsigned short		nscount;
	unsigned short		arcount;

	unsigned short		*idval;
	unsigned short		*flval;
	unsigned short		*qdval;
	unsigned short		*anval;
	unsigned short		*nsval;
	unsigned short		*arval;

	int					complist[1024];
	int					comptot;
};
/*--------------------------------------------------------------------------*/
class HashTable
{
public:

	HashTable(int argBuckets);
	~HashTable(void);

	int InsertObject(HashObject *argObject);
	HashObject* SearchObject(const char *argString);
	void GetTableSize(int &aCount,int &aBytes);

private:

	unsigned int HashKey(const char *argString);

	pthread_mutex_t		*control;
	HashObject			**table;
	int					buckets;
};
/*--------------------------------------------------------------------------*/
class HashObject
{
friend class HashTable;

public:

	HashObject(const char *argTitle);
	virtual ~HashObject(void);
	virtual int GetObjectSize(void);

private:

	HashObject			*next;
	char				*ObjectName;
};
/*--------------------------------------------------------------------------*/
class NetworkEntry : public HashObject
{
public:

	NetworkEntry(unsigned long aObject,unsigned long aOwner,const char* aNetwork);
	virtual ~NetworkEntry(void);

	unsigned long		Object;
	unsigned long		Owner;

private:

	int GetObjectSize(void);
};
/*--------------------------------------------------------------------------*/
void process_message(const MessageFrame *message);
void load_configuration(void);
void sighandler(int sigval);
char *strclean(char *s);
char *newstr(const char *s);
void freestr(char *s);
/*--------------------------------------------------------------------------*/
#ifndef DATALOC
#define DATALOC extern
#endif
/*--------------------------------------------------------------------------*/
DATALOC struct itimerval	g_itimer;
DATALOC pthread_key_t		g_threadkey;
DATALOC category_info		*g_catinfo;
DATALOC FilterManager		*g_manager;
DATALOC MessageQueue		*g_master;
DATALOC ClientNetwork		*g_client;
DATALOC ServerNetwork		*g_server;
DATALOC QueryFilter			*g_qfilter;
DATALOC ReplyFilter			*g_rfilter;
DATALOC ProxyTable			*g_table;
DATALOC HashTable			*g_network;
DATALOC Database			*g_database;
DATALOC Logger				*g_log;
DATALOC void				*g_catbuff;
DATALOC size_t				g_catcount;
DATALOC int					g_console;
DATALOC int					g_goodbye;
DATALOC int					g_debug;
DATALOC AtomicValue			g_clientcount;
DATALOC AtomicValue			g_servercount;
DATALOC AtomicValue			g_querycount;
DATALOC AtomicValue			g_replycount;
DATALOC AtomicValue			g_dirtycount;
/*--------------------------------------------------------------------------*/
DATALOC unsigned int		cfg_NetFilterAddr[256];
DATALOC unsigned int		cfg_NetFilterMask[256];
DATALOC char				cfg_LogFiles[1024];
DATALOC int					cfg_LogClientBinary;
DATALOC int					cfg_LogServerBinary;
DATALOC int					cfg_LogDatabase;
DATALOC int					cfg_NetFilterCount;
DATALOC int					cfg_ListenBacklog;
DATALOC int					cfg_SessionTimeout;
DATALOC int					cfg_SessionLimit;
DATALOC int					cfg_ServerPort;
DATALOC char				cfg_BlockServerAddr[32];
DATALOC char				cfg_PushServerAddr[32];
DATALOC char				cfg_PushLocalAddr[32];
DATALOC int					cfg_PushServerPort;
DATALOC int					cfg_PushLocalPort;
DATALOC int					cfg_PushLocalCount;
DATALOC int					cfg_QueryThreads,cfg_QueryLimit;
DATALOC int					cfg_ReplyThreads,cfg_ReplyLimit;

DATALOC char				cfg_SQLhostname[256];
DATALOC char				cfg_SQLusername[256];
DATALOC char				cfg_SQLpassword[256];
DATALOC char				cfg_SQLdatabase[256];
DATALOC int					cfg_SQLflags;
DATALOC int					cfg_SQLport;
/*--------------------------------------------------------------------------*/


// Logger.cpp
// DNS Proxy Filter Server
// Copyright (c) 2010-2019 Untangle, Inc.
// All Rights Reserved
// Written by Michael A. Hotz

#include "common.h"

/*
	This is a generic class for message logging.  When the console
	argument is zero, this class will write all log messages using
	the syslog facility.  When console is not zero, this class will
	write all log messages to the console.  It derives from both the
	ThreadFrame and MessageQueue classes.  The public LogMessage
	function get called from all over the place, and creates a
	LoggerInfo object with the contents which is pushed into the
	message queue. The worker thread pulls messages from the queue
	and writes them to the proper destination, while also monitoring
	the ThreadKiller so it knows when to terminate.
*/

/*--------------------------------------------------------------------------*/
Logger::Logger(const char *aProgram,const char *aTitle,int aConsole)
{
// get the current time
gettimeofday(&runtime,NULL);

ourprogram = newstr(aProgram);
ourtitle = newstr(aTitle);
console = aConsole;

// if not on the console open system log
if (console == 0) openlog(aTitle,LOG_NDELAY | LOG_PID,LOG_LOCAL0);
}
/*--------------------------------------------------------------------------*/
Logger::~Logger(void)
{
// if not on console close systemlog
if (console == 0) closelog();
freestr(ourprogram);
freestr(ourtitle);
}
/*--------------------------------------------------------------------------*/
void* Logger::ThreadWorker(void)
{
struct timespec		ts;
LoggerInfo			*local;
int					check;
int					ret;

LogMessage(LOG_DEBUG,"Logger thread %s is starting\n",ourtitle);

	for(;;)
	{
	// watch the thread signal for termination
	check = 0;
	ret = sem_getvalue(&ThreadSignal,&check);
	if (ret != 0) break;
	if (check != 0) break;

		for(;;)
		{
		// wait for an object in the work queue
		clock_gettime(CLOCK_REALTIME,&ts);
		ts.tv_sec++;
		ret = sem_timedwait(&MessageSignal,&ts);
		if (ret != 0) break;

		// grab, process, and delete the message
		local = (LoggerInfo *)GrabMessage();
		WriteMessage(local);
		delete(local);
		}
	}

return(NULL);
}
/*--------------------------------------------------------------------------*/
void Logger::LogMessage(int level,const char *format,...)
{
LoggerInfo		*mess;
va_list			args;
int				ret;

if ((level == LOG_DEBUG) && (g_debug == 0)) return;

// allocate a new logger message object
mess = new LoggerInfo(level);

// write the formatted output to the buffer
va_start(args,format);
ret = vsnprintf(mess->detail,mess->bsize,format,args);
va_end(args);

	// if buffer was too small reallocate and try again
	if (ret >= mess->bsize)
	{
	mess->Resize(ret + 1);
	va_start(args,format);
	ret = vsnprintf(mess->detail,mess->bsize,format,args);
	va_end(args);
	}

// push the message on our message queue
PushMessage(mess);
}
/*--------------------------------------------------------------------------*/
void Logger::LogBuffer(int level,int size,const char *prefix,const char *buffer)
{
LoggerInfo		*mess;

if ((level == LOG_DEBUG) && (g_debug == 0)) return;

// allocate a new logger message object
mess = new LoggerInfo(level,size + 1);

// copy the raw message to the buffer and add null terminator
memcpy(mess->detail,buffer,size);
mess->detail[size] = 0;
mess->prefix = prefix;

// push the message on our message queue
PushMessage(mess);
}
/*--------------------------------------------------------------------------*/
void Logger::LogBinary(int level,const char *info,const void *buffer,int length)
{
const unsigned char		*data;
LoggerInfo				*mess;
char					*spot;
int						size,x;

if ((level == LOG_DEBUG) && (g_debug == 0)) return;

// allocate a new logger message object
size = ((length * 3) + 2);
if (info != NULL) size+=strlen(info);
mess = new LoggerInfo(level,size);

// create a text string of XX values
data = (const unsigned char *)buffer;
spot = mess->detail;
if (info != NULL) spot+=sprintf(spot,"%s",info);
for(x = 0;x < length;x++) spot+=sprintf(spot,"%02hhX ",data[x]);
spot+=sprintf(spot,"%s","\n");

// push the message on our message queue
PushMessage(mess);
}
/*--------------------------------------------------------------------------*/
void Logger::WriteMessage(LoggerInfo *aMess)
{
struct timeval		nowtime;
double				rr,nn,ee;
char				string[32];

	if (console == 0)
	{
	if (aMess->prefix != NULL) syslog(aMess->level,"%s%s",aMess->prefix,aMess->detail);
	else syslog(aMess->level,"%s",aMess->detail);
	return;
	}

gettimeofday(&nowtime,NULL);

rr = ((double)runtime.tv_sec * (double)1000000.00);
rr+=(double)runtime.tv_usec;

nn = ((double)nowtime.tv_sec * (double)1000000.00);
nn+=(double)nowtime.tv_usec;

ee = ((nn - rr) / (double)1000000.00);

VALUEtoLEVEL(aMess->level,string);
if (aMess->prefix != NULL) fprintf(stdout,"[%.6f] %s %s",ee,string,aMess->prefix);
else fprintf(stdout,"[%.6f] %s ",ee,string);
fputs(aMess->detail,stdout);

fflush(stdout);
}
/*--------------------------------------------------------------------------*/
char *Logger::VALUEtoLEVEL(int value,char *dest)
{
if (value == LOG_EMERG)		return(strcpy(dest,"EMERGENCY"));
if (value == LOG_ALERT)		return(strcpy(dest,"ALERT"));
if (value == LOG_CRIT)		return(strcpy(dest,"CRITICAL"));
if (value == LOG_ERR)		return(strcpy(dest,"ERROR"));
if (value == LOG_WARNING)	return(strcpy(dest,"WARNING"));
if (value == LOG_NOTICE)	return(strcpy(dest,"NOTICE"));
if (value == LOG_INFO)		return(strcpy(dest,"INFO"));
if (value == LOG_DEBUG)		return(strcpy(dest,"DEBUG"));
sprintf(dest,"LOG_%d",value);
return(dest);
}
/*--------------------------------------------------------------------------*/
/****************************************************************************/
/*--------------------------------------------------------------------------*/
LoggerInfo::LoggerInfo(int aLevel,int aSize) : level(aLevel)
{
detail = (char *)malloc(aSize);
bsize = aSize;
prefix = NULL;
}
/*--------------------------------------------------------------------------*/
LoggerInfo::~LoggerInfo(void)
{
free(detail);
}
/*--------------------------------------------------------------------------*/
void LoggerInfo::Resize(int aSize)
{
detail = (char *)realloc(detail,aSize);
bsize = aSize;
}
/*--------------------------------------------------------------------------*/


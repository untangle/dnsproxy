// Thread.cpp
// DNS Proxy Filter Server
// Copyright (c) 2010-2019 Untangle, Inc.
// All Rights Reserved
// Written by Michael A. Hotz

#include "common.h"

/*
	ThreadLogic is the base class for all objects that need to spawn
	a seperate threads of execution.  Includes logic to start the
	thread in suspended mode and terminate the thread when the
	destructor is called.  The ThreadSignal semaphore is initially
	clear, causing the static ThreadMaster function to wait until
	the BeginExecution function is called, after which it will call
	the member ThreadWorker function.  ScramExecution sets the same
	semaphore again, which tells the running thread to terminate.
	Derived classes should override the ThreadWorker function and
	must watch the ThreadSignal semaphore which will be set when
	the destructor is called.

	ThreadPool is the base class for all objects that need to execute
	within a dynamic thread pool.  It spawns the requested number
	of theads as instances of ThreadItem, which is derived from
	and expands upon ThreadLogic to support the pool logic.  The
	threads all monitor a shared message queue, and will call the
	ThreadCallback which derived classes should override to process
	the messages from the queue.
*/
/*--------------------------------------------------------------------------*/
ThreadLogic::ThreadLogic(void)
{
// initialize the thread control semaphore
sem_init(&ThreadSignal,0,0);

// spin up a new thread
pthread_create(&ThreadHandle,NULL,ThreadMaster,this);
}
/*--------------------------------------------------------------------------*/
ThreadLogic::~ThreadLogic(void)
{
// set the thread signal semaphore
sem_post(&ThreadSignal);

// signal the thread function to terminate
pthread_kill(ThreadHandle,SIGWINCH);

// wait for the thread to terminate
pthread_join(ThreadHandle,NULL);

// destroy the thread killer semaphore
sem_destroy(&ThreadSignal);
}
/*--------------------------------------------------------------------------*/
void ThreadLogic::BeginExecution(int argWait)
{
int		value,ret;

// signal the thread function to begin execution
sem_post(&ThreadSignal);
if (argWait == 0) return;

	// Normally argWait will be zero but I added this stupidity for
	// the sole purpose of allowing the main thread console notice
	// message to appear after all the other threads have finished
	// spewing their starup messages.  Without it the console notice
	// was appearing first!  Go figure.
	for(;;)
	{
	ret = sem_getvalue(&ThreadSignal,&value);
	if (ret != 0) break;
	if (value == 0) break;
	usleep(argWait);
	}
}
/*--------------------------------------------------------------------------*/
void ThreadLogic::ScramExecution(void)
{
// signal the thread function to begin execution
sem_post(&ThreadSignal);
}
/*--------------------------------------------------------------------------*/
void* ThreadLogic::ThreadMaster(void *aObject)
{
ThreadLogic		*mypointer = (ThreadLogic *)aObject;
sigset_t		sigset;

// first we store our object pointer in thread local storage
pthread_setspecific(g_threadkey,aObject);

// start by blocking all signals
sigfillset(&sigset);
pthread_sigmask(SIG_BLOCK,&sigset,NULL);

// now we allow only the signals we care about
sigemptyset(&sigset);
sigaddset(&sigset,SIGWINCH);
sigaddset(&sigset,SIGPROF);
pthread_sigmask(SIG_UNBLOCK,&sigset,NULL);

// set the itimer value of the main thread which is required
// for gprof to work properly with multithreaded applications
setitimer(ITIMER_PROF,&g_itimer,NULL);

// wait for the control semaphore
sem_wait(&mypointer->ThreadSignal);

// call to our member worker function
return(mypointer->ThreadWorker());
}
/*--------------------------------------------------------------------------*/
/****************************************************************************/
/*--------------------------------------------------------------------------*/
ThreadPool::ThreadPool(int aCount,int aLimit,const char *argName)
{
int		x;

// save our pool name and clear member variables
PoolName = newstr(argName);
ThreadList = NULL;
ThreadTotal = 0;
ThreadLimit = aLimit;

// spawn the requested number of threads
for(x = 0;x < aCount;x++) InsertThread();
}
/*--------------------------------------------------------------------------*/
ThreadPool::~ThreadPool(void)
{
ThreadItem		*local;

// signal all the threads to speed up shutdown
for(local = ThreadList;local != NULL;local = local->next) sem_post(&local->ThreadSignal);

// now remove all the threads
while (ThreadList != NULL) RemoveThread();

// clean up our pool name string
freestr(PoolName);
}
/*--------------------------------------------------------------------------*/
void ThreadPool::BeginExecution(int argWait)
{
ThreadItem		*local;

// signal all the threads to start execution
for(local = ThreadList;local != NULL;local = local->next) local->BeginExecution(argWait);
}
/*--------------------------------------------------------------------------*/
void ThreadPool::InsertThread(int argStart)
{
ThreadItem		*local;

// don't exceed our limit
if (ThreadTotal == ThreadLimit) return;

// allocate a new thread item
local = new ThreadItem(this,ThreadCounter++);

// insert into the double linked list
local->next = ThreadList;
if (ThreadList != NULL) ThreadList->last = local;
ThreadList = local;

// increment the thread count
ThreadTotal++;

// normally the start flag will not be set as the pool BeginExecution
// member takes care of spinning everything up.  However when new threads
// are added later the flag will be set to signal startup is required
if (argStart != 0) local->BeginExecution();
}
/*--------------------------------------------------------------------------*/
void ThreadPool::RemoveThread(void)
{
ThreadItem		*local;

if (ThreadList == NULL) return;

// remove the first item from the linked list
local = ThreadList;
ThreadList = ThreadList->next;
if (local->next != NULL) local->next->last = NULL;

// delete the thread item
delete(local);

// decrement the thread count
ThreadTotal--;
}
/*--------------------------------------------------------------------------*/
void ThreadPool::EnterCallback(void)
{
// increment threads in use counter
BusyCounter++;

// if all the threads are now busy call the virtual notification
if (BusyCounter == ThreadTotal) ThreadSaturation(ThreadTotal);
}
/*--------------------------------------------------------------------------*/
void ThreadPool::LeaveCallback(void)
{
// decrement threads in use counter
BusyCounter--;
}
/*--------------------------------------------------------------------------*/
/****************************************************************************/
/*--------------------------------------------------------------------------*/
ThreadItem::ThreadItem(ThreadPool *argParent,int argIndex)
{
// save our parent
Parent = argParent;
next = last = NULL;
ThreadNumber = argIndex;
}
/*--------------------------------------------------------------------------*/
ThreadItem::~ThreadItem(void)
{
}
/*--------------------------------------------------------------------------*/
void* ThreadItem::ThreadWorker(void)
{
struct timespec		ts;
MessageFrame		*local;
int					check;
int					ret;

g_log->LogMessage(LOG_INFO,"Thread pool %s starting thread %d\n",Parent->PoolName,ThreadNumber);

	for(;;)
	{
	// watch the thread signal for termination
	check = 0;
	ret = sem_getvalue(&ThreadSignal,&check);
	if (ret != 0) break;
	if (check != 0) break;

	// wait for an object in the work queue
	clock_gettime(CLOCK_REALTIME,&ts);
	ts.tv_sec++;
	ret = sem_timedwait(&Parent->MessageSignal,&ts);
	if (ret != 0) continue;

	// grab, process, and delete the message
	local = Parent->GrabMessage();
	if (local == NULL) continue;
	Parent->EnterCallback();
	Parent->ThreadCallback(local);
	Parent->LeaveCallback();
	delete(local);
	}

g_log->LogMessage(LOG_INFO,"Thread pool %s stopping thread %d\n",Parent->PoolName,ThreadNumber);

return(NULL);
}
/*--------------------------------------------------------------------------*/


// MessageQueue.cpp
// DNS Proxy Filter Server
// Copyright (c) 2010-2019 Untangle, Inc.
// All Rights Reserved
// Written by Michael A. Hotz

#include "common.h"

/*
	Base class for all objects that need a message queue.  Includes
	thread safe logic for pushing messages onto the queue and grabbing
	messages off the queue in FIFO order.  The logic assumes that the
	GrabMessage member will not be called until the MessageSignal object
	indicates that one or more messages are available.  Application
	specific messages objects should be created by deriving from the
	MessageFrame base.  The destructor will automatically clean up
	any messages that are left in the queue.
*/

/*--------------------------------------------------------------------------*/
MessageQueue::MessageQueue(void)
{
// initialize our head and tail pointers
ListHead = ListTail = NULL;

// create a new access control device
ListLock = new SyncDevice();

// create the signal semaphore
sem_init(&MessageSignal,0,0);
}
/*--------------------------------------------------------------------------*/
MessageQueue::~MessageQueue(void)
{
// clean up the signal semaphore
sem_destroy(&MessageSignal);

// delete the access control device
delete(ListLock);

	// cleanup any messages left in the queue
	while (ListHead != NULL)
	{
	ListTail = ListHead->next;
	delete(ListHead);
	ListHead = ListTail;
	}
}
/*--------------------------------------------------------------------------*/
void MessageQueue::PushMessage(MessageFrame *argMessage)
{

// acquire the access control lock
ListLock->Acquire();

// if queue is empty assign message to tail pointer
if (ListTail == NULL) ListTail = argMessage;

	// otherwise append to the current tail object
	else
	{
	ListTail->next = argMessage;
	ListTail = argMessage;
	}

// if head is null copy the tail
if (ListHead == NULL) ListHead = ListTail;

// increment the message signal semaphore
sem_post(&MessageSignal);

// release the access control lock
ListLock->Release();
}
/*--------------------------------------------------------------------------*/
MessageFrame* MessageQueue::GrabMessage(void)
{
MessageFrame		*local;

// acquire the access control lock
ListLock->Acquire();

	// list is empty
	if (ListHead == NULL)
	{
	local = NULL;
	}

	// list has single item
	else if (ListHead == ListTail)
	{
	local = ListHead;
	ListHead = ListTail = NULL;
	}

	// grab the first item in the list
	else
	{
	local = ListHead;
	ListHead = local->next;
	}

// release the access control device
ListLock->Release();

// return the message
return(local);
}
/*--------------------------------------------------------------------------*/


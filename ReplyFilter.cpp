// ReplyFilter.cpp
// DNS Proxy Filter Server
// Copyright (c) 2010-2019 Untangle, Inc.
// All Rights Reserved
// Written by Michael A. Hotz

#include "common.h"

/*
	The ReplyFilter class is responsible for performing all query filtering
	on the data in the DNS responses received from the external server.
	It derives from both MessageQueue and ThreadPool.  Query responses
	will be received by the ServerNetwork class and placed in our
	message queue, which all of our ThreadPool threads will be monitoring.
	When a thread pulls a message off the queue, it will pass the message
	to our ThreadCallback for processing.  Note that this function must be
	thread safe as it could be called by multiple worker threads at the
	same time.  We grab the ProxyTable index values from the message,
	retrieve the corresponding ProxyEntry object, and do the actual filtering
	work.  The calling thread takes care of deleting the message object, and
	the ProxyEntry will be deleted when the response is finally transmitted
	to the original client.
*/

/*--------------------------------------------------------------------------*/
ReplyFilter::ReplyFilter(int aCount,int aLimit) : ThreadPool(aCount,aLimit,"ReplyFilter")
{
}
/*--------------------------------------------------------------------------*/
ReplyFilter::~ReplyFilter(void)
{
}
/*--------------------------------------------------------------------------*/
void ReplyFilter::ThreadSaturation(int argTotal)
{
// This function will get called by a pool worker when all of the threads
// become busy.  We don't want to spin up a new thread in this context so
// we send a message to the main thread with the request, but only if
// we haven't already created the maximum number of worker threads.

if (argTotal < ThreadLimit) g_master->PushMessage(new MessageFrame(MSG_ADDREPLYTHREAD));
}
/*--------------------------------------------------------------------------*/
void ReplyFilter::ThreadCallback(MessageFrame *argMessage)
{
ProxyMessage	*message = (ProxyMessage *)argMessage;
ProxyEntry		*local;

g_replycount++;
g_log->LogMessage(LOG_DEBUG,"ReplyFilter processing index %hu-%hu\n",message->qgrid,message->qslot);

// grab the proxy entry from the table
local = g_table->RetrieveObject(message->qgrid,message->qslot);
if (local == NULL) return;

// This is where the actual blacklist checks should happen.  Right now we
// just foward the reply to the client.  Eventually we'll do the actual
// checking, and also have a mechanism to return a block response

// forward the query response back to the client
if (local->netprotocol == IPPROTO_UDP) g_client->ForwardUDPReply(local);
if (local->netprotocol == IPPROTO_TCP) g_client->ForwardTCPReply(local);

// all done so delete the proxy table entry
g_table->RemoveObject(message->qgrid,message->qslot);
}
/*--------------------------------------------------------------------------*/


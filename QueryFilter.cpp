// QueryFilter.cpp
// DNS Proxy Filter Server
// Copyright (c) 2010-2019 Untangle, Inc.
// All Rights Reserved
// Written by Michael A. Hotz

#include "common.h"

/*
	The QueryFilter class is responsible for performing all query filtering
	on the data in the DNS queries received from clients.  It derives
	from both MessageQueue and ThreadPool.  Inbound DNS queries from
	clients will be received by the ClientNetwork class and placed in
	our message queue, which all of our ThreadPool threads will be
	monitoring.  When a thread pulls a message off the queue, it will
	pass the message to our ThreadCallback for processing.  Note that
	this function must be thread safe as it could be called by multiple
	worker threads at the same time.  We grab the ProxyTable index values
	from the message, retrieve the corresponding ProxyEntry object, and do
	the actual filtering work.  The calling thread takes care of deleting
	the message object, and the ProxyEntry will be deleted when the response
	is finally transmitted to the original client.
*/

/*--------------------------------------------------------------------------*/
QueryFilter::QueryFilter(int aCount,int aLimit) : ThreadPool(aCount,aLimit,"QueryFilter")
{
database = new Database();
}
/*--------------------------------------------------------------------------*/
QueryFilter::~QueryFilter(void)
{
delete(database);
}
/*--------------------------------------------------------------------------*/
void QueryFilter::ThreadSaturation(int argTotal)
{
// This function will get called by a pool worker when all of the threads
// become busy.  We don't want to spin up a new thread in this context so
// we send a message to the main thread with the request, but only if
// we haven't already created the maximum number of worker threads.

if (argTotal < ThreadLimit) g_master->PushMessage(new MessageFrame(MSG_ADDQUERYTHREAD));
}
/*--------------------------------------------------------------------------*/
void QueryFilter::ThreadCallback(MessageFrame *argMessage)
{
ProxyMessage	*message = (ProxyMessage *)argMessage;
ProxyEntry		*local;
NetworkEntry	*network;
char			textaddr[32];
int				white,black;

g_querycount++;
g_log->LogMessage(LOG_DEBUG,"QueryFilter processing index %hu-%hu\n",message->qgrid,message->qslot);

// grab the proxy entry from the table
local = g_table->RetrieveObject(message->qgrid,message->qslot);
if (local == NULL) return;

// grab the origin address from the proxy entry
inet_ntop(AF_INET,&local->origin.sin_addr,textaddr,sizeof(textaddr));

// lookup the owner of the source network
network = (NetworkEntry *)g_network->SearchObject(textaddr);

	// for unknown networks we block everything
	if (network == NULL)
	{
	g_log->LogMessage(LOG_NOTICE,"Received query from unknown network %s\n",textaddr);

	// transmit the block response and cleanup the table entry
	TransmitBlockTarget(local);
	g_table->RemoveObject(message->qgrid,message->qslot);
	return;
	}

g_log->LogMessage(LOG_DEBUG,"Processing query for %s from %s (USER = %d)\n",local->q_record.qname,textaddr,network->Owner);

// first check the whitelist
white = database->CheckPolicyList(WHITELIST,network,local->q_record.qname);

// if not in whitelist then we check the blacklist
if (white == 0) black = database->CheckPolicyList(BLACKLIST,network,local->q_record.qname);
else black = 0;

g_log->LogMessage(LOG_DEBUG,"NAME:%s  WHITE:%d  BLACK:%d\n",local->q_record.qname,white,black);

	// if the query name was in the whitelist or if it was not in
	// either the blaclist or category block we forward
	if ((white != 0) || (black == 0))
	{
	if (local->netprotocol == IPPROTO_TCP) g_server->ForwardTCPQuery(local);
	if (local->netprotocol == IPPROTO_UDP) g_server->ForwardUDPQuery(local);
	}

	// otherwise it was blocked so we send back the block
	// response and clean up the proxy table entry
	else
	{
	TransmitBlockTarget(local);
	g_table->RemoveObject(message->qgrid,message->qslot);
    }
}
/*--------------------------------------------------------------------------*/
void QueryFilter::TransmitBlockTarget(ProxyEntry *argEntry)
{
DNSPacket		*packet;
dnsflags		flags;

// get the query flags from the original request
flags = argEntry->q_header.flags;

// set the AA and RA flags
flags.pf.authority = 1;
if (flags.pf.wantrec != 0) flags.pf.haverec = 1;

// create a DNS response with our block server as the answer
packet = new DNSPacket();
packet->Insert_Master(htons(argEntry->q_header.qid),flags.value,1,1,0,0);
packet->Insert_Question(argEntry->q_record.qname,argEntry->q_record.qtype,argEntry->q_record.qclass);
packet->Begin_Record(argEntry->q_record.qname,argEntry->q_record.qtype,argEntry->q_record.qclass,60);
packet->Insert_IPV4(cfg_BlockServerAddr);
packet->Close_Record();

// insert our synthetic response into the proxy table object
argEntry->InsertReply(packet);

// delete our synthetic response
delete(packet);

// forward the query response back to the client
if (argEntry->netprotocol == IPPROTO_UDP) g_client->ForwardUDPReply(argEntry);
if (argEntry->netprotocol == IPPROTO_TCP) g_client->ForwardTCPReply(argEntry);
}
/*--------------------------------------------------------------------------*/


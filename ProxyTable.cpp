// ProxyTable.cpp
// DNS Proxy Filter Server
// Copyright (c) 2010-2019 Untangle, Inc.
// All Rights Reserved
// Written by Michael A. Hotz

#include "common.h"

/*
	The ProxyTable manages the list of all active queries in the server.
	When a new entry is added, 16 bit grid and slot values are assigned.
	These values give us a way to correlate the DNS query and response
	from the external DNS server with the client that originally made the
	request.  When proxying a query for resolution, we replace the query
	id from the client request with our slot value before sending the
	packet to the server, and we use the grid value to determine the index
	of our port array to use for transmit.  When we get the response, we
	lookup the corresponding entry in this table based on the receive
	socket index (grid) and the query id (slot) in the reply, and
	processing continues.  When we finally send the response back to the
	client, we restore the query id from the original packet and send
	the result to the client.

	Given the standard DNS query timeout, it's possible in theory for a
	server under very heavy load to have more than 64k queries active
	at any given time, so the grid and slot model allows us to have
	multiple 64k tables for tracking outstanding queries.  All this
	nonsense because the DNS spec only allocated 16 bits for the query
	id.  If they had allowed 32 bits this would be so much easier, but
	instead we have this mess.  But hey, it gave me an excuse to
	use *** which is kinda cool!
*/

/*--------------------------------------------------------------------------*/
ProxyTable::ProxyTable(int argSize)
{
int		x;

// allocate the argumented number of work tables
worktable = (ProxyEntry ***)calloc(argSize,sizeof(ProxyEntry *));

	for(x = 0;x < argSize;x++)
	{
	worktable[x] = (ProxyEntry **)calloc(0x10000,sizeof(ProxyEntry *));
	}

tablesize = argSize;
slotindex = 0;
gridindex = 0;
}
/*--------------------------------------------------------------------------*/
ProxyTable::~ProxyTable(void)
{
int		x,y;

	// delete any objects hanging around
	for(x = 0;x < tablesize;x++)
	{
		for(y = 0;y < 0x10000;y++)
		{
		delete(worktable[x][y]);
		}
	}

// delete the work tables
for(x = 0;x < tablesize;x++) free(worktable[x]);
free(worktable);
}
/*--------------------------------------------------------------------------*/
int ProxyTable::InsertObject(ProxyEntry *argEntry)
{
unsigned short		grid,slot;

// grab the index values for the new object
slot = slotindex;
grid = gridindex;

// increment the slot index
slotindex++;

	// if we have wrapped around increment the grid index
	if (slotindex == 0)
	{
	gridindex++;

	// if we hit the table size wrap back to zero
	if (gridindex == tablesize) gridindex = 0;
	}

	// if object is dirty delete the old object first
	if (worktable[grid][slot] != NULL)
	{
	delete(worktable[grid][slot]);
	g_dirtycount++;
	}

// store the new object in the table
worktable[grid][slot] = argEntry;

// store object index inside the object
argEntry->mygrid = grid;
argEntry->myslot = slot;

g_log->LogMessage(LOG_DEBUG,"QINDEX:%hu-%hu  QNAME:%s  QTYPE:%hu  QCLASS:%hu\n",
	grid,slot,argEntry->q_record.qname,argEntry->q_record.qtype,argEntry->q_record.qclass);

return(1);
}
/*--------------------------------------------------------------------------*/
int ProxyTable::RemoveObject(unsigned short argGrid,unsigned short argSlot)
{
// object is null so return error
if (worktable[argGrid][argSlot] == NULL) return(0);

// delete the object and clear the entry
delete(worktable[argGrid][argSlot]);
worktable[argGrid][argSlot] = NULL;

// return index as confirmation
return(1);
}
/*--------------------------------------------------------------------------*/
ProxyEntry *ProxyTable::RetrieveObject(unsigned short argGrid,unsigned short argSlot)
{
// return the object at the argumented index
return(worktable[argGrid][argSlot]);
}
/*--------------------------------------------------------------------------*/


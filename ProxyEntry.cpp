// ProxyEntry.cpp
// DNS Proxy Filter Server
// Copyright (c) 2010-2019 Untangle, Inc.
// All Rights Reserved
// Written by Michael A. Hotz

#include "common.h"

/*
	The ProxyEntry class manages all of the details associated with each
	DNS query that is being handled by the server.  A new instance is
	created by the ClientNetwork class for every query received, and
	inserted into the global ProxyTable.  The entry is then passed
	by reference to its grid and slot values through all subsequent
	logic stages in the system.  The grid value accociates the query
	with a particular network port in NetworkServer, and the 16 bit
	slot value is used in the query header and response for mapping
	the forwarded query/reply chain to the outstanding client request.
*/

/*--------------------------------------------------------------------------*/
ProxyEntry::ProxyEntry(void)
{
memset(&origin,0,sizeof(origin));
netprotocol = 0;
netsocket = 0;
mygrid = 0;
myslot = 0;

rawquery = rawreply = NULL;
rawqsize = rawrsize = 0;

memset(&q_header,0,sizeof(q_header));
memset(&q_record,0,sizeof(q_record));
}
/*--------------------------------------------------------------------------*/
ProxyEntry::~ProxyEntry(void)
{
if (rawquery != NULL) free(rawquery);
if (rawreply != NULL) free(rawreply);
}
/*--------------------------------------------------------------------------*/
int ProxyEntry::InsertQuery(const char *argBuffer,int argSize,netportal *argPortal)
{
const unsigned char		*data;
int						offset;
int						out;

// first make sure we have the minimum size for a valid DNS query
if (argSize < 17) return(0);

// save the origin address and connection information
memcpy(&origin,&argPortal->addr,sizeof(origin));
netprotocol = argPortal->proto;
netsocket = argPortal->sock;

// save the raw query packet
rawquery = (char *)malloc(argSize);
memcpy(rawquery,argBuffer,argSize);
rawqsize = argSize;

data = (const unsigned char *)argBuffer;

// first we grab the DNS header fields
q_header.qid = ntohs(*(unsigned short *)&data[0]);
q_header.flags.value = ntohs(*(unsigned short *)&data[2]);
q_header.qdcount = ntohs(*(unsigned short *)&data[4]);
q_header.ancount = ntohs(*(unsigned short *)&data[6]);
q_header.nscount = ntohs(*(unsigned short *)&data[8]);
q_header.arcount = ntohs(*(unsigned short *)&data[10]);

// ignore queries with invalid qdcount
if (q_header.qdcount != 1) return(0);

// extract the qname
offset = 12;
out = 0;

	// if first label is zero we have a request for dot
	if (data[offset] == 0)
	{
	q_record.qname[out++] = '.';
	q_record.qname[out] = 0;
	}

	// walk the string until we find the final label
	else while (data[offset] != 0)
	{
	// labels are limited to 63 octets
	if (data[offset] > 63) return(0);

	// make sure we don't exceed the received data size
	if ((offset + data[offset]) > argSize) return(0);

	// names are limited to 255 octets
	if ((out + data[offset]) > 255) return(0);

	// copy the label to our qname buffer and append a dot
	memcpy(&q_record.qname[out],&data[offset+1],data[offset]);
	out+=data[offset];
	q_record.qname[out++] = '.';
	q_record.qname[out] = 0;

	// adjust the offset
	offset+=data[offset];
	offset++;
	}

// skip over the final label
offset++;

// extract the query type and class
q_record.qtype = ntohs(*(unsigned short *)&data[offset]);
offset+=2;
q_record.qclass = ntohs(*(unsigned short *)&data[offset]);
offset+=2;

return(1);
}
/*--------------------------------------------------------------------------*/
int ProxyEntry::InsertReply(const char *argBuffer,int argSize)
{
// save the raw reply packet
rawreply = (char *)malloc(argSize);
memcpy(rawreply,argBuffer,argSize);
rawrsize = argSize;

return(1);
}
/*--------------------------------------------------------------------------*/
int ProxyEntry::InsertReply(DNSPacket *argPacket)
{
// copy the raw data from the argumented packet
rawreply = (char *)malloc(argPacket->length);
memcpy(rawreply,argPacket->buffer,argPacket->length);
rawrsize = argPacket->length;

return(1);
}
/*--------------------------------------------------------------------------*/


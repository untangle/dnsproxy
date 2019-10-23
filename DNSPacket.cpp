// DNSPacket.cpp
// DNS Proxy Filter Server
// Copyright (c) 2010-2019 Untangle, Inc.
// All Rights Reserved
// Written by Michael A. Hotz

#include "common.h"
/*--------------------------------------------------------------------------*/
DNSPacket::DNSPacket(void)
{
buffer = (char *)malloc(DNSBUFFER);

memset(complist,0,sizeof(complist));
comptot = 0;

memset(buffer,0,DNSBUFFER);
length = prefix = 0;
marker = NULL;
offset = 0;

id = 0;
idval = NULL;

flags = 0;
flval = NULL;

qdcount = 0;
qdval = NULL;

ancount = nscount = arcount = 0;
anval = nsval = arval = NULL;
}
/*--------------------------------------------------------------------------*/
DNSPacket::~DNSPacket(void)
{
free(buffer);
}
/*--------------------------------------------------------------------------*/
void DNSPacket::Insert_Master(unsigned short aId,unsigned short aFlags,short qd,short an,short ns,short ar)
{
idval = (unsigned short *)&buffer[length];	Insert_INT16(aId);
flval = (unsigned short *)&buffer[length];	Insert_INT16(aFlags);
qdval = (unsigned short *)&buffer[length];	Insert_INT16(qd);
anval = (unsigned short *)&buffer[length];	Insert_INT16(an);
nsval = (unsigned short *)&buffer[length];	Insert_INT16(ns);
arval = (unsigned short *)&buffer[length];	Insert_INT16(ar);
}
/*--------------------------------------------------------------------------*/
void DNSPacket::Update_Master(unsigned short aId,unsigned short aFlags,short qd,short an,short ns,short ar)
{
*idval = htons(aId);
*flval = htons(aFlags);
*qdval = htons(qd);
*anval = htons(an);
*nsval = htons(ns);
*arval = htons(ar);
}
/*--------------------------------------------------------------------------*/
void DNSPacket::Begin_Record(const char *aName,short aType,short aClass,long aLife)
{
Insert_DNAME(aName);
Insert_INT16(aType);
Insert_INT16(aClass);
Insert_INT32(aLife);

marker = (unsigned short *)&buffer[length];
length+=2;
prefix = length;
}
/*--------------------------------------------------------------------------*/
void DNSPacket::Close_Record(void)
{
*marker = htons(length - prefix);
marker = NULL;
}
/*--------------------------------------------------------------------------*/
void DNSPacket::Insert_Question(const char *aName,int aType,int aClass)
{
Insert_DNAME(aName);
Insert_INT16(aType);
Insert_INT16(aClass);
}
/*--------------------------------------------------------------------------*/
void DNSPacket::Insert_DNAME(const char *aName)
{
const char		*find,*next;
char			work[256];
int 			len,dif;
int 			x,loc;

if (strcmp(aName,".") == 0) goto ROOTSKIP;

// first convert the name to a string of labels

loc = 0;
find = aName;

	for(;;)
	{
	next = strchr(find,'.');
	if (next == NULL) break;
	dif = (int)(next - find);
	next++;

	work[loc] = (unsigned char)dif;
	loc++;
	memcpy(&work[loc],find,dif);
	loc+=dif;

	find = next;
	}

work[loc] = 0;

// start working at first label and pack it in

next = work;

	while (next[0] != 0)
	{
		for(x = 0;x < comptot;x++)
		{
		// see if anything exactly matches current chunk
		if (Search_DNAME(&buffer[complist[x]],next) == 0) continue;

		// found a match so insert a pointer and return
		*(unsigned short *)&buffer[length] = htons((short)complist[x]);
		buffer[length]|=0xC0;
		length+=2;
		return;
		}

	// no match so add the current offset to the compression
	// array and then pack the label into the output buffer

	complist[comptot] = length;
	comptot++;

	len = next[0];
	next++;

	buffer[length] = (char)len;
	length++;

	memcpy(&buffer[length],next,len);
	length+=len;
	next+=len;
	}

ROOTSKIP:

buffer[length] = 0;
length++;
}
/*--------------------------------------------------------------------------*/
void DNSPacket::Insert_IPV4(const char *aData)
{
*(unsigned long *)&buffer[length] = inet_addr(aData);
length+=4;
}
/*--------------------------------------------------------------------------*/
void DNSPacket::Insert_IPV6(const char *aData)
{
}
/*--------------------------------------------------------------------------*/
void DNSPacket::Insert_INT8(const char *aData)
{
buffer[length] = atoi(aData);
length++;
}
/*--------------------------------------------------------------------------*/
void DNSPacket::Insert_INT8(char aValue)
{
buffer[length] = aValue;
length++;
}
/*--------------------------------------------------------------------------*/
void DNSPacket::Insert_INT16(const char *aData)
{
*(unsigned short *)&buffer[length] = htons(atoi(aData));
length+=2;
}
/*--------------------------------------------------------------------------*/
void DNSPacket::Insert_INT16(short aValue)
{
*(unsigned short *)&buffer[length] = htons(aValue);
length+=2;
}
/*--------------------------------------------------------------------------*/
void DNSPacket::Insert_INT32(const char *aData)
{
*(unsigned long *)&buffer[length] = htonl(atol(aData));
length+=4;
}
/*--------------------------------------------------------------------------*/
void DNSPacket::Insert_INT32(long aValue)
{
*(unsigned long *)&buffer[length] = htonl(aValue);
length+=4;
}
/*--------------------------------------------------------------------------*/
void DNSPacket::Insert_STRING(const char *aData)
{
int			len;

len = (int)strlen(aData);
buffer[length] = (unsigned char)len;
length++;
memcpy(&buffer[length],aData,len);
length+=len;
}
/*--------------------------------------------------------------------------*/
void DNSPacket::Insert_BINARY(const void *aData,int aSize)
{
memcpy(&buffer[length],aData,aSize);
length+=aSize;
}
/*--------------------------------------------------------------------------*/
int DNSPacket::Search_DNAME(const char *jungle,const char *needle)
{
int			value;

	for(;;)
	{
	// if we find the end of both at same time return true
	if ((needle[0] == 0) && (jungle[0] == 0)) return(1);

	// if we reach the end of either one or the other return false
	if (needle[0] == 0) return(0);
	if (jungle[0] == 0) return(0);

		// handle pointers embeded in the jungle
		while (jungle[0] & 0xC0)
		{
		value = ntohs(*(unsigned short *)&jungle[0]);
		value&=0x3FFF;
		jungle = &buffer[value];
		}

	// if length doesn't match return false
	if (jungle[0] != needle[0]) return(0);

	// if the bytes don't match return false
	if (memcmp(&jungle[1],&needle[1],needle[0]) != 0) return(0);

	// label matches so skip over and continue with next
	jungle+=jungle[0];
	jungle++;
	needle+=needle[0];
	needle++;
	}
}
/*--------------------------------------------------------------------------*/
int DNSPacket::Extract_DNAME(char *target,unsigned tlen)
{
unsigned short		holder,actual,taroff;
unsigned			len;

target[0] = 0;
holder = 0;
actual = 0;
taroff = 0;

	// pull the name out of the packet
	while (buffer[offset] != 0)
	{
		// look for compression pointers
		if ((buffer[offset] & 0xC0) != 0)
		{
			// save current offset the first time we find a pointer
			if (holder == 0)
			{
			holder = offset;
			actual = taroff;
			}

		// adjust working offset and continue grabing the name
		offset = ntohs(*(unsigned short *)&buffer[offset]);
		offset&=0x3FFF;

		// if pointer is invalid zero offset and bail
		if (offset > (length - 2)) return(-1);

		// if pointer to another pointer we bail
		if (buffer[offset] & 0xC0) return(-1);

		continue;
		}

	len = buffer[offset];

		// the rules say labels are limited to 63 octets
		if (len > 63) return(-1);

		// if length byte is invalid zero offset and bail
		if ((int)(offset + len) > length) return(-1);

		// if buffer overrun zero offset and bail
		if ((taroff + len + 2) > tlen) return(-1);

	// copy the label and add the dot
	strncpy(&target[taroff],(char *)&buffer[offset+1],len);
	taroff+=len;
	target[taroff] = '.';
	taroff++;
	target[taroff] = 0;

	offset+=len;
	offset++;
	}

	// the rules say names are limited to 255 octets
	if (taroff > 255) return(-1);

	// skip over final zero byte of name when no pointers found
	if (holder == 0)
	{
	offset++;
	taroff++;
	target[taroff] = 0;
	actual = taroff;
	}

	// otherwise add two bytes to skip over the first pointer
	else
	{
	offset = (holder + 2);
	actual+=2;
	taroff++;
	target[taroff] = 0;
	}

return(actual);
}
/*--------------------------------------------------------------------------*/
int DNSPacket::Extract_IPV4(char *target,unsigned tlen)
{
struct in_addr		local;

// make sure we do not walk outside the buffer
if ((offset + 4) > length) return(-1);

// convert the address to xxx.xxx.xxx.xxx
memcpy((char *)&local.s_addr,(char *)&buffer[offset],sizeof(local.s_addr));
offset+=4;
strcpy(target,inet_ntoa(local));

return(4);
}
/*--------------------------------------------------------------------------*/
int DNSPacket::Extract_INT8(char *target,unsigned tlen)
{
// make sure we do not walk outside the buffer
if ((offset + 1) > length) return(-1);

// convert the int8 value to a string
sprintf(target,"%hu",(unsigned short)buffer[offset]);
offset++;

return(1);
}
/*--------------------------------------------------------------------------*/
int DNSPacket::Extract_INT16(char *target,unsigned tlen)
{
unsigned short		value;

// make sure we do not walk outside the buffer
if ((offset + 2) > length) return(-1);

// convert the int16 value to a string
value = ntohs(*(unsigned short *)&buffer[offset]);
offset+=2;
sprintf(target,"%hu",value);

return(2);
}
/*--------------------------------------------------------------------------*/
int DNSPacket::Extract_INT32(char *target,unsigned tlen)
{
unsigned long		value;

// make sure we do not walk outside the buffer
if ((offset + 4) > length) return(-1);

// convert the int32 value to a string
value = ntohl(*(unsigned long *)&buffer[offset]);
offset+=4;
sprintf(target,"%lu",value);

return(4);
}
/*--------------------------------------------------------------------------*/
int DNSPacket::Extract_STRING(char *target,unsigned tlen)
{
unsigned			len;

// make sure we do not walk outside the buffer
if ((offset + 1) > length) return(-1);

len = buffer[offset];
offset++;

// make sure we do not walk outside the buffer or the target
if ((int)(offset + len) > length) return(-1);
if (len > tlen) return(-1);

memcpy(target,&buffer[offset],len);
target[len] = 0;
offset+=len;

return(len+1);
}
/*--------------------------------------------------------------------------*/


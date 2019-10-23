// HashTable.cpp
// DNS Proxy Filter Server
// Copyright (c) 2010-2019 Untangle, Inc.
// All Rights Reserved
// Written by Michael A. Hotz

#include "common.h"

/*--------------------------------------------------------------------------*/
HashTable::HashTable(int aBuckets)
{
int		x;

// save the number of buckets
buckets = aBuckets;

// allocate the bucket array
table = (HashObject **)calloc(buckets,sizeof(HashObject *));

// allocate and initialize the bucket locks
control = (pthread_mutex_t *)calloc(buckets,sizeof(pthread_mutex_t));

	for(x = 0;x < buckets;x++)
	{
	memset(&control[0],0,sizeof(pthread_mutex_t));
	pthread_mutex_init(&control[x],NULL);
	}
}
/*--------------------------------------------------------------------------*/
HashTable::~HashTable(void)
{
HashObject	*work,*hold;
int			x;

	// walk through all the buckets and delete everything
	for(x = 0;x < buckets;x++)
	{
	if (table[x] == NULL) continue;
	work = table[x];
		while (work != NULL)
		{
		hold = work->next;
		delete(work);
		work = hold;
		}
	}

// free the bucket array
free(table);

// free the bucket locks
for(x = 0;x < buckets;x++) pthread_mutex_destroy(&control[x]);
free(control);
}
/*--------------------------------------------------------------------------*/
int HashTable::InsertObject(HashObject *argObject)
{
int			key;

// calculate bucket using the active hash function
key = HashKey(argObject->ObjectName);

// save existing item in new item next pointer
argObject->next = table[key];

// put new item at front of list
table[key] = argObject;

return(key);
}
/*--------------------------------------------------------------------------*/
HashObject* HashTable::SearchObject(const char *argString)
{
HashObject	*find;
int			key;

// calculate bucket using the active hash function
key = HashKey(argString);

// if the bucket is empty return nothing
if (table[key] == NULL) return(NULL);

// search for exact match or default
for(find = table[key];find != NULL;find = find->next) if (strcmp(argString,find->ObjectName) == 0) return(find);

// return NULL if nothing found
return(NULL);
}
/*--------------------------------------------------------------------------*/
unsigned int HashTable::HashKey(const char *argString)
{
const unsigned char		*key = (const unsigned char *)argString;
unsigned int			hash;

hash = 0;
while (*key) hash = ((*key++) + (hash << 6) + (hash << 16) - hash);
return(hash % buckets);
}
/*--------------------------------------------------------------------------*/
void HashTable::GetTableSize(int &aCount,int &aBytes)
{
HashObject	*work;
int			x;

aCount = 0;
aBytes = 0;

// start with our size
aBytes = sizeof(*this);
aBytes+=(buckets * sizeof(HashObject *));
aBytes+=(buckets * sizeof(pthread_mutex_t));

	// walk through all of the table entries
	for(x = 0;x < buckets;x++)
	{
	// lock the bucket
	pthread_mutex_lock(&control[x]);

		// count and add the size of every object in active tables
		if (table[x] != NULL)
		{
			for(work = table[x];work != NULL;work = work->next)
			{
			aBytes+=work->GetObjectSize();
			aCount++;
			}
		}

	// unlock the bucket
	pthread_mutex_unlock(&control[x]);
	}
}
/*--------------------------------------------------------------------------*/
/****************************************************************************/
/*--------------------------------------------------------------------------*/
HashObject::HashObject(const char *argTitle)
{
ObjectName = NULL;
next = NULL;
if (argTitle == NULL) return;

ObjectName = newstr(argTitle);
}
/*--------------------------------------------------------------------------*/
HashObject::~HashObject(void)
{
freestr(ObjectName);
}
/*--------------------------------------------------------------------------*/
int HashObject::GetObjectSize(void)
{
int		mysize;

mysize = sizeof(*this);
return(mysize);
}
/*--------------------------------------------------------------------------*/
/****************************************************************************/
/*--------------------------------------------------------------------------*/
NetworkEntry::NetworkEntry(unsigned long aObject,unsigned long aOwner,const char* aNetwork) : HashObject(aNetwork)
{
Object = aObject;
Owner = aOwner;
};
/*--------------------------------------------------------------------------*/
NetworkEntry::~NetworkEntry(void)
{
}
/*--------------------------------------------------------------------------*/
int NetworkEntry::GetObjectSize(void)
{
int		mysize;

mysize = sizeof(*this);
return(mysize);
}
/*--------------------------------------------------------------------------*/


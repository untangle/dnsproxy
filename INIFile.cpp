// INIFile.cpp
// Configuration File Management Class
// Copyright (c) 1989-2019 InterSafe, Inc.
// Written by Michael A. Hotz

#include "common.h"

/*--------------------------------------------------------------------------*/
INIFile::INIFile(const char *aFileName)
{
INIGroup			*group;
INIEntry			*entry;
FILE				*in;
struct stat			finfo;
char				*check,*after;
char				*buffer;
char				local[1024];

basegroup = NULL;
filename = NULL;

if (aFileName == NULL) return;

filename = new char[strlen(aFileName)+1];
strcpy(filename,aFileName);

in = fopen(filename,"r");
if (in == NULL) return;

memset(&finfo,0,sizeof(finfo));
fstat(fileno(in),&finfo);

buffer = new char[0x1000];
if (buffer != NULL) setvbuf(in,buffer,_IOFBF,0x1000);

group = MakeGroup("NULL");

	for(;;)
	{
	check = fgets(local,sizeof(local),in);
	if (check == NULL) break;

	while ((check[0] != 0) && (check[0] != '#') && (check[0] != '\n') && (check[0] != '\r')) check++;
	check[0] = 0;

	check = strchr(local,'[');
	if (check != NULL) after = strchr(check,']');
	else after = NULL;

		if (after != NULL)
		{
		group = MakeGroup(local);
		continue;
		}

	check = strchr(local,'=');
	if (check == NULL) continue;
	*check++=0;

	// skip over any leading space
	while ((check[0] != 0) && (isspace(check[0]))) *check++=0;

		// for quoted strings look for closing quote
		if (check[0] == '"')
		{
		*check++=0;
		after = strchr(check,'"');
		if (check == NULL) continue;
		after[0] = 0;
		}

		// otherwise trim any trailing space
		else
		{
		after = check;
		while ((after[0] != 0) && (!isspace(after[0]))) after++;
		after[0] = 0;
		}

	if (group == NULL) continue;
	entry = group->MakeEntry(local);
	if (entry != NULL) entry->SetEntryText(check);
	}

fclose(in);
if (buffer != NULL) delete[](buffer);
}
/*--------------------------------------------------------------------------*/
INIFile::~INIFile(void)
{
INIGroup		*current,*chain;

if (filename != NULL) delete[](filename);

current = basegroup;

	while (current != NULL)
	{
	chain = current->next;
	delete(current);
	current = chain;
	}

basegroup = NULL;
}
/*--------------------------------------------------------------------------*/
INIGroup *INIFile::FindGroup(const char *aGroupName)
{
INIGroup		*current;

	for(current = basegroup;current != NULL;current = current->next)
	{
	if (strcasecmp(current->GroupName,aGroupName) == 0) return(current);
	}

return(NULL);
}
/*--------------------------------------------------------------------------*/
INIGroup *INIFile::MakeGroup(const char *aGroupName)
{
INIGroup		*current;

if (basegroup == NULL) return(basegroup = new INIGroup(NULL,aGroupName));
for(current = basegroup;current->next != NULL;current = current->next);
current->next = new INIGroup(current,aGroupName);
return(current->next);
}
/*--------------------------------------------------------------------------*/
int INIFile::GetItem(const char *group,const char *field,signed char& dest,signed char init)
{
char			*find;

dest = init;
find = FindString(group,field);
if (find != NULL) dest = (char)strtol(find,NULL,0);
return(find ? 1 : 0);
}
/*--------------------------------------------------------------------------*/
int INIFile::GetItem(const char *group,const char *field,signed short& dest,signed short init)
{
char			*find;

dest = init;
find = FindString(group,field);
if (find != NULL) dest = (short)strtol(find,NULL,0);
return(find ? 1 : 0);
}
/*--------------------------------------------------------------------------*/
int INIFile::GetItem(const char *group,const char *field,signed int& dest,signed int init)
{
char			*find;

dest = init;
find = FindString(group,field);
if (find != NULL) dest = (int)strtol(find,NULL,0);
return(find ? 1 : 0);
}
/*--------------------------------------------------------------------------*/
int INIFile::GetItem(const char *group,const char *field,signed long& dest,signed long init)
{
char			*find;

dest = init;
find = FindString(group,field);
if (find != NULL) dest = strtol(find,NULL,0);
return(find ? 1 : 0);
}
/*--------------------------------------------------------------------------*/
int INIFile::GetItem(const char *group,const char *field,unsigned char& dest,unsigned char init)
{
char			*find;

dest = init;
find = FindString(group,field);
if (find != NULL) dest = (unsigned char)strtoul(find,NULL,0);
return(find ? 1 : 0);
}
/*--------------------------------------------------------------------------*/
int INIFile::GetItem(const char *group,const char *field,unsigned short& dest,unsigned short init)
{
char			*find;

dest = init;
find = FindString(group,field);
if (find != NULL) dest = (unsigned short)strtoul(find,NULL,0);
return(find ? 1 : 0);
}
/*--------------------------------------------------------------------------*/
int INIFile::GetItem(const char *group,const char *field,unsigned int& dest,unsigned int init)
{
char			*find;

dest = init;
find = FindString(group,field);
if (find != NULL) dest = (unsigned int)strtoul(find,NULL,0);
return(find ? 1 : 0);
}
/*--------------------------------------------------------------------------*/
int INIFile::GetItem(const char *group,const char *field,unsigned long& dest,unsigned long init)
{
char			*find;

dest = init;
find = FindString(group,field);
if (find != NULL) dest = strtoul(find,NULL,0);
return(find ? 1 : 0);
}
/*--------------------------------------------------------------------------*/
int INIFile::GetItem(const char *group,const char *field,char *dest,const char *init)
{
char			*find;

if (init == NULL) strcpy(dest,"");
else strcpy(dest,init);
find = FindString(group,field);
if (find != NULL) strcpy(dest,find);
return(find ? 1 : 0);
}
/*--------------------------------------------------------------------------*/
int INIFile::GetItem(const char *group,const char *field,void *dest,int size,void *init)
{
unsigned	char	*target;
unsigned	char	byte;
unsigned	char	niba,nibb;
char				*find;
int				x,y;

if (init == NULL) memset(dest,0,size);
else memcpy(dest,init,size);

find = FindString(group,field);
if (find == NULL) return(0);

target = (unsigned char *)dest;

	for(x = 0;x < size;x++)
	{
	y = (x * 2);
	niba = (unsigned char)((find[y]) - 65);
	nibb = (unsigned char)((find[y+1]) - 65);
	byte = (unsigned char)(niba | (nibb << 4));
	target[x] = byte;
	}

return(1);
}
/*--------------------------------------------------------------------------*/
char *INIFile::FindString(const char *aGroupName,const char *aEntryName)
{
INIGroup		*group;
INIEntry		*entry;

group = FindGroup(aGroupName);
if (group == NULL) return(NULL);
entry = group->FindEntry(aEntryName);
if (entry == NULL) return(NULL);
return(entry->EntryText);
}
/*--------------------------------------------------------------------------*/
/****************************************************************************/
/*--------------------------------------------------------------------------*/
INIGroup::INIGroup(INIGroup *aLast,const char *aGroupName) : last(aLast)
{
char			*check,*strip;
char			worktext[32];

baseentry = NULL;
next = NULL;

strcpy(worktext,aGroupName);

check = strchr(worktext,'[');
if (check == NULL) check = worktext;
else *check++ = 0;
strip = strchr(check,']');
if (strip != NULL) *strip = 0;

GroupName = new char[strlen(check)+1];
if (GroupName != NULL) strcpy(GroupName,check);
}
/*--------------------------------------------------------------------------*/
INIGroup::~INIGroup(void)
{
INIEntry		*current,*chain;

current = baseentry;

	while (current != NULL)
	{
	chain = current->next;
	delete(current);
	current = chain;
	}

delete[](GroupName);
}
/*--------------------------------------------------------------------------*/
INIEntry *INIGroup::MakeEntry(const char *aEntryName)
{
INIEntry		*current;

if (baseentry == NULL) return(baseentry = new INIEntry(NULL,aEntryName));
for(current = baseentry;current->next != NULL;current = current->next);
current->next = new INIEntry(current,aEntryName);
return(current->next);
}
/*--------------------------------------------------------------------------*/
INIEntry *INIGroup::FindEntry(const char *aEntryName)
{
INIEntry		*current;

	for(current = baseentry;current != NULL;current = current->next)
	{
	if (strcasecmp(current->EntryName,aEntryName) == 0) return(current);
	}

return(NULL);
}
/*--------------------------------------------------------------------------*/
/****************************************************************************/
/*--------------------------------------------------------------------------*/
INIEntry::INIEntry(INIEntry *aLast,const char *aEntryName) : last(aLast)
{
EntryName = new char[strlen(aEntryName)+1];
if (EntryName != NULL) strcpy(EntryName,aEntryName);
EntryText = NULL;
next = NULL;
}
/*--------------------------------------------------------------------------*/
INIEntry::~INIEntry(void)
{
if (EntryName != NULL) delete[](EntryName);
if (EntryText != NULL) delete[](EntryText);
}
/*--------------------------------------------------------------------------*/
int INIEntry::SetEntryText(const char *aEntryText)
{
if (EntryText != NULL) delete[](EntryText);
EntryText = new char[strlen(aEntryText)+1];
if (EntryText == NULL) return(1);
strcpy(EntryText,aEntryText);
return(0);
}
/*--------------------------------------------------------------------------*/


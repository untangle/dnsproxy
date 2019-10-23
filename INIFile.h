// INIFile.h
// Configuration File Management Class
// Copyright (c) 1989-2019 InterSafe, Inc.
// Written by Michael A. Hotz

/*--------------------------------------------------------------------------*/
class INIFile;
class INIGroup;
class INIEntry;
/*--------------------------------------------------------------------------*/
class INIFile
{
public:

	INIFile(const char *aFileName);
	~INIFile(void);

	int GetItem(const char *group,const char *field,signed char& dest,signed char init);
	int GetItem(const char *group,const char *field,signed short& dest,signed short init);
	int GetItem(const char *group,const char *field,signed int& dest,signed int init);
	int GetItem(const char *group,const char *field,signed long& dest,signed long init);
	int GetItem(const char *group,const char *field,unsigned char& dest,unsigned char init);
	int GetItem(const char *group,const char *field,unsigned short& dest,unsigned short init);
	int GetItem(const char *group,const char *field,unsigned int& dest,unsigned int init);
	int GetItem(const char *group,const char *field,unsigned long& dest,unsigned long init);
	int GetItem(const char *group,const char *field,char *dest,const char *init);
	int GetItem(const char *group,const char *field,void *dest,int size,void *init);

protected:

	char *FindString(const char *aGroupName,const char *aEntryName);

private:

	INIGroup *FindGroup(const char *aGroupName);
	INIGroup *MakeGroup(const char *aGroupName);

	INIGroup		*basegroup;
	char			*filename;
};
/*--------------------------------------------------------------------------*/
class INIGroup
{
friend class INIFile;

public:

	INIGroup(INIGroup *aLast,const char *aGroupName);
	~INIGroup(void);
	INIEntry *FindEntry(const char *aEntryName);
	INIEntry *MakeEntry(const char *aEntryName);

private:

	INIEntry		*baseentry;
	INIGroup		*last,*next;
	char			*GroupName;
};
/*--------------------------------------------------------------------------*/
class INIEntry
{
friend class INIFile;

public:

	INIEntry(INIEntry *aLast,const char *aEntryName);
	~INIEntry(void);
	int SetEntryText(const char *aEntryText);

public:

	INIEntry		*last,*next;
	char			*EntryName;
	char			*EntryText;
};
/*--------------------------------------------------------------------------*/


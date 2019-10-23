// Database.cpp
// DNS Proxy Filter Server
// Copyright (c) 2010-2019 Untangle, Inc.
// All Rights Reserved
// Written by Michael A. Hotz

#include "common.h"

/*
	The Database class handles all details required to interface with
	the MySQL database.  A purist might argue that the credentials, filter
	categoreies, and other things should be passed to the different member
	functions as parameters.  If we were building a library to be used by
	multiple applications I would agree.  But since the goal here is to
	create a class to handle all of the DB stuff just for this code, I
	opted to have this class leverage existing global variables.
*/

/*--------------------------------------------------------------------------*/
Database::Database(void)
{
MYSQL		*check;

querybuff[0] = 0;
error_flag = 0;

// initialize the database using our member context variable
memset(&context,0,sizeof(context));
check = mysql_init(&context);

	// if null is returned set the error flag and bail
	if (check == NULL)
	{
	g_log->LogMessage(LOG_ERR,"Error calling mysql_init()\n");
	error_flag = 1;
	return;
	}

// tell the library to look for options in our section of the my.cnf file
mysql_options(&context,MYSQL_READ_DEFAULT_GROUP,"dnsproxy");

// create the connection to the database and set the
// error flag with the return status of the connect
check = mysql_real_connect(&context,cfg_SQLhostname,cfg_SQLusername,cfg_SQLpassword,cfg_SQLdatabase,cfg_SQLport,NULL,cfg_SQLflags);
error_flag = mysql_errno(&context);

	if (error_flag != 0)
	{
	HandleError(__PRETTY_FUNCTION__,__FILE__,__LINE__);
	return;
	}
}
/*--------------------------------------------------------------------------*/
Database::~Database(void)
{
// close the database connection
mysql_close(&context);
memset(&context,0,sizeof(context));
}
/*--------------------------------------------------------------------------*/
void Database::HandleError(const char *function,const char *file,int line)
{
unsigned int	code;
char			problem[10240];

// grab the mysql error code and text
code = mysql_errno(&context);
strcpy(problem,mysql_error(&context));
if (strchr(problem,'\n') == NULL) strcat(problem,"\n");
if (strchr(querybuff,'\n') == NULL) strcat(querybuff,"\n");

// dump all the details to the log file
g_log->LogMessage(LOG_ERR,"----------------------------------------\n");
g_log->LogMessage(LOG_ERR,"** CRITICAL MYSQL ERROR IN %s **\n",function);
g_log->LogMessage(LOG_ERR,"** FILE:%s  LINE:%d  CODE:%d **\n",file,line,code);
g_log->LogMessage(LOG_ERR,problem);
g_log->LogMessage(LOG_ERR,querybuff);
g_log->LogMessage(LOG_ERR,"----------------------------------------\n");

// set the global shutdown flag
g_goodbye++;
}
/*--------------------------------------------------------------------------*/
unsigned long Database::ResultToValue(void)
{
unsigned long	value;
MYSQL_RES		*data;
MYSQL_ROW		row;

// store the result and bail on error
data = mysql_store_result(&context);

	if (data == NULL)
	{
	HandleError(__PRETTY_FUNCTION__,__FILE__,__LINE__);
	return(0);
	}

	// make sure we only get one row
	if (mysql_num_rows(data) != 1)
	{
	mysql_free_result(data);
	return(0);
	}

// seek to the first row and fetch
mysql_data_seek(data,0);
row = mysql_fetch_row(data);

// get the value from the result if valid
value = 0;
if ((row != NULL) && (row[0] != NULL)) value = strtoul(row[0],NULL,10);

// free the result and return the value
mysql_free_result(data);
return(value);
}
/*--------------------------------------------------------------------------*/
HashTable *Database::BuildNetworkTable(void)
{
HashTable		*table;
NetworkEntry	*entry;
MYSQL_RES		*data;
MYSQL_ROW		row;
unsigned long	objid;
unsigned long	owner;
const char		*netaddr;
int				count,bytes;
int				len,ret;

g_log->LogMessage(LOG_DEBUG,"Building network identification table\n");

// allocate a new network table
table = new HashTable(99991);

// select all of the network records
len = sprintf(querybuff,"SELECT objid, owner, netaddr FROM user_network");
if (cfg_LogDatabase != 0) g_log->LogMessage(LOG_DEBUG,"DATABASE: %s\n",querybuff);
ret = mysql_real_query(&context,querybuff,len);

	// check for error
	if (ret != 0)
	{
	HandleError(__PRETTY_FUNCTION__,__FILE__,__LINE__);
	return(NULL);
	}

// prepare the result set
data = mysql_use_result(&context);

	// check for error
	if (data == NULL)
	{
	HandleError(__PRETTY_FUNCTION__,__FILE__,__LINE__);
	return(NULL);
	}

	// grab each row and create network table entry
	for(;;)
	{
	row = mysql_fetch_row(data);
	if (row == NULL) break;

	// skip the row if any fields are null
	if (row[0] == NULL) continue;
	if (row[1] == NULL) continue;
	if (row[2] == NULL) continue;

	// convert the data to values we can use
	objid = strtoul(row[0],NULL,10);
	owner = strtoul(row[1],NULL,10);
	netaddr = row[2];

	// create a new network entry and stuff it in the table
	entry = new NetworkEntry(objid,owner,netaddr);
	table->InsertObject(entry);
	}

// free the result
mysql_free_result(data);

// query the network table details
count = bytes = 0;
table->GetTableSize(count,bytes);
g_log->LogMessage(LOG_DEBUG,"Network table contains %d entries using %d bytes\n",count,bytes);

// return the network table to the caller
return(table);
}
/*--------------------------------------------------------------------------*/
int Database::CheckPolicyList(int listcode,NetworkEntry *network,const char *qname)
{
unsigned long		value;
char				*spot,*find;
char				lname[260];
int					len,ret;

// local copy of the query name for walking
strcpy(lname,qname);

// trim the trailing space
find = strrchr(lname,'.');
find[0] = 0;

spot = querybuff;

	// create the select based on argumented listcode value
	switch(listcode)
	{
	case BLACKLIST:
		spot+=sprintf(spot,"SELECT COUNT(*) FROM policy_definition pd, policy_assignment pa, policy_blacklist pl ");
		break;

	case WHITELIST:
		spot+=sprintf(spot,"SELECT COUNT(*) FROM policy_definition pd, policy_assignment pa, policy_whitelist pl ");
		break;

	default: return(0);
	}

// everything else works for checking white or black
spot+=sprintf(spot,"WHERE ((pl.policy = pd.objid) AND (pa.policy = pd.objid)) ");
spot+=sprintf(spot,"AND ( ");
spot+=sprintf(spot,"((pa.class = 'network') AND (target = %lu)) ",network->Object);
spot+=sprintf(spot,"OR ");
spot+=sprintf(spot,"((pa.class = 'user') AND (target = %lu)) ",network->Owner);
spot+=sprintf(spot,") AND ( ");
spot+=sprintf(spot,"(pl.domain = '%s') ",lname);

// start at beginning of query name
find = lname;

	// walk down the query name adding each parent name
	for(;;)
	{
	// look for the next dot and bail when not found
	find = strchr(find,'.');
	if (find == NULL) break;

	// null the dot and increment the pointer
	*find++=0;

	// add the shortened name to the query
	spot+=sprintf(spot,"OR (pl.domain = '%s') ",find);
	}

spot+=sprintf(spot,")");

len = strlen(querybuff);
if (cfg_LogDatabase != 0) g_log->LogMessage(LOG_DEBUG,"DATABASE: %s\n",querybuff);
ret = mysql_real_query(&context,querybuff,len);

	// check for error
	if (ret != 0)
	{
	HandleError(__PRETTY_FUNCTION__,__FILE__,__LINE__);
	return(0);
	}

// convert the result to the numeric count
value = ResultToValue();

// return the number of entries found in the database
return(value);
}
/*--------------------------------------------------------------------------*/


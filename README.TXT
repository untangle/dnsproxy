** ClientNetwork.cpp

Handles inbound DNS queries from clients

** ServerNetwork.cpp

Handles forwarding DNS queries to a real DNS server

** QueryFilter.cpp

This is the class that does filtering on the QNAME in the client DNS query.
Currently implemented are a simple blacklist and a whitelist based on
the queried hostname. This allows yahoo.com to be added to the whitelist,
while the more specific porn.yahoo.com  can be added to the blacklist.
Queries that match the blacklist will be answered with the IP address
of a block server. All other queries will be forwared to an external
DNS server.

** ReplyFilter.cpp

This is the class that does filtering on the information contained in the
DNS response from the server. Currently it does a lookup to determine the
client waiting for the reply, and forwards the response from the server.
Additional filtering can be added here, with either the actual response
or a block response being returned, depending on the filtering logic.

** ProxyTable.cpp ProxyEntry.cpp

Manages the table of client DNS queries that have been forwarded and are
actively waiting for a response from the external DNS server. Complicated
by the fact that a DNS query only has a 16 bit identifier that we can use
to map the server reply to the original client that made the request.
To allow a dnsproxy under very heavy load to track more outstanding requests
than can be represented in 16 bits, we use multiple source ports when
forwarding queries, effectively giving us nearly 32 bits for uniquely
tracking active queries that we are proxying.

** DNSPacket.cpp

A class for extracting info from DNS queries, such as getting the QNAME from
an client query, and creating DNS responses, such as when we send
the block server IP address for DNS query that should be blocked.

** Database.cpp

Handles the database connection used to lookup DNS names in the
white and black lists.

** HashTable.cpp

Holds the table of source network addresses that are used to find
the policy and rules that should be applied to queries received
from that address.

** Thread.cpp MessageQueue.cpp

These files implement the multi-threaded message based framework that controls
the flow of traffic through the system.

** INIFile.cpp INIFile.h

A class for reading and writing configuration files

** Logger.cpp

A class for logging messages

** Makefile common.h dnsproxy.cpp dnsproxy.h dnsproxy.ini dnsproxy.sql

The main application code, header, and other support files.


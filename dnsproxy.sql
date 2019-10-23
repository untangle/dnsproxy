/**
	Script for creating the dnsproxy user and database. This script
	is destructive. It will first remove any existing dnsproxy
	database and user, and then create new with defaults.
**/


USE mysql;

DROP DATABASE IF EXISTS dnsproxy;
DROP USER IF EXISTS dnsproxy@localhost;

CREATE DATABASE dnsproxy;
CREATE USER dnsproxy@localhost identified by 'password';
GRANT ALL ON dnsproxy.* to 'dnsproxy'@'localhost';

USE dnsproxy;

CREATE TABLE user_account
(
	username	VARCHAR(64)		NOT NULL,
	password	VARCHAR(64)		NOT NULL,
	email		VARCHAR(128)	NOT NULL,
	objid		INTEGER			NOT NULL AUTO_INCREMENT,
	PRIMARY KEY (objid)
);

ALTER TABLE user_account AUTO_INCREMENT = 100000001;
INSERT INTO user_account (username , password , email, objid) VALUES('mahotz' , 'password' , 'mahotz@untangle.com', 1001);

CREATE TABLE user_network
(
	owner		INTEGER			NOT NULL,
	netaddr		VARCHAR(64)		NOT NULL,
	description	VARCHAR(128),
	objid		INT				NOT NULL AUTO_INCREMENT,
	PRIMARY KEY(objid),
	FOREIGN KEY (owner) REFERENCES user_account (objid)
);

ALTER TABLE user_account AUTO_INCREMENT = 200000001;
INSERT INTO user_network (owner , netaddr , description , objid) VALUES(1001 , '192.168.222.2' , 'rolex.intersafe.net' , 2001);

CREATE TABLE policy_definition
(
	owner		INTEGER			NOT NULL,
	nickname	VARCHAR(64)		NOT NULL,
	description	VARCHAR(128),
	visibility	VARCHAR(16)		NOT NULL,
	objid		INTEGER			NOT NULL AUTO_INCREMENT,
	PRIMARY KEY (objid),
	FOREIGN KEY (owner) REFERENCES user_account (objid)
);

ALTER TABLE user_account AUTO_INCREMENT = 300000001;
INSERT INTO policy_definition (owner , nickname , visibility , objid) VALUES(1001 , 'User Policy' , 'private' , 3001);
INSERT INTO policy_definition (owner , nickname , visibility , objid) VALUES(1001 , 'Network Policy' , 'private' , 3002);

CREATE TABLE policy_blacklist
(
	policy		INTEGER			NOT NULL,
	nickname	VARCHAR(64)		NOT NULL,
	domain		VARCHAR(256)	NOT NULL,
	description	VARCHAR(128),
	FOREIGN KEY (policy) REFERENCES policy_definition (objid)
);

INSERT INTO policy_blacklist VALUES(3001 , "Playboy" , "www.playboy.com" , "Block Playboy");
INSERT INTO policy_blacklist VALUES(3002 , "Hustler" , "www.hustler.com" , "Block Hustler");

CREATE TABLE policy_whitelist
(
	policy		INTEGER			NOT NULL,
	nickname	VARCHAR(64)		NOT NULL,
	domain		VARCHAR(256)	NOT NULL,
	description	VARCHAR(128),
	FOREIGN KEY (policy) REFERENCES policy_definition (objid)
);

INSERT INTO policy_whitelist VALUES(3001 , "Google" , "www.google.com" , "Allow Google");
INSERT INTO policy_whitelist VALUES(3002 , "Yahoo" , "www.yahoo.com" , "Allow Yahoo");

CREATE TABLE policy_assignment
(
	policy		INTEGER			NOT NULL,
	class		VARCHAR(16)		NOT NULL,
	target		INTEGER			NOT NULL,
	FOREIGN KEY (policy) REFERENCES policy_definition (objid)
);

INSERT INTO policy_assignment VALUES(3001 , 'user' , 1001);
INSERT INTO policy_assignment VALUES(3002 , 'network' , 2001);

COMMIT;


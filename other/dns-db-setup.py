#!/usr/bin/python

import MySQLdb as mysql
import sys

try:
	con = mysql.connect('localhost','dnsservice','dnsservice','dnsservice')
	with con:
		print "[*] Creating Table Watched"
		cur = con.cursor()
		cur.execute(drop table if exists watched")
		cur.execute("create table watched(id int primary key auto_increment, domain varchar(25), time_stamp timestamp)")
	
		print "[*] Creating Table Baseline"
		cur.execute("drop table if exists baseline")
		cur.execute("create table baseline(id int primary key auto_increment,  qname int, qtype varchar(10), dst_ns varchar(25),an_rdata varchar(25),an_type varchar(10),time_stamp timestamp, constraint fk_qname foreign key (qname) references watched(id) on update cascade on delete cascade)")

		print "[*] Creating Table latest_update"
		cur.execute("drop table if exists latest_update")
		cur.execute("create table latest_update(id int primary key auto_increment,  qname int, qtype varchar(10), dst_ns varchar(25),an_rdata varchar(25),an_type varchar(10),time_stamp timestamp, constraint fk_qname_latest foreign key (qname) references watched(id) on update cascade on delete cascade)")


		print "[*] Creating Table descrepencies
		cur.execute("drop table if exists descrepencies
		cur.execute("create table descrepencies(id int primary key auto_increment, qname int, dst_ns varchar(25), an_rdata varchar(50), an_type varchar(11),time_stamp timestamp, constraint fk_qname_diff foreign key (qname) references watched(id) on update cascade on delete cascade)")

except mysql.Error,e:
	print "Error %d: %s" % (e.args[0],e.args[1])
	sys.exit(1)
#finally:
#	if con:
	con.close()

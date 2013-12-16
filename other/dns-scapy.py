#!/usr/bin/python

from scapy.all import *
import sys
import os
import MySQLdb as mysql
import argparse

class initialize():
        def __init__(self):
	
		self.db_host = 'localhost'			#db host
		self.db_user = 'dnsservice'			#db username
		self.db_pass = 'dnsservice'			#db password
		self.db = 'dnsservice'					#db 					
                self.ip = IP()					# packet datalink layer 
                self.udp = UDP()				# packet UDP layer
                self.dnsqr = DNSQR()				# packet DNS Query
                self.dns = DNS(rd=1,qd=self.dnsqr)		# packet Session layer 
                self.type = ['A','NS']				# DNS query types
                conf.verb = 0	
                self.nameserver = ['8.8.4.4','8.8.8.8']	# name servers to query
                pass

	def sql_conn(self):

	# initiate connection to MySQL db
		try:
			self.conn = mysql.connect(self.db_host,self.db_user,self.db_pass,self.db)
		except mysql.Error,self.e:
			print "Error %d: %s" % (self.e.args[0],self.e.args[1])
		    	sys.exit(1)

	def sql_populate(self,b=None):

	# if baseline argument is set set table_name to 'baseline' else set table_name to 'latest_update'
		if b:
			self.table = 'baseline'
		else:
			self.table = 'latest_update'

	# set cursor we get the cursor object. The cursor is used to traverse the records from the result set.
		self.cur = self.conn.cursor()

	# we use %%s in table_name so MySQLdb doesn't insert quotes in table_name %% will let python skip the other variables from the first python format string
	# we check to see if there is a record for same server exist cursor.fetchone() returns None if no data is retrieved "data with same domain, name server, query Type"
		self.cur.execute("select * from %s where qname=(select id from watched where domain=%%s) and qtype=%%s and dst_ns=%%s" % self.table, (self.ans.qd.qname,self.ans.qd.qtype,self.ans.src))
		if self.cur.fetchone() == None:

		# if no data is retrieved by  cursor.fetchone()
		# insert new data in corresponding table
			self.cur.execute("insert into %s(qname,qtype,dst_ns,an_rdata,an_type) values((select id from watched where domain=%%s),%%s,%%s,%%s,%%s)" % self.table, (self.ans.qd.qname, self.ans.qd.qtype, self.ans.src, self.ans.an.rdata, self.ans.an.type))

			print "[*] Logged record to DB in table: %s" % self.table

		else:
		# if there is data with same domain, name server, query Type update the current records with the current time stamp utilizing time_stamp[col]=now()

			print "[*] Updating Old record in table: %s" % self.table

			self.cur.execute("update %s set qname=(select id from watched where domain=%%s), qtype=%%s, dst_ns=%%s, an_rdata=%%s, an_type=%%s, time_stamp=now() where qname=(select id from watched where domain=%%s) and qtype=%%s and dst_ns=%%s" % self.table, (self.ans.qd.qname, self.ans.qd.qtype, self.ans.src, self.ans.an.rdata, self.ans.an.type, self.ans.qd.qname,self.ans.qd.qtype, self.ans.src))
		
		# Commit changes to database
		self.conn.commit()

	def send_pkt(self,q1):
		
		self.q1 = q1
		# send packets with sr1() which will send and recieve answers but will discard unanswered packets
#		try:
		self.ans = sr1(self.q1)
		return self.ans

	def packet_magic(self,b=None):

		self.sql_conn()
		self.cur = self.conn.cursor()
                self.cur.execute("select domain from watched")
		# use cursor object as row iterator
		for self.query in self.cur:
			print "[*] Domain:%s" % self.query[0]
              		for self.ns in self.nameserver:
			# set packet destination to name server to query
        	        	self.ip.dst = self.ns

	               		for self.t in self.type:
	
					self.dnsqr.qtype = self.t
	                                self.dnsqr.qname = self.query[0]
					# generate packet layers 
	                                self.q1 = self.ip/self.udp/self.dns
	                                print "[*] Query: %s" % self.q1.summary()
        	                        self.ans = self.send_pkt(self.q1)
					if b:

						self.sql_populate(b)
					else:
	
						self.sql_populate()
	
		self.conn.close()
		self.cur.close()
		
	def add_domain(self,domain):
		
		self.domain = domain
		self.sql_conn()
		self.cur = self.conn.cursor()
		self.cur.execute("insert into watched (domain) values (%s)",self.domain)
		self.conn.commit()
		print "[*] Adding domain %s to table" % self.domain
		self.cur.close()
		self.conn.close()
	
	def checking(self):
	# Check if there were any changes between latest update and baseline		
		self.sql_conn()
		self.cur = self.conn.cursor()
		self.cur.execute("select qname, qtype, dst_ns, an_rdata, an_type from baseline")
		# use cursor as iterator
		for self.row in self.cur:
			self.qname, self.qtype, self.dst_ns, self.an_rdata, self.an_type = self.row
			self.cur.execute("select * from latest_update where qname=%s and qtype=%s and dst_ns=%s and an_rdata=%s and an_type=%s", self.row)
			# if rows are returned from the above query then the eact values from baseline were found in latest_update
			# if not then some DNS entry has changed

			if self.cur.fetchone() == None:
				print "[*] Error Error Error !!!"
				print self.row
			else:
				print "[*] Everything is dandy"



r = initialize()

parser = argparse.ArgumentParser(description = 'DNS records Check', epilog = 'Saif El-Sherei')
parser.add_argument('-b','--baseline',help = 'Add result to database baseline',action='store_true')
parser.add_argument('-d','--domain', help = ' Add domain to domains table')
parser.add_argument('-c','--check',help = 'Check for any discrepancies in databse',action='store_true')
p = parser.parse_args()

if not p.baseline and not p.domain and not p.check:
	
	r.packet_magic()

if p.baseline and not p.domain and not p.check:

	r.packet_magic(p.baseline)

if p.domain and not p.baseline:
	
	r.add_domain(p.domain)

if p.check and not p.baseline and not p.domain:
	
	r.checking()

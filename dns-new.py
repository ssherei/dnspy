#!/usr/bin/python

import DNS
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
	# set cursor we get the cursor object. The cursor is used to traverse the records from the result set.
			self.cur = self.conn.cursor()
		
	# we use %%s in table_name so MySQLdb doesn't insert quotes in table_name %% will let python skip the other variables from the first python format string
	# we check to see if there is a record for same server exist cursor.fetchone() returns None if no data is retrieved "data with same domain, name server, query Type"
	
			self.cur.execute("select * from %s where qname=(select id from watched where domain=%%s) and dst_ns=%%s" % self.table, (self.ans.args['name'], self.ans.args['server']))
			if self.cur.fetchone() == None:
				print "[*] New Entry"
				self.cur.execute("insert into %s(qname,dst_ns) values ((select id from watched where domain=%%s), %%s)" % self.table, (self.ans.args['name'],self.ans.args['server']))
	
			print "[*] Added new Name Server"
			#self.cur.execute("update %s set dst_ns = case when dst_ns is null then %%s else concat_ws(',',dst_ns,%%s) end, time_stamp = NOW()" % self.table, (self.ans.args['server'], self.ans.args['server']))
			self.conn.commit()
			for self.a in self.ans.answers:
				if self.a['typename'] == 'A':
					print "[*] Updating 'A' record in table: %s" % self.table
					self.cur.execute("update %s set A=case when A is null then %%s when A like %%s then %%s else concat_ws(',',A,%%s) end , time_stamp=now() where qname=(select id from watched where domain=%%s) and dst_ns=%%s" % self.table, (self.a['data'],"%"+self.a['data']+"%",self.a['data'],self.a['data'],self.ans.args['name'], self.ans.args['server']))

				elif self.a['typename'] == 'NS':
                	        	print "[*] Updating 'NS' record in table: %s" % self.table
                                        self.cur.execute("update %s set NS=case when NS is null then %%s when NS like %%s then %%s else concat_ws(',',NS,%%s) end , time_stamp=now() where qname=(select id from watched where domain=%%s) and dst_ns=%%s" % self.table, (self.a['data'],"%"+self.a['data']+"%",self.a['data'],self.a['data'],self.ans.args['name'], self.ans.args['server']))

				elif self.a['typename'] == 'MX':
                        		print "[*] Updating 'MX' record in table: %s" % self.table
	                                self.cur.execute("update %s set MX=case when MX is null then %%s when MX like %%s then %%s else concat_ws(',',MX,%%s) end , time_stamp=now() where qname=(select id from watched where domain=%%s) and dst_ns=%%s" % self.table, (self.a['data'][1],"%"+self.a['data'][1]+"%",self.a['data'][1],self.a['data'][1],self.ans.args['name'], self.ans.args['server']))
	
				elif self.a['typename'] == 'TXT':
					print "[*] Updating 'TXT' record in table: %s" % self.table
					self.cur.execute("update %s set TXT=case  when TXT is null then %%s when TXT like %%s then %%s else concat_ws(',',TXT,%%s) end , time_stamp=now() where qname=(select id from watched where domain=%%s) and dst_ns=%%s" % self.table, (str(self.a['data']),"%"+str(self.a['data'])+"%",str(self.a['data']),str(self.a['data']),self.ans.args['name'], self.ans.args['server']))	
			
				elif self.a['typename'] == 'SOA':
                                        print "[*] Updating 'SOA' record in table: %s" % self.table
                                        self.cur.execute("update %s set SOA=case  when SOA is null then %%s when SOA like %%s then %%s else concat_ws(',',SOA,%%s) end , time_stamp=now() where qname=(select id from watched where domain=%%s) and dst_ns=%%s" % self.table, (str(self.a['data']),"%"+str(self.a['data'])+"%",str(self.a['data']),str(self.a['data']),self.ans.args['name'], self.ans.args['server']))			
				else: 
					continue

		# Commit changes to database
				self.conn.commit()
		else:
			self.table = 'latest_update'
			self.cur = self.conn.cursor()
		
	# we use %%s in table_name so MySQLdb doesn't insert quotes in table_name %% will let python skip the other variables from the first python format string
	# we check to see if there is a record for same server exist cursor.fetchone() returns None if no data is retrieved "data with same domain, name server, query Type"
	
			self.cur.execute("insert into %s(qname,dst_ns) values ((select id from watched where domain=%%s), %%s)" % self.table, (self.ans.args['name'],self.ans.args['server']))
			self.conn.commit()
			self.cur.execute("select NOW()")
			self.ts = self.cur.fetchone()
			print self.ts[0]
			for self.a in self.ans.answers:
				if self.a['typename'] == 'A':
					print "[*] Updating 'A' record in table: %s" % self.table
					self.cur.execute("update %s set A=case when A is null then %%s else concat_ws(',',A,%%s) end , time_stamp=now() where qname=(select id from watched where domain=%%s) and dst_ns=%%s and time_stamp >= %%s" % self.table, (self.a['data'],self.a['data'],self.ans.args['name'], self.ans.args['server'],self.ts[0]))

				elif self.a['typename'] == 'NS':
                	        	print "[*] Updating 'NS' record in table: %s" % self.table
                	        	self.cur.execute("update %s set NS=case when NS is null then %%s else concat_ws(',',NS,%%s) end , time_stamp=now() where qname=(select id from watched where domain=%%s) and dst_ns=%%s and time_stamp >= %%s" % self.table, (self.a['data'],self.a['data'],self.ans.args['name'],self.ans.args['server'],self.ts[0]))

				elif self.a['typename'] == 'MX':
                        		print "[*] Updating 'MX' record in table: %s" % self.table
                        		self.cur.execute("update %s set MX=case when MX is null then %%s else concat(',',A,%%s) end , time_stamp=now() where qname=(select id from watched where domain=%%s) and dst_ns=%%s and time_stamp>=%%s" % self.table, (self.a['data'][1],self.a['data'][1],self.ans.args['name'],self.ans.args['server'],self.ts[0]))
				
				elif self.a['typename'] == 'TXT':
                                        print "[*] Updating 'TXT' record in table: %s" % self.table
                                        self.cur.execute("update %s set TXT=case when TXT is null then %%s when TXT like %%s then %%s else concat_ws(',',TXT,%%s) end , time_stamp=now() where qname=(select id from watched where domain=%%s) and dst_ns=%%s" % self.table, (str(self.a['data']),str(self.a['data']),str(self.a['data']),str(self.a['data']),self.ans.args['name'], self.ans.args['server']))				
				elif self.a['typename'] == 'SOA':
                                        print "[*] Updating 'SOA' record in table: %s" % self.table
                                        self.cur.execute("update %s set SOA=case  when SOA is null then %%s when SOA like %%s then %%s else concat_ws(',',SOA,%%s) end , time_stamp=now() where qname=(select id from watched where domain=%%s) and dst_ns=%%s" % self.table, (str(self.a['data']),"%"+str(self.a['data'])+"%",str(self.a['data']),str(self.a['data']),self.ans.args['name'], self.ans.args['server']))

				else: 
					continue

		# Commit changes to database
				self.conn.commit()


	def send_pkt(self,q1):
		
		self.q1 = q1
		self.ans = self.req.req()
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
        	        	self.req = DNS.DnsRequest(name = self.query[0], qtype = 'ANY', server = self.ns)
				print "[*] Query: %s" % self.req.args
        	                self.ans = self.send_pkt(self.req)
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
		self.cur.execute("select NOW()")
		self.tsc  = self.cur.fetchone()
		self.cur.execute("select qname, A, NS, MX, TXT, SOA, dst_ns from baseline")
		# use cursor as iterator
		for self.row in self.cur:
			self.qname, self.A, self.NS, self.MX, self.TXT, self.SOA, self.dst_ns = self.row
			self.bl_q = list(self.row)
			print self.bl_q
			self.bl_q = [self.i for self.col in self.row if type(self.col) is str for self.i in self.col.split(",")]
			print self.bl_q
			#self.cur.execute("select qname, A, NS, MX, TXT, SOA, dst_ns from latest_update where qname=%%s and dst_ns =%%s", (self.qname, self.dst_ns)
			#self.bl_query = self.cur.fetchone()
			
			# if rows are returned from the above query then the eact values from baseline were found in latest_update
			# if not then some DNS entry has changed

		self.conn.close()
		self.cur.close()

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

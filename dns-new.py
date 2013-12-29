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
	
			self.cur.execute("select * from %s where qname=(select id from watched where domain=%%s) and dst_ns=(select id from name_servers where name_server=%%s)" % self.table, (self.ans.args['name'], self.ans.args['server']))
			if self.cur.fetchone() == None:
				print "\r\n[*] New Entry\r\n"
				self.cur.execute("insert into %s(qname,dst_ns) values ((select id from watched where domain=%%s), (select id from name_servers where name_server=%%s))" % self.table, (self.ans.args['name'],self.ans.args['server']))
	
			print "\r\n[*] Added new Name Server\r\n"
			self.conn.commit()
			for self.a in self.ans.answers:
				if self.a['typename'] == 'A':
					print "[*] Updating 'A' record in table: %s" % self.table
					self.cur.execute("update %s set A=case when A is null then %%s when A like %%s then %%s else concat_ws(',',A,%%s) end , time_stamp=now() where qname=(select id from watched where domain=%%s) and dst_ns=(select id from name_servers where name_server=%%s)" % self.table, (self.a['data'],"%"+self.a['data']+"%",self.a['data'],self.a['data'],self.ans.args['name'], self.ans.args['server']))

				elif self.a['typename'] == 'NS':
                	        	print "[*] Updating 'NS' record in table: %s" % self.table
                                        self.cur.execute("update %s set NS=case when NS is null then %%s when NS like %%s then %%s else concat_ws(',',NS,%%s) end , time_stamp=now() where qname=(select id from watched where domain=%%s) and dst_ns=(select id from name_servers where name_server=%%s)" % self.table, (self.a['data'],"%"+self.a['data']+"%",self.a['data'],self.a['data'],self.ans.args['name'], self.ans.args['server']))

				elif self.a['typename'] == 'MX':
                        		print "[*] Updating 'MX' record in table: %s" % self.table
	                                self.cur.execute("update %s set MX=case when MX is null then %%s when MX like %%s then %%s else concat_ws(',',MX,%%s) end , time_stamp=now() where qname=(select id from watched where domain=%%s) and dst_ns=(select id from name_servers where name_server=%%s)" % self.table, (self.a['data'][1],"%"+self.a['data'][1]+"%",self.a['data'][1],self.a['data'][1],self.ans.args['name'], self.ans.args['server']))
	
				elif self.a['typename'] == 'TXT':
					print "[*] Updating 'TXT' record in table: %s" % self.table
					self.cur.execute("update %s set TXT=case  when TXT is null then %%s when TXT like %%s then %%s else concat_ws(',',TXT,%%s) end , time_stamp=now() where qname=(select id from watched where domain=%%s) and dst_ns=(select id from name_servers where name_server=%%s)" % self.table, (str(self.a['data']),"%"+str(self.a['data'])+"%",str(self.a['data']),str(self.a['data']),self.ans.args['name'], self.ans.args['server']))	
			
				elif self.a['typename'] == 'SOA':
                                        print "[*] Updating 'SOA' record in table: %s" % self.table
                                        self.cur.execute("update %s set SOA=case  when SOA is null then %%s when SOA like %%s then %%s else concat_ws(',',SOA,%%s) end , time_stamp=now() where qname=(select id from watched where domain=%%s) and dst_ns=(select id from name_servers where name_server=%%s)" % self.table, (str(self.a['data']),"%"+str(self.a['data'])+"%",str(self.a['data']),str(self.a['data']),self.ans.args['name'], self.ans.args['server']))			
				else: 
					continue

		# Commit changes to database
				self.conn.commit()
		else:
			self.table = 'latest_update'
			self.cur = self.conn.cursor()
		
	# we use %%s in table_name so MySQLdb doesn't insert quotes in table_name %% will let python skip the other variables from the first python format string
	# we check to see if there is a record for same server exist cursor.fetchone() returns None if no data is retrieved "data with same domain, name server, query Type"
	
			self.cur.execute("insert into %s(qname,dst_ns) values ((select id from watched where domain=%%s), (select id from name_servers where name_server=%%s))" % self.table, (self.ans.args['name'],self.ans.args['server']))
			self.conn.commit()
			for self.a in self.ans.answers:
				self.cur.execute("select MAX(time_stamp) from %s where qname=(select id from watched where domain=%%s) and dst_ns=(select id from name_servers where name_server=%%s)" % self.table, (self.ans.args['name'],self.ans.args['server']))
				self.ts = self.cur.fetchone()
				if self.a['typename'] == 'A':
					print "[*] Updating 'A' record in table: %s" % self.table
					self.cur.execute("update %s set A=case when A is null then %%s else concat_ws(',',A,%%s) end where qname=(select id from watched where domain=%%s) and dst_ns=(select id from name_servers where name_server=%%s) and time_stamp =%%s" % self.table, (self.a['data'],self.a['data'],self.ans.args['name'], self.ans.args['server'],self.ts[0]))

				elif self.a['typename'] == 'NS':
                	        	print "[*] Updating 'NS' record in table: %s" % self.table
                	        	self.cur.execute("update %s set NS=case when NS is null then %%s else concat_ws(',',NS,%%s) end where qname=(select id from watched where domain=%%s) and dst_ns=(select id from name_servers where name_server=%%s) and time_stamp = %%s" % self.table, (self.a['data'],self.a['data'],self.ans.args['name'],self.ans.args['server'],self.ts[0]))

				elif self.a['typename'] == 'MX':
                        		print "[*] Updating 'MX' record in table: %s" % self.table
                        		self.cur.execute("update %s set MX=case when MX is null then %%s else concat(',',A,%%s) end where qname=(select id from watched where domain=%%s) and dst_ns=(select id from name_servers where name_server=%%s) and time_stamp=%%s" % self.table, (self.a['data'][1],self.a['data'][1],self.ans.args['name'],self.ans.args['server'],self.ts[0]))
				
				elif self.a['typename'] == 'TXT':
                                        print "[*] Updating 'TXT' record in table: %s" % self.table
                                        self.cur.execute("update %s set TXT=case when TXT is null then %%s when TXT like %%s then %%s else concat_ws(',',TXT,%%s) end where qname=(select id from watched where domain=%%s) and dst_ns=(select id from name_servers where name_server=%%s) and time_stamp=%%s" % self.table, (str(self.a['data']),str(self.a['data']),str(self.a['data']),str(self.a['data']),self.ans.args['name'], self.ans.args['server'],self.ts[0]))				
				elif self.a['typename'] == 'SOA':
                                        print "[*] Updating 'SOA' record in table: %s" % self.table
                                        self.cur.execute("update %s set SOA=case  when SOA is null then %%s when SOA like %%s then %%s else concat_ws(',',SOA,%%s) end  where qname=(select id from watched where domain=%%s) and dst_ns=(select id from name_servers where name_server=%%s) and time_stamp=%%s" % self.table, (str(self.a['data']),"%"+str(self.a['data'])+"%",str(self.a['data']),str(self.a['data']),self.ans.args['name'], self.ans.args['server'],self.ts[0]))
				
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
			print "[*] Domain:%s\r\n" % self.query[0]
			self.cur2 = self.conn.cursor()
			self.cur2.execute("select name_server from name_servers")
              		for self.ns in self.cur2:
			# set packet destination to name server to query
        	        	self.req = DNS.DnsRequest(name = self.query[0], qtype = 'ANY', server = self.ns[0])
				print "[*] Query: %s\r\n" % self.req.args
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
		print "[*] Adding domain %s to table\r\n" % self.domain
		self.cur.close()
		self.conn.close()

	def add_name_server(self,nameserver):
		self.nameserver = nameserver
		self.sql_conn()
		self.cur = self.conn.cursor()
		self.cur.execute("insert into name_servers (name_server) values (%s)",self.nameserver)
		self.conn.commit()
		print "[*] Adding Name Server %s to table\r\n" % self.nameserver
		self.cur.close()
		self.conn.close()

	def reccmp(self,rec1,rec2):
		
		self.rec1 = rec1.split(",")
		self.rec2 = rec2.split(",")
		for self.rec in self.rec2:
			if self.rec not in self.rec1:
				print "---------Differnet Entry: %s------Domain: %s-------Name Server: %s" % (self.rec, str(self.qname), self.dst_ns)
				return False
		return True
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
			self.cur.execute("select max(time_stamp) from latest_update where qname=%s and dst_ns=%s", (self.qname,self.dst_ns))
			self.tsc = self.cur.fetchone()
        	        self.cur.execute("select qname, A, NS, MX, TXT, SOA, dst_ns from latest_update where qname=%s and dst_ns=%s and time_stamp=%s", (self.qname,self.dst_ns,self.tsc[0]))
			for self.row_latest in self.cur:
				self.qname_latest, self.A_latest, self.NS_latest, self.MX_latest, self.TXT_latest, self.SOA_latest, self.dst_ns_latest = self.row_latest		
		
				if self.reccmp(self.A,self.A_latest) and\
				   self.reccmp(self.NS,self.NS_latest) and\
				   self.reccmp(self.MX, self.MX_latest) and\
				   self.reccmp(self.TXT,self.TXT_latest) and\
				   self.reccmp(self.SOA,self.SOA_latest): 				

					print "--------Domain: %s----------NameServer: %s----------\r\n" % (self.qname_latest, self.dst_ns_latest)
					print "[*] Server Address is in baseline: %s" % self.A_latest
					print "[*] Name Servers Match Baseline: %s" % self.NS_latest
					print "[*] MX Records Match Baseline: %s" % self.MX_latest
					print "[*] TXT Records Match Baseline: %s" % self.TXT_latest
					print "[*] SOA Record Match Baseline: %s" % self.SOA_latest
					print "[*] Time Stamp: %s\r\n\r\n" % str(self.tsc[0])
				else:
					print """
EEEEEEEEEEEEEEEEEEEEEE                                                                             
E::::::::::::::::::::E                                                                             
E::::::::::::::::::::E                                                                             
EE::::::EEEEEEEEE::::E                                                                             
  E:::::E       EEEEEErrrrr   rrrrrrrrr   rrrrr   rrrrrrrrr      ooooooooooo   rrrrr   rrrrrrrrr   
  E:::::E             r::::rrr:::::::::r  r::::rrr:::::::::r   oo:::::::::::oo r::::rrr:::::::::r  
  E::::::EEEEEEEEEE   r:::::::::::::::::r r:::::::::::::::::r o:::::::::::::::or:::::::::::::::::r 
  E:::::::::::::::E   rr::::::rrrrr::::::rrr::::::rrrrr::::::ro:::::ooooo:::::orr::::::rrrrr::::::r
  E:::::::::::::::E    r:::::r     r:::::r r:::::r     r:::::ro::::o     o::::o r:::::r     r:::::r
  E::::::EEEEEEEEEE    r:::::r     rrrrrrr r:::::r     rrrrrrro::::o     o::::o r:::::r     rrrrrrr
  E:::::E              r:::::r             r:::::r            o::::o     o::::o r:::::r            
  E:::::E       EEEEEE r:::::r             r:::::r            o::::o     o::::o r:::::r            
EE::::::EEEEEEEE:::::E r:::::r             r:::::r            o:::::ooooo:::::o r:::::r            
E::::::::::::::::::::E r:::::r             r:::::r            o:::::::::::::::o r:::::r            
E::::::::::::::::::::E r:::::r             r:::::r             oo:::::::::::oo  r:::::r            
EEEEEEEEEEEEEEEEEEEEEE rrrrrrr             rrrrrrr               ooooooooooo    rrrrrrr     \r\n\r\n\r\n"""
					print "[*] Error Matching Record to Baseline"
					print "[*] Latest Record: A %s Baseline: A %s" % (str(self.A_latest), str(self.A))
					print "[*] Latest Record: NS %s Baseline: NS %s" % (str(self.NS_latest), str(self.NS))
					print "[*] Latest Record: MX %s Baseline: MX %s" % (str(self.MX_latest), str(self.MX))
					print "[*] Latest Record: TXT %s Baseline: TXT %s" % (str(self.TXT_latest), str(self.TXT))
					print "[*] Latest Record: SOA %s baseline: SOA %s" % (str(self.SOA_latest), str(self.SOA))
					print "[*] Time_stamp: %s\r\n\r\n" % str(self.tsc[0])

		self.conn.close()
		self.cur.close()

r = initialize()

parser = argparse.ArgumentParser(description = 'DNS records Check', epilog = 'Saif El-Sherei')
parser.add_argument('-b','--baseline',help = 'Add result to database baseline',action='store_true')
parser.add_argument('-d','--domain', help = ' Add domain to domains table')
parser.add_argument('-n','--ns', help = ' Add Name Server to table')
parser.add_argument('-c','--check',help = 'Check for any discrepancies in databse',action='store_true')
p = parser.parse_args()

if not p.baseline and not p.domain and not p.check and not p.ns:
	
	r.packet_magic()

if p.baseline and not p.domain and not p.check and not p.ns:

	r.packet_magic(p.baseline)

if p.domain and not p.baseline and not p.check and not p.ns:
	
	r.add_domain(p.domain)

if p.ns and not p.baseline and not p.check and not p.domain:

	r.add_name_server(p.ns)

if p.check and not p.baseline and not p.domain and not p.ns:
	
	r.checking()

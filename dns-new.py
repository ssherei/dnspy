#!/usr/bin/python

import DNS
import sys
import os
import MySQLdb as mysql
import argparse
import smtplib
import email.utils
from email.mime.text import MIMEText
import time


class initialize():
        def __init__(self):
		
		self.db_host = 'localhost'			#db host
		self.db_user = 'dnsservice'			#db username
		self.db_pass = 'dnsservice'			#db password
		self.db = 'dnsservice'					#db 					
               # sys.stdout = open('/var/log/dns-mon.log','a')
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
			self.cur.close()
		else:
			self.table = 'latest_update'
			self.cur2 = self.conn.cursor()
		
	# we use %%s in table_name so MySQLdb doesn't insert quotes in table_name %% will let python skip the other variables from the first python format string
	# we check to see if there is a record for same server exist cursor.fetchone() returns None if no data is retrieved "data with same domain, name server, query Type"
	
			self.cur2.execute("insert into %s(qname,dst_ns) values ((select id from watched where domain=%%s), (select id from name_servers where name_server=%%s))" % self.table, (self.ans.args['name'],self.ans.args['server']))
			self.conn.commit()
			for self.a in self.ans.answers:
				self.cur2.execute("select MAX(time_stamp) from %s where qname=(select id from watched where domain=%%s) and dst_ns=(select id from name_servers where name_server=%%s)" % self.table, (self.ans.args['name'],self.ans.args['server']))
				self.ts = self.cur2.fetchone()
				if self.a['typename'] == 'A':
					print "[*] Updating 'A' record in table: %s" % self.table
					self.cur2.execute("update %s set A=case when A is null then %%s when A like %%s then %%s else concat_ws(',',A,%%s) end where qname=(select id from watched where domain=%%s) and dst_ns=(select id from name_servers where name_server=%%s) and time_stamp =%%s" % self.table, (self.a['data'],"%"+self.a['data']+"%",self.a['data'],self.a['data'],self.ans.args['name'], self.ans.args['server'],self.ts[0]))

				elif self.a['typename'] == 'NS':
                	        	print "[*] Updating 'NS' record in table: %s" % self.table
                	        	self.cur2.execute("update %s set NS=case when NS is null then %%s when NS like %%s then %%s else concat_ws(',',NS,%%s) end where qname=(select id from watched where domain=%%s) and dst_ns=(select id from name_servers where name_server=%%s) and time_stamp = %%s" % self.table, (self.a['data'],"%"+self.a['data']+"%",self.a['data'],self.a['data'],self.ans.args['name'],self.ans.args['server'],self.ts[0]))

				elif self.a['typename'] == 'MX':
                        		print "[*] Updating 'MX' record in table: %s" % self.table
                        		self.cur2.execute("update %s set MX=case when MX is null then %%s when MX like %%s then %%s else concat_ws(',',MX,%%s) end where qname=(select id from watched where domain=%%s) and dst_ns=(select id from name_servers where name_server=%%s) and time_stamp=%%s" % self.table, (self.a['data'][1],"%"+self.a['data'][1]+"%",self.a['data'][1],self.a['data'][1],self.ans.args['name'],self.ans.args['server'],self.ts[0]))
				
				elif self.a['typename'] == 'TXT':
                                        print "[*] Updating 'TXT' record in table: %s" % self.table
                                        self.cur2.execute("update %s set TXT=case when TXT is null then %%s when TXT like %%s then %%s else concat_ws(',',TXT,%%s) end where qname=(select id from watched where domain=%%s) and dst_ns=(select id from name_servers where name_server=%%s) and time_stamp=%%s" % self.table, (str(self.a['data']),str(self.a['data']),str(self.a['data']),str(self.a['data']),self.ans.args['name'], self.ans.args['server'],self.ts[0]))				
				elif self.a['typename'] == 'SOA':
                                        print "[*] Updating 'SOA' record in table: %s" % self.table
                                        self.cur2.execute("update %s set SOA=case  when SOA is null then %%s when SOA like %%s then %%s else concat_ws(',',SOA,%%s) end  where qname=(select id from watched where domain=%%s) and dst_ns=(select id from name_servers where name_server=%%s) and time_stamp=%%s" % self.table, (str(self.a['data']),"%"+str(self.a['data'])+"%",str(self.a['data']),str(self.a['data']),self.ans.args['name'], self.ans.args['server'],self.ts[0]))
				
				else: 
					continue

		# Commit changes to database
				self.conn.commit()
			self.cur2.close()

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
				self.req = DNS.DnsRequest(name = self.query[0], qtype = DNS.Type.ANY, server = self.ns[0])
				print "[*] Query: %s\r\n" % self.req.args
				#time.sleep(1)
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
		
	def add_email(self,email):

		self.email = email
		self.sql_conn()
		self.cur = self.conn.cursor()
		self.cur.execute("insert into emails (email) values (%s)", self.email)
		self.conn.commit()
		print "[*] Adding Email %s to table\r\n" % self.email
		self.cur.close()
		self.conn.close()

	def reccmp(self,rec1=None,rec2=None):
		
		self.rec1 = rec1
		self.rec2 = rec2
		if self.rec1 and self.rec2:
			self.rec1 = self.rec1.split(",")
			#if "," in self.rec2:
			self.rec2 = self.rec2.split(",")
		elif not self.rec1 and not self.rec2:
			return True
		elif not self.rec1 and self.rec2:
			self.rec = None
			return False
		elif not self.rec2 and self.rec1:
			self.rec = None
			return False
		for self.rec in self.rec2:
			if self.rec not in self.rec1:
				return False
		return True
		
	def send_email(self,msg):
		
		self.msg = MIMEText(msg)
		self.sql_conn()
		self.cur = self.conn.cursor()
		self.to = []
		self.cur.execute("select email from emails")
		self.emails = self.cur.fetchall()
		for self.mail in self.emails:
			self.to.append(self.mail[0])
		self.from_email = 'dns-mon@alert-moi.com' 
		self.msg['subject'] = 'ISC DNS monitor Alert' 
		self.server = smtplib.SMTP('localhost',25)
		#self.server.set_debuglevel(True)
		self.server.starttls()
		self.server.sendmail(self.from_email,self.to,self.msg.as_string())
		self.server.quit()

	def checking(self):
	# Check if there were any changes between latest update and baseline		
		self.sql_conn()
		self.cur = self.conn.cursor()
		self.cur2 = self.conn.cursor()
		self.cur3 = self.conn.cursor()
	#	self.cur.execute("select NOW()")
	#	self.tsc  = self.cur.fetchone()
		self.cur.execute("select qname, A, NS, MX, TXT, SOA, dst_ns from baseline")
		# use cursor as iterator
		for self.row in self.cur:
			self.qname, self.A, self.NS, self.MX, self.TXT, self.SOA, self.dst_ns = self.row
			self.cur2.execute("select max(time_stamp) from latest_update where qname=%s and dst_ns=%s", (self.qname,self.dst_ns))
			self.tsc = self.cur2.fetchone()
        		self.cur2.execute("select qname, A, NS, MX, TXT, SOA, dst_ns from latest_update where qname=%s and dst_ns=%s and time_stamp=%s", (self.qname,self.dst_ns,self.tsc[0]))
			self.row_latest = self.cur2.fetchone()
			#for self.row_latest in self.cur2:
			self.qname_latest, self.A_latest, self.NS_latest, self.MX_latest, self.TXT_latest, self.SOA_latest, self.dst_ns_latest = self.row_latest		
			self.diff = False
			print "--------Domain: %s----------NameServer: %s----------\r\n" % (self.qname_latest, self.dst_ns_latest)
			if not self.reccmp(self.A,self.A_latest):

				self.diff = True
				self.dtype = 'A'
				self.diff_rec = self.rec
				print "[*] A record different than Baseline: %s" % self.rec 

			elif not self.reccmp(self.NS,self.NS_latest):

				self.diff =  True
				self.dtype = 'NS'
				self.diff_rec = self.rec
				print "[*] NS record different than Baseline: %s" % self.rec

			elif not self.reccmp(self.MX, self.MX_latest) :
		
				self.diff = True
				self.dtype = 'MX'
				self.diff_rec = self.rec
				print "[*] MX record different than Baseline: %s" % self.rec			
					
			elif not self.reccmp(self.TXT,self.TXT_latest):
			
				self.diff = True
				self.dtype = 'TXT'
				self.diff_rec = self.rec
				print "[*] TXT record different than Baseline: %s" % self.rec	

			elif not self.reccmp(self.SOA,self.SOA_latest): 				

				self.diff = True
				self.dtype = 'SOA'
				self.diff_rec = self.rec
				print "[*] SOA record different than Baseline: %s" % self.rec
				

			else:
				print "[*] Server Address is in baseline: %s" % self.A_latest
				print "[*] Name Servers Match Baseline: %s" % self.NS_latest
				print "[*] MX Records Match Baseline: %s" % self.MX_latest
				print "[*] TXT Records Match Baseline: %s" % self.TXT_latest
				print "[*] SOA Record Match Baseline: %s" % self.SOA_latest
				print "[*] Time Stamp: %s\r\n\r\n" % str(self.tsc[0])


			if self.diff:

				self.msg = """
---------Differnet Entry: %s------Domain: %s-------Name Server: %s 
[*] Error Matching Record to Baseline
[*] Latest Record: A %s Baseline: A %s
[*] Latest Record: NS %s Baseline: NS %s
[*] Latest Record: MX %s Baseline: MX %s
[*] Latest Record: TXT %s Baseline: TXT %s
[*] Latest Record: SOA %s baseline: SOA %s
[*] Time_stamp: %s\r\n\r\n """ % (self.diff_rec, str(self.qname), self.dst_ns, str(self.A_latest), str(self.A), str(self.NS_latest), str(self.NS), str(self.MX_latest), str(self.MX), str(self.TXT_latest), str(self.TXT), str(self.SOA_latest), str(self.SOA), str(self.tsc[0]))
				#print self.msg
				
				self.done = False
				self.cur3.execute("select %s,dst_ns from latest_update where qname=%%s and dst_ns=%%s and time_stamp != %%s" % str(self.dtype), (self.qname,self.dst_ns,self.tsc[0]))
				for self.r in self.cur3:
					self.check,self.hck = self.r
					# if this difference was alerted before this means that its valid insert into baseline (hack)
					if self.reccmp(self.check,self.diff_rec):
						self.done = True						

				if self.done:	

					self.cur3.execute("insert into validate (qname, dst_ns, diff_type, diff_rec) values (%s,%s,%s,%s)", (self.qname_latest, self.dst_ns_latest, self.dtype, self.diff_rec))
					#self.cur3.execute("update baseline set %s=case when %s is null then %%s when %s like %%s then %%s else concat_ws(',',%s,%%s) end,time_stamp=now() where qname=%%s and dst_ns=%%s" % (self.dtype, self.dtype, self.dtype, self.dtype), (self.diff_rec, self.diff_rec, self.diff_rec, self.diff_rec, self.qname_latest, self.dst_ns_latest))
					self.conn.commit()
					print "[*] Differene already alerted Adding New %s Record to validation table: %s" % (self.dtype,self.diff_rec)

				else:								

					print "Aleeeeeeeeeeeeeeeeeeeeeert!!!!!"		
					print self.msg
					#self.send_email(self.msg)
	
		self.conn.close()
		self.cur.close()
		self.cur2.close()
		self.cur3.close()

	def validate(self,d=None):
	
		self.answer = False
		self.sql_conn()
		self.cur = self.conn.cursor()
	
		if d:
			self.d = d
			self.cur.execute("select id,qname,dst_ns, diff_type, diff_rec from validate where qname = (select id from watched where domain = %s)", self.d)
			print "[*] Gathering Entries that need validation from database for domain: %s" % self.d
		else:
			self.cur.execute("select id,qname,dst_ns,diff_type,diff_rec from validate")
			print "[*] Gathering Entries that need validation for all domains"
	
		if not self.cur.fetchone():
			print "[*] No Entries Found for specified domain"
		else:
			for self.r in self.cur:
		
			#if self.cur.fetchone():
			#	print "[*] No Entries Found for specified domain"
			#else:
					
				self.id_v,self.qname_v,self.dst_ns_v, self.dtype_v, self.diff_rec_v = self.r
				self.cur.execute("select domain from watched where id = %s", self.qname_v)
				self.d = self.cur.fetchone()[0]
				print "[*] Entry for domain %s Different Record %s for Type %s" % (self.d, self.diff_rec_v, self.dtype_v)
				print "[*] please enter choice [Y]Yes, [N]No"
				self.question = raw_input("Validate Entry?  ")
				while not self.answer:
					if self.question == 'Y':
							
						self.cur.execute("update baseline set %s=case when %s is null then %%s when %s like %%s then %%s else concat_ws(',',%s,%%s) end,time_stamp=now() where qname=%%s and dst_ns=%%s" % (self.dtype_v, self.dtype_v, self.dtype_v, self.dtype_v), (self.diff_rec_v, self.diff_rec_v, self.diff_rec_v, self.diff_rec_v, self.qname_v, self.dst_ns_v))
				
						self.cur.execute("delete from validate where id = %s", self.id_v)
						print "[*] Malicious Entry Validated"
						print "[*] New Entry Added to Baseline."	
						self.answer = True

					elif self.question == 'N':
						self.cur.execute("insert into alert_history(qname,dst_ns,diff_type,diff_rec) values (%s,%s,%s,%s)", (self.d, self.dst_ns_v, self.dtype_v, self.diff_rec_v))
						self.cur.execute("delete from validate where id  = %s", self.id_v)
						self.answer = True
						self.msg_v = """
Maliciouss entry found after validation for:
[*] Domain: %s
[*] DNS Server: %s
[*] Query Type: %s
[*] Malicious Entry: %s""" % (self.d, self.dst_ns_v, self.dtype_v, self.diff_rec_v)
						print self.msg_v
						#self.send_email(self.msg)
					else:
						print "[*] Invalid Choicei,Try again"
			
					self.conn.commit()
					self.cur.close()

r = initialize()

parser = argparse.ArgumentParser(description = 'DNS records Check', epilog = 'Saif El-Sherei')
parser.add_argument('-b','--baseline',help = 'Add result to database baseline',action='store_true')
parser.add_argument('-d','--domain', help = ' Add domain to domains table')
parser.add_argument('-n','--ns', help = ' Add Name Server to table')
parser.add_argument('-c','--check',help = 'Check for any discrepancies in databse',action='store_true')
parser.add_argument('-e','--email',help = 'Add Email to table')
parser.add_argument('-v','--validate',help = 'Manual validation of diff records', nargs='?', default = None, const = 'all')
p = parser.parse_args()

if not p.baseline and not p.domain and not p.check and not p.ns and not p.email and not p.validate:
	
	r.packet_magic()
#	r.checking()

if p.baseline and not p.domain and not p.check and not p.ns and not p.email and not p.validate:

	r.packet_magic(p.baseline)

if p.domain and not p.baseline and not p.check and not p.ns and not p.email and not p.validate:
	
	r.add_domain(p.domain)
	r.packet_magic(True)

if p.ns and not p.baseline and not p.check and not p.domain and not p.email and not p.validate:

	r.add_name_server(p.ns)
	r.packet_magic(True)

if p.check and not p.baseline and not p.domain and not p.ns and not p.email and not p.validate:
	
	r.checking()

if p.email and not p.baseline and not p.check and not p.domain and not p.ns and not p.validate:
	
	r.add_email(p.email)

if p.validate and not  p.baseline and not p.domain and not p.check and not p.ns and not p.email:

	if p.validate == 'all':
		r.validate()
	else:
		r.validate(p.validate)

'''
Registration/Login Form

Things to do:
	1) Send email verification
    2) Pass to main GUI App
	6) Test against brute force
'''

from Tkinter import *
from tkMessageBox import *
import mysql.connector
from mysql.connector import MySQLConnection, Error
import bcrypt
import re
from django.core.mail import send_mail
#from configuratons import Configuration

#class Dev(Configuration):
#	DEBUG = True

class Login:
	def __init__(self, root):
		fields = ["Last Name", "First Name", "Email", "UserName", "Password", \
			"Confirm Password"]
		
		self.root = root
		root.title("Register")
		
		ents = self.makeform(root, fields)

	def makeform(self, root, fields):
		count = 0
		entries = []
		for field in fields:
			row = Frame(root)
			lab = Label(row, width=20, text=field, anchor=W)

			if (fields[count] == "Password") or (fields[count] == "Confirm Password"):
				ent = Entry(row, show="*")
			else:
				ent = Entry(row)

			row.pack(side=TOP, fill=X, padx=5, pady=5)
			lab.pack(side=LEFT)
			ent.pack(side=RIGHT, expand=YES, fill=X)
			entries.append((field,ent))
			count += 1 

		b1 = Button(root, text="Register", \
			command=lambda: self.status(entries, root))
		b1.pack(side=LEFT, padx=(75,5), pady=5)
		b2 = Button(root, text="Quit", command=root.quit)
		b2.pack(side=RIGHT, padx=(5,75), pady=5)
		root.maxsize(350, 250)
		root.minsize(350, 250)

		return entries

	def entFill(self, entries):
		count = 0
		for ents in entries:
			if len(ents[1].get()) != 0:
				count += 1
			else:
				return -1

		if count == len(entries):
			return 0

	def uniqueCheck(self, entries):
		query1 = "SELECT userName from reg"
		query2 = "SELECT email from reg"
		usernames = []
		emails = []

		try:
			conn = mysql.connector.connect(host='test', database='Login',\
				user='root', password='password123') 	#  add hostname and password here
			
			cursor = conn.cursor()
			cursor.execute("SELECT userName from reg")
			usernames = cursor.fetchall()
			usernames = [row[0] for row in usernames]
			cursor.execute("SELECT email from reg")
			emails = cursor.fetchall()
			emails = [row[0] for row in emails]

		except Error as error:
			print(error)

		finally:
			cursor.close()
			conn.close()

		if (entries[3][1].get() in usernames) and (entries[2][1].get() in emails):
			return -1

		if entries[3][1].get() in usernames:
			return -2

		if entries[2][1].get() in emails:
			return -3

		return 0

	def emailVer(self, entries):
		#settings.configure()
		verify = entries[2][1].get()
		match = re.match('^[_a-z0-9-]+(\.[_a-z0-9-]+)*@[a-z0-9-]+(\.[a-z0-9-]+)*(\.[a-z]{2,4})$', \
			verify)

		if not match:
			return -1;

		#send_mail('Account Confirmation', 'Please click on the link to verify your email address: '\
		#	, 'avelieu@gmail.com', [verify], fail_silently=False)

		return 0

	def status(self, entries, root): #clean up code, condense if conditions
		complete = self.entFill(entries)
		topStatus = Toplevel()
		unique = self.uniqueCheck(entries) 
		lengths = [entries[3][1].get(), entries[4][1].get()]
		email = self.emailVer(entries)

		if (complete == 0) and (entries[4][1].get() == entries[5][1].get())\
		and (unique == 0) and (6 <= len(lengths[0]) <= 30) and (8 <= len(lengths[1]) <= 30)\
		and (re.match("^[A-Za-z0-9_-]*", lengths[1])):
			topStatus.title("Registration Success")
			self.insertDD(entries)
			regMsg = Label(topStatus, text="Congratulations! You are" \
				" registered.")
			regMsg.pack(fill=BOTH, pady=(10,15))
			enterApp = Button(topStatus, text="Enter", command=root.quit)
			enterApp.pack()
			topStatus.maxsize(250,100)
			topStatus.minsize(250,100)
			root.withdraw()
		elif (complete == 0):
			topStatus.title("Registration Error")
			if (unique == -1):
				regMsg = Label(topStatus, text="Username and email must unique.")
			elif (unique == -2):
				regMsg = Label(topStatus, text="Username already exists.")
			elif (unique == -3):
				regMsg = Label(topStatus, text="Email address already registered.")
			elif (len(lengths[0]) < 6) or (len(lengths[0]) > 30):
				regMsg = Label(topStatus, text="Username must be between 6-30 characters.")
			elif ((len(lengths[1]) < 8) or (len(lengths[0]) > 30)):
				regMsg = Label(topStatus, text="Password must be between 8-30 characters.")
			elif (not (re.match("^[A-Za-z0-9_-]*", lengths[1]))):
				regMsg = Label(topStatus, text="Password must contain numbers and symbols.")
			elif (entries[4][1].get() != entries[5][1].get()):
				regMsg = Label(topStatus, text="Passwords must match.")
			regMsg.pack(fill=BOTH, pady=(15,15))
			endBut = Button(topStatus, text="Ok", command=topStatus.destroy)
			endBut.pack()
			topStatus.maxsize(300,95)
			topStatus.minsize(300,95)
		else:
			topStatus.title("Registration Error")
			regMsg = Label(topStatus, text="Required data fields empty." \
				" Please \ncomplete to continue.")
			regMsg.pack(fill=BOTH, pady=(10,15))
			endBut = Button(topStatus, text="Ok", anchor=S, \
				command=topStatus.destroy)
			endBut.pack()
			topStatus.maxsize(250,100)
			topStatus.minsize(250,100)

	def insertDD(self, entries):
		query = "INSERT INTO reg(lastName,firstName,userName,email,password) "\
			"VALUES(%s,%s,%s,%s,%s)"

		password = entries[4][1].get()
		hashed = bcrypt.hashpw(password, bcrypt.gensalt(12))
		args = (entries[0][1].get(), entries[1][1].get(), entries[3][1].get(), \
			entries[2][1].get(), hashed)

		try:
			conn = mysql.connector.connect(host='test', database='Login',\
				user='root', password='password123')	#  add hostname and password here 
			
			cursor = conn.cursor()
			cursor.execute(query, args)

			if cursor.lastrowid:
				print('last insert id', cursor.lastrowid)
			else:
				print('last insert id not found')

			conn.commit()

		except Error as error:
			print(error)

		finally:
			cursor.close()
			conn.close()

root = Tk()
test1 = Login(root)
root.mainloop()
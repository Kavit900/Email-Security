import string
import random
import sys
import os
import urllib2
import csv
import urllib
from urllib2 import urlopen
import subprocess
from subprocess import Popen,PIPE

def session_key_generator(size=32, chars=string.ascii_uppercase + string.ascii_lowercase +string.digits):
	return ''.join(random.choice(chars) for _ in range(size))

def send_mail1():
	flag=1
	set=0
	found=0
	valid=0
	begin_msg="-----BEGIN CSC574 MESSAGE-----"
	end_msg="-----END CSC574 MESSAGE-----"
	#Initial database fetch
	if(os.path.isfile("databasefile.txt")):
		flag=1
	else:
		f=open("databasefile.txt","wb")
		flag=0
		f.close()
	print "Receiver Email is:"
	rec_email=raw_input()
	rec_id=rec_email.split("@")[0]
	rec_cert=rec_id+".pem"
	#if database is null fetch from site
	if(flag==0):
		url = 'https://courses.ncsu.edu/csc574/lec/001/CertificateRepo'
		response = urllib2.urlopen(url)
		cr = csv.reader(response)
		for row in cr:
			if row[0]==rec_id:
				dest_cert = urllib.URLopener()
	                        dest_cert.retrieve(row[1],rec_cert)
				found=1
				break
		if(found==0 and flag==0):
				 print "File not found in webpage and local cache"
	                	 return	
		f=open("databasefile.txt","r+b")
		f.write(rec_cert)
		f.write("\n")
		f.close()
	#database exists check for certificate
	else:
		f=open("databasefile.txt","r+b")
		for line in f:
			if(rec_cert==line[:-1]):
				set=1
				break
		#database exists but receiver public key not in database
		if(set==0):
			url = 'https://courses.ncsu.edu/csc574/lec/001/CertificateRepo'
			response = urllib2.urlopen(url)
			cr = csv.reader(response)
			for row in cr:
				if row[0]==rec_id:
					dest_cert = urllib.URLopener()
	                	        dest_cert.retrieve(row[1],rec_cert)
					found=1
					break
			if(found==0 and set==0):
				 print "File not found in webpage and local cache"
	                	 return	
			f=open("databasefile.txt","r+b")
			f.seek(0, 2)
			f.write(rec_cert)
			f.write("\n")
			f.close()

#Verifying Receiver certificate
	try:
		output=subprocess.check_output(["openssl","verify","-CAfile","root-ca.crt",rec_cert])
	except subprocess.CalledProcessError,e:
		l=e.output
		if(l!=' '):
			print "Certificate not valid"
			return
	
#Generate session password	
	random_value=''.join(random.SystemRandom().choice(string.ascii_uppercase +string.ascii_lowercase + string.digits) for _ in range(32))
	f = open('session_password.txt', 'wb')
	f.write(random_value)
	f.close()

#Get the receiver public key from certificate
	try:
		receiver_publickey=subprocess.check_output(["openssl","x509","-in",rec_cert,"-pubkey","-noout"])
		#print receiver_publickey
		f=open("receiver_pubkey.pem","wb")
		f.write(receiver_publickey)
		f.close()
	except subprocess.CalledProcessError,e:
		l=e.output
		#print l

#Encrypt session password with receiver public key
	try:
		#subprocess.check_output(["openssl","enc","-aes-256-cbc","-base64","-in","session_password.txt","-k",receiver_publickey,"-out","sessnpass_encry.txt"])
		subprocess.check_output(["openssl","rsautl","-encrypt","-inkey","receiver_pubkey.pem","-pubin","-in","session_password.txt","-out","sessnpass_encry.txt"])
	except subprocess.CalledProcessError,  e:
		l=e.output
	print "Enter Message:"
	sender_message=raw_input()
	f=open('send_message.txt', 'wb')
	f.write(sender_message)
	f.close()
#Encrypt message with session password
	try:
		subprocess.check_output(["openssl","enc","-aes-256-cbc","-base64","-in","send_message.txt","-k",random_value,"-out","encrypted_message.txt"])
	except subprocess.CalledProcessError,  e:
		l=e.output


#Test code for decryption
#try:
#	subprocess.check_output(["openssl","enc","-d","-aes-256-cbc","-base64","-a","-in","encrypted_message.txt","-k",random_value,"-#out","decrypted_message.txt"])
#except subprocess.CalledProcessError,  e:
#	l=e.output
	
	#Write unsigned message into a file
	f=open("encrypted_message.txt",'rb')
	encrypted_message=f.read()
	f.close()
	f=open("sessnpass_encry.txt",'rb')
	encrypted_sessionpassword=f.read()
	f.close()
	f=open('unsigned_message.txt','wb')
	f.write(encrypted_sessionpassword)
	f.write("\n\n");
	f.write(encrypted_message)
	#f.write("\n")
	f.close()
	#hashing message
	try:
		hashed_message=subprocess.check_output(["openssl","dgst","-sha1","unsigned_message.txt"])
		h_msg = hashed_message.split("= ")[1]
	except subprocess.CalledProcessError,  e:
		l=e.output

	f=open("hashed_message.txt","wb")
	f.write(h_msg)
	f.close()
	#Signed the hash message with my private key
	try:
		signed_message=subprocess.check_output(["openssl","rsautl","-sign","-inkey","mykey.pem","-keyform","PEM","-in","hashed_message.txt"])
	except subprocess.CalledProcessError,  e:
		l=e.output

	#writing final message
	f=open("final_message.txt","wb")
	f.write("from: kmmehta@ncsu.edu,to: "+rec_email)
	f.write("\n")
	f.write(begin_msg)
	f.write("\n")
	f.write(encrypted_sessionpassword)
	f.write("\n\n")
	f.write(encrypted_message)
	f.write("\n\n")
	f.write(signed_message)
	f.write("\n")
	f.write(end_msg)
	f.close()
	
	try:
		subprocess.check_output(["rm","session_password.txt"])
		subprocess.check_output(["rm","receiver_pubkey.pem"])
		subprocess.check_output(["rm","send_message.txt"])
		subprocess.check_output(["rm","encrypted_message.txt"])
		subprocess.check_output(["rm","sessnpass_encry.txt"])
		subprocess.check_output(["rm","unsigned_message.txt"])
		subprocess.check_output(["rm","hashed_message.txt"])
	except subprocess.CalledProcessError, error:
		print error

def receive_mail():
	flag=1
	set=0
	found=0
	valid=0
	print "Give the received mail:"
	received_mail=raw_input()
	f=open(received_mail,"r+b")
	total_encryptedmail=f.read()
	f.close()
	senderinfo=total_encryptedmail.split("-----BEGIN CSC574 MESSAGE-----\n")[0]
	senderinfo1st=senderinfo.split(",")[0]
	sendermail=senderinfo1st.split(" ")[1]
	
	if(os.path.isfile("databasefile.txt")):
		flag=1
	else:
		f=open("databasefile.txt","wb")
		flag=0
		f.close()
	sender_id=sendermail.split("@")[0]
	sender_cert=sender_id+".pem"
	if(flag==0):
		url = 'https://courses.ncsu.edu/csc574/lec/001/CertificateRepo'
		response = urllib2.urlopen(url)
		cr = csv.reader(response)
		for row in cr:
			if row[0]==sender_id:
				dest_cert = urllib.URLopener()
	                        dest_cert.retrieve(row[1],sender_cert)
				found=1
				break
		if(found==0 and flag==0):
				 print "File not found in webpage and local cache"
	                	 return	
		f=open("databasefile.txt","r+b")
		f.write(sender_cert)
		f.write("\n")
		f.close()
	else:
		f=open("databasefile.txt","r+b")
		for line in f:
			if(sender_cert==line[:-1]):
				set=1
				break
		if(set==0):
			url = 'https://courses.ncsu.edu/csc574/lec/001/CertificateRepo'
			response = urllib2.urlopen(url)
			cr = csv.reader(response)
			for row in cr:
				if row[0]==sender_id:
					dest_cert = urllib.URLopener()
	                	        dest_cert.retrieve(row[1],sender_cert)
					found=1
					break
			if(found==0 and set==0):
				 print "File not found in webpage and local cache"
	                	 return	
			f=open("databasefile.txt","r+b")
			f.seek(0, 2)
			f.write(sender_cert)
			f.write("\n")
			f.close()
	#Verifying Sender certificate
	try:
		output=subprocess.check_output(["openssl","verify","-CAfile","root-ca.crt",sender_cert])
	except subprocess.CalledProcessError,e:
		l=e.output
		if(l!=' '):
			print "Certificate not valid"
			return
	#writing Password and encrypted message to file
	body=total_encryptedmail.split("-----BEGIN CSC574 MESSAGE-----\n")[1]
	pass_n_mesg=body.split("\n\n\n")[0]
	f=open("pass_n_mesg.txt","wb")
	f.write(pass_n_mesg)
	f.write("\n")
	f.close()
	#hashing this file
	try:
		hashed_message=subprocess.check_output(["openssl","dgst","-sha1","pass_n_mesg.txt"])
		h_msg = hashed_message.split("= ")[1]
		#print h_msg[:-1]
	except subprocess.CalledProcessError,  e:
		l=e.output
	#Writing signed part of sender mail to file
	signed_wid_end=body.split("\n\n\n")[1]
	signed_message=signed_wid_end.split("\n-----END CSC574 MESSAGE-----")[0]
	f=open("signed_message.txt","wb")
	f.write(signed_message)
	f.close()
	
	#Get the sender public key from certificate
	try:
		sender_publickey=subprocess.check_output(["openssl","x509","-in",sender_cert,"-pubkey","-noout"])
		#print receiver_publickey
		f=open("sender_pubkey.pem","wb")
		f.write(sender_publickey)
		f.close()
	except subprocess.CalledProcessError,e:
		l=e.output
		#print l

	try:
		decrypt_signed_mesg=subprocess.check_output(["openssl","rsautl","-inkey","sender_pubkey.pem","-pubin","-in","signed_message.txt","-out","decrypted_mess.txt"])
		f=open("decrypted_mess.txt","rb")
		decrypt_signed_mesg=f.read()
		f.close()
	except subprocess.CalledProcessError,e:
		l=e.output
		#print l
	#print decrypt_signed_mesg[:-1]
	if(h_msg[:-1]==decrypt_signed_mesg[:-1]):
		print "certificate verified"

	#Get Session Password
	unsigned_mesg=body.split("\n\n\n")[0]
	encrypted_password=unsigned_mesg.split("\n\n")[0]
	f=open("encry_pass.txt","wb")
	f.write(encrypted_password)
	#f.write("\n")
	f.close()
	
	try:
		session_key=subprocess.check_output(["openssl","rsautl","-decrypt","-in","encry_pass.txt","-inkey","mykey.pem"])
	except subprocess.CalledProcessError, error:
		print error

	final_message=unsigned_mesg.split("\n\n")[1]
	f=open("last_message.txt","wb")
	f.write(final_message)
	f.write("\n")
	f.close()


	#print final_message
	orig_message = ""
	try:
		orig_message=subprocess.check_output(["openssl","enc","-d","-aes-256-cbc","-base64","-in","last_message.txt","-k",session_key])
	except subprocess.CalledProcessError, error:
		print error	
	print "Message is: "+orig_message

	try:
		subprocess.check_output(["rm","pass_n_mesg.txt"])
		subprocess.check_output(["rm","signed_message.txt"])
		subprocess.check_output(["rm","sender_pubkey.pem"])
		subprocess.check_output(["rm","decrypted_mess.txt"])
		subprocess.check_output(["rm","encry_pass.txt"])
		subprocess.check_output(["rm","last_message.txt"])
	except subprocess.CalledProcessError, error:
		print error

def take_input_user_message():
	# take input from stdin and stor it in a text file
	message_file = open("message.txt", "w")
	while(1):
		line = raw_input()
		if (line=="/"):
			break
		line = line + "\n"
		message_file.write(line)

def main():
	
	print "Enter send for sending a message and receive for receiving a message"
	input_test = raw_input()
	if(input_test=="send"):
		send_mail1()
	else:
		receive_mail()

if __name__ == '__main__':
	main()

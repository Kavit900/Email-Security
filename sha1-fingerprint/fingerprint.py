import sys
import os
from subprocess import call, Popen
import subprocess

v = Popen(['openssl', 'x509', '-in', 'kmmehta.pem', '-text'],stdout=subprocess.PIPE).communicate()
#print v[0]
public = v[0]
pub_file = open("text.txt", 'w+')
pub_file.write(public)
pub_file.close()

v = Popen(['openssl', 'x509', '-sha1', '-in', 'root-ca.crt', '-noout', '-fingerprint'],stdout=subprocess.PIPE).communicate()
#print v[0]
public = v[0]
pub_file = open("fingerprint.txt", 'w+')
pub_file.write(public)
pub_file.close()

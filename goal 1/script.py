from itertools import product
import string 
from string import ascii_lowercase
import subprocess 
import chardet
f = open('output.txt', 'wb')
f.close()
keywords = [''.join(i) for i in product(ascii_lowercase, repeat = 3)]
for s in keywords:
	try:
		subprocess.check_output(["openssl","enc","-d","-des-cbc","-a","-in","outfile.txt","-k",s,"-out","out.txt"])
		with open('output.txt', 'a') as f:
    			f.write(s)
			f.write("\n")
			f.close()
	except subprocess.CalledProcessError,  e:
		l=e.output
		continue
	
with open('output.txt') as f:
    content = f.readlines()
f.close()
for i in range(0,len(content)):
	str= (content[i])[:3]
	try:
		subprocess.check_output(["openssl","enc","-d","-des-cbc","-a","-in","outfile.txt","-k",str,"-out","out.txt"])
		with open('out.txt') as f:
			string=f.read()
			encoding = chardet.detect(string)
			if encoding['encoding'] == 'ascii':
					f.close()
					break
			else:
					f.close()
					continue
	except subprocess.CalledProcessError,  e:
		print str		
		continue

print "Secret Key is: " + str + "\n"
print "Secret Message is: \n" + string
	

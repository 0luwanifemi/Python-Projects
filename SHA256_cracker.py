from pwn import *
import sys
import os
import re

def banner():
	print("""

	   ================================================
	   
	   A simple SHA256 password cracker
	    
	   ================================================
	   [+] Usage:
	   python3 SHA256_crack.py <wordlist> <hash>
	   

	   [+] Author:
	   n00by73 (https://noobyte.vercel.app)

	   """)


def hash_check(hash_text):
    pattern = re.compile(r'^[0-9a-f]{64}$')
    if pattern.match(hash_text):
        print("[+] Valid SHA-256 hash.")
        return True
    else:
        print("[!] Invalid SHA-256 hash.")
        exit()
        return False


def wordlist_check(password_list_path):
	print("[..] '{}' Wordlist Check..".format(password_list_path))
	if not os.path.exists(password_list_path):
		print(f"Error: File '{password_list_path}' does not exist.")
		exit()
		return False

	if not os.path.isfile(password_list_path):
		print(f"Error: '{password_list_path}' is not a valid file.")
		exit()
		return False

	if not os.access(password_list_path, os.R_OK):
		print(f"Error: File '{password_list_path}' is not readable.")
		exit()
		return False

	print("[+] '{}' valid and readable".format(password_list_path))
	return True


def SHA_crack(hash_text,password_list_path,attempts):
	with log.progress("Cracking in progres: {}!\n".format(hash_text)) as p:
		with open(password_list_path, "r", encoding='latin-1') as wordlist:
			for password in wordlist:
				password = password.strip("\n").encode('latin-1')
				password_hash = sha256sumhex(password)
				p.status("[{}] {} == {}".format(attempts, password.decode('latin-1'), password_hash))
				if password_hash == hash_text:
					p.success("Password cracked after {} attempts: {} ".format(attempts, password.decode('latin-1')))
					exit()
				attempts += 1
			p.failure("[!]Password not found in wordlist")


def main():
	if len(sys.argv) != 3:
		print("Usage: python3 SHA256_crack.py <wordlist> <hash>")
		exit()
	else:
		banner()

	password_list_path = sys.argv[1]
	hash_text = sys.argv[2]
	attempts = 0

	wordlist_check(password_list_path)
	hash_check(hash_text)

	SHA_crack(hash_text,password_list_path,attempts)


if __name__ == "__main__":
    main()

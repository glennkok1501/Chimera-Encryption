from chimera import Chimera, Chimera_ECB_SHA256, Chimera_CBC_SHA256, Chimera_CTR_SHA256, PAD, Generate_Key
from datetime import datetime
from os import system
import argparse
from getpass import getpass

def banner():
	print("""
\t _____  _   _ ________  ___ ___________  ___  
\t/  __ \\| | | |_   _|  \\/  ||  ___| ___ \\/ _ \\ 
\t| /  \\/| |_| | | | | .  . || |__ | |_/ / /_\\ \\
\t| |    |  _  | | | | |\\/| ||  __||    /|  _  |
\t| \\__/\\| | | |_| |_| |  | || |___| |\\ \\| | | |
\t \\____/\\_| |_/\\___/\\_|  |_/\\____/\\_| \\_\\_| |_/
""")

def ReadFile(file):
	with open(file,"rb") as f:
		a = f.read()
		f.close()
	return a

def ReadKey(key):
	with open(key,"rb") as f:
		a = f.read()
		f.close()
	if len(a) == 32:
		return a
	raise ValueError("Invalid key.")

def WriteFile(file, content):
	with open(file,"wb") as f:
		f.write(content)
		f.close()

def Run(mode, file):
	print("Running...")
	start=datetime.now() #initialize time
	with open(file,"rb") as f:
		m = f.read()
		f.close()
	m = ReadFile(file)
	WriteFile(file, mode(m))
	print(f"Completed - Time: {datetime.now()-start}") #finish time

def main():

	parser = argparse.ArgumentParser(description='This is an application of Chimera algorithm with ECB SHA256 and CBC SHA256.')
	parser.add_argument("filepath", help="encrypt or decrypt desired file", type=str)
	method = parser.add_mutually_exclusive_group()
	method.add_argument("-e", "--encrypt", help="encrypt file", action="store_true")
	method.add_argument("-d", "--decrypt", help="decrypt file", action="store_true")
	mode = parser.add_mutually_exclusive_group()
	mode.add_argument("-1", "--ECB", help="Electronic code book with SHA256", action="store_true")
	mode.add_argument("-2", "--CBC", help="Cipher block chaining with SHA256", action="store_true")
	mode.add_argument("-3", "--CTR", help="Counter mode with SHA256", action="store_true")
	parser.add_argument("-p", "--passwd", help="input password", action="store_true")
	parser.add_argument("-K", "--gen_key", help="Generate key", action="store_true")
	
	args = parser.parse_args()
	if args.gen_key:
		Generate_Key()
	try:
		key = ReadKey("chimera.key")
	except FileNotFoundError:
		try:
			key = ReadKey(input("Insert Key: ").replace('"',""))
		except FileNotFoundError:
			raise parser.error("No key inserted.")

	system('cls')
	banner()

	file = (args.filepath).replace('"','')
	if args.passwd:
		chimera = Chimera(key)
		p = getpass()
		p = p[:16]
		key = chimera.Encrypt(PAD(p.encode('latin-1'))).hex().encode()
	if args.ECB:
		chimera = Chimera_ECB_SHA256(key)
	elif args.CBC:
		chimera = Chimera_CBC_SHA256(key)
	elif args.CTR:
		chimera = Chimera_CTR_SHA256(key)
	else:
		raise parser.error("[--ECB | --CBC | --CTR] is required.")
	if args.encrypt:
		Run(chimera.Encrypt_SHA256, file)
	elif args.decrypt:
		Run(chimera.Decrypt_SHA256, file)
	else:
		raise parser.error("[--encrypt | --decrypt] is required.")

if __name__ == "__main__":
	try:
		main()
	except KeyboardInterrupt:
		print("Force exit")
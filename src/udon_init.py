#!/usr/local/bin/udon/udon-venv/bin/python3
# SPDX-License-Identifier: GPL-2.0
# Copyright (c) 2025 Tree Davies

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.fernet import Fernet
from signal import signal
from signal import SIGINT
from concurrent import futures
from pathlib import Path
from optparse import OptionParser
import subprocess
import platform
import datetime
import hashlib
import shutil
import config
import uuid
import sys
import os

try:
	from libudon import udon_DB
	from libudon import udon_client
	from libudon import udon_server
	from libudon import udon_utils
except Exception as e:
	path_str = str(Path(__file__))
	if "/udon/src/udon_init.py" in path_str:
		print(f"Error: Incorrect file path:{path_str}")
		print("Run from '/usr/local/bin/udon/udon_init.py'")
		sys.exit(1)

""" Global Variables """
TEST_DB = "/tmp/test.db"
UDON_DIR = ".udon"
UDON_CHAN_DIR = f"{UDON_DIR}/channel_cfgs"
UDON_KEYS_DIR = f"{UDON_DIR}/keys"
UDON_TLS_DIR = f"{UDON_DIR}/TLS"
UDON_DB_DIR = f"{UDON_DIR}/db"
UDON_SERVER_KEYS_DIR  = f"{UDON_KEYS_DIR}/server_side_keys"
UDON_CLIENT_KEYS_DIR  = f"{UDON_KEYS_DIR}/client_side_keys"


def handler(signal_received, frame):
    ''' Handle SIGIN/CTRL-C '''
    sys.exit(' exiting...')
signal(SIGINT, handler)

class initialization:

	def __init__(self):
		self.home_dir = udon_utils.home_dir()

		# Directories
		self.udon_dir    = f"{self.home_dir}/{UDON_DIR}"
		self.cfg_dir     = f"{self.home_dir}/{UDON_CHAN_DIR}"
		self.keys_dir    = f"{self.home_dir}/{UDON_KEYS_DIR}"
		self.tls_dir     = f"{self.home_dir}/{UDON_TLS_DIR}"
		self.db_dir      = f"{self.home_dir}/{UDON_DB_DIR}"

		# Configs
		self.test_cfg    = f"{self.home_dir}/{UDON_CHAN_DIR}/test"
		self.server_cfg  = f"{self.home_dir}/{UDON_DIR}/server"

		# Keys
		self.test_key_A  = f"{self.home_dir}/{UDON_KEYS_DIR}/test_key_A"
		self.test_key_B  = f"{self.home_dir}/{UDON_KEYS_DIR}/test_key_B"
		self.server_key  = f"{self.home_dir}/{UDON_KEYS_DIR}/server"

	def error_and_exit(self, msg: str):
		"""
		"""
		print(str(msg))
		sys.exit(1)


	def dir_setup(self):
		"""
		"""
		if not os.path.exists(self.udon_dir):
			print(f" Creating: {self.udon_dir}")
			try:
				os.mkdir(self.udon_dir)
				os.chmod(self.udon_dir, 0o700)
			except Exception as ex:
				self.error_and_exit(f"dir_setup(): {ex}")

		for directory in ["channel_cfgs", "db", "keys", "keys/client_side_keys",
							"keys/server_side_keys", "logs", "TLS"]:
			dpath = f"{self.udon_dir}/{directory}"
			if not os.path.exists(dpath):
				print(f" Creating: {dpath}")
				try:
					os.mkdir(dpath)
					os.chmod(dpath, 0o700)
				except Exception as ex:
					self.error_and_exit(ex)
			else:
				os.chmod(dpath, 0o700)
				print(f" [Exists] {directory} - Doing nothing...")


	def ask_to_create_key(self):
		"""
		"""
		skip = False
		client_keys_dir = f"{self.home_dir}/{UDON_CLIENT_KEYS_DIR}"
		server_keys_dir = f"{self.home_dir}/{UDON_SERVER_KEYS_DIR}"
		hostname = platform.node()

		if not os.path.exists(client_keys_dir):
			print(f"ERROR: Path not found: {client_keys_dir}")
			print(" Run `udon_init.py` first.")
			sys.exit(1)

		op = input("\nCreate a user key? (y/n): ")
		if op == "y":
			name = input(" Name of key: ")

			print("\n Minimum reccomended Key size: 4096")
			print(" Note: Larger key sizes will icrease encoding time")
			key_size = input(" Desired Key size? (default=4096): ")
			if len(key_size) == 0:
				key_size = '4096'
			elif not udon_utils.is_int(key_size):
				print(" Error: key size not integer")
				sys.exit(1)
			elif int(key_size) < 1024:
				print(" Error: key size < 1024")
				sys.exit(1)
			print(f" Key size = {key_size}")

			client_kpath = f"{client_keys_dir}/{name}"
			server_kpath = f"{server_keys_dir}/{name}"

			if os.path.exists(client_kpath):
				print(f" [EXISTS] {client_kpath} - Doing Nothing")
				skip = True
			if os.path.exists(server_kpath):
				print(f" [EXISTS] {server_kpath} - Doing Nothing")
				skip = True

			if skip == False:
				priv, pub = self.create_keys(int(key_size))
				with open(client_kpath, 'wb') as f:
					print(f" Writing private key: {client_kpath}")
					f.write(priv)

				ckp_path = f"{client_kpath}.pub"
				with open(ckp_path, 'wb') as f:
					print(f" Writing Public key: {ckp_path}")
					f.write(pub)

				skp_path = f"{server_kpath}.pub"
				with open(skp_path, 'wb') as f:
					print(f" Writing Public key: {skp_path}")
					f.write(pub)
				self.create_self_config(name, name+'.pub', name, hostname)


	def create_test_keys(self):
		"""
		"""
		op = input("\nCreate TEST keys A and B? (y/n): ")
		if op != "y":
			return

		client_keys_dir = f"{self.home_dir}/{UDON_CLIENT_KEYS_DIR}"
		server_keys_dir = f"{self.home_dir}/{UDON_SERVER_KEYS_DIR}"

		hostname = platform.node()

		ck_A = f"{client_keys_dir}/test_key_A"
		ck_A_pub = f"{client_keys_dir}/test_key_A.pub"
		ck_B = f"{client_keys_dir}/test_key_B"
		ck_B_pub = f"{client_keys_dir}/test_key_B.pub"

		sk_A = f"{server_keys_dir}/test_key_A"
		sk_A_pub = f"{server_keys_dir}/test_key_A.pub"
		sk_B = f"{server_keys_dir}/test_key_B"
		sk_B_pub = f"{server_keys_dir}/test_key_B.pub"

		priv, pub = self.create_keys(key_size=4096)
		with open(ck_A, 'wb') as f:
			print(f" Creating private key: {ck_A}")
			f.write(priv)
		with open(ck_A_pub, 'wb') as f:
			print(f" Creating public key: {ck_A_pub}")
			f.write(pub)
		with open(sk_A_pub, 'wb') as f:
			print(f" Creating public key: {ck_A_pub}")
			f.write(pub)

		priv, pub = self.create_keys(key_size=4096)
		with open(ck_B, 'wb') as f:
			print(f" Creating private key: {ck_B}")
			f.write(priv)
		with open(ck_B_pub, 'wb') as f:
			print(f" Creating public key: {ck_B}")
			f.write(pub)
		with open(sk_B_pub, 'wb') as f:
			print(f" Creating public key: {sk_B_pub}")
			f.write(pub)

		self.create_self_config('test', 'test_key_A.pub', 'test_key_A', hostname)


	def create_keys(self, key_size: int):
		"""
		"""
		private_key = rsa.generate_private_key(
			public_exponent=65537,
			key_size=key_size,
			backend=default_backend()
		)
		public_key = private_key.public_key()

		private_pem = private_key.private_bytes(
			encoding=serialization.Encoding.PEM,
			format=serialization.PrivateFormat.PKCS8,
			encryption_algorithm=serialization.NoEncryption()
		)

		public_pem = public_key.public_bytes(
			encoding=serialization.Encoding.PEM,
			format=serialization.PublicFormat.SubjectPublicKeyInfo
		)
		return (private_pem, public_pem)


	def create_server_config(self):
		""" Check server config """
		server_cfg = f"{self.home_dir}/{UDON_DIR}/server.conf"
		test = f"""
server_port = '50051'
server_db_path  = '{self.home_dir}/{UDON_DB_DIR}/udon-server.db'
ssl_cert = '{self.home_dir}/{UDON_TLS_DIR}/localhost/localhost.crt'
ssl_cert_key = '{self.home_dir}/{UDON_TLS_DIR}/localhost.pem'
	"""
		if not os.path.exists(server_cfg):
			with open(server_cfg, "x") as fd:
				fd.write(test)
				print(f" Created {server_cfg}")
		else:
			print(f" [Exists] {server_cfg} - Doing nothing...")


	def determine_cert_subject(self):
		"""
		"""
		subject = None
		hostname = platform.node()

		print(f" Detected hostname for cert: {hostname}")
		op = input(" Use this hostname for cert? (y/n): ")
		if op == "y":
			subject = f"/CN={hostname}"
			return subject
		else:
			user_hostname = input("Enter hostname for cert subjct: ")
			print(f"Using subject:{user_hostname}")
			subject = f"/CN={user_hostname}"
		return subject


	def create_tls_certs(self):
		"""
			TODO: remove operation I, as J replaces it
		"""
		hostname = platform.node()
		tls_dir = f"{self.home_dir}/{UDON_TLS_DIR}"
		openssl = shutil.which("openssl")
		key_size = str(5120)

		rand_uuid = str(uuid.uuid4())
		passwd = udon_DB.dehyphenate_uuid(rand_uuid)

		if not os.path.exists(openssl):
			sys.exit("Error: openssl path not found")
			return

		new_tls = input("\nCreate new TLS Certs? (y/n): ")
		if new_tls == "n":
			return

		subject = self.determine_cert_subject()
		if subject == None:
			sys.exit("Error: Cert subject not defined")

		A = [openssl, 'genrsa', '-passout', f'pass:{passwd}', '-des3', '-out',
		 		f"{tls_dir}/ca.key", key_size]

		B = [openssl, "req", "-passin", f"pass:{passwd}", "-new", "-x509",
		 		"-days", "365", "-key", f"{tls_dir}/ca.key", "-out", f"{tls_dir}/ca.crt", "-subj", subject]

		C = [openssl, "genrsa", "-passout", f"pass:{passwd}", "-des3", "-out",
		 		f"{tls_dir}/server.key", key_size]

		D = [openssl, "req", "-passin", f"pass:{passwd}", "-new", "-key",
		 		f"{tls_dir}/server.key", "-out", f"{tls_dir}/server.csr", "-subj", f"{subject}"]

		E = [openssl, "x509", "-req", "-passin", f"pass:{passwd}", "-days",
		 		"365", "-in", f"{tls_dir}/server.csr", "-CA", f"{tls_dir}/ca.crt", "-CAkey", f"{tls_dir}/ca.key", "-set_serial", "01", "-out", f"{tls_dir}/server.crt"]

		F = [openssl, "pkcs8", "-topk8", "-nocrypt", "-passin", f"pass:{passwd}",
		 		"-in", f"{tls_dir}/server.key", "-out", f"{tls_dir}/server.pem"]
		
		G = ['cp', f'{tls_dir}/server.pem', f'{tls_dir}/localhost.key']
		H = ['cp', f'{tls_dir}/server.crt', f'{tls_dir}/localhost.crt']
		I = ['cp', f'{tls_dir}/ca.crt', f'{tls_dir}/root.crt']
		J = ['cp', f'{tls_dir}/ca.crt', f'{tls_dir}/{hostname}-root.crt']

		for cmd in [A, B, C, D, E, F, G, H, I, J]:
			try:
				c = " ".join(cmd)
				print(f" Running: `{c}`")
				p = subprocess.run(cmd, stdout=None, stderr=None)
				rtn = int(p.returncode)
				if rtn != 0:
					print(f"Error: {cmd}")
					return
			except Exception as e:
				print("error")


	def create_self_config(self, name: str, pkn:str, privkn:str, fqdn: str):
		""" Check test config """
		chan_cfg_path = f"{self.home_dir}/{UDON_CHAN_DIR}/{name}"

		test = f"""
channel = "{name}"
client_key_name = '{pkn}'
client_private_key = '{self.home_dir}/{UDON_KEYS_DIR}/client_side_keys/{privkn}'
client_db_path = '{self.home_dir}/{UDON_DB_DIR}/{pkn}-udon-local.db'
dest_key_name_list = ['{pkn}']
server_fqdn = '{fqdn}'
server_port = '50051'
ssl_root = '{self.home_dir}/{UDON_TLS_DIR}/root.crt'
"""
		if not os.path.exists(chan_cfg_path):
			with open(chan_cfg_path, "x") as fd:
				fd.write(test)
				print(f" Created {chan_cfg_path}")
			os.chmod(chan_cfg_path, 0o400)
			print(f" Created {chan_cfg_path}")
			return
		else:
			print(f"[Exists] {chan_cfg_path} - Doing nothing...")


def init_env():
	parser = OptionParser()
	parser.add_option("-u", "--user", dest="new_user_key", action='store_true',
					help="Create new user public/private key pair", metavar="")
	(options, args) = parser.parse_args()

	i = initialization()

	euid = os.geteuid()
	if euid == 0:
		i.error_and_exit("Can not run as root user.\nPlease run as a non-priviledged user.")

	if options.new_user_key:
		i.ask_to_create_key()
	else:
		print("Initializing...")
		i.dir_setup()
		i.create_test_keys()
		i.create_tls_certs()
		i.create_server_config()
		i.ask_to_create_key()
		sys.exit(0)

if __name__ == '__main__':
	init_env()

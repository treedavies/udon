#!/usr/bin/udon.d/udon-venv/bin/python3
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
import subprocess
import platform
import datetime
import hashlib
import shutil
import socket
import config
import json
import sys
import os
import getpass

try:
	from libudon import udon_DB
	from libudon import udon_client
	from libudon import udon_server
	from libudon import udon_utils
except Exception as e:
	path_str = str(Path(__file__))
	if "/udon/src/test_libudon.py" in path_str:
		print(f"Error: Incorrect file path:{path_str}")
		print("Run from '/usr/bin/udon.d/test_libudon.py'")
		sys.exit(1)


def handler(signal_received, frame):
    ''' Handle SIGIN/CTRL-C '''
    sys.exit(' exiting...')
signal(SIGINT, handler)

class Test:

	user = None
	home_dir = None
	cfg_name = None
	srv_cfg_name = None
	cfg_path = None
	srvr_cfg_path = None

	def __init__(self):
		euid = os.geteuid()
		if euid == 0:
			print("Can not run as root user.\nPlease run as a non-priviledged user.")
			sys.exit(1)

		self.TEST_DB = "/tmp/test.db"
		self.UDON_DIR = ".udon"
		self.UDON_CHAN_DIR = f"{self.UDON_DIR}/channel_cfgs"
		self.UDON_KEYS_DIR = f"{self.UDON_DIR}/keys"
		self.UDON_TLS_DIR = f"{self.UDON_DIR}/TLS"
		self.UDON_DB_DIR = f"{self.UDON_DIR}/db"

		self.user = getpass.getuser()
		self.home_dir = udon_utils.home_dir()
		self.cfg_name = "test"
		self.srv_cfg_name = "server.conf"
		self.cfg_path = f"{self.home_dir}/{self.UDON_CHAN_DIR}/{self.cfg_name}"
		self.srvr_cfg_path = f"{self.home_dir}/{self.UDON_DIR}/{self.srv_cfg_name}"

	def run(self):
		self.run_tests(self.cfg_path, self.srvr_cfg_path)
		self.evaluate(True, True, "All Tests Ccompleted")

	def evaluate(self, expected, recvd, name, quiet=False, silent=False) -> int:
		"""
		"""
		fail = "\033[0;31;48m [ERROR] \033[0m"
		ok = "\033[0;32;48m [OK] \033[0m"

		if expected == recvd:
			if silent == False:
				if quiet == True:
					print(f"{ok}{name} e:quieted r:quieted")
				else:
					print(f"{ok}{name} e:{expected} r:{recvd}")
		else:
			if quiet == True:
				print(f"{fail}{name} e:quieted r:quieted")
			else:
				print(f"{fail}{name} e:{expected} r:{recvd}")
			sys.exit(1)


	def clean_up(self, cfg: str):
		"""
		"""
		try:
			cfg = config.Config(cfg)
		except Exception as e:
			print(f"Effor: clean_up() - {e}")
			sys.exit(1)

		if os.path.exists("/tmp/test-clean.db"):
			os.remove("/tmp/test-clean.db")
		if os.path.exists(self.TEST_DB):
			os.remove(self.TEST_DB)
		if os.path.exists(cfg["client_db_path"]):
			os.remove(cfg["client_db_path"]) 


	def init_db_tests(self):
		print("\n----------------------")
		print(" DB Tests - init tables")
		print("------------------------")
		r = udon_DB.init_primary_table(self.TEST_DB, "test_table")
		self.evaluate(0, r, "init_primary_table()")

		r = udon_DB.init_uuid_table(self.TEST_DB)
		self.evaluate(0, r, "init_uuid_table()")

		r = udon_DB.init_client_chan_table(self.TEST_DB, "test_chan")
		self.evaluate(0, r, "init_client_table()")


	def db_table_exist(self):
		print("\n----------------------")
		print(" DB Table Exist Test")
		print("------------------------")

		r = udon_DB.table_exist(self.TEST_DB, "test_table")
		self.evaluate(True, r, "table_exist() - test_table")

		r = udon_DB.table_exist(self.TEST_DB, "test_chan")
		self.evaluate(True, r, "test_exit() - test_chan")

		r = udon_DB.table_exist(self.TEST_DB, "NE_TABLE")
		self.evaluate(False, r, "Non Existing table_exist() NE_TABLE")

		r = udon_DB.table_exist(self.TEST_DB, "UUID")
		self.evaluate(True, r, "table_exist() UUID")


	def db_write_table(self):
		print("\n----------------------")
		print(" DB write to table test")
		print("------------------------")

		# Make 10 rows. 0-9
		for i in range(10):
			src  = f"src_{str(i)}"
			dest = f"dest_{str(i)}"
			msg  = f"msg_{str(i)}"
			time_stamp = "00:00:00"
			sym_key = "XYZ"
			digest="XYZ"
			parts="XYZ"
			r = udon_DB.write_msg_table_entry(db_path=self.TEST_DB,
												table="test_table",
												time=time_stamp.encode(),
												src=src.encode(),
												msg=msg.encode(),
												msgsig="".encode(),
												channel="".encode(),
												symetric_key="".encode(),
												digest=digest.encode(),
												parts=parts.encode())
			self.evaluate(0, r, f"write_msg_table_entry({i})")


	def uuid_match(self):
		print("\n----------------------")
		print(" UUID match replay test")
		print("------------------------")

		uuidA = 'a52cd7e8-c77b-4e9f-9a91-efe456ed4d8d'
		i = udon_DB.write_uuid_entry(db_path=self.TEST_DB, uid=uuidA)
		print(f"{self.TEST_DB}: {i}")
		self.evaluate(0, i, f"uuid_match() - write uuid")

		r = udon_DB.replayed_uuid(self.TEST_DB, "UUID", uuidA)
		self.evaluate(1, r, f"uuid_match(A) - replayed_uuid test")


	def db_row_count(self):
		print("\n----------------------")
		print(" DB Row count")
		print("------------------------")
		r = udon_DB.table_row_count(self.TEST_DB, "test_table")        
		self.evaluate(10, r, "table_row_count()")


	def db_read_table(self):
		print("\n----------------------")
		print(" DB Read from table")
		print("------------------------")

		# Attempt read of non-existant row. (Rows start at 1)
		r = udon_DB.read_msg_table_entry(self.TEST_DB, "test_table", 0)
		self.evaluate([], r, "read_msg_table_entry(0)")

		r = udon_DB.read_msg_table_entry(self.TEST_DB, "test_table", 2)
		self.evaluate(2, r[0][0], "read_msg_table_entry(2)")

		# Attempt read last row. (Rows end at 10)                           
		r = udon_DB.read_msg_table_entry(self.TEST_DB, "test_table", 10)
		self.evaluate(10, r[0][0], "read_msg_table_entry(10)")

		# Attempt read of non-existant row. (Rows end at 10)                           
		r = udon_DB.read_msg_table_entry(self.TEST_DB, "test_table", 11)
		self.evaluate([], r, "read_msg_table_entry(11)")


	def client_init_test(self, cfg: str):
		print("\n----------------------")
		print(" Client init Test")
		print("----------------------")

		# Test 1 - Client Initialization, Load config
		cfg = config.Config(cfg)
		client = udon_client()
		self.evaluate(True, bool(client), "Init Client")
		rtn = client.c_load_config(cfg)
		self.evaluate(True, rtn, "Init Client_test() - c_load_config()")


	def client_key_load_test(self, cfg: str):
		print("\n----------------------")
		print(" Client - load keys Test")
		print("------------------------")

		cfg = config.Config(cfg)
		client = udon_client()
		self.evaluate(True, bool(client), "Init Client")
		rtn = client.c_load_config(cfg)
		self.evaluate(True, rtn, "client_key_load_test() - c_load_config()")

		# Test 2 - Load public keys
		for name in client.key_paths:
			r = client.c_load_pub_key(client.key_paths[name])
			self.evaluate(True, bool(r), "c_load_pub_key("+name+")", quiet=True)

		# Test 3 - Load Private Keys (if found)
		for name in client.key_paths:
			pkp = client.key_paths[name].replace(".pub", "")
			if not os.path.exists(pkp):
				self.evaluate(True, True, "Skipping c_load_priv_key("+name+") path not found.", quiet=True)	
				continue
			else:
				r = client.c_load_priv_key(client.key_paths[name])
				self.evaluate(True, bool(r), "c_load_priv_key("+name+")", quiet=True)

		# Test 4 Load key with None result
		r = client.c_load_priv_key("/tmp/nope")
		self.evaluate(None, r, "c_load_priv_key(/tmp/nope)")


	def client_encrypt_decrypt_test(self, cfg: str):
		print("\n----------------------")
		print(" Client - enc/dec Test")
		print("------------------------")

		cfg = config.Config(cfg)
		client = udon_client()
		self.evaluate(True, bool(client), "Init Client")
		rtn = client.c_load_config(cfg)
		self.evaluate(True, rtn, "client_encrypt_decrypt_test() - c_load_config()")

		eight_bytes = "eightbyt"
		for i in range(5):
			print("\n")
			data = eight_bytes * 10 * i
			d = data.encode()

			sig  = client.c_gen_signature(d)
			self.evaluate(True, bool(sig), "c_gen_signature()")

			cipher = client.c_encrypt_bstring_with_public_key(d, client.key_name)
			self.evaluate(True, bool(cipher), "Result Returned c_encrypt_bstring()", quiet=True)
			clear = client.c_decrypt_bstring_with_key(cipher)

			verify = client.c_verify_signature(sig, clear, client.key_name)
			self.evaluate(True, verify, "Verify Signature", quiet=True)

			clr = clear.decode('utf-8')
			self.evaluate(len(data), len(clr), "Result Length c_decrypt_bstring()")
			self.evaluate(data, clr, "c_decrypt_bstring()", quiet=True)


	def client_signature_test(self, cfg):
		print("\n----------------------")
		print(" Client signature Tests")
		print(" Load Keys ")
		print("----------------------")

		cfg = config.Config(cfg)
		client = udon_client()
		rtn = client.c_load_config(cfg)
		self.evaluate(True, rtn, "client_signature_test() - c_load_config()")

		eight_bytes = "eightbyt"

		for key in cfg["dest_key_name_list"]:
			for i in range(1,20):
				payload = eight_bytes * i
				payload = payload.encode()

				sig = client.c_gen_signature(payload)
				rtn = client.c_verify_signature(sig, payload, key)
				self.evaluate(True, rtn, f"client_signature_tests(key:{key} size:{i})")


	def client_symkey_test(self):
		print("\n----------------------")
		print(" cleint Tests")
		print(" symkey ")
		print("------------------------")

		key = Fernet.generate_key()
		print(f"Test: Generated key: {key}")

		client = udon_client()
		s = "Free as in speach, but beer would also be good".encode()
		ct = client.c_encrypt_bstring_with_sym_key(byte_str=s, sym_key=key)
		self.evaluate(True, bool(ct), "client_symkey_test() encrypt() return True")

		clear = client.c_decrypt_bstring_with_sym_key(byte_str=ct, sym_key=key)
		self.evaluate(True, bool(clear), f"client_symkey_test(): decrypt return {clear}")
		self.evaluate(s, clear, f"client_symkey_test(): ")


	"""
	"""
	def server_init_test(self, cfg_path, srv_cfg_path):
		print("\n----------------------")
		print(" Server init Test")
		print("----------------------")

		# Test 1
		srv_config = config.Config(srv_cfg_path)
		server = udon_server()
		self.evaluate(True, bool(server), "Init Server")

		home_dir = udon_utils.home_dir()
		md5 = udon_utils.utl_file_md5(f"{home_dir}/{self.UDON_KEYS_DIR}/client_side_keys/test_key_A")
		print(f"{md5}")
		if udon_DB.table_exist(srv_config["server_db_path"], md5):
			print("table exists")
			rtn = udon_DB.run_db_commit(f"drop table '{md5}'", srv_config["server_db_path"])
			self.evaluate(0, rtn, "Error: drop table test_key_A", quiet=False)
		if udon_DB.table_exist(srv_config["server_db_path"], md5):
			print("table exists")
		rtn = server.s_load_config(srv_config)
		self.evaluate(True, rtn, "s_load_config(srv_cfg)", quiet=True)


	"""
	"""
	def drop_test_table(self, cfg_path, srv_cfg_path):
		"""
			Drop test table if it exists.
		"""
		print("\n----------------------")
		print(" Drop Test Table")
		print("------------------------")

		home_dir = udon_utils.home_dir()
		kpath = f"{home_dir}/{self.UDON_KEYS_DIR}/client_side_keys/test_key_A.pub"
		md5_table_name = udon_utils.utl_file_md5(kpath)
		if md5_table_name == None:
			self.evaluate(True, bool(server), "drop_test_table(): utl_file_md5() failed")

		srv_config = config.Config(srv_cfg_path)
		server = udon_server()
		self.evaluate(True, bool(server), "drop_test_table(): Init Server")


		if udon_DB.table_exist(srv_config["server_db_path"], md5_table_name):
			rtn = udon_DB.run_db_commit(f"drop table '{md5_table_name}'", srv_config["server_db_path"])
			self.evaluate(0, rtn, "Error: drop table test_key_A", quiet=False)

		rtn = udon_DB.table_exist(srv_config["server_db_path"], md5_table_name)
		self.evaluate(False, rtn, f"Error: drop_test_table: test_key_A:{md5_table_name}", quiet=False)


	def server_laod_test(self, cfg_path, srv_cfg_path):
		print("\n----------------------")
		print(" Server load Test")
		print("----------------------")

		# Test 1
		srv_config = config.Config(srv_cfg_path)
		server = udon_server()
		self.evaluate(True, bool(server), "Init Server")

		# Test 2
		for name in server.key_paths:
			r = server.s_load_client_pub_key(server.key_paths[name])
			self.evaluate(True, bool(r), "s_load_client_pub_key("+name+")", quiet=True)

		# Test 3
		#for name in server.key_paths:
		#	r = server.s_load_server_priv_key(server.priv_key_path)
		#	evaluate(True, bool(r), "+s_load_server_priv_key("+name+")", quiet=True)


		# Load key with None result
		# r = server.s_load_server_priv_key("/tmp/nope")
		# evaluate(None, r, "c_load_priv_key(/tmp/nope)")

	def is_server_running_test(self):
		rtn = udon_utils.is_udon_server_running()
		self.evaluate(True, rtn, "is_server_running_test()")

	def c_ping_test(self, cfg):
		print("\n----------------------")
		print(" gRPC Test")
		print(" c_ping() Test ")
		print("------------------------")
		cfg = config.Config(cfg)
		client = udon_client()
		rtn = client.c_load_config(cfg)
		self.evaluate(True, rtn, "c_ping_test() - c_load_config()")

		status = client.c_ping()
		self.evaluate(True, status, f"c_ping_test() bool")


	def c_send_commit_test(self, cfg):
		print("\n----------------------")
		print(" gRPC Test")
		print(" c_send_commit() Test ")
		print("------------------------")

		cfg = config.Config(cfg)
		client = udon_client()
		rtn = client.c_load_config(cfg)
		self.evaluate(True, rtn, "c_send_test() - c_load_config()")

		key_name = cfg["client_key_name"]

		""" Generate md5sum of key_name """
		kpath = client.key_paths[key_name]
		req_src = udon_utils.utl_file_md5(kpath)

		""" Server readable args. Encryption handled by TLS """
		recip_id    = key_name.encode()
		sender_id   = key_name.encode()

		""" Server readable arg, Generate uuid and uuid_signature """
		uuid = udon_utils.generate_uuid()
		if uuid == None:
			self.evaluate(True, bool(uuid), f"c_send_commit_test() generate_uuid()")

		uuid_sig = client.c_gen_signature(uuid.encode())
		if uuid_sig == None:
			self.evaluate(True, bool(uuid_sig), f"c_send_commit_test() c_gen_signature()")
		uuid = uuid.encode()

		""" Generate symetric key """
		sym_key = Fernet.generate_key()
		enc_sym_key = client.c_encrypt_bstring_with_public_key(sym_key, key_name)

		""" Recipient args """
		payload = f"This is a test Payload for {req_src}".encode()
		msg_sig = client.c_gen_signature(payload)
		if msg_sig == None:
			self.evaluate(True, bool(msg_sig), f"c_send_commit_test() c_gen_signature() msg_sig")

		""" Generate message timestamp """
		time_stamp = datetime.datetime.now().strftime('%H:%M:%S').encode()
		cipher_time = client.c_encrypt_bstring_with_sym_key(time_stamp, sym_key)

		"""" Symetric encrypt msg values """
		cipher_payload = client.c_encrypt_bstring_with_sym_key(payload, sym_key)

		kpath = client.key_paths[key_name]
		req_src = udon_utils.utl_file_md5(kpath)
		csrc = client.c_encrypt_bstring_with_sym_key(req_src.encode(), sym_key)

		channel = client.channel_name
		cipher_channel = client.c_encrypt_bstring_with_sym_key(channel.encode(), sym_key)

		# kpath = client.key_paths[key_name]
		# req_src = udon_utils.utl_file_md5(kpath)
		if req_src == None:
			self.evaluate(True, bool(req_src), f"c_send_commit_test() utl_file_md5()")
		self.evaluate(32, len(req_src), f"c_send_commit_test() utl_file_md5() length")
		recip_md5 = req_src

		resp = client.c_send_commit(
								breq_src=req_src.encode(),
								breq_uuid_sig=uuid_sig,
								breq_uuid=uuid,

								btime=cipher_time,
								bdest=recip_md5.encode(),
								bpayload=cipher_payload,
								bsource=csrc,
								bsignature=msg_sig,
								bchannel=cipher_channel,
								bsymetric_key=enc_sym_key)
		self.evaluate(True, bool(resp), f"c_send_commit_test() resp")
		self.evaluate(True, bool(resp.response), f"c_send_committest(): resp.response")


	def c_send_commit_test_2mb(self, cfg):
		print("\n----------------------")
		print(" gRPC Test")
		print(" c_send_commit_test_2bm() Test")
		print("------------------------")

		cfg = config.Config(cfg)
		client = udon_client()
		rtn = client.c_load_config(cfg)
		self.evaluate(True, rtn, "c_send_test() - c_load_config()")

		key_name = cfg["client_key_name"]

		""" Generate md5sum of key_name """
		kpath = client.key_paths[key_name]
		req_src = udon_utils.utl_file_md5(kpath)

		""" Server readable args. Encryption handled by TLS """
		recip_id    = key_name.encode()
		sender_id   = key_name.encode()

		""" Server readable arg, Generate uuid and uuid_signature """
		uuid = udon_utils.generate_uuid()
		if uuid == None:
			self.evaluate(True, bool(uuid), f"c_send_commit_test() generate_uuid()")

		uuid_sig = client.c_gen_signature(uuid.encode())
		if uuid_sig == None:
			self.evaluate(True, bool(uuid_sig), f"c_send_commit_test() c_gen_signature()")
		uuid = uuid.encode()

		""" Generate symetric key """
		sym_key = Fernet.generate_key()
		enc_sym_key = client.c_encrypt_bstring_with_public_key(sym_key, key_name)

		""" Recipient args """
		payload = ""
		for i in range(3000000):
			payload = payload + 'X'
		payload = payload.encode()

		msg_sig = client.c_gen_signature(payload)
		if msg_sig == None:
			self.evaluate(True, bool(msg_sig), f"c_send_commit_test() c_gen_signature() msg_sig")

		""" Generate message timestamp """
		time_stamp = datetime.datetime.now().strftime('%H:%M:%S').encode()
		cipher_time = client.c_encrypt_bstring_with_sym_key(time_stamp, sym_key)

		"""" Symetric encrypt msg values """
		cipher_payload = client.c_encrypt_bstring_with_sym_key(payload, sym_key)

		kpath = client.key_paths[key_name]
		req_src = udon_utils.utl_file_md5(kpath)
		csrc = client.c_encrypt_bstring_with_sym_key(req_src.encode(), sym_key)

		channel = client.channel_name
		cipher_channel = client.c_encrypt_bstring_with_sym_key(channel.encode(), sym_key)

		if req_src == None:
			evaluate(True, bool(req_src), f"c_send_commit_test() utl_file_md5()")
		self.evaluate(32, len(req_src), f"c_send_commit_test() utl_file_md5() length")
		recip_md5 = req_src

		resp = client.c_send_commit(
								breq_src=req_src.encode(),
								breq_uuid_sig=uuid_sig,
								breq_uuid=uuid,

								btime=cipher_time,
								bdest=recip_md5.encode(),
								bpayload=cipher_payload,
								bsource=csrc,
								bsignature=msg_sig,
								bchannel=cipher_channel,
								bsymetric_key=enc_sym_key)
		self.evaluate(True, bool(resp), f"c_send_commit_test() resp")
		self.evaluate(True, bool(resp.response), f"c_send_committest(): resp.response")


	def commit_error_replay_test(self, cfg):
		"""
			All request IDs should be unique. The server
			logs the UUIDs. Call c_send_commit twice with the
			same request ID.
			This tests the error condition is caught.
		"""
		print("\n----------------------")
		print(" gRPC Test")
		print(" commit() replay error test")
		print("------------------------")

		cfg = config.Config(cfg)
		client = udon_client()
		rtn = client.c_load_config(cfg)
		self.evaluate(True, rtn, "commit_error_replay_test() - c_load_config()")

		key_name = cfg["client_key_name"]

		""" Server readable args. Encryption handled by TLS """
		recip_id    = key_name.encode()
		sender_id   = key_name.encode()

		""" Server readable arg, Generate uuid and uuid_signature """
		uuid = udon_utils.generate_uuid()
		if uuid == None:
			evaluate(True, bool(uuid), f"c_send_commit_test() generate_uuid()")
		
		uuid_sig = client.c_gen_signature(uuid.encode())
		if uuid_sig == None:
			evaluate(True, bool(uuid_sig), f"c_send_commit_test() c_gen_signature()")
		uuid = uuid.encode()

		""" Generate symetric key """
		sym_key = Fernet.generate_key()
		enc_sym_key = client.c_encrypt_bstring_with_public_key(sym_key, key_name)

		""" Recipient args """
		payload = f"This is a test Payload for {key_name}".encode()
		msg_sig = client.c_gen_signature(payload)
		if msg_sig == None:
			self.evaluate(True, bool(msg_sig), f"c_send_commit_test() c_gen_signature() msg_sig")

		""" Generate message timestamp """
		time_stamp = datetime.datetime.now().strftime('%H:%M:%S').encode()
		cipher_time = client.c_encrypt_bstring_with_sym_key(time_stamp, sym_key)

		"""" Symetric encrypt msg values """
		cipher_payload = client.c_encrypt_bstring_with_sym_key(payload, sym_key)

		kpath = client.key_paths[key_name]
		req_src = udon_utils.utl_file_md5(kpath)
		csrc = client.c_encrypt_bstring_with_sym_key(req_src.encode(), sym_key)

		channel = client.channel_name
		cipher_channel = client.c_encrypt_bstring_with_sym_key(channel.encode(), sym_key)

		kpath = client.key_paths[key_name]
		req_src = udon_utils.utl_file_md5(kpath)
		if req_src == None:
			evaluate(True, bool(req_src), f"c_send_commit_test() utl_file_md5()")
		self.evaluate(32, len(req_src), f"c_send_commit_test() utl_file_md5() length")
		recip_md5 = req_src

		resp = client.c_send_commit(
								breq_src=req_src.encode(),
								breq_uuid_sig=uuid_sig,
								breq_uuid=uuid,

								btime=cipher_time,
								bdest=recip_md5.encode(),
								bpayload=cipher_payload,
								bsource=csrc,
								bsignature=msg_sig,
								bchannel=cipher_channel,
								bsymetric_key=enc_sym_key)
		self.evaluate(True, bool(resp.response), f"commit_error_replay_test() - sent {uuid}")

		resp = client.c_send_commit(
								breq_src=req_src.encode(),
								breq_uuid_sig=uuid_sig,
								breq_uuid=uuid,

								btime=cipher_time,
								bdest=recip_md5.encode(),
								bpayload=cipher_payload,
								bsource=csrc,
								bsignature=msg_sig,
								bchannel=cipher_channel,
								bsymetric_key=enc_sym_key)

		exp_uuid = uuid.decode("utf-8").replace("-","")
		expected = f"Error: commit() - replayed_uuid() {exp_uuid}"
		r = resp.error.decode("utf-8")
		self.evaluate(expected, resp.error.decode("utf-8"), f"commit_error_replay_test() previous uuid ")


	def check_tests(self, cfg):
		print("\n----------------------")
		print(" gRPC Test")
		print(" Check()")
		print("----------------------")

		cfg = config.Config(cfg)
		client = udon_client()
		rtn = client.c_load_config(cfg)
		self.evaluate(True, rtn, "check_test() - c_load_config()")
		
		""" Test 1 """
		#Akey = client.key_name
		#key_id = Akey.encode()
		#cipher_key_id = key_id

		key_path = client.key_paths[client.key_name]
		key_md5 = udon_utils.utl_file_md5(key_path)
		key_id = key_md5.encode()
		self.evaluate(True, bool(key_id), "client.c_encrypt_bstring_with_key()")

		""" Test 2 """
		req_uuid = udon_utils.generate_uuid()
		req_uuid = req_uuid.encode()
		uuid_sig = client.c_gen_signature(req_uuid)

		resp = client.c_msg_check(breq_src=key_id, breq_uuid_sig=uuid_sig, breq_uuid=req_uuid)
		self.evaluate(False, bool(resp.error), f"check_tests() Test 2 - resp.error: {resp.error}")


	def check_error_tests(self, cfg):
		print("\n----------------------")
		print(" gRPC Test")
		print(" Check() error tests")
		print("----------------------")
		cfg = config.Config(cfg)
		client = udon_client()
		rtn = client.c_load_config(cfg)
		self.evaluate(True, rtn, "check_error_tests() - c_load_config()")

		"""
		Test: Send empty key_id
		"""
		uuid = udon_utils.generate_uuid()
		uuid_sig = client.c_gen_signature(uuid.encode())

		resp = client.c_msg_check(breq_src="".encode(), breq_uuid_sig=uuid_sig, breq_uuid=uuid.encode())
		expected = "Error: check() - missing arg: key_id"
		self.evaluate(expected, resp.error.decode("utf-8"), "check() Error")


		"""
		Test: Send bogus key_id 
		"""
		#key_id = "BOGUS_KEY".encode()
		#resp = client.c_msg_check(breq_src=key_id, breq_uuid_sig=uuid_sig, breq_uuid=uuid.encode())
		#expected = "Error: check() - public key for key_id BOGUS_KEY not found"
		#evaluate(expected, resp.error.decode("utf-8"), "check() Error")

		"""
		Test: Send incorrect signature
		"""
		uuid = udon_utils.generate_uuid()
		print("Wrong key test")
		""" Sign with wrong key """
		uuid_sig = client.c_gen_signature(uuid.encode())
		resp = client.c_msg_check(
			breq_src="test_key_A".encode(),
			breq_uuid_sig=uuid_sig,
			breq_uuid=uuid.encode()
			)
		#expected = 'Error: check():False - s_verify_signature()'
		#evaluate(expected, resp.error.decode("utf-8"), "check() Error")


	def fetch_tests(self, cfg):
		print("\n----------------------")
		print(" gRPC Tests")
		print(" fetch()")
		print("------------------------")

		cfg = config.Config(cfg)                                               
		client = udon_client()                                                    
		rtn = client.c_load_config(cfg)
		self.evaluate(True, rtn, "fetch_tests() - c_load_config()")

		key_id = client.key_name
		for i in range(1,2):
			uuid = udon_utils.generate_uuid()
			uuid_sig = client.c_gen_signature(uuid.encode())
			cipher_uuid = uuid.encode()

			value  = str(i).encode()

			kpath = client.key_paths[client.key_name]
			key_md5 = udon_utils.utl_file_md5(kpath)
			key_id = key_md5.encode()

			cipher_value = value
			response = client.c_msg_fetch(bval=cipher_value,
										breq_src=key_id,
										breq_uuid_sig=uuid_sig,
										breq_uuid=cipher_uuid)
			self.evaluate(True, bool(response), "fetch_tests() response true")

			esk = response.symetric_key
			sym_key = client.c_decrypt_bstring_with_key(esk)
			payload = client.c_decrypt_bstring_with_sym_key(response.payload, sym_key)
			expected = f"This is a test Payload for {key_md5}"
			rtn = payload.decode("utf-8")
			self.evaluate(expected, rtn, "fetch("+str(int(i))+")")


	def fetch_error_tests(self, cfg):
		print("\n----------------------")
		print(" gRPC Tests")
		print(" fetch() Error Tests")
		print("------------------------")

		cfg = config.Config(cfg)                                               
		client = udon_client()                                                    
		rtn = client.c_load_config(cfg)
		self.evaluate(True, rtn, "fetch_error_tests() - c_load_config()")

		key_id = client.key_name
		kpath = client.key_paths[client.key_name]
		key_md5 = udon_utils.utl_file_md5(kpath)
		value  = "".encode()

		""" Test: Send empty message value """
		uuid = udon_utils.generate_uuid()
		uuid_sig = client.c_gen_signature(uuid.encode())
		mvalue = "".encode()
		response = client.c_msg_fetch(bval=mvalue, breq_src=key_md5.encode(), 
								breq_uuid_sig=uuid_sig, 
								breq_uuid=uuid.encode())
		expected = "Error: fetch() - missing arg: value"
		self.evaluate(expected, response.error.decode("utf-8"), "fetch()")

		""" Test: Send empty key_id """
		key_id = "".encode()
		mvalue = "2".encode()
		response = client.c_msg_fetch(bval=mvalue, breq_src=key_id,
								breq_uuid_sig=uuid_sig, 
								breq_uuid=uuid.encode())
		expected = "Error: fetch() - missing arg: key_id"
		self.evaluate(expected, response.error.decode("utf-8"), "fetch()")

		""" Test: Send non-integer value """
		value  = "X".encode()
		key_id = client.key_name.encode()
		uuid = udon_utils.generate_uuid()
		uuid_sig = client.c_gen_signature(uuid.encode())
		response = client.c_msg_fetch(bval=value, breq_src=key_md5.encode(),
								breq_uuid_sig=uuid_sig, 
								breq_uuid=uuid.encode())
		expected = "Error: fetch() - non-int msg_num"
		self.evaluate(expected, response.error.decode("utf-8"), "fetch()")

		# Server Side Decryption failure of value
		# Server Side Decryption failure of key_id


	"""
	"""
	def check_all_configs(self):
		home_dir = udon_utils.home_dir()
		configs = os.listdir(f"{self.home_dir}/{self.UDON_CHAN_DIR}")

		if len(configs) > 0:
			for cfg in configs:
				p = f"{self.home_dir}/{self.UDON_CHAN_DIR}/{cfg}"
				self.config_test(p, silent_flag=True)


	def verify_channel(self, cfg: dict, cfg_path: str) -> bool:
		""" verify channel name conforms to required format """
		chan_name = None
		if "channel" in cfg.keys():
			chan_name =  cfg["channel"]
		else:
			return False

		if len(chan_name) == 0:
			print(f"Error: invalid channel name - found: '{chan_name}'")
			return False

		if '-' in chan_name:
			print(f"Error: invalid channel name - found '-' (hyphen) char in {chan_name}")
			return False

		if ' ' in chan_name:
			print(f"Error: invalid channel name - found ' ' (space) char in {chan_name}")
			return False

		""" Test channel file name is the same channel name defined """
		file_name = cfg_path.split("/")[-1]
		if not file_name == chan_name:
			print(f"Error: Channel file name: '{file_name}' mismastch with config'd channel: '{chan_name}' ")
			print("Channel config Requirement: channel name must be equivalent to filename")
			return False
		return True


	def verify_recipient_list(self, cfg: dict) -> bool:
		""" verify recipeitn list is not empty """
		if "dest_key_name_list" in cfg.keys():
			lst =  cfg["dest_key_name_list"]
			if len(lst) < 1:
				print("Error: the config's recipient list is empty")
				return False
			return True
		else:
			return False


	def	verify_client_key_name_in_list(self, cfg: dict):
		""" verify the client's key name is in recipeint list """
		if "dest_key_name_list" in cfg.keys():
			if 'client_key_name' in cfg.keys():
				name = cfg['client_key_name']
				lst = cfg["dest_key_name_list"]
				if name in lst:
					return True
			else:
				print("Error: 'client_key_name' not found in config")
				return False
		else:
			print(f"Error: 'dest_key_name_list' not found in config")
			return False
		return False


	def	verify_key_name_extension(self, cfg: dict):
		""" verify the client's key name ends in '.pub' """
		if 'client_key_name' in cfg.keys():
			name = cfg['client_key_name']
			lst = name.split('.')
			if len(lst) == 2:
				if lst[1] == 'pub':
					return True
		return False


	def	verify_key_name_not_equal_to_channel_names(self, cfg: dict) -> bool:
		home_dir = udon_utils.home_dir()
		chan_file_list = os.listdir(f"{home_dir}/{self.UDON_CHAN_DIR}")
		ckn = cfg["client_key_name"]

		""" verify by file name """
		for chan_file in chan_file_list:
			if chan_file.lower() == ckn.lower():
				self.evaluate(True, False, f"Found channel: '{chan_file}' and Key: '{ckn}' - Channel/Key names can not be equivalent")

		return True


	def verify_client_db_path(self, cfg: dict):
		""" verify client's DB exists """
		if "client_db_path" in cfg.keys():
			cdp = cfg["client_db_path"]
		else:
			return False
		# check filename format
		return True


	def verify_client_private_key(self, cfg: dict) -> bool:
		if 'client_private_key' in cfg.keys():
			cpk = cfg['client_private_key']
			if not os.path.exists(cpk):
				print(f"Error: verify_client_private_key() - key path not found: {cpk}")
				return False
		else:
			print("Error: verify_client_private_key() - key not found: 'client_private_key'")
			return False
		return True


	def verify_root_cert(self, cfg: dict) -> bool:
		home_dir = udon_utils.home_dir()
		root_cert = cfg["ssl_root"]
		if not os.path.exists(root_cert):
			print(f"Error: verify_root_cert() - path not found {root_cert}")
			return False
		return True


	def verify_cleint_key_name(self, cfg: dict):
		if "client_key_name" in cfg.keys():
			ckn = cfg["client_key_name"]
			if len(ckn) > 0:
				return True
		return False


	def verify_server_address(self, cfg):
		"""
		"""
		if "server_fqdn" in cfg.keys():
			addr = cfg["server_fqdn"]
			channel = cfg['channel']
			if 'FQDN' in addr:
				print(f"Error: verify_server_address():{channel} {addr} - FQDN not set in config")
				return False
		else:
			return False
		return True


	def verify_recip_keys_exist(self, cfg: dict) -> bool:
		home_dir = udon_utils.home_dir()
		keys_dir = f"{home_dir}/{self.UDON_KEYS_DIR}/client_side_keys"
		dest_keys = cfg["dest_key_name_list"]

		for key in dest_keys:
			kpath = f"{keys_dir}/{key}"
			if not os.path.exists(kpath):
				c = cfg["channel"]
				print(f"Error: channel:{c} Key:{kpath} - not in {keys_dir}")
				return False
		return True


	def verify_no_priv_keys_on_server(self) -> bool:
		kpath_lst = []
		home_dir = udon_utils.home_dir()

		srv_keys_dir = f"{home_dir}/{self.UDON_KEYS_DIR}/server_side_keys"
		if not os.path.exists(srv_keys_dir):
			print(f"Error: path not found: {srv_keys_dir}")
			return False

		lst = os.listdir(srv_keys_dir)
		for key in lst:
			kpath = f"{srv_keys_dir}/{key}"
			kpath_lst.append(kpath)

		for kpath in kpath_lst:
			with open(kpath, "r") as fd:
				key = fd.read()
				if "BEGIN PRIVATE KEY" in key:
					print(f"Error: found private key:{kpath}")
					return False
		return True


	def verify_recip_keys_end_in_pub(self, cfg: dict) -> bool:
		home_dir = udon_utils.home_dir()
		keys_dir = f"{home_dir}/{self.UDON_KEYS_DIR}/client_side_keys"
		dest_keys = cfg["dest_key_name_list"]

		for key in dest_keys:
			kpath = f"{keys_dir}/{key}"
			if os.path.exists(kpath):
				s = kpath.split('.')
				if len(s) == 2:
					if s[1] != 'pub':
						return False
		return True


	def test_home_dir(self):
		user = getpass.getuser()
		home_dir = udon_utils.home_dir()
		if not os.path.exists(home_dir):
			evaluate(True, False, "test_home_dir() path not exist")
		self.evaluate(True, True, "test_home_dir() path exists")

		if not user in home_dir:
			evaluate(True, False, "test_home_dir() user id not found")
		self.evaluate(True, True, "test_home_dir() user id found")


	def test_utl_file_md5(self):
		with open("/tmp/md5_this", "w") as fd:
			fd.write("1 2 3 4 5 6 7 8 9")
		md5 = udon_utils.utl_file_md5("/tmp/md5_this")
		expected = 'c2d06f689fbd660d2f9dbf888352d9d2'
		self.evaluate(expected, md5, "test_utl_file_md5()")
		os.remove("/tmp/md5_this")


	"""
	List of what is verified for all channel configs
		- verify if channel defined
		- verify if channel name and file name should be the same?
		- verify dest_key_name_list defined
		- verify client_db_path defined
		- verify client_private_key defined
		- verify root.crt
		- verify client_key_name defined
		- verify client_key_name is in dest list
		- verify server_fqdn defined
		- verify server_port defined
		- verify recipient keys exist
		- verify public keys end in .pub
	"""
	def config_test(self, cfg_path: str, silent_flag=False):
			if not os.path.exists(cfg_path):
				self.evaluate(True, False, "config_test() path not found - {cfg}", silent=silent_flag)

			try:
				cfg = config.Config(cfg_path).as_dict()
			except Exception as e:
				print(f"Error: load config as dictionary {e}: {cfg_path}")
				self.evaluate(True, False, f"config_test() - config.Config({cfg_path}).as_dict()", silent=silent_flag)

			""" Verify all assets are defined """
			""" Verify channel is named correctly """
			if self.verify_channel(cfg, cfg_path):
				self.evaluate(True, True, "config_test() - verify_channel()", silent=silent_flag)
			else:
				self.evaluate(True, False, "config_test() - verify_channel()", silent=silent_flag)
			chan = cfg['channel']

			""" Verify client_key_name defined """
			if self.verify_cleint_key_name(cfg):
				self.evaluate(True, True, f"config_test() channel:{chan} client_key_name size empty", silent=silent_flag)
			else:
				self.evaluate(True, False, f"config_test() channel:{chan} client_key_name size NOT empty", silent=silent_flag)

			""" Verify client_private_key defined """
			if self.verify_client_private_key(cfg):
				self.evaluate(True, True, f"config_test() channel:{chan} client_private_key", silent=silent_flag)
			else:
				self.evaluate(True, False, f"config_test() channel:{chan} client_private_key", silent=silent_flag)

			""" Verify client_db_path defined """
			if self.verify_client_db_path(cfg):
				self.evaluate(True, True, f"config_test() channel:{chan} verify_client_db_path", silent=silent_flag)
			else:
				self.evaluate(True, True, f"config_test() channel:{chan} client_db_path", silent=silent_flag)

			""" Verify recipent list not empty """
			if self.verify_recipient_list(cfg):
				self.evaluate(True, True, f"config_test() channel:{chan} dest_key_name_list NOT size empty",
					silent=silent_flag)
			else:
				self.evaluate(True, False, f"config_test() channel:{chan} dest_key_name_list size empty",
					silent=silent_flag)

			""" Verify server_fqdn defined """
			if self.verify_server_address(cfg):
				self.evaluate(True, True, f"config_test() channel:{chan} server_fqdn size empty", silent=silent_flag)
			else:
				self.evaluate(True, False, f"config_test() channel:{chan}srver_ip size empty", silent=silent_flag)

			""" Verify server_port defined """
			try:
				srv_port = cfg["server_port"]
				if not len(srv_port) >= 1:
					self.evaluate(True, False, f"config_test() channel:{chan} server_port size empty", silent=silent_flag)
			except Exception as e:
				print(f"Error: config_test() try:server_port {e}")
			self.evaluate(True, True, f"config_test() channel:{chan} server_port size not empty", silent=silent_flag)

			""" verify root cert defined """
			if self.verify_root_cert(cfg):
				self.evaluate(True, True, f"config_test() channel:{chan} verify_root_cert", silent=silent_flag)
			else:
				self.evaluate(True, False, f"config_test() channel:{chan} verify_root_cert", silent=silent_flag)


			""" Verify asset correctness """
			""" Verify that client_key_name is at least in the dest_key_list """
			if self.verify_client_key_name_in_list(cfg):
				self.evaluate(True, True, f"config_test() channel:{chan} client_key_name IN destination list",
					silent=silent_flag)
			else:
				self.evaluate(True, False, f"config_test() channel:{chan} client_key_name NOT in destination list",
					silent=silent_flag)

			""" Verify that client_key_name ends in .pub """
			if self.verify_key_name_extension(cfg):
				self.evaluate(True, True, f"config_test() channel:{chan} client_key_name extenstion '.pub'",
					silent=silent_flag)
			else:
				self.evaluate(True, False, f"config_test() channel:{chan} client_key_name extension NOT '.pub'",
					silent=silent_flag)

			""" TODO: Verify client_key_name is named correctly. No Hyphens! """

			""" Verify channel names are not same as key names. """
			if self.verify_key_name_not_equal_to_channel_names(cfg):
				self.evaluate(True, True, f"config_test() channel:{chan} key name != channel name", silent=silent_flag)
			else:
				self.evaluate(True, False, f"config_test() channel:{chan} key name == channel name", silent=silent_flag)

			""" Verify ssl_root path exists """
			try:
				ssl_root = cfg["ssl_root"]
				if not len(srv_port) >= 1:
					self.evaluate(True, False, f"config_test() channel:{chan} ssl_root size empty", silent=silent_flag)
				if not os.path.exists(ssl_root):
					self.evaluate(True, False, f"config_test() channel:{chan} ssl_root path not found {ssl_root}", silent=silent_flag)
			except Exception as e:
				print(f"Error: config_test() try:server_port {e}")
			self.evaluate(True, True, f"config_test() channel:{chan} ssl_root path found {ssl_root}", silent=silent_flag)

			""" Verify all recipient keys end in .pub """
			if self.verify_recip_keys_end_in_pub(cfg):
				self.evaluate(True, True, f"config_test() channel:{chan} Recipeint Key: - found .pub recipeint keys", silent=silent_flag)
			else:
				self.evaluate(True, False, f"config_test() channel:{chan} Recipeint Key: - found non-.pub recipient keys", silent=silent_flag)

			""" Verify recipient keys exist """
			if self.verify_recip_keys_exist(cfg):
				self.evaluate(True, True, f"config_test() channel:{chan} Recipeint Key: - found in keys_dir", silent=silent_flag)
			else:
				self.evaluate(True, False, f"config_test() channel:{chan} Recipient Key: - not in keys_dir", silent=silent_flag)

			""" Verify public-only keys in server_side_keys dir """
			if self.verify_no_priv_keys_on_server():
				self.evaluate(True, True, f"config_test() channel:{chan} verify_no_priv_keys_on_server()", silent=silent_flag)
			else:
				self.evaluate(True, False, f"config_test() channel:{chan} verify_no_priv_keys_on_server(): Found private key on server", silent=silent_flag)


	def db_list_tables_test(self, cfg):
		print("\n----------------------")
		print(" db_list_tables")
		print("------------------------")

		expected = ['test_table',  'sqlite_sequence',
				'test_table_with_channel_column']
		lst = udon_DB.get_table_list(self.TEST_DB)
		for table in expected:
			r = table in expected
			self.evaluate(True, r, f"db_list_tables() - {table}")
		self.clean_up(cfg)


	def db_clean_test(self):
		print("\n----------------------")
		print(" Clean DB table Test")
		print("------------------------")
		TEST_DB = "/tmp/test-clean.db"
		NULL = "NULL".encode()

		r = udon_DB.init_primary_table(self.TEST_DB, "test_table")
		self.evaluate(0, r, "init_primary_table()")

		# Make 10 rows. 0-9
		for i in range(10):
			time_stamp = "00:00:00"
			src  = "src_" + str(i)
			msg  = "msg_" + str(i)
			msg_sig = "sig_" + str(i)
			sym_key = ""
			digest = "sha"
			parts = "parts"
			chan = "default"

			r = udon_DB.write_msg_table_entry(self.TEST_DB, "test_table",
										time_stamp.encode(),
										src.encode(),
										msg.encode(),
										msg_sig.encode(),
										sym_key.encode(),
										digest.encode(),
										parts.encode(),
										chan.encode())
			self.evaluate(0, r, f"write_msg_table_entry({i})")

		rtn = udon_DB.clean_msgs_in_primary_table(self.TEST_DB, "test_table")
		self.evaluate(0, rtn, f"db_clean_test() - clean_msgs_in_primary_table() return code")

		NULL = "".encode()
		for i in range(1, 11):
			rtn = udon_DB.read_msg_table_entry(self.TEST_DB, "test_table", i)
			self.evaluate(1, len(rtn), f"db_clean_test() - read_msg_table_entry({i}) return size")
			expected = (i, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)
			self.evaluate(expected, rtn[0], f"db_clean_test() - read_msg_table_entry({i})")


	def clean_on_server_test(self, cfg: str):
		"""
		"""
		print("\n----------------------")
		print(" Clean table on server")
		print("------------------------")

		cfg = config.Config(cfg)
		client = udon_client()
		rtn = client.c_load_config(cfg)
		self.evaluate(True, rtn, "clean_on_server_test() - c_load_config()")

		key_id = client.key_name
		uuid = udon_utils.generate_uuid()
		uuid_sig = client.c_gen_signature(uuid.encode())
		uuid = uuid.encode()

		nothing = "-1".encode()
		rsp = client.c_clean(key_id=key_id, buuid_sig=uuid_sig, buuid=uuid, clean_count=nothing )
		print(str(rsp))
		self.evaluate("".encode(), rsp.error, f"clean_on_server_test() - no error response")


	def rpc_module_test(self, cfg: str):
		print("\n----------------------")
		print(" RPC Module Test")
		print("------------------------")

		cfg = config.Config(cfg)
		client = udon_client()
		rtn = client.c_load_config(cfg)
		self.evaluate(True, rtn, "0 rpc_module_test() - c_load_config()")

		key_id = client.key_name

		mod_args = {}
		mod_args["name"] = "Dave"
		json_str_mod_args = json.dumps(mod_args)
		bargs = json_str_mod_args.encode()

		""" Hello """
		rsp = client.c_module(key_id=key_id,
								mod_name="hello".encode(),
								args=bargs)
		self.evaluate("0".encode(), rsp.rc, f"1 rpc_module_test() - Hello() response: {rsp.error}")
		self.evaluate("Hello, Dave!".encode(), rsp.data, f"2 rpc_module_test() - hello response:{rsp.data}")


	def udon_dir_check(self):
		"""
			Verify required directories exist or Fail
		"""
		home_dir = udon_utils.home_dir()
		udon_dir = f"{home_dir}/{self.UDON_DIR}"
		if not os.path.exists(udon_dir):
			self.evaluate(True, False, f"udon_dir_check() - {udon_dir}")

		lst = ["channel_cfgs", "db", "keys", "keys/server_side_keys",
				"keys/client_side_keys", "logs", "TLS"]
		for directory in lst:
			dpath = f"{udon_dir}/{directory}"
			if not os.path.exists(dpath):
				self.evaluate(True, False, f"udon_dir_check() - {dpath}")
			else:
				self.evaluate(True, True, f"udon_dir_check() - {dpath}")


	def check_types(self):
		"""
			Verify various types or fail
		"""
		rb = udon_utils.type_check([(1, int)])
		self.evaluate(True, rb, f"check_types - int")

		rb = udon_utils.type_check([("str", str)])
		self.evaluate(True, rb, f"check_types - str")

		rb = udon_utils.type_check([("bytes".encode(), bytes)])
		self.evaluate(True, rb, f"check_types - bytes")

		rb = udon_utils.type_check([("Not-bytes", bytes)])
		self.evaluate(False, rb, f"check_types - Not bytes")

		rb = udon_utils.type_check([({}, dict)])
		self.evaluate(True, rb, f"check_types - dict")

		rb = udon_utils.type_check([([], list)])
		self.evaluate(True, rb, f"check_types - list")


	def running_tests_on_server(self, cfs_path: str):
		try:
			cfg = config.Config(self.cfg_path).as_dict()
		except Exception as e:
			print(f"Error: load config at dictionary {e}: {cfg_path}")
			self.evaluate(True, False, f"tests_on_server() - config.Config({cfg_path}).as_dict()", silent=silent_flag)

		hostname = socket.gethostname()
		cfg_hostname = cfg['server_fqdn']

		print(hostname,cfg_hostname)
		if cfg_hostname == hostname:
			self.evaluate(True, True, f"test_on_server()")
		else:
			self.evaluate(True, False, f"test_on_server()")


	def run_tests(self, cfg: str, srv_cfg: str):
		self.check_types()

		self.running_tests_on_server(cfg)

		""" Utils tests """
		self.test_home_dir()
		self.test_utl_file_md5()

		"""" Config tests """
		self.udon_dir_check()
		self.config_test(cfg)

		""" DB Tests """
		self.drop_test_table(cfg, srv_cfg)
		self.init_db_tests()
		self.db_table_exist()
		self.db_write_table()
		self.db_row_count()
		self.db_read_table()
		self.db_list_tables_test(cfg)
		self.db_clean_test()

		""" Client object tests """
		self.client_init_test(cfg)
		self.client_key_load_test(cfg)
		self.client_encrypt_decrypt_test(cfg)
		self.client_signature_test(cfg)
		self.client_symkey_test()

		""" Server object tests """
		self.server_init_test(cfg, srv_cfg)
		self.server_laod_test(cfg, srv_cfg)

		""" is_server_running() """
		self.is_server_running_test()

		""" ping() test """
		self.c_ping_test(cfg)

		""" Commmit() Tests"""
		self.c_send_commit_test(cfg)
		self.c_send_commit_test_2mb(cfg)
		self.commit_error_replay_test(cfg)

		""" check() Tests """
		self.check_tests(cfg)
		self.check_error_tests(cfg)

		""" fetch() Tests """
		self.fetch_tests(cfg)
		self.fetch_error_tests(cfg)

		""" clean() test"""
		self.db_clean_test()
		self.clean_on_server_test(cfg)

		self.rpc_module_test(cfg)

		""" cleanup test related data """
		self.drop_test_table(cfg, srv_cfg)
		self.clean_up(cfg)


if __name__ == '__main__':
	t = Test()
	t.run()


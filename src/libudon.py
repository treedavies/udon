# SPDX-License-Identifier: GPL-2.0
# Copyright (c) 2025 Tree Davies

import os
import sys
import grpc
import uuid
import pathlib
import datetime
import udon_pb2 as pb2
import udon_pb2_grpc as pb2_grpc
import config
import sqlite3
import platform
import hashlib
from concurrent import futures
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
import logging
logger = logging.getLogger(__name__)
import getpass

""" Global Variables """
SUCCESS  = 0
FAILURE  = 1
DEBUG    = False
UDON_DIR = '.udon'
UDON_CHAN_DIR = '.udon/channel_cfgs'
UDON_CLIENT_SIDE_KEYS = '.udon/keys/client_side_keys'
UDON_TLS_DIR = '.udon/TLS'
UDON_LOGS_DIR = '.udon/logs'


def debug(msg: str, enable=False):
	"""
		DEBUG: global variable. Set to True to enable debug out for all
		       functions in libudon.py
	"""
	if DEBUG or enable:
		print(f"DEBUG:{msg}")


def error(msg: str, to_file=False):
	print(f"Error:{msg}")
	if to_file:
		home_dir = udon_utils.home_dir()
		tfmt = '%Y-%m-%d %H:%M:%S'
		time_stamp = datetime.datetime.now().strftime(tfmt)
		logfile = f"{home_dir}/{UDON_LOGS_DIR}/log"
		logging.basicConfig(filename=logfile, level=logging.INFO)
		logger.error(f"{time_stamp}:{msg}")


def output(msg: str, to_file=False):
	types_lst = [(msg, str), (to_file, bool)]
	if not udon_utils.type_check(types_lst):
		error("output(): type_check")
		return False

	print(f"{msg}")
	if to_file:
		home_dir = udon_utils.home_dir()
		tfmt = '%Y-%m-%d %H:%M:%S'
		time_stamp = datetime.datetime.now().strftime(tfmt)
		logfile = f"{home_dir}/{UDON_LOGS_DIR}/log"
		logging.basicConfig(filename=logfile, level=logging.INFO)
		logger.info(f"{time_stamp}:{msg}")


class udon_client:

	def __init__(self):
		"""
			Initialize client object.
			Returns client object

			client_db_path -- str: path of client's local db
			config         -- dict: profile config
			priv_key_path  -- path of private key
			key_name       -- name of client key
			key_paths      -- dict: Resolves key names to key paths
			recipients     -- list[str]: key names
			server_fqdn      -- str: IP address of remote Udon server
			server_port    -- str: remote udon server port
			channel_name   -- str: name of channel (not the gRPC channel)
		"""
		debug("client.__init__():")
		self.client_db_path = None
		self.config         = None
		self.priv_key_path  = None
		self.key_name       = None
		self.key_paths      = {}
		self.keyname_to_hash = {}
		self.hash_to_keyname = {}
		self.recipients     = None
		self.server_fqdn    = None
		self.server_port    = None
		self.channel_name   = None
		self.ssl_root       = None


	def c_load_config(self, cfg: dict) -> bool:
		"""
			Load client channel config
		"""
		debug('c_load_config()')
		types_lst = [(type(cfg), type(config.Config))]
		if not udon_utils.type_check(types_lst):
			return False
		
		try:
			self.key_paths       = {}
			self.keyname_to_hash = {}
			self.hash_to_keyname = {}
			self.config         = cfg
			self.client_db_path = self.config["client_db_path"]
			self.priv_key_path  = self.config["client_private_key"]
			self.key_name       = self.config["client_key_name"]
			self.recipients     = self.config["dest_key_name_list"]
			self.server_fqdn    = self.config["server_fqdn"]
			self.server_port    = self.config["server_port"]
			self.channel_name   = self.config['channel']
			self.ssl_root       = self.config["ssl_root"]
		except Exception as e:
			error(f"udon_client.c_load_config()- {e}")
			return False

		if not os.path.exists(self.ssl_root):
			error(f"c_load_config():File not found - {self.ssl_root}")
			return False

		home_dir = udon_utils.home_dir()
		if home_dir == None:
			error("udon_server().__init__() -  home_dir() returned None")
			sys.exit(1)

		pk = f"{home_dir}/{UDON_CLIENT_SIDE_KEYS}/{self.key_name}"
		if not os.path.exists(pk):
			error("udon_client:c_load_config() - public key not found")

		""" create maps of public key name, path, and  md5 """
		klist = os.listdir(f"{home_dir}/.udon/keys/client_side_keys/")
		for k in klist:
			if ".pub" in k:
				md5 = udon_utils.utl_file_md5(f"{home_dir}/.udon/keys/client_side_keys/{k}")
				self.key_paths[k] = f"{home_dir}/.udon/keys/client_side_keys/{k}"
				self.keyname_to_hash[k] = md5
				self.hash_to_keyname[md5] = k

		rtn = udon_DB.init_primary_table(self.client_db_path, self.key_name)
		if rtn != SUCCESS:
			error('c_load_config(): init_primary_table() call failure')
			return False

		try:
			self.channel_cred = grpc.ssl_channel_credentials(
				udon_utils.load_credential_from_file(self.ssl_root))
		except Exception as e:
			error(f"c_load_config() - {e}")
			return False

		try:
			server_and_port = f"{self.server_fqdn}:{self.server_port}"
			channel = grpc.secure_channel(server_and_port, self.channel_cred)
			self.stub = pb2_grpc.UnaryStub(channel)
		except Exception as e:
			error(f"udon_client.c_load_config() - {e}")
			return False
		return True


	def c_send(self, recip_key: str, msg: str, signature: bytes,
					channel: str) -> bool:
				"""
					Validate and prepare to send message to server
					returns: boolean
				"""
				if not udon_utils.type_check([
					(recip_key, str),
					(msg, str),
					(signature, bytes),
					(channel, str)]):
					return False

				if not self.c_ping():
					error(f"Connection to server:{self.server_fqdn} Failed.")
					return False

				if not recip_key:
					error('c_send() - recip_key destination = Null')
					return False

				if not msg:
					error('c_send() - msg = Null')
					return False
				payload = msg.rstrip().encode()

				if not signature:
					error('c_send() - signature = Null')
					return False

				if not self.key_name:
					error('c_send() - msg_sender = Null')
					return False
				msg_sender = self.key_name

				if not channel:
					error('c_send() - channel = Null')
					return False
				channel = channel.encode()

				""" create sym key and encrypt it with recipient pub key"""
				sym_key = Fernet.generate_key()
				enc_sym_key = self.c_encrypt_bstring_with_public_key(sym_key, recip_key)

				""" Start encrypting message fields..."""
				csignature = self.c_encrypt_bstring_with_sym_key(
															signature,
															sym_key
															)

				cpayload = self.c_encrypt_bstring_with_sym_key(
															payload,
															sym_key
															)

				if not cpayload:
					error('c_send() - payload == None')
					return False

				kpath = self.key_paths[msg_sender]
				msg_sender_key_hash = udon_utils.utl_file_md5(kpath)
				csrc = self.c_encrypt_bstring_with_sym_key(
														msg_sender_key_hash.encode(),
														sym_key
														)
				if not csrc:
					error('c_send() - csrc == None')
					return False

				tfmt = '%Y-%m-%d %H:%M:%S:%f'
				time_stamp = datetime.datetime.now().strftime(tfmt).encode()
				ctime = self.c_encrypt_bstring_with_sym_key(time_stamp, sym_key)
				if not ctime:
					error('c_send() - ctime == None')
					return False

				uuid = udon_utils.generate_uuid().encode()
				bsig = self.c_sign_bstring(uuid, self.key_name)
				if not bsig:
					error('c_send() - bsig == None')
					return False

				cchan = self.c_encrypt_bstring_with_sym_key(channel, sym_key)
				if not cchan:
					error('c_send() - chan == None')
					return False


				""" get digest of recip key """
				hash = None
				rkey_path = self.key_paths[recip_key]
				with open(rkey_path, "r") as fd:
					key_data = fd.read()
				hash = hashlib.md5(key_data.encode()).hexdigest()
				recip_key = hash.encode()

				msg_sender = msg_sender_key_hash.encode()

				resp = self.c_send_commit(breq_src=msg_sender,
										breq_uuid_sig=bsig,
										breq_uuid=uuid,
										btime=ctime,
										bdest=recip_key,
										bpayload=cpayload,
										bsource=csrc,
										bsignature=csignature,
										bchannel=cchan,
										bsymetric_key=enc_sym_key)

				if resp == None:
					error('udon:send():c_send_commit() resp=None')
					return False

				return True


	def c_send_commit(self, 
				   breq_src: bytes,
				   breq_uuid_sig: bytes,
				   breq_uuid: bytes,
				   btime: bytes,
				   bdest: bytes,
				   bpayload: bytes,
				   bsource: bytes,
				   bsignature: bytes,
				   bchannel: bytes,
				   bsymetric_key: bytes):
		"""
		client side passthrough for proto message to commit() on remote
		machine

		Keyword arguments:
		msg_srg    -- bstring: sender's key id - ciphered by server key
		buuid_sig  -- bstring: crypto signature of UUID - ciphered by server
		              key
		buuid      -- bstring: id - ciphered by server key
		btime      -- bstring: timestamp - ciphered by recipeint key
		bdest      -- bstring: recipient's key name
		              key
		bpayload   -- bstring: message (data) - ciphered by recipeint key
		bsource    -- bstrring: message sender's key id - ciphered by recipeint
		              key
		bsignature -- bstring: crypto signature of message (bpayload)
		bchannel   -- bstring: conversation channel id

		returns MessageResponse on success, None on error
		"""
		debug('client.c_send_commit()')

		types_lst = [
			(breq_src, bytes),
			(breq_uuid_sig, bytes),
			(breq_uuid, bytes),
			(btime, bytes),
			(bdest, bytes),
			(bpayload, bytes),
			(bsource, bytes),
			(bsignature, bytes),
			(bchannel, bytes), 
			(bsymetric_key, bytes)]
		if not udon_utils.type_check(types_lst):
			error('c_send_commit() - Type check')
			return None

		resp = None
		message = pb2.CommitMessage(key_id=breq_src,
						signature=breq_uuid_sig,
						uuid=breq_uuid,
						time=btime,
						destination=bdest,
						payload=bpayload,
						source=bsource,
						msg_signature=bsignature,
						channel=bchannel,
						symetric_key=bsymetric_key)
		try:
			resp = self.stub.commit(message)
		except Exception as e:
			error(f'c_send_commit()- failed connect/commit() on server. {e}')
			error('It is possible the server-side rpc crashed.')
			return None
		return resp


	def c_ping(self) -> bool:
		""" """
		resp = None
		try:
			preq = pb2.PingRequest()
			resp = self.stub.ping(preq)
		except Exception as e:
			return False
		return True


	def c_msg_check(self, breq_src: bytes, breq_uuid_sig: bytes,
					breq_uuid: bytes):
		"""
			client side prepare and send proto message to check() on remote machine
			returns CheckResponse on success, None on error
		"""
		debug('c_msg_check()')
		rtn = None
		if not udon_utils.type_check([(breq_src, bytes), 
								(breq_uuid_sig, bytes),
								(breq_uuid, bytes)]):
			error('Invalid type - c_msg_check')
			return None

		resp = None
		message = pb2.CheckRequest(key_id=breq_src, signature=breq_uuid_sig, 
									uuid=breq_uuid)
		try:
			resp = self.stub.check(message)
		except Exception as e:
			error(f'c_msg_check() - Failure connect/check(): {e}')
			return None
		return resp


	def c_clean(self, key_id: str, buuid_sig: bytes, buuid: bytes, clean_count: bytes):
		"""
			client side prepare and send proto message to clean table
			data on remote machine
			returns CleanResponse on sucess, None on error
		"""
		debug('c_msg_clean()')
		if not udon_utils.type_check([(key_id, str),
								(buuid_sig, bytes),
								(buuid, bytes),
								(clean_count, bytes)]):
			error('Invalid type - c_clean')
			return None

		if not self.c_ping():
			error("Connection to server:{self.server_fqdn} Failed.")
			return None

		kpath = self.key_paths[key_id]
		if not os.path.exists(kpath):
			error(f"c_clean() - path not found:{kpath}")
			return None
		md5 = udon_utils.utl_file_md5(kpath)
		key_id = md5.encode()

		resp = None
		try:
			req = pb2.CleanRequest(key_id=key_id, signature=buuid_sig,
									uuid=buuid, clean_count=clean_count)
			resp = self.stub.clean(req)
		except Exception as e:
			error(f'c_clean() - Failure connect/Clean()')
			return None
		return  resp


	def c_msg_fetch(self, bval: bytes, breq_src: bytes,
				breq_uuid_sig: bytes, breq_uuid: bytes):
		"""
			client side prepare and send proto message to fetch() on remote machine
			returns MessageResponse on success or None on error
		"""
		debug('c_msg_fetch()')
		types_lst = [
			(bval, bytes),
			(breq_src, bytes),
			(breq_uuid_sig, bytes),
			(breq_uuid, bytes)
			]
		if not udon_utils.type_check(types_lst):
			error('c_msg_fetch() - invalid types')
			return None

		resp = None
		try:
			message = pb2.Request(value=bval, key_id=breq_src,
									signature=breq_uuid_sig,
									uuid=breq_uuid)
			resp = self.stub.fetch(message)
		except Exception as e:
			error(f"c_msg_fetch() {e}")
			return None
		return resp


	def c_load_pub_key(self, key_path: str) -> str:
		"""
			Load a public key
			Returns string on success
			None on Error
		"""
		debug('c_load_pub_key()')
		if not udon_utils.type_check([(key_path, str)]):
			error('c_load_pub_key() - Invalid type:key_path')
			return None
		if key_path == "":
			error(f'c_load_pub_key() - empty key_path string')
			return None
		return udon_utils.utl_load_pub_key(key_path)


	def c_load_priv_key(self, key_path: str) -> str:
		"""
			load client private key
			Returns: string on success
					 None on Error
			TODO: Is there a test that tests .pub and priv match up?
		"""
		debug("c_load_priv_key()")
		if not udon_utils.type_check([(key_path, str)]):
			error('Invalid type:key_path - c_load_priv_key')
			return None
		if key_path == "":
			error(f"c_load_priv_key() - empty key_path string")
			return None
		if '.pub' in key_path and key_path.endswith(".pub"):
			key_path = key_path.replace(".pub", "")
		return udon_utils.utl_load_priv_key(key_path)


	def c_encrypt_bstring_with_sym_key(self, byte_str: bytes, sym_key: bytes) -> bytes:
		"""
			Return None on error, cipher text on success
		"""
		if not udon_utils.type_check([(byte_str, bytes),
										(sym_key, bytes)]):
			error('Invalid type:key_path - c_encrypt_bstring_with_sym_key')
			return None

		cipher_txt = None
		try:
			sym_key = Fernet(sym_key)
			cipher_txt = sym_key.encrypt(byte_str)
		except Exception as e:
			error("c_encrypt_bstring_with_sym_key():{e}")
			return None
		return cipher_txt


	def c_decrypt_bstring_with_sym_key(self, byte_str: bytes, sym_key: str) -> bytes:
		"""
			Return None on error, cipher text on success
		"""
		if not udon_utils.type_check([(byte_str, bytes),
										(sym_key, bytes)]):
			error('Invalid type:key_path - c_encrypt_bstring_with_sym_key')
			return None

		clear_txt = None
		try:
			sym_key = Fernet(sym_key)
			clear_txt = sym_key.decrypt(byte_str)
		except Exception as e:
			error(f"c_encrypt_bstring_with_sym_key():{e}")
			return None
		return clear_txt


	def c_encrypt_bstring_with_public_key(self, byte_str: bytes,
									key_id: str) -> bytes:
		"""
			client side Encrypt byte string
			Returns: Encrypted byte string on success
		    	     None on failure
		"""
		debug('c_encrypt_bstring_with_key()')
		if not udon_utils.type_check([(byte_str, bytes),(key_id, str)]):
			error('Invalid types - c_encrypt_bstring_with_key()')
			return None

		pubkey = self.c_load_pub_key(self.key_paths[key_id])
		if pubkey != None:
			ciphertext = pubkey.encrypt(byte_str, padding.OAEP(
				mgf=padding.MGF1(algorithm=hashes.SHA256()),
				algorithm=hashes.SHA256(),
				label=None))
			return ciphertext


	def c_decrypt_bstring_with_key(self, cipher_msg: bytes) -> bytes:
		"""
			client side Decrypt ciphered byte string
			Returns: decrypted byte string
					 None on failure
		"""
		debug("c_decrypt_bstring_with_key()")
		if not udon_utils.type_check([(cipher_msg, bytes)]):
			error('c_decrypt_bstring_with_key() - Invalid inputs')
			return None

		pkp = self.priv_key_path
		privkey = self.c_load_priv_key(pkp)
		plaintext = privkey.decrypt(
			cipher_msg,
			padding.OAEP(
			mgf=padding.MGF1(algorithm=hashes.SHA256()),
			algorithm=hashes.SHA256(),
			label=None))
		return plaintext


	def c_sign_bstring(self, message: bytes, key_id: str) -> bytes:
		"""
			Cryptographically Sign byte string
			Returns: returns byte string
		"""
		debug('c_sign_bstring()')
		if not udon_utils.type_check([(message, bytes),(key_id, str)]):
			error('Invalid type:message - c_sign_bstring()')
			return None

		key_path = self.config["client_private_key"]
		if not os.path.exists(key_path):
			error("c_sign_bstring() - path not found: {key_path}")
			return None

		# try
		with open(key_path, "rb") as key_file:
			private_key = serialization.load_pem_private_key(
			key_file.read(),
			password=None, )

			signature = private_key.sign(message,
				padding.PSS(
					mgf=padding.MGF1(hashes.SHA256()),
					salt_length=padding.PSS.MAX_LENGTH),
					hashes.SHA256())
			return signature


	def c_verify_signature(self, signature: bytes,
							message: bytes, key_id: str) -> bool:
		"""
			Cryptographically verify byte string signature
			Returns: returns byte string
		"""
		debug('c_verify_signature()')
		if not udon_utils.type_check([
				(signature, bytes),
				(message, bytes),
				(key_id, str)]):
			error('Invalid type:message - c_verify_signature()')
			return False

		key_path = self.key_paths[key_id]
		if not os.path.exists(key_path):
			error(f"c_verify_signature() - path not found:{key_path}")
			return False

		return udon_utils.utl_verify_signature(self, signature, message,
												key_path)


	def c_mark_msg_as_read(self, channel: str, num: int) -> int:
		"""
		"""
		if not udon_utils.type_check([
				(channel, str),
				(num, int)]):
			error('Invalid type:message - c_mark_msg_as_read()')
			return FAILURE

		if not channel.startswith('chan_'):
			error('c_mark_msg_as_read(): invalid channel name')
			return FAILURE

		db_path = self.client_db_path
		query = f"UPDATE {channel} SET NEW_MSG = 'FALSE' WHERE ID = {num};"
		rtn = udon_DB.run_db_commit(query=query, db_path=db_path)
		if rtn != FAILURE:
			return SUCCESS


	def read_range(self, start, local_count, table, read_unread=False) -> list:
		"""
			Reatd/Print a range of messages from the client's local DB
			Return: list of messages on success
			        None on error
			todo: happsn on client rename to c_?
		"""
		if not udon_utils.type_check([
				(start, int),
				(local_count, int),
				(table, str),
				(read_unread, bool)]):
			error('Invalid type:message - c_mark_msg_as_read()')
			return None

		msg_list = []
		NOT_VALID = "\033[0;31;48m[!]\033[0m"
		VALID = "\033[0;32;48m[V]\033[0m"

		if read_unread == True:
			start = 1

		for i in range(start, local_count+1):
			rtn = udon_DB.read_msg_table_entry(self.client_db_path,
													table, i)
			if rtn == []:
				error('No messages.')
				return []

			if read_unread == True:
				unread_value = rtn[0][6]
				if unread_value != 'TRUE':
					continue

			sk = rtn[0][7]
			sym_key = self.c_decrypt_bstring_with_key(sk)

			msg_num = rtn[0][0]
			time_stamp = self.c_decrypt_bstring_with_sym_key(rtn[0][1], sym_key)
			time_stamp = time_stamp.decode("utf-8")
			if time_stamp == None:
				error("message timestamp == None")
				return None

			source = self.c_decrypt_bstring_with_sym_key(rtn[0][2], sym_key)
			source = source.decode("utf-8")
			if source == None:
				error("message source == None")
				return None

			msg = self.c_decrypt_bstring_with_sym_key(rtn[0][3], sym_key)
			msg = msg.decode("utf-8")
			if msg == None:
				error("message msg == None")
				return None

			# TODO this needs fixing
			# source should be md5
			source = self.hash_to_keyname[source]

			signature = rtn[0][4]
			signature = self.c_decrypt_bstring_with_sym_key(rtn[0][4], sym_key)
			validation = self.c_verify_signature(signature,
								msg.encode(), source)

			channel = self.c_decrypt_bstring_with_sym_key(rtn[0][5], sym_key)
			channel = channel.decode("utf-8")
			if channel == None:
				error("message channel == None")
				return None

			validity = NOT_VALID
			if validation == True:
				validity = VALID

			# TRranslate MD5 to pub key name
			msg_as_lst = [i, time_stamp, validity, source, channel, msg]
			msg_list.append(msg_as_lst)

			chan = f"chan_{channel}"
			rtn = self.c_mark_msg_as_read(chan, i)
			if rtn != SUCCESS:
				error('read_range() - mark_msg_as_read() failure')
				return None
		return msg_list


	def c_read(self, table: str, num: int, read_unread=False) -> list:
		"""
			0. get local table row count
		"""
		if not udon_utils.type_check([
				(table, str),
				(num, int),
				(read_unread, bool)
				]):
			error('Invalid type:message - c_read()')
			return None

		NOT_VALID = "\033[0;31;48m[!]\033[0m"
		VALID = "\033[0;32;48m[V]\033[0m"

		local_count = udon_DB.table_row_count(self.client_db_path,
													table)
		if local_count == None:
			error("c_read(): table_row_count() return error")
			return None

		if local_count < 0:
			error("c_read(): table_row_count() return -1 ??")
			return None

		if read_unread == True:
			return self.read_range(1, local_count, table, read_unread)
		else:
			if local_count > 0:
				diff = local_count - num
				start = diff + 1
				if start == 0 or start < 0:
					start = 1
				return self.read_range(start, local_count, table, read_unread)
		return None


	def c_check_sync(self, first: int, last: int, diff: int, quiet: bool) -> int:
		"""
			Fetch series of messages from first to last
			Return positive integer on success, -1 on error
		"""
		if not udon_utils.type_check([
				(first, int),
				(last, int),
				(diff, int)]):
			error("Invalid type:message - c_poll_sync()")
			return -1

		nr_synced = 0
		for i in range(first, last):
			uuid = udon_utils.generate_uuid()
			uuid = uuid.encode()
			uuid_sig = self.c_sign_bstring(uuid, self.key_name)
			if not uuid_sig:
				error("c_check_sync(): c_sign_bstring()")
				return -1

			try:
				kpath = self.key_paths[self.key_name]
				md5 = udon_utils.utl_file_md5(kpath)
				key_id = md5.encode()
				value = str(i).encode()
			except Exception as e:
				error(f"c_check_sync():{e}")
				return -1

			""" Fetch message from server """
			response = self.c_msg_fetch(bval=value, breq_src=key_id,
							   breq_uuid_sig=uuid_sig, breq_uuid=uuid)
			if response == None:
				return -1

			""" Decrypt sym_key with private key"""
			sym_key = self.c_decrypt_bstring_with_key(response.symetric_key)

			""" Decrypt channel with sym_key """
			channel = self.c_decrypt_bstring_with_sym_key(response.channel, sym_key)
			if channel == None:
				error("c_poll_sync(): resp channel:")
				return -1
			channel = channel.decode('utf-8')
	
			""" Write message to local primary table """
			rtn = udon_DB.write_msg_table_entry(db_path=self.client_db_path,
											table=self.key_name,
											time=response.time,
											src=response.source,
											msg=response.payload,
											msgsig=response.signature,
											channel=response.channel,
											symetric_key=response.symetric_key,
											digest="".encode(),
											parts="".encode(),
											channel_table=False)
			if rtn == 1:
				error(f"c_poll_synce() - [1] write_msg_table_entry failure")

			chan_table_name = f"chan_{channel}"
			if not udon_DB.table_exist(self.client_db_path, chan_table_name):
				rtn = udon_DB.init_client_chan_table(self.client_db_path,
										 				chan_table_name)
				if rtn != 0:
					error("c_poll_sync() - init_client_chan_table() failued")
					return FAILURE

			""" Write message to local channel table """
			rtn = udon_DB.write_msg_table_entry(db_path=self.client_db_path,
											table=chan_table_name,
											time=response.time,
											src=response.source,
											msg=response.payload,
											msgsig=response.signature,
											channel=response.channel,
											symetric_key=response.symetric_key,
											digest="".encode(),
											parts="".encode(),
											channel_table=True)
			if rtn == FAILURE:
				error(f"c_check_sync() - [2] write_msg_table_entry failure")
				return -1
			nr_synced = nr_synced + 1

		if not quiet:
			output(f"Sync'd: {nr_synced}")
		return diff


	def local_remote_count(self):
		"""
			Return local/remote message counts and difference 
			return tuple (local, remote, diff)
			return (-1,-1,-1) on error
		"""
		req_uuid = udon_utils.generate_uuid()
		uuid_sig = self.c_sign_bstring(req_uuid.encode(), self.key_name)
		if uuid_sig == None:
			error("local_remote_count() - uuid_siq = None")
			return (-1,-1,-1)
		req_uuid = req_uuid.encode()

		key_name = self.key_name.encode()
		if key_name == None:
			error("local_remote_count() - key_name = None")
			return 	(-1,-1,-1)

		key_path = self.key_paths[self.key_name]
		md5_key_name = udon_utils.utl_file_md5(key_path)
		md5_key_name = md5_key_name.encode()

		resp = self.c_msg_check(breq_src=md5_key_name, breq_uuid_sig=uuid_sig,
								breq_uuid=req_uuid)
		if resp == None:
			error("lrc() - udon_client:c_poll(): c_msg_check() returned None")
			return (-1,-1,-1)

		nr_msgs = resp.value
		if nr_msgs == None:
			return (-1,-1,-1)

		remote_msg_count = nr_msgs.decode("utf-8")
		if not udon_utils.is_int(remote_msg_count):
			error(f"lrc: server_msg_count not integer {remote_msg_count}")
			return (-1,-1,-1)

		local_msg_count = udon_DB.table_row_count(self.client_db_path,
													self.key_name)

		diff = 0
		if int(remote_msg_count) > int(local_msg_count):
			diff = int(remote_msg_count) - int(local_msg_count)
		return (local_msg_count, remote_msg_count, diff)


	def c_poll(self, sync=False, quiet=False) -> int:
		"""
		 	AKA check()
			returns message count of user's table
			return -1 on error
			return >0 on success
		"""
		NOT_VALID = "\033[0;31;48m[!]\033[0m"
		VALID = "\033[0;32;48m[V]\033[0m"
		validity = NOT_VALID

		if not self.c_ping():
			if not quiet:
				error(f"c_poll():Connection to server:{self.server_fqdn} Failed.")
			return False

		""" Determine message count from server """
		local_msg_count, server_msg_count, diff = self.local_remote_count()
		if sync == False:
			if not quiet:
				output(f" Key: {self.key_name} - Local:{str(local_msg_count)} Remote:{str(server_msg_count)}")
		else:
			last = int(server_msg_count) + 1
			if local_msg_count == 0:
				first = 1
			else:
				first = int(local_msg_count) + 1
			self.c_check_sync(first, last, diff, quiet)
		return diff


class udon_server(pb2_grpc.UnaryServicer):

	def __init__(self):
		debug("udon_server.__init__()")

		home_dir = udon_utils.home_dir()
		if home_dir == None:
			error("udon_server().__init__() -  home_dir() returned None")
			sys.exit(1)

		self.config_path = f"{home_dir}/{UDON_DIR}/server.conf"
		self.cfg = config.Config(self.config_path)

		self.key_paths = {}
		self.keys_dict = {}
		self.srv_db_path = self.cfg["server_db_path"]
		self.ssl_cert_key = self.cfg["ssl_cert_key"]
		self.ssl_cert = self.cfg["ssl_cert"]

		self.conform_server_side_keys()
		self.s_load_pub_keys()

		rtn = udon_DB.init_uuid_table(self.srv_db_path)
		output(f"udon_DB.init_uuid_table() returned {rtn}")
		if rtn != 0:
			error(f"udon_server.__init__() - init_uuid_tables() Failures")

		output("Keys loaded", to_file=True)
		output(f"Using Database at: {self.srv_db_path}" , to_file=True)
		output(f"Using SSL Cert: {self.ssl_cert}", to_file=True)
		output(f"Using SSL Cert Private Key (CA): {self.ssl_cert_key}", to_file=True)


	def s_start_server(server):
		debug("s_start_server()")

		home_dir = udon_utils.home_dir()
		if home_dir == None:
			error("udon_server.s_start_server() -  home_dir() returned None", True)
			sys.exit(1)

		cfg = f"{home_dir}/{UDON_DIR}/server.conf"
		cfg = config.Config(cfg)

		port = cfg["server_port"]
		srv_port = '[::]:'+port
		output("Serving on port: "+srv_port)
		ssl_cert_key = f"{home_dir}/{UDON_TLS_DIR}/localhost.key"
		ssl_cert = f"{home_dir}/{UDON_TLS_DIR}/localhost.crt"

		if not os.path.exists(ssl_cert_key) and os.path.exists(ssl_cert):
			error(f"Keys not found!\n {server.ssl_cert_key}\n {server.ssl_cert}", True)
			sys.exit(1)
		else:
			output(f"Found ssl_cert_key: {server.ssl_cert_key}", True)
			output(f"Found ssl_cert: {server.ssl_cert}", True)

		SERVER_CERTIFICATE_KEY = udon_utils.load_credential_from_file(ssl_cert_key)
		SERVER_CERTIFICATE = udon_utils.load_credential_from_file(ssl_cert)

		# TLS Server
		server = grpc.server(futures.ThreadPoolExecutor(max_workers=2))
		pb2_grpc.add_UnaryServicer_to_server(udon_server(), server)

		server_credentials = grpc.ssl_server_credentials(
			(
				(
					SERVER_CERTIFICATE_KEY,
					SERVER_CERTIFICATE,
				),
			)
		)
	
		_LISTEN_ADDRESS_TEMPLATE = "0.0.0.0:"+ str(int(port))
		output(_LISTEN_ADDRESS_TEMPLATE)
		server.add_secure_port(_LISTEN_ADDRESS_TEMPLATE, server_credentials)
		server.start()
		server.wait_for_termination()


	def conform_server_side_keys(self,) -> bool:
		"""
			Search server side keys directory, abd
			rename public key files to be the md5sum of the file itself.
		"""
		home_dir = udon_utils.home_dir()
		ssk_dir = f"{home_dir}/.udon/keys/server_side_keys"

		key_lst = os.listdir(ssk_dir)
		if len(key_lst) < 1:
			return True

		for key in key_lst:
			path = f"{ssk_dir}/{key}"
			key_data = None
			with open(path, "r") as fd:
				key_data = fd.read()

			hash = hashlib.md5(key_data.encode()).hexdigest()
			hpath = f"{ssk_dir}/{hash}"
			if hpath != path:
				os.rename(path, hpath)
		return True


	def s_load_pub_keys(self) -> bool:
		"""
		 todo: try or return false
		"""
		home_dir = udon_utils.home_dir()
		srv_side_key_dir = f"{home_dir}/.udon/keys/server_side_keys/"
		klst = os.listdir(srv_side_key_dir)
		for k in klst:
			with open(f"{srv_side_key_dir}/{k}") as fd:
				key_data = fd.read()
				self.keys_dict[k] = key_data
		return True


	def s_load_config(self, cfg: dict) -> bool:
		"""
			Load config profile
			Returns: bool
		"""
		debug("s_load_config()")
		types_lst = [(type(cfg), type(config.Config))]
		if not udon_utils.type_check(types_lst):
			return False

		self.config        = cfg
		self.srv_db_path   = self.config["server_db_path"]
		return True


	def s_load_client_pub_key(self, key_path: str) -> str:
		"""
			Load public key of client
			Returns: str
		"""
		debug("s_load_client_pub_key()")
		if not udon_utils.type_check([(key_path, str)]):
			error("Invalid inputs - s_load_client_pub_key()", True)
			return None
		return udon_utils.utl_load_pub_key(key_path)


	"""
		Verify byte string was signed by sender
	"""
	def s_verify_signature(self, sig: bytes, message: bytes,
							key_id: str) -> bool:
		# verify types
		debug("s_verify_signature()")
		key_path = None
		home_dir = udon_utils.home_dir()

		if key_id in self.keys_dict.keys():
			key_path = f"{home_dir}/.udon/keys/server_side_keys/{key_id}"
		else:
			return False

		if not os.path.exists(key_path):
			error(f"s_verify_signature() - key_path not found: {key_path}")
			return Fasle
		return udon_utils.utl_verify_signature(self, sig, message, key_path)


	def _verify_request(self, request, op="unknown") -> tuple:
		"""
			Verify request id is unique.
			Verify request is from valid user.
			Returns: (bool, dict, str)
		"""
		debug("\nreq_prereq_verify()")

		msg_sig = request.signature
		if not msg_sig:
			# verify tyoe
			err = f"Error: {op}() - missing arg: signature".encode()
			err_resp = {"error":err}
			error(f"A _verify_request() returning: (False, {err_resp})", True)
			return (False, err_resp, None)

		sender_key_id = request.key_id
		if not sender_key_id:
			# verify type
			err = f"Error: {op}() - missing arg: key_id".encode()
			err_resp = {"error":err}
			error(f"B _verify_request() returning: (False, {err_resp})", True)
			return (False, err_resp, None)

		req_uuid = request.uuid
		if not req_uuid:
			# verify type
			err = f"Error: {op}() - missing arg: uuid".encode()
			err_resp = {"error":err}
			error(f"C _verify_request() returning: (False, {err_resp})", True)
			return (False, err_resp, None)

		type_check_ok = udon_utils.type_check([(request.signature, bytes),
						 		(request.key_id, bytes),
								 (request.uuid, bytes)])
		if not type_check_ok:
			err = f"Error: {op}() - Type check failed".encode()
			err_resp = {"error":err}
			return (False, err_resp, None)

		key_id = sender_key_id.decode('utf-8')

		if not key_id in self.keys_dict.keys():
			self.conform_server_side_keys()
			self.s_load_pub_keys()
			if not key_id in self.keys_dict.keys():
				err = f"Error: {op}() - public key for key_id {key_id} [key_dict] not found".encode()
				err_resp = {"error":err}
				error(f"D _verify_request() returning: (False, {err_resp})", True)
				return (False, err_resp, None)

		# redundant?
		if not key_id in self.keys_dict.keys():
			err = f"Error: {op}() - public key for key_id {key_id} [key_dict] not found".encode()
			err_resp = {"error":err}
			error(f"F _verify_request() returning: (False, {err_resp})", True)
			return (False, err_resp, None)

		valid_signature = self.s_verify_signature(sig=msg_sig, message=req_uuid, key_id=key_id)
		if not valid_signature:
			err = f"Error: {op}():{valid_signature} - s_verify_signature()".encode()
			err_resp = {"error":err}
			error(f"G _verify_request() returning: ({valid_signature}, {err_resp})", True)
			return (False, err_resp, None)

		""" verify UUID is unique to previous requests """
		r = udon_DB.replayed_uuid(self.srv_db_path, "UUID", req_uuid.decode("utf-8"))
		if r == -1:
			err = f"Error: {op}() - replayed_uuid() returned error".encode()
			err_resp = {"error":err}
			error(f"H _verify_request() returning: (False, {err_resp}, None)", True)
			return (False, err_resp, None)

		if r > 0:
			reqid = req_uuid.decode('utf-8').replace("-","")
			err = f"Error: {op}() - replayed_uuid() {reqid}".encode()
			err_resp = {"error":err}
			error(f"I _verify_request() returning: (False, {err_resp}, None)", True)
			return (False, err_resp, None)

		""" write UUID to DB """
		rtn = udon_DB.write_uuid_entry(db_path=self.srv_db_path, uid=req_uuid.decode('utf-8'))
		if rtn == 1:
			error("J _verify_request() failed write_uuid_entry()", True)
			err_resp = {"error":f"Error: {op}() - write_uuid_entry() {req_uuid}",}
			return (False, err_resp, None)
		return (True, None, key_id)


	def fetch(self, request, context):
		"""
			Server side RPC to request message
			keyword arguments:
			request: proto request

			Pull the message from DB and return it
			request.signature
			request.value
			request.key_id
			request.uuid
		"""
		debug("\fetch()")
		row_entry = ''

		success, err_msg, key_id = self._verify_request(request, op="fetch")
		if success == False:
			error(f"fetch:req_prereq_verify() -> {success}, {err_msg}, {key_id}", True)
			return pb2.MessageResponse(**err_msg)

		cipher_value = request.value
		if len(cipher_value) == 0:
			err_resp = "Error: fetch() - missing arg: value".encode()
			MessageResponse = {"error":err_resp}
			return pb2.MessageResponse(**MessageResponse)
		msg_num = cipher_value.decode('utf-8')

		if not udon_utils.is_int(msg_num):
			error("fetch() - non-int msg_num", True)
			err_resp = "Error: fetch() - non-int msg_num".encode()
			MessageResponse = {"error":err_resp}
			return pb2.MessageResponse(**MessageResponse)
		msg_num = int(msg_num)

		""" Returned format is [(row, time, src, payload)]"""
		rtn = udon_DB.read_msg_table_entry(db_path=self.srv_db_path,
											table=key_id,
											id=msg_num)

		if len(rtn) == 1:
			row_entry = rtn[0]
		else:
			error("fetch() - read_msg_table_entry(): no data returned", True)
			err_resp = "Error: fetch() - read_msg_table_entry(): no data returned".encode()
			MessageResponse = {"error":err_resp}
			return pb2.MessageResponse(**MessageResponse)

		rtn_time       = row_entry[1]
		rtn_src_sender = row_entry[2]
		rtn_bpayload   = row_entry[3]
		rtn_signature  = row_entry[4]
		rtn_channel    = row_entry[5]
		rtn_sym_key    = row_entry[6]

		MessageResponse = {
			"response":b"",
			"time":rtn_time,
			"payload":rtn_bpayload,
			"source":rtn_src_sender,
			"signature":rtn_signature,
			"channel":rtn_channel,
			"symetric_key":rtn_sym_key,
			"error":b""
			}
		return pb2.MessageResponse(**MessageResponse)


	def ping(self, request, context):
		"""
		"""
		response = {"status":"true".encode(),}
		return pb2.PingResponse(**response)


	def check(self, request, context):
		"""
			server side RPC check
			Retruns byte string in format of:

			Request
				- request.key_id
				- request.signature for clear text of message uuid
				- request.error
    	"""
		debug("\ncheck()")
		success, err_msg, key_id = self._verify_request(request, op="check")
		if success == False:
			error(f"check:req_prereq_verify() -> {success}, {err_msg}, {key_id}", True)
			return pb2.CheckRequestResponse(**err_msg)

		rows = str(udon_DB.table_row_count(self.srv_db_path, key_id))
		if rows == None or not udon_utils.is_int(rows):
			CheckRequestResponse = {"error":"Invalid_row_count".encode()}
			return pb2.CheckRequestResponse(**CheckRequestResponse)
		bmsg_count = rows.encode()

		CheckRequestResponse = {"value":bmsg_count, "signature":"".encode(), "error":"".encode()}
		return pb2.CheckRequestResponse(**CheckRequestResponse)


	def clean(self, request, context):
		"""
			Server side RPC
			Clean (scrub) data from user table
			Keyword arguments:
			request - proto CleanRequest
		
			Return: pb2.CleanResponse
		"""
		debug("clean()")
		success, err_msg, key_id = self._verify_request(request, op="clean")
		if success == False:
			error(f"clean:req_prereq_verify() -> {success}, {err_msg}, {key_id}", True)
			return pb2.CleanRequestResponse(**err_msg)

		msg_count = request.clean_count.decode('utf-8')
		if not len(msg_count) > 0:
			output(f"clean(): msg_count null length")
			err_resp = {"error":"clean(): clean_count null length"}
			return pb2.CleanRequestResponse(**err_resp)

		try:
			msg_count = int(msg_count)
		except Exception as e:
			err_resp = {"error":"clean(): msg_count not integer"}
			return pb2.CleanRequestResponse(**err_resp)

		rtn = udon_DB.clean_msgs_in_primary_table(db_path=self.srv_db_path,
											table=key_id, clean_count=msg_count)
		if rtn != 0:
			error(f"clean() - clean_msgs_in_primary_table() non-zero return", True)
			rtn_msg = {"error":f"Error: clean() - clean_msgs_in_primary_table() non-zero return".encode(),}
			return pb2.CleanResponse(**rtn_msg)

		rtn_msg = {"error":"".encode(),}
		return pb2.CleanResponse(**rtn_msg)


	def commit(self, request, context):
		"""
			Server side RPC
			Commit message to server side DB
			Returns: Message response

			Keyword arguments:
			request -- 
			context -- 
			Sabaton - metal band?
		"""
		debug("\ncommit()")
		success, err_msg, key_id = self._verify_request(request, op='commit')
		if success == False:
			error(f"err commit(): _verify_request() - {success}, {err_msg}, {key_id}")
			return pb2.MessageResponse(**err_msg)

		type_check_ok = udon_utils.type_check([(request.destination, bytes),])
		if not type_check_ok:
			err = f"Error: commit() - typecheck".encode()
			err_resp = {"error":err}
			error(f"commit(): type_check")
			return pb2.MessageResponse(**err_resp)

		""" Verify destination arg """
		req_dest = request.destination
		if not req_dest:
			err = f"Error: commit() - missing arg: distination".encode()
			err_resp = {"error":err}
			error(f"commit(): commit() - missing arg: distination")
			return pb2.MessageResponse(**err_resp)
		dest_key_id = req_dest.decode('utf-8')

		""" Create DB Table if it doesn't exist - table name is des_key_id """
		rtn = udon_DB.init_primary_table(self.srv_db_path, dest_key_id)
		if rtn != 0:
			error(f"init_primary_tables() Failures {dest_key_id.decode('utf-8')}")

		# Write entry to table
		rtn = udon_DB.write_msg_table_entry(db_path=self.srv_db_path,
										table=dest_key_id,
										time=request.time,
										src=request.source,
										msg=request.payload,
										msgsig=request.msg_signature,
										channel=request.channel,
										digest="".encode(),
										parts="".encode(),
										symetric_key=request.symetric_key)

		if rtn != 0:
			error(f'Error: commit() - write_msg_table_entry', True)
			err_resp = f'Error: commit() - write_msg_table_entry'.encode()
			rtn_msg = {'error':err_resp}
			return pb2.MessageResponse(**rtn_msg)

		""" Send Response """ 
		rtn_msg = {'response':b'Payload Written',
			'payload':b'Payload Written',
			'source':b'Source Written',
			'error':'x'.encode()}

		return pb2.MessageResponse(**rtn_msg)


class udon_utils:
	def home_dir() -> str:
		"""
			Returns: home dir string on success, otherwise None
		"""
		hd = pathlib.Path.home().resolve()
		if hd:
			return str(hd)
		return None


	def generate_uuid() -> str:
		"""
			Generate a Universal Unique ID
			returns string
		"""
		id = None
		try:
			id = str(uuid.uuid4())
		except Exception as e:
			error(f"Error: generate_uuid(): {e}")
			return None
		return id


	def is_int(input) -> bool:
		"""
			public
			Test if argument is an integer
			reutrn True/False
		"""
		try:
			x = int(input)
		except :
			return False
		return True


	def utl_load_priv_key(key_path: str) -> str:
		"""
			load private key
			Keyword arguments:
			key_path -- string: filesystem path of key
			Returns string on success
			None on Error
		"""
		debug("udon_utils.utl_load_priv_key()")
		if not udon_utils.type_check([(key_path, str)]):
			return None

		if not os.path.exists(key_path):
			error(f"Error: utl_load_priv_key() - Path not exists: {key_path}")
			return None

		try: 
			with open(key_path, "rb") as key_file:
				kf = key_file.read()
				pk = serialization.load_pem_private_key(kf, password=None,)
				if str(kf) == "" or pk == "":
					return None
				return pk 
		except Exception as e:
			error(str(e))
			return None


	def utl_load_pub_key(key_path: str) -> str:
		"""
			Load public key
			Keyword arguments:
			key_path -- string: filesystem path of key
			Returns string on success
			None on Error
		"""
		debug("udon_utils.utl_load_pub_key()")
		if not udon_utils.type_check([(key_path, str)]):
			return None

		if key_path == "":
			error(f"Error: {key_path} == "" - utl_load_pub_key()")
			return None

		if not os.path.exists(key_path):
			error(f"Error: {key_path} not exist - utl_load_pub_key()")
			return None

		pk = None
		try :
			with open(key_path, "rb") as key_file:
				kf = key_file.read()
				pk = serialization.load_pem_public_key(kf,
										   	key_file.read(),
											# password=None,
											# backend=default_backend()
										   )

				if str(kf) == "" or pk == "":
					return None
		except Exception as e:
			error(str(e))
			return None
		return pk


	def utl_file_md5(key_path: str) -> str:
		"""
			Fetch md5sum of file
			Keyword arguments:
			key_path --

			Returns string on success
			None on Error
		"""
		debug("utl_file_md5()")
		if not udon_utils.type_check([(key_path, str)]):
			return None

		if key_path == "":
			error(f"Error: {key_path} == "" - utl_load_pub_key()")
			return None

		if not os.path.exists(key_path):
			error(f"Error: {key_path} not exist - utl_load_pub_key()")
			return None

		hash = None
		try :
			with open(key_path, "rb") as fd:
				data = fd.read()
				hash = hashlib.md5(data).hexdigest()
		except Exception as e:
			error(str(e))
			return None
		return hash


	def type_check(lst: list) -> bool:
		"""
			Verify arg are intended type

			Keyword arguments:
			lst : list of tuples
			[(A,type),(B,type)]
		"""
		count   = 0
		lst_nr  = len(lst)
		err_lst = []

		if not type(lst) is list:
			error("Error: invalid type: lst - type_check()")
			return False

		for i in range(lst_nr):
			A = str(type(lst[i][0]))
			B = str(lst[i][1])
			if A == B:
				count = count + 1
			else:
				err_lst.append(f"Error: invalid type:arg {i}")

		if count == lst_nr:
			return True
		else:
			error(str(lst))
			for err in err_lst:
				error(err)
		return False


	def utl_verify_signature(self, sig: bytes, message: bytes, key_path: str) -> bool:
		"""
			Verify public key cryptographically verifies message and signature 
			Returns bool
		"""
		debug('utl_verify_signature()')
		if not udon_utils.type_check([(sig, bytes),(message, bytes),
								(key_path, str)]):
			error('Error: Invalid inputs - s_verify_signature()')
			return False

		if not os.path.exists(key_path):
			return False
		
		public_key = udon_utils.utl_load_pub_key(key_path)
		if public_key == None:
			error(f"utl_verify_signature() - utl_load_pub_key() returned: None")
			return False

		try:
			public_key.verify(sig, message,
							padding.PSS(
							mgf=padding.MGF1(hashes.SHA256()),
							salt_length=padding.PSS.MAX_LENGTH),
							hashes.SHA256())
		except Exception as e:
			error(str(e))
			return False
		return True


	def load_credential_from_file(filepath):
		"""
			return credential from file
			return None on error
		"""
		if not os.path.exists(filepath):
			error(f"load_credential_from_file(): file not found {filepath}")
			return None

		real_path = os.path.join(os.path.dirname(__file__), filepath)
		with open(real_path, "rb") as f:
			return f.read()


class udon_DB:

	def open_db_connection(db_path: str):
		if not udon_utils.type_check([(db_path, str)]):
			return None

		conn = None
		try:
			conn = sqlite3.connect(db_path)
		except Exception as e:
			error(f"Error: udon_DB.open_db_connection():{db_path} -- {e}")
			return None
		return conn


	def run_db_commit(query: str, db_path: str) -> int:
		if not udon_utils.type_check([(query, str),
									(db_path, str)]):
			return FAILURE
		
		conn = udon_DB.open_db_connection(db_path=db_path)
		if conn == None:
			return FAILURE

		try:
			cur = conn.cursor()
			cur.execute(query)
			conn.commit()
			conn.close()
		except Exception as e:
			conn.close()
			error(f"Error: udon_DB.run_db_commit(): query:{query} - {e}")
			return FAILURE
		return SUCCESS


	def run_db_commit_values(query: str, values: tuple, db_path: str) -> int:
		if not udon_utils.type_check([(query, str),
									(values, tuple),
									(db_path, str)]):
			return FAILURE

		conn = udon_DB.open_db_connection(db_path=db_path)
		if conn == None:
			return FAILURE

		try:
			cur = conn.cursor()
			cur.execute(query, values)
			conn.commit()
			conn.close()
		except Exception as e:
			conn.close()
			error(f"Error: udon_DB.run_db_commit_values() - query: {e}")
			return FAILURE
		return SUCCESS


	def run_db_fetch(query: str, db_path: str) -> list:
		"""
			return records list,
			None on error
		"""
		if not udon_utils.type_check([(query, str), (db_path, str)]):
			error('Error: input error - run_db_fetch()')
			return None

		records = None
		conn = udon_DB.open_db_connection(db_path=db_path)
		if conn == None:
			return None

		try:
			cur = conn.cursor()
			cur.execute(query)
			""" recodes format: ____ """
			records = cur.fetchall()
			conn.close()
		except Exception as e:
			conn.close()
			error(f"Error: read_msg_table_entry(): - {e}")
			return None
		return records


	def	init_client_chan_table(path: str, table: str) -> int:
		"""
			Create channel table on client.

			User Table:
			ID -- primary key
			TIME -- timestamp
			SRC -- source user
			DEST -- destination user
			MSG -- message
			MSGSIG -- message signature
			CHANNEL -- channel name
			NEW_MSG -- New Message marker.
			KEY -- symetric key
			digest -- md5sum actually
			PARTS -- number of parts of uploaded file
			returns: 0/1 (success/failure)
		"""
		debug('init_client_chan_table()')
		if not udon_utils.type_check([(path, str), (table, str)]):
			error('Error: input error - init_client_chan_table()')
			return FAILURE

		init_chan_table = f"""CREATE TABLE IF NOT EXISTS "{table}" (
						ID integer PRIMARY KEY AUTOINCREMENT,
						TIME blob NOT NULL,
						SRC blob,
						MSG blob,
						MSGSIG blob,
						CHANNEL blob,
						NEW_MSG blob,
						KEY blob,
						DIGEST blob,
						PARTS blob);"""
		return udon_DB.run_db_commit(init_chan_table, db_path=path)


	def	init_primary_table(path: str, table: str) -> int:
		"""
			Keyword arguments:
		"""
		debug("init_primary_table()")
		if not udon_utils.type_check([(path, str), (table, str)]):
			error('Error: udon_DB.init_primary_table() type_check()')
			return FAILURE

		init_table = f"""CREATE TABLE IF NOT EXISTS "{table}" (
						ID integer PRIMARY KEY AUTOINCREMENT,
						TIME blob NOT NULL,
						SRC blob,
						MSG blob,
						MSGSIG blob,
						CHANNEL blob,
						KEY blob,
						DIGEST blob,
						PARTS blob);"""
		return udon_DB.run_db_commit(init_table, db_path=path)


	def	init_uuid_table(path: str) -> int:
		debug('init_db_table()')
		if not udon_utils.type_check([(path, str)]):
			error('Error: input error - init_db_table()')
			return FAILURE

		uuid_table = f"""CREATE TABLE IF NOT EXISTS UUID (
						UUID TEXT);"""
		return udon_DB.run_db_commit(uuid_table, db_path=path)


	def write_msg_table_entry(db_path: str, table: str, time: bytes, 
								src: bytes, msg: bytes, msgsig: str, 
								channel: bytes, 
								symetric_key: bytes,
								digest: bytes,
								parts: bytes,
								channel_table=False) -> int:
		"""
			Write row into table

			Keyword arguments:
			db_path - string
			table   - string
			time    - bytes
			src     - bytes
			msg     - bytes
			msgsig  - bytes
			channe  - bytes
			symetric_key - bytes
			digest - bytes
			parts - bytes
			channel_table - bool

			returns: 0/1
		"""
		debug('write_msg_table_entry()')
		if not udon_utils.type_check([
			(db_path, str),
			(table, str),
			(time, bytes),
			(src, bytes),
			(msg, bytes),
			(msgsig, bytes),
			(channel, bytes),
			(symetric_key, bytes),
			(digest, bytes),
			(parts, bytes),
			(channel_table, bool),
			]):
			error('Error: invalid type - udon_DB.write_msg_table_entry()')
			return FAILURE

		sql_write_row = ""
		if channel_table == False:
			sql_write_row = f"""INSERT INTO "{table}" (TIME, SRC, MSG, MSGSIG, CHANNEL, KEY, DIGEST, PARTS)
									VALUES(?,?,?,?,?,?,?,?);"""
			values = (time, src, msg, msgsig, channel, symetric_key, digest, parts)
		else:
			sql_write_row = f"""INSERT INTO "{table}" (TIME, SRC, MSG, MSGSIG, CHANNEL, NEW_MSG, KEY, DIGEST, PARTS)
									VALUES(?,?,?,?,?,?,?,?,?);"""
			values = (time, src, msg, msgsig, channel, "TRUE", symetric_key, digest, parts)

		return udon_DB.run_db_commit_values(sql_write_row, values=values, db_path=db_path)


	def read_msg_table_entry(db_path: str, table: str, id: int) -> list:
		"""
			Read Row from db

			Keyword arguments:
			db_path - string
			table - string
			id - int

			return [] on values out of db range (error)
			# goody
		"""
		debug('read_msg_table_entry()')
		if not udon_utils.type_check(
			[(db_path, str),
			(table, str),
			(id, int)]):
			error('Error: invalid type - read_msg_table_entry()')
			return []

		records = []

		try:
			tmp = int(id)
		except:
			error('Error: type error: id - int')
			return []

		conn = udon_DB.open_db_connection(db_path=db_path)
		if conn == None:
			return []

		if not udon_DB.table_exist(db_path=db_path, table=table):
			conn.close()
			return []
		conn.close()

		sql_read_row = f"""SELECT * FROM "{table}" WHERE ID={id};"""
		records = udon_DB.run_db_fetch(query=sql_read_row, db_path=db_path)
		if records == None:
			return []
		return records


	def channel_new_msg_count(db_path: str, table: str) -> int:
		"""
			Count the 'NEW_MSG' column, where the value = 'TRUE'

			Keyword arguments:
			db_path - string
			table - string
			
			return integer 
		"""
		debug('read_msg_table_entry()')
		if not udon_utils.type_check([
			(db_path, str),
			(table, str)]):
			error('Error: count_new_msgs(): type check')
			return -1

		conn = udon_DB.open_db_connection(db_path=db_path)
		if conn == None:
			return -1

		if not udon_DB.table_exist(db_path=db_path, table=table):
			conn.close()
			return -1

		sql_read_row = f"""SELECT COUNT() FROM "{table}" WHERE NEW_MSG='TRUE';"""
		records = udon_DB.run_db_fetch(query=sql_read_row, db_path=db_path)
		if records == None:
			conn.close()
			return -1
		conn.close()

		"""records = [(n,)]"""
		if len(records) == 1:
			if len(records[0]) == 1:
				records = records[0][0]
			else:
				records = 0
		else:
			records = 0
		return records


	def table_row_count(db_path: str, table: str) -> int:
		"""
			Get the integer row count of a db table
		
			Keyword arguments:
			db_path - str
			table - str

			Returns: int on success
					None on failure
		"""
		debug('table_row_count()', enable=False)
		if not udon_utils.type_check([(db_path, str),
										(table, str)]):
			error('Error: invalid type - table_row_count()')
			return None

		conn = udon_DB.open_db_connection(db_path=db_path)
		if conn == None:
			error("table_row_count(): open_db_connection() returned None")
			return None
		conn.close()

		if not udon_DB.table_exist(db_path=db_path, table=table):
			# error(f"table_row_count() udon_DB.table_exist() {db_path} {table} - False")
			return 0

		sql_read_row = f"""SELECT COUNT() FROM "{table}";"""
		records = udon_DB.run_db_fetch(query=sql_read_row, db_path=db_path)
		if records == None:
			error("table_row_count(): udon_DB.run_db_fetch() returned error ")
			return None
		return records[0][0]


	def channel_table_exists(db_path: str, channel: str):
		if not udon_utils.type_check([(db_path, str), (channel, str)]):
			error('Error: input type error')
			return False
		if not channel.startswith("chan_"):
			channel = f"chan_{channel}"
		return udon_DB.table_exist(db_path, channel)


	def table_exist(db_path: str, table: str) -> bool:
		"""
			Check if table exists

			Return bool - True/False if Table exists
		"""
		debug('table_exist()')
		if not udon_utils.type_check([(db_path, str), (table, str)]):
			error('Error: input type error')
			return False

		if not os.path.exists(db_path):
			error(f"table_exist() - path does not exist: {db_path}")
			return False

		conn = udon_DB.open_db_connection(db_path=db_path)
		if conn == None:
			error('table_exist() - DB connection failed')
			return None
		conn.close()
		
		sql_read_row = "SELECT name FROM sqlite_master where TYPE='table'"
		records = udon_DB.run_db_fetch(query=sql_read_row, db_path=db_path)
		if records == None:
			False

		for r in records:
			if r[0] == table:
				return True
		return False


	def get_client_db_paths(lst: list) -> list:
		"""
			Return list of file paths in .udon/db directory

			Keyword arguments:
			lst - list of channel config names

			Returns: list on success, None on error
		"""
		if not udon_utils.type_check([(lst, list)]):
			error('Error: input type error')
			return None

		home_dir = udon_utils.home_dir()
		if home_dir == None:
			error('Error: udon_DB.get_client_db_paths() home_dir() return None')
			return None

		rtn = []
		for cfg_name in lst:
			cfg_path = f"{home_dir}/{UDON_CHAN_DIR}/{cfg_name}"
			try:
				cfg = config.Config(cfg_path)
			except Exception as e:
				error(f"Error: udon_DB.get_client_db_paths() opening Config() {cfg_path} {e}")
				return None
			cfg = cfg.as_dict()
			if "client_db_path" in cfg.keys():
				rtn.append(cfg["client_db_path"])
		s = set(rtn)
		rtn = list(s)		
		return rtn


	def get_table_list(db_path: str) -> list:
		"""
			Return list of table names for a database

			Keyword arguments:
			db_path - string

			Returns: list
		"""
		if not udon_utils.type_check([(db_path, str)]):
			error('Error: input type error')
			return None

		rtn = []
		if os.path.exists(db_path):
			table_lst = udon_DB.list_db_tables(db_path=db_path)
			if not table_lst:
				error("get_table_list: list_db_tables() returned None (error)")
		else:
			table_lst = []
		return table_lst


	def get_channel_list():
		"""
			Retrun list of file names in channel_cfgs directory
			Return None on error
		"""
		home_dir = udon_utils.home_dir()
		if home_dir == None:
			error("Error: udon_DB.get_config_list() - home_dir() return None")
			return None

		channels_dir = f"{home_dir}/{UDON_CHAN_DIR}"
		if not os.path.exists(channels_dir):
			error(f"Error: udon_DB.get_config_list() - path not exist {channels_dir}")
			return None

		lst = os.listdir(channels_dir)
		if len(lst) > 0:
			lst = sorted(lst)
		return lst


	def list_db_tables(db_path: str) -> list:
		"""
			Returns list of table names.

			Keyword arguments:
			db_path - string

			Requires init_db called before use.
			returns list
		"""
		debug("list_db_tables()")
		if not udon_utils.type_check([(db_path, str)]):
			error('Error: input type error')
			return None

		rtn = []
		if not udon_utils.type_check([(db_path, str)]):
			error('Error: input type error: db_path : list_db_tables()')
			return []

		if not os.path.exists(db_path):
			error(f"Error: path does not exist: {db_path}")
			return []

		conn = udon_DB.open_db_connection(db_path=db_path)
		if conn == None:
			return []
		conn.close()

		sql_read_row = "SELECT name FROM sqlite_master WHERE type='table';"
		records = udon_DB.run_db_fetch(query=sql_read_row, db_path=db_path)
		if records == None:
			return []

		for rec in records:
			if len(rec) == 1:
				rtn.append(rec[0])
		return rtn


	def dehyphenate_uuid(uid: str):
		if not udon_utils.type_check([(uid, str)]):
			error('Error: input type error')
			return None

		try:
			return uid.replace("-","")
		except Exception as e:
			error(f"dehyphenate_uuid(): {e}")
			return None


	def write_uuid_entry(db_path: str, uid: str) -> int:
		"""
			Write uuid to UUID table
			Requires init_db called before use.

			return 0/1
		"""
		debug('write_msg_table_entry()')
		if not udon_utils.type_check([
			(db_path, str),
			(uid, str)]):
			error('Error: invalid type - write_uuid_entry()')
			return FAILURE

		conn = udon_DB.open_db_connection(db_path=db_path)
		if conn == None:
			error('Error: write_uuid_entry() - failed connection')
			return FAILURE

		exist = udon_DB.table_exist(db_path=db_path, table="UUID")
		if not exist:
			error("UUID Table does not exist")
			return FAILURE

		uid = udon_DB.dehyphenate_uuid(uid)
		if uid == None:
			error("write_uuid_entry(): dehyphenate_uuid returned None")
			return FAILURE

		sql_write_uuid = f"""INSERT INTO UUID VALUES(?);""" 
		values = ([uid])

		try:
			cur = conn.cursor()
			cur.execute(sql_write_uuid, values)
			conn.commit()
			conn.close()
		except Exception as e:
			conn.close()
			error(f"Error: write_uuid_entry {e}")
			return FAILURE
		return SUCCESS


	def replayed_uuid(db_path: str, table: str, uid: str) -> int:
		"""
			Test if arg uid is present in UUID table

			Requires init_db called before use.
			returns:
				 -1 on error
				  0 on False
				 >0 on True
		"""
		debug("replayed_uuid()")
		if not udon_utils.type_check([
			(db_path, str),
			(table, str),
			(uid, str),
			]):
			error('Error: invalid type - replayed_uuid()')
			return -1

		uid = uid.replace("-","")
		sql_read_row = f"""SELECT COUNT() FROM UUID WHERE UUID = '{uid}';"""

		if not udon_DB.table_exist(db_path, table):
			error('replayed_uuid(): - DB Table not found')
			return -1
		
		""" records = [(blah,)] """
		records = udon_DB.run_db_fetch(query=sql_read_row, db_path=db_path)
		if records == None:
			return -1

		if len(records) > 0:
			tpl = records[0]
			if len(tpl) > 0:
				return tpl[0]
			else:
				return -1
		else:
			return -1


	def clean_msgs_in_primary_table(db_path: str, table: str, clean_count=-1) -> int:
		"""
			Clean messages in primary table
			Returns 0 on success, 1 on failure
		"""
		debug('write_msg_table_entry()')
		if not udon_utils.type_check([
			(db_path, str),
			(table, str)]):
			error('Error: invalid type - write_msg_table_entry()')
			return FAILURE

		NULL = "".encode()

		row_count = udon_DB.table_row_count(db_path, table)
		if row_count < 0:
			return FAILURE

		if clean_count != -1:
			row_count = clean_count

		for id in range(1, row_count+1):
			sql_write_row = f"""UPDATE "{table}" SET TIME=?, SRC=?, MSG=?, MSGSIG=?, DIGEST=?, PARTS=?, CHANNEL=?, KEY=? WHERE ID=?"""
			values = (NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, id)

			rtn = udon_DB.run_db_commit_values(query=sql_write_row, values=values, db_path=db_path)
			if rtn == FAILURE:
				return FAILURE
		return SUCCESS

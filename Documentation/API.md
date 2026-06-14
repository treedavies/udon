
# Udon Client Methods


## `c_send(recip_key, msg, signature, channel)`

* Send a message to another user by committing it to the server. 
  This calls the lower level method c_send_commit()

* Arguments:
  * recip_key: string name of recipient key.
  * msg: string message being sent
  * signature: byte string of the cryptographic signature of the `msg`.
  * channel: string channel name


c_send_commit(breq_src: bytes,
			  breq_uuid_sig: bytes,
			  breq_uuid: bytes,
			  btime: bytes,
			  bdest: bytes,
			  bpayload: bytes,
			  bsource: bytes,
			  bsignature: bytes,
			  bchannel: bytes,
			  bsymetric_key: bytes)


  Prepares, validates message field for commitment to the server. 

  Arguments:
    - breq_src: byte string. md5 sum of the senders public key.



c_ping()

c_msg_check(self, breq_src: bytes, breq_uuid_sig: bytes,
					breq_uuid: bytes)

c_poll(self, sync=False, quiet=False)

c_clean(self, key_id: str, buuid_sig: bytes, buuid: bytes, clean_count: bytes):

c_msg_fetch(self, bval: bytes, breq_src: bytes,
				breq_uuid_sig: bytes, breq_uuid: bytes):

c_load_pub_key(self, key_path: str)
c_load_priv_key(self, key_path: str)


c_encrypt_bstring_with_sym_key(self, byte_str: bytes, sym_key: bytes) 

c_decrypt_bstring_with_sym_key(self, byte_str: bytes, sym_key: str)

c_encrypt_bstring_with_public_key(self, byte_str: bytes,
									key_id: str)

c_decrypt_bstring_with_key(self, cipher_msg: bytes)

c_sign_bstring(self, message: bytes, key_id: str)

c_verify_signature(self, signature: bytes,
							message: bytes, key_id: str)

c_mark_msg_as_read(self, channel: str, num: int)

read_range(self, start, local_count, table, read_unread=False)

c_read(self, table: str, num: int, read_unread=False)

c_check_sync(self, first: int, last: int, diff: int, quiet: bool)

local_remote_count(self):

c_poll(self, sync=False, quiet=False)



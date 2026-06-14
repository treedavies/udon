
# Udon Client Methods


## `c_send(recip_key, msg, signature, channel)`

* Send a message to another user by committing it to the server. 
  This calls the lower level method c_send_commit()

* Arguments:
  * recip_key: string name of recipient key.
  * msg: string message being sent
  * signature: byte string of the cryptographic signature of the `msg`.
  * channel: string channel name


## `c_send_commit(...)`

* Prepares, validates message field for commitment to the server. 

* Arguments:
  * breq_src: bytes,
  * breq_uuid_sig: bytes,
  * breq_uuid: bytes,
  * btime: bytes,
  * bdest: bytes,
  * bpayload: bytes,
  * bsource: bytes,
  * bsignature: bytes,
  * bchannel: bytes,
  * bsymetric_key: bytes

## `c_ping()`

## `c_msg_check(breq_src, breq_uuid_sig, breq_uuid)`

## `c_poll(sync=False, quiet=False)`

## `c_clean(key_id, buuid_sig, buuid, clean_count)`

## `c_msg_fetch(bval, breq_src, breq_uuid_sig, breq_uuid)`

## `c_load_pub_key(key_path)`

## `c_load_priv_key(key_path)`

## `c_encrypt_bstring_with_sym_key(byte_str, sym_key) `

## `c_decrypt_bstring_with_sym_key(byte_str, sym_key)`

## `c_encrypt_bstring_with_public_key(byte_str,	key_id)`

## `c_decrypt_bstring_with_key(cipher_msg)`

## `c_sign_bstring(message, key_id)`

## `c_verify_signature(signature, message, key_id)`

## `c_mark_msg_as_read(channel, num)`

## `read_range(self, start, local_count, table, read_unread)`

## `c_read(table, num, read_unread)`

## `c_check_sync(first, last, diff, quiet)`

## `local_remote_count(self)`

## `c_poll(sync, quiet)`



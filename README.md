
# What is Udon?

* Udon is a minimalist End to End Encrypted (E2EE) message passing
  client/server tool. It utilizes gRPC, Public key cryptography, and
  sqlite3 database.

* Udon provides simple messaging between clients via a centralized server.

* See Setion 7 for examples of basic usage.

* It is a proof of concept.


# Project Goals

* Minimal and Primitive message passing service - No GUI. No fluff.

* The Server is ignorant - Server does not store user info or state. The server
  identifues users by the md5sum of their public key, located in
  ../..udon/keys/server_side_keys/ direcotry.

# Tested Platforms

This project has been sucessfully installed and tested on the following:
OS platforms

* Arch Linux

* Debian (Trixie)

* Fedora (43)

* Raspian (Bookworm)

# 0. Installation

Run the following install script. This will install files to
/usr/local/bin/udon/

    ./INSTALL.sh

Add `/usr/local/bin/udon` to your shell's PATH. Add the following line to your
.bashrc

    PATH=$PATH:/usr/local/bin/udon

# 1 DNS

DNS is required for clients to communicate with the server FQDN.
Verify the serving host can be found via its hostname and/or DNS record.
You can verify this by running `ping <hostname>` or `dig <hostname>`.

# 2. Initialization

Run the `udon_init.py` command.

`udon_init.py` will perform the following actions:

* Setup a '.udon' directory in your home directory (/home/$USER/.udon).
  See Section 3 for directory structure.

* Ask to create test keys. These are used for running the tests in
  `test_libudon.py`

* Create TLS Certificates. This will create a self signed cerificate.
  Even if you do not intend to run a server, creating a cert will allow you
  to run the tests. Which is a good idea. The hostname for the cert should match
  the server's DNS record.

* Create a user public/private key pair. These are written to
  `cleint_side_key/` and `server_side_key/` directories. If you only
  want to create a user key pair, run: `udon_init.py --user`

# 3. The /home/$USER/.udon directory tree

## .udon/keys

User public/private key pairs are written to the
/home/$USER/.udon/keys/(client|server)_side_keys/ directories. The
`client_side_keys` directory is used by the client. Copy the public keys you
intend to communicate with to this direcotry.

NOTE: This directory will also contain your private key. DO NOT SHARE THIS!

The `server_side_keys` directory is used by the server. The server will rename
the files to the md5sum of the key itself.

## .udon/channel_cfgs

This directory contains config files which define communication channels.
See example config in section 6 below.

## .udon/db

This directory contains the sqlite3 message databases

## .udon/TLS

This directory contains the server certificates used to establish Transport
Layer Security (TLS) connections between cleints and server.

## .udon/logs

Server log files. The server only logs errors.


# 4. Run the server

Start the server:

	unon-server

On the server host, copy the public keys of the users to
/home/$USER/.udon/keys/server_side_keys/. This allows the server to
authenticate user requests.

# 5. Run the tests

With the server running, run the tests:

    test_libudon.py


# 6 Channel configs

A channel is a configured profile for communication. It identifies the server,
the intended recipeints, message databases, and the keys by which to communicate.
Configs are located in the `/home/$USER/.udon/channel_cfgs/` directory after
`udon_init.py` is run.

The following is an example of a channel shared between Bob and Sally:

filename: `bob_and_sally`

    channel = "bob_and_sally"
    client_key_name = 'bob.pub'
    client_private_key = '/home/bob/.udon/keys/client_side_keys/bob'
    client_db_path = '/home/bob/.udon/db/bob.pub-udon-local.db'
    dest_key_name_list = ['bob.pub', 'sally.pub']
    server_fqdn = 'udonserver.net'
    server_port = '50051'
    ssl_root = '/home/bob/.udon/TLS/udonserver.net-root.crt'


# 7. Command line examples of usage

    $ udon --message bob_and_sally
    > Free Software, is Free as in Speech, but beer would be nice also.
    >
    Sending...
    Sent: 2/2

    $ udon --poll bob_and_sally
    Key: bob.pub - Local:0 Remote:2

    $ udon --sync bob_and_sally
    sync'd: 2

    $ udon --poll bob_and_sally
    Key: bob.pub - Local:2 Remote:2

    $ udon --read bob_and_sally -n 2
    #1: 2026-04-08 10:06:02:104942
    [V] sally.pub [bob_and_sally]
    What is Free Software?

    #2: 2026-04-08 10:09:08:307931
    [V] bob.pub [bob_and_sally]
    Free Software, is Free as in Speech, but beer would be nice also.
    LOL :)

    $ udon --clean bob_and_sally
    This operation is DESTRUCTIVE!
    Messages on the server will be sync'ed to the client,
    and then Deleted from the server
    Do you really want to continue? (y/n):y
    Sync'd: 0

    # Continuously poll/sync from server, and print messages to terminal as they arrive.
    $ udon --iterated-poll
    Waiting for messages...

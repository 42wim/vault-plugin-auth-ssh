#!/usr/bin/env python3
# Example python program to login to vault-plugin-auth-ssh using ssh-agent
# $VAULT_ADDR must be set, and role passed as an argument

import sys
import os
import base64
import struct
import json
import urllib.request
import paramiko

def usage():
    print("Usage: " + me + " [-V] role [metadatakey=value ...]", file=sys.stderr)
    print(" -V: verbose, show data sent to vault", file=sys.stderr)
    sys.exit(1)

def main():
    argv = sys.argv
    global me
    me = sys.argv[0]
    verbose = False
    if len(argv) > 1:
        if argv[1] == "-V":
            verbose = True
            argv = argv[1:]
        elif argv[1][0] == '-':
            print(me + ': unknown option: ' + argv[1], file=sys.stderr)
            usage()
    if len(argv) < 2:
        usage()
    role = argv[1]

    vault = os.getenv("VAULT_ADDR")
    if vault is None:
        print("$VAULT_ADDR not set", file=sys.stderr)
        sys.exit(2)

    agent = paramiko.Agent()
    agent_keys = agent.get_keys()
    if len(agent_keys) == 0:
        print("No ssh agent keys found", file=sys.stderr)
        sys.exit(2)

    metadata = {}
    for arg in argv[2:]:
        parts = arg.split('=')
        if len(parts) > 1:
            metadata[parts[0]] = parts[1]

    errmsgs = []
    for key in agent_keys:
        with urllib.request.urlopen(vault + "/v1/auth/ssh/nonce") as response:
            body = response.read()
        data = json.loads(body)
        nonce = data["data"]["nonce"]
        b64nonce = base64.b64encode(nonce.encode()).decode()

        d = key.sign_ssh_data(nonce)
        parts = []
        while d:
            ln = struct.unpack('>I', d[:4])[0]
            bits = d[4:ln+4]
            parts.append(bits)
            d = d[ln+4:]
        sig = parts[1]
        b64sig = base64.b64encode(sig).decode()

        pubkey = key.get_name() + ' ' + key.get_base64() + ' x'
        data = {
            'role': role,
            'public_key': pubkey,
            'signature': b64sig,
            'nonce': b64nonce,
        }
        if metadata != {}:
            data['metadata'] = metadata

        datastr = json.dumps(data, indent=4, sort_keys=True)
        if verbose:
            print("-- Attempting login with\n" + datastr + "\n--", file=sys.stderr)

        req = urllib.request.Request(vault + "/v1/auth/ssh/login", datastr.encode())
        try:
            with urllib.request.urlopen(req) as response:
                body = response.read()
        except Exception as e:
            typ = type(e).__name__
            msg = typ + ': ' + str(e)
            if typ == 'HTTPError':
                errmsg = e.read().decode()
                try:
                    decoded = json.loads(errmsg)
                    if 'errors' in decoded:
                        errmsg = ':'
                        for error in decoded['errors']:
                            errmsg += ' ' + error
                except:
                    errmsg = ' ' + errmsg
                msg += errmsg
            if verbose:
                print('Login attempt failed: ' + msg, file=sys.stderr)
            else:
                errmsgs.append(msg)
            continue

        data = json.loads(body)
        print(json.dumps(data, indent=4, sort_keys=True))

        sys.exit(0)

    for msg in errmsgs:
        print('Login failed: ' + msg, file=sys.stderr)
    sys.exit(1)

if __name__ == '__main__':
    main()


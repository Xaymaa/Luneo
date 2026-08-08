import socket as s
import logging as log
import threading
import os
import json
import base64
import secrets
import re
import hmac
import argparse
import ssl
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization,hashes
from cryptography.exceptions import InvalidSignature
from protocol import send_framed,recv_framed

log.basicConfig(level=log.INFO, format='[%(levelname)s] | %(asctime)s | %(message)s')

parser = argparse.ArgumentParser(description="Luneo server")
parser.add_argument("--tls", action="store_true",help="Enable TLS (default: off)")
parser.add_argument("--cert", default=None, help="Path to certificate (fullchain.pem)")
parser.add_argument("--key", default=None, help="Path to private key (privkey.pem)")
args = parser.parse_args()

tls_context = None
if args.tls:
    tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls_context.load_cert_chain(certfile=args.cert, keyfile=args.key)
    log.info("TLS enabled")
else:
    log.warning("TLS disabled — traffic is unencrypted")

if not os.path.isdir('user_data'):
  os.makedirs("user_data")

#Ouverture du serveur sur le port 9941
log.info("Launching the Luneo server...")
port=9941
s_listen = s.socket(s.AF_INET, s.SOCK_STREAM)
s_listen.setsockopt(s.SOL_SOCKET, s.SO_REUSEADDR, 1)
s_listen.bind(('0.0.0.0',port))
log.info("Server launched successfully !")

s_listen.listen()

connected_clients={}
clients_lock = threading.Lock()

VALID_USERNAME = re.compile(r"^[a-z0-9_-]{2,32}$")

def valid_username(name):
    return isinstance(name, str) and bool(VALID_USERNAME.match(name))

def send_msg(msg_code,client_connection,*,username="",recipient="",msg="",code=0,isRegistered="",pubkey=""):
  if msg_code==20:
    formatted_msg={
        "type":{"code":20, "description":"Server Info"},
        "info_code":code,
        "message": msg
      }
  elif msg_code==21:
    if not os.path.isdir(f"user_data/{username}/pending"):
      os.makedirs(f"user_data/{username}/pending")
    pending_messages=os.listdir(f"user_data/{username}/pending")
    formatted_msg={
      "type":{"code":21, "description":"Pending Messages Notification"},
      "username":username,
      "pending messages":{}
    }
    for message in pending_messages:
      author=message.removeprefix("pending_").removesuffix(".json")
      with open(f"user_data/{username}/pending/{message}","rb") as msg:
        message_count=len(json.loads(msg.read()))
      formatted_msg["pending messages"][author]=message_count
  elif msg_code==22:
    formatted_msg={
      "type":{"code":22, "description":"Pending Messages Response"},
      "pending messages":msg
    }
  elif msg_code==23:
    formatted_msg={
      "type":{"code":23, "description":"Authentication Success"},
      "username":username
    }
  elif msg_code==24:
    formatted_msg={
      "type":{"code":24, "description":"Authentication Fail"},
      "failure_code":code,
      "username":username,
      "message":msg,
      "isRegistered":isRegistered
    }
  elif msg_code==25:
    formatted_msg={
      "type":{"code":25, "description":"Challenge Query"},
      "username":username,
      "challenge_phrase":msg
    }
  elif msg_code==26:
    formatted_msg={
      "type":{"code":26, "description":"Public Key Response"},
      "username":username,
      "recipient":recipient,
      "pubkey":pubkey.decode("utf-8")
    }
  send_framed(client_connection,formatted_msg)

def deliver_pending_messages(client_connection, username):
    pending_dir = f"user_data/{username}/pending"
    for pending_msg in os.listdir(pending_dir):
      path = f"{pending_dir}/{pending_msg}"
      if os.path.isfile(path):
          log.info(f"delivering the pending messages of user : {username}")
          with open(path, "r") as m:
              message = json.load(m)
          send_msg(22, client_connection, msg=message)
          os.remove(path)

def authenticate(client_connection,username,isRegistered,pubkey):
  if isRegistered==False:
    if os.path.isdir(f"user_data/{username}"):
      send_msg(24,client_connection,username=username,isRegistered=isRegistered,code=0,msg=f" The user {username} already exists.")
      client_connection.close()
      return False,username
    else:
      os.makedirs(f"user_data/{username}")
      with open(f"user_data/{username}/{username}.pub","wb") as pubkey_file:
        pubkey_file.write(pubkey.encode("utf-8"))
      send_msg(23,client_connection,username=username)
      return True,username
  else:
    if os.path.isdir(f"user_data/{username}"):
      with open(f"user_data/{username}/{username}.pub", "rb") as key_file:
        pubkey = serialization.load_pem_public_key(
            key_file.read()
        )
      challenge_phrase=secrets.token_bytes(32)
      ciphertext_challenge = pubkey.encrypt(
          challenge_phrase,
          padding.OAEP(
              mgf=padding.MGF1(algorithm=hashes.SHA256()),
              algorithm=hashes.SHA256(),
              label=None))
      ciphertext_challenge=base64.b64encode(ciphertext_challenge).decode("ascii")
      send_msg(25,client_connection,username=username,msg=ciphertext_challenge)
      data = recv_framed(client_connection)
      if data is None: 
        return False, username
      challenge_response=parse_challenge_response(data,username)
      if challenge_response and hmac.compare_digest(challenge_phrase, challenge_response):
        send_msg(23,client_connection,username=username)
        return True,username
      else :
        send_msg(24,client_connection,username=username,code=2,msg="")
        return False,username
    else:
      send_msg(24,client_connection,username=username,isRegistered=isRegistered,code=1,msg=f"The user {username} does not exist.")
      return False,username

def verify_signature(payload,username,*,recipient=""):
  with open(f"user_data/{username}/{username}.pub", "rb") as key_file:
          pubkey = serialization.load_pem_public_key(
              key_file.read()
          )
  try:  
    signature=base64.b64decode(payload["signature"])
  except Exception:
    return False
  payload=payload.copy()
  del payload["signature"]
  payload=json.dumps(payload).encode("utf-8")
  try:
    pubkey.verify(
      signature,
      payload,
      padding.PSS(
          mgf=padding.MGF1(hashes.SHA256()),
          salt_length=padding.PSS.MAX_LENGTH
      ),
      hashes.SHA256()
    )
    return True
  except InvalidSignature:
    log.error(f"Invalid Signature from user {username}")
    return False

def handle_messages(client_connection, data, session_username):
  msg_code = data["type"]["code"]
  if data.get("username") != session_username:
      log.warning(f"{session_username} claimed author {data.get('username')}")
      return
  if not verify_signature(data, session_username):
      log.info(f"Invalid signature from {session_username}")
      raise ValueError("bad signature")
  if not valid_username(data["username"]):
    send_msg(20, client_connection, code=2, msg="Invalid username.")
    return
  username=session_username
  if msg_code==10:
    if not valid_username(data["recipient"]):
      send_msg(20, client_connection, code=2, msg="Invalid username.")
      return
    recipient=data["recipient"]
    log.info(f"Received message type {msg_code} from {username} to {recipient}")
    if not os.path.isdir(f"user_data/{recipient}"):
      send_msg(20,client_connection,msg=f"The user {recipient} does not exist")
    else:
      with clients_lock:
        recipient_conn = connected_clients.get(recipient)
      if recipient_conn is None:
          if not os.path.isdir(f"user_data/{recipient}/pending"):
              os.makedirs(f"user_data/{recipient}/pending")
          pending_path = f"user_data/{recipient}/pending/pending_{username}.json"
          if os.path.isfile(pending_path):
              with open(pending_path, "rb") as pending_msg:
                  pending = json.loads(pending_msg.read())
              pending[len(pending)] = data
          else:
              pending = {0: data}
          with open(pending_path, "w") as pending_msg:
              pending_msg.write(json.dumps(pending))
          send_msg(20, client_connection, code=1,msg=f"{recipient} is not currently online, your message will reach them once he logs back on.")  
      else:
          send_framed(recipient_conn, data) 
  elif msg_code==11:
    deliver_pending_messages(client_connection,username)
  elif msg_code==14:
    if not valid_username(data["recipient"]):
      send_msg(20, client_connection, code=2, msg="Invalid username.")
      return
    recipient=data['recipient']
    try:
      with open(f"user_data/{recipient}/{recipient}.pub", "rb") as key_file:
          pubkey = serialization.load_pem_public_key(
              key_file.read()
          )
          pubkey=pubkey.public_bytes(encoding=serialization.Encoding.PEM,
          format=serialization.PublicFormat.SubjectPublicKeyInfo)
          send_msg(26,client_connection,username=username,recipient=recipient,pubkey=pubkey)
    except FileNotFoundError:
      send_msg(20,client_connection,msg=f"The user {recipient} does not exist.")
  elif msg_code==15:
    if not valid_username(data["username"]):
      send_msg(20, client_connection, code=2, msg="Invalid username.")
      return
    send_msg(21,client_connection,username=data["username"])
  else:
    log.warning(f"Unknown code sent from user : {username}")
    client_connection.close()

def parse_challenge_response(data, session_username):
  msg_code = data["type"]["code"]
  if msg_code==13:
    if data.get("username") != session_username:
        log.warning(f"{session_username} claimed author {data.get('username')}")
        return
    if not verify_signature(data, session_username):
        log.info(f"Invalid signature from {session_username}")
        raise ValueError("bad signature")
    challenge_response=base64.b64decode(data["challenge_phrase"])
    return challenge_response
  else:
     return ""

def handle_client(client_connection):
    username = None
    try:
        #Authentication
        data = recv_framed(client_connection)
        if data is None:
            return
        if data["type"]["code"] != 12:
            send_msg(20, client_connection, code=2, msg="Authentication required.")
            return
        if not valid_username(data["username"]):
          send_msg(20, client_connection, code=3, msg="Invalid username.")
          return
        ok, username = authenticate(client_connection, data["username"],data["isRegistered"],data["pubkey"])
        if not ok:
            return
        with clients_lock:
            connected_clients[username] = client_connection
        #Normal traffic after auth
        while True:
            data = recv_framed(client_connection)
            if data is None:
                break
            handle_messages(client_connection, data, username)
    except (ConnectionResetError, ConnectionAbortedError, OSError) as e:
        log.info(f"connection dropped: {e!r}")
    except Exception as e:
        log.error(f"error for {username}: {e!r}")
    finally:
        if username:
            with clients_lock:
                if connected_clients.get(username) is client_connection:
                    del connected_clients[username]
        client_connection.close()
    

while True:
    raw_conn, client_addr = s_listen.accept()
    if tls_context:
        try:
            client_connection = tls_context.wrap_socket(raw_conn, server_side=True)
        except ssl.SSLError as e:
            log.warning(f"TLS handshake failed from {client_addr}: {e}")
            raw_conn.close()
            continue
    else:
        client_connection = raw_conn
    threading.Thread(target=handle_client, args=(client_connection,), daemon=True).start()
import socket as s
import logging as log
import threading
import os
import json
import base64
import secrets
import time
from cryptography.hazmat.primitives.asymmetric import rsa,padding
from cryptography.hazmat.primitives import serialization,hashes
from cryptography.exceptions import InvalidSignature

log.basicConfig(level=log.INFO, format='[%(levelname)s] | %(asctime)s | %(message)s')

if not os.path.isdir('user_data'):
  os.makedirs("user_data")

#Ouverture du serveur sur le port 9941
log.info("Launching the Luneo server...")
s_listen = s.socket(s.AF_INET, s.SOCK_STREAM)
port=9941
s_listen.bind(('0.0.0.0',port))
log.info("Server launched successfully !")

s_listen.listen()

connected_clients={}

def send_msg(msg_code,client_connection,*,username="",recipient="",pending_author="",msg="",code=0,isRegistered="",pubkey=""):
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
      author=message.split("_")[1][:-5]
      with open(f"user_data/{username}/pending/{message}","rb") as msg:
        message_count=len(json.loads(msg.read()))
      formatted_msg["pending messages"][author]=message_count
  elif msg_code==22:
    formatted_msg={
      "type":{"code":22, "description":"Pending Messages Response"},
      "pending_author":pending_author,
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
  client_connection.send(json.dumps(formatted_msg).encode("utf-8"))

def deliver_pending_messages(client_connection,username,pending_author):
    pending_dir=f"user_data/{username}/pending"
    if os.path.isfile(f"{pending_dir}/pending_{pending_author}.json"):
      log.info(f"delivering the pending messages of user : {username}")
      with open(f"{pending_dir}/pending_{pending_author}.json","r") as m:
        message=json.dumps(m.read())
        send_msg(22,client_connection,msg=message,pending_author=pending_author)
      os.remove(f"{pending_dir}/pending_{pending_author}.json")

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
      time.sleep(0.1)
      while True:
        data = client_connection.recv(65536)
        if data:
          challenge_response=handle_messages(client_connection,data)
          time.sleep(0.1)
          if challenge_phrase==challenge_response:
            send_msg(23,client_connection,username=username)
            return True,username
          else :
            send_msg(24,client_connection,username=username,code=2,msg="")
            return False,username
    else:
      send_msg(24,client_connection,username=username,isRegistered=isRegistered,code=1,msg=f"The user {username} does not exist.")

def verify_signature(payload,username,*,recipient=""):
  with open(f"user_data/{username}/{username}.pub", "rb") as key_file:
          pubkey = serialization.load_pem_public_key(
              key_file.read()
          )
  try:  
    signature=base64.b64decode(payload["signature"])
  except:
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
    print("Invalid Signature.")
    return False

def handle_messages(client_connection, data):
  data=json.loads(data.decode("utf-8"))
  msg_code=data["type"]["code"]
  username=data["username"]
  if msg_code==12:
    username=data["username"].lower()
    isRegistered=data["isRegistered"]
    pubkey=data["pubkey"]
    authenticated=authenticate(client_connection,username,isRegistered,pubkey)
    return authenticated
  if verify_signature(data,username):
    log.info(f"Signature verified successfully from user : {username}")
    if msg_code==10:
      recipient=data["recipient"]
      log.info(f"Received message type {msg_code} from {username} to {recipient}")
      if not os.path.isdir(f"user_data/{recipient}"):
        send_msg(20,client_connection,msg=f"The user {recipient} does not exist")
      else:
        if recipient not in connected_clients :
          if not os.path.isdir(f"user_data/{recipient}/pending"):
            os.makedirs(f"user_data/{recipient}/pending")
          if os.path.isfile(f"user_data/{recipient}/pending/pending_{username}.json"):
            with open (f"user_data/{recipient}/pending/pending_{username}.json","rb") as pending_msg:
              pending=json.loads(pending_msg.read())
              pending[len(pending)]=data
            with open (f"user_data/{recipient}/pending/pending_{username}.json","w") as pending_msg:
              pending_msg.write(f"{json.dumps(pending)}")
          else:
            with open (f"user_data/{recipient}/pending/pending_{username}.json","w") as pending_msg:
              pending={}
              pending[0]=data
              pending_msg.write(f"{json.dumps(pending)}")
          send_msg(20,client_connection,code=1,msg=f"{recipient} is not currently online, your message will reach them once he logs back on.")
        else:
          connected_clients[recipient].send(json.dumps(data).encode("utf-8")) 
    elif msg_code==11:
      username=data["username"]
      pending_author=data["pending_author"]
      deliver_pending_messages(client_connection,username,pending_author)
    elif msg_code==13:
      challenge_response=base64.b64decode(data["challenge_phrase"])
      return challenge_response
    elif msg_code==14:
      username=data['username']
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
  else:
    log.info(f"Invalid Signature from user : {username}")
    client_connection.close()

    

def handle_client(client_connection):
  authenticated=False
  while not authenticated:
    data = client_connection.recv(65536)
    if data:
      authenticated,username=handle_messages(client_connection,data)
      if authenticated==False:client_connection.close()
      break
  connected_clients[username]=client_connection
  send_msg(21,client_connection,username=username)
  while authenticated:
    data = client_connection.recv(4096)
    if not data:
      del connected_clients[username]
      break
    handle_messages(client_connection, data)
    

while True:
  client_connection, client_addr = s_listen.accept()
  threading.Thread(target=handle_client, args=(client_connection,), daemon=True).start()
import socket as s
import logging as log
import threading
import json
import os
import base64
import shutil
import sys
import secrets
import time
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import rsa,padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization,hashes
from cryptography.exceptions import InvalidSignature
from prompt_toolkit import prompt
from prompt_toolkit.patch_stdout import patch_stdout
from protocol import send_framed,recv_framed

home = Path.home()
log.basicConfig(level=log.INFO, format='[%(levelname)s] | %(asctime)s | %(message)s')
s_connect = s.socket(s.AF_INET, s.SOCK_STREAM)
#hostname="87.106.192.17"
hostname="0.0.0.0"
host_port=9941

def generate_keys(username):
  user_dir=f"{home}/.luneo/{username}"
  os.makedirs(user_dir)
  private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=4096,
  )
  privkey=private_key.private_bytes(
   encoding=serialization.Encoding.PEM,
   format=serialization.PrivateFormat.TraditionalOpenSSL,
   encryption_algorithm=serialization.NoEncryption()
  )
  pubkey=private_key.public_key().public_bytes(encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo)
  with open(f"{user_dir}/{username}.key","wb") as privkey_file:
    privkey_file.write(privkey)
  with open(f"{user_dir}/{username}.pub","wb") as pubkey_file:
    pubkey_file.write(pubkey)
  return private_key,pubkey

def encrypt(plaintext,username,recipient):
  plain_key=secrets.token_bytes(16)
  iv=secrets.token_bytes(12)
  encryptor=Cipher(algorithms.AES(plain_key),modes.GCM(iv),).encryptor()
  ciphertext=encryptor.update(plaintext.encode("utf-8")) + encryptor.finalize() 
  with open(f"{home}/.luneo/{username}/contacts/{recipient}.pub", "rb") as key_file:
          pubkey = serialization.load_pem_public_key(
              key_file.read()
          )
  encrypted_key = pubkey.encrypt(
          plain_key,
          padding.OAEP(
              mgf=padding.MGF1(algorithm=hashes.SHA256()),
              algorithm=hashes.SHA256(),
              label=None))
  iv=base64.b64encode(iv).decode()
  ciphertext=base64.b64encode(ciphertext).decode()
  encrypted_key=base64.b64encode(encrypted_key).decode()
  tag=base64.b64encode(encryptor.tag).decode()
  return iv,ciphertext,encrypted_key,tag

def decrypt(iv,ciphertext,encrypted_key,tag,username):
  iv=base64.b64decode(iv)
  ciphertext=base64.b64decode(ciphertext)
  encrypted_key=base64.b64decode(encrypted_key)
  tag=base64.b64decode(tag)
  with open(f"{home}/.luneo/{username}/{username}.key", "rb") as key_file:
    privkey = serialization.load_pem_private_key(
    key_file.read(),
    password=None,
    ) 
  plain_key = privkey.decrypt(
  encrypted_key,
  padding.OAEP(
      mgf=padding.MGF1(algorithm=hashes.SHA256()),
      algorithm=hashes.SHA256(),
      label=None))
  decryptor = Cipher(
        algorithms.AES(plain_key),
        modes.GCM(iv, tag),
    ).decryptor()
  return (decryptor.update(ciphertext) + decryptor.finalize()).decode("utf-8")
  
def sign(payload,username):
  with open(f"{home}/.luneo/{username}/{username}.key", "rb") as key_file:
    privkey = serialization.load_pem_private_key(
    key_file.read(),
    password=None,
    ) 
  signature = privkey.sign(
    payload,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
  )
  signature=base64.b64encode(signature).decode()
  decoded_payload=json.loads(payload.decode("utf-8"))
  decoded_payload["signature"]=signature
  return decoded_payload

def verify_signature(payload,username,*,recipient=""):
  with open(f"{home}/.luneo/{recipient}/contacts/{username}.pub", "rb") as key_file:
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


def send_msg(msg_code,connection,username="",*, recipient="", msg="",pubkey="",isRegistered=""):
    if msg_code==10:
      iv,ciphertext,encrypted_key,tag=encrypt(msg,username,recipient)
      formatted_msg={
        "type":{"code":10, "description":"Message"},
        "username":username,
        "recipient":recipient,
        "ciphertext":ciphertext,
        "iv":iv,
        "key":encrypted_key,
        "tag":tag
      }
    elif msg_code==11:
      formatted_msg={
        "type":{"code":11, "description":"Pending Messages Request"},
        "username":username,
        "pending_author":recipient
      }
    elif msg_code==12:
      formatted_msg={
        "type":{"code":12, "description":"User Authentication"},
        "username":username,
        "pubkey":pubkey.decode("utf-8"),
        "isRegistered":isRegistered
      }
    elif msg_code==13:
      formatted_msg={
        "type":{"code":13, "description":"Challenge Response"},
        "username":username,
        "challenge_phrase":msg
      }
    elif msg_code==14:
      formatted_msg={
        "type":{"code":14, "description":"Public Key Request"},
        "username":username,
        "recipient":recipient
      }
    payload=json.dumps(formatted_msg).encode("utf-8")
    send_framed(connection, sign(payload, username))

authentication_try=threading.Event()
authenticated=False

contact_selection=threading.Event()
contact_selected=True

pending_verification = {}

def handle_messages(connection):
  global authenticated
  global contact_selected
  while True:
    data = recv_framed(connection)
    if not data:
      print("connection closed.")
      sys.exit(1)
      break
    msg_code=data["type"]["code"]
    if msg_code==10:
      username=data["username"]
      recipient=data["recipient"]
      keypath = f"{home}/.luneo/{recipient}/contacts/{username}.pub"
      if not os.path.isfile(keypath):
          pending_verification.setdefault(username, []).append(data)
          send_msg(14, connection, username=recipient, recipient=username)
          continue 
      if verify_signature(data,username,recipient=recipient):
        message=decrypt(data["iv"],data["ciphertext"],data["key"],data["tag"],data["recipient"])
        print(f"{username} : {message}")
    elif msg_code==20:   
      print(f"received from server : {data["message"]}")
      if data["info_code"]==0:
        contact_selected=False
        contact_selection.set()
    elif msg_code==21:
      if data["pending messages"]=={}:
        print("You have no new messages")
      else:
        print(f"You have new message(s) : {data["pending messages"]}")
    elif msg_code==22:
      pendings=json.loads(json.loads(data["pending messages"]))
      print("New messages :")
      for index in pendings:
        if verify_signature(pendings[index],pendings[index]["username"],recipient=pendings[index]["recipient"]):
          message=decrypt(pendings[index]["iv"],pendings[index]["ciphertext"],pendings[index]["key"],pendings[index]["tag"],pendings[index]["recipient"])
          print(f"{pendings[index]["username"]} : {message}")
    elif msg_code==23:
      print(f"Authentication Successful")
      authenticated=True
      authentication_try.set()
    elif msg_code==24:
      print(f"Failed Authentication : {data["message"]}")
      authenticated=False
      if data["failure_code"]==0:
        shutil.rmtree(f"{home}/.luneo/{data["username"]}")
        authentication_try.set()
        break
      authentication_try.set()
    elif msg_code==25:
      username=data["username"]
      ciphertext=base64.b64decode(data["challenge_phrase"])
      try:
        with open(f"{home}/.luneo/{username}/{username}.key", "rb") as key_file:
          privkey = serialization.load_pem_private_key(
          key_file.read(),
          password=None,
          ) 
      except:
        print(f"You have no key for user {username}")
        s_connect.close()
        sys.exit(1)
      try :
        plaintext = privkey.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None))
      except : 
        print("Public Key Error : Decryption Failed.")
        connection.close()
        sys.exit(1)
      plaintext=base64.b64encode(plaintext).decode("ascii")
      send_msg(13,connection,username=username,msg=plaintext)
    elif msg_code==26:
      username=data["username"]
      recipient=data["recipient"]
      pubkey=data["pubkey"]
      if not os.path.isdir(f"{home}/.luneo/{username}/contacts"):
        os.makedirs(f"{home}/.luneo/{username}/contacts")
      with open(f"{home}/.luneo/{username}/contacts/{recipient}.pub", "wb") as pub_file:
          pub_file.write(pubkey.encode("utf-8"))
      for held in pending_verification.pop(recipient, []):
        if verify_signature(held, held["username"], recipient=held["recipient"]):
            print(f"{held['username']} : {decrypt(held["iv"],held["ciphertext"],held["key"],held["tag"],held["recipient"])}")
      contact_selection.set()
      



if not os.path.isdir(f"{home}/.luneo"):
  os.makedirs(f"{home}/.luneo")

s_connect.connect((hostname,host_port))
log.info(f"connected to server {hostname} on port {host_port}")
threading.Thread(target=handle_messages, args=(s_connect,),daemon=True).start()

while True:
  isRegistered=prompt("Register (R) or Login (L) : ")
  if isRegistered.lower()=="r":
    isRegistered=False
  elif isRegistered.lower()=="l":
    isRegistered=True
  else:
    print("Choose between R (to register) and L (to login)")
    continue
  
  username=prompt("username : ").lower()
  if username=="":
    continue
  user_dir=f"{home}/.luneo/{username}"
  if isRegistered==False and os.path.isdir(user_dir):
    print("You already have data for this user, you will log in instead.")
    isRegistered=True
  break

if isRegistered==False:
  private_key,pubkey=generate_keys(username)
  send_msg(12,s_connect,username=username,pubkey=pubkey,isRegistered=False)
else:
  try:
    with open(f"{user_dir}/{username}.pub", "rb") as key_file:
      pubkey = serialization.load_pem_public_key(
          key_file.read()
      )
  except:
    print(f"You have no data for user {username}")
    s_connect.close()
    sys.exit(1)
  pubkey=pubkey.public_bytes(encoding=serialization.Encoding.PEM,
  format=serialization.PublicFormat.SubjectPublicKeyInfo)
  send_msg(12,s_connect,username=username,pubkey=pubkey,isRegistered=True)

authentication_try.wait()
if not authenticated:
  sys.exit(1)

with patch_stdout():
  while True :
    recipient=prompt("choose contact: ")
    if recipient == "":
      log.info("Not a valid contact")
      continue
    contact_selected=True
    contact_selection.clear()
    send_msg(14,s_connect,username=username,recipient=recipient)
    contact_selection.wait()
    if contact_selected:
      log.info("send '/c' to change contact")
      send_msg(11,s_connect,username=username, recipient=recipient)
      while True:
        msg=prompt(">")
        if msg =="":
          log.info("No message was sent")
          continue
        elif msg=="/c":
          break
        send_msg(10,s_connect,username=username,recipient=recipient,msg=msg)
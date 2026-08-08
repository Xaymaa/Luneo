import socket as s
import logging as log
import threading
import json
import os
import base64
import shutil
import sys
import secrets
import re
import uuid
import argparse
import ssl
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import rsa,padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization,hashes
from cryptography.exceptions import InvalidSignature
from prompt_toolkit import prompt
from prompt_toolkit.patch_stdout import patch_stdout
from protocol import send_framed,recv_framed

HOME = Path.home()
LUNEO_DIR = HOME / ".luneo"
MAX_FILE_SIZE=100*1024*1024

parser = argparse.ArgumentParser()
parser.add_argument("--tls", action="store_true",help="Enable TLS (default: off)")
parser.add_argument("--host", default="127.0.0.1")
parser.add_argument("--port", type=int, default=9941)
parser.add_argument("--cert", default=None, help="Path to CA cert (for self-signed)")
args = parser.parse_args()

log.basicConfig(level=log.INFO, format='[%(levelname)s] | %(asctime)s | %(message)s')
hostname=args.host
port=args.port

authentication_try=threading.Event()
authenticated=False

contact_selection=threading.Event()
contact_selected=True

connection_lost=threading.Event()

in_conversation=""

auth_failed_reason = None
awaiting_contact = None
username = None

known_ids=set()

pending_verification = {}

VALID_USERNAME = re.compile(r"^[a-z0-9_-]{2,32}$")

def valid_username(name):
    return isinstance(name, str) and bool(VALID_USERNAME.match(name))

def valid_filename(name):
    return  ("/" not in name) and ("\\" not in name) and (name!="..")

def generate_keys(username):
  user_dir=f"{LUNEO_DIR}/{username}"
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
  plain_key=secrets.token_bytes(32)
  iv=secrets.token_bytes(12)
  encryptor=Cipher(algorithms.AES(plain_key),modes.GCM(iv),).encryptor()
  if type(plaintext)==str:
    ciphertext=encryptor.update(plaintext.encode("utf-8")) + encryptor.finalize() 
  else:
    ciphertext=encryptor.update(plaintext) + encryptor.finalize() 
  with open(f"{LUNEO_DIR}/{username}/contacts/{recipient}/{recipient}.pub", "rb") as key_file:
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
  with open(f"{LUNEO_DIR}/{username}/{username}.key", "rb") as key_file:
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
  return (decryptor.update(ciphertext) + decryptor.finalize())
  
def sign(payload,username):
  with open(f"{LUNEO_DIR}/{username}/{username}.key", "rb") as key_file:
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
  with open(f"{LUNEO_DIR}/{recipient}/contacts/{username}/{username}.pub", "rb") as key_file:
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
    print("Invalid Signature.")
    return False

def load_known_ids(username):
    global known_ids
    uuids_path = f"{LUNEO_DIR}/{username}/known_ids.txt"
    try:
        with open(uuids_path, "r") as u:
            known_ids = set(u.read().split())
    except FileNotFoundError:
        known_ids = set()

def is_uuid_unique(uid):
    return uid not in known_ids

def record_uuid(uid, username):
    known_ids.add(uid)
    try:
        with open(f"{LUNEO_DIR}/{username}/known_ids.txt", "a") as u:
            u.write(uid + "\n")
    except Exception as e:
        print(f"{e!r}")

def print_pending_messages(username,recipient):
  contact_dir=f"{LUNEO_DIR}/{username}/contacts/{recipient}"
  pending_dir=f"{contact_dir}/pending"
  pending_path=f"{pending_dir}/pending.txt"
  if os.path.isdir(pending_dir):
    if os.path.isfile(pending_path):
      with open(pending_path,"r") as p:
        messages=p.read().splitlines()
      if messages!=[]:
        print("New messages :")
      for message in messages:
        print(message)
      os.remove(pending_path)
    os.makedirs(f"{pending_dir}/image",exist_ok=True)
    os.makedirs(f"{pending_dir}/video",exist_ok=True)
    os.makedirs(f"{contact_dir}/image",exist_ok=True)
    os.makedirs(f"{contact_dir}/video",exist_ok=True)
    images=os.listdir(f"{pending_dir}/image")
    videos=os.listdir(f"{pending_dir}/video")
    for image in images:
      shutil.move(f"{pending_dir}/image/{image}",f"{contact_dir}/image/{image}")
      print(f"{recipient} sent you {image} in {contact_dir}/image")
    for video in videos:
      shutil.move(f"{pending_dir}/video/{video}",f"{contact_dir}/video/{video}")
      print(f"{recipient} sent you {video} in {contact_dir}/video")

def send_msg(msg_code,connection,username="",*, recipient="", msg="",pubkey="",isRegistered="",msg_format={}):
    if msg_code==10:
      iv,ciphertext,encrypted_key,tag=encrypt(msg,username,recipient)
      formatted_msg={
        "type":{"code":10, "description":"Message"},
        "username":username,
        "recipient":recipient,
        "ciphertext":ciphertext,
        "format":msg_format,
        "iv":iv,
        "key":encrypted_key,
        "tag":tag,
        "id":uuid.uuid4().hex
      }
    elif msg_code==11:
      formatted_msg={
        "type":{"code":11, "description":"Pending Messages Request"},
        "username":username
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
    elif msg_code==15:
      formatted_msg={
        "type":{"code":15, "description":"Pending Notification Request"},
        "username":username
      }
    payload=json.dumps(formatted_msg).encode("utf-8")
    try:
      send_framed(connection, sign(payload, username))
    except (BrokenPipeError, ConnectionResetError, OSError):
        connection_lost.set()
        authentication_try.set()
        contact_selection.set()
        print("Connection to server lost.")


def handle_messages(connection):
  global authenticated
  global contact_selected
  global auth_failed_reason
  global awaiting_contact
  global in_conversation
  while True:
    data = recv_framed(connection)
    if data is None: 
      connection_lost.set()
      authentication_try.set()
      contact_selection.set()
      return
    try:
      msg_code=data["type"]["code"]
      if msg_code==10:
        if not valid_username(data["username"]):
          print("Invalid username received from server.")
          continue
        if not valid_username(data["recipient"]):
          print("Invalid username received from server.")
          continue
        sender=data["username"]
        recipient=data["recipient"]
        if not is_uuid_unique(data["id"]):
          continue
        keypath = f"{LUNEO_DIR}/{recipient}/contacts/{sender}/{sender}.pub"
        if not os.path.isfile(keypath):
            pending_verification.setdefault(sender, []).append(data)
            send_msg(14, connection, username=recipient, recipient=sender)
            continue
        if verify_signature(data,sender,recipient=recipient):
          msg_format=data["format"]["format"]
          if msg_format=="text":
            message=decrypt(data["iv"],data["ciphertext"],data["key"],data["tag"],data["recipient"]).decode("utf-8")
            if in_conversation==sender:
              print(f"{sender} : {message}")
            else:
              if not os.path.isdir(f"{LUNEO_DIR}/{recipient}/contacts/{sender}/pending"):
                os.makedirs(f"{LUNEO_DIR}/{recipient}/contacts/{sender}/pending")
              with open(f"{LUNEO_DIR}/{recipient}/contacts/{sender}/pending/pending.txt","a") as p:
                  p.write(f"{sender} : {message}\n")
          elif msg_format in ("image","video"):
            message=decrypt(data["iv"],data["ciphertext"],data["key"],data["tag"],data["recipient"])
            format_pending_dir=f"{LUNEO_DIR}/{recipient}/contacts/{sender}/pending/{msg_format}"
            format_dir=f"{LUNEO_DIR}/{recipient}/contacts/{sender}/{msg_format}"
            if not valid_filename(data["format"]["name"]) :
              continue
            os.makedirs(format_dir,exist_ok=True)
            os.makedirs(format_pending_dir,exist_ok=True)
            if in_conversation==sender:
              with open(f"{format_dir}/{data["format"]["name"]}","wb") as f:
                f.write(message)
              print(f"{sender} sent you {data["format"]["name"]}, you can find it in {format_dir}")
            else:
              with open(f"{format_pending_dir}/{data["format"]["name"]}","wb") as f:
                f.write(message)
          record_uuid(data["id"],recipient)
      elif msg_code==20:   
        print(f"received from server : {data["message"]}")
        if data["info_code"]==0:
          contact_selected=False
          contact_selection.set()
      elif msg_code==21:
          pending_messages=data["pending messages"]
          contact_path=f"{LUNEO_DIR}/{data["username"]}/contacts/"
          if os.path.isdir(contact_path):
            for contact in os.listdir(contact_path):
              try:
                image_count=len(os.listdir(f"{contact_path}/{contact}/pending/image"))
                video_count=len(os.listdir(f"{contact_path}/{contact}/pending/video"))
              except Exception:
                image_count,video_count=0,0
              pending_path=f"{contact_path}/{contact}/pending/pending.txt"
              if os.path.isfile(pending_path) or image_count>0 or video_count>0:
                try:
                  with open(pending_path,"r") as p:
                    message_count=len(p.readlines())
                except FileNotFoundError:
                  message_count=0
                if contact in pending_messages:
                  pending_messages[contact]+=(message_count+image_count+video_count)
                else:
                  pending_messages[contact]=(message_count+image_count+video_count)
              else:
                continue
            if pending_messages=={}:
              print("You have no new messages.")
            else:
              print(f"You have new message(s) : {pending_messages}")
      elif msg_code==22:
        pendings=data["pending messages"]
        for index in pendings:
          pending_msg=pendings[index]
          if not valid_username(pending_msg["recipient"]):
            continue
          if not is_uuid_unique(pending_msg["id"]):
            continue
          keypath = f"{LUNEO_DIR}/{pending_msg['recipient']}/contacts/{pending_msg['username']}/{pending_msg['username']}.pub"
          if not os.path.isfile(keypath):
              pending_verification.setdefault(pending_msg["username"], []).append(pending_msg)
              send_msg(14, connection, username=pending_msg["recipient"], recipient=pending_msg["username"])
              continue
          if verify_signature(pending_msg,pending_msg["username"],recipient=pending_msg["recipient"]):
            msg_format=pending_msg["format"]["format"]
            if msg_format=="text":
              message=decrypt(pending_msg["iv"],pending_msg["ciphertext"],pending_msg["key"],pending_msg["tag"],pending_msg["recipient"]).decode("utf-8")
              spool_dir = f"{LUNEO_DIR}/{pending_msg['recipient']}/contacts/{pending_msg['username']}/pending"
              os.makedirs(spool_dir, exist_ok=True)
              with open(f"{spool_dir}/pending.txt", "a") as p:
                  p.write(f"{pending_msg['username']} : {message}\n")
            elif msg_format in ("image","video"):
              message=decrypt(pending_msg["iv"],pending_msg["ciphertext"],pending_msg["key"],pending_msg["tag"],pending_msg["recipient"])
              format_pending_dir=f"{LUNEO_DIR}/{pending_msg['recipient']}/contacts/{pending_msg['username']}/pending/{msg_format}"
              os.makedirs(format_pending_dir,exist_ok=True)
              if not valid_filename(pending_msg["format"]["name"]) :
                continue
              with open(f"{format_pending_dir}/{pending_msg["format"]["name"]}","wb") as f:
                f.write(message)
            record_uuid(pending_msg["id"], pending_msg["recipient"])
      elif msg_code==23:
        print(f"Authentication Successful")
        authenticated=True
        authentication_try.set()
      elif msg_code == 24:
        if username is None: 
          auth_failed_reason = data.get("message", "unknown")
          authenticated = False
          authentication_try.set()
          return
        if not valid_username(data["username"]):
          print("Invalid username received from server.")
          return
        if data["username"] != username:
          print("Server tried to delete keys for a different account.")
          return
        auth_failed_reason = data["message"]
        authenticated = False
        if data["failure_code"] == 0:
            shutil.rmtree(f"{LUNEO_DIR}/{data['username']}")
        authentication_try.set()
        return
      elif msg_code==25:
        if not valid_username(data["username"]):
          print("Invalid username received from server.")
          continue
        challengee=data["username"]
        ciphertext=base64.b64decode(data["challenge_phrase"])
        try:
          with open(f"{LUNEO_DIR}/{challengee}/{challengee}.key", "rb") as key_file:
            privkey = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            ) 
        except FileNotFoundError:
          print(f"You have no key for user {challengee}")
          connection_lost.set()
          authentication_try.set()
          contact_selection.set()
          return
        try :
          plaintext = privkey.decrypt(
          ciphertext,
          padding.OAEP(
              mgf=padding.MGF1(algorithm=hashes.SHA256()),
              algorithm=hashes.SHA256(),
              label=None))
        except Exception as e:
          print(f"Decryption failed: {e!r}")
          connection_lost.set()
          authentication_try.set()
          contact_selection.set()
          return
        plaintext=base64.b64encode(plaintext).decode("ascii")
        send_msg(13,connection,username=challengee,msg=plaintext)
      elif msg_code==26:
        if not valid_username(data["username"]):
          print("Invalid username received from server.")
          continue
        if not valid_username(data["recipient"]):
          print("Invalid recipient received from server.")
          continue
        key_owner=data["username"]
        recipient=data["recipient"]
        pubkey=data["pubkey"]
        if not os.path.isdir(f"{LUNEO_DIR}/{key_owner}/contacts"):
          os.makedirs(f"{LUNEO_DIR}/{key_owner}/contacts")
        if not os.path.isdir(f"{LUNEO_DIR}/{key_owner}/contacts/{recipient}"):
          os.makedirs(f"{LUNEO_DIR}/{key_owner}/contacts/{recipient}")
        with open(f"{LUNEO_DIR}/{key_owner}/contacts/{recipient}/{recipient}.pub", "wb") as pub_file:
            pub_file.write(pubkey.encode("utf-8"))
        for held in pending_verification.pop(recipient, []):
          if not is_uuid_unique(held["id"]):
            continue
          if verify_signature(held, held["username"], recipient=held["recipient"]):
              msg_format=held["format"]["format"]
              if msg_format=="text":
                message=decrypt(held["iv"],held["ciphertext"],held["key"],held["tag"],held["recipient"]).decode("utf-8")
                if in_conversation==held["username"]:
                  print(f"{held['username']} : {message}")
                else:
                  if not os.path.isdir(f"{LUNEO_DIR}/{held["recipient"]}/contacts/{held["username"]}/pending"):
                    os.makedirs(f"{LUNEO_DIR}/{held["recipient"]}/contacts/{held["username"]}/pending")
                  with open(f"{LUNEO_DIR}/{held["recipient"]}/contacts/{held["username"]}/pending/pending.txt","a") as p:
                    p.write(f"{held['username']} : {message}\n")
              elif msg_format in ("image","video"):
                message=decrypt(held["iv"],held["ciphertext"],held["key"],held["tag"],held["recipient"])
                format_pending_dir=f"{LUNEO_DIR}/{held["recipient"]}/contacts/{held['username']}/pending/{msg_format}"
                format_dir=f"{LUNEO_DIR}/{held["recipient"]}/contacts/{held['username']}/{msg_format}"
                if not valid_filename(held["format"]["name"]) :
                  continue
                os.makedirs(format_dir,exist_ok=True)
                os.makedirs(format_pending_dir,exist_ok=True)
                if in_conversation==held['username']:
                  with open(f"{format_dir}/{held["format"]["name"]}","wb") as f:
                    f.write(message)
                  print(f"{held['username']} sent you {held["format"]["name"]}, you can find it in {format_dir}")
                else:
                  with open(f"{format_pending_dir}/{held["format"]["name"]}","wb") as f:
                    f.write(message)
              record_uuid(held["id"],held["recipient"])
        if awaiting_contact==recipient:
          contact_selection.set()
    except Exception as e:
      #print(f"error handling message: {e!r}")
      import traceback
      traceback.print_exc()

if not os.path.isdir(f"{LUNEO_DIR}"):
  os.makedirs(f"{LUNEO_DIR}")

raw_sock = s.socket(s.AF_INET, s.SOCK_STREAM)

if args.tls:
    if args.cert:                       # self-signed: pin it
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations(args.cert)
        context.check_hostname = False
        s_connect = context.wrap_socket(raw_sock)
    else:                               # CA-signed (Let's Encrypt)
        context = ssl.create_default_context()
        s_connect = context.wrap_socket(raw_sock, server_hostname=hostname)
else:
    s_connect = raw_sock

try:
    s_connect.connect((args.host, args.port))
except ssl.SSLCertVerificationError as e:
    print(f"Certificate verification failed: {e}")
    sys.exit(1)
except ConnectionRefusedError:
    print(f"Could not connect to {hostname}:{port}")
    sys.exit(1)

log.info(f"connected to server {hostname} on port {port}")
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
  user_dir=f"{LUNEO_DIR}/{username}"
  if not valid_username(username):
    print("Invalid username.")
    continue
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
  except FileNotFoundError:
    print(f"You have no data for user {username}")
    s_connect.close()
    sys.exit(1)
  pubkey=pubkey.public_bytes(encoding=serialization.Encoding.PEM,
  format=serialization.PublicFormat.SubjectPublicKeyInfo)
  send_msg(12,s_connect,username=username,pubkey=pubkey,isRegistered=True)

authentication_try.wait()
if connection_lost.is_set():
    print("Lost connection to server.")
    sys.exit(1)

if not authenticated:
    print(f"Authentication failed: {auth_failed_reason}")
    s_connect.close()
    sys.exit(1)

load_known_ids(username)

with patch_stdout():
  if not os.path.isdir(f"{user_dir}/contacts"):
    os.makedirs(f"{user_dir}/contacts")
  print("Type /q to quit.")
  while not connection_lost.is_set() :
    in_conversation=""
    send_msg(15, s_connect, username)
    send_msg(11,s_connect,username=username)
    recipient=prompt("choose contact: ")
    if recipient == "":
      continue
    elif recipient == "/q":
      sys.exit(1)
    contact_selected=True
    contact_selection.clear()
    awaiting_contact=recipient
    send_msg(14,s_connect,username=username,recipient=recipient)
    if not contact_selection.wait(10):
      print("Server did not respond, try again.")
      continue
    if contact_selected:
      in_conversation=recipient
      print("Send '/c' to change contact")
      print("Send '/v:path/to/file' to send a video and '/i:path/to/file' to send an image")
      print_pending_messages(username,recipient)
      while True:
        msg=prompt(">")
        if msg =="":
          print("No message was sent")
          continue
        elif msg=="/c":
          break
        elif msg=="/q":
          sys.exit(1)
        elif msg[:3]=="/i:":
          msg=msg.removeprefix("/i:")
          file_extension=msg.split(".")[-1]
          if file_extension not in ("jpg","png","jpeg"):
            print("The file format should be jpg, jpeg or png.")
            continue
          try:
            if os.path.getsize(msg) > MAX_FILE_SIZE:
              print("Maximum file size : 100MB")
              continue
            with open(msg,"rb") as i:
              image=i.read()
          except FileNotFoundError:
            print("This file does not exist.")
            continue
          send_msg(10,s_connect,username=username,recipient=recipient,msg=image,msg_format={"format":"image","name":msg.split("/")[-1],"extension":file_extension})
          continue
        elif msg[:3]=="/v:":
          msg=msg.removeprefix("/v:")
          file_extension=msg.split(".")[-1]
          if file_extension not in ("mp4","mov","gif"):
            print("The file format should be mp4, mov or gif.")
            continue
          try:
            if os.path.getsize(msg) > MAX_FILE_SIZE:
              print("Maximum file size : 100MB")
              continue
            with open(msg,"rb") as v:
              video=v.read()
          except FileNotFoundError:
            print("This file does not exist.")
            continue
          send_msg(10,s_connect,username=username,recipient=recipient,msg=video,msg_format={"format":"video","name":msg.split("/")[-1],"extension":file_extension})
          continue
        send_msg(10,s_connect,username=username,recipient=recipient,msg=msg,msg_format={"format":"text"})
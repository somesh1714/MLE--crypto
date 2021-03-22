from django.shortcuts import render,redirect
from django.http import HttpResponse
from django.contrib import messages
from django.contrib.auth.models import User,auth
from .models import ServerMessages,Messages
from django.contrib.auth.decorators import login_required

# Create your views here.

import base64
import hashlib
import Crypto
from Crypto import Random
from Crypto.Cipher import AES
class MLE():
  def __init__(self,message):
    self.msg = message
    self.bs = AES.block_size
    self.key =self.KeyGen()
    self.enc = self.encrypt()
    self.tag = self.TagGen()
    

  def KeyGen(self):
    hash = hashlib.sha256(self.msg.encode())
    return hash.digest()

  def encrypt(self):
        raw = self._pad(self.msg)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw.encode()))
  def rmsg(self):
    return {
        "key": self.key,
        "cipher": self.enc,
        "tag": self.tag
    }
  def decrypt(enc, key):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return MLE._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')

  def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

  @staticmethod
  def _unpad(s):
        return s[:-ord(s[len(s)-1:])]

  def TagGen(self):
    enc = self.msg
    l = len(enc)
    tag = str(enc)+(str(l))
    tag = hashlib.sha1(tag.encode())
    return tag.digest()


def base(request):
    return render(request,'users/base.html')

def register(request):
    if request.method == 'POST':
        first_name = request.POST['first_name']
        last_name = request.POST['last_name']
        username = request.POST['username']
        password1 = request.POST['password1']
        password2 = request.POST['password2']
        email = request.POST['email']
        

        if password1==password2:
            if User.objects.filter(username=username).exists():
                messages.info(request,'Username Taken')
                messages.info(request,'Use Another Username..')
                return redirect('users-register')
            elif User.objects.filter(email=email).exists():
                messages.info(request,'Email Taken ')
                messages.info(request,'Use Another Email..')
                return redirect('users-register')
            else:   
                user = User.objects.create_user(username=username, password=password1, email=email,first_name=first_name,last_name=last_name)
                
                user.save()
                #user_s = Member(userName=username, password=password1, email=email,f_name=first_name,l_name=last_name)
                
                #user_s.save()
                print('user created')
                return redirect('users-login')

        else:
            messages.info(request,'Password not matching..') 
            messages.info(request,'Please re enter the password')     
            return redirect('users-register')
        return redirect('/')
        
    else:
        return render(request,'users/register.html')


def login(request):
    if request.method== 'POST':
        username = request.POST['username']
        password = request.POST['password']

        user = auth.authenticate(username=username,password=password)

        if user is not None:
            auth.login(request, user)
            return redirect("users-base")
        else:
            messages.info(request,'Invalid credentials !! Try Again ')
            
            return redirect('users-login')

    else:
        return render(request,'users/login.html')

def logout(request):
    auth.logout(request)
    return redirect('/')  

def switchAccount(request):
    auth.logout(request)
    return redirect('users-login')  

def get_all_plain_text(user_id):
    user = User.objects.get(id = user_id)
    all_user_messages = Messages.objects.all().filter(userId = user)
    decrypted_messages = []
    for msg in all_user_messages:
        cipher = ServerMessages.objects.get(messages = msg)
        cText = cipher.cipherText
        key = msg.key
        plain_text = MLE.decrypt(cText,key)
        print(plain_text)
        decrypted_messages.append(plain_text)

    print(decrypted_messages)
    return decrypted_messages


def serverPage(request):
    all_server_messages = ServerMessages.objects.all()
    return render(request,'users/server.html',{"message": all_server_messages})


@login_required(login_url='/login')
def encryptMessage(request):

    if request.method == 'POST':
        message = request.POST['message'].strip()
        print(request.POST)
        print(message)
        q = MLE(message)
        encrypt_dict = q.rmsg()
        key = encrypt_dict['key']
        cipher = encrypt_dict['cipher']
        tag = encrypt_dict['tag']
        print(tag)

        msg = ServerMessages.objects.all().filter(tag = tag)
        print('Inital Check')
        print(msg)
        print(len(msg))

        if len(msg): # Object exists
            print(msg[0])
            user_id = request.user.id
            user = User.objects.get(id = user_id)
            
            print('object already exists')
            retrieve_msg = ServerMessages.objects.all().filter(tag = tag)
            print(retrieve_msg)

            print('Message Retrieved')
            message_id = retrieve_msg[0]
            server_msg_id = message_id.id

            check_in_local = Messages.objects.all().filter(messageId = message_id,userId=user)
            print('checking if message is local storage')
            print(len(check_in_local))
            messages.info(request,'file already exists with Server Id = ' + str(server_msg_id)+' ! Deduplication performed successfully !!!')
            print('Server msg Id is ' + str(server_msg_id))
            #print(message_id)
            #print(type(request.user))
            
            #user = Member.objects.get(id = request.user.id)
            if len(check_in_local) == 0 :
                user_msg = Messages.objects.create(messageId = message_id,key = key,userId = user)
                user_msg.save()
    

        else:
            #object does not exist
            print('Creating a message')
            server_msg = ServerMessages.objects.create(tag = tag,cipherText = cipher)
            server_msg.save()
            print('Created!')
            

            retrieve_msg = ServerMessages.objects.all().filter(tag = tag)
            print(retrieve_msg)

            print('Message Retrieved')
            message_id = retrieve_msg[0]
            print(message_id)
            print(type(request.user))

            messages.info(request,'File Uploaded Sucessfully with ServerId ' + str(message_id.id))
            user_id = request.user.id
            user = User.objects.get(id = user_id)
            #user = Member.objects.get(id = request.user.id)
            user_msg = Messages.objects.create(messageId = message_id,key = key,userId = user)
            user_msg.save()
            print('message saved!')
            

        decrypted_messages = get_all_plain_text(request.user.id)
        print(decrypted_messages)
        return render(request,'users/base.html', { "message" : decrypted_messages})

    else:
        decrypted_messages = get_all_plain_text(request.user.id)
        print(decrypted_messages)
        return render(request,'users/base.html',{"message" : decrypted_messages})

from django.db import models
from datetime import date
from django.contrib.auth.models import User
# Create your models here.


class ServerMessages(models.Model):
    cipherText=models.BinaryField()
    tag=models.BinaryField()
    
    def __str__(self):
        return str(self.id)


class Messages(models.Model):
    messageId=models.ForeignKey(ServerMessages,on_delete = models.CASCADE)
    userId=models.ForeignKey(User,on_delete = models.CASCADE)
    key=models.BinaryField()

    def __str__(self):
        return str(self.messageId)


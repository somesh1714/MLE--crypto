from django.contrib import admin
from .models import *
# Register your models here.



class ServerMessagesAdmin(admin.ModelAdmin):
    list_display = ('id','cipherText','tag')

class MessagesAdmin(admin.ModelAdmin):
    list_display = ('messageId','userId','key')



admin.site.register(ServerMessages,ServerMessagesAdmin)
admin.site.register(Messages,MessagesAdmin)
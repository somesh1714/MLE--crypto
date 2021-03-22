from django.urls import path
from . import views

urlpatterns = [
    path('',views.encryptMessage, name="users-base"),
    path('register', views.register,name="users-register"),
    path('login', views.login,name="users-login"),
    path('logout',views.logout,name="users-logout"),
    path('switchAccount',views.switchAccount,name="users-switchAccount"),
    path('server',views.serverPage,name= "server-page")
]
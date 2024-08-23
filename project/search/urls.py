from django.urls import path
from .views import *
urlpatterns = [
    path('', view_, name='view_'),
    path('index/', index, name='index'),
    path('login/', login, name='loginn'),
    
]
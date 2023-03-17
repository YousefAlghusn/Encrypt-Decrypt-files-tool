from django.urls import path

from . import views

urlpatterns = [
    path("", views.main, name="main"),
    path('main/', views.main, name='main'),
    path('generate_AES/', views.generate_AES, name='generate_AES'),
    path('generate_RSA/', views.generate_RSA, name='generate_RSA'),
]
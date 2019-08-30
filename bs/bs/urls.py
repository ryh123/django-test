"""bs URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/2.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from django.conf import settings
from django.conf.urls.static import static
from bsapp import views
from django.conf.urls import include


urlpatterns = [

    path('', views.index),
    path('admin/', admin.site.urls),
    path('index/', views.index),
    path('login/', views.login),
    path('register/', views.register),
    path('logout/', views.logout_user),
    path('change_pwd/', views.change_page),
    path('change/', views.change_pwd),
    path('forget/',views.forget),
    path('forget_pwd/', views.forget_pwd),
    path('captcha', include('captcha.urls')),
    path('check/', views.getsqlpage),
    path('get_ip/', views.getip),
    path('ipsearch/', views.ipsearch),
    path('crack/', views.crack),
    path('crackbase64/', views.decodebase64),
    path('crypt/', views.encodebase64),
    path('md5/', views.encodemd5),
    path('spider/', views.spider),
    path('spider_get_page_url/', views.spider_get_page_url),
    path('delete/', views.delete),
    path('download_text/', views.download_text),
    path('sql_check/',views.sql_check),
    path('show_result/',views.show_result),
    path('search_text/',views.search_text),
    path('download_pic/',views.download_pic),
    path('text_search/',views.text_search),

]
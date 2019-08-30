from django.db import models
from django.contrib.auth.models import AbstractUser

class User(AbstractUser):

    """用户表"""

    gender = (
        ('male', '男'),
        ('female', '女'),
    )

    username = models.CharField(max_length=128,unique=True)
    password = models.CharField(max_length=256)
    email = models.EmailField(unique=True)
    sex = models.CharField(max_length=32,choices=gender,default='')
    c_time = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.username

    class Meta:
        ordering = ['c_time']
        verbose_name = '用户'
        verbose_name_plural = '用户'


class Save_html(models.Model):

    html_url = models.CharField(max_length=255,unique=True)
    htmlpage = models.TextField(blank=True)
    username = models.ForeignKey(User, on_delete=models.CASCADE)

class Save_sql_check(models.Model):

    sql_url = models.CharField(max_length=255,unique=True)
    msg1 = models.TextField(blank=True)
    msg2 = models.TextField(blank=True)
    username = models.ForeignKey(User, on_delete=models.CASCADE)
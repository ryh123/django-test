import base64
import hashlib
import json
import os
import re
import threading
import time
import urllib.request
import zipfile
import requests
from bs4 import BeautifulSoup
from bsapp.models import User
from bsapp.spider_url import Spider
from django.contrib import auth
from django.contrib.auth import authenticate
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.http import FileResponse
from django.http import HttpResponseRedirect, HttpResponse
from django.shortcuts import render, redirect

from . import models
from .forms import RegisterForm
from .forms import UserForm

payloads = ["%20and%20sleep(5)--+", "%27%20and%20sleep(5)--+", "%22%20and%20sleep(5)--+",
            "%3Bwaitfor%20delay%20%270%3A0%3A5%27%3B--",
            "or%201%3Ddbms_pipe.receive_%20%20%20message%28%27RDS%27%2C%205%29", "%3B%20SELECT%20pg_sleep%2810%29%3B--",
            "%27%29%20and%20sleep(5)--+", "%22%29%20and%20sleep(5)--+",
            "%27%29%29%20and%20sleep(5)--+"]       # sql注入检测语句，可以手动添加
DBMS_ERRORS = {
    "MySQL": (r"SQL syntax.*MySQL", r"Warning.*mysql_.*", r"valid MySQL result", r"MySqlClient\.", r"SQL syntax"),
    "PostgreSQL": (r"PostgreSQL.*ERROR", r"Warning.*\Wpg_.*", r"valid PostgreSQL result", r"Npgsql\."),
    "Microsoft SQL Server": (
    r"Driver.* SQL[\-\_\ ]*Server", r"OLE DB.* SQL Server", r"(\W|\A)SQL Server.*Driver", r"Warning.*mssql_.*",
    r"(\W|\A)SQL Server.*[0-9a-fA-F]{8}", r"(?s)Exception.*\WSystem\.Data\.SqlClient\.",
    r"(?s)Exception.*\WRoadhouse\.Cms\."),
    "Microsoft Access": (r"Microsoft Access Driver", r"JET Database Engine", r"Access Database Engine"),
    "Oracle": (
    r"\bORA-[0-9][0-9][0-9][0-9]", r"Oracle error", r"Oracle.*Driver", r"Warning.*\Woci_.*", r"Warning.*\Wora_.*"),
    "IBM DB2": (r"CLI Driver.*DB2", r"DB2 SQL error", r"\bdb2_\w+\("),
    "SQLite": (r"SQLite/JDBCDriver", r"SQLite.Exception", r"System.Data.SQLite.SQLiteException", r"Warning.*sqlite_.*",
               r"Warning.*SQLite3::", r"\[SQLITE_ERROR\]"),
    "Sybase": (r"(?i)Warning.*sybase.*", r"Sybase message", r"Sybase.*Server message.*"),
}                                                  #判断数据库类型
checks = ['','%27', '%22', '%29']                  #报错
path = os.getcwd()                                 #当前环境路径
user_agent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.12; rv:55.0) Gecko/20100101 Firefox/55.0'
headers = {'User-Agent' : user_agent}





def index(request):
    pass
    return render(request, 'login/index.html')


def login(request):
    if request.user.is_authenticated:
        return redirect('/index/')
    else:
        if request.method == "POST":
            login_form = UserForm(request.POST)
            message = "请检查填写的内容！"
            if login_form.is_valid():
                username = login_form.cleaned_data['username']
                password = login_form.cleaned_data['password']
                user = authenticate(username=username, password=password)
                try:
                    if user.is_active:
                        auth.login(request, user)  # 登录
                        return HttpResponseRedirect('/index/')
                    else:
                        message = "密码不正确！"
                except:
                    message = "用户不存在！"
            return render(request, 'login/login.html', locals())

    login_form = UserForm()
    return render(request, 'login/login.html', locals())



def register(request):
    if request.method == "POST":
        register_form = RegisterForm(request.POST)
        message = "请检查填写的内容！"
        if register_form.is_valid():  # 获取数据
            username = register_form.cleaned_data['username']
            password1 = register_form.cleaned_data['password1']
            password2 = register_form.cleaned_data['password2']
            email = register_form.cleaned_data['email']
            sex = register_form.cleaned_data['sex']
            if password1 != password2:  # 判断两次密码是否相同
                message = "两次输入的密码不同！"
                return render(request, 'login/register.html', locals())
            else:
                same_name_user = models.User.objects.filter(username=username)
                if same_name_user:  # 用户名唯一
                    message = '用户已经存在，请重新选择用户名！'
                    return render(request, 'login/register.html', locals())
                same_email_user = models.User.objects.filter(email=email)
                if same_email_user:  # 邮箱地址唯一
                    message = '该邮箱地址已被注册，请使用别的邮箱！'
                    return render(request, 'login/register.html', locals())

                # 当一切都OK的情况下，创建新用户
                user = User.objects.create_user(username, email, password1)
                user.sex = sex
                user.save()
                return redirect('/login/')  # 自动跳转到登录页面
    register_form = RegisterForm()
    return render(request, 'login/register.html', locals())


def logout_user(request):
    auth.logout(request)
    return HttpResponseRedirect('/login/')



def change_page(request):
    pass
    return render(request,"login/change_pwd.html")



@login_required
def change_pwd(request):
    if request.method == "POST":
        y_pwd = request.POST.get('y_pwd')
        x_pwd = request.POST.get('x_pwd')
        username = request.user.username
        user = authenticate(username=username, password=y_pwd)
        if user.is_active:
            user.set_password(raw_password=x_pwd)
            user.save()
            auth.logout(request)
            return HttpResponseRedirect('/login/')
        else:
            message = "原密码不正确"
            return render(request, "login/change_pwd.html", locals())




def forget(request):
    pass
    return render(request, "login/forget.html")




def forget_pwd(request):
    if request.method == "POST":
        username = request.POST.get('username')
        email = request.POST.get('email')
        x_pwd = request.POST.get('x_pwd')
        user = models.User.objects.get(username=username)
        email = models.User.objects.get(email=email)
        if user and email:
            user.set_password(raw_password=x_pwd)
            user.save()
            return redirect("/login/")
        else:
            message = "邮箱或用户名不正确"
            return render(request, "login/change_pwd.html",locals())





@login_required
def spider(request):
    if request.user.is_authenticated:
        return render(request, "spider/spider.html", locals())
    else:
        return redirect('/index/')




#爬取子网站地址并存入数据库
def spider_get_page_url(request):
    if request.method == "POST":
        url = request.POST.get('url')
        cookie = request.POST.get('cookie')
        x = models.Save_html.objects.filter(html_url=url)
        if x:
            a = models.Save_html.objects.all().values_list('html_url')
            return render(request, "spider/all_url.html", locals())
        else:
            spider = Spider(url, cookie)
            ggeett, fails = spider.start()
            a = ggeett.keys()
            b = fails.keys()
            c = list(a)
            e = list(b)
            d = list(ggeett.values())
            for i in range(len(ggeett)):
                g_r = models.Save_html.objects.create(html_url=c[i],htmlpage=d[i],username_id=request.user.id)
                g_r.save()
            return render(request, "spider/all_url.html", locals())




#下载源码
def download_text(request):
    if request.method == "POST":
        url = request.POST.get('url')
        cookie = request.POST.get('cookie')
        x = models.Save_html.objects.filter(html_url=url)
        if x:
            page = models.Save_html.objects.get(html_url=url)
            html = page.htmlpage.encode()
            url1 = url.replace('http://','')
            url1 = url1.replace('/','')
            with open(r'{0}/static/data/{1}.txt'.format(path,url1),"wb") as f:
                f.write(html)
            file = open('{0}/static/data/{1}.txt'.format(path,url1), 'rb')
            response = FileResponse(file)
            response['Content-Type'] = 'application/octet-stream'
            response['Content-Disposition'] = 'attachment;filename="{}.txt"'.format(url1)
            return response



def sql_check(request):
    pass
    return render(request, "sqlcheck/sql_check.html", locals())



#检测函数
def sql_injection_check(request,ss_url):
    dbm = []
    data = {}
    content = {}
    flags = []
    if '?id=1' in ss_url:
        c_url = ss_url
    else:
        c_url = ss_url + '?id=1'
    for check in checks:           #先用check使报错
        e_url = c_url + check
        _content = requests.get(e_url,headers=headers).text
        for (dbms, regex) in ((dbms, regex) for dbms in DBMS_ERRORS for regex in DBMS_ERRORS[dbms]):
            if (re.findall(regex, _content)):
                dbm.append(dbms)
        if len(dbm) == 0:
            msg1 = '未检测到数据库类型'
        else:
            msg1 = '数据库类型可能为{}'.format(dbm[0])
        for payload in payloads:
            flag1 = time.time()
            url1 = e_url + payload
            content["flag"] = requests.get(url1,headers=headers)
            flag2 = time.time()
            flag = flag2 - flag1
            if flag > 5 and flag < 15 and content["flag"].status_code == 200:  # 如果有一个payload成功延时，则存在注入
                flags.append(flag)
    if len(flags) >= 1:
        msg2 = '可能存在SQL注入漏洞'
    else:
        msg2 = '未检测到sql注入漏洞'
    data['url'] = ss_url
    data['msg1'] = msg1
    data['msg2'] = msg2
    data_1 = models.Save_sql_check.objects.create(sql_url=data['url'],msg1=data['msg1'],msg2=data['msg2'],username_id=request.user.id)
    data_1.save()



@login_required
def getsqlpage(request):
    threads = []
    if request.method == "POST":
        g_url = request.POST.get('url')
        cookie = request.POST.get('cookie')
        spider = Spider(g_url, cookie)
        s_url, f_url = spider.start()
        if cookie:
            headers["Cookies"] = cookie
        for ss_url in list(s_url.keys()):
            t = threading.Thread(target=sql_injection_check,args=(request,ss_url))    #多线程
            t.start()
            threads.append(t)
        for thread in threads:
            thread.join()
    return HttpResponse('检测完成')




def show_result(request):
    json= []
    data = models.Save_sql_check.objects.filter(username_id=request.user.id)
    for i in range(len(data)):
        json_data = {}
        json_data['url'] = data[i].sql_url
        json_data['msg1'] = data[i].msg1
        json_data['msg2'] = data[i].msg2
        json.append(json_data)
    return render(request, 'sqlcheck/check_result.html', locals())



@login_required
def delete(request):   #删除数据

    if request.method == "GET":
        delete = request.GET['del']
        try:
            if delete == "save_html":
                models.Save_html.objects.filter(username_id=request.user.id).delete()
                return render(request,"spider/all_url.html",locals())
            elif delete == "save_sql_check":
                models.Save_sql_check.objects.filter(username_id=request.user.id).delete()
                message = '删除成功'
                return render(request,"sqlcheck/sql_result.html",locals())
        except:
            return HttpResponse("删除失败，数据库可能为空！")



@login_required
def ipsearch(request):
    if request.user.is_authenticated:
        return render(request, "ipsearch/ipsearch.html", locals())
    else:
        return redirect('/index/')



def getip(request):
    urllist = []
    titlelist = []
    if request.method == "POST":
        ip1 = request.POST.get('ip')
        r = re.compile('((2[0-4]\d|25[0-5]|[01]?\d\d?)\.){3}(2[0-4]\d|25[0-5]|[01]?\d\d?)')      #检测输入ip的正确性
        ip2 = r.match(ip1)
        if ip2:
            ip3 = "https://apistore.aizhan.com/site/dnsinfos/2157bf6df185b171b237e22fed66050d?query=" + ip1  # ip_api    #2157bf6df185b171b237e22fed66050d
            ipinfo = requests.get(ip3)
            ipinfo = ipinfo.text
            data = json.loads(ipinfo)
            ip = data['data']['ip']
            address = data['data']['address']
            a = len(data['data']['domains'])
            for i in range(0, a):
                url = data['data']['domains'][i]['domain']
                urllist.append(url)
                title = data['data']['domains'][i]['title']
                titlelist.append(title)
            result = dict(zip(urllist, titlelist))
            return render(request, 'ipsearch/result.html', locals())
        else:
            message1 = '请正确填写ip'
            return render(request, 'ipsearch/ipsearch.html', locals())



@login_required
def crack(request):
    pass
    return render(request, 'crack/crack.html')



def decodebase64(request):
    c = ''
    try:
        if request.method == "POST":
            choice = request.POST.get('base')
            str1 = request.POST.get('str')
            if choice == "b16":
                c = base64.b16decode(str1)
            elif choice == "b32":
                c = base64.b32decode(str1)
            elif choice == "b64":
                c = base64.b64decode(str1)
        return render(request, 'crack/decrypt.html', locals())
    except:
        message = '解密失败'
        return render(request, 'crack/crack.html', locals())



def encodebase64(request):
    c = ''
    #try:
    if request.method == "POST":
        choice = request.POST.get('base')
        str1 = request.POST.get('str')
        str1 = str1.encode()
        if choice == "b16":
            c = base64.b16encode(str1)
        elif choice == "b32":
            c = base64.b32encode(str1)
        elif choice == "b64":
            c = base64.b64encode(str1)
            print(c)
    return render(request, 'crack/crypt.html', locals())
    #except:
        #return HttpResponseRedirect('/crack/')



def encodemd5(request):
    c = ''
    try:
        if request.method == "POST":
            str1 = request.POST.get('str')
            md5 = hashlib.md5()
            md5.update(str1.encode('utf-8'))
            c = md5.hexdigest()
        return render(request, 'crack/md5.html', locals())
    except:
        return HttpResponseRedirect('/crack/')


def search_text(request):
    pass
    return render(request,"spider/search.html")



def download_pic(request):
    if request.method == "POST":
        url = request.POST.get('url')
        url1 = url.replace('http://', '')
        url1 = url1.replace('/', '')
        url1 = url1.replace('.','')
        url1 = url1.replace(':', '')
        url1 = url1.replace('?', '')
        page = models.Save_html.objects.get(html_url=url)
        soup = BeautifulSoup(page.htmlpage, "html.parser")
        imgsrc = soup.find_all('img')
        print(imgsrc)
        if len(imgsrc):
            if os.path.exists('{0}/static/data/{1}'.format(path, url1)):
                x = 0
                for i in imgsrc:
                    imgurl = i.get('src')
                    imgurl = url+imgurl
                    urllib.request.urlretrieve(imgurl, '{0}/static/data/{1}/%s.jpg'.format(path, url1) % x)
                    x += 1
            else:
                os.makedirs('{0}/static/data/{1}'.format(path, url1))
                x = 0
                for imgurl in imgsrc:
                    urllib.request.urlretrieve(imgurl, '{0}/static/data/{1}/%s.jpg'.format(path, url1) % x)
                    x += 1
            azip = zipfile.ZipFile('{0}/static/data/{1}.zip'.format(path, url1), 'w')
            for current_path, subfolders, filesname in os.walk(r'{0}/static/data/{1}'.format(path, url1)):
                # print(current_path, subfolders, filesname)
                #  filesname是一个列表，我们需要里面的每个文件名和当前路径组合
                for file in filesname:
                    # 将当前路径与当前路径下的文件名组合，就是当前文件的绝对路径
                    azip.write(os.path.join(current_path, file))
                # 关闭资源
            azip.close()
        file = open('{0}/static/data/{1}.zip'.format(path, url1), 'rb')
        response = FileResponse(file)
        response['Content-Type'] = 'application/octet-stream'
        response['Content-Disposition'] = 'attachment;filename="{}.zip"'.format(url1)
        return response
    else:
        return HttpResponse("未寻找到图片")



def text_search(request):
    try:
        if request.method == "POST":
            url = request.POST.get('url')
            x_re = request.POST.get('re')
            page = models.Save_html.objects.get(html_url=url)
            r = re.compile(x_re)
            result = r.search(page.htmlpage)
            result = result.group(0)
            return render(request, "spider/text_result.html", locals())
    except:
        return HttpResponse("未匹配")

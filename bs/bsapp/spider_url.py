# -*- coding: utf-8 -*-
import requests
import threading
from time import sleep
from urllib.parse import urlparse,urljoin
from bs4 import BeautifulSoup

user_agent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.12; rv:55.0) Gecko/20100101 Firefox/55.0'
headers = {'User-Agent' : user_agent}

class UrlManager():
    def __init__(self, host_url):
        self.used_url = set()
        self.new_url = set([host_url])
        self.host_url = urlparse(host_url)[1]
    def addUrl(self, url, link):
        url = urljoin(url,link)
        if urlparse(url)[1] != self.host_url:
            return
        if url in self.used_url:
            return
        self.new_url.add(url)
    def hasUrl(self):
        return len(self.new_url) != 0
    def get_url(self):
        url = self.new_url.pop()
        self.used_url.add(url)
        return url

class Spider():
    def __init__(self,host_url, cookies = None):
        self.urlmanager = UrlManager(host_url)
        self.page_dict = dict()
        self.fail = dict()
        self.threads = []
        if cookies:
            headers["Cookies"] = cookies
    def start(self):
        while self.urlmanager.hasUrl() or sleep(3) or self.urlmanager.hasUrl():
            url = self.urlmanager.get_url()
            thread = threading.Thread(target=self.Download, args=(url,))
            thread.start()
            self.threads.append(thread)
        for thread in self.threads:
            thread.join()
        return self.page_dict, self.fail
            
    def Download(self,url):
        if url == None:
            return
        try:
            page = requests.get(url,headers=headers)
        except BaseException as expression:
            self.fail[url] = expression
            return
        if page.status_code != 200:
            self.fail[url] = page.status_code
            return
        self.page_dict[url] = page.text
        soup = BeautifulSoup(page.text, "html.parser")
        for link in soup.find_all('a') + soup.find_all('area'):
            link = link.get("href")
            if link and link[0] != "#":
                self.urlmanager.addUrl(url,link)



if __name__ == "__main__":
    spider = Spider("http://127.0.0.1/sqli/")
    pages, fails = spider.start()
    for page in pages.keys():
        print("[+]Get : " + page)
    for fail in fails.keys():
        print("[-]Get : " + fail)
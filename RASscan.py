#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# code by 1904521507
import Queue
import threading
from threading import Thread
import time
import re
import sys
import os
import socket
import optparse
import urllib2

'''
一般默认常用端口扫描介绍：
3311:3312 kangle主机管理系统
3389 远程登录
4440 rundeck是用java写的开源工具
5672 rabbitMQ
5900 VNC
6082 varnish  参考WooYun: Varnish HTTP accelerator CLI 未授权访问易导致网站被直接篡改或者作为代理进入内网
6379 redis 一般无认证，可直接访问
7001 weblogic
8080 tomcat
8089 jboss
8161 activeMQ
8649 ganglia集群系统监控软件
9000 fastcgi服务
9090 IBM服务
9200,9300 elasticsearch  参考WooYun: 多玩某服务器ElasticSearch命令执行漏洞
9999 amg加密版
10050 zabbix
11211  memcache  未授权访问
27017,28017 mongodb  未授权访问   mongodb默认无口令登录
3777 大华监控设备
50000 sap netweaver远程命令执行漏洞
50060 50070 hahoop、apache hasoop
21 默认是ftp端口  主要看是否支持匿名，也可以跑弱口令
22 默认是ssh端口
23 默认是telnet端口
25 默认是smtp服务
53 默认是DNS
123 是NTP
161,162，8161 snmp服务（8161 IBM一款产品所开放的SNMP）
389 ldap团体
443  openssl  、hearthleed
512,513 rlogin服务或者是exec
873 rsync 主要看是否支持匿名，也可以跑弱口令
1433 mssql数据库
1080 socks代理
1521 oracle
1900 bes默认后台
2049 nfs服务
2601,2604 zebra路由 默认密码zebra
2082,2083 cpanel主机管理系统
3128，3312 squid代理默认端口，如果没设置口令很可能就直接漫游内网了
3306 mysql数据库
4899 R-admin 连接端
4440 rundeck rundeck  参考WooYun: 借用新浪某服务成功漫游新浪内网
8834 nessus
4848 glashfish
'''


def ip2num(ip):
    ip = [int(x) for x in ip.split('.')]
    return ip[0] << 24 | ip[1] << 16 | ip[2] << 8 | ip[3]
    
def num2ip(num):
    return '%s.%s.%s.%s' % ((num & 0xff000000) >> 24,
                            (num & 0x00ff0000) >> 16,
                            (num & 0x0000ff00) >> 8,
                            num & 0x000000ff)

def bThread():
    global queue
    global SETTHREAD
    print '[Note] Running...\n'
    threadl = []
    threadl = [tThread(queue) for x in xrange(0, int(SETTHREAD))]
    for t in threadl:
        t.start()
    for t in threadl:
        t.join()

#输入到结束
def ip_range(start, end):
    return [num2ip(num) for num in range(ip2num(start), ip2num(end) + 1) if num & 0xff]
# http请求获取返回内容
'''
return [0] 文件内容
return [1] 返回服务状态码
return [2] 返回服务器类型
return [3] location
return [4] title
'''
'''port scan'''
def scan_open_port_server():
    global lock
    while True:
        host,port=queue.get()
        ss=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ss.settimeout(2)
        try:
            ss.connect((host,port))
            lock.acquire()
            print "%s 开放端口 %s   %s" % (host, port,PORT[port])
            lock.release()
            ss.close()
        except:
            pass
        queue.task_done()

if __name__ == '__main__':
    usage="usage: mul_scan.py  192.168.1.1 192.168.1.254 -t 20"
    parser = optparse.OptionParser(usage=usage)
    parser.add_option("-t", "--threads", dest="NUM",help="Maximum threads, default 20")
    parser.add_option("-b", "--start-ip", dest="startIp",help="start_ip")
    parser.add_option("-e", "--end-ip", dest="endIp",help="end_ip")
    (options, args) = parser.parse_args()
    if len(args) < 1:
        parser.print_help()
        sys.exit()
    if options.NUM!=None and int(options.NUM)!=0:
        SETTHREAD=int(options.NUM)
    else:
        SETTHREAD=20
    #接受开始ip和结束ip
    startIp =str(options.startIp)
    endIp = str(options.endIp)
    startIp=args[0]
    endIp=args[1]
    lock = threading.Lock()
    #程序运行时间
    PORT={80:"web",8080:"web",3311:"kangle主机管理系统",3312:"kangle主机管理系统",3389:"远程登录",4440:"rundeck是用java写的开源工具",5672:"rabbitMQ",5900:"vnc",6082:"varnish",7001:"weblogic",8161:"activeMQ",8649:"ganglia",9000:"fastcgi",9090:"ibm",9200:"elasticsearch",9300:"elasticsearch",9999:"amg",10050:"zabbix",11211:"memcache",27017:"mongodb",28017:"mondodb",3777:"大华监控设备",50000:"sap netweaver",50060:"hadoop",50070:"hadoop",21:"ftp",22:"ssh",23:"telnet",25:"smtp",53:"dns",123:"ntp",161:"snmp",8161:"snmp",162:"snmp",389:"ldap",443:"ssl",512:"rlogin",513:"rlogin",873:"rsync",1433:"mssql",1080:"socks",1521:"oracle",1900:"bes",2049:"nfs",2601:"zebra",2604:"zebra",2082:"cpanle",2083:"cpanle",3128:"squid",3312:"squid",3306:"mysql",4899:"radmin",8834:'nessus',4848:'glashfish'}
    starttime=time.time()
    queue = Queue.Queue()
    iplist = ip_range(startIp, endIp)
    print '端口采用默认扫描请自行进行比对:\nbegin Scan '+str(len(iplist))+" ip..."
    for i in xrange(SETTHREAD):
        st1 = threading.Thread(target=scan_open_port_server)
        st1.setDaemon(True)
        st1.start()
    for host in iplist:
        for port in PORT.keys():
            queue.put((host,port))
    queue.join()
    print 'All RUN TIME：'+str(time.time()-starttime)
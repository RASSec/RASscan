<PRE>测试常见端口
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

用法 ：
demo.py 192.168.1.1 192.168.254.254 -t 20
`
</PRE>
__author__ : yds

## Stargazers over time

[![Stargazers over time](https://starchart.cc/RASSec/RASscan.svg)](https://starchart.cc/RASSec/RASscan)


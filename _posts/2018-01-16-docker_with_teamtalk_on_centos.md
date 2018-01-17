---
layout: post
title:  docker with teamtalk on centos
date: 2017-11-18 22:56:48 +0800
#category: xiaominfc
author: xiaominfc
description: centos with teamtalk
categories: teamtalk docker
source: tensorflow
comments: true
---


## docker 准备 centos7镜像

### 1.download

以openshift/base-centos7为centos7的基础

~~~
docker pull openshift/base-centos7

or

docker pull registry.docker-cn.com/openshift/base-centos7 
国内镜像源快

~~~

wait!

### 2.run(要支持systemctl start service以便mariadb，redis能启动)

~~~

docker run -d -e "container=docker" --privileged=true -v /sys/fs/cgroup:/sys/fs/cgroup  registry.docker-cn.com/openshift/base-centos7 /usr/sbin/init
docker exec -it {containerId}  /bin/bash

~~~

## 获取teamtalk的源码

~~~

git clone https://github.com/xiaominfc/TeamTalk.git

or 

wget https://github.com/xiaominfc/TeamTalk/archive/master.zip
unzip master.zip
mv ./TeamTalk-master ./TeamTalk
体积小些快些
~~~

## 编译

~~~
cd TeamTalk/server/src

./make_hiredis.sh
./make_log4cxx.sh
./make_protobuf.sh
./make_mariadb.sh
./build.sh version test

~~~

## 安装redis and mariadb


### 1.install redis
~~~
yum install epel-release
yum install redis
systemctl enable redis
systemctl start redis
~~~

### 2.install mariadb

~~~
cd /opt/app-root/src/TeamTalk/auto_setup/mariadb
chmod +x setup.sh
./setup.sh install
systemctl enable mariadb
systemctl start mariadb
~~~

### 3.设置mariadb 密码 导入数据表

~~~
cd /opt/app-root/src/TeamTalk/auto_setup/mariadb/conf
mysql_secure_installation
mysql -uroot -p123456
source ttopen.sql
quit

~~~

## 启动服务

### 1.准备服务
~~~
cd /opt/app-root/src/TeamTalk/server
#解压
tar -xf ./im-server-test.tar.gz
cd im-server-test
chmod +x ./sync_lib_for_zip.sh
./sync_lib_for_zip.sh

~~~
### 修改配置


### 启动服务
~~~
cd /opt/app-root/src/TeamTalk/server/im-server-test/
./restart.sh db_proxy_server
./restart.sh login_server
./restart.sh route_server
./restart.sh msg_server
.....
~~~


## 提交镜像


## 注意事项

### 1.db\_proxy\_server

~~~
db_proxy_server依赖mysql/mariadb 跟redis服务 移动失败了话
1.检查mysql/mariadb 是否启动
2.检查redis 是否启动
3.检查配置文件是否正确
~~~

### 2.msg_server

~~~
msg_server 依赖login_server db_proxy_server route_server
启动失败的话 检查配置以及上述服务
~~~

## 附上我上传的一个docker 镜像

~~~
docker pull xiaominfc/teamtalkoncentos7:latest
~~~

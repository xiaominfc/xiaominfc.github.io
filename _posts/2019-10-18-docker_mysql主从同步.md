---
layout: post
title:  docker mysql 主从同步（一主多备）
date: 2019-10-18 10:26:48 +0800
#category: xiaominfc
author: xiaominfc
description: mysql 主从同步
categories: shell docker
comments: true
---


# docker mysql 主从同步（一主多备）

## 获取mysql的docker镜像

[https://hub.docker.com/_/mysql](https://hub.docker.com/_/mysql)

```sh
docker pull mysql:tag
#docker pull mysql:5.7

```

## 主库的建立 启动脚本(master)

```sh

#! /bin/sh

cur_dir=$(pwd)

name=master
port=13306

data_dir=data_${name}

if [ ! -d ${data_dir} ] ; then
  mkdir -p ./${data_dir}
fi

conf_dir=${name}_mysql_conf

if [ ! -d ${conf_dir} ] ; then
  mkdir -p ./${conf_dir}
fi


mount_data_dir=${cur_dir}/${data_dir}
config_data_dir=${cur_dir}/${conf_dir}

docker run --name ${name}-mysql -v ${mount_data_dir}:/var/lib/mysql -v ${config_data_dir}:/etc/mysql/conf.d  -p ${port}:3306  -e MYSQL_ROOT_PASSWORD=123456 -d mysql:5.7

```

启动之

### 进入容器 连上mysql

```sh
docker exec -it master-mysql /bin/bash 
mysql -uroot -p123456
```

### 添加从库操作用户

```sql
GRANT REPLICATION SLAVE,REPLICATION CLIENT ON *.* TO repl@'172.17.0.%' IDENTIFIED BY '123456';

#退出mysql
ctrl+D
#退出容器
exit
```

记下这里的操作用户名:repl 以及密码:123456

### 编辑 mysql-master 配置

```sh
vi ./master_mysql_conf/master.cnf
```

[master.cnf]

```cnf
[mysqld]
log_bin = mysql-bin
server_id = 10

```

### 重启master-mysql

```sh
docker restart master-mysql
```

### ps 查看状态（进入master mysql用下列语句查看）

```sql
SHOW MASTER STATUS;
```


## 备库的建立 启动脚本(slave)

类似master的脚本(换个name跟port)

```sh
#! /bin/sh

cur_dir=$(pwd)

name=slave
port=13308

data_dir=data_${name}

if [ ! -d ${data_dir} ] ; then
  mkdir -p ./${data_dir}
fi

conf_dir=${name}_mysql_conf

if [ ! -d ${conf_dir} ] ; then
  mkdir -p ./${conf_dir}
fi


mount_data_dir=${cur_dir}/${data_dir}
config_data_dir=${cur_dir}/${conf_dir}

docker run --name ${name}-mysql -v ${mount_data_dir}:/var/lib/mysql -v ${config_data_dir}:/etc/mysql/conf.d  -p ${port}:3306  -e MYSQL_ROOT_PASSWORD=123456 -d mysql:5.7
```

启动之

### 添加从库配置

```sh
vi ./slave_mysql_conf/slave.cnf
```

slave.cnf

```cnf
[mysqld]
log_bin   = mysql-bin
server_id = 2
relay_log = /var/lib/mysql/mysql-relay-bin
log_slave_updates = 1
#只读模式 只从master读数据过来
read_only = 1

```

### 重启slave 连接mysql

```sh
docker restart slave-mysql
docker exec -it slave-mysql /bin/bash 
mysql -uroot -p123456
```


### 启动同步

```sql
CHANGE MASTER TO MASTER_HOST='172.17.0.2',
MASTER_USER='repl',
MASTER_PASSWORD='123456',
MASTER_LOG_FILE='mysql-bin.000001',
MASTER_LOG_POS=0;


#开始同步
START SLAVE;
```

```
MASTER_USER:前面写的操作用户 repl
MASTER_PASSWORD:前面写的操作用户的密码 123456
MASTER_LOG_FILE: 默认尾缀应该是000001
MASTER_LOG_POS: 写0 就是从头开始 写master的status显示的值就是从此刻开始
```



### ps 

MASTER_HOST 可以通过docker 查看 master-mysql的docker ip 我的是172.17.0.2 故而写172.17.0.2

## 可以尝试在主库里写入看看效果了哦
## 重复上述slave相关的步骤即可生成多个备份


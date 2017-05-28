---
layout: post
title:  ubuntu 移除多余kernel的脚本
date: 2017-05-28 10:18:48 +0800
category: ubuntu
author: xiaominfc
description: ubuntu 移除多余kernel的脚本
---



每次ubuntu linux内核升级旧的内核都会残留 占空间 所以写了这个脚本

autoremovekernel.sh

~~~~shell
#!/bin/sh 

mkfifo tmp_fifo;
#获取当前使用kernel的版本
kernel_name=$(uname -r)
kernel_code=${kernel_name%'-generic'}

echo 'current kernel_code:'$kernel_code
dpkg --get-selections | grep linux-.* | awk -v kernel_code="$kernel_code" '/.*\-[0-9]+.*/{ 
    if(index($1,kernel_code) == 0 && $2=="install"){
        print $1
    }
}'>tmp_fifo &

while read kernel_name
do
    cmd='sudo apt-get -y autoremove '$kernel_name
    echo 'remove :'$kernel_name' by cmd:'$cmd
    $cmd
done <tmp_fifo
rm tmp_fifo; 

sudo apt-get autoclean
~~~~
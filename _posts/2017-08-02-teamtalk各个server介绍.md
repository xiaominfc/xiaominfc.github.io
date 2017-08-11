---
layout: post
title:  teamtalk各个server的介绍
date: 2017-08-02 22:56:48 +0800
#category: xiaominfc
author: xiaominfc
description: teamtalk各个server的介绍
categories: teamtalk
source: teamtalk
comments: true
---

teamtalk研究了一段时间了，一直没有好好总结过，想写篇文章来总结一下各个服务的作用


## teamtalk的服务
teamtalk这个项目编译出来以后会有这些服务:login_server http_msg_server msg_server db_proxy_server route_server push_server file_server msfs 


### login_server
提供http服务 提供msg_server,msfs服务地址以及端口号的，每次都会返回client连接数少的msg_server。具有负载均衡的作用，每次客户端打开都会向login_server发起一次请求获取msg_server的ip以及port，以此来连接msg_server，可以部署多个 

### msg_server
提供tcp服务 维护所有的client连接 可以部署多个 将客户端发来的的行为消息转发给db_proxy_server 每个msg_server都得连接到db_proxy_server。

### db_proxy_server
提供tcp服务 即时通讯中大部分的业务逻辑都是在db_proxy_server中实现的 它主要是对mysql，redis数据库进行业务上的行为。可以部署多个，本身能并发处理业务。

### route_server
提供tcp服务  连接所有的msg_server 充当路由中转的服务 解决不同的msg_server之间client直接的通讯。

### http_msg_server
提供http服务 修改群成员的http的API就是它实现的 它直接连接db_proxy_server 去进行业务上的处理，参考基本API的实现可以拓展一些其他的API，共业务上使用。

### push_server
提供tcp服务 msg_server都会连接它，它配置并连接apple的推送接口以此来对ios设备进行消息推送

### file_server
提供tcp服务 辅助完成文件传输功能，提供对文件的推流跟拉流的功能。在线文件时作为文件流的中转，离线文件时做文件的上传的接收服务，等到接受用户上线，又会提供接收用户的拉流服务。

### msfs
提供http服务 小型的共享文件系统，在实现图片传输功能时，充当了图片文件的上传以及下载的功能。同时后台管理上传用户头像也会用这个服务。




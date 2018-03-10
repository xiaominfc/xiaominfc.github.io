---
layout: post
title:  socketIO Client 的实现流程
date: 2016-09-10 22:56:48 +0800
#category: xiaominfc
author: xiaominfc
description: SocketIO Client 的实现流程
categories: SocketIO
source: socketio
comments: true
---

基于socketIO 1.x的版本
服务端：http://localhost:3007

## 1.获取sid
```
http get

request:http://localhost:3007/socket.io/?transport=polling&b64=1&sid


response:
97:0{"sid":"wEnc-Ds06m0oZ1z_AAAM","upgrades":["websocket"],"pingInterval":25000,"pingTimeout":60000}

解析上述信息可以得出sid
解析的流程是
1.读出第一个:的位置 前面的字符串转成int值 就是从:开始后数据结尾的长度
2.得到json格式的数据体
3.获取相关值 sid   upgrades  pingInterval pingTimeout

```

## 2.创建ws连接
```
连接格式:ws://localhost:3007/socket.io/?transport=websocket&sid={sid}
sid的值就是之前获取的sid
```

## 3.发送http的Ping 直到ws连接成功
```
http get
  request:http://localhost:3007/socket.io/?transport=polling&b64=1&sid={sid}

  response:
  返回些数据

```

## 4.在ws没连接成功前 client向server 通过emit行为发送的数据是以http post的方式提交的

```
http post
    request:http://localhost:3007/socket.io/?transport=polling&b64=1&sid={sid}

	response:
	服务端应答的数据

```

## 5.ws连接成功后
```
   首先发送2probe的textframe过去 服务端应答一个3probe的textframe 这样与socketio服务端的连接就算完成建立了
```



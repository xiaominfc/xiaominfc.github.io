---
layout: post
title: 关于sip server内网映射外网的一些记录
date: 2018-03-26 10:26:48 +0800
#category: xiaominfc
author: xiaominfc
description: 关于sip server内网映射外网的一些记录
categories: sip
source: record
comments: true
---


## 前言

~~~

1. 公司要搞个呼叫中心
2. 用了sip这套方案
3. 买了GSM<=>sip的卡机
4. 卡机架设在内网
5. 外网放了个freepbx的sip server
~~~


~~~
freepbx 能通过卡机 拨打手机号
~~~


### 1 端口映射(卡机映射到外网的某个ip)
一开始用了ngrok,但是不行 ngrok只支持tcp，万能github让我找到了国人写的[frp](https://github.com/fatedier/frp)能支持dup(sip server 也支持tcp传输的 但是默认用udp 就默认的来了 少改些配置)
卡机的5060 udp 映射出去了


### 2 拨号
拨号正常收到来电了,但是没有声音。。。。。 各种猜想(运营商屏蔽了rtp包)。。。。。 觉得自己好可爱。。。。。 原因是语音传输rtp 分双线走的。。。。。 内网的卡机也许可以访问到外网 但是外网不一定能访问卡机 所以语音包传输的有问题 怎么办？
恶补各种资料 好吧 很常见的解决方式nat 内网穿透 最后在外网装了个coturn提供stun服务 配置一下卡机有声音了。。。。。（摸索配置的修改搞了半天 确实对这些不熟）

### 3 挂机
很奇怪通电话的双方 居然收不到彼此的挂机事件。。。。。。。 哎 各种看得到的事件都有了 就是没有挂机。。。。。。感觉自己哪里错了。。。。。。想改各种配置 但是都没用，说白了就是在没有理论指导的情况下瞎试验 怎么办?
又恶补各种资料 渐渐熟悉了sip协议，走老路子 抓包，各种包Invite，100Trying，180Ringing，200OK。好吧 没了 没有ACK包 

~~~
1.多亏frp开源 又是用golang开发了
2.研究了一下源码 好吧frp是这么回事呀
3.改。。。。。。
~~~

包都有。。。。。 看着格式也对。。。。。 猜想着 估计ACK发错地方了。。。。。。 想着在frp层面改sip包 看了看sip包里各种跟ip地址相关的 都改了一下，又是一次没有理论指导的尝试
又恶补各种资料 偶然看到了篇文章[SIP INVITE: Contact Header](https://telconotes.wordpress.com/2014/03/09/sip-invite-contact-header/) 恍然大悟 原来是Contact这个字段值写错了 仔细查看发现 虽然卡机的端口确实映射到外网了 但是sip传输的时候 卡机发的sip包中的Contact一直都是自己这个内网所对应的外网IP
而卡机要收到re-INVITE, BYE ,ACK这些包 都是往Contact写的地址发的，于是改了一下frp的源码 处理了Contact的值 改成了我们映射到的外网ip以及port 这样ACK包就收到了。。。。。。。。。


## ps

实践到了一定地步 回过头来看理论 这更有助于理解问题以及解决问题


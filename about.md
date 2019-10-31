---
layout: page
title: About Me
comments: true
#permalink: /about/
---

我是一名热爱研究的programmer

![image of me](/assets/img/user_icon.png){:height="48px"}.

姓名：羊志敏 

籍贯：海南

出生：1991年03月26日

大学：华中科技大学（2009-2013）


----

##### 工作经历：

###### 2013.07-2014.07
公司：深圳有方科技
<br>
职责：android程序员 android rom的定制修改

###### 2014.07-至今
公司：武汉鸣鸾信息科技有限公司
<br>
职责：移动技术总监

1. 负责海投网android ios的app的程序实现以及框架设计
2. 海投网即时通讯系统的后台开发以及维护
3. 各种技术难点攻关实现
4. 培养移动开发人员。
----

#### 擅长工作：
```
1. 运维以及熟练操作linux/unix操作系统
2. 各种语言以及平台的程序开发
3. 热衷研究一些跟工作相关的源码{各种编程语言以及各种平台(win除外)}
4. 一整套即时通讯系统的开发
5. 一整套语音识别系统的开发
6. 各种难点技术的攻关
7. 新奇的技术

```



#### 项目经验:
##### 大学期间：
######  宣讲会查询系统app的实现[2012.01-2013.7]
1. 宣讲会查询系统app(海投网app的前身)开发
2. 迭代维护 主要调用查询接口 显示信息列表 详情 


##### 深圳有方科技期间(android, java)
######  android系统launcher的定制化修改[2013.07-2013.10]
1. 自定义UI
2. 参考市面主流手机对android系统程序luancher做定制
3. 修改部分android framework的代码 手机公司都开始做自己的rom

###### android系统锁屏的定制化修改[2013.10-2013.11]
1. 给锁屏加上定制化效果


###### android系统music应用的实现[2013.11-2014.05]
1. 根据设计重新开发了一款music应用


###### android系统fota升级系统以及推送系统的实现[2013.12-2014.07]
1. 给客户端开发依赖库提供api实现推送
2. 推送系统的后台实现

##### 武汉鸣鸾信息科技(承接多种平台的独立开发以及维护)[海投网:http://www.haitou.cc](http://www.haitou.cc)
###### 海投网app(android java ios objc)[014.08-至今]
1. android/ios客户端的架构设计以及实现
2. android/ios客户端的迭代开发以及维护 5次重大升级
3. 宣讲会/招聘会查询 -> 校招板块 -> 笔经，面经-> 社交板块 ->直播


######  海投网移动端API的重构(php)[2014.08-2014.10]
1. 重构api方便 客户端使用
2. 面向过程的代码用面向对象实现
3. 自定义了一套路由规则
4. 插件式添加安全模块，加密模块

###### 即时通许系统(比较市面最后选择了一个开源项目进行二次开发)(c++ linux java objc php socket epoll libevent pthread ProtocolBuffers mysql redis)[2015.06-至今]
1. 即时通讯系统的后台服务开发以及维护(客户端连接维护服务 数据库业务操作服务 微型文件分享系统 apple推送服务 路由服务 负载均衡服务 http_API服务)
2. 即时通讯系统的客户端开发以及维护(android / ios)
3. 各个平台的集成
4. 拓展业务的开发

###### 至本教育app(校友的创业项目 一款帮助高中毕业生选择大学的app)[2015.10-2016.12]
1. 完成业务需求


###### 即时通讯系统web端的实现(c++ html5 javascript aes websocket ProtocolBuffers)[2015.12-2016.01]
1. 服务端在原有的通讯协议上加上websocket协议完美兼容原有的即时通讯系统
2. 开发web端的api 实现即时web端与客户端之间的通讯
3. 给各个需要整合即时通讯的web模块提供api

###### 直播系统(各种云直播的尝试) [2016.05-2016.10]
1. 培养指导新员工实现android推流客户端
2. 对直播系统进行预研
3. 整合直播功能到客户端


###### 在线教育(nodejs c++ librtmp mp3lame portaudio ffmpeg anyrtc) [2017.04-2017.06]
1. pc端推流模块的实现
2. 只需要音频推流的功能兼容mac跟win，用了ffmpeg 过于臃肿 anyrtc不兼容mac于是整合librtmp mp3lame portaudio开发出了现有的推流模块
3. pc端为了跨平台是基于Electron开发的 所以开发了一个nodejs的c++ addon在win跟mac上使用
4. 在线教育画布的基本实现(websocket) 


###### 移动端web浏览器的直播播放器开发(降低延时) [2017.06-2017.07]
1. fetch API读http+flv的直播流并解析出audio tag 
2. mp3前端解码
3. web audio api播放
4. 降低延时(移动端浏览器不支持flash 相关api也缺少 只能采用格式m3u8做直播 延时25秒+)至5秒内


###### teamtalk [2017.07-至今]
1. 持续迭代改进开发开源即时通讯系统teamtalk(https://github.com/xiaominfc/TeamTalk)
2. dart实现了teamtalk的相关api(https://github.com/xiaominfc/teamtalk_dart_lib)
3. 实现flutter版的聊天app(https://github.com/xiaominfc/flutter_tt)


###### asr [2018.07-至今]
1. 基于kaldi开发基于深度学习的语音识别(asr)系统
2. 开发实时流识别系统提供websocket版api
3. 改进识别模型
4. 训练其他辅助模型完善语音识别


###### 外呼中心 [2018.07-至今]
1. 开发外呼中心调度系统
2. 将sip客户端与语音识别系统,外呼中心对接
3. 实现外呼中心的业务处理

###### tts [2019.07-至今]
1. 开发语音合成(tts)系统

----



##### 技能：

```
1. 写代码 写各种语言的代码 
2. unix文化粉丝 
3. 喜欢研究操作系统的api 平时工作就是写写android或者ios程序（现在写的少了，现在凡是程序都写） 
4. 偶尔写写业务型的javascript代码 
5. 要不然就是胡搞瞎搞各种程序以及源码 喜欢研究posix系统的api 
6. 喜欢从操作系统层面理解并解决问题 
7. 不拘泥于任何语言任何平台任何场景的程序开发
```


#### 业余爱好:

```
骑行，听音乐，看各种编程相关书籍，实践各种编程语言以及想法。
```

#### 联系方式:

1. email: [xiaominfc@126.com](mailto:xiaominfc@126.com)   

2. github: [https://github.com/xiaominfc](https://github.com/xiaominfc)

3. qq: 793101503



微信:扫扫二维码，加我微信

![image of me](/assets/img/weixin_qr.JPG){:height="400px"}.

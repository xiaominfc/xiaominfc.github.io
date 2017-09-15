---
layout: post
title:  android编译librtmp
date: 2017-09-15 20:48:48 +0800
category: android
author: xiaominfc
description: android 编译 librtmp
comments: true
---

## 获取源码
~~~~
git clone git://git.ffmpeg.org/rtmpdump
cd rtmpdump
cp -r ./librtmp ./jni
~~~~


## 在jni目录下写入android ndk的编译配置文件
Android.mk
~~~~
LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)

LOCAL_MODULE := rtmp

#写入要编译的源码 你自己添加的也加上去
LOCAL_SRC_FILES := amf.c hashswf.c log.c parseurl.c rtmp.c


#不依赖加密模式 就是不支持ssl了
LOCAL_CFLAGS += -DNO_CRYPTO
LOCAL_LDLIBS := -llog

include $(BUILD_SHARED_LIBRARY)
~~~~

Application.mk
~~~~
APP_ABI := armeabi armeabi-v7a x86 mips
~~~~

## 编译

~~~~
在jni下执行 ndk-build
~~~~
上级目录就会生成libs 里面就有 armeabi armeabi-v7a x86 mips 需要的依赖 

## 后记
有空再把ssl加上去


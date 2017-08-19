---
layout: post
title:  用llvm_lang认识swift的optionals
date: 2017-08-02 22:56:48 +0800
#category: xiaominfc
author: xiaominfc
description: 用llvm_lang认识swift的optionals
categories: swift
source: swift
comments: true
---

# 前言
~~~~
You use optionals in situations where a value may be absent. An optional represents two possibilities: Either there is a value, and you can unwrap the optional to access that value, or there isn’t a value at all.
~~~~
这是摘录自The Swift Programming Language 书中的一句话。讲了optionals的使用场景，大概就是说：当一个值可能是缺省的时候，要么可以访问这个值，要么不是一个值（为null）


## 一段简单的代码

demo.swift
~~~~
var code: Int? = 100
code = 200
var code_value: Int = code!
var code_b: Int?
code_b = 2
var code_c = code
~~~~

编译一下(带上了编译优化的参数)
~~~~
swiftc -O  -emit-ir ./demo.swift > demo.ll
~~~~
demo.ll核心的几行代码
~~~~
%GSqSi_ = type <{ [8 x i8], [1 x i8] }>
%Si = type <{ i64 }>

@_Tv4demo4codeGSqSi_ = hidden local_unnamed_addr global %GSqSi_ zeroinitializer, align 8
@_Tv4demo10code_valueSi = hidden local_unnamed_addr global %Si zeroinitializer, align 8
@_Tv4demo6code_bGSqSi_ = hidden local_unnamed_addr global %GSqSi_ zeroinitializer, align 8
@_Tv4demo6code_cGSqSi_ = hidden local_unnamed_addr global %GSqSi_ zeroinitializer, align 8
@__swift_reflection_version = linkonce_odr hidden constant i16 1
@llvm.used = appending global [1 x i8*] [i8* bitcast (i16* @__swift_reflection_version to i8*)], section "llvm.metadata"

; Function Attrs: norecurse nounwind
define i32 @main(i32, i8** nocapture readnone) local_unnamed_addr #0 {
entry:
  store i64 200, i64* bitcast (%GSqSi_* @_Tv4demo4codeGSqSi_ to i64*), align 8
  store i1 false, i1* bitcast ([1 x i8]* getelementptr inbounds (%GSqSi_, %GSqSi_* @_Tv4demo4codeGSqSi_, i64 0, i32 1) to i1*), align 8
  store i64 200, i64* getelementptr inbounds (%Si, %Si* @_Tv4demo10code_valueSi, i64 0, i32 0), align 8
  store i64 2, i64* bitcast (%GSqSi_* @_Tv4demo6code_bGSqSi_ to i64*), align 8
  store i1 false, i1* bitcast ([1 x i8]* getelementptr inbounds (%GSqSi_, %GSqSi_* @_Tv4demo6code_bGSqSi_, i64 0, i32 1) to i1*), align 8
  store i64 200, i64* bitcast (%GSqSi_* @_Tv4demo6code_cGSqSi_ to i64*), align 8
  store i1 false, i1* bitcast ([1 x i8]* getelementptr inbounds (%GSqSi_, %GSqSi_* @_Tv4demo6code_cGSqSi_, i64 0, i32 1) to i1*), align 8
  ret i32 0
}
~~~~

## 分析
代码很简单声明定义了optional int型的变量
~~~~
定义了两种结构体:

%GSqSi_ = type <{ [8 x i8], [1 x i8] }> //其实就是一个int64 用来存值 一个int8用来存bool值标识是否值存在
%Si = type <{ i64 }> //为了存一个整数

~~~~

~~~~
初始化变量
@_Tv4demo4codeGSqSi_ = hidden local_unnamed_addr global %GSqSi_ zeroinitializer, align 8 //code
@_Tv4demo10code_valueSi = hidden local_unnamed_addr global %Si zeroinitializer, align 8  //code_value
@_Tv4demo6code_bGSqSi_ = hidden local_unnamed_addr global %GSqSi_ zeroinitializer, align 8 //code_b
@_Tv4demo6code_cGSqSi_ = hidden local_unnamed_addr global %GSqSi_ zeroinitializer, align 8 //code_c

可以看出 变量code code_b code_c 都被声明成%GSqSi_的类型
变量 code_value 则是%Si
~~~~

~~~~
store i64 200, i64* bitcast (%GSqSi_* @_Tv4demo4codeGSqSi_ to i64*), align 8
store i1 false, i1* bitcast ([1 x i8]* getelementptr inbounds (%GSqSi_, %GSqSi_* @_Tv4demo4codeGSqSi_, i64 0, i32 1) to i1*), align 8
~~~~
很典型的赋值 value为200 同时值为空的标识设置为false 若是空值 则为true


## 再来一段代码
~~~~
ode:Int? = 200
code = nil
~~~~

~~~~
define i32 @main(i32, i8** nocapture readnone) local_unnamed_addr #0 {
entry:
  store i64 0, i64* bitcast (%GSqSi_* @_Tv5demo14codeGSqSi_ to i64*), align 8
  store i1 true, i1* bitcast ([1 x i8]* getelementptr inbounds (%GSqSi_, %GSqSi_* @_Tv5demo14codeGSqSi_, i64 0, i32 1) to i1*), align 8
  ret i32 0
}

~~~~
可以看到 code为nil的时候 就是为空标识设置为true了


## 小结:
由此可得optional本质 其实就是用了一个结构体包装了它修饰的类型以及一个为空标识符 当值存在 则标识为false 不存在则标识为true


---
layout: post
title:  CGAffineTransform 使用
date: 2015-09-19 22:00:48 +0800
#category: xiaominfc
author: xiaominfc
description: UIView 使用CGAffineTransform做动画
categories: ios
source: ios
comments: true
---

## 总结一下CGAffineTransform

CGAffineTransform 主要是UIView中的一个名为transform的属性使用的结构体

~~~~
public struct CGAffineTransform {
    public var a: CGFloat
    public var b: CGFloat
    public var c: CGFloat
    public var d: CGFloat
    public var tx: CGFloat
    public var ty: CGFloat
    public init()
    public init(a: CGFloat, b: CGFloat, c: CGFloat, d: CGFloat, tx: CGFloat, ty: CGFloat)
}
~~~~

主要是为了实现UIVIew 旋转(rotate) 移动(translate) 伸缩(scale) 这样的2D变换

CGAffineTransform这个结构体里有6个属性
假设一个point为 (x,y)  经过CGAffineTransform 变化后的point为

~~~~
x’ = a * x + c * y + t * x 
y’ = b * x + b * y + t * y
~~~~

说白了就是坐标系的变换


## 几个构造CGAffineTransform的函数

1.移动变换:
~~~~
public func CGAffineTransformMakeTranslation(tx: CGFloat, _ ty: CGFloat) -> CGAffineTransform
~~~~
~~~~
构造出来的CGAffineTransform  a = 1, b = 0, c = 0, d = 1, tx = _tx , ty = _ty
代入公式就有:
x’ = x + tx 
y’ = y + ty
~~~~

2.伸缩变换:
~~~~
public func CGAffineTransformMakeScale(sx: CGFloat, _ sy: CGFloat) -> CGAffineTransform
~~~~
~~~~
构造出来的CGAffineTransform  a = sx, b = 0, c = 0, d = sy, tx = 0, ty = 0
代入公式就有:
x’ = x * sx
y’ = y * sy
~~~~
3.旋转变换:
~~~~
public func CGAffineTransformMakeRotation(angle: CGFloat) -> CGAffineTransform
~~~~
~~~~
构造出来的CGAffineTransform  a = cos(angle), b = sin(angle), c = -sin(angle) , d = cos(angle) , tx = 0, ty = 0
代入公式就有:
x’ = x * cos(angle) - y * sin(angle)
y’ = x * sin(angle) + y * cos(angle) 
~~~~

4.矩阵求逆:
~~~~
public func CGAffineTransformInvert(t: CGAffineTransform) -> CGAffineTransform
~~~~
~~~~
这个是根据矩阵求逆 求出对应的逆变换
api里讲道 CGAffineTransform 配合最后一列为(0,0,1) 构造了3x3的一个矩阵
| a  b  0 |
| c  d  0 |
| tx ty 1 |
~~~~
上述接口就是对该矩阵求其逆矩阵 如果不存在逆矩阵就返回原来的(ps: 判断有没有逆矩阵的可以通过判断 (a * d) - (b * c)的值 如果不等于0 就有 等于 0 则没有)
求逆矩阵 可以看看线性代数


5.矩阵相乘:
~~~~
public func CGAffineTransformConcat(t1: CGAffineTransform, _ t2: CGAffineTransform) -> CGAffineTransform
~~~~
这个是让两个矩阵相乘得出新的3x3矩阵中对应的值 构造出新的CGAffineTransform (矩阵相乘)

6.矩阵相乘(其他形式):
~~~~
public func CGAffineTransformTranslate(t: CGAffineTransform, _ tx: CGFloat, _ ty: CGFloat) -> CGAffineTransform
public func CGAffineTransformScale(t: CGAffineTransform, _ sx: CGFloat, _ sy: CGFloat) -> CGAffineTransform
public func CGAffineTransformRotate(t: CGAffineTransform, _ angle: CGFloat) -> CGAffineTransfor
~~~~
这个三个api 主要是在后面用的参数的(除t: CGAffineTransform以外的参数)的基础上构造出的CGAffineTransform 与 t 进行矩阵相乘


## 其他接口

~~~~
public func CGAffineTransformIsIdentity(t: CGAffineTransform) -> Bool
~~~~
这个是判断 通过构造出来的CGAffineTransform 变换后的x’ y’ 是否跟原来的x y一样

~~~~
public func CGPointApplyAffineTransform(point: CGPoint, _ t: CGAffineTransform) -> CGPoint
public func CGSizeApplyAffineTransform(size: CGSize, _ t: CGAffineTransform) -> CGSize
public func CGRectApplyAffineTransform(rect: CGRect, _ t: CGAffineTransform) -> CGRect
~~~~
这三个接口是依次为了计算点 线(长宽) 面(矩形区域) 进行变换后的结果

## 小结
来个易于理解的公式:

~~~~

(x’ , y’ , 1) = ( x , y , 1) * | a  b  0 |
                               | c  d  0 |
                               | tx ty 1 |
~~~~

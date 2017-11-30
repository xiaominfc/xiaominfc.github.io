
---
layout: post
title:  机器学习&tensorflow相关
date: 2017-11-18 22:56:48 +0800
#category: xiaominfc
author: xiaominfc
description: 机器学习 tensorflow相关
categories: 机器学习 tensorflow
source: tensorflow
comments: true
---


##机器学习任务

###1.supervised learning(监督式学习)

~~~~
是从标记的训练数据推断函数的机器学习任务。
在监督式学习中，每个例子都是由一个输入对象（通常是一个向量）和一个期望的输出值（也称为监督信号）组成的一对。
监督式学习算法分析训练数据并产生一个推断的函数，可用于映射新的例子。
最佳方案将允许算法正确地确定不可见实例的类标签。
这就要求学习算法以“合理”的方式从训练数据推广到看不见的情况（见感应偏差）
~~~~


###2.unsupervised learning(无监督式学习)

~~~~
从“未标记的”数据（未包括在观察中的分类或分类）推导出隐藏结构的功能。
由于给予学习者的例子没有标签，所以没有评估相关算法输出的结构的准确性-这是区分无监督学习与监督学习和强化学习的一种方法。
~~~~


###3.reinforcement learning(强化学习)

~~~~
强化学习（RL）是受行为主义心理学启发的机器学习领域，关注软件特工如何在环境中采取行动，从而最大化累积奖励的概念。
这个问题由于其一般性，在博弈论，控制论，运筹学，信息论，基于仿真的优化，多智能体系统，群体智能，统计学和遗传算法等许多学科中都有研究。
在操作研究和控制文献中，强化学习方法被研究的领域称为近似动态规划。
在最优控制理论中已经研究了这个问题，尽管大多数研究都关注最优解的存在及其表征，而不是学习或近似的方面。
在经济学和博弈论中，强化学习可以用来解释在有限理性下平衡是如何产生的。
~~~~


##tensorflow

###data model(数据模型)

~~~~
数据模型相当于在tensorflow中的张量(tensor)，简单的说就是多维数组,具有三个特征:Rank(阶),Shape(形状),Type(类型)
~~~~

Rank(阶)

阶 | 数学实例              | python(tensorflow)
---|-----------------------|------------------------------------------------------------------------
0  | 纯量 (只有大小)       | size      = tf.constant(100)
1  | 向量(大小和方向)      | vector    = tf.constant([1,2,3,4]) 
2  | 矩阵(数据表)          | matrix    = tf.constant([1,2],[3,4])
3  | 3阶张量 (数据立体)    | cube_matrix = tf.constant([[[1],[2],[3]],[[4],[5],[6]],[[7],[8],[9]]])
n  | n阶张量               | .....


Shape(形状)


阶 |形状                 |维数  |实例
---|---------------------|------|-------------------------------------
0  |[]                   | 0-D  | 一个0维张量即纯量
1  |[D0]                 | 1-D  | 一维张量形式[2]
2  |[D0,D1]              | 2-D  | 二维张量形式[2,3]
3  |[D0,D1,D2]           | 3-D  | 三维张量形式[2,3,4]
n  |[D0,D1,D2....D(n-1)] | n-D  | n维张量的形式[D0,D1,D2.....D(n-1)]  


Type(类型)


数据类型      | Python类型       |描述
--------------|------------------|--------------------------------------
DT_FLOAT      |tf.float32        |32位浮点型
DT_DOUBLE     |tf.float64        |64位浮点型
DT_INT8       |tf.int8           |8位有符整型
DT_INT16      |tf.int16          |16位有符整型
DT_INT32      |tf.int32          |32位有符整型
DT_INT64      |tf.int64          |64位有符整型
DT_UINT8      |tf.uint8          |8位无符整型
DT_STRING     |tf.string         |可变长度的字节数组
DT_BOOL       |tf.bool           |布尔
DT_COMPLEX128 |tf.complex128     |2个64位浮点型数据组(实数和虚数)成的复数
DT_QINT8      |tf.qint8          |用于量化ops的8位有符整型
DT_QINT32     |tf.qint32         |用于量化ops的32位有符整型
DT_QUINT8     |tf.quint8         |用于量化ops的8位无符整型



###Variables

~~~
Variable 是tensorflow 用于存放或者更新参数的实例
~~~

demo

~~~
import tensorflow as tf
value = tf.Variable(0,name="value")
one = tf.constant(1)
new_value = tf.add(value,one)
update_value = tf.assgin(value,new_value)
initialize_var = tf.global_variables_initializer()
with tf.Session() as sess:
    sess.run(initialize_var)
    print(sess.run(value))
    for _ in range(10):
        sess.run(update_value)
        print(sess.run(value))

~~~

###Fetches

~~~
获取运算的输出结果
~~~

demo

~~~
import tensorflow as tf

constant_A = tf.constant([100.0])
constant_B = tf.constant([300.0])
constant_C = tf.constant([3.0])

sum_ = tf.add(constant_A,constant_B)
mul_ = tf.multiply(constant_A, constant_C)
with tf.Session() as sess:
    result = sess.run([sum_,mul])
    print(result)


~~~


###Feeds

~~~
提供运算的输入数据
~~~


demo

~~~
import tensorflow as tf
import numpy as np

a = 3
b = 2
x = tf.placeholder(tf.float32, shape=(a,b))
y = tf.add(x,x)
data = np.random.rand(a,b)
sess = tf.Session()
print sess.run(y, feed_data={x:data})

~~~

###使用TensorBoard

####安装

~~~
pip install tensorboard

~~~

###未完待续！



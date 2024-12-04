---
layout: post
title: llm一种剪枝的方式(合并LayerNorm跟Linear)
date: 2024-12-05 01:45:11 +0800
author: xiaominfc
description: llm一种简单的剪枝方式
categories: 机器学习 llm
source: record
comments: true
---
# llm一种剪枝的方式(合并LayerNorm跟Linear)

## 前言 
llm模型中经常会遇到LayerNorm跟Linear相连，通过LayerNorm中的weight跟bias作用到Linear中，进而不再依赖LayerNorm的weight跟bias来计算


## 测试代码


```(python)
import torch
from torch import nn
import time


shape =(512,1024)


norm = nn.LayerNorm(shape[0])
linear = nn.Linear(shape[0],shape[1])

# 初始化参数
nn.init.normal_(norm.weight,std=0.1)
nn.init.normal_(norm.bias,std=0.1)
nn.init.normal_(linear.weight,std=0.1)
nn.init.normal_(linear.bias,std=0.1)




# 合并 norm 跟 linear 成一个新的linear
linear1 = nn.Linear(shape[0],shape[1])
linear1.weight = torch.nn.Parameter(torch.mul(linear.weight,norm.weight))
linear1.bias = torch.nn.Parameter(torch.add(torch.matmul(linear.weight,norm.bias),linear.bias))


norm = norm.eval()
linear = linear.eval()
linear1 = linear1.eval()
if torch.cuda.is_available():
    norm = norm.cuda()
    linear = linear.cuda()
    linear1 = linear1.cuda()




input = torch.rand(20,shape[0])
if torch.cuda.is_available():
    input = input.cuda()

out1 = linear1(torch.layer_norm(input,(shape[0],)))

out = linear(norm(input))
print("out1:",out1)
print("out:",out)


test_count = 10000
time0 = 0
time1 = 0


for i in range(test_count):
    input = torch.rand(20,shape[0])
    if torch.cuda.is_available():
        input = input.cuda()
    start = time.time()
    out = linear(norm(input))
    time0 = time0 + (time.time()-start)

for i in range(test_count):
    input = torch.rand(20,shape[0])
    if torch.cuda.is_available():
        input = input.cuda()
    start = time.time()
    out1 = linear1(torch.layer_norm(input,(shape[0],)))
    time1 = time1 + (time.time()-start)

# 比较耗时
print(time0,time1)
```

上述代码可以看出 out1 out的输出是一样的,time1 也比 time0小一些。
原理上来说LayerNorm 没有weight跟bias 所以就可以少做一次tensor的乘法跟加法了


### 后记 

在用ggml这种来实现llm时遇到这种情况构图时就会体现的特别明显

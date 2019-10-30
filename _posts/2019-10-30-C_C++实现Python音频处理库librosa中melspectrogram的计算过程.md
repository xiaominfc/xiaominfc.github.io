---
layout: post
title:  C/C++实现Python音频处理库librosa中melspectrogram的计算
date: 2019-10-30 10:26:48 +0800
author: xiaominfc
description: c/c++ 实现 librosa中melspectrogram
categories: kaldi asr python librosa
comments: true
---


# C/C++实现Python音频处理库librosa中melspectrogram的计算

## 前言

为何这般无聊！

```
1.神经网络模型用了python实现 需移植到C/C++上
2.不想引入python的依赖库来运行python代码
3.C/C++没找到相关实现
4.生活不易
```

## 探索

阅读了librosa.feature.melspectrogram的源码发现其实这一整个过程都是用python的numpy计算库完成的于是提取 于是进行了整理 归总如下：

file:melspectrogram_util.py

```python

import numpy as np
from numpy.lib.stride_tricks import as_strided
MAX_MEM_BLOCK = 2**8 * 2**10

### hann window

def _len_guards(M):
    if int(M) != M or M < 0:
        raise ValueError('Window length M must be a non-negative integer')
    return M <= 1


def _extend(M, sym):
    if not sym:
        return M + 1, True
    else:
        return M, False


def _truncate(w, needed):
    if needed:
        return w[:-1]
    else:
        return w



def general_cosine(M, a, sym=True):
    if _len_guards(M):
        return np.ones(M)
    M, needs_trunc = _extend(M, sym)
    fac = np.linspace(-np.pi, np.pi, M)
    w = np.zeros(M)
    for k in range(len(a)):
        w += a[k] * np.cos(k * fac)

    return _truncate(w, needs_trunc)


def general_hamming(M, alpha, sym=True):
    return general_cosine(M, [alpha, 1. - alpha], sym)


def hann(M, sym=True):
    return general_cosine(M, [0.5, 0.5], sym)
    #return general_hamming(M, 0.5, sym)


#### end window



#### filters
def fft_frequencies(sr=22050, n_fft=2048):

    return np.linspace(0,
                       float(sr) / 2,
                       int(1 + n_fft//2),
                       endpoint=True)

def hz_to_mel(frequencies, htk=False):
    frequencies = np.asanyarray(frequencies)
    if htk:
        return 2595.0 * np.log10(1.0 + frequencies / 700.0)

    # Fill in the linear part
    f_min = 0.0
    f_sp = 200.0 / 3

    mels = (frequencies - f_min) / f_sp

    # Fill in the log-scale part

    min_log_hz = 1000.0                         # beginning of log region (Hz)
    min_log_mel = (min_log_hz - f_min) / f_sp   # same (Mels)
    logstep = np.log(6.4) / 27.0                # step size for log region

    if frequencies.ndim:
        # If we have array data, vectorize
        log_t = (frequencies >= min_log_hz)
        mels[log_t] = min_log_mel + np.log(frequencies[log_t]/min_log_hz) / logstep
    elif frequencies >= min_log_hz:
        # If we have scalar data, heck directly
        mels = min_log_mel + np.log(frequencies / min_log_hz) / logstep

    return mels

def mel_to_hz(mels, htk=False):
    mels = np.asanyarray(mels)
    if htk:
        return 700.0 * (10.0**(mels / 2595.0) - 1.0)

    # Fill in the linear scale
    f_min = 0.0
    f_sp = 200.0 / 3
    freqs = f_min + f_sp * mels
    min_log_hz = 1000.0                         # beginning of log region (Hz)
    min_log_mel = (min_log_hz - f_min) / f_sp   # same (Mels)
    logstep = np.log(6.4) / 27.0                # step size for log region

    if mels.ndim:
        # If we have vector data, vectorize
        log_t = (mels >= min_log_mel)
        freqs[log_t] = min_log_hz * np.exp(logstep * (mels[log_t] - min_log_mel))
    elif mels >= min_log_mel:
        # If we have scalar data, check directly
        freqs = min_log_hz * np.exp(logstep * (mels - min_log_mel))

    return freqs

def mel_frequencies(n_mels=128, fmin=0.0, fmax=11025.0, htk=False):
    min_mel = hz_to_mel(fmin, htk=htk)
    max_mel = hz_to_mel(fmax, htk=htk)
    mels = np.linspace(min_mel, max_mel, n_mels)
    return mel_to_hz(mels, htk=htk)


def filters_mel(sr, n_fft, n_mels=128, fmin=0.0, fmax=None, htk=False,
        norm=1):
    if fmax is None:
        fmax = float(sr) / 2

    if norm is not None and norm != 1 and norm != np.inf:
        raise ParameterError('Unsupported norm: {}'.format(repr(norm)))

    # Initialize the weights
    n_mels = int(n_mels)
    weights = np.zeros((n_mels, int(1 + n_fft // 2)))
    fftfreqs = fft_frequencies(sr=sr, n_fft=n_fft)
    mel_f = mel_frequencies(n_mels + 2, fmin=fmin, fmax=fmax, htk=htk)
    fdiff = np.diff(mel_f)
    ramps = np.subtract.outer(mel_f, fftfreqs)
    
    for i in range(n_mels):
        lower = -ramps[i] / fdiff[i]
        upper = ramps[i+2] / fdiff[i+1]
        weights[i] = np.maximum(0, np.minimum(lower, upper))

    if norm == 1:
        # Slaney-style mel is scaled to be approx constant energy per channel
        enorm = 2.0 / (mel_f[2:n_mels+2] - mel_f[:n_mels])
        weights *= enorm[:, np.newaxis]

    return weights

#### end filters


def frame(x, frame_length=2048, hop_length=512, axis=-1):
    n_frames = 1 + (x.shape[axis] - frame_length) // hop_length
    strides = np.asarray(x.strides)
    new_stride = np.prod(strides[strides > 0] // x.itemsize) * x.itemsize
    shape = list(x.shape)[:-1] + [frame_length, n_frames]
    strides = list(strides) + [hop_length * new_stride]
    result = as_strided(x, shape=shape, strides=strides)
    return result



def pad_center(data, size, axis=-1, **kwargs):
    kwargs.setdefault('mode', 'constant')

    n = data.shape[axis]
    lpad = int((size - n) // 2)
    lengths = [(0, 0)] * data.ndim
    lengths[axis] = (lpad, int(size - n - lpad))

    if lpad < 0:
        raise ParameterError(('Target size ({:d}) must be '
                              'at least input size ({:d})').format(size, n))

    return np.pad(data, lengths, **kwargs)




# fft

def stft(y, n_fft=2048, hop_length=None, win_length=None, window='hann',
         center=True, dtype=np.complex64, pad_mode='reflect'):
    if win_length is None:
        win_length = n_fft
    if hop_length is None:
        hop_length = int(win_length // 4)
    fft_window = hann(win_length,sym=False)
    fft_window = pad_center(fft_window, n_fft)
    fft_window = fft_window.reshape((-1, 1))
    if center:
        y = np.pad(y, int(n_fft // 2), mode=pad_mode) # 两边各补n_fft的一半 对称

    
    y_frames = frame(y, frame_length=n_fft, hop_length=hop_length) 
    stft_matrix = np.empty((int(1 + n_fft // 2), y_frames.shape[1]),
                           dtype=dtype,
                           order='F')
    fft = np.fft
    n_columns = int(MAX_MEM_BLOCK / (stft_matrix.shape[0] *
                                          stft_matrix.itemsize))
    for bl_s in range(0, stft_matrix.shape[1], n_columns):
        bl_t = min(bl_s + n_columns, stft_matrix.shape[1])
        data = y_frames[:, bl_s:bl_t] *fft_window
        stft_matrix[:, bl_s:bl_t] = fft.rfft(fft_window *
                                             y_frames[:, bl_s:bl_t],
                                             axis=0)
    return stft_matrix


def melspectrogram(y=None, sr=22050, S=None, n_fft=2048, hop_length=512,power=2.0, **kwargs):
    S = stft(y,n_fft=1024,hop_length=hop_length)
    S = np.abs(S)**power
    mel_basis = filters_mel(sr,n_fft=n_fft,**kwargs)
    return np.dot(mel_basis, S)


if __name__ == '__main__':
    import librosa
    #y, sr = librosa.load('./5016672465406.wav',sr=None)
    y, sr = librosa.load('./6983123609037.wav',sr=None)
    n_fft = 1024
    mels = librosa.feature.melspectrogram(y=y, sr=sr, n_mels=80,fmax=8000,n_fft=n_fft)
    print(mels.T)
    print("=============")
    print(melspectrogram(y,sr=sr,n_fft=n_fft,n_mels=80,fmax=8000).T)


```

```
1.这里面有些我用默认的所以去掉了些多余代码
2.写到这里以后python计算melspectrogram 以后就不再依赖librosa 而只依赖numpy了
3.大致可以看到它的实现 window=>frame=>fft=>mel_basis
```

## C/C++的实现 

### 1. window(加窗)

```
//hanning窗
void hanning_w(int frame_length,Vector<double64>& window) {
	window.Resize(frame_length);
	double PI = 3.141592653589793;
	double PI_2 = PI * 2.0;
	double a = PI_2 / (frame_length);
	//printf("a:%.10lf\n",a);
	for (int32 i = 0; i < frame_length; i++) {
		double i_fl = static_cast<double>(i);
		window(i) = 0.5  - 0.5*cos(a * i_fl);
	}
}

// 指定长度用等步长就能求了
```


### 2.数据分帧

```
//数据分帧
void frame_data(Vector<double64> &data,int frame_length,int hop_length, Matrix<double64> &frames){
	int n_frames = (data.Dim() - frame_length ) / hop_length + 1;
	frames.Resize(frame_length,n_frames);
	for(int i=0; i < frame_length; i ++) {
		for(int j = 0; j < n_frames; j ++) {
			int index = i + j * hop_length;
			if(index < data.Dim()) {
				frames(i,j) = data.Data()[index]; 
			}else {
				printf("index to large:%d\n",index);
			}
		}
	}
}

// 帧长 步长 数据长度 就能计算 帧总数 按步长取值填入
```

### 3.fft

进行fft之前 先要对frames跟window做乘法运算 在进行快速傅立叶变换

```
frames.MulRowsVec(window);
Matrix<double64> fft_result;
fft_result.Resize(half_n_fft + 1,frames.NumCols());
complex *pSignal = new complex[frames.NumRows()];
for(int i = 0; i < frames.NumCols(); i ++) {
	for(int j = 0; j < frames.NumRows();j++) {
		pSignal[j] = frames(j,i);
	}
	CFFT::Forward(pSignal,n_fft);
	for(int j = 0; j < fft_result.NumRows(); j ++) {
		double v = sqrt(pSignal[j].re()*pSignal[j].re()+pSignal[j].im()*pSignal[j].im());
		fft_result(j,i) = pow(v,2.0);//power的值 默认2.0 用在这个地方 其实直接前面一步不开方就是结果了
	}
}
//在numpy中 用的是rfft 这样的结果就是 正常fft结果的一半+1个数据
```

### 4. 计算mel_basis



```
double hz_to_mel(double frequencies){
	double mels = (frequencies - MIN_F) / FSP;
	if(frequencies >= MIN_LOG_HZ) {
	  mels = (MIN_LOG_HZ - MIN_F)/FSP + log(frequencies / MIN_LOG_HZ) / LOG_STEP;
	}
	return mels;
}

double mel_to_hz(double mels) {
	double freqs = MIN_F + FSP * mels;
	if(mels >= MIN_LOG_MEL) {
		freqs = MIN_LOG_HZ * exp(LOG_STEP * (mels - MIN_LOG_MEL));
	}
	return freqs;
}

//mel 单元
void filters_mel(float sr,uint n_fft,uint n_mels,float fmin,float fmax, Matrix<double64> &mel_basis) {
	if(fmax == 0.0) {
		fmax = sr / 2.0;
	}
	uint rows = 1+n_fft/2;
	mel_basis.Resize(n_mels,rows);
	// gen mel_frequencies
	double min_mel = hz_to_mel(fmin);
	double max_mel = hz_to_mel(fmax);
	Vector<double64> mels;
	mels.Resize(n_mels + 2);
	double offset_mel = (max_mel - min_mel)/(n_mels + 1);
	double offset_hz = sr/n_fft; 
	mels(0) = mel_to_hz(min_mel);
	mels(1) = mel_to_hz(min_mel + offset_mel);
	mels(mels.Dim() - 1) = mel_to_hz(max_mel);
	for(int i = 2; i < mels.Dim(); i ++) {
		double down_hz= mels(i - 2);
		double up_hz = mel_to_hz(min_mel + offset_mel*i);
		mels(i) = up_hz;
		for(int j = 0; j < rows; j++ ) {
			double lower = -1.0 * (down_hz - offset_hz*j) / (mels(i-1)-down_hz);
			double upper = (up_hz -offset_hz*j) / (up_hz - mels(i-1));
			double min  = lower < upper? lower:upper;
			min = min > 0?min:0.0;
      		mel_basis(i-2,j) = min*2.0/ (up_hz-down_hz);
		}
	}
}

/*
前两个函数是辅助计算 频率跟梅谱之间的转换
filters_mel 生成结构
*/

```

### 5. 计算结果

```

result.Resize(fft_result.NumCols(),mel_basis.NumRows());
for(int i = 0; i < result.NumRows(); i ++) {
	for(int j = 0; j < result.NumCols(); j ++) {
		double sum = 0;
		for(int index = 0; index < half_n_fft + 1; index++ ){
			sum += fft_result(index,i)*mel_basis(j,index);
		}
		result(i,j) = sum;
	}
}
// 就是做一次矩阵相乘
```

以上就是计算过程


## 尾声
按照上述过程还能类似实现librosa的一些别的特征求值过程如：librosa.feature.mfcc 
其实就是在此基础上实现的

[代码上传到了github上](https://github.com/xiaominfc/melspectrogram_cpp)


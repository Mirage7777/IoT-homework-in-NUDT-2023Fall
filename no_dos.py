# DoS_attack_dataset_no_zero
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

# 1.读取csv文件
df = pd.read_csv('No_DoS_attack.csv', sep='\t')

# 2.滑动窗口
w=500
k=2.5

shang=[]  # 记录不同窗口的信息熵
err_time=[]  # 记录时间戳
for st in range(0,len(df),w):
    # 以w的步长移动窗口
    data = df.iloc[st:st+w]
    # 得到本窗口内第1条消息的时间戳的值
    end_time = data.iloc[0]['TimeStamp']
    err_time.append(end_time)
    # 得到窗口内不同ID消息出现的频率
    p_data = data['ID'].value_counts() / data['ID'].count()
    # 计算该窗口内的信息熵
    shang.append(-sum(p_data*np.log(p_data)))
    if st % 1000==0:
        print(st)

# 计算无攻击下的信息熵均值和方差
arr_mean = np.mean(shang)    
arr_std = np.std(shang, ddof=1)
print(arr_mean,arr_std)

# 区间
a=arr_mean-k*arr_std
b=arr_mean+k*arr_std

# 绘图
plt.plot(err_time,shang,c='b')
plt.axhline(y=a,ls='--',c='blue')
plt.axhline(y=b,ls='--',c='blue')
plt.show()

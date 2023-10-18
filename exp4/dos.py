# Add_DoS_attack_dataset1
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

# 读取csv文件
df = pd.read_csv('DoS_attack.csv', sep='\t')
w=500

shang=[]
err_time=[]
k=2.5

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

plt.plot(err_time,shang,c='g')
plt.show()

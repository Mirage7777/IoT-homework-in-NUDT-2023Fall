import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import random
import math

def entropy(df_no,df_dos,x,dos_start,flag): 
    
    # 1.初始化
    num=0  # 攻击块数目
    ans=0  # 正确检测为攻击块个数
    err_ans=0 # 错误检测为攻击块个数
    t=[]  # 记录时间戳
    shang=[]  # 记录信息熵
    t_dos=[]
    shang_dos=[]
    df_no=df_no.values
    df_dos=df_dos.values
    
    # 用数据1计算信息熵均值和方差
    for st in range(0,len(df_no),x[0]):
        # 取出以st为起点，窗口大小为step的数据
        data = df_no[st:st+x[0]]
        # 得到本窗口内第1条消息的时间戳的值
        end_time = data[0,1]
        t.append(end_time)
        #得到窗口内不同ID消息出现的频率
        unique, counts = np.unique(data[:,2], return_counts=True)
        p_data = counts/np.sum(counts)
        # 计算熵
        shang.append(-sum(p_data*np.log(p_data)))

    # 计算均值和方差
    arr_std = np.std(shang, ddof=1)
    arr_mean = np.mean(shang)
    # 得到正常的信号区间
    a=arr_mean-x[1]*arr_std
    b=arr_mean+x[1]*arr_std
    
    # 用数据2检测受攻击块数
    res_time=[]  # 记录响应时间  
    for st in range(0,len(df_dos),x[0]):
        data = df_dos[st:st+x[0]]
        end_time = data[0,3]
        t_dos.append(end_time)
        unique, counts = np.unique(data[:,2], return_counts=True)
        p_data = counts/np.sum(counts)
        shang_t=-sum(p_data*np.log(p_data))  # 定义shang_t用于判断攻击块
        shang_dos.append(shang_t)
        
        # 若有ID=0,记录为攻击块
        if 0 in data[:,2]:
            num+=1
            # 是攻击块且正确检测
            if shang_t<a or shang_t>b:
                ans+=1
                # 计算响应时间
                dos_time=dos_start[st]  # 攻击更早开始，则有延时
                if dos_time==-1:
                    # temp=st
                    # while dos_start[temp]==-1:
                    #     temp+=1
                    dos_time=st    # 攻击在该窗口，当做无延迟
                res_time.append(df_dos[st,3]-df_dos[dos_time,3])
        else:
            # 不是攻击块被错误检测
            if shang_t<a or shang_t>b:
                err_ans+=1
            
    # 评估函数
    # 评估指标
    ra=ans/num  # 预测准确率
    rn=err_ans/(int(len(df_dos)/x[0])-num)  # 假阳性率
    rs=np.array(res_time)
    rs=np.mean((max(rs)-rs)/(max(rs)-min(rs)))  # 响应时间
    
    # 综合评估
    eva=0.5*ra+0.3*(1-rn)+0.2*rs
    print("预测准确率: %.2f"%ra,"假阳性率: %.2f"%rn,"响应时间: %.4f"%(1-rs),"评估指数: %.4f"%eva)
    if flag==1:
        plot_fig(t,shang,t_dos,shang_dos,a,b)
    return eva

#构造新解
def solution(x):
    x_new=[0,0]
    x_new[0] = int(x[0]+np.random.uniform(low=-10, high=10))
    while x_new[0]<=30:
        x_new[0] = int(x[0]+np.random.uniform(low=-10, high=10))
    x_new[1] = x[1]+np.random.uniform(low=-0.3, high=0.3)
    while x_new[1]<=1:
        x_new[1] = x[1]+np.random.uniform(low=-0.3, high=0.3)
    return x_new

def plot_fig(t,shang,t_dos,shang_dos,a,b):
    plt.plot(t,shang,c='b',label='No_DOS_Attack')
    plt.plot(t_dos,shang_dos,c='g',label='Exist_DOS_Attack')
    plt.legend()
    plt.axhline(y=a,ls='--',c='y')
    plt.axhline(y=b,ls='--',c='y')
    


def attack_start(df_dos):
    pre_i = -1  # 下标初始化-1
    dos_start=[]
    df=df_dos.values
    flag=1  # flag=0代表出现（连续）攻击块
    for i in df[:,0]:
        if df[i,2]==0:  # 若是攻击块
            if flag==1:  # 且是新的连续攻击
                pre_i=i  # 起点置为当前下标
                flag=0   # 标记为连续攻击
        else:   # 若不是攻击块
            pre_i=-1  
            flag=1  # 标记为非攻击
        dos_start.append(pre_i)  # 记录下标
    return dos_start
    
    
if __name__ == '__main__':
    
    ##1. 读取数据
    df_no = pd.read_csv('No_DoS_attack.csv', sep='\t')
    df_dos = pd.read_csv('DoS_attack.csv', sep='\t')
    
    ##2. 打表，标记各数据的攻击开始时间
    print("正在打表，标记攻击开始时间:")
    dos_start=attack_start(df_dos)
    print("打表完成")
    
    #模拟退火优化w和k
    #设定迭代次数和终止条件
    t = 100  # 初始温度
    t_dis=0.98
    step=5  # 每个温度下迭代次数
    t_min=1  # 停止温度
    
    #随机初始解
    w=100
    k=5
    x=[w,k]
    print("初始解")
    print("T = %.2f" % t,"w =",w,"k = %.2f"%k)
    
    # 初始解的结果
    eva_cur=entropy(df_no,df_dos,x,dos_start,0)
    eva_ls=[eva_cur]
    temp=8000
    
    #模拟退火
    print("\n模拟退火迭代:")
    while t>=t_min:
        for i in range(step):
            # 构造新解w,k
            x_new=solution(x)
            print("T = %.2f" % t,"w =",x_new[0],"k = %.2f"%x_new[1])
            # 新解的结果
            eva_new=entropy(df_no,df_dos,x_new,dos_start,0)
            # 若新解更优秀，选择新解
            if eva_new>eva_cur:
                x=x_new
                eva_cur=eva_new
                print("新解更优,接受新解\n")
            else:
                # 否则，以 p 的概率接受新解
                p = math.exp(-(eva_cur - eva_new)*temp / t)
                r = np.random.uniform(low=0,high=1)
                print("新解较差,以 %.2f 的概率接受新解"%p," → 随机 p = %.2f"% r)
                if r<p:
                    x = x_new
                    eva_cur = eva_new
                    print("接受新解\n")
                else:
                    print("拒绝新解\n")
        eva_ls.append(eva_cur)
        t = t_dis*t
        # print("T = %.2f" % t,"w =",w,"k = %.2f"%k)
        
    #输出结果并绘制图像
    #绘制信息熵和判断范围图
    fig = plt.figure()
    ax = fig.add_subplot(121)
    entropy(df_no,df_dos,x,dos_start,flag=1)
    
    #绘制评估指标变化图
    ax = fig.add_subplot(122)
    plt.plot(eva_ls)

from matplotlib import colors
import pandas as pd
import math
import matplotlib.pyplot as plt
import numpy as np
import random as rnd
import time

INF = 999

#绘制图像的功能，输入横纵坐标
def draw_photo(x_data, y_data, x_label, y_label, W, avg_y):
    plt.xlabel(x_label)
    plt.ylabel(y_label)

    x = np.arange(0, x_data[-1] + 1, 0.1)
    y = x * 0 + avg_y
    plt.plot(x, y, color = "Blue")
    plt.plot(x_data, y_data, color = "red")

    plt.title("Entropy detection (sample number is: {})".format(W))
    plt.show()

#根据W计算Ue的最值和sigma_e
def cal_Ue_best(W):
    count = 0
    No_attack_file = pd.read_csv('No_DoS_attack.csv', sep='\t')
    H_I = []
    range_e_list = []

    #绘图用
    time_list = []
    test_start_time = time.time()

    while count < len(No_attack_file):
        if count + W <= len(No_attack_file):
            test_data = No_attack_file.iloc[count: count + W]
            count = count + W
        else:
            test_data = No_attack_file.iloc[count: len(No_attack_file)]
            count = len(No_attack_file)
            
        #计算H(id)的值，信息熵一般取2为底
        p_data = test_data['ID'].value_counts() / test_data['ID'].count()
        H_id = p_data * np.log2(1 / p_data)

        #将每个H_I添加到列表里，然后计算出它的平均值
        H_I.append(np.sum(H_id))

        #绘图用
        test_time = time.time() - test_start_time
        time_list.append(test_time)

        #将每个标准差添加到列表里，计算出range_e的平均值
        range_e_list.append(np.std(H_id, ddof=1))
    
    Ue_best = np.mean(H_I)
    range_e = np.mean(range_e_list) 
    draw_photo(time_list, H_I, "test time", "test Entropy Value",  W, Ue_best)
    print(Ue_best, range_e)
    return Ue_best, range_e


#算法1的主要思想是计算滑动窗口中出现的所有消息id的信息熵
#其中Test_Data由具有攻击块的CAN消息集的时间线组成
#Rt表示攻击检测的响应时间。然后，对滑动窗口单元的入侵进行实时监控
#本研究使用固定数量的消息W作为滑动窗口
#加入绘制图像的功能
def Information_Entropy_Based_Intrusion_Detection(k, W):
    #根据窗口得出Ue，标准差
    Ue, range_e = cal_Ue_best(W)

    # 读取csv文件
    df = pd.read_csv('DoS_attack.csv', sep='\t')

    count = 0
    Da = 0
    Ta = 0
    Dn = 0
    Tn = 0
    Rt_max = 0
    
    test_start_time = time.time()
    H_I_list = []
    test_time_list = []

    num = 0
    #取出窗口为count到count+W的数据
    while count < len(df):
        if count + W <= len(df):
            test_data = df.iloc[count: count + W]
            count = count + W
        else:
            test_data = df.iloc[count: len(df)]
            count = len(df)
        num = num + 1

        #计算H(id)的值，信息熵一般取2为底
        p_data = test_data['ID'].value_counts() / test_data['ID'].count()
        H_id = p_data * np.log2(1 / p_data)

        #计算攻击块的数目和正常块的数目
        if 0 in p_data: #？？？Ta的判断条件有误 if 0 in list(test_data['ID']):
            Ta = Ta + 1
        else:
            Tn = Tn + 1

        #计算H(I)
        H_I = np.sum(H_id)


        #绘制图像的功能
        H_I_list.append(H_I)
        test_time = time.time() - test_start_time
        test_time_list.append(test_time)

        #比较HI，看是否符合攻击块条件
        if H_I <= Ue - k*range_e or H_I >= Ue + k*range_e:
            if 0 in p_data: #？？？Da的判断条件有误 if 0 in list(test_data['ID']):
                Da = Da + 1

                start_time = 0
                end_time = 0
                #计算时间Rt
                for i in range(W):
                    if test_data.iloc[i]['ID'] == 0:
                        start_time = test_data.iloc[i]['TimeStamp']
                        break
                end_time = test_data.iloc[W - 1]['TimeStamp']
                Rt_now = end_time - start_time
                if Rt_now > Rt_max:
                    Rt_max = Rt_now

            else:
                Dn = Dn + 1

    #计算Ra，预测准确度%
    if Ta == 0:
        Ra = INF
    else:
        Ra = Da / Ta * 100

    #计算Rn，计算假阳性率%
    if Tn == 0:
        Rn = INF
    else:
        Rn = Dn / Tn * 100

    #绘图
    draw_photo(test_time_list, H_I_list, "test time", "test Entropy Value",  W, Ue)

    return Ra, Rn, Rt_max, range_e

Information_Entropy_Based_Intrusion_Detection(2.5, 500)
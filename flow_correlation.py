import imp
import math
import os
import time
import pickle
import numpy as np

def ifCor(A, B):
    x = np.array(A)
    y = np.array(B)

    data = [A, B]

    # 计算平均值
    mx = x.mean()
    my = y.mean()

    # 计算标准差
    stdx = x.std()
    stdy = y.std()

    # 计算协方差矩阵
    covxy = np.cov(x, y)

    # 相关系数矩阵（和上面的协方差矩阵类似）
    coefxy = np.corrcoef(x, y)
    

    return coefxy.mean()
    


class Flow():
    
    def __init__(self, srcIP, dstIP, srcPort, dstPort, startTime, stopTime, flow, filePath) -> None:
        self.srcIP = srcIP
        self.dstIP = dstIP
        self.srcPort = srcPort
        self.dstPort = dstPort
        self.startTime = startTime
        self.stopTime = stopTime
        self.flow = flow
        self.filePath = filePath

    def compare(self, flowB):
        return ifCor(self.flow, flowB.flow)

def getint(bytestring):
    stringlength = len(bytestring)
    outputint = bytestring[-1]
    for i in range (stringlength-2, -1, -1):
        outputint = outputint * 256 + bytestring[i]
    return outputint

def getpcapcontent(bytestring):
    realtime = getint(bytestring[0:4])+getint(bytestring[4:7])/1000000
    realipsrc = str(bytestring[42])+'.'+str(bytestring[43])+'.'+str(bytestring[44])+'.'+str(bytestring[45])
    realipdst = str(bytestring[46])+'.'+str(bytestring[47])+'.'+str(bytestring[48])+'.'+str(bytestring[49])
    realportsrc = str(bytestring[50]*256+bytestring[51])
    realportdst = str(bytestring[52]*256+bytestring[53])
    return realtime, realipsrc, realipdst, realportsrc, realportdst

def extract_pcap(filename):
    if (os.path.exists(filename)):
        with open(filename, 'rb') as f:
            line = f.read()
        lenfile = len(line)
        sind = 24
        pcapind = 0
        timestart = pow(2, 32)
        timestop = 0
        while (sind < lenfile - 16):
            pcaplen = getint(line[sind + 8:sind + 12]) + 16
            pcaplen2 = getint(line[sind + 12:sind + 16]) + 16
            pcapcont = line[sind:sind + pcaplen]
            pcaptime, pcapipsrc, pcapipdst, pcapportsrc, pcapportdst = getpcapcontent(pcapcont)
            if (pcaptime > timestop):
                timestop = pcaptime
            if (pcaptime < timestart):
                timestart = pcaptime
            sind += pcaplen
        print(str(time.ctime(timestart)) + '\t' + str(time.ctime(timestop) + '\n'))
        flow = Flow(pcapipsrc, pcapipdst, pcapportsrc, pcapportdst, timestart, timestop, [], filename)

        return flow

def extract_A_flow(fileFolder):

    A_flow_list = []
    filelist = os.listdir(fileFolder)
    listpcapfile = []
    for i in filelist:
        if (i[-5:] == '.pcap'):
            listpcapfile.append(i)
    
    for i in listpcapfile:
        filename = fileFolder + '\\' + i
        A_flow_list.append(extract_pcap(filename))
    
    return A_flow_list

def get_B_pcap(fileFolder):
    if os.path.isfile(fileFolder) and fileFolder.split('.')[-1] == 'pcap' and os.path.getsize(fileFolder)/float(1024) > 1:
        return [fileFolder]
    
    if os.path.isdir(fileFolder):
        pcap_list = []
        filelist = os.listdir(fileFolder)
        for i in filelist:
            file = fileFolder + '\\' + i
            pcap_list += get_B_pcap(file)
        return pcap_list

def extract_B_flow(fileFolder):
    pcap_list = get_B_pcap(fileFolder)
    B_flow_list = []
    for pcap_file in pcap_list:
        B_flow_list.append(extract_pcap(pcap_file))
    
    return B_flow_list

def genFlow(timeStart, timeStop, fileName):
    if (os.path.exists(fileName)):
        with open(fileName, 'rb') as f:
            line = f.read()
        lenfile = len(line)
        sind = 24
        pcapind = 0

        # 按分钟统计规律
        timestart = int(timeStart//60)
        timestop = int(timeStop//60)

        # # 按秒统计规律
        # timestart = int(time_range_modify[0])
        # timestop = int(time_range_modify[1])

        # print(timestart)
        # print(timestop)
        dic = {}
        for j in range(timestart, timestop + 1):
            dic[j] = 0
        while (sind < lenfile - 16):
            pcaplen = getint(line[sind + 8:sind + 12]) + 16
            pcaplen2 = getint(line[sind + 12:sind + 16]) + 16
            pcapcont = line[sind:sind + pcaplen]
            pcaptime, pcapipsrc, pcapipdst, pcapportsrc, pcapportdst = getpcapcontent(pcapcont)
            # 交叉时间下单位时间内字节总数序列
            if (pcaptime>=(timeStart -1) and pcaptime <= timeStop  ):
                # dict[i][int(pcaptime)] += (pcaplen - 16) #带包头计算值 单位是秒
                dic[int(pcaptime)//60] += (pcaplen - 16) #单位是分钟

            sind += pcaplen
        flow = list(dic.values())
        return flow

if __name__ == '__main__':
    
    A_flow_list = extract_A_flow(r'C:\Users\wbaup\Desktop\tra_cor\流关联程序\test_A')
    B_flow_list = extract_B_flow(r'C:\Users\wbaup\Desktop\tra_cor\流关联程序\test_B')
    threshold = 0.8
    results = []

    for A_flow in A_flow_list:
        for B_flow in B_flow_list:
            if A_flow.startTime > B_flow.stopTime or A_flow.stopTime < B_flow.startTime:
                continue
            else:
                startTime = max(A_flow.startTime, B_flow.startTime)
                stopTime = min(A_flow.stopTime, B_flow.stopTime)
                A_flow.flow = genFlow(startTime, stopTime, A_flow.filePath)
                B_flow.flow = genFlow(startTime, stopTime, B_flow.filePath)
                cor = A_flow.compare(B_flow)
                if cor > threshold:
                    #两个PCAP文件名称、各自起止时间、相互交叉时间、关联概率值
                    results.append((A_flow.filePath, B_flow.filePath, (A_flow.startTime, A_flow.stopTime), (B_flow.startTime, \
                                    B_flow.stopTime), startTime, stopTime, (A_flow.srcIP, A_flow.dstIP), (B_flow.srcIP, B_flow.dstIP), cor))

    with open('result.pkl', 'wb') as f:
        pickle.dump(results, f)
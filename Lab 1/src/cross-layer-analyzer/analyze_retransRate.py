import csv
import os
import numpy as np
import sys
import matplotlib.pyplot as plt

retransmission_file = open(os.path.join('csv', 'tcp_retransmission.csv'), 'r')

retransmission_csv = csv.reader(retransmission_file, delimiter=',')

retrans_list = list()
for retrans_row in retransmission_csv:
    if retrans_row[0] == 'No.':
        continue

    retrans_time = float(retrans_row[1])

    retrans_seq = retrans_row[-1].find('Seq')
    if retrans_seq < 0:
        continue
    retrans_seq = int(retrans_row[-1][retrans_seq + 4:].split(' ')[0])

    retrans_list.append((retrans_time, retrans_seq))

transmission_file = open(os.path.join('csv', 'tcp_transmission.csv'), 'r')

transmission_csv = csv.reader(transmission_file, delimiter=',')

trans_list = list()
for trans_row in transmission_csv:
    if trans_row[0] == 'No.':
        continue

    trans_time = float(trans_row[1])

    trans_seq = trans_row[-1].find('Seq')
    if trans_seq < 0:
        continue
    trans_seq = int(trans_row[-1][trans_seq + 4:].split(' ')[0])

    trans_list.append((trans_time, trans_seq))

time_interval = 0.005
MAX_TIME = 70
MAX_SLOT = int(70 / 0.005)

def calNum(csvFile):
    global time_interval
    lst = [0 for x in range(MAX_SLOT)]
    for row in csvFile:
        t = row[0]
        x = int(t / 0.005)
        # print(x)
        lst[x] += 1
    return lst

trans_num_list = calNum(trans_list)
retrans_num_list = calNum(retrans_list)

print("Retransmission rate: {:.6f}".format(len(retrans_list) / (len(trans_list) + len(retrans_list))))

rate_list = list()
rate_list.append(0 if (retrans_num_list[0] + trans_num_list[0]) == 0 else retrans_num_list[0] / (retrans_num_list[0] + trans_num_list[0]))
for i in range(1, MAX_SLOT):
    trans_num_list[i] += trans_num_list[i - 1]
    retrans_num_list[i] += retrans_num_list[i - 1]
    rate_list.append(0 if (retrans_num_list[i] + trans_num_list[i]) == 0 else retrans_num_list[i] / (retrans_num_list[i] + trans_num_list[i]))

plt.figure()
plt.title('Retransmission Rate')
plt.xlabel('Time')
plt.ylabel('Retransmission Rate')

x = np.arange(0, 70, step=0.005)
y = np.array(rate_list)
plt.plot(x, y)
plt.show()
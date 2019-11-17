import csv
import os
import numpy as np
import sys
import matplotlib.pyplot as plt

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

time_list = []
for item in trans_list:
    time_list.append(item[0])

plt.figure()
plt.title('Throughtput')
plt.xlabel('Time')
plt.ylabel('Throughput')
plt.hist(time_list, bins=150)
plt.show()
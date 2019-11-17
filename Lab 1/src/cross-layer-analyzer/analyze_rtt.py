import csv
import os
import numpy as np
import sys
import matplotlib.pyplot as plt

rtt_file = open(os.path.join('csv', 'wlan_rtt.csv'), 'r')

rtt_csv = csv.reader(rtt_file, delimiter=',')

rtt_time_list = list()
rtt_duration_list = list()
for rtt_row in rtt_csv:
    if rtt_row[0] == 'No.':
        continue

    rtt_time = float(rtt_row[1])

    rtt_duration = rtt_row[-1].find(',')
    if rtt_duration < 0:
        rtt_duration = float(rtt_row[-1])
    else:    
        rtt_duration = float(rtt_row[-1][rtt_duration + 1:])

    rtt_time_list.append(rtt_time)
    rtt_duration_list.append(rtt_duration)

rtt_time_arr = np.array(rtt_time_list)
rtt_duration_arr = np.array(rtt_duration_list)
print("Mean: {:.6f}. Std: {:.6f}".format(np.mean(rtt_duration_arr), np.std(rtt_duration_arr)))

plt.figure()
plt.title("RTT")
plt.xlabel("Time")
plt.ylabel("RTT")
plt.plot(rtt_time_arr, rtt_duration_arr)
plt.show()
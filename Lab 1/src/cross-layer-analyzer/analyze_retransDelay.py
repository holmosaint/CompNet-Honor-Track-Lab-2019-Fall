import csv
import os
import numpy as np
import sys

badFCS_file = open(os.path.join('csv', 'wlan_badFCS.csv'), 'r')
retransmission_file = open(os.path.join('csv', 'wlan_retransmission.csv'), 'r')

badFCS_csv = csv.reader(badFCS_file, delimiter=',')
retransmission_csv = csv.reader(retransmission_file, delimiter=',')

delay_list = list()
badFCS_list = list()
retrans_list = list()
for bad_row in badFCS_csv:
    if bad_row[0] == 'No.':
        continue

    bad_time = float(bad_row[1])
    
    bad_seq = bad_row[-1].find('Seq')
    if bad_seq < 0:
        continue
    bad_seq = int(bad_row[-1][bad_seq + 4:].split(' ')[0])

    badFCS_list.append((bad_time, bad_seq))

for retrans_row in retransmission_csv:
    if retrans_row[0] == 'No.':
        continue

    retrans_time = float(retrans_row[1])

    retrans_seq = retrans_row[-1].find('Seq')
    if retrans_seq < 0:
        continue
    retrans_seq = int(retrans_row[-1][retrans_seq + 4:].split(' ')[0])

    retrans_list.append((retrans_time, retrans_seq))

for bad_row in badFCS_list:
    for retrans_row in retrans_list:
        bad_time, bad_seq = bad_row
        retrans_time, retrans_seq = retrans_row

        """if cnt > 0:
            print("Bad seq: {}. Retrans seq: {}".format(bad_seq, retrans_seq))
            print("Bad time: {}. Retrans time: {}".format(bad_time, retrans_time))"""

        if (bad_time < retrans_time) and (bad_seq == retrans_seq):
            delay_list.append(retrans_time - bad_time)
            break

delay_arr = np.array(delay_list)
print("Mean: {:.2f}s. Standard Deviation: {:.2f}".format(np.mean(delay_arr), np.std(delay_arr)))

badFCS_file.close()
retransmission_file.close()
import csv
import os
import numpy as np
import sys

outofOrder_file = open(os.path.join('csv', 'tcp_outofOrder.csv'), 'r')
inOrder_file = open(os.path.join('csv', 'tcp_inOrder.csv'), 'r')

outofOrder_csv = csv.reader(outofOrder_file, delimiter=',')
inOrder_csv = csv.reader(inOrder_file, delimiter=',')

delay_list = list()
outofOrder_list = list()
inOrder_list = list()
for outofOrder_row in outofOrder_csv:
    if outofOrder_row[0] == 'No.':
        continue

    outofOrder_time = float(outofOrder_row[1])
    
    outofOrder_seq = outofOrder_row[-1].find('Seq')
    if outofOrder_seq < 0:
        continue
    outofOrder_seq = int(outofOrder_row[-1][outofOrder_seq + 4:].split(' ')[0])

    outofOrder_list.append((outofOrder_time, outofOrder_seq))

for inOrder_row in inOrder_csv:
    if inOrder_row[0] == 'No.':
        continue

    inOrder_time = float(inOrder_row[1])

    inOrder_seq = inOrder_row[-1].find('Seq')
    if inOrder_seq < 0:
        continue
    inOrder_seq = int(inOrder_row[-1][inOrder_seq + 4:].split(' ')[0])

    inOrder_list.append((inOrder_time, inOrder_seq))

for outofOrder_row in outofOrder_list:
    for inOrder_row in inOrder_list:
        outofOrder_time, outofOrder_seq = outofOrder_row
        inOrder_time, inOrder_seq = inOrder_row

        """if cnt > 0:
            print("outofOrder seq: {}. inOrder seq: {}".format(outofOrder_seq, inOrder_seq))
            print("outofOrder time: {}. inOrder time: {}".format(outofOrder_time, inOrder_time))"""

        if (outofOrder_time > inOrder_time) and (outofOrder_seq < inOrder_seq):
            delay_list.append(outofOrder_time - inOrder_time)
            break

delay_arr = np.array(delay_list)
print("Mean: {:.6f}s. Standard Deviation: {:.6f}".format(np.mean(delay_arr), np.std(delay_arr)))

outofOrder_file.close()
inOrder_file.close()
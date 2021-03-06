import matplotlib.pyplot as plt
import numpy as np

# matplotlib.style.use('ggplot')

modes = [
	'ECB: Electronic Codebook',
	'CBC: Cipher Block Chaining',
	'CFB: Cipher Feedback',
	'OFB: Output Feedback',
	'CTR: Counter'
]

arr = []
with open('../../out/DES_BLOCK_MODES.txt') as f:
    lines = [l.rstrip() for l in f.readlines()]
    x_labels = [str(int(l) / 1000) for l in lines[0].split()]
    lines = lines[1:]
    arr.append([l.split() for l in lines])
    N = len(lines)

arr = np.asarray(arr, dtype=np.int).reshape((N, 5))

ind = np.arange(N)  # the x locations for the groups
width = 0.35  # the width of the bars: can also be len(x) sequence

p1 = plt.bar(ind, arr[:, 0], width)
p2 = plt.bar(ind, arr[:, 1], width, bottom=arr[:, 0])
p3 = plt.bar(ind, arr[:, 2], width, bottom=arr[:, 0] + arr[:, 1])
p4 = plt.bar(ind, arr[:, 3], width, bottom=arr[:, 0] + arr[:, 1] + arr[:, 2])
p5 = plt.bar(ind, arr[:, 4], width, bottom=arr[:, 0] + arr[:, 1] + arr[:, 2] + arr[:, 3])

plt.xticks(ind, x_labels)

plt.xlabel('message length (in thousands chars)')
plt.ylabel('encryption time (in msec)')
plt.title('encryption time vs message length')

plt.legend((p1[0], p2[0], p3[0], p4[0], p5[0]), modes)

plt.show()

# Cypher feedback graph

arr = []

with open('../../out/CIPHER_FEEDBACK.txt') as f:
    lines = [l.rstrip() for l in f.readlines()]
    arr.append([l.split() for l in lines])

arr = np.asarray(arr, dtype=np.int).reshape((2, 8))

plt.figure()
ind = [i for i in range(1, 9)]  # the x locations for the groups
width = 0.35  # the width of the bars: can also be len(x) sequence

p1 = plt.bar(ind, arr[1, :], width)
plt.xlabel('block size (in bytes)')
plt.ylabel('encryption time (in msec)')
plt.title('CFB encryption time vs block size')

plt.show()

import time
import os

time.sleep(.05)

child = os.fork()

print('child pid ', child, ' parent ', os.getpid())

if child <= 0:
	time.sleep(.1)
	print('done waiting in child')

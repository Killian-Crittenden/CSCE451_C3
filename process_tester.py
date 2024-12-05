import psutil
import time
import datetime

initial_pids = {p.pid:p.info for p in psutil.process_iter(['name', 'username', 'status', 'ppid', 'create_time'])}

while True:
	current_pids = {p.pid:p.info for p in psutil.process_iter(['name', 'username', 'status', 'ppid', 'create_time'])}

	for pid in current_pids:
		if pid not in initial_pids:
			#print("New process created with PID: ", pid, " ", current_pids[pid])
			initial_pids[pid] = current_pids[pid]
			print("Name: {} Status: {} PID: {} created at {}".format(current_pids[pid]["name"], current_pids[pid]["status"], pid, datetime.datetime.fromtimestamp(current_pids[pid]["create_time"]).strftime("%Y-%m-%d %H:%M:%S")))
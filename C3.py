import sys
import subprocess

num_args = len(sys.argv)

if (num_args != 2):
    print("Error incorrect args")
    exit()

dir_name = sys.argv[1]
 
process = subprocess.Popen(["inotifywait", "-m", dir_name], stdout=subprocess.PIPE)

while True:
    user_input = input("Currently Reading, Enter 1 to stop reading: ")
    if user_input == "1":
        process.kill()
        stdout = process.communicate()
        break


print(stdout)




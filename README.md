# pwn-Toolbox
In practice, continuously supplement tools and scripts related to pwn questions.

#1、elf_exec_find.py

#Check all executable parameters in the elf file such as /bin/sh\x00,$0,sh\x00, etc

#usage

python3 elf_exec_find.py [elf_file_name]
<img width="1207" height="438" alt="elf_exec_find" src="https://github.com/user-attachments/assets/c9605b46-f5c0-40a2-9c09-458b86657f20" />

#2、float2hex.py

#Convert a floating-point number to hexadecimal data that can be seen in memory

#usage

python3 float2hex.py 0.1
<img width="914" height="415" alt="float2hex" src="https://github.com/user-attachments/assets/77777da0-df7a-4e71-96b2-56fcb4ed4003" />

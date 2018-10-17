setup:
	sudo rm /bin/sh
	sudo ln -s /bin/zsh /bin/sh
	sudo sysctl -w kernel.randomize_va_space=0
run_server:
	./tcpserver
connect:
	python attackcode.py
debug:
	gdb tcpserver
compile:
	gcc -g -z execstack -fno-stack-protector -o tcpserver tcpserver.c
clean:
	rm tcpserver
inject:
	nc -l 127.0.0.1 9999
	#python attackcode2.py

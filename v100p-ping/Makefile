#CC=arm-none-linux-gnueabi-g++
CC=g++
CFLAGS=-c -g -Wall -I.
APP=v100p-ping-app

.PHONY: all clean

all : ${APP}

${APP} : main.o cnettest_ping.o
	${CC} -o $@ main.o cnettest_ping.o -lrt

main.o : main.cpp
	${CC} -o main.o -c main.cpp

cnettest_ping.o : cnettest_ping.cpp
	${CC} -o cnettest_ping.o -c cnettest_ping.cpp

clean:
	rm -f main.o cnettest_ping.o ${APP}

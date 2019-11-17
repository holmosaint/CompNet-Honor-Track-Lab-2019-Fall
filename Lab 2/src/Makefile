CC = g++
FLAGS = -lpcap -lpthread

main: main.o device.o packetio.o ip.o tools.o socket.o
	$(CC) main.o device.o packetio.o ip.o tools.o socket.o -o main -g $(FLAGS)
main.o: main.cpp
	$(CC) main.cpp -c -g
packetio.o: packetio.cpp
	$(CC) packetio.cpp -c -g
device.o: device.cpp
	$(CC) device.cpp -c -g
ip.o: ip.cpp
	$(CC) ip.cpp -c -g
tools.o: tools.cpp
	$(CC) tools.cpp -c -g
socket.o: socket.cpp
	$(CC) socket.cpp -c -g
clean:
	rm *.o main
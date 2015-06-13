CC = g++
SRC = Src\Crypter
BIN = .
OBJ = Obj
CFLAGS = -ansi -c -Wall -pedantic -O2

.PHONY:all
all: createoutput.o fileaccess.o peanalysis.o pe.o main.o
	$(CC) -o $(BIN)\crypter.exe $(OBJ)\main.o $(OBJ)\pe.o $(OBJ)\peanalysis.o $(OBJ)\fileaccess.o $(OBJ)\createoutput.o
		 
createoutput.o: $(SRC)\createoutput.cpp
	$(CC) $(CFLAGS) -o $(OBJ)\createoutput.o $(SRC)\createoutput.cpp
	
fileaccess.o: $(SRC)\fileaccess.cpp
	$(CC) $(CFLAGS) -o $(OBJ)\fileaccess.o $(SRC)\fileaccess.cpp
	
peanalysis.o: $(SRC)\peanalysis.cpp
	$(CC) $(CFLAGS) -o $(OBJ)\peanalysis.o $(SRC)\peanalysis.cpp

pe.o: $(SRC)\pe.cpp
	$(CC) $(CFLAGS) -o $(OBJ)\pe.o $(SRC)\pe.cpp

main.o: $(SRC)\main.cpp
	$(CC) $(CFLAGS) -o $(OBJ)\main.o $(SRC)\main.cpp

.PHONY:clean
clean:
	del $(BIN)\crypter.exe && del $(OBJ)\*.o

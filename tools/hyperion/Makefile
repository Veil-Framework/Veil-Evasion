CC = g++
SRC = Src\Crypter
BIN = .
OBJ = Obj
CFLAGS = -ansi -c -Wall -pedantic -O2 -m32

.PHONY:all
all: createoutput.o fileaccess.o peanalysis.o pe.o hyperion.o ostreamlog.o
	$(CC) -o $(BIN)\hyperion.exe $(OBJ)\hyperion.o $(OBJ)\pe.o $(OBJ)\peanalysis.o $(OBJ)\fileaccess.o $(OBJ)\createoutput.o $(OBJ)\ostreamlog.o
		 
createoutput.o: $(SRC)\createoutput.cpp
	$(CC) $(CFLAGS) -o $(OBJ)\createoutput.o $(SRC)\createoutput.cpp
	
fileaccess.o: $(SRC)\fileaccess.cpp
	$(CC) $(CFLAGS) -o $(OBJ)\fileaccess.o $(SRC)\fileaccess.cpp
	
peanalysis.o: $(SRC)\peanalysis.cpp
	$(CC) $(CFLAGS) -o $(OBJ)\peanalysis.o $(SRC)\peanalysis.cpp

pe.o: $(SRC)\pe.cpp
	$(CC) $(CFLAGS) -o $(OBJ)\pe.o $(SRC)\pe.cpp

hyperion.o: $(SRC)\hyperion.cpp
	$(CC) $(CFLAGS) -o $(OBJ)\hyperion.o $(SRC)\hyperion.cpp
	
ostreamlog.o: $(SRC)\ostreamlog.cpp
	$(CC) $(CFLAGS) -o $(OBJ)\ostreamlog.o $(SRC)\ostreamlog.cpp

.PHONY:clean
clean:
	del $(BIN)\hyperion.exe && del $(OBJ)\*.o

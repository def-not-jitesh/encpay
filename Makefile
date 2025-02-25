
CC = x86_64-w64-mingw32-gcc 
# for cross-compilation

OBJS = main.o encrypt_func.o file_io.o # making a variable for all object files

TARGET = encpay.exe # our final target

$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $(TARGET)

%.o: %.c # to compile all the object files
	$(CC) -c $< -o $@

clean: # after running 'make clean', the program will remove all .o and the target file
	rm -f $(OBJS) $(TARGET)

run: $(TARGET)
	./$(TARGET) -f payload.bin -m rc4

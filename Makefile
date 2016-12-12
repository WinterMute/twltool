OBJS = dsi.o main.o f_xy.o utils.o
POLAR_OBJS = polarssl/aes.o polarssl/bignum.o polarssl/rsa.o polarssl/sha2.o sha1.o
LIBS = -static-libstdc++ -static
CXXFLAGS = -I. 
CFLAGS = -Wall -Wno-unused-variable -Wno-unused-but-set-variable -I.
OUTPUT = twltool
CC = gcc

main: $(OBJS) $(POLAR_OBJS) $(TINYXML_OBJS)
	g++ -Os -o $(OUTPUT) $(LIBS) $(OBJS) $(POLAR_OBJS) $(TINYXML_OBJS)


clean:
	rm -rf $(OUTPUT) $(OBJS) $(POLAR_OBJS) $(TINYXML_OBJS)

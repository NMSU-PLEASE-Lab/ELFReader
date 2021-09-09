

CPPFLAGS = -I. -g -Wall -fPIC

OBJS = ProgramInfo.o LoadObject.o ElfSection.o ElfSegment.o \
       DynamicSection.o ElfSymbol.o

elfreader: elfreader.o libelfread.so
	g++ -o $@ elfreader.o -L. -lelfread -ldl 

libelfread.so: $(OBJS)
	g++ -shared -o $@ -Wl,-soname="libelfread.so" $(OBJS)

clean:
	/bin/rm -f *.o *.so elfreader

depend:
	g++ -I. -MM *.cpp > Make.depends

include Make.depends

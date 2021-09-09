#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <dlfcn.h>
#include <ElfProgram.h>

/*
 * Data struct to hold info from reading the "maps" psuedo-file
 * in /proc/[pid]/
 */
typedef struct _mapinfo_struct
{
      char* startAddress;
      char* endAddress;
      unsigned int permissions;
      char objectName[64];
} MapObject;

/**
 * No-arg constructor: reads the current processes' maps file
 * and initializes everything about it from there. The maps file
 * is in /proc/[pid]/maps, and contains a memory map of all the
 * loaded objects. This is parsed and used to create all of the
 * LoadObject objects to represent each loaded ELF object for the
 * program.
 */
ProgramInfo::ProgramInfo(void)
{
   FILE *mapFile;
   char mapFilename[256];
   char line[128];
   MapObject mapObjects[32];
   int numObjects, i;

   name=0;
   loadedObjects = 0;
   //symbols = 0;
   pid = getpid();

   sprintf(mapFilename,"/proc/%d/maps",pid);
   //printf("my map file is (%s)\n",mapFilename);
   //sprintf(line, "/bin/cat %s", mapFilename);
   //system(line);

   mapFile = fopen(mapFilename,"r");
   if (!mapFile)
      return;

   numObjects = 0;
   while (fgets(line, sizeof(line), mapFile) != 0)
   {
      unsigned int xpos = 0;
      line[strlen(line)-1] = '\0';
      //printf("line read: (%s)\n", line);
      xpos = strchr(line, 'x') - line;
      if (xpos > 30 || xpos < 20)
      {
         //printf("not executable: skipping\n");
         continue;
      }
      //08048000-0804a000 r-xp 00000000 03:01 227437     /opt/kde3/bin/kwrapper
      sscanf(line,"%p-%p", &mapObjects[numObjects].startAddress,
             &mapObjects[numObjects].endAddress);
      strcpy(mapObjects[numObjects].objectName,line+49);
      //
      // if just another map of same object, then concatenate
      //  -- should keep track of permissions, though
      //  -- skipping non-exec maps above moots this
      //
      if (numObjects > 0 && !strcmp(mapObjects[numObjects].objectName,
                                    mapObjects[numObjects-1].objectName) &&
          mapObjects[numObjects-1].endAddress == 
          mapObjects[numObjects].startAddress)
      {
         mapObjects[numObjects-1].endAddress = 
            mapObjects[numObjects].endAddress;
         numObjects--;
      }
      /*
         printf("map %p %p (%s)\n---\n", 
             mapObjects[numObjects].startAddress,
             mapObjects[numObjects].endAddress, 
             mapObjects[numObjects].objectName);
      */
      numObjects++;
   }
   fclose(mapFile);
   LoadObject *lo=0, *tail=0;
   for (i=0; i < numObjects; i++)
   {
      //printf("=====================================================\n");
      //printf("map %p %p (%s)\n", mapObjects[i].startAddress,
      //        mapObjects[i].endAddress, mapObjects[i].objectName);
      if (memcmp(ELFMAG, mapObjects[i].startAddress, SELFMAG))
      {
         //printf("not an elf object\n");
         continue;
      }
      lo = new LoadObject(mapObjects[i].objectName, mapObjects[i].startAddress,
                          mapObjects[i].endAddress);
      if (tail)
      {
         tail->next = lo;
         tail = lo;
      } else {
         loadedObjects = tail = lo;
      }
   }
   return;
}

/**
 * TODO: Read an object file rather than an executing process
 * @param objFilename is the object file to read.
 */
ProgramInfo::ProgramInfo(char *objFilename)
{
   name = 0;
   pid = -1;
   loadedObjects = 0;
   //symbols = 0;
   return;
}

/**
 * Print out debugging information. Loops through LoadObjects and
 * asks each to print out its own debug info.
 */
void ProgramInfo::debugPrintInfo()
{
   LoadObject *lo = loadedObjects;
   while (lo)
   {
      lo->debugPrintInfo();
      lo = lo->next;
   }
}

/**
 * Not implemented: need to delete a whole bunch of stuff.
 */
ProgramInfo::~ProgramInfo()
{
}

/**
 * Add a LoadObject to this ProgramInfo record (Not implemented).
 * @param lo is a pointer to the LoadObject to add
 */
int ProgramInfo::addLoadObject(class LoadObject *lo)
{
   return 0;
}

/*
 * not sure yet if this will be needed
 */
/***
int ProgramInfo::addProgramSymbol(void)
{
   return 0;
}
***/

/** 
 * Find all definitions of a symbol throughout the program. 
 * This function iterates over the load objects and finds all 
 * dynamic exported instances of a symbol.
 * @param symbolName is the string name of the symbol.
 * @param numDefs is a return parameter set to the number of defs found.
 * @return An array of ElfSymbol objects (use delete, not delete[])
 */
ElfSymbol** ProgramInfo::findSymbolDefinitions(char* symbolName, int* numDefs)
{
   LoadObject *lo;
   ElfSymbol *sym;
   ElfSymbol **defs;
   unsigned int iter, defcnt=0, defarr=5;

   defs = new ElfSymbol*[defarr];
   lo = loadedObjects;
   while (lo)
   {
      sym = lo->startDynamicSymbolIter(&iter);
      while (sym)
      {
         if (!strcmp(sym->getName(), symbolName))
            break;
         sym = lo->nextDynamicSymbolIter(&iter);
      }
      // how does the below tell if definition??!?? (need to document)
      if (sym && sym->getSHIndex()!=0 && sym->getSHIndex()<1000) 
      {
         if (defcnt >= defarr)
         {
            ElfSymbol **tmp;
            defarr += 10;
            tmp = new ElfSymbol*[defarr];
            memcpy(tmp,defs,sizeof(ElfSymbol*)*(defarr-10));
            delete[] defs;
            defs = tmp;
         }
         defs[defcnt++] = sym;
      }
      lo = lo->next;
   }
   *numDefs = defcnt;
   return defs;
}

/** 
 * Find all symbol uses throughout the program. This function iterates
 * over the load objects and finds all external references to a dynamic
 * symbol.
 * @param symbolName is the string name of the symbol.
 * @param numUses is a return parameter set to the number of uses found.
 * @return An array of ElfSymbol objects (use delete, not delete[])
 */
ElfSymbol** ProgramInfo::findSymbolUses(char* symbolName, int* numUses)
{
   LoadObject *lo;
   ElfSymbol *sym;
   ElfSymbol **uses;
   unsigned int iter, usecnt=0, usearr=10;

   uses = new ElfSymbol*[usearr];
   lo = loadedObjects;
   while (lo)
   {
      sym = lo->startDynamicSymbolIter(&iter);
      while (sym)
      {
         if (!strcmp(sym->getName(), symbolName))
            break;
         sym = lo->nextDynamicSymbolIter(&iter);
      }
      // way to tell if use: the symbol has no section defined for it
      // (there should be a better way?)
      if (sym && sym->getSHIndex()==0) 
      {
         if (usecnt >= usearr)
         {
            ElfSymbol **tmp;
            usearr += 10;
            tmp = new ElfSymbol*[usearr];
            memcpy(tmp,uses,sizeof(ElfSymbol*)*(usearr-10));
            delete[] uses;
            uses = tmp;
         }
         uses[usecnt++] = sym;
      }
      lo = lo->next;
   }
   *numUses = usecnt;
   return uses;
}


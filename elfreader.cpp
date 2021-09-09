#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <elf.h>
#include <dlfcn.h>
#include <ElfProgram.h>

//
// Get all definitions and uses of a program symbol, and
// print their information. A symbol can have multiple 
// definitions, as long as one is regular and others are
// weak (or if some libs have been PRELOADed or dynamically
// loaded).
//
void printSymbolDU(ProgramInfo* pInfo, char* symbol)
{
   ElfSymbol *sym, **defs, **uses;
   int i, dcount, ucount;

   defs = pInfo->findSymbolDefinitions(symbol,&dcount);
   uses = pInfo->findSymbolUses(symbol,&ucount);
   printf("(%s) has %u defs and %u uses\n",symbol, dcount,ucount);
   for (i=0; i<dcount; i++)
   {
      sym = defs[i];
      printf(" D:(%s) Raw=%8.8x PLT=%p GOT=%p (%p) in (%s)\n", 
             sym->getName(), sym->getRawValue(), 
             sym->getPLTEntryAddress(), sym->getGOTEntryAddress(),
             sym->getSymbolAddress(),
             sym->getLoadObject()->getName());
      printf("    Bind=%2.2d Type=%2.2d I=%2.2d Size=%d Other=%d\n", 
             sym->getBind(), sym->getType(), 
             (sym->getSHIndex()==65521)?99:sym->getSHIndex(), 
             sym->getSize(), sym->getOther());
   }
   for (i=0; i<ucount; i++)
   {
      sym = uses[i];
      printf(" U:(%s) Raw=%8.8x PLT=%p GOT=%p (%p) in (%s)\n", 
             sym->getName(), sym->getRawValue(), 
             sym->getPLTEntryAddress(), sym->getGOTEntryAddress(),
             sym->getSymbolAddress(),
             sym->getLoadObject()->getName());
      printf("    Bind=%2.2d Type=%2.2d I=%2.2d Size=%d Other=%d\n", 
             sym->getBind(), sym->getType(), 
             (sym->getSHIndex()==65521)?99:sym->getSHIndex(), 
             sym->getSize(), sym->getOther());
   }
}

//
// Main
//
int main(int argc, char **argv)
{
   ProgramInfo *pInfo;
   LoadObject *lo;
   ElfSymbol *sym;
   unsigned int iter;
   //int i;
   void *p1;
   void *p2;

   //
   // get some sample function pointers and print values
   //
   //p1 = (void*) &printf; // will point to PLT entry, not actual function
   p1 = 0;
   p2 = (void*) &fopen;
   printf("(printf)=%p, fopen=%p\n",p1,p2);
   //
   // because of statements above, getting printf through dlsym will
   // also return PLT entry. If statements above are missing, dlsym will
   // return the actual function address.
   p1 = (void*) dlsym(0,"printf");
   printf("(printf)-dl=%p\n",p1);

   //
   // Create new ProgramInfo object -- this triggers and entire reading
   // of the ELF info for all loaded objects
   //
   pInfo = new ProgramInfo();
   //pInfo->debugPrintInfo();

   //
   // iterate over all loaded objects and print out all
   // dynamic symbols (currently disabled by while (0))
   //
   lo = pInfo->loadedObjects;
   while (0) //(lo)
   {
      printf("Loaded Object: %s\n", lo->getName());
      sym = lo->startDynamicSymbolIter(&iter);
      while (sym)
      {
         // uncomment to just get code symbols
         //(sym->isDataObject() || sym->isCodeObject())
         {
            printf("  (%s) Raw=%8.8x PLT=%p GOT=%p\n", 
                   sym->getName(), sym->getRawValue(), 
                   sym->getPLTEntryAddress(), sym->getGOTEntryAddress());
            printf("    Bind=%2.2d Type=%2.2d I=%2.2d Size=%d Other=%d\n", 
                   sym->getBind(), sym->getType(), 
                   (sym->getSHIndex()==65521)?99:sym->getSHIndex(), 
                   sym->getSize(), sym->getOther());
         }
         sym = lo->nextDynamicSymbolIter(&iter);
      }
      lo = lo->next;
   }

   //
   // iterate over all loaded objects and print out all
   // static symbols NOT(currently disabled by while (0))
   //
   lo = pInfo->loadedObjects;
   while (lo)
   {
      printf("Loaded Object: %s\n", lo->getName());
      sym = lo->startStaticSymbolIter(&iter);
      while (sym)
      {
         // uncomment to just get code symbols
         //(sym->isDataObject() || sym->isCodeObject())
         {
            printf("  (%s) Raw=%8.8x PLT=%p GOT=%p\n", 
                   sym->getName(), sym->getRawValue(), 
                   sym->getPLTEntryAddress(), sym->getGOTEntryAddress());
            printf("    Bind=%2.2d Type=%2.2d I=%2.2d Size=%d Other=%d\n", 
                   sym->getBind(), sym->getType(), 
                   (sym->getSHIndex()==65521)?99:sym->getSHIndex(), 
                   sym->getSize(), sym->getOther());
         }
         sym = lo->nextStaticSymbolIter(&iter);
      }
      lo = lo->next;
   }

   //
   // See function definition above main()
   //
   printSymbolDU(pInfo, "printf");
   printSymbolDU(pInfo, "malloc");
   printSymbolDU(pInfo, "fopen");
   printSymbolDU(pInfo, "stdout");
   printSymbolDU(pInfo, "__gmon_start__");

   delete pInfo;
   return 0;
}

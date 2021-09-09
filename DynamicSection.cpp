#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ElfProgram.h>
//#include <libelf.h>

/**
 * Sets up info about a dynamic section. The dynamic section contains
 * all the info to be able to dynamically link this object with other
 * ELF objects, and other info pertaining to run time. As such, it is
 * quite important to maintain information about it.
 * @param dynamicSectionAddress is the beginning address of the section.
 * @param size is the section's total size in bytes.
 * @param loadObject is the ELF object this section belongs to.
 */
DynamicSection::DynamicSection(char* dynamicSectionAddress, unsigned int size,
                  LoadObject* loadObject)
{
   ElfW(Dyn) *dynamicEntry = (ElfW(Dyn)*) dynamicSectionAddress;
   dynamicSec = dynamicEntry;
   numEntries = size / sizeof(ElfW(Dyn));
   unsigned int i;
   RelASection=0;
   RelSection=0;
   PLTRels=0;
   stringTable=0;
   symbolTable=0;
   stringTableSize=0;
   symbolTableCount=0;
   symbolEntrySize=0;
   this->loadObject = loadObject;
   //
   // first find string table and symbol table, and hash table
   //
   for (i=0; i < numEntries && dynamicEntry->d_tag != DT_NULL; i++)
   {
      if (dynamicEntry->d_tag == DT_STRTAB)
         stringTable = (char*) dynamicEntry->d_un.d_ptr;
      if (dynamicEntry->d_tag == DT_SYMTAB)
         symbolTable = (ElfW(Sym)*) dynamicEntry->d_un.d_ptr;
      if (dynamicEntry->d_tag == DT_STRSZ)
         stringTableSize = dynamicEntry->d_un.d_val;
      if (dynamicEntry->d_tag == DT_SYMENT)
         symbolEntrySize = dynamicEntry->d_un.d_val;
      if (dynamicEntry->d_tag == DT_HASH)
      {
         hashTable = (char*) dynamicEntry->d_un.d_ptr;
         symbolTableCount = *(((int*)dynamicEntry->d_un.d_ptr)+1);
      }
      dynamicEntry++;
   }
   //
   // Now find the PLT, GOT, and relocation information
   //
   dynamicEntry = (ElfW(Dyn)*) dynamicSectionAddress;
   for (i=0; i < numEntries && dynamicEntry->d_tag != DT_NULL; i++)
   {
      if (dynamicEntry->d_tag == DT_RELA)
         RelASection = (ElfW(Rela)*)dynamicEntry->d_un.d_ptr;
      if (dynamicEntry->d_tag == DT_RELASZ)
         RelaSize = (unsigned int)dynamicEntry->d_un.d_val;
      if (dynamicEntry->d_tag == DT_RELAENT)
         RelaEntSize = (unsigned int)dynamicEntry->d_un.d_val;
      if (dynamicEntry->d_tag == DT_REL)
         RelSection = (ElfW(Rel)*)dynamicEntry->d_un.d_ptr;
      if (dynamicEntry->d_tag == DT_RELSZ)
         RelSize = (unsigned int)dynamicEntry->d_un.d_val;
      if (dynamicEntry->d_tag == DT_RELENT)
         RelEntSize = (unsigned int)dynamicEntry->d_un.d_val;
      if (dynamicEntry->d_tag == DT_PLTGOT)
         loadObject->setGOTAddress((char*)dynamicEntry->d_un.d_ptr);
      if (dynamicEntry->d_tag == DT_JMPREL)
      {
         PLTRels = (ElfW(Rel)*)dynamicEntry->d_un.d_ptr;
      }
      if (dynamicEntry->d_tag == DT_PLTREL)
      {
         PLTRType = dynamicEntry->d_un.d_val;
         if (dynamicEntry->d_un.d_val == DT_REL)
            PLTREntSize = sizeof(ElfW(Rel));
         else
            PLTREntSize = sizeof(ElfW(Rela));
      }
      if (dynamicEntry->d_tag == DT_PLTRELSZ)
      {
         PLTRSize = dynamicEntry->d_un.d_val;
      }
      dynamicEntry++;
   }
}

DynamicSection::~DynamicSection()
{
}

void DynamicSection::debugPrintInfo()
{
   ElfW(Dyn) *dynamicEntry = dynamicSec;
   unsigned int i;
   ElfSymbol* esym;
   printf("-DYNAMIC-SEGMENT-SECTION\n");
   printf("dynamic addr=%p, numentries=%d\n", dynamicEntry, numEntries);
   esym = findDynamicSymbolByName("printf");
   printf(" sym entry for printf is %p\n",esym);
   if (esym)
      printf("   (%p) is (%s), val %x, size %x, (%x,%x,%x,%x)\n",
            esym, esym->getName(), esym->getRawValue(), esym->getSize(), 
            esym->getBind(), esym->getType(),
            esym->getOther(), esym->getSHIndex());
   for (i=0; i < numEntries; i++)
   {
      printf("dynamic: tag (0x%x)  val (0x%x)\n",
             (int) dynamicEntry->d_tag, (int) dynamicEntry->d_un.d_val);
      if (dynamicEntry->d_tag == DT_STRTAB)
         printf("  is string table: %p\n", 
                (char*) dynamicEntry->d_un.d_ptr);
      if (dynamicEntry->d_tag == DT_SYMTAB)
         printf("  is symbol table: %p\n",
                (ElfW(Sym)*) dynamicEntry->d_un.d_ptr);
      if (dynamicEntry->d_tag == DT_STRSZ)
         printf("  is string table size: %d\n",
                (int) dynamicEntry->d_un.d_val);
      if (dynamicEntry->d_tag == DT_SYMENT)
         printf("  is symbol entry size: %d\n",
                (int) dynamicEntry->d_un.d_val);
      if (dynamicEntry->d_tag == DT_HASH)
      {
         printf("  is hash table: %p\n",
                (char*) dynamicEntry->d_un.d_ptr);
      }
      if (dynamicEntry->d_tag == DT_PLTGOT)
         printf("  is plt/got address: %p\n",(char*) dynamicEntry->d_un.d_ptr);
      if (dynamicEntry->d_tag == DT_JMPREL)
      {
         printf("   JMPREL address of plt relocs: %p\n",
                (int*)dynamicEntry->d_un.d_ptr);
      }
      if (dynamicEntry->d_tag == DT_PLTREL)
      {
         printf("   PLTREL type of plt relocs: %x\n",
                (int) dynamicEntry->d_un.d_val);
      }
      if (dynamicEntry->d_tag == DT_PLTRELSZ)
      {
         printf("   PLTRELSZ size of plt relocs: %x\n",
                (int) dynamicEntry->d_un.d_val);
      }
      if (dynamicEntry->d_tag == DT_SONAME)
      {
         printf("   SONAME name: (%s)\n",
                (stringTable)? stringTable+dynamicEntry->d_un.d_val : "zzz");
      }
      if (dynamicEntry->d_tag == DT_RPATH || dynamicEntry->d_tag == DT_RUNPATH)
      {
         printf("   RPATH name: (%s)\n",
                (stringTable)? stringTable+dynamicEntry->d_un.d_val : "zzz");
      }

      dynamicEntry++;
   }
   printf("string table (%p) size (0x%x)\n", stringTable, stringTableSize);
   printf("symbol table (%p) size (0x%x,%d)\n", symbolTable, symbolEntrySize,
          symbolTableCount);
   int *p = (int*) findGOTEntryByName("printf");
   printf("DSG: printf is in GOT at %p (val=%x)\n",
          p, p?*p:0);
   p = (int*) findGOTPLTEntryByName("printf");
   printf("DSG: printf is in GOT at %p (val=%x)\n",
          p, p?*p:0);
   //int symcount = 4;
   //if (stringTable)
   //   symcount = DoDumpStringTable(stringTable, stringTableSize);
   if (stringTable && symbolTable)
   {
      ElfW(Sym) *sym = symbolTable;
      unsigned int i=0;
      while (i < symbolTableCount)
      {
         printf("  dynsym (%p) is (%s), val %lx, size %lx, (%x,%x,%x,%x)\n",
                sym, getSymbolString(sym), sym->st_value, sym->st_size, 
                GEN_ST_BIND(sym->st_info), GEN_ST_TYPE(sym->st_info),
                sym->st_other, sym->st_shndx);
         sym++; i++;
      }
   }
   if (RelASection)
   {
      ElfW(Rela) *relsym = RelASection;
      unsigned int count = RelaSize/RelaEntSize;
      printf("have RELA section at %p, count %d\n",RelASection, count);
      unsigned int i = 0;
      while (i < count)
      {
         printf("  %d: offset %lx, type %lx symndx %lx add %lx (%s)\n", i,
                relsym->r_offset, GEN_R_TYPE(relsym->r_info), 
                GEN_R_SYM(relsym->r_info), relsym->r_addend,
                getSymbolString(symbolTable+GEN_R_SYM(relsym->r_info)));
         relsym++;
         i++;
      }
   }
   if (RelSection)
   {
      ElfW(Rel) *relsym = RelSection;
      int count = RelSize/RelEntSize;
      printf("have REL section at %p count %d\n",RelSection,count);
      int i = 0;
      while (i < count)
      {
         printf("  %d: offset %lx, type %lx symndx %lx (%s)\n", i, 
                relsym->r_offset,
                GEN_R_TYPE(relsym->r_info), GEN_R_SYM(relsym->r_info),
                getSymbolString(symbolTable+GEN_R_SYM(relsym->r_info)));
         relsym++;
         i++;
      }
   }
   if (PLTRels)
   {
      ElfW(Rel) *relsym = PLTRels;
      int count = PLTRSize/PLTREntSize;
      printf("have PLTREL section at %p count %d\n",relsym,count);
      int i = 0;
      while (i < count)
      {
         printf("  %d: offset %lx, type %lx symndx %lx (%s)\n", i, 
                relsym->r_offset,
                GEN_R_TYPE(relsym->r_info), GEN_R_SYM(relsym->r_info),
                getSymbolString(symbolTable+GEN_R_SYM(relsym->r_info)));
         relsym++;
         i++;
      }
   }
}

unsigned long DynamicSection::findDynamicEntry(unsigned int EntryType)
{
   ElfW(Dyn) *dynamicEntry = dynamicSec;
   unsigned int i;
   for (i=0; i < numEntries && dynamicEntry->d_tag != DT_NULL; i++)
   {
      if ((unsigned long)dynamicEntry->d_tag == EntryType)
         return (unsigned long) dynamicEntry;
   }
   return 0;
}

char* DynamicSection::getSymbolString(ElfW(Sym)* dsym)
{
   if (!stringTable)
      return 0;
   char *str;
   //printf("  string lookup: table (%p), index (%x)\n", stringTable,
   //       dsym->st_name);
   str = stringTable + dsym->st_name;
   return str;
}

// Not needed, use more efficient hash below
/****
ElfW(Sym)* DynamicSection::findDynamicSymbolByName(char* name)
{
   ElfW(Sym) *sym = symbolTable;
   unsigned int i=0;
   if (!symbolTable)
      return 0;
   while (i < symbolTableCount)
   {
      if (!strcmp(name,getSymbolString(sym)))
         break;
      sym++; i++;
   }
   if (i < symbolTableCount)
      return sym; //new ElfSymbol(sym,stringTable,loadObject);
   else
      return 0;
}
****/

ElfSymbol* DynamicSection::findDynamicSymbolByName(char *name)
{
   ElfSymbol *esym;
   ElfW(Sym) *sym = symbolTable;
   char *gote, *plte; int goti;
   int* hashBuckets;
   int* hashChains;
   unsigned int index, hi;
   unsigned int numBuckets;
   unsigned int numChains;
   if (!hashTable)
      return 0;
   numBuckets = *((unsigned int*)hashTable);
   numChains = *((unsigned int*)hashTable+1);
   hashBuckets = (int*)hashTable+2;
   hashChains = (int*)hashTable+2+numBuckets;
   hi = elfHash((const unsigned char*)name); //elf_hash(name);
   index = hashBuckets[hi%numBuckets];
   do {
      sym = symbolTable+index;
      if (index == STN_UNDEF)
         return 0;
      if (!strcmp(name,getSymbolString(sym)))
         break;
      index = hashChains[index];
   } while (index < numChains); // just for safety
   if (index >= numChains)
      return 0;

   if (GEN_ST_TYPE(sym->st_info) == STT_OBJECT)
      gote = findGOTEntryByName(getSymbolString(sym));
   else
      gote = findGOTPLTEntryByName(getSymbolString(sym));
   goti = ((unsigned long)gote - (unsigned long)loadObject->getGOTAddress())/4;
   plte = loadObject->getPLTAddress() + (goti*16);
   esym = new ElfSymbol(sym, stringTable, loadObject, plte, gote);
   return esym;
}

unsigned long DynamicSection::elfHash(const unsigned char *name)
{
   unsigned long h = 0;
   unsigned long g;
   while (*name)
   {
      h = (h << 4) + (unsigned long) *name++;
      if ((g = h & (unsigned long) 0xf0000000))
         h ^= g >> 24;
      h &= ~g;
   }
   return h;
}

// return ptr to GOT entry of symbolName
char *DynamicSection::findGOTEntryByName(char *symbolName)
{
   if (RelASection)
   {
      ElfW(Rela) *relsym = RelASection;
      unsigned int count = RelaSize/RelaEntSize;
      unsigned int i = 0;
      while (i < count)
      {
         if (!strcmp(symbolName, getSymbolString(symbolTable+
                                             GEN_R_SYM(relsym->r_info))))
         {
            return (char*) relsym->r_offset; // correct??? + relsym->r_addend ???
         }
         relsym++;
         i++;
      }
   }
   if (RelSection)
   {
      ElfW(Rel) *relsym = RelSection;
      int count = RelSize/RelEntSize;
      int i = 0;
      while (i < count)
      {
         if (!strcmp(symbolName, getSymbolString(symbolTable+
                                             GEN_R_SYM(relsym->r_info))))
         {
            return (char*)relsym->r_offset; // correct???
         }
         relsym++;
         i++;
      }
   }
   return (char*)0;
}


// return ptr to GOT entry of PLT-based symbolName
char *DynamicSection::findGOTPLTEntryByName(char *symbolName)
{
   if (!PLTRels)
      return 0;
   if (PLTRType == DT_RELA)
   {
      ElfW(Rela) *relsym = (ElfW(Rela) *) PLTRels;
      unsigned int count = PLTRSize/PLTREntSize;
      unsigned int i = 0;
      while (i < count)
      {
         if (!strcmp(symbolName, getSymbolString(symbolTable+
                                             GEN_R_SYM(relsym->r_info))))
         {
            return (char*)relsym->r_offset; // correct??? + relsym->r_addend ???
         }
         relsym++;
         i++;
      }
   }
   else
   {
      ElfW(Rel) *relsym = PLTRels;
      unsigned int count = PLTRSize/PLTREntSize;
      unsigned int i = 0;
      while (i < count)
      {
         if (!strcmp(symbolName, getSymbolString(symbolTable+
                                             GEN_R_SYM(relsym->r_info))))
         {
            return (char*)relsym->r_offset; // correct???
         }
         relsym++;
         i++;
      }
   }
   return (char*)0;
}

ElfSymbol* DynamicSection::startDynamicSymbolIter(unsigned int* iter)
{
   char *gote, *plte;
   int goti;
   if (!stringTable || !symbolTable)
      return 0;
   *iter = 0;
   ElfW(Sym) *sym = symbolTable;
   if (GEN_ST_TYPE(sym->st_info) == STT_OBJECT)
      gote = findGOTEntryByName(getSymbolString(sym));
   else
      gote = findGOTPLTEntryByName(getSymbolString(sym));
   goti = ((unsigned long)gote - (unsigned long)loadObject->getGOTAddress())/4;
   plte = loadObject->getPLTAddress() + (goti*16);
   ElfSymbol *esym = new ElfSymbol(sym, stringTable, loadObject, plte, gote);
   return esym;
}

ElfSymbol* DynamicSection::nextDynamicSymbolIter(unsigned int* iter)
{
   char *gote, *plte;
   int goti;
   if (!stringTable || !symbolTable)
      return 0;
   (*iter)++;
   if (*iter >= symbolTableCount)
      return 0;
   ElfW(Sym) *sym = symbolTable;
   sym += *iter;
   if (GEN_ST_TYPE(sym->st_info) == STT_OBJECT)
      gote = findGOTEntryByName(getSymbolString(sym));
   else
      gote = findGOTPLTEntryByName(getSymbolString(sym));
   goti = (((unsigned long)gote) - 
           ((unsigned long)loadObject->getGOTAddress()))/4;
   goti -= 2; // hack; why??
   plte = loadObject->getPLTAddress() + (goti*16);
   if (0) printf("got=%p  gote=%p  goti=%d  plt=%p  plte=%p\n",
          loadObject->getGOTAddress(), gote, goti, 
          loadObject->getPLTAddress(), plte);
   ElfSymbol *esym = new ElfSymbol(sym, stringTable, loadObject, plte, gote);
   return esym;
}


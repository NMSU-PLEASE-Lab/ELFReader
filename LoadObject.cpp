#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ElfProgram.h>

/***
          c = &loadcmds[nloadcmds++];
          c->mapstart = ph->p_vaddr & ~(GLRO(dl_pagesize) - 1);
          c->mapend = ((ph->p_vaddr + ph->p_filesz + GLRO(dl_pagesize) - 1)
                       & ~(GLRO(dl_pagesize) - 1));
          c->dataend = ph->p_vaddr + ph->p_filesz;
          c->allocend = ph->p_vaddr + ph->p_memsz;
          c->mapoff = ph->p_offset & ~(GLRO(dl_pagesize) - 1);

/lib/libc-2.5.so
architecture: i386, flags 0x00000150:
HAS_SYMS, DYNAMIC, D_PAGED
start address 0x000160e0

Program Header:
    PHDR off    0x00000034 vaddr 0x00000034 paddr 0x00000034 align 2**2
         filesz 0x00000160 memsz 0x00000160 flags r-x
  INTERP off    0x00113e90 vaddr 0x00113e90 paddr 0x00113e90 align 2**0
         filesz 0x00000013 memsz 0x00000013 flags r--
    LOAD off    0x00000000 vaddr 0x00000000 paddr 0x00000000 align 2**12
         filesz 0x0012724c memsz 0x0012724c flags r-x
    LOAD off    0x001281f8 vaddr 0x001281f8 paddr 0x001281f8 align 2**12
         filesz 0x000027a4 memsz 0x000053cc flags rw-
 DYNAMIC off    0x00129d9c vaddr 0x00129d9c paddr 0x00129d9c align 2**2
         filesz 0x000000f0 memsz 0x000000f0 flags rw-
    NOTE off    0x00000194 vaddr 0x00000194 paddr 0x00000194 align 2**2
         filesz 0x00000020 memsz 0x00000020 flags r--
    NOTE off    0x000001b4 vaddr 0x000001b4 paddr 0x000001b4 align 2**2
         filesz 0x00000018 memsz 0x00000018 flags r--
     TLS off    0x001281f8 vaddr 0x001281f8 paddr 0x001281f8 align 2**2
         filesz 0x00000008 memsz 0x0000003c flags r--
EH_FRAME off    0x00113ea4 vaddr 0x00113ea4 paddr 0x00113ea4 align 2**2
         filesz 0x0000273c memsz 0x0000273c flags r--
   STACK off    0x00000000 vaddr 0x00000000 paddr 0x00000000 align 2**2
         filesz 0x00000000 memsz 0x00000000 flags rw-
   RELRO off    0x00128200 vaddr 0x00128200 paddr 0x001281f8 align 2**0
         filesz 0x00001c8c memsz 0x00001c70 flags r--

***/


/**
 * A LoadObject is created for each loaded program object: the
 * main program exe, each shared library, a "virtual" object for
 * system calls (auto-created by Linux), and one for the dyn linker
 */

/**
 * Constructor args come from map file.
 * @param objectName is the internal name of the load object.
 * @param baseAddress is the beginning address of the object.
 * @param endAddress is the end address of the object.
 */
LoadObject::LoadObject(char* objectName, char* baseAddress, char* endAddress)
{
   elfHeader = (ElfW(Ehdr)*) baseAddress;
   segments = 0; sections = 0; 
   //got = 0; plt = 0; //dynamicSymbols = 0; 
   staticSymbols = 0; 
   numStaticSymbols = 0;
   next = 0;
   l_map = 0;
   PLTAddress = 0;
   GOTAddress = 0;

   // verify that it is an ELF object
   if (!(elfHeader->e_ident[1]=='E' && elfHeader->e_ident[2]=='L' &&
         elfHeader->e_ident[3]=='F'))
   {
      printf("ERROR: Address %p not an ELF object: skipping\n",elfHeader);
      return;
   }

   objectFileName = objectName;
   this->baseAddress = baseAddress;
   this->highAddress = endAddress;

   // if the section header section is loaded, process it 
   // (usually it is not loaded, since section headers are
   //  not used at run time)
   if ((baseAddress + elfHeader->e_shoff) < highAddress)
   {
      processSectionHeaders();
   } 
   else 
   {
      // grab the section header section from the actual file
      char* secHeaders = getFileSection(getSectionTableOffset(),
                                        getSectionHeaderSize()* 
                                        getNumberOfSections());
      if (secHeaders)
      {
         processSectionHeaders(secHeaders);
      }
      // need to delete secHeaders????
   }
   // if segment header section is loaded, process it 
   // (this should always be true, as segment headers are 
   //  needed at runtime)
   if ((baseAddress + elfHeader->e_phoff) < highAddress)
   {
      //printf("...DoSegmentHeaders\n");
      processSegmentHeaders();
   }
   findAndSetLinkMap();
   debugPrintInfo();
}

/**
 * Print out debugging info about this load object
 */
void LoadObject::debugPrintInfo()
{
   unsigned int i;
   printf("  header at %p\n", elfHeader);
   printf("  head:%c%c%c%c\n",elfHeader->e_ident[0], elfHeader->e_ident[1],
          elfHeader->e_ident[2], elfHeader->e_ident[3]);
   printf("ELF object at %p to %p  (%s)\n", elfHeader, highAddress,
          getName());
   printf("--ELF-HEADER--\n");
   printf("  machine (%d) version (%d), entry (0x%x), phoff (0x%x)\n",
          (int) elfHeader->e_machine, (int) elfHeader->e_version,
          (int) elfHeader->e_entry, (int) elfHeader->e_phoff);
   printf("  shoff (0x%x) flags (0x%x), ehsize (%d)\n",
          (int) elfHeader->e_shoff, (int) elfHeader->e_flags,
          (int) elfHeader->e_ehsize);
   printf("  phentsize (%d) phnum (%d), shentsize (%d), shnum (%d)\n",
          (int) elfHeader->e_phentsize, (int) elfHeader->e_phnum,
          (int) elfHeader->e_shentsize, (int) elfHeader->e_shnum);
   printf("  shstrndx (0x%x)\n", (int) elfHeader->e_shstrndx);
   printf("section table should be at %p\n",(baseAddress + 
                                             elfHeader->e_shoff));

   if (!strstr(getName(),"/ld-")) {
   struct link_map* lm = l_map;
   printf("my linkmap: %p\n",lm);
   /* hope that the list is NULL terminated */
   while (lm && lm->l_prev > (void*) 0xffff && lm->l_prev < (void*) 0xff00000000000000L)
                lm = lm->l_prev;
   printf("first linkmap: %p\n",lm);
   for (; lm; lm = lm->l_next)
      printf("linkmap name: %p (%s)\n",lm,lm->l_name);
   }
   return;   

   for (i=0; i < numSegments; i++)
   {
      segments[i]->debugPrintInfo();
   }
   for (i=0; i < numSections; i++)
   {
      sections[i]->debugPrintInfo(secHeaderStringTable);
   }
   if (dynamicSection)
      dynamicSection->debugPrintInfo();

   ElfW(Sym)* sym = (ElfW(Sym)*) staticSymbols;
   for (i=0; i < numStaticSymbols; i++)
   {
      if (GEN_ST_TYPE(sym->st_info) == STT_FUNC)
         printf(" st-func (%p) is (%s), val %lx, size %x, type %x (%x,%x,%x)\n",
             sym, symbolStringTable+sym->st_name, sym->st_value, 
             (int) sym->st_size, (int) GEN_ST_TYPE(sym->st_info),
             (int) GEN_ST_BIND(sym->st_info), 
             (int) sym->st_other, (int) sym->st_shndx);
      sym++;
   }
   ElfSection* sec = findSectionByName(".plt");
   if (sec)
   {
      printf("  section .plt found by name: %p (%p)\n",
             sec->getSectionDataPtr(),PLTAddress);
      //PLTAddress = sec->getSectionDataPtr();
   }
   ElfSymbol *esym = findStaticSymbolByName("printf");
   if (esym)
   {
      printf(" S: found printf by name: (%p) is (%s), val %x, size %x, type %x (%x,%x,%x)\n",
            esym, esym->getName(), esym->getRawValue(), esym->getSize(), 
            esym->getType(), esym->getBind(), 
            esym->getOther(), esym->getSHIndex());
   }
   if (dynamicSection)
      esym = dynamicSection->findDynamicSymbolByName("printf");
   else
      esym = 0;
   if (esym)
   {
      printf(" D: found printf by name: (%p) is (%s), val %x, size %x, type %x (%x,%x,%x)\n",
            esym, esym->getName(), esym->getRawValue(), esym->getSize(), 
            esym->getType(), esym->getBind(), 
            esym->getOther(), esym->getSHIndex());
   }
   printf("  GS: found printf by name: (%p)\n", 
          getSymbolAddressByName("printf"));
   printf("  GSPLT: found printf by name: (%p)\n", 
          getPLTEntryAddressByName("printf"));
   printf("  GSGOT: found printf by name: (%p)\n",
          getGOTEntryAddressByName("printf"));
}

LoadObject::LoadObject(char* objFilename)
{
}


LoadObject::~LoadObject()
{
}

char* LoadObject::getName()
{
   return objectFileName;
}

/**
 * Iterate through the segment header table and create ElfSegment
 * objects for each one.
 * @return Zero always.
 */
int LoadObject::processSegmentHeaders()
{
   ElfSegment* newseg;
   unsigned int i;
   ElfW(Phdr)* segHeader = (ElfW(Phdr)*)(getBaseAddress()+elfHeader->e_phoff);
   int segHeaderSize = getSegmentHeaderSize();
   numSegments = getNumberOfSegments();
   segments = new ElfSegment*[numSegments];
   //char* baseAddress = getBaseAddress();
   for (i=0; i < numSegments; i++)
   {
      //printf("new segment\n");
      newseg = new ElfSegment(i, segHeader, this);
      segments[i] = newseg;
      segHeader = (ElfW(Phdr)*)(((char*)segHeader)+segHeaderSize);
   }
   return 0;
}

/**
 * Iterate through the section header table and create ElfSection
 * objects for each one. Tricky because sections are not load-time
 * abstractions. Some of the stuff done here should be done from
 * the dynamic section segment pointer.
 * @param secHeaderData is the address of the first section header.
 * @return Zero always.
 */
int LoadObject::processSectionHeaders(char* secHeaderData)
{
   ElfSection* newsec;
   ElfW(Shdr)* secHeader;
   if (secHeaderData)
      secHeader = (ElfW(Shdr)*) secHeaderData;
   else
      secHeader = (ElfW(Shdr)*)(getBaseAddress()+ elfHeader->e_shoff);
   int secHeaderSize = getSectionHeaderSize();
   numSections = getNumberOfSections();
   sections = new ElfSection*[numSections];
   //char* baseAddress = getBaseAddress();
   unsigned int i, sti;
   for (i=0; i < numSections; i++)
   {
      //printf("new section\n");
      newsec = new ElfSection(i, secHeader, this);
      sections[i] = newsec;
      if (i == getSectionHeaderStringIndex())
      {
         secHeaderStringTable = newsec->getSectionDataPtr();
      }
      if (newsec->isSymbolTable())
      {
         staticSymbols = (ElfW(Sym)* ) newsec->getSectionDataPtr();
         numStaticSymbols =  newsec->getSizeInBytes() / 
            newsec->getEntrySize();
         sti = newsec->getSectionLink();
      }
      secHeader = (ElfW(Shdr)*)(((char*)secHeader)+secHeaderSize);
   }
   for (i=0; i < numSections; i++)
   {
      if (!strcmp(sections[i]->getName(secHeaderStringTable),".plt"))
         PLTAddress = sections[i]->getSectionDataPtr();
      //if (!strcmp(sections[i]->getName(secHeaderStringTable),".got.plt"))
      //   GOTAddress = sections[i]->getSectionDataPtr();
   }
   if (staticSymbols)
   {
      //printf("static symbols, count = %d\n", numStaticSymbols);
      symbolStringTable = sections[sti]->getSectionDataPtr();
   }
   return 0;
}

/**
 * Create a DynamicSection object for the dynamic section
 * @param dynamicSectionAddress is the beginning address of the section.
 * @param size is the section's size.
 * @return Zero always.
 */
int LoadObject::processDynamicSection(char* dynamicSectionAddress, 
                                      unsigned int size)
{
   //printf("new dynamic section\n");
   dynamicSection = new DynamicSection(dynamicSectionAddress, size, this);
   return 0;
}

/**
 * Open a file, read a block of data from the file, and return a
 * pointer to that data (allocated).
 * @param offset is the offset from the file start.
 * @param size is the number of bytes to get.
 * @return Char* pointer to the section data (allocated using new char[]).
 */
char* LoadObject::getFileSection(unsigned int offset, unsigned int size)
{
   FILE* fp;
   char* dataBlock;
   fp = fopen(objectFileName,"r");
   if (!fp)
      return 0;
   if (fseek(fp, offset, SEEK_SET))
   {
      fclose(fp);
      return 0;
   }
   dataBlock = new char[size];
   if (fread(dataBlock, sizeof(char), size, fp) != size)
   {
      delete dataBlock;
      dataBlock = 0;
   }
   fclose(fp);
   return dataBlock;
}

/**
 * Iterate through the section header string table and find a section
 * index by name.
 * @param name is the section name (e.g. ".text").
 * @return An ElfSection object pointer for the found section, or null.
 */
ElfSection* LoadObject::findSectionByName(char* name)
{
   unsigned int i;
   if (!secHeaderStringTable)
      return 0;
   for (i=0; i < numSections; i++)
      if (!strcmp(name,sections[i]->getName(secHeaderStringTable)))
         break;
   if (i < numSections)
      return sections[i];
   else
      return 0;
}

ElfSymbol* LoadObject::startDynamicSymbolIter(unsigned int* iter)
{
   return dynamicSection->startDynamicSymbolIter(iter);
}

ElfSymbol* LoadObject::nextDynamicSymbolIter(unsigned int* iter)
{
   return dynamicSection->nextDynamicSymbolIter(iter);
}

ElfSymbol* LoadObject::startStaticSymbolIter(unsigned int* iter)
{
   ElfW(Sym)* sym = (ElfW(Sym)*) staticSymbols;
   if (!sym)
      return 0;
   *iter = 0;
   ElfSymbol *esym = new ElfSymbol(sym, symbolStringTable, this, 0, 0);
   return esym;
}

ElfSymbol* LoadObject::nextStaticSymbolIter(unsigned int* iter)
{
   ElfW(Sym)* sym = (ElfW(Sym)*) staticSymbols;
   if (!sym)
      return 0;
   (*iter)++;
   if (*iter >= numStaticSymbols)
      return 0;
   sym += *iter;
   ElfSymbol *esym = new ElfSymbol(sym, symbolStringTable, this, 0, 0);
   return esym;
}

ElfSymbol* LoadObject::findStaticSymbolByName(char* name)
{
   unsigned int i;
   ElfW(Sym)* sym = (ElfW(Sym)*) staticSymbols;
   if (!sym)
      return 0;
   for (i=0; i < numStaticSymbols; i++)
   {
      if (!strcmp(name,symbolStringTable+sym->st_name))
         break;
      sym++;
   }
   if (i < numStaticSymbols)
   {
      ElfSymbol *esym = new ElfSymbol(sym, symbolStringTable, this, 0, 0);
      return esym;
   }
   else
      return 0;
}

ElfSymbol* LoadObject::findDynamicSymbolByName(char* name)
{
   ElfSymbol* esym;
   if (!dynamicSection)
      return 0;
   esym = dynamicSection->findDynamicSymbolByName(name);
   return esym;
   return 0;
}

struct link_map* LoadObject::getLinkMap()
{
   return l_map;
}

/**
 * Find this load object's link_map structure that the dynamic linker
 * uses to keep track of it. Assumes that the load object's GOT table
 * has already been found and set.
 * @return Zero always (and sets l_map object field).
 */
int LoadObject::findAndSetLinkMap()
{
   // start with address of "ELF" magic symbol for this object
   // find PT_DYNAMIC segment
   // find address of GOT by locating DT_PLTGOT entry in dynamic section
   // link map entry is GOT[1] (can vary on other platforms)
   ElfW(Addr) *got;
   if (!GOTAddress)
      return -1;
   got = (ElfW(Addr)*) GOTAddress;
   l_map = (struct link_map *) got[1];
   return 0;
}

char* LoadObject::getGOTAddress()
{
   return GOTAddress;
}

void LoadObject::setGOTAddress(char *address)
{
   GOTAddress = address;
}

char* LoadObject::getPLTAddress()
{
   return PLTAddress;
}

char* LoadObject::getGOTEntryAddressByName(char *symbolName)
{
   char *e;
   if (!dynamicSection)
      return 0;
   e = dynamicSection->findGOTEntryByName(symbolName);
   if (e)
      return e;
   e = dynamicSection->findGOTPLTEntryByName(symbolName);
   return e;
}

char* LoadObject::getPLTEntryAddressByName(char *symbolName)
{
   ElfSymbol* esym = findDynamicSymbolByName(symbolName);
   if (!esym || esym->getRawValue() == 0 || esym->getSHIndex() != 0)
      return 0;
   return (char*) esym->getRawValue();
}

char* LoadObject::getSymbolAddressByName(char *symbolName)
{
   ElfSymbol* esym = findDynamicSymbolByName(symbolName);
   if (!esym || esym->getRawValue() == 0 || esym->getSHIndex() != 0)
      return 0;
   return baseAddress + (unsigned int)esym->getRawValue();
}

int LoadObject::getSectionHeaderSize()
{
   if (elfHeader)
      return (int) elfHeader->e_shentsize;
   else
      return 0;
}

int LoadObject::getNumberOfSections()
{
   if (elfHeader)
      return (int) elfHeader->e_shnum;
   else
      return 0;
}

int LoadObject::getSegmentHeaderSize()
{
   if (elfHeader)
      return (int) elfHeader->e_phentsize;
   else
      return 0;
}

int LoadObject::getNumberOfSegments()
{
   if (elfHeader)
      return (int) elfHeader->e_phnum;
   else
      return 0;
}

char* LoadObject::getBaseAddress()
{
   return (char*) elfHeader;
}

char* LoadObject::getHighAddress()
{
   return highAddress;
}

char* LoadObject::getEntryAddress()
{
   return (char*) elfHeader->e_entry;
}

unsigned int LoadObject::getSegmentTableOffset()
{
   return elfHeader->e_phoff;
}

unsigned int LoadObject::getSegmentEntrySize()
{
   return elfHeader->e_phentsize;
}

unsigned int LoadObject::getSegmentEntryCount()
{
   return elfHeader->e_phnum;
}

unsigned int LoadObject::getSectionTableOffset()
{
   return elfHeader->e_shoff;
}

unsigned int LoadObject::getSectionEntrySize()
{
   return elfHeader->e_shentsize;
}

unsigned int LoadObject::getSectionEntryCount()
{
   return elfHeader->e_shnum;
}

unsigned int LoadObject::getSectionHeaderStringIndex()
{
   return elfHeader->e_shstrndx;
}

unsigned int LoadObject::is32BitClass() // e_ident[4]
{
   return (elfHeader->e_ident[EI_CLASS] == ELFCLASS32);
}

unsigned int LoadObject::is64BitClass() // e_ident[4]
{
   return (elfHeader->e_ident[EI_CLASS] == ELFCLASS64);
}

unsigned int LoadObject::isLittleEndian() // e_ident[5]
{
   return (elfHeader->e_ident[EI_DATA] == ELFDATA2LSB);
}

unsigned int LoadObject::isBigEndian() // e_ident[5]
{
   return (elfHeader->e_ident[EI_DATA] == ELFDATA2MSB);
}

unsigned int LoadObject::getElfVersion() // e_ident[6]
{
   return elfHeader->e_ident[EI_VERSION]; // must be EV_CURRENT
}

unsigned int LoadObject::getOSABI() // e_ident[7]
{
   return elfHeader->e_ident[EI_OSABI]; 
}

unsigned int LoadObject::getOSABIVersion() // e_ident[8]
{
   return elfHeader->e_ident[EI_ABIVERSION]; 
}

unsigned int LoadObject::isNoType() // e_type
{
   return (elfHeader->e_type == ET_NONE); 
}

unsigned int LoadObject::isRelocatable() // e_type
{
   return (elfHeader->e_type == ET_REL); 
}

unsigned int LoadObject::isExecutable() // e_type
{
   return (elfHeader->e_type == ET_EXEC); 
}

unsigned int LoadObject::isSharedLibrary() // e_type
{
   return (elfHeader->e_type == ET_DYN); 
}

unsigned int LoadObject::isCoreFile() // e_type
{
   return (elfHeader->e_type == ET_CORE); 
}

unsigned int LoadObject::isOSType() // e_type
{
   return (elfHeader->e_type >= ET_LOOS && elfHeader->e_type <= ET_HIOS); 
}

unsigned int LoadObject::isProcessorType() // e_type
{
   return (elfHeader->e_type >= ET_LOPROC && elfHeader->e_type <= ET_HIPROC); 
}

unsigned int LoadObject::getArchitectureType() // e_machine
{
   return elfHeader->e_machine; 
}

unsigned int LoadObject::isCurrentVersion() // e_version
{
   return (elfHeader->e_version == EV_CURRENT); 
}

unsigned int LoadObject::getHeaderFlags() // e_flags
{
   return elfHeader->e_flags; 
}

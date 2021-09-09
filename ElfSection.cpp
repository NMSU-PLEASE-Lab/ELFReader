
#include <ElfProgram.h>
#include <stdio.h>

/**
 * Sets up object holding info about an ELF section. This does
 * some special stuff for symbol table and string table sections.
 * If the section data is not already loaded in memory, this 
 * constructor asks the loadObject to fetch it from the file.
 * @param secIndex is the index # of this section.
 * @param secHeader is the address of this section's header record.
 * @param loadObject is the ELF object this section belongs to.
 */
ElfSection::ElfSection(int secIndex, ElfW(Shdr) *secHeader, 
                       LoadObject *loadObject)
{
   char *stringTable;
   char *symbolTable;
   unsigned int stringTableSize;
   unsigned int symbolTableSize;
   unsigned int symbolEntrySize;
   unsigned int stringTableIndex;

   stringTable=0;
   symbolTable=0;
   stringTableSize=0;
   symbolTableSize=0;
   symbolEntrySize=0;
   stringTableIndex = 0;

   index = secIndex;
   this->secHeader = secHeader;
   baseAddress = loadObject->getBaseAddress() + (int) secHeader->sh_offset;

   //
   // executable has blank spaces -- maybe a DSO does, too?
   //
   if ((char*)secHeader->sh_addr > baseAddress && 
       loadObject->isExecutable() && 
       isLoadedInMemory())
      baseAddress = (char*) secHeader->sh_addr;
   
   highAddress = baseAddress + (int) secHeader->sh_size;
   sectionDataPtr = baseAddress;
   alignMask = ~(1 - (int) secHeader->sh_addralign);
   this->loadObject = loadObject;

   //debugPrintInfo();

   // if not in memory, then fetch section data from file
   if ((getType() == SHT_SYMTAB || getType() == SHT_STRTAB) &&
       (baseAddress > loadObject->getHighAddress() ||
        highAddress > loadObject->getHighAddress()))
   {
      sectionDataPtr = 
         loadObject->getFileSection((unsigned int) secHeader->sh_offset,
                                    (unsigned int) secHeader->sh_size);
      //printf("section fetched from file\n");
      assert(sectionDataPtr);
   }

   if (isStringTable()) //secHeader->sh_type == SHT_STRTAB)
   {
      //printf("  SHT DoDumpStringTable..SHT...\n");
      //DoDumpStringTable(baseAddress + secHeader->sh_offset,
      //                  (int) secHeader->sh_size);
   }
   if (isSymbolTable()) //secHeader->sh_type == SHT_SYMTAB)
   {
      //printf("DoDumpSymbolTable..SHT...\n");
      symbolTable = baseAddress + secHeader->sh_offset;
      symbolEntrySize = secHeader->sh_entsize;
      symbolTableSize = secHeader->sh_size;
      stringTableIndex = secHeader->sh_link;
   }
   if (stringTableIndex && index == stringTableIndex)
   {
      stringTable = baseAddress + secHeader->sh_offset;
      stringTableSize = secHeader->sh_size;
   }

   return;
}

void ElfSection::debugPrintInfo(char *shStrTable)
{
   //unsigned int i, count;
   printf("----SECTION ");
   printf(" %d: sec_name (%d,%s), type (%x) flags (0x%x)\n", index,
          getNameIndex(), (shStrTable) ? getName(shStrTable) : "n/a",
          getType(), getFlags());
   printf("      vaddr (0x%x), offset (0x%x) size (%d) [data addr=%p]\n",
          getVirtualAddress(), getFileOffset(), getSizeInBytes(),
          getSectionDataPtr());
   printf("      link (%d), info (%d) align (%d) entsize (%d)\n",
          getSectionLink(), (int) secHeader->sh_info,
          getAlignmentMask(), getEntrySize());
}

unsigned int ElfSection::getIndex()
{
   return index;
}

char* ElfSection::getBaseAddress()
{
   return baseAddress;
}

char* ElfSection::getHighAddress()
{
   return highAddress;
}

ElfW(Shdr) *ElfSection::getSectionHeader()
{
   return secHeader;
}

char* ElfSection::getSectionDataPtr()
{
   return sectionDataPtr;
}

unsigned int ElfSection::getAlignmentMask()
{
   return alignMask;
}

unsigned int ElfSection::getNameIndex()
{
   return secHeader->sh_name;
}

char* ElfSection::getName(char* stringTable)
{
   if (!stringTable)
      return 0;
   return stringTable + secHeader->sh_name;
}

unsigned int ElfSection::getType()
{
   return secHeader->sh_type;
}

unsigned int ElfSection::getFlags()
{
   return secHeader->sh_flags;
}

unsigned int ElfSection::getVirtualAddress()
{
   return secHeader->sh_addr;
}

unsigned int ElfSection::getFileOffset()
{
   return secHeader->sh_offset;
}

unsigned int ElfSection::getSizeInBytes()
{
   return secHeader->sh_size;
}

unsigned int ElfSection::getSectionLink()
{
   return secHeader->sh_link;
}

unsigned int ElfSection::getEntrySize()
{
   return secHeader->sh_entsize;
}

unsigned int ElfSection::isUndefinedSection() //sh_index
{
   return (index == SHN_UNDEF);
}

unsigned int ElfSection::isReserved()//sh_index
{
   return (index >= SHN_LORESERVE && 
           index <= SHN_HIRESERVE);
}

unsigned int ElfSection::isNull() //sh_type
{
   return (secHeader->sh_type == SHT_NULL);
}

unsigned int ElfSection::isProgramBits() //sh_type
{
   return (secHeader->sh_type == SHT_PROGBITS);
}

unsigned int ElfSection::isSymbolTable() //sh_type
{
   return (secHeader->sh_type == SHT_SYMTAB);
}

unsigned int ElfSection::isStringTable() //sh_type
{
   return (secHeader->sh_type == SHT_STRTAB);
}

unsigned int ElfSection::isRelocationWithAddends() //sh_type
{
   return (secHeader->sh_type == SHT_RELA);
}

unsigned int ElfSection::isRelocationNoAddends() //sh_type
{
   return (secHeader->sh_type == SHT_REL);
}

unsigned int ElfSection::isSymbolHashTable() //sh_type
{
   return (secHeader->sh_type == SHT_HASH);
}

unsigned int ElfSection::isDynamicInfo() //sh_type
{
   return (secHeader->sh_type == SHT_DYNAMIC);
}

unsigned int ElfSection::isNote() //sh_type
{
   return (secHeader->sh_type == SHT_NOTE);
}

unsigned int ElfSection::isProgramSpaceNoBits() //sh_type
{
   return (secHeader->sh_type == SHT_NOBITS);
}

unsigned int ElfSection::isDynamicSymbolTable() //sh_type
{
   return (secHeader->sh_type == SHT_DYNSYM);
}

unsigned int ElfSection::isInitalization() //sh_type
{
   return (secHeader->sh_type == SHT_INIT_ARRAY);
}

unsigned int ElfSection::isFinalization() //sh_type
{
   return (secHeader->sh_type == SHT_FINI_ARRAY);
}

unsigned int ElfSection::isPreInitialization() //sh_type
{
   return (secHeader->sh_type == SHT_PREINIT_ARRAY);
}

unsigned int ElfSection::isSectionGroup() //sh_type
{
   return (secHeader->sh_type == SHT_GROUP);
}

unsigned int ElfSection::isExtendedSectionIndices() //sh_type
{
   return (secHeader->sh_type == SHT_SYMTAB_SHNDX);
}

unsigned int ElfSection::isNumberOfTypes() //sh_type
{
   return (secHeader->sh_type == SHT_NUM);
}

unsigned int ElfSection::isOSSpecific() //sh_type
{
   return (secHeader->sh_type >= SHT_LOOS);
}

unsigned int ElfSection::isWritable() //sh_flags
{
   return (secHeader->sh_flags & SHF_WRITE);
}

unsigned int ElfSection::isLoadedInMemory() //sh_flags
{
   return (secHeader->sh_flags & SHF_ALLOC);
}

unsigned int ElfSection::isExecutable() //sh_flags
{
   return (secHeader->sh_flags & SHF_EXECINSTR);
}

unsigned int ElfSection::isCanBeMerged() //sh_flags
{
   return (secHeader->sh_flags & SHF_MERGE);
}

unsigned int ElfSection::isSetOfString() //sh_flags
{
   return (secHeader->sh_flags & SHF_STRINGS);
}

unsigned int ElfSection::infoHasSHTIndex() //sh_flags
{
   return (secHeader->sh_flags & SHF_INFO_LINK);
}

unsigned int ElfSection::preserveLinkOrder() //sh_flags
{
   return (secHeader->sh_flags & SHF_LINK_ORDER);
}

unsigned int ElfSection::nonConformingOS() //sh_flags
{
   return (secHeader->sh_flags & SHF_OS_NONCONFORMING);
}

unsigned int ElfSection::isGroupMember() //sh_flags
{
   return (secHeader->sh_flags & SHF_GROUP);
}

unsigned int ElfSection::isThreadLocalStorage() //sh_flags
{
   return (secHeader->sh_flags & SHF_TLS);
}

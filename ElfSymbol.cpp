#include <ElfProgram.h>

/**
 * Sets up a symbol information object. ElfSymbol objects are mostly
 * used transiently to reference symbols. The object just points to
 * the symbol record, and provides accessor functions to access the
 * data and attributes.
 * @param sym is the ELF symbol record.
 * @param strTable is the base address of the string table holding this symbol.
 * @param loadObject is the ELF object containing this symbol record.
 * @param PLT is the address of the symbol's PLT entry, if it has one.
 * @param GOT is the address of the symbol's GOT entry, if it has one.
 */
ElfSymbol::ElfSymbol(ElfW(Sym)* sym, char* strTable, LoadObject* loadObject,
                     char* PLT, char* GOT)
{
   this->sym = sym;
   this->strTable = strTable;
   this->loadObject = loadObject;
   PLTEntry = PLT;
   GOTEntry = GOT;
}

ElfSymbol::~ElfSymbol()
{
}

char* ElfSymbol::getName()
{
   if (!strTable)
      return 0;
   return strTable + sym->st_name;
}

unsigned int ElfSymbol::getRawValue()
{
   return sym->st_value;
}

unsigned int ElfSymbol::getSize()
{
   return sym->st_size;
}

unsigned int ElfSymbol::getType()
{
   return ELF32_ST_TYPE(sym->st_info);
}

unsigned int ElfSymbol::isDataObject()
{
   return (ELF32_ST_TYPE(sym->st_info) == STT_OBJECT);
}

unsigned int ElfSymbol::isCodeObject()
{
   return (ELF32_ST_TYPE(sym->st_info) == STT_FUNC);
}

unsigned int ElfSymbol::getBind()
{
   return ELF32_ST_BIND(sym->st_info);
}

unsigned int ElfSymbol::isLocal()
{
   return (ELF32_ST_BIND(sym->st_info) == STB_LOCAL);
}

unsigned int ElfSymbol::isGlobal()
{
   return (ELF32_ST_BIND(sym->st_info) == STB_GLOBAL);
}

unsigned int ElfSymbol::isWeak()
{
   return (ELF32_ST_BIND(sym->st_info) == STB_WEAK);
}

unsigned int ElfSymbol::getOther()
{
   return sym->st_other;
}

unsigned int ElfSymbol::getSHIndex()
{
   return sym->st_shndx;
}

char* ElfSymbol::getGOTEntryAddress()
{
   return GOTEntry;
}

char* ElfSymbol::getPLTEntryAddress()
{
   return PLTEntry;
}

LoadObject* ElfSymbol::getLoadObject()
{
   return loadObject;
}

/**
 * Fairly complex logic here to get an address for a symbol. We
 * need to do different things for data/code symbols, symbols in
 * a shared library versus an executable, and defined or undefined
 * symbols. Please see the code to understand it. 
 */
char* ElfSymbol::getSymbolAddress()
{
   //
   // if this is a symbol definition, then return its address
   //
   if (getSHIndex() != 0 && getSHIndex() < 1000)
   {
      if (loadObject->isSharedLibrary()) // must add objects base address
         return loadObject->getBaseAddress() + sym->st_value;
      // 
      // The above should maybe use the load segment's virtual address
      // plus the base address, or some formula like that, because
      // there can be gaps between the loaded segments (because of
      // page alignment. But how to find that? We could simply compare
      // the symbol's value to the start/stop of each segment, but it
      // seems like it ought to be easier. Maybe not, though, because
      // the static symbols are not meant to be used at runtime so this
      // was not planned out.
      //
      else // executable has actual value (does the above apply?)
         return (char*) sym->st_value;
   }
   else // is a use (and undefined symbol)
   {
      // if a code object, return PLT entry address
      if (isCodeObject())
         return PLTEntry;
      else // is a data object, so return GOT address
      {
         if (loadObject->isSharedLibrary()) // must add objects base address
            return loadObject->getBaseAddress() + (unsigned long) GOTEntry;
         else // executable has actual value
            return GOTEntry; 
      }
   }
}

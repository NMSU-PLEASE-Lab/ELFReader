/**
 * @mainpage 
 * A Library of ELF object inspection capabilities. 
 *
 * The basic idea is to provide access to all of the ELF file format's
 * features, and to provide inspection of a program and its shared
 * libraries as it is running. Ultimately we would like to do things
 * such as manipulate the dynamic bindings and symbol references.
 * 
 * A ProgramInfo object is the top-level object. It holds information 
 * about the whole program. It holds a list of LoadObject objects, one
 * for each ELF object loaded (one application, zero or more shared 
 * libraries, the dynamic linker, and one pseudo-ELF object for the
 * system calls (named "vdso" for virtual dynamic shared object).
 *
 * From the LoadObject objects, Other classes represent the segments 
 * and sections inside the ELF object (ElfSegment, ElfSection), a class
 * DynamicSection represents the special .dynamic section, and ElfSymbol
 * is used in a variety of places to hold symbol information.
 *
 * This library is still under development.
 *
 * Copyright (C) 2006-2008 Regents of New Mexico State University.
 *
 */
#ifndef  ELF_PROGRAM_INFO_H
#define ELF_PROGRAM_INFO_H

#include <assert.h>
//#include <elf.h>
#include <link.h>
#include <bits/elfclass.h>

#define GEN_ST_TYPE _GTYPE1 (ELF, __ELF_NATIVE_CLASS, _ST_TYPE)
#define GEN_ST_BIND _GTYPE1 (ELF, __ELF_NATIVE_CLASS, _ST_BIND)
#define GEN_R_SYM  _GTYPE1 (ELF, __ELF_NATIVE_CLASS, _R_SYM)
#define GEN_R_TYPE _GTYPE1 (ELF, __ELF_NATIVE_CLASS, _R_TYPE)
#define GEN_R_INFO _GTYPE1 (ELF, __ELF_NATIVE_CLASS, _R_INFO)
#define _GTYPE1(e,w,t) _COMP3 (e, w, t)
#define _COMP3(e,w,t) e##w##t

/**
 * ElfSymbol is a class embodying a generic program symbol. 
 * ElfSymbol is returned in many places, and thus is worth declaring first.
 * -- still needs version checking and reporting in here (and everywhere)
 * -- getSymbolAddress() may still need some work. It tries to do 
 *    alot: for an undefined symbol, it returns the PLT entry address
 *    for a code symbol, and the GOT entry address for a data symbol;
 *    for a defined symbol (i.e., it is in the LoadObject that it is
 *    returned for), it returns the actual address of the code/data.
 */
class ElfSymbol
{
  public:
   ElfSymbol(ElfW(Sym) *sym, char* strTable, 
             class LoadObject* loadObject,
             char* PLT=0, char* GOT=0);
   ~ElfSymbol();
   char* getName();
   unsigned int getRawValue();  //!< Returns st_value
   char* getSymbolAddress();    //!< Attempts to calculate actual address
   unsigned int getSize();      //!< Returns st_size
   unsigned int getType();      //!< Returns raw type value
   unsigned int isDataObject(); //!< Boolean test on type
   unsigned int isCodeObject(); //!< Boolean test on type
   unsigned int getBind();      //!< Returns raw binding value
   unsigned int isLocal();      //!< Boolean test on bind
   unsigned int isGlobal();     //!< Boolean test on bind
   unsigned int isWeak();       //!< Boolean test on bind
   unsigned int getOther();     //!< Returns raw st_other value
   unsigned int getSHIndex();   //!< Returns raw st_shndx
   char* getGOTEntryAddress();  //!< Pointer to actual GOT entry
   char* getPLTEntryAddress();  //!< Pointer to actual PLT entry (for functions)
   class LoadObject* getLoadObject(); //!< Return ELF object this symbol is in
  private:
   ElfW(Sym)* sym;         //!< Pointer to sym entry (somewhere?)
   char* strTable;         //!< String table this symbol is in
   LoadObject *loadObject; //!< ELF object this symbol is in
   char* PLTEntry;         //!< Pointer to actual PLT entry
   char* GOTEntry;         //!< Pointer to actual GOT entry
};

/**
 * The ProgramInfo class offers an entry point to qerying info about
 * the whole program, over all loaded objects, rather than individual
 * loaded objects.
 * -- loaded object list should be private, with iterator functions
 * -- the symbol list is not used, and will probably be removed
 */
class ProgramInfo
{
  public:
   ProgramInfo(void); 
   ProgramInfo(char* objFilename);
   ~ProgramInfo();
   void debugPrintInfo();
   int addLoadObject(class LoadObject* lo); 
   ElfSymbol** findSymbolDefinitions(char* symbolName, int* numDefs);
   ElfSymbol** findSymbolUses(char* symbolName, int* numUses);
   //int addProgramSymbol(void);
   //private:
   char* name;                      //!< Program name
   unsigned int pid;                //!< Process ID
   class LoadObject* loadedObjects; //!< Loaded objects list
   //class ProgramSymbol* symbols;  // list
};

/**
 * Each object of the class LoadObject represents one loaded ELF
 * object, the executable program itself or the shared libs that have
 * been loaded.
 */
class LoadObject
{
  public:
   LoadObject(char* objectName, char* baseAddress, char* endAddress);
   LoadObject(char* objFilename);
   ~LoadObject();
   void debugPrintInfo();
   char* getName();
   int processSegmentHeaders();
   int processSectionHeaders(char* secHeaderData=0);
   int processDynamicSection(char* dynamicSectionAddress, unsigned int size);
   char* getFileSection(unsigned int offset, unsigned int size);
   class ElfSection* findSectionByName(char* sectionName);
   ElfSymbol* findStaticSymbolByName(char* symbolName);
   ElfSymbol* findDynamicSymbolByName(char* symbolName);
   ElfSymbol* startDynamicSymbolIter(unsigned int* iter);
   ElfSymbol* nextDynamicSymbolIter(unsigned int* iter);
   ElfSymbol* startStaticSymbolIter(unsigned int* iter);
   ElfSymbol* nextStaticSymbolIter(unsigned int* iter);
   struct link_map* getLinkMap();
   int findAndSetLinkMap();
   char* getGOTAddress();
   void setGOTAddress(char* address);
   char* getPLTAddress();
   char* getGOTEntryAddressByName(char *symbolName);
   char* getPLTEntryAddressByName(char *symbolName);
   char* getSymbolAddressByName(char *symbolName);
   int getSegmentHeaderSize();
   int getNumberOfSegments();
   int getSectionHeaderSize();
   int getNumberOfSections();
   char* getBaseAddress();
   char* getHighAddress();
   char* getEntryAddress();
   unsigned int getSegmentTableOffset();
   unsigned int getSegmentEntrySize();
   unsigned int getSegmentEntryCount();
   unsigned int getSectionTableOffset();
   unsigned int getSectionEntrySize();
   unsigned int getSectionEntryCount();
   unsigned int getSectionHeaderStringIndex();
   unsigned int is32BitClass();    //!< From e_ident[4]
   unsigned int is64BitClass();    //!< From e_ident[4]
   unsigned int isLittleEndian();  //!< From e_ident[5]
   unsigned int isBigEndian();     //!< From e_ident[5]
   unsigned int getElfVersion();   //!< From e_ident[6]
   unsigned int getOSABI();        //!< From e_ident[7]
   unsigned int getOSABIVersion(); //!< From e_ident[8]
   unsigned int isNoType();        //!< From e_type
   unsigned int isRelocatable();   //!< From e_type
   unsigned int isExecutable();    //!< From e_type
   unsigned int isSharedLibrary(); //!< From e_type
   unsigned int isCoreFile();      //!< From e_type
   unsigned int isOSType();        //!< From e_type
   unsigned int isProcessorType(); //!< From e_type
   unsigned int getArchitectureType(); //!< From e_machine
   unsigned int isCurrentVersion();    //!< From e_version
   unsigned int getHeaderFlags();      //!< From e_flags
   class LoadObject* next;
  private:
   char* name;               //!< Loaded object internal name (sometimes null?)
   ElfW(Ehdr)* elfHeader;    //!< Pointer to ELF header of this object
   char* baseAddress;        //!< Beginning address (same as elfHeader?)
   char* highAddress;        //!< End address
   char* objectFileName;     //!< Object filename
   unsigned int type;        //!< Type of object (executable or shared lib)
   unsigned int permissions; //!< Permissions of object
   char* GOTAddress;         //!< Address of GOT
   char* PLTAddress;         //!< Address of PLT
   //class GOTInfo* got;       //!< Not used?
   //class PLTInfo* plt;       //!< Not used?
   class ElfSegment** segments;            //!< Segment object array
   unsigned int numSegments;               //!< Number of segments
   class ElfSection** sections;            //!< Section object array
   unsigned int numSections;               //!< Number of sections
   class DynamicSection* dynamicSection;   //!< Special dynamic section
   //class ProgramSymbol* dynamicSymbols;  // list
   //class ProgramSymbol* staticSymbols;   // list
   ElfW(Sym)* staticSymbols;               //!< Static symbol array
   unsigned int numStaticSymbols;          //!< Number of static symbols
   char* symbolStringTable;                //!< Static symbol string table
   char* secHeaderStringTable;             //!< Section header string table
   struct link_map *l_map;       //!< Dynamic linker's link_map for this object
};

/**
 * Each segment in a loaded object is represented by an ElfSegment object
 * -- nothing exciting here, mostly a wrapper around the segment header
 *    data, but I need to check whether or not the load virtual address
 *    is being calculated right. Segments are mmap()'d individually, and
 *    there can be gaps and offsets so that the file offset is different
 *    than the loaded offset.
 */ 
class ElfSegment
{
  public:
   ElfSegment(int segIndex, ElfW(Phdr)* segHeader, LoadObject* loadObject);
   ~ElfSegment();
   void debugPrintInfo();
   char* getBaseAddress();
   char* getHighAddress();
   unsigned int getAlignmentMask();
   char* getVirtualAddress();
   char* getPhysicalAddress();
   unsigned int getFileOffset();
   unsigned int getType();
   unsigned int getFlags();
   unsigned int isLoadable();
   unsigned int isDynamicInfo();
   unsigned int isInterpreter();
   unsigned int isNote();
   unsigned int isSegmentHeaders();
   unsigned int isThreadLocalStorage();
   unsigned int isOSSpecific();
   unsigned int isExecutable();
   unsigned int isReadable();
   unsigned int isWriteable();
  private:
   unsigned int index;     //!< Index of this segment
   unsigned int type;      //!< Type of segment (data/code/etc)
   ElfW(Phdr)* segHeader;  //!< Segment header pointer
   char* baseAddress;      //!< Beginning address
   char* highAddress;      //!< End address
   unsigned int alignMask; //!< ~(1 - alignment)
   LoadObject* loadObject; //!< Load object
};

/**
 * Each section in a loaded object is represented by an ElfSection object.
 * Sections are tricky because they are not a run-time entity, only segments
 * are. Some sections are not loaded by the O/S and dynamic linker, 
 * including some important (static) ones, such as the static symbol 
 * table and its string table, and debugging sections. For sections that
 * have not been loaded, we retrieve these sections' contents from the 
 * file directly, and then use them. If a section has been loaded (i.e.,
 * is part of a loaded segment), then we just point to its in-memory
 * image.
 */ 
class ElfSection
{
  public:
   ElfSection(int secIndex, ElfW(Shdr)* secHeader, LoadObject* loadObject);
   ~ElfSection();
   void debugPrintInfo(char* shStrTable=0);
   unsigned int getIndex();
   char* getBaseAddress();
   char* getHighAddress();
   ElfW(Shdr)* getSectionHeader();
   char* getSectionDataPtr();
   unsigned int getAlignmentMask();
   unsigned int getNameIndex();
   char* getName(char* stringTable);
   unsigned int getType();
   unsigned int getFlags();
   unsigned int getVirtualAddress();
   unsigned int getFileOffset();
   unsigned int getSizeInBytes();
   unsigned int getSectionLink();
   unsigned int getEntrySize();
   unsigned int isUndefinedSection();       //!< From sh_index
   unsigned int isReserved();               //!< From sh_index
   unsigned int isNull();                   //!< From sh_type
   unsigned int isProgramBits();            //!< From sh_type
   unsigned int isSymbolTable();            //!< From sh_type
   unsigned int isStringTable();            //!< From sh_type
   unsigned int isRelocationWithAddends();  //!< From sh_type
   unsigned int isRelocationNoAddends();    //!< From sh_type
   unsigned int isSymbolHashTable();        //!< From sh_type
   unsigned int isDynamicInfo();            //!< From sh_type
   unsigned int isNote();                   //!< From sh_type
   unsigned int isProgramSpaceNoBits();     //!< From sh_type
   unsigned int isDynamicSymbolTable();     //!< From sh_type
   unsigned int isInitalization();          //!< From sh_type
   unsigned int isFinalization();           //!< From sh_type
   unsigned int isPreInitialization();      //!< From sh_type
   unsigned int isSectionGroup();           //!< From sh_type
   unsigned int isExtendedSectionIndices(); //!< From sh_type
   unsigned int isNumberOfTypes();          //!< From sh_type
   unsigned int isOSSpecific();             //!< From sh_type
   unsigned int isWritable();               //!< From sh_flags
   unsigned int isLoadedInMemory();         //!< From sh_flags
   unsigned int isExecutable();             //!< From sh_flags
   unsigned int isCanBeMerged();            //!< From sh_flags
   unsigned int isSetOfString();            //!< From sh_flags
   unsigned int infoHasSHTIndex();          //!< From sh_flags
   unsigned int preserveLinkOrder();        //!< From sh_flags
   unsigned int nonConformingOS();          //!< From sh_flags
   unsigned int isGroupMember();            //!< From sh_flags
   unsigned int isThreadLocalStorage();     //!< From sh_flags
  private:
   unsigned int index;     //!< This section's index number
   ElfW(Shdr)* secHeader;  //!< Header for this section
   char* baseAddress;      //!< Beginning address for section
   char* highAddress;      //!< End address for section
   char* sectionDataPtr;   //!< Data pointer (same as base address?)
   unsigned int alignMask; //!< ~(1 - alignment)
   LoadObject* loadObject; //!< Load object of this section

};

/**
 * This class represents the ".dynamic" section, and retrieves all of
 * the dynamic symbol and other information from it.
 */
class DynamicSection
{
  public:
   DynamicSection(char* dynamicSectionAddress, unsigned int size,
                  LoadObject* loadObject); //!< Constructor (does alot!)
   ~DynamicSection(); //!< Destructor
   void debugPrintInfo(); //!< Print info about object
   //! Find a dynamic entry based on type (should return ptr?)
   unsigned long findDynamicEntry(unsigned int EntryType);
   //! Get a symbol's string from its dynamic struct
   char* getSymbolString(ElfW(Sym)* dsym);
   //! Find a dynamic symbol
   ElfSymbol* findDynamicSymbolByName(char *name);
   //! Hash a symbol string
   unsigned long elfHash(const unsigned char *name);
   //! Find a GOT entry by symbol name (works?)
   char *findGOTEntryByName(char *symbolName);
   //! Find a GOTPLT entry by symbol name (works?)
   char *findGOTPLTEntryByName(char *symbolName);
   //! Start an iteration over the dynamic symbols
   ElfSymbol* startDynamicSymbolIter(unsigned int* iter);
   //! Continue a dyn_sym iteration (returns null when done)
   ElfSymbol* nextDynamicSymbolIter(unsigned int* iter);
  private:
   ElfW(Dyn)* dynamicSec;   //!< Pointer to dynamic section
   LoadObject* loadObject;  //!< Load object of this section
   unsigned int numEntries; //!< # of entries in section
   ElfW(Sym)* symbolTable;  //!< Symbol table for dynamic syms
   char* stringTable;       //!< String table for dyanmic syms
   char* hashTable;         //!< Hash table for dynamic syms
   unsigned int stringTableSize;  //!< Size of string table
   unsigned int symbolTableCount; //!< Size of symbol table
   unsigned int symbolEntrySize;  //!< Size of symbol table
   ElfW(Rela)* RelASection; //!< RelA section
   ElfW(Rel)* RelSection;   //!< Rel section (?)
   ElfW(Rel)* PLTRels;      //!< Rels that are in PLT?
   unsigned int RelaSize, RelaEntSize;
   unsigned int RelSize, RelEntSize;
   unsigned int PLTRSize, PLTRType, PLTREntSize;
};

//
// NOT USED (YET)
//
/***

class PLTInfo
{
   char* baseAddress;
   // need to keep track of entries 
   // array of ptrs to ProgramSymbol's?
};

class GOTInfo
{
   char* baseAddress;
   // need to keep track of entries
   // array of ptrs to ProgramSymbol's?
};
***/

#endif

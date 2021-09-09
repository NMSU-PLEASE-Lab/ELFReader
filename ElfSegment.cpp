#include <ElfProgram.h>
#include <stdio.h>

/**
 * Sets up the object to hold info about this segment. If the segment
 * is the dynamic section (PT_DYNAMIC), then call back to the load
 * object and process it as a dynamic section.
 * @param segIndex is the index # for this segment.
 * @param segHeader is the address of the segment header record.
 * @param loadObject is the ELF object that this segment belongs to.
 */
ElfSegment::ElfSegment(int segIndex, ElfW(Phdr) *segHeader, 
                       LoadObject *loadObject)
{
   index = segIndex;
   //printf("segment constructor\n");
   type = (int) segHeader->p_type;
   this->segHeader = segHeader;
   baseAddress = loadObject->getBaseAddress() + (int) segHeader->p_offset; //??
   highAddress = baseAddress + (int) segHeader->p_memsz; // ??
   alignMask = ~(1 - (int) segHeader->p_align);
   this->loadObject = loadObject;
   if (isDynamicInfo()) //segHeader->p_type == PT_DYNAMIC)
   {
      char * dynaddr = (char *) segHeader->p_vaddr;
      printf("**Do Dynamic Section** (%p, %p)\n", dynaddr, baseAddress);
      if (dynaddr < baseAddress)
         dynaddr += (long) loadObject->getBaseAddress();
      loadObject->processDynamicSection(dynaddr, segHeader->p_memsz);
   }
}

ElfSegment::~ElfSegment()
{
}

void ElfSegment::debugPrintInfo()
{
   printf("----SEGMENT ");
   printf(" type (0x%x), offset (0x%x) vaddr (%p) paddr (%p)\n",
          getType(), getFileOffset(), getVirtualAddress(),
          getPhysicalAddress());
   printf("      seg_filsize (%d), memsize (%d) flags (0x%x) align (0x%x)\n",
          (int) segHeader->p_filesz, (int) segHeader->p_memsz,
          (int) segHeader->p_flags, (int) segHeader->p_align);
}

char* ElfSegment::getBaseAddress()
{
   return baseAddress;
}

char* ElfSegment::getHighAddress()
{
   return highAddress;
}

unsigned int ElfSegment::getAlignmentMask()
{
   return alignMask;
}

char* ElfSegment::getVirtualAddress()
{
   return (char*) segHeader->p_vaddr;
}

char* ElfSegment::getPhysicalAddress()
{
   return (char*) segHeader->p_paddr;
}

unsigned int ElfSegment::getFileOffset()
{
   return segHeader->p_offset;
}

unsigned int ElfSegment::getType()
{
   return segHeader->p_type;
}

unsigned int ElfSegment::getFlags()
{
   return segHeader->p_flags;
}

unsigned int ElfSegment::isLoadable()
{
   return (segHeader->p_type == PT_LOAD);
}

unsigned int ElfSegment::isDynamicInfo()
{
   return (segHeader->p_type == PT_DYNAMIC);
}

unsigned int ElfSegment::isInterpreter()
{
   return (segHeader->p_type == PT_INTERP);
}

unsigned int ElfSegment::isNote()
{
   return (segHeader->p_type == PT_NOTE);
}

unsigned int ElfSegment::isSegmentHeaders()
{
   return (segHeader->p_type == PT_PHDR);
}

unsigned int ElfSegment::isThreadLocalStorage()
{
   return (segHeader->p_type == PT_TLS);
}

unsigned int ElfSegment::isOSSpecific()
{
   return (segHeader->p_type & PT_LOOS);
}

unsigned int ElfSegment::isExecutable()
{
   return (segHeader->p_flags & PF_X);
}

unsigned int ElfSegment::isReadable()
{
   return (segHeader->p_flags & PF_R);
}

unsigned int ElfSegment::isWriteable()
{
   return (segHeader->p_flags & PF_W);
}


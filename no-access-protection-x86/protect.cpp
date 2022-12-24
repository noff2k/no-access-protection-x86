#include "protect.h"

#pragma optimize("", off) //Disable it so it doesn't get inlined
#pragma section(".0dev", execute, read, write) //Write so we can erase encryption func
#pragma comment(linker,"/SECTION:.0dev,ERW")
#pragma code_seg(push, ".0dev")

void test_func() {
  printf("HELLO FROM .text func!\n");
}

uint8_t encryption_key;

PIMAGE_SECTION_HEADER get_section_by_name(const char* name) {
  uint32_t modulebase = (uint32_t)GetModuleHandleA(0);
  PIMAGE_NT_HEADERS32 nt = (PIMAGE_NT_HEADERS)(modulebase + ((PIMAGE_DOS_HEADER)modulebase)->e_lfanew);
  PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);
  for (int i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section) {
    if (!_stricmp((char*)section->Name, name))
      return section;
  }
  return nullptr;
}

void encrypt_section(PIMAGE_SECTION_HEADER section) {
  uint32_t modulebase = (uint32_t)GetModuleHandleA(0);
  int valid_page_count = section->Misc.VirtualSize / 0x1000; //If section is smaller than page size skip it
  for (int page_idx = 0; page_idx < valid_page_count; page_idx++) {
    uintptr_t address = modulebase + section->VirtualAddress + page_idx * 0x1000;
    printf("Encrypted: %p\n", address);
    DWORD old;
    VirtualProtect((LPVOID)address, 0x1000, PAGE_EXECUTE_READWRITE, &old);
    for (int off = 0; off < 0x1000; off += 0x1) {
      *(BYTE*)(address + off) = _rotr8((*(BYTE*)(address + off) + 0x10) ^ encryption_key, 69);
    }
    VirtualProtect((LPVOID)address, 0x1000, PAGE_NOACCESS, &old);
  }
}

bool rip_in_legit_module(uint32_t rip) {
  PPEB peb = (PPEB)__readfsdword(0x30);
  PPEB_LDR_DATA ldr = peb->Ldr;
  PLDR_DATA_TABLE_ENTRY module = NULL;
  PLIST_ENTRY list = ldr->InMemoryOrderModuleList.Flink;
  while (list != NULL && list != &ldr->InMemoryOrderModuleList) {
    module = CONTAINING_RECORD(list, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((uint32_t)module->DllBase + ((PIMAGE_DOS_HEADER)module->DllBase)->e_lfanew);
    if ((rip >= (uint32_t)module->DllBase) && (rip <= (uint32_t)module->DllBase + nt->OptionalHeader.SizeOfImage)) {
      return true;
    }
    list = list->Flink;
  }
  return false;
}

LONG WINAPI handler(struct _EXCEPTION_POINTERS* ExceptionInfo) {
  if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
    DWORD old;
    //ExceptionInformation[1] holds the invalid referenced memory address
    uint32_t page_start = (uint32_t)ExceptionInfo->ExceptionRecord->ExceptionInformation[1];
    page_start = page_start - (page_start % 0x1000);
    //Before we decrypt our page we want to verify the RIP
    if (rip_in_legit_module(ExceptionInfo->ContextRecord->Eip)) {
      VirtualProtect((LPVOID)page_start, 0x1000, PAGE_EXECUTE_READWRITE, &old);
      for (int off = 0; off < 0x1000; off += 0x1) {
        *(BYTE*)(page_start + off) = _rotr8((*(BYTE*)(page_start + off) + 0x10) ^ encryption_key, 69);
      }
      VirtualProtect((LPVOID)page_start, 0x1000, PAGE_NOACCESS, &old);
    }
  }
  return EXCEPTION_CONTINUE_EXECUTION;
}

void protect::initialize() {
  srand(time(NULL));
  encryption_key = rand() % 255 + 1; //Generate a small decryption key
  AddVectoredExceptionHandler(1, handler); //Handler will handle decryption and access rights
  encrypt_section(get_section_by_name(".text"));
  //We won't use memset since this will unnecessarily decrypt a page
  for (int i = 0; i < (uint32_t)rip_in_legit_module - (uint32_t)encrypt_section; i += 0x1) {
    *(uint8_t*)((uint32_t)encrypt_section + i) = 0;
  }
  //Tests 1: Dereference an address that has NO_ACCESS
  printf("%x\n", *(BYTE*)(test_func));
  //Tests 2: Call a func that in a NO_ACCESS region
  test_func();
  system("pause");
}

#pragma code_seg(pop, ".0dev")
#pragma optimize("", on)
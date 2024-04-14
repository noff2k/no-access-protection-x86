#include "protect.h"

#pragma optimize("", off)
#pragma section(".0dev", execute, read, write)
#pragma comment(linker,"/SECTION:.0dev,ERW")
#pragma code_seg(push, ".0dev")

std::uint8_t encryption_key;

PIMAGE_SECTION_HEADER get_section_by_name( const char* name )
{
	std::uint64_t modulebase = ( std::uint64_t )GetModuleHandleA( NULL );

	PIMAGE_NT_HEADERS32 nt = ( PIMAGE_NT_HEADERS )( modulebase + ( ( PIMAGE_DOS_HEADER )modulebase )->e_lfanew );
	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION( nt );

	for ( int i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section )
	{
		if ( !_stricmp( ( char* )section->Name, name ) )
			return section;
	}
	return nullptr;
}

void encrypt_section( PIMAGE_SECTION_HEADER section )
{
	std::uint64_t modulebase = ( std::uint64_t )GetModuleHandleA( 0 );
	int valid_page_count = section->Misc.VirtualSize / 0x1000;

	for ( int page_idx = 0; page_idx < valid_page_count; page_idx++ )
	{
		std::uintptr_t address = modulebase + section->VirtualAddress + page_idx * 0x1000;

		DWORD old{ };
		VirtualProtect( ( LPVOID )address, 0x1000, PAGE_EXECUTE_READWRITE, &old );
		
		for ( int off = 0; off < 0x1000; off += 0x1 )
		{
			*( BYTE* )( address + off ) = _rotr8( ( *( BYTE* )( address + off ) + 0x10 ) ^ encryption_key, 69 );
		}
		
		VirtualProtect( ( LPVOID )address, 0x1000, PAGE_NOACCESS, &old );
	}
}

bool eip_in_legit_module( std::uint64_t eip )
{
	PPEB peb = ( PPEB )__readfsdword( 0x30 );
	PPEB_LDR_DATA ldr = peb->Ldr;
	PLDR_DATA_TABLE_ENTRY module = NULL;
	PLIST_ENTRY list = ldr->InMemoryOrderModuleList.Flink;

	while ( list != NULL && list != &ldr->InMemoryOrderModuleList )
	{
		module = CONTAINING_RECORD( list, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks );
		PIMAGE_NT_HEADERS nt = ( PIMAGE_NT_HEADERS )( ( std::uint64_t )module->DllBase + ( ( PIMAGE_DOS_HEADER )module->DllBase )->e_lfanew );
		
		if ( ( eip >= ( std::uint64_t )module->DllBase ) && ( eip <= ( std::uint64_t )module->DllBase + nt->OptionalHeader.SizeOfImage ) )
			return true;
		
		list = list->Flink;
	}
	return false;
}

LONG WINAPI handler( struct _EXCEPTION_POINTERS* ExceptionInfo )
{
	if ( ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION )
	{
		DWORD old{ };
		
		std::uint64_t page_start = ( std::uint64_t )ExceptionInfo->ExceptionRecord->ExceptionInformation[ 1 ];
		page_start = page_start - ( page_start % 0x1000 );

		if ( !eip_in_legit_module( ExceptionInfo->ContextRecord->Eip ) )
			return EXCEPTION_CONTINUE_SEARCH;
		
		VirtualProtect( ( LPVOID )page_start, 0x1000, PAGE_READWRITE, &old );

		for ( int off = 0; off < 0x1000; off += 0x1 )
		{
			*( BYTE* )( page_start + off ) = ( _rotl8( *( BYTE* )( page_start + off ), 69 ) ^ encryption_key ) - 0x10;
		}

		VirtualProtect( ( LPVOID )page_start, 0x1000, PAGE_EXECUTE_READ, &old );
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	return EXCEPTION_CONTINUE_SEARCH;
}

void protect::initialize( )
{
	srand( time( NULL ) );
	encryption_key = rand( ) % 255 + 1;
	AddVectoredExceptionHandler( 1, handler );
	encrypt_section( get_section_by_name( ".text" ) );

	for ( int i = 0; i < ( std::uint64_t )eip_in_legit_module - ( std::uint64_t )encrypt_section; i += 0x1 )
	{
		*( uint8_t* )( ( std::uint64_t )encrypt_section + i ) = 0;
	}
	
	//MEMORY_BASIC_INFORMATION mbi{ };
	//VirtualQuery( ( void* )test_func, &mbi, sizeof( MEMORY_BASIC_INFORMATION ) );
	//std::printf( "0x%p\n", mbi.Protect );
}

#pragma code_seg(pop, ".0dev")
#pragma optimize("", on)

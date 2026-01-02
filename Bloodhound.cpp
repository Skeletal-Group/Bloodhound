#include "Bloodhound.h"
#include "VPGATHER.h"

#define BH_RET_EXEC_MAGIC     0xBBBB0000BEEFC0DE
#define BH_RET_NOT_EXECUTABLE 0xBADC0DE

typedef UINT64( *PBH_EXECUTABLE_RET )( 
	_In_ UINT64 MagicNumber
	);

typedef enum _BH_FEATURES : UINT32
{
#define BH_VPGATHER_SUPPORT_SHIFT 0
	Vpgather = ( 1 << 0 ),
}BH_FEATURES, *PBH_FEATURES;

//
// A bitmap of supported EPT detection features on the running system
//
UINT32 BhFeatureBitmap = 0;

LONG
WINAPI
BhExceptionHandler( 
	_In_ LPEXCEPTION_POINTERS ExceptionPointers 
	)
{
	CONST PCONTEXT          ContextRecord   = ExceptionPointers->ContextRecord;
	CONST PEXCEPTION_RECORD ExceptionRecord = ExceptionPointers->ExceptionRecord;

	if ( ExceptionRecord->ExceptionCode == STATUS_ACCESS_VIOLATION )
	{
		if ( ContextRecord->Rcx != BH_RET_EXEC_MAGIC )
		{
			return EXCEPTION_CONTINUE_SEARCH;
		}

		//
		// The access violation occured as a result of attempting
		// to execute non executable memory.
		//
		ContextRecord->Rip  = *( UINT64* )ContextRecord->Rsp;
		ContextRecord->Rsp += 8;

		//
		// Indicate to the caller the RET instruction is not executable.
		//
		ContextRecord->Rax = BH_RET_NOT_EXECUTABLE;

		return EXCEPTION_CONTINUE_EXECUTION;
	}
}

BOOLEAN
BhInitialize( 
	VOID 
	)
{
	BhFeatureBitmap |= Vpgather & ( VpgInitialize( ) << BH_VPGATHER_SUPPORT_SHIFT );

	return AddVectoredExceptionHandler( TRUE, BhExceptionHandler ) != NULL;
}

//
// Locate a RET instruction within the page that belongs to a specified
// virtual address.
//
LPVOID
BhLocateRetInPage( 
	_In_ LPVOID AddressInPage 
	)
{
	UINT8* Current = ( UINT8* )( ( UINT64 )AddressInPage & ~( 0xFFFull ) );

	while ( *Current != 0xC3 )
	{
		Current++;

		if ( ( ( UINT64 )Current & 0xFFF ) == 0xFFF )
		{
			return NULL;
		}
	}

	return Current;
}

//
// Locate a RET instruction within the page that belongs to a specified
// virtual address, and execute it to possibly incur an EPT violation.
//
BOOLEAN
BhExecuteInPage( 
	_In_ LPVOID AddressInPage 
	)
{
	//
	// Locate a RET instruction within the page
	//
	PBH_EXECUTABLE_RET ExecutableRet = ( PBH_EXECUTABLE_RET )BhLocateRetInPage( AddressInPage );

	if ( ExecutableRet == NULL )
	{
		return FALSE;
	}

	//
	// Return TRUE if the RET was executed successfully
	//
	return ExecutableRet( BH_RET_EXEC_MAGIC ) != BH_RET_NOT_EXECUTABLE;
}

//
// Perform a load-from operation within a page to possibly incur
// an EPT violation.
//
VOID
BhLoadFromPage( 
	_In_ LPVOID AddressInPage 
	)
{
	//
	// Perform a CLFLUSH as a light way of performing an operation
	// equivalent to a load operation.
	//
	_mm_clflush( AddressInPage );
}

BOOLEAN
BhIsEptHookPresent( 
	_In_ LPVOID Address 
	)
{
	if ( BhFeatureBitmap & Vpgather )
	{
		UINT32 Confidence = 0;

		for ( UINT32 i = 0; i < 100; i++ )
		{
			//
			// Execute something within the target page to incur possible
			// EPT violations, resulting in a swap to a read-only page.
			//
			BOOLEAN Executed = BhExecuteInPage( Address );

			if ( Executed == FALSE )
			{
				//
				// If the current page is presently not executable,
				// we will not use VPGATHER functionality.
				//
				continue;
			}

			_mm_lfence( );
			_mm_mfence( );

			BOOLEAN Accessible = VpgIsAddressAccessible( Address );

			if ( Accessible == FALSE )
			{
				//
				// Increase our confidence if the target page is not accessible
				//
				Confidence++;
			}
		}

		if ( Confidence >= 90 )
		{
			//
			// Assume EPT hooks have been applied to this page if our confidence
			// is high enough.
			//
			return TRUE;
		}
	}
}
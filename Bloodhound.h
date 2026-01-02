#ifndef __BLOODHOUND_H__
#define __BLOODHOUND_H__

#include <Windows.h>
#include <intrin.h>

/**
 * @brief Initialize Bloodhound EPT hooking detection functionality
 * 
 * @return TRUE if everything was initialized successfully
 * @return FALSE if an error occured during initialization
 */
BOOLEAN
BhInitialize( 
	VOID 
	);

/**
 * @brief Use various novel EPT hook detection mechanisms to determine
 *        whether a given page is being EPT hooked.
 * 
 * @param [in] Address: The address to test
 * 
 * @return TRUE if EPT is manipulating the given page
 * @return FALSE if EPT is not manipulating the given page
 */
BOOLEAN
BhIsEptHookPresent( 
	_In_ LPVOID Address 
	);

#endif
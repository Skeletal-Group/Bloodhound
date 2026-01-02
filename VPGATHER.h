//
// File:
//     VPGATHER.h
// 
// Abstract:
//     An interesting way to determine the accessibility or validity of virtual addresses
//     before they are truly accessed. This allows for a much stealther way to determine
//     if an address is accessible, as it does not affect the state or page table entries
//     pointed to by the virtual address. 
// 
//     This proof of concept was made strictly for educational purposes, I am
//     in no way responsible for any software that might implement this functionality
//     for any other purpose.  
//
#ifndef __VPGATHER_H__
#define __VPGATHER_H__

#include <Windows.h>
#include <intrin.h>

/**
 * @brief Initialize functionality required to leverage VPGATHER's behavior
 * 
 * @return TRUE if initialized successfully
 * @return FALSE if the running system does not support VPGATHER(AVX2)
 */
BOOLEAN
VpgInitialize( 
	VOID 
	);

/**
 * @brief Use VPGATHER to determine whether an address will incur a fault
 *        before it is actually accessed.
 * 
 * @param [in] Address: The address to test
 * 
 * @return TRUE if the specified address will not incur a fault when accessed.
 * @return FALSE if the specified address will incur a fault when accessed.
 */
BOOLEAN
VpgIsAddressAccessible(
	_In_ LPVOID Address
	);

#endif
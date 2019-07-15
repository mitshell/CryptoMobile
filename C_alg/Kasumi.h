/* -----------------------------------------------------------------------
 * code extracted from 3GPP TS 35.202, annex 2, for core functions
 * https://portal.3gpp.org/desktopmodules/Specifications/SpecificationDetails.aspx?specificationId=2387
 * code extracted from 3GPP TS 35.201, annex 2, for F8 and F9 functions
 * https://portal.3gpp.org/desktopmodules/Specifications/SpecificationDetails.aspx?specificationId=2386
 *-----------------------------------------------------------------------*/

/* this is the trick to make the code cross-platform
 * at least, Win32 / Linux */

#if defined(_WIN32) || defined(__WIN32__)
#	include <windows.h>
#	define EXPORTIT __declspec(dllexport)
#else
#	define EXPORTIT
#endif

/*---------------------------------------------------------
 *					Kasumi.h
 *---------------------------------------------------------*/

#include <stdio.h>

typedef unsigned  char   u8;
typedef unsigned short  u16;
/* original reference is using long, which is 64 bits on 64 bits system
   I changed to int to make it work on x86 32 / 64 bits system
typedef unsigned  long  u32;
*/
typedef unsigned   int  u32;


/*------- unions: used to remove "endian" issues ------------------------*/

typedef union {
	u32 b32;
	u16 b16[2];
	u8  b8[4];
} REGISTER32; /* is redefining DWORD */

typedef union {
	u16 b16;
	u8  b8[2];
} REGISTER16; /* is redefining WORD */

/*----- a 64-bit structure to help with endian issues -----*/

typedef union {
	u32 b32[2];
	u16 b16[4];
	u8  b8[8];
} REGISTER64;

/*------------- prototypes --------------------------------
 * take care: length (in f8 and f9) is always in bits
 *---------------------------------------------------------*/

/* initialize the 128 bits key into the cipher */
EXPORTIT void KeySchedule( u8 *key );

/* cipher a block of 64 bits */
EXPORTIT void Kasumi( u8 *data );

/* cipher a whole message in 3GPP -counter- mode */
EXPORTIT void f8( u8 *key, u32 count, u32 bearer, u32 dir, \
                  u8 *data, int length );

/* compute a 3GPP MAC on a message */
EXPORTIT u8 * f9( u8 *key, u32 count, u32 fresh, u32 dir, \
                  u8 *data, int length );

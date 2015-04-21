/* this is the trick to make the code cross-platform
*  at least, Win32 / Linux */

#if defined(_WIN32) || defined(__WIN32__)
#	include <windows.h>
#	define EXPORTIT __declspec(dllexport)
#else
#	define EXPORTIT
#endif

#include <stdlib.h>

/*------------------------------------------------------------------------
 * ZUC.h
 * Code taken from the ZUC specification
 * available on the GSMA website
 *------------------------------------------------------------------------*/

/* type definition from */
typedef unsigned char u8;
typedef unsigned int u32;

/*
 * ZUC keystream generator
 * k: secret key (input, 16 bytes)
 * iv: initialization vector (input, 16 bytes)
 * Keystream: produced keystream (output, variable length)
 * KeystreamLen: length in bits requested for the keystream (input)
*/
EXPORTIT void Initialization(u8* k, u8* iv);
EXPORTIT void GenerateKeystream(u32* pKeystream, u32 KeystreamLen);

/*
 * CK: ciphering key
 * COUNT: frame counter
 * BEARER: radio bearer
 * DIRECTION
 * LENGTH: length of the frame in bits
 * M: original message (input)
 * C: processed message (output)
*/
EXPORTIT void EEA3(u8* CK, u32 COUNT, u32 BEARER, u32 DIRECTION, 
		           u32 LENGTH, u32* M, u32* C);

/*
 * IK: integrity key
 * COUNT: frame counter
 * BEARER: radio bearer
 * DIRECTION
 * LENGTH: length of the frame in bits
 * M: original message (input)
 * C: processed message (output)
*/
EXPORTIT void EIA3(u8* IK, u32 COUNT, u32 BEARER, u32 DIRECTION,
		           u32 LENGTH, u32* M, u32* MAC);

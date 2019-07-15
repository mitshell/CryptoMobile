/* -----------------------------------------------------------------------
 * code extracted from ETSI / SAGE specification of the 3GPP Confidentiality and Integrity Algorithms 128-EEA3 & 128-EIA3.
 * Document 2: ZUC Specification. Version 1.6 from 28th June 2011, appendix A.
 * https://www.gsma.com/security/wp-content/uploads/2019/05/eea3eia3zucv16.pdf
 * code extracted from ETSI / SAGE specification of the 3GPP Confidentiality and Integrity Algorithms 128-EEA3 & 128-EIA3.
 * Document 1: 128-EEA3 and 128-EIA3 Specification. Version 1.7 from the 30th December 2011, annex 1.
 * https://www.gsma.com/security/wp-content/uploads/2019/05/EEA3_EIA3_specification_v1_8.pdf
 * (warning: only link to version 1.9 exists)
 *
 * All updated ZUC specifications maybe found on the GSMA website:
 * https://www.gsma.com/security/security-algorithms/
 *-----------------------------------------------------------------------*/

/* this is the trick to make the code cross-platform
 * at least, Win32 / Linux */

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
 * KeystreamLen: length in 32-bit words requested for the keystream (input)
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
 * MAC: processed message MAC (output)
 */
EXPORTIT void EIA3(u8* IK, u32 COUNT, u32 BEARER, u32 DIRECTION,
		           u32 LENGTH, u32* M, u32* MAC);

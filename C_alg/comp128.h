/* this is the trick to make the code cross-platform
 * at least, Win32 / Linux */

#if defined(_WIN32) || defined(__WIN32__)
#	include <windows.h>
#   include <string.h>
#	define EXPORTIT __declspec(dllexport)
    typedef unsigned char uint8_t;

#else
#	define EXPORTIT
#   include <string.h>
#   include <stdint.h>
#   include <stdbool.h>
#endif

#ifndef _COMP128_H
#define _COMP128_H

EXPORTIT void comp128v1(uint8_t *sres, uint8_t *kc, const uint8_t *ki, const uint8_t *rand);
EXPORTIT void comp128v23(uint8_t *sres, uint8_t *kc, uint8_t const *ki, uint8_t const *rand, bool v2);

#endif

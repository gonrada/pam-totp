/**
 * @file
 * @author Sean Easton <gonrada@gmail.com>
 *
 * @section COURSE
 *
 * Course Information: CIS5370 - Fall '12 <br/>
 * Due Date: December 14, 2012 <br/>
 *
 * @section LICENSE
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details at
 * http://www.gnu.org/copyleft/gpl.html
 *
 * @section DESCRIPTION
 *
 * A C/C++ implementation of a Time-base One-Time Password generator using openssl
 */


#include "generator.h"

unsigned int generate_totp()
{
	FILE * keyFile;
	uint32_t bin_code, totp;
	uint64_t data;
	unsigned char key[64], *result;

	/* read in shared key
	 *
	 * data = (uint64_t)floor(time(NULL)/PERIOD)
	 *
	 * result = hmac(key, data)
	 *
	 * DBC = dynamic_truncation()
	 *
	 * TOTP = DBC mod (10 ^ DIGITS)
	 */


	keyFile = fopen(KEY_FILE, "r");
	if(!keyFile)
	{
		printf("Error opening [%s] for r",KEY_FILE);
		return false;
	}

	fread( key, 64, 1, keyFile);

	fclose(keyFile);

	data = (uint64_t) floor( time(NULL)/PERIOD);

	result = hmac_sha512( key, RESULT_LEN, (unsigned char *) &data, sizeof(uint64_t) /* 8 */);
	bin_code = dynamic_truncation( result, RESULT_LEN);

	totp = bin_code % (int) floor(pow(10.0, DIGITS));

	return (unsigned int) totp;
}

/**
 * Dynamic Truncation Function
 * 
 * 
 */
uint32_t dynamic_truncation(const unsigned char *input, int length)
{
	uint32_t bin_code;
	unsigned char offset;

	offset = input[length - 1] & 0x34; /* Assume 64 bytes; thus we want the low 6 bits */
	offset = offset % 59; /* Again, assume 64 of input */

	/* RFC4226; Page 7-8;
	 */    
	bin_code = (input[offset] & 0x7f) << 24
		| (input[offset+1] & 0xff) << 16
		| (input[offset+2] & 0xff) << 8
		| (input[offset+3] & 0xff) ;

	return bin_code;
}

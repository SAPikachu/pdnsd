/* make_hashconvtable.c

   Copyright (C) 2004 Paul Rombouts

   Based on the code originally in hash.c written by Thomas Moestl.
   This file is part of the pdnsd package.

   Make the conversion table for the dns hashes (character-to-number mapping).
   Note: this used to be done at run-time, but it is now done at build-time.
*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

static const unsigned char posval[]="ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_";

static unsigned char values[256];

static void mk_hash_ctable ()
{
	unsigned int i, poslen=strlen(posval);

	memset(values,poslen,sizeof(values));
	for (i=0;i<poslen;i++) {
		values[tolower(posval[i])]=i;
		values[toupper(posval[i])]=i;
	}
}

int main(int argc, char *argv[])
{
	int i;

	mk_hash_ctable();

	for(i=0;i<sizeof(values);++i) {
		if(printf(i==0?"%3d":i%16==0?",\n%3d":",%3d",values[i])<0)
			return 1;
	}

	if(printf("\n")<0)
		return 1;

	return 0;
}

/*
*  sha1.h
*
*	Copyright (C) 1998
*	Paul E. Jones <paulej@arid.us>
*	All Rights Reserved
*
*****************************************************************************
*	$Id: sha1.h,v 1.2 2004/03/27 18:00:33 paulej Exp $
*****************************************************************************
*
*  Description:
*      This class implements the Secure Hashing Standard as defined
*      in FIPS PUB 180-1 published April 17, 1995.
*
*      Many of the variable names in the SHA1Context, especially the
*      single character names, were used because those were the names
*      used in the publication.
*
*      Please read the file sha1.c for more information.
*
*/

#ifndef _SHA1_H_
#define _SHA1_H_

/* 
*  This structure will hold context information for the hashing
*  operation
*/
typedef struct SHA1Context
{
	unsigned Message_Digest[5]; /* Message Digest (output)          */

	unsigned Length_Low;        /* Message length in bits           */
	unsigned Length_High;       /* Message length in bits           */

	unsigned char Message_Block[64]; /* 512-bit message blocks      */
	int Message_Block_Index;    /* Index into message block array   */

	int Computed;               /* Is the digest computed?          */
	int Corrupted;              /* Is the message digest corruped?  */
} SHA1Context;

#define SHA_DIGEST_LENGTH 20

/*
*  Function Prototypes
*/
void SHA1Reset(SHA1Context *);
int SHA1Result(SHA1Context *);
void SHA1Input( SHA1Context *,
	const unsigned char *,
	unsigned);

#endif
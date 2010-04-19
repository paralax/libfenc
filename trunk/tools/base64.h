/*
 *  base64.h
 *  mg-cpabe
 *
 *  Created by Joseph Ayo Akinyele on 4/16/10.
 *  Copyright 2010 __MyCompanyName__. All rights reserved.
 *
 */

#ifndef __BASE64_H__
#define __BASE_64_H__

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define TRUE 1
#define FALSE 0

void *NewBase64Decode(const char *inputBuffer, size_t length, size_t *outputLength);

char *NewBase64Encode(const void *inputBuffer, size_t length, int separateLines, size_t *outputLength);

#endif
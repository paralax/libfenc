#ifndef __COMMON_H__
#define __COMMON_H__

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <fenc/libfenc.h>
#include <fenc/libfenc_group_params.h>
#include <fenc/libfenc_ABE_common.h>			
#include <fenc/libfenc_LSSS.h>
#include <fenc/libfenc_WatersCP.h>
#include <fenc/policy_lang.h>
#include <pbc/pbc_test.h> 
#include "base64.h"

#define KEYSIZE_MAX 4096
#define SIZE 2048
#define SIZE_MAX 8192
#define MAX_ATTRIBUTES 100
#define SESSION_KEY_LEN 16

#define MAGIC "ABE|"
#define AES_TOKEN "AES"
#define AES_TOKEN_END "AES_END"
#define ABE_TOKEN "ABE_CP"
#define ABE_TOKEN_END "ABE_CP_END"

static char *public_params_file = "public.param";
static char *secret_params_file = "master_secret.param";

void report_error(char* action, FENC_ERROR result);
ssize_t read_file(FILE *f, char** out);
void print_help(void);
void print_buffer_as_hex(uint8* data, size_t len);

#endif

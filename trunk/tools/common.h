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
#include <fenc/libfenc_LSW.h>
#include <fenc/policy_lang.h>
#include <pbc/pbc_test.h> 
#include <math.h>
#include "base64.h"

#define SCHEME_LSW "KP"
#define SCHEME_WCP "CP"
#define SCHEME_WSCP "SCP"
#define LSW 0
#define WCP 1
#define SWCP 2

#define KEYSIZE_MAX 20480
#define SIZE 2048
#define SIZE_MAX KEYSIZE_MAX
#define MAX_ATTRIBUTES 100
#define SESSION_KEY_LEN 16

#define PARAM "d224.param"
#define MAGIC "ABE|"
#define AES_TOKEN "AES"
#define AES_TOKEN_END "AES_END"
#define ABE_TOKEN "ABE_CP"
#define ABE_TOKEN_END "ABE_CP_END"

#define PUBLIC_FILE "public.param"
#define SECRET_FILE "secret.param"

// static char *public_params_file = "public.param";
// static char *secret_params_file = "master_secret.param";

void report_error(char* action, FENC_ERROR result);
ssize_t read_file(FILE *f, char** out);
void print_help(void);
void print_buffer_as_hex(uint8* data, size_t len);
//int construct_attribute_list(char *input, char** attributes, size_t *attributes_len);

#endif

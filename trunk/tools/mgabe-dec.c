#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <getopt.h>
#include "libfenc.h"
#include "libfenc_group_params.h"
#include "libfenc_ABE_common.h"			
#include "libfenc_LSSS.h"
#include "libfenc_WatersCP.h"
#include "policy_lang.h"
#include <pbc/pbc_test.h>
#include "base64.h"
#include "openssl/aes.h"
#include "openssl/sha.h"
#include "openssl/evp.h"
#include "openssl/err.h"
#include "openssl/rand.h"

/* test encryption of "hello world" under policy of "ONE or TWO" */
#define AES_TOKEN "AES"
#define ABE_TOKEN "ABE_CP"

#define MAX_ATTRIBUTES 100
#define SIZE 2048
#define SIZE_MAX 4096
#define SESSION_KEY_LEN 16
char *public_params_file = "public.param";
char *secret_params_file = "master_secret.param";
void report_error(char* action, FENC_ERROR result);
void print_help(void);
Bool cpabe_decrypt(char *inputfile, char *keyfile);
void print_buffer_as_hex(uint8* data, size_t len);
ssize_t read_file(FILE *f, char** out);
void tokenize_inputfile(char* in, char** abe, char** aes);

/* Description: abe-dec takes two inputs: an encrypted file and a private key and
 produces a file w/ the contents of the plaintext.
 */
int main (int argc, char *argv[]) {
	int fflag = FALSE, kflag = FALSE;
	char *file = "enc_data.txt", *key = "user_priv.key";
	int c;
	
	opterr = 0;

	while ((c = getopt (argc, argv, "f:k:")) != -1) {
		
		switch (c)
		{
			case 'f': // file that holds encrypted data
				fflag = TRUE;
				file = optarg;
				printf("encrypted file = '%s'\n", key);
				break;
			case 'k': // input of private key 
				kflag = TRUE;
				key = optarg;
				printf("private-key file = '%s'\n", file);
				break;
			case 'h': // print usage 
				print_help();
				exit(0);
				break;
			case '?':
				if (optopt == 'f' || optopt == 'k')
					fprintf (stderr, "Option -%c requires an argument.\n", optopt);
				else if (isprint (optopt))
					fprintf (stderr, "Unknown option `-%c'.\n", optopt);
				else
					fprintf (stderr,
							 "Unknown option character `\\x%x'.\n", optopt);
				return 1;
			default:
				print_help();
				abort ();
		}
	}

	if(fflag == FALSE) {
		fprintf(stderr, "No file to decrypt!\n");
		print_help();
		exit(1);
	}
	
	if(kflag == FALSE) {
		fprintf(stderr, "Decrypt without a key? c'mon!\n");
		print_help();
		exit(1);
	}
	
	
	printf("Ok. Decrypting data.\n");
	cpabe_decrypt(file, key);
	printf("Complete!\n");
	return 0;
}

void print_help(void)
{
	printf("Usage: ./abe-dec -k [ private-key-file ] -f [ file-to-decrypt ] \n\n");
}

void report_error(char* action, FENC_ERROR result)
{
	printf("%s...\n\t%s (%d)\n", action, libfenc_error_to_string(result), result);
}

void print_buffer_as_hex(uint8* data, size_t len)
{
	size_t i;
	
	for (i = 0; i < len; i++) {
		printf("%02x ", data[i]);
	}
	printf("\n");
}

ssize_t read_file(FILE *f, char** out) {
	
	if(f != NULL) {
		/* See how big the file is */
		fseek(f, 0L, SEEK_END);
		ssize_t out_len = ftell(f);
		printf("out_len: %zd\n", out_len);
		if(out_len <= SIZE_MAX) {
			/* allocate that amount of memory only */
			if((*out = (char *) malloc(out_len)) != NULL) {
				fseek(f, 0L, SEEK_SET);
				fread(*out, sizeof(char), out_len, f);
				return out_len;
			}
		}
	}
	return 0;
}

/* This function tokenizes the input file with the 
expected format: "ABE_TOKEN : base-64 : ABE_TOKEN_END : 
  			      AES_TOKEN : base-64 : AES_TOKEN_END"
 */
void tokenize_inputfile(char* in, char** abe, char** aes) 
{	
	ssize_t abe_len, aes_len;
	char delim[] = ":";
	char *token = strtok(in, delim);
	while (token != NULL) {
		if(strcmp(token, ABE_TOKEN) == 0) {
			token = strtok(NULL, delim);
			abe_len = strlen(token);
			if((*abe = (char *) malloc(abe_len+1)) != NULL) {
				strncpy(*abe, token, abe_len);
			}
		}
		else if(strcmp(token, AES_TOKEN) == 0) {
			token = strtok(NULL, delim);
			aes_len = strlen(token);
			if((*aes = (char *) malloc(aes_len+1)) != NULL) {
				strncpy(*aes, token, aes_len);
			}
		}
		token = strtok(NULL, delim);
	}
}

Bool cpabe_decrypt(char *inputfile, char *keyfile)
{
	FENC_ERROR result;
	fenc_context context;
	fenc_group_params group_params;
	fenc_global_params global_params;
	fenc_ciphertext ciphertext;
	fenc_function_input func_list_input;
	fenc_plaintext aes_session_key;
	pairing_t pairing;
	fenc_key secret_key;
	
	FILE *fp;
	char c;
	int pub_len = 0, sec_len = 0;
	size_t serialized_len = 0;
	uint8 public_params_buf[SIZE];
	uint8 secret_params_buf[SIZE];
	char session_key[SESSION_KEY_LEN];
	char output_str[200];
	int output_str_len = 200;
	/* Clear data structures. */
	memset(&context, 0, sizeof(fenc_context));
	memset(&group_params, 0, sizeof(fenc_group_params));
	memset(&global_params, 0, sizeof(fenc_global_params));	
	memset(&public_params_buf, 0, SIZE);
	memset(&ciphertext, 0, sizeof(fenc_ciphertext));
	memset(&aes_session_key, 0, sizeof(fenc_plaintext));
	memset(public_params_buf, 0, SIZE);
	memset(output_str, 0, output_str_len);
	memset(&secret_key, 0, sizeof(fenc_key));
	// all this memory must be free'd 
	char *input_buf = NULL,*keyfile_buf = NULL;
	char *aes_blob64 = NULL, *abe_blob64 = NULL;
	ssize_t input_len, key_len;
	
	/* Load user's input file */
	fp = fopen(inputfile, "r");
	if(fp != NULL) {
		if((input_len = read_file(fp, &input_buf)) > 0) {
			// printf("Input file: %s\n", input_buf);
			tokenize_inputfile(input_buf, &abe_blob64, &aes_blob64);
#ifdef DEBUG 			
			printf("abe_blob64 = '%s'\n", abe_blob64);
			printf("aes_blob64 = '%s'\n", aes_blob64);
#endif
			free(input_buf);
		}			
	}
	else {
		fprintf(stderr, "Could not load input file: %s\n", inputfile);
		return FALSE;
	}
	fclose(fp);
	
	/* make sure the abe and aes ptrs are set */
	if(aes_blob64 == NULL || abe_blob64 == NULL) {
		fprintf(stderr, "Input file either not well-formed or not encrypted.\n");
		return FALSE;
	}
	
	/* Initialize the library. */
	result = libfenc_init();
	/* Create a Sahai-Waters context. */
	result = libfenc_create_context(&context, FENC_SCHEME_WATERSCP);	
	/* Load group parameters from a file. */
	fp = fopen("d224.param", "r");
	if (fp != NULL) {
		libfenc_load_group_params_from_file(&group_params, fp);
		libfenc_get_pbc_pairing(&group_params, pairing);
	} else {
		fprintf(stderr, "File does not exist: global parmeterers");
		return FALSE;
	}
	fclose(fp);
	
	/* Set up the global parameters. */
	result = context.generate_global_params(&global_params, &group_params);
	report_error("Loading global parameters", result);
	
	result = libfenc_gen_params(&context, &global_params);
	// report_error("Generating scheme parameters and secret key", result);
	
	/* read file */
	fp = fopen(public_params_file, "r");
	if(fp != NULL) {
		while (TRUE) {
			c = fgetc(fp);
			if(c != EOF) {
				public_params_buf[pub_len] = c;
				pub_len++;
			}
			else {
				break;
			}
		}
	}
	else {
		fprintf(stderr, "File does not exist: %s\n", public_params_file);
		return FALSE;
	}
	fclose(fp);
	// printf("public params input = '%s'\n", public_params_buf);
	
	/* base-64 decode public parameters */
	uint8 *bin_public_buf = NewBase64Decode((const char *) public_params_buf, pub_len, &serialized_len);
	// printf("public params binary = '%s'\n", bin_public_buf);
	
	/* Import the parameters from binary buffer: */
	result = libfenc_import_public_params(&context, bin_public_buf, serialized_len);
	report_error("Importing public parameters", result);
	
	/* read file
	fp = fopen(secret_params_file, "r");
	if(fp != NULL) {
		while (TRUE) {
			c = fgetc(fp);
			if(c != EOF) {
				secret_params_buf[sec_len] = c;
				sec_len++;
			}
			else {
				break;
			}
		}
	}
	else {
		fprintf(stderr, "File does not exist: %s\n", secret_params_file);
		return FALSE;
	}	
	fclose(fp);
	
	uint8 *bin_secret_buf = NewBase64Decode((const char *)secret_params_buf, sec_len, &serialized_len);
	result = libfenc_import_secret_params(&context, bin_secret_buf, serialized_len, NULL, 0);
	report_error("Importing secret parameters", result);
*/
	/* read input key file */ // (PRIVATE KEY)
	printf("keyfile => '%s'\n", keyfile);
	fp = fopen(keyfile, "r");
	if(fp != NULL) {
		if((key_len = read_file(fp, &keyfile_buf)) > 0) {
			// printf("\nYour private-key:\t'%s'\n", keyfile_buf);
			size_t keyLength;
			uint8 *bin_keyfile_buf = NewBase64Decode((const char *) keyfile_buf, key_len, &keyLength);

#ifdef DEBUG			
			/* base-64 decode user's private key */
			printf("Base-64 decoded buffer:\t");
			print_buffer_as_hex(bin_keyfile_buf, keyLength);
#endif			
			result = libfenc_import_secret_key(&context, &secret_key, bin_keyfile_buf, keyLength);
			report_error("Importing secret key", result);
			free(keyfile_buf);
		}			
	}
	else {
		fprintf(stderr, "Could not load input file: %s\n", keyfile);
		return FALSE;
	}
	fclose(fp);	
	
/*	
	 // print out new buffer 
	 fenc_key_WatersCP *myKey2 = (fenc_key_WatersCP *) key2.scheme_key;
	 size_t serialized_len2;
	 uint8 *buffer2 = malloc(KEYSIZE_MAX);
	 memset(buffer2, 0, KEYSIZE_MAX);
	 result = libfenc_serialize_key_WatersCP(myKey2, buffer2, KEYSIZE_MAX, &serialized_len2);		
	 report_error("Serialize user's key", result);
	 
	 printf("Key-len2: '%zu'\n", serialized_len2);
	 printf("Buffer contents 2:\n");
	 print_buffer_as_hex(buffer2, serialized_len2);
	 // END	
	
	/* stores user's authorized attributes */
/*	memset(&func_list_input, 0, sizeof(fenc_function_input));
	char *attr[9] = {"ONE", "TWO", "THREE", "FOUR", "FIVE", "SIX", "SEVEN", "EIGHT"};
	libfenc_create_attribute_list_from_strings(&func_list_input, attr, 8);
	fenc_attribute_list_to_buffer((fenc_attribute_list*)(func_list_input.scheme_input), output_str, 200, &output_str_len);
	printf("Attribute list: %s\n", output_str);
	
	result = libfenc_extract_key(&context, &func_list_input, &secret_key);
	report_error("Extracting a decryption key", result);	
*/	

	size_t abeLength;
	uint8 *data = NewBase64Decode((const char *) abe_blob64, strlen(abe_blob64), &abeLength);
	ciphertext.data = data;
	ciphertext.data_len = abeLength;
	ciphertext.max_len = abeLength;
	
	
	/* Descrypt the resulting ciphertext. */
	result = libfenc_decrypt(&context, &ciphertext, &secret_key, &aes_session_key);
	if (result == FENC_ERROR_NONE) {
		if (memcmp(aes_session_key.data, session_key, aes_session_key.data_len) != 0) {
			result = FENC_ERROR_UNKNOWN;
		}
	}
	report_error("Decrypting the ciphertext", result);
	
	printf("\tDecrypted session key is: ");
	print_buffer_as_hex(aes_session_key.data, aes_session_key.data_len);

	/* decode the aesblob64 */
	size_t aesLength;
	char *aesblob = NewBase64Decode((const char *) aes_blob64, strlen(aes_blob64), &aesLength);
	
	/* use the PSK to encrypt using openssl functions here */
	AES_KEY sk;
	char iv[SESSION_KEY_LEN*4];
	char aes_result[aesLength+1];
	AES_set_decrypt_key((uint8 *) aes_session_key.data, 8*SESSION_KEY_LEN, &sk);
	memset(iv, 0, SESSION_KEY_LEN*4);
	memset(aes_result, 0, aesLength+1);
	AES_cbc_encrypt((uint8 *) aesblob, (uint8 *) aes_result, aesLength, &sk, (unsigned char *) iv, AES_DECRYPT);
	/* base-64 both ciphertext and write to the stdout -- in XML? */
	
	printf("Plaintext: %s\nSize: %zd\n", aes_result, aesLength);
	
	/* Destroy the context. */
	result = libfenc_destroy_context(&context);
	report_error("Destroying the encryption context", result);	
	
	/* Shutdown the library. */
	result = libfenc_shutdown();
	report_error("Shutting down library", result);
	return TRUE;
}


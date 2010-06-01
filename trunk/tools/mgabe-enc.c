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
#include "policy_lang.h"
#include <pbc/pbc_test.h>
#include "base64.h"
#include "openssl/aes.h"
#include "openssl/sha.h"
#include "openssl/evp.h"
#include "openssl/err.h"
#include "openssl/rand.h"

/* include code that creates policy by hand */
#define AES_TOKEN "AES"
#define AES_TOKEN_END "AES_END"
#define ABE_TOKEN "ABE_CP"
#define ABE_TOKEN_END "ABE_CP_END"
#define BYTES 4

#define MAX_ATTRIBUTES 100
#define SIZE 2048
#define SIZE_MAX 4096
#define SESSION_KEY_LEN 16
char *public_params_file = "public.param";
// char *secret_params_file = "master_secret.param";
void report_error(char* action, FENC_ERROR result);
void print_help(void);
void parse_attributes(char *input);
void cpabe_encrypt(char *policy, char *data, char *enc_file);
void print_buffer_as_hex(uint8* data, size_t len);
fenc_attribute_policy *construct_test_policy();
ssize_t read_file(FILE *f, char** out);

/* Description: mgabe-keygen takes the outfile to write the users keys, and the .
 
 */
int main (int argc, char *argv[]) {
	int pflag = FALSE, dflag = FALSE, oflag = FALSE, iflag = FALSE;
	char *policy = NULL, *data = NULL, *enc_file = NULL;
	ssize_t data_len;
	FILE *fp;
	int c, exit_status = 0;
		
	opterr = 0;
	
	while ((c = getopt (argc, argv, "d:i:o:p:")) != -1) {
		
		switch (c)
		{
			case 'p': /* holds policy string */
				pflag = TRUE;
				if((policy = malloc(strlen(optarg)+1)) == NULL) {
					perror("malloc failed");
					exit(1);
				}
				strncpy(policy, optarg, strlen(optarg));			  
				break;
			case 'i':
				if(dflag == TRUE) /* i or d option, but not both */
					break;
				
				iflag = TRUE;
				fp = fopen(optarg, "r");
				if(fp != NULL) {
				  data_len = read_file(fp, &data);
				}
				else {
					perror("failed to read input file");
					exit(1);
				}

				break;
			case 'd': /* data to encrypt */
				if(iflag == TRUE) /* i or d */
					break;
				dflag = TRUE;
				// printf("optarg = '%s'\n", optarg);
				if((data = malloc(strlen(optarg)+1)) == NULL) {
					perror("malloc failed");
					exit(1);
				}
				strncpy(data, optarg, strlen(optarg));
				break;
				
			case 'o': /* output file */
				oflag = TRUE;
				enc_file = optarg;
				break;
			case 'h':
				print_help();
				exit(1);
			case '?':
				if (optopt == 'p' || optopt == 'd' || optopt == 'o')
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
	
	if(dflag == FALSE && iflag == FALSE) {
		fprintf(stderr, "Need some data to encrypt!\n");
		print_help();
		exit(1);
	}	
	
	if(pflag == FALSE) {
		fprintf(stderr, "No policy specified to encrypt data!\n");
		print_help();
		exit_status = -1;
		goto clean;
	}	

	if(oflag == FALSE) {
		fprintf(stderr, "Specify file to store ciphertext!\n");
		print_help();
		exit_status = -1;
		goto clean;
	}
	
	// printf("Setting up encryption.\n");
	cpabe_encrypt(policy, data, enc_file);
clean:	
	free(data);
	return exit_status;
}

void print_help(void)
{
	printf("Usage: ./abe-enc -d [ \"data\" ] -i [ input-filename ] -p '((ATTR1 and ATTR2) or ATT3) -o [ output-filename ]'\n\n");
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

void cpabe_encrypt(char *policy, char *data, char *enc_file)
{
	FENC_ERROR result;
	fenc_context context;
	fenc_group_params group_params;
	fenc_global_params global_params;
	fenc_ciphertext ciphertext;
	fenc_function_input func_policy_input;
	pairing_t pairing;
	FILE *fp;
	char c;
	int pub_len = 0;
	ssize_t serialized_len = 0;
	uint8 public_params_buf[SIZE];
	char session_key[SESSION_KEY_LEN];
	// size_t session_key_len;
	char pol_str[MAX_POLICY_STR];
	int pol_str_len = MAX_POLICY_STR;
	/* Clear data structures. */
	memset(&context, 0, sizeof(fenc_context));
	memset(&group_params, 0, sizeof(fenc_group_params));
	memset(&global_params, 0, sizeof(fenc_global_params));	
	memset(&public_params_buf, 0, SIZE);
	memset(&ciphertext, 0, sizeof(fenc_ciphertext));
	memset(pol_str, 0, pol_str_len);
	
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
		perror("Could not open parameters file.\n");
		return;
	}
	fclose(fp);
	
	/* Set up the global parameters. */
	result = context.generate_global_params(&global_params, &group_params);
	// report_error("Loading global parameters", result);
	
	result = libfenc_gen_params(&context, &global_params);
	// report_error("Generating scheme parameters and secret key", result);
	
	// printf("Reading the public parameters file = %s\n", public_params_file);	
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
		perror("File does not exist.\n");
		return;
	}
	fclose(fp);
	
	fenc_attribute_policy *parsed_policy = (fenc_attribute_policy *) malloc(sizeof(fenc_attribute_policy));
	if(parsed_policy == NULL) {
		printf("parsed_policy is NULL!");
	}
	memset(parsed_policy, 0, sizeof(fenc_attribute_policy)); 
	
	fenc_policy_from_string(parsed_policy, policy);
	// test_policy = construct_simple_test_policy();
	// printf("Address at 0x%x\n", &(parsed_policy->root));
	// result = fenc_attribute_policy_to_string(parsed_policy->root, pol_str, pol_str_len);
	// report_error("Fenc_policy_to_string", result);
	// printf("\noutput policy: %s\n", pol_str); 	
	func_policy_input.input_type = FENC_INPUT_NM_ATTRIBUTE_POLICY;
	func_policy_input.scheme_input = (void*)parsed_policy;	
	
	// printf("public params input = '%s'\n", public_params_buf);
	
	/* base-64 decode */
	uint8 *bin_public_buf = NewBase64Decode((const char *) public_params_buf, pub_len, &serialized_len);
	// printf("public params binary = '%s'\n", bin_public_buf);
	
	/* Import the parameters from binary buffer: */
	result = libfenc_import_public_params(&context, bin_public_buf, serialized_len);
	// report_error("Importing public parameters", result);
	
	/*  */
	result = libfenc_kem_encrypt(&context, &func_policy_input, SESSION_KEY_LEN, (uint8 *)session_key, &ciphertext);	
	
	/* generated PSK from policy string */
	// printf("\tSession key is: ");
	print_buffer_as_hex((uint8 *) session_key, SESSION_KEY_LEN);

	/* encrypted blob that belongs in the <ABED></ABE> tags */
	// printf("\tABE Ciphertex is: ");
	// print_buffer_as_hex(ciphertext.data, ciphertext.data_len);
		
	/* use the PSK to encrypt using openssl functions here */
	AES_KEY key;
	char iv[AES_BLOCK_SIZE*4];
	int data_len = strlen(data)*5; // consider padding?
	char aes_ciphertext[data_len];
	
	memset(iv, 0, AES_BLOCK_SIZE*4);
	memset(aes_ciphertext, 0, data_len);
	AES_set_encrypt_key((uint8 *) session_key, 8*SESSION_KEY_LEN, &key);
	// printf("\tPlaintext is => '%s'\n", data);
	// print_buffer_as_hex((uint8 *)data, data_len);
	
	AES_cbc_encrypt((uint8 *)data, (uint8 *) aes_ciphertext, data_len, &key, (uint8 *) iv, AES_ENCRYPT);
	// printf("\tAES Ciphertext base 64: ");
	// print_buffer_as_hex((uint8 *) aes_ciphertext, data_len);
	
	printf("\n\n<====  Base-64 encode ciphertext  ====> \n\n");
	FILE *f = fopen("enc_data.xml", "w");
	FILE *f1 = fopen(enc_file, "w");
	
	/* generate the random unique id */
	uint8 *rand_id[BYTES+1];
	if(RAND_bytes(rand_id, BYTES) == 0) {
		perror("Unusual failure.\n");
		strcpy((char *)rand_id, "0123");
	}
	
	/* base-64 both ciphertexts and write to the stdout -- in XML? */
	size_t abe_length, aes_length;
	char *ABE_cipher_base64 = NewBase64Encode(ciphertext.data, ciphertext.data_len, FALSE, &abe_length);
	fprintf(f,"<Encrypted id='");
	fprintf(f, "%08x", (unsigned int) rand_id[0]);
	fprintf(f,"'><ABE type='CP'>%s</ABE>", ABE_cipher_base64);
	fprintf(f1, ABE_TOKEN":%s:"ABE_TOKEN_END":", ABE_cipher_base64);
	
	char *AES_cipher_base64 = NewBase64Encode(aes_ciphertext, data_len, FALSE, &aes_length);
	fprintf(f,"<EncryptedData>%s</EncryptedData></Encrypted>", AES_cipher_base64);
	fprintf(f1, AES_TOKEN":%s:"AES_TOKEN_END, AES_cipher_base64);
	fclose(f);
	fclose(f1);
		
	free(ABE_cipher_base64);
	free(AES_cipher_base64);
	free(parsed_policy);
	
	/* Shutdown the library. */
	result = libfenc_shutdown();
	report_error("Shutting down library", result);
	return;
}

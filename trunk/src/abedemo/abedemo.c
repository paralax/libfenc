/*!	\file setup.c
 *
 *	\brief Test application for the Functional Encryption Library.  Links against libfenc.a.
 *  
 *	Copyright 2009 Matthew Green. All rights reserved.
 */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "libfenc.h"
#include "libfenc_group_params.h"
#include "libfenc_ABE_common.h"
#include "libfenc_LSW.h"
#include <pbc_test.h>

#define SESSION_KEY_LEN	16

void
report_error(char* action, FENC_ERROR result)
{
	printf("%s...\n\t%s (%d)\n", action, libfenc_error_to_string(result), result);
	
	if (result != FENC_ERROR_NONE) {
		exit(1);
	}
}

void
usage(char *exe_name)
{
	printf("usage: %s <command> <arguments>\n", exe_name);
	printf("\t <command> = (setup, extract, encrypt, decrypt)\n");
}

void
print_buffer_as_hex(uint8* data, size_t len)
{
	int i;
	
	for (i = 0; i < len; i++) {
		printf("%2x ", data[i]);
	}
	printf("\n");
}

fenc_attribute_policy *
construct_test_policy()
{
	fenc_attribute_policy *policy;
	fenc_attribute_subtree *subtree_AND, *subtree_L1, *subtree_L2, *subtree_L3, *subtree_L4, *subtree_L5, *subtree_OR;
	
	policy = (fenc_attribute_policy*)SAFE_MALLOC(sizeof(fenc_attribute_policy));
	memset(policy, 0, sizeof(fenc_attribute_policy));
	
	/* Add a simple one-level 3-out-of-3 policy.  Eventually we'll have helper routines to
	 * do this work.	*/
	subtree_AND = (fenc_attribute_subtree*)SAFE_MALLOC(sizeof(fenc_attribute_subtree));
	subtree_L1 = (fenc_attribute_subtree*)SAFE_MALLOC(sizeof(fenc_attribute_subtree));
	subtree_L2 = (fenc_attribute_subtree*)SAFE_MALLOC(sizeof(fenc_attribute_subtree));
	subtree_L3 = (fenc_attribute_subtree*)SAFE_MALLOC(sizeof(fenc_attribute_subtree));
	subtree_L4 = (fenc_attribute_subtree*)SAFE_MALLOC(sizeof(fenc_attribute_subtree));
	subtree_L5 = (fenc_attribute_subtree*)SAFE_MALLOC(sizeof(fenc_attribute_subtree));
	subtree_OR = (fenc_attribute_subtree*)SAFE_MALLOC(sizeof(fenc_attribute_subtree));
	memset(subtree_AND, 0, sizeof(fenc_attribute_subtree));
	memset(subtree_L1, 0, sizeof(fenc_attribute_subtree));
	memset(subtree_L2, 0, sizeof(fenc_attribute_subtree));
	memset(subtree_L3, 0, sizeof(fenc_attribute_subtree));
	memset(subtree_L4, 0, sizeof(fenc_attribute_subtree));
	memset(subtree_L5, 0, sizeof(fenc_attribute_subtree));
	memset(subtree_OR, 0, sizeof(fenc_attribute_subtree));
	
	subtree_L1->node_type = FENC_ATTRIBUTE_POLICY_NODE_LEAF;
	strcpy((char*)subtree_L1->attribute.attribute_str, "ONE");
	
	subtree_L2->node_type = FENC_ATTRIBUTE_POLICY_NODE_LEAF;
	strcpy((char*)subtree_L2->attribute.attribute_str, "TWO");
	
	subtree_L3->node_type = FENC_ATTRIBUTE_POLICY_NODE_LEAF;
	strcpy((char*)subtree_L3->attribute.attribute_str, "THREE");
	
	subtree_L4->node_type = FENC_ATTRIBUTE_POLICY_NODE_LEAF;
	strcpy((char*)subtree_L4->attribute.attribute_str, "FOUR");
	
	subtree_L5->node_type = FENC_ATTRIBUTE_POLICY_NODE_LEAF;
	strcpy((char*)subtree_L5->attribute.attribute_str, "FIVE");
	
	subtree_AND->node_type = FENC_ATTRIBUTE_POLICY_NODE_OR;
	subtree_AND->threshold_k = 2;
	subtree_AND->num_subnodes = 3;
	subtree_AND->subnode = SAFE_MALLOC(sizeof(fenc_attribute_subtree*) * 5);
	subtree_AND->subnode[0] = subtree_L1;
	subtree_AND->subnode[1] = subtree_L2;
	subtree_AND->subnode[2] = subtree_OR;
	
	subtree_OR->node_type = FENC_ATTRIBUTE_POLICY_NODE_AND;
	subtree_OR->subnode = SAFE_MALLOC(sizeof(fenc_attribute_subtree*) * 3);
	subtree_OR->num_subnodes = 3;
	subtree_OR->subnode[0] = subtree_L3;
	subtree_OR->subnode[1] = subtree_L4;
	subtree_OR->subnode[2] = subtree_L5;
	
	policy->root = subtree_AND;
	
	return policy;
}



/********************************************************************************
 * Main test routine
 ********************************************************************************/

FENC_SCHEME_TYPE
fenc_scheme_from_string(char *str)
{
	if (strcmp(str, "lsw") == 0) {
		return FENC_SCHEME_LSW;
	} else {
		return FENC_SCHEME_NONE;
	}
}

void
setup(int argc, char **argv)
{
	FENC_ERROR result;
	fenc_context context;
	fenc_group_params group_params;
	fenc_global_params global_params;
	char* buf;
	FILE* fp;
	size_t serialized_len;
	char mpk_filename[200];
	char msk_filename[200];
	
	if (argc < 5) { 
		printf("usage:\t%s setup <scheme_type> <group_params_file> <out_file>\n", argv[0]);
		printf("\t<scheme_type> = lsw\n");
		exit(1);
	}
	
	/* Initialize the library. */
	result = libfenc_init();
	report_error("Initializing library", result);
	
	/* Clear data structures. */
	memset(&context, 0, sizeof(fenc_context));
	memset(&group_params, 0, sizeof(fenc_group_params));
	memset(&global_params, 0, sizeof(fenc_global_params));
	
	/* Create a scheme context. */
	result = libfenc_create_context(&context, fenc_scheme_from_string(argv[2]));
	report_error("Creating an encryption context", result);

	/* Load group parameters from a file. */
	fp = fopen(argv[3], "r");
	if (fp != NULL) {
		libfenc_load_group_params_from_file(&group_params, fp);
	} else {
		printf("Could not open parameters file.");
		exit(1);
	}
	fclose(fp);
	
	/* Set up the global parameters. */
	result = context.generate_global_params(&global_params, &group_params);
	report_error("Loading global parameters", result);
	
	/* Generate the scheme parameters and secret key. */
	result = libfenc_gen_params(&context, &global_params);
	report_error("Generating scheme parameters and secret key", result);
	
	sprintf(mpk_filename, "%s.mpk", argv[4]);
	sprintf(msk_filename, "%s.msk", argv[4]);
	
	/* Serialize the public parameters into a buffer. */
	result = libfenc_export_public_params(&context, NULL, 0, &serialized_len, TRUE);
	if (result != FENC_ERROR_NONE) { report_error("Computing public parameter output size", result); }
	buf = malloc(serialized_len);
	result = libfenc_export_public_params(&context, buf, serialized_len, &serialized_len, TRUE);
	report_error("Exporting public parameters", result);
	
	fp = fopen(mpk_filename, "wb");
	fwrite(buf, 1, serialized_len, fp);
	fclose(fp);
	free(buf);
	
	/* Serialize the secret parameters into a buffer. */
	result = libfenc_export_secret_params(&context, NULL, 0, &serialized_len, NULL, 0);
	if (result != FENC_ERROR_NONE) { report_error("Computing secret parameter output size", result); }
	buf = malloc(serialized_len);
	result = libfenc_export_secret_params(&context, buf, serialized_len, &serialized_len, NULL, 0);
	report_error("Exporting secret parameters", result);

	fp = fopen(msk_filename, "wb");
	fwrite(buf, 1, serialized_len, fp);
	fclose(fp);
	free(buf);
	
	printf("Parameters generated successfully.\n\nOutput written to \"%s\" and \"%s\".\n", mpk_filename, msk_filename);
}

void
extract_key(int argc, char **argv)
{
	FENC_ERROR result;
	fenc_context context;
	fenc_group_params group_params;
	fenc_global_params global_params;
	fenc_key key;
	char* buf;
	FILE* fp;
	size_t bytes_read = 0;
	char mpk_filename[200];
	char msk_filename[200];
	uint8 file_buf[5000];
	fenc_function_input policy_input;
	uint32 arg_cnt = 2;
	char *output_file_name;
	FILE *output_file;
	
	if (argc < 6) { 
		printf("usage:\t%s extract <scheme_type> <mpk/msk file prefix> <output file> <policy>\n", argv[0]);
		exit(1);
	}
	
	/* Initialize the library. */
	result = libfenc_init();
	report_error("Initializing library", result);
	
	/* Clear data structures. */
	memset(&context, 0, sizeof(fenc_context));
	memset(&group_params, 0, sizeof(fenc_group_params));
	memset(&global_params, 0, sizeof(fenc_global_params));
	
	/* Create a scheme context. */
	result = libfenc_create_context(&context, fenc_scheme_from_string(argv[arg_cnt++]));
	report_error("Creating an encryption context", result);
	
	/* Import the MPK from a file. */
	strcpy(mpk_filename, argv[arg_cnt]);
	strcat(mpk_filename, ".mpk");
	fp = fopen(mpk_filename, "rb");
	if (fp != NULL) {
		bytes_read = fread(file_buf, 1, 5000, fp);
	} else {
		printf("Could not open MPK file.");
		exit(1);
	}
	fclose(fp);
	result = libfenc_import_public_params(&context, file_buf, bytes_read);
	report_error("Loading public parameters", result);
	
	/* Import the MSK from a file. */
	strcpy(msk_filename, argv[arg_cnt++]);
	strcat(msk_filename, ".msk");
	fp = fopen(msk_filename, "rb");
	if (fp != NULL) {
		bytes_read = fread(file_buf, 1, 5000, fp);
	} else {
		printf("Could not open MSK file.");
		exit(1);
	}
	fclose(fp);
	result = libfenc_import_secret_params(&context, file_buf, bytes_read, NULL, 0);
	report_error("Loading secret parameters", result);
	
	/* Open the output file.	*/
	output_file_name = argv[arg_cnt++];
	output_file = fopen(output_file_name, "wb");
	if (output_file == NULL) {
		printf("Could not open output file %s.\n", output_file_name);
		exit(1);
	}
	
	/* TODO: parse a string properly.	*/
	memset(&policy_input, 0, sizeof(fenc_function_input));
	policy_input.input_type = FENC_INPUT_NM_ATTRIBUTE_POLICY;
	policy_input.scheme_input = (void*)construct_test_policy();
	
	/* Extract the key.	*/
	result = libfenc_extract_key(&context, &policy_input, &key);
	report_error("Extracting a decryption key", result);
	
	/* Write out the key.	*/
	libfenc_serialize_key_LSW((fenc_key_LSW*)(key.scheme_key), file_buf, 5000, &bytes_read);
	fwrite(file_buf, 1, bytes_read, output_file);
	fclose(output_file);
}

void
encrypt(int argc, char **argv)
{
	FENC_ERROR result;
	fenc_context context;
	fenc_global_params global_params;
	fenc_function_input input;
	fenc_ciphertext ciphertext;
	char* buf;
	FILE* fp, *out_file;
	size_t bytes_read = 0;
	char mpk_filename[200];
	char msk_filename[200];
	char file_buf[5000];
	uint32 arg_cnt = 2, i;
	char session_key[SESSION_KEY_LEN];
	char *out_file_name;
	
	if (argc < 6) { 
		printf("usage:\t%s encrypt <scheme_type> <mpk file prefix> <output file> <attribute1> ... <attributeN>\n", argv[0]);
		exit(1);
	}
	
	/* Initialize the library. */
	result = libfenc_init();
	report_error("Initializing library", result);
	
	/* Clear data structures. */
	memset(&context, 0, sizeof(fenc_context));
	memset(&global_params, 0, sizeof(fenc_global_params));
	
	/* Create a scheme context. */
	result = libfenc_create_context(&context, fenc_scheme_from_string(argv[arg_cnt++]));
	report_error("Creating an encryption context", result);
	
	/* Import the MPK from a file. */
	strcpy(mpk_filename, argv[arg_cnt++]);
	strcat(mpk_filename, ".mpk");
	fp = fopen(mpk_filename, "rb");
	if (fp != NULL) {
		bytes_read = fread(file_buf, 1, 5000, fp);
	} else {
		printf("Could not open MPK file.");
		exit(1);
	}
	fclose(fp);
	result = libfenc_import_public_params(&context, file_buf, bytes_read);
	report_error("Loading public parameters", result);
		
	/* Open the output file.			*/
	out_file_name = argv[arg_cnt++];
	out_file = fopen(out_file_name, "wb");
	if (out_file == NULL) {
		printf("Could not open output file %s.\n", out_file_name);
		exit(1);
	}
	
	/* Construct the attribute list.	*/
	libfenc_create_attribute_list_from_strings(&input, &(argv[arg_cnt]), argc - arg_cnt);
	printf("\t%d attributes in list:\n", (argc - arg_cnt));
	for (i = arg_cnt; i < argc; i++) {
		printf("\t\t%s\n", argv[i]);
	}
	printf("\n");
	
	result = libfenc_kem_encrypt(&context, &input, SESSION_KEY_LEN, session_key, &ciphertext);
	report_error("Encrypting a session key", result);

	if (result == FENC_ERROR_NONE) {
		printf("\tSession key is: ");
		print_buffer_as_hex(session_key, SESSION_KEY_LEN);
		printf("\t%d bytes written to %s\n", ciphertext.data_len, out_file_name);
		fwrite(ciphertext.data, 1, ciphertext.data_len, out_file);
	}

	fclose(out_file);
}

void
decrypt(int argc, char **argv)
{ }

int
main(int argc, char **argv)
{
	FENC_ERROR result;
	
	if (argc < 2) {
		usage(argv[0]);
		return 1;
	}
	
	if (strcmp(argv[1], "setup") == 0) {
		/* Setup and output keys.		*/
		setup(argc, argv);
	} else if (strcmp(argv[1], "extract") == 0) {
		/* Extract a decryption key.	*/
		extract_key(argc, argv);
	} else if (strcmp(argv[1], "encrypt") == 0) {
		/* Encrypt a message.			*/
		encrypt(argc, argv);
	} else if (strcmp(argv[1], "decrypt") == 0) {
		/* Decrypt a ciphertext.		*/
		decrypt(argc, argv);
	} else {
		usage(argv[0]);
		return 1;
	}
	
	/* Shut down the library. */
	result = libfenc_shutdown();
	report_error("Shutting down library", result);
	
	return 0;
}



#if 0
int
main(int argc, char **argv)
{
	FENC_ERROR result;
	fenc_context context;
	fenc_group_params group_params;
	fenc_global_params global_params;
	fenc_function_input func_list_input;
	fenc_function_input func_policy_input;
	fenc_plaintext plaintext;
	fenc_ciphertext ciphertext;
	fenc_key key;
	fenc_plaintext new_plaintext;
	fenc_attribute_policy *test_policy;
	size_t serialized_len = 0;
	uint8* buf = 0;
	FILE *fp;
	struct element_s foo;
	element_t bar;
	pairing_t pairing;
	char *plaintext_str = "Test Plaintext";
	char session_key[SESSION_KEY_LEN];
	size_t session_key_len;
	
	
	/* Clear data structures. */
	memset(&context, 0, sizeof(fenc_context));
	memset(&group_params, 0, sizeof(fenc_group_params));
	memset(&global_params, 0, sizeof(fenc_global_params));
	memset(&func_list_input, 0, sizeof(fenc_function_input));
	memset(&plaintext, 0, sizeof(fenc_plaintext));
	memset(&ciphertext, 0, sizeof(fenc_ciphertext));
	memset(&key, 0, sizeof(fenc_key));
	memset(&new_plaintext, 0, sizeof(fenc_plaintext));
	
	/* Initialize the library. */
	result = libfenc_init();
	report_error("Initializing library", result);
	
	/* Create a Sahai-Waters context. */
	result = libfenc_create_context(&context, FENC_SCHEME_LSW);
	report_error("Creating a Lewko-Sahai-Waters encryption context", result);

	/* Load group parameters from a file. */
	fp = fopen("d224.param", "r");
	if (fp != NULL) {
		libfenc_load_group_params_from_file(&group_params, fp);
		libfenc_get_pbc_pairing(&group_params, pairing);
	} else {
		printf("Could not open parameters file.");
		exit(1);
	}
	fclose(fp);
	
	/* Set up the global parameters. */
	result = context.generate_global_params(&global_params, &group_params);
	report_error("Loading global parameters", result);
	
	/* Construct a sample policy and attribute list.	*/
	test_policy = construct_simple_test_policy();
	construct_test_attribute_list(&func_list_input);
	func_policy_input.input_type = FENC_INPUT_NM_ATTRIBUTE_POLICY;
	func_policy_input.scheme_input = (void*)test_policy;
	//test_secret_sharing(test_policy, pairing);
	
	/* Generate the scheme parameters and secret key. */
	result = libfenc_gen_params(&context, &global_params);
	report_error("Generating scheme parameters and secret key", result);
	
	/* Serialize the public parameters into a buffer (not strictly necessary, just a test). */
	result = libfenc_export_public_params(&context, NULL, 0, &serialized_len);
	if (result != FENC_ERROR_NONE) { report_error("Computing public parameter output size", result); }
	buf = malloc(serialized_len);
	result = libfenc_export_public_params(&context, buf, serialized_len, &serialized_len);
	report_error("Exporting public parameters", result);

	/* Serialize the secret parameters into a buffer (not strictly necessary, just a test). */
	result = libfenc_export_secret_params(&context, NULL, 0, &serialized_len, NULL, 0);
	if (result != FENC_ERROR_NONE) { report_error("Computing secret parameter output size", result); }
	buf = malloc(serialized_len);
	result = libfenc_export_secret_params(&context, buf, serialized_len, &serialized_len, NULL, 0);
	report_error("Exporting secret parameters", result);
	
	/* Encrypt a test ciphertext using KEM mode. */
	//result = libfenc_set_plaintext_bytes(&plaintext, plaintext_str, strlen(plaintext_str) + 1);
	result = libfenc_kem_encrypt(&context, &func_list_input, SESSION_KEY_LEN, session_key, &ciphertext);
	//result = libfenc_encrypt(&context, &func_list_input, &plaintext, &ciphertext);
	report_error("Encrypting a test ciphertext", result);
	
	printf("\tSession key is: ");
	print_buffer_as_hex(session_key, SESSION_KEY_LEN);
	
	/* Extract a decryption key. */
	result = libfenc_extract_key(&context, &func_policy_input, &key);
	report_error("Extracting a decryption key", result);

	/* Descrypt the resulting ciphertext. */
	result = libfenc_decrypt(&context, &ciphertext, &key, &new_plaintext);
	if (result == FENC_ERROR_NONE) {
		if (memcmp(new_plaintext.data, session_key, new_plaintext.data_len) != 0) {
			result = FENC_ERROR_UNKNOWN;
		}
	}
	report_error("Decrypting the ciphertext", result);
	
	printf("\tDecrypted session key is: ");
	print_buffer_as_hex(new_plaintext.data, new_plaintext.data_len);

	/* Destroy the context. */
	result = libfenc_destroy_context(&context);
	report_error("Destroying the encryption context", result);
	
	/* Shutdown the library. */
	result = libfenc_shutdown();
	report_error("Shutting down library", result);
	
	return 0;
}
#endif
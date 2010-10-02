 /*!	\file test_libfenc.c
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
#include "libfenc_ABE_common.h"			/* Used for internal tests, not a standard include.	*/
#include "libfenc_LSSS.h"				/* Used for internal tests, not a standard include.	*/
#include "policy_lang.h"
#include <pbc_test.h>

#define SESSION_KEY_LEN	16

void
report_error(char* action, FENC_ERROR result)
{
	printf("%s...\n\t%s (%d)\n", action, libfenc_error_to_string(result), result);
}

void
construct_test_attribute_list(fenc_function_input *input)
{
	char *attributes[3] = {"JohnDoeDoctor", "THREE", "FIVE"};//, "THREE", "FIVE" };
	
	libfenc_create_attribute_list_from_strings(input, attributes, 3);
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

fenc_attribute_policy *
construct_simple_test_policy()
{
	fenc_attribute_policy *policy;
	fenc_attribute_subtree *subtree_AND, *subtree_L1, *subtree_L2, *subtree_L3, *subtree_L4, *subtree_L5, *subtree_OR;
	
	policy = (fenc_attribute_policy*)SAFE_MALLOC(sizeof(fenc_attribute_policy));
	memset(policy, 0, sizeof(fenc_attribute_policy));
	
	/* Add a simple one-level 3-out-of-3 policy.  Eventually we'll have helper routines to
	 * do this work.	*/
	subtree_L1 = (fenc_attribute_subtree*)SAFE_MALLOC(sizeof(fenc_attribute_subtree));
	memset(subtree_L1, 0, sizeof(fenc_attribute_subtree));
	subtree_L2 = (fenc_attribute_subtree*)SAFE_MALLOC(sizeof(fenc_attribute_subtree));
	memset(subtree_L2, 0, sizeof(fenc_attribute_subtree));
	
	subtree_OR = (fenc_attribute_subtree*)SAFE_MALLOC(sizeof(fenc_attribute_subtree));
	memset(subtree_OR, 0, sizeof(fenc_attribute_subtree));
	subtree_OR->subnode = SAFE_MALLOC(sizeof(fenc_attribute_subtree*) * 2);
	subtree_OR->node_type = FENC_ATTRIBUTE_POLICY_NODE_OR;
	subtree_OR->num_subnodes = 2;
	subtree_OR->subnode[0] = subtree_L1;
	subtree_OR->subnode[1] = subtree_L2;
	
	subtree_L1->node_type = FENC_ATTRIBUTE_POLICY_NODE_LEAF;
	strcpy((char*)subtree_L1->attribute.attribute_str, "ONE");
	
	subtree_L2->node_type = FENC_ATTRIBUTE_POLICY_NODE_LEAF;
	strcpy((char*)subtree_L2->attribute.attribute_str, "TWO");
	
	policy->root = subtree_OR;
	//policy->root = subtree_L1;
	
	return policy;
}

void
test_secret_sharing(fenc_attribute_policy *policy, pairing_t pairing)
{
	element_t secret, recovered_secret, tempZ, temp2Z;
	FENC_ERROR err_code;
	fenc_attribute_list attribute_list;
	fenc_lsss_coefficient_list coefficient_list;
	int i;
	char *policy_str;
	size_t str_len = 2048, index = 0;
	
	/* Print the policy.	*/
	//fenc_attribute_policy_to_string(policy->root, NULL, &str_len, 100000);
	fenc_attribute_policy_to_string(policy->root, NULL, 100000);
	policy_str = (char*)SAFE_MALLOC(str_len);
	//fenc_attribute_policy_to_string(policy->root, policy_str, &index, str_len);
	fenc_attribute_policy_to_string(policy->root, policy_str, str_len);
	printf("%s\n", policy_str);
	
	/* Pick a random secret value.	*/
	element_init_Zr(secret, pairing);
	element_init_Zr(recovered_secret, pairing);
	element_random(secret);
	element_printf("Original secret: %B\n", secret);
	
	/* Share the secret.  The shares are placed within a newly-initialized attribute_list.	*/
	memset(&attribute_list, 0, sizeof(fenc_attribute_list));
	err_code = fenc_LSSS_calculate_shares_from_policy(&secret, policy, &attribute_list, pairing);
	if (err_code != FENC_ERROR_NONE) {
		printf("could not share secrets!\n");
		return;
	}
	
	printf("\nCreated %d shares:\n", attribute_list.num_attributes); 
	for (i = 0; i < attribute_list.num_attributes; i++) {
		element_printf("\t share %d: %B\n", i, attribute_list.attribute[i].share);
	}

	/* Take the resulting attribute_list and feed it as input to the coefficient recovery mechanism.
	 * Note that the coefficient recovery doesn't use the shares as input, it just looks at the
	 * attributes.	*/
	err_code = LSSS_allocate_coefficient_list(&coefficient_list, attribute_list.num_attributes, pairing);
	if (err_code != FENC_ERROR_NONE) {
		printf("could not allocate coefficient list!\n");
		return;
	}
	
	err_code = fenc_LSSS_calculate_coefficients_from_policy(policy, &attribute_list, &coefficient_list, pairing);
	if (err_code != FENC_ERROR_NONE) {
		printf("could not compute coefficients!\n");
		return;
	}
	
	printf("\nComputed %d coefficients:\n", attribute_list.num_attributes); 
	for (i = 0; i < attribute_list.num_attributes; i++) {
		if (coefficient_list.coefficients[i].is_set == TRUE) {
			element_printf("\t coefficient %d: %B\n", i, coefficient_list.coefficients[i].coefficient);
		} else {
			printf("\t coefficient %d: <pruned>\n", i);
		}
	}
	
	/* Now let's manually try to recover the secret.  Unfortunately this requires some messy
	 * element arithmetic.	*/
	element_init_Zr(tempZ, pairing);
	element_init_Zr(temp2Z, pairing);
	element_set0(recovered_secret);
	for (i = 0; i < attribute_list.num_attributes; i++) {
		if (coefficient_list.coefficients[i].is_set == TRUE) {
			element_mul(tempZ, coefficient_list.coefficients[i].coefficient, attribute_list.attribute[i].share);
			element_add(temp2Z, tempZ, recovered_secret);
			element_set(recovered_secret, temp2Z);
		}
	}
	
	element_printf("Recovered secret: %B\n", recovered_secret);
	
	element_clear(secret);
	element_clear(recovered_secret);
	element_clear(tempZ);
	element_clear(temp2Z);
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

/********************************************************************************
 * Main test routine
 ********************************************************************************/

int
main(/*int argc, char **argv*/)
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
	fenc_attribute_policy parsed_policy;
	size_t serialized_len = 0;
	uint8* buf = 0;
	FILE *fp;
	struct element_s foo;
	element_t bar;
	pairing_t pairing;
	char *plaintext_str = "Test Plaintext";
	char session_key[SESSION_KEY_LEN];
	size_t session_key_len;
	char output_str[20000];
	size_t output_str_len = 20000;
	
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
	
	//parse_policy_lang_as_str("FOO");
	fenc_policy_from_string(&parsed_policy, "(JohnDoe or JohnDoeDoctor) or (JohnDoeParent and (time = 99999))");//"((1 of (Firstname Lastname, Jane Smith)) OR (2 of (Parent of Firstname Lastname, time = 1639285200.0)))");
	strcpy(output_str, "");
	fenc_attribute_policy_to_string(parsed_policy.root, output_str, &output_str_len);
	printf("output policy: %s\n", output_str);

	/* Create a Sahai-Waters context. */
	result = libfenc_create_context(&context, FENC_SCHEME_WATERSCP);
	report_error("Creating a Waters CP encryption context", result);

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
	func_policy_input.scheme_input = (void*)&(parsed_policy);//test_policy;
	fenc_attribute_policy_to_string(test_policy->root, output_str, 100000);
	printf("Test policy is: %s\n", output_str);
	//test_secret_sharing(test_policy, pairing);
	
	fenc_attribute_list_to_buffer((fenc_attribute_list*)(func_list_input.scheme_input), output_str, 200, &output_str_len);
	printf("Attribute list: %s\n", output_str);
	
	/* Generate the scheme parameters and secret key. */
	result = libfenc_gen_params(&context, &global_params);
	report_error("Generating scheme parameters and secret key", result);
	
	/* Serialize the public parameters into a buffer (not strictly necessary, just a test). */
	result = libfenc_export_public_params(&context, NULL, 0, &serialized_len, FALSE);
	if (result != FENC_ERROR_NONE) { report_error("Computing public parameter output size", result); }
	buf = malloc(serialized_len);
	result = libfenc_export_public_params(&context, buf, serialized_len, &serialized_len, FALSE);
	report_error("Exporting public parameters", result);
	
	/* TEST: Import the parameters back, just for fun!	*/
	result = libfenc_import_public_params(&context, buf, serialized_len);
	report_error("Re-importing public parameters", result);

	/* Serialize the secret parameters into a buffer (not strictly necessary, just a test). */
	result = libfenc_export_secret_params(&context, NULL, 0, &serialized_len, NULL, 0);
	if (result != FENC_ERROR_NONE) { report_error("Computing secret parameter output size", result); }
	buf = malloc(serialized_len);
	result = libfenc_export_secret_params(&context, buf, serialized_len, &serialized_len, NULL, 0);
	report_error("Exporting secret parameters", result);
	
	/* TEST: Import the parameters back, just for fun!	*/
	result = libfenc_import_secret_params(&context, buf, serialized_len, NULL, 0);
	report_error("Re-importing secret parameters", result);
	
	/* Encrypt a test ciphertext using KEM mode. */
	//result = libfenc_set_plaintext_bytes(&plaintext, plaintext_str, strlen(plaintext_str) + 1);
	result = libfenc_kem_encrypt(&context, &func_policy_input, SESSION_KEY_LEN, session_key, &ciphertext);
	//result = libfenc_encrypt(&context, &func_list_input, &plaintext, &ciphertext);
	report_error("Encrypting a test ciphertext", result);
	
	printf("\tSession key is: ");
	print_buffer_as_hex(session_key, SESSION_KEY_LEN);
	printf("\tCiphertext size is: %d\n", ciphertext.data_len);
	
	/* Extract a decryption key. */
	result = libfenc_extract_key(&context, &func_list_input, &key);
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

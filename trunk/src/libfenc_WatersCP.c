/*!	\file libfenc_WatersCP.c
 *
 *	\brief Routines for the Waters CP-ABE scheme.
 *  
 *	Copyright 2009 Matthew Green. All rights reserved.
 */

#include <stdlib.h>
#include <string.h>
#include <pbc.h>
#include "libfenc.h"
#include "libfenc_group_params.h"
#include "libfenc_ABE_common.h"
#include "libfenc_utils.h"
#include "libfenc_WatersCP.h"
#include "libfenc_LSSS.h"

/********************************************************************************
 * Waters Ciphertext-Policy Implementation
 ********************************************************************************/

/*!
 * Initialize a fenc_context data structure for use with the Waters scheme.  
 * Any number of fenc_context structures may be simultaneously used, with the same
 * or different schemes.  The caller assumes responsible for allocating the context
 * buffer.
 *
 * @param context		Pre-allocated buffer for the fenc_context data structure.
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR
libfenc_create_context_WatersCP(fenc_context *context)
{
	CHECK_LIBRARY_STATE;
	
	FENC_ERROR result = FENC_ERROR_UNKNOWN;
	
	/* Allocate a scheme-specific context. */
	context->scheme_context = SAFE_MALLOC( sizeof(fenc_scheme_context_WatersCP) );
	
	if (context->scheme_context != NULL) {
		/* Set up the scheme context. */
		memset(context->scheme_context, 0, sizeof(fenc_scheme_context_WatersCP) );
		
		/* TODO */
		result = FENC_ERROR_NONE;
	} else {
		 /* Couldn't allocate scheme context. */
		 result = FENC_ERROR_OUT_OF_MEMORY;
	}
	
	/* Configure  function pointers within the fenc_context to point to
	 * LSW scheme-specific routines.									*/
	if (result == FENC_ERROR_NONE) {
		context->gen_params				= libfenc_gen_params_WatersCP;
		context->set_params				= libfenc_set_params_WatersCP;
		context->extract_key			= libfenc_extract_key_WatersCP;
		context->encrypt				= libfenc_encrypt_WatersCP;
		context->kem_encrypt			= libfenc_kem_encrypt_WatersCP;
		context->decrypt				= libfenc_decrypt_WatersCP;
		context->destroy_context		= libfenc_destroy_context_WatersCP;
		context->generate_global_params	= libfenc_generate_global_params_COMMON;
		context->destroy_global_params	= libfenc_destroy_global_params_COMMON;
		context->export_public_params	= libfenc_export_public_params_WatersCP;
		context->export_secret_params	= libfenc_export_secret_params_WatersCP;
		context->import_public_params	= libfenc_import_public_params_WatersCP;
		context->import_secret_params	= libfenc_import_secret_params_WatersCP;
		context->export_global_params	= libfenc_export_global_params_WatersCP;
		context->import_global_params	= libfenc_import_global_params_WatersCP;
	}
		
	/* Return success/error. */
	return result;
}

/*!
 * Generate public and secret parameters.
 *
 * @param context		The fenc_context data structure
 * @param global_params	Global params (scheme-specific).
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR
libfenc_gen_params_WatersCP(fenc_context *context, fenc_global_params *global_params)
{
	FENC_ERROR result = FENC_ERROR_UNKNOWN, err_code = FENC_ERROR_NONE;
	element_t eggT, alphaZ, loghZ;
	fenc_scheme_context_WatersCP* scheme_context;
	Bool elements_initialized = FALSE;
	
	/* Get the scheme-specific context. */
	scheme_context = (fenc_scheme_context_WatersCP*)context->scheme_context;
	if (scheme_context == NULL) {
		result = FENC_ERROR_INVALID_CONTEXT;
		goto cleanup;
	}
	
	/* Validate the global parameters. */
	err_code = libfenc_validate_global_params_WatersCP(global_params);
	if (err_code != FENC_ERROR_NONE) {
		LOG_ERROR("libfenc_gen_params_WatersCP: could not validate global params, error: %s", libfenc_error_to_string(err_code));
		result = err_code;
		goto cleanup;
	}
	
	/* Global parameters check out ok.  Copy them and generate the scheme-specific parameters.  The NULL
	 * parameter causes the structure to be allocated.		*/
	scheme_context->global_params = initialize_global_params_WatersCP(global_params->group_params, NULL);
	
	/* Initialize the elements in the public and secret parameters, along with some temporary variables. */
	public_params_initialize_WatersCP(&(scheme_context->public_params), scheme_context->global_params->pairing);
	secret_params_initialize_WatersCP(&(scheme_context->secret_params), scheme_context->global_params->pairing);
	element_init_GT(eggT, scheme_context->global_params->pairing);
	element_init_Zr(alphaZ, scheme_context->global_params->pairing);
	element_init_Zr(loghZ, scheme_context->global_params->pairing);
	elements_initialized = TRUE;
	
	/* Select randoms generators g, h \in G1, h, g2 \in G2 and secret exponents alpha', alpha'', b \in Zp */
	element_random(scheme_context->public_params.gONE);
	element_random(scheme_context->public_params.gTWO);
	element_random(loghZ);																			/* log_g(h) */
	element_pow_zn(scheme_context->secret_params.hONE, scheme_context->public_params.gONE, loghZ);	/* gONE^log_g(h) */
	element_pow_zn(scheme_context->secret_params.hTWO, scheme_context->public_params.gTWO, loghZ);	/* gTWO^log_g(h) */
	element_random(scheme_context->secret_params.alphaprimeZ);
	element_random(scheme_context->secret_params.alphaprimeprimeZ);
	element_random(scheme_context->secret_params.bZ);
	
	/* Compute g^b, g^{b^2}, h^b, e(g,g)^\alpha, */
	element_pow_zn(scheme_context->public_params.gbONE, scheme_context->public_params.gONE, scheme_context->secret_params.bZ);	/* gbONE = gONE^b */
	element_pow_zn(scheme_context->public_params.gb2ONE, scheme_context->public_params.gbONE, scheme_context->secret_params.bZ); /* gb2ONE = gbONE^b */
	element_pow_zn(scheme_context->public_params.hbONE, scheme_context->secret_params.hONE, scheme_context->secret_params.bZ);	/* hbONE = hONE^b */

	/* Compute e(gONE,gTWO)^(alpha' * alpha'') */
	pairing_apply(eggT, scheme_context->public_params.gONE, scheme_context->public_params.gTWO, scheme_context->global_params->pairing);	/* eggT = e(gONE, gTWO) */
	element_mul(alphaZ, scheme_context->secret_params.alphaprimeZ, scheme_context->secret_params.alphaprimeprimeZ);					/* alphaZ = alphaprimeZ * alphaprimeprimeZ */
	element_pow_zn(scheme_context->public_params.eggalphaT, eggT, alphaZ);															/* eggalphaT = eggT^alpha */

	/* Success */
	result = FENC_ERROR_NONE;
	
cleanup:
	if (elements_initialized == TRUE) {
		/* Destroy any temporary elements. */
		element_clear(eggT);
		element_clear(alphaZ);
		element_clear(loghZ);
	}
	
	return result;
}

/*!
 * Load public and (optionally) secret parameters into the context.  All relevant global
 * parameters are embedded within the public_params data structure.
 *
 * @param context		The fenc_context data structure
 * @param public_params	Public scheme parameters.
 * @param secret_params	Secret scheme parameters (optional).
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR
libfenc_set_params_WatersCP(fenc_context *context, fenc_public_params *public_params, fenc_secret_params *secret_params)
{
	return FENC_ERROR_NOT_IMPLEMENTED;
}

/*!
 * Extract a secret key representing a given function input, which is defined as an access structure.
 * Note that this function will only be called if the secret parameters (MSK) are available within 
 * the context.
 *
 * @param context		The fenc_context data structure
 * @param input			The function input from which this key will be built.
 * @param key			A pre-allocated buffer for the resulting key
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR
libfenc_extract_key_WatersCP(fenc_context *context, fenc_function_input *input, fenc_key *key)
{
	FENC_ERROR					result = FENC_ERROR_UNKNOWN, err_code = FENC_ERROR_NONE;
	fenc_key_WatersCP				*key_WatersCP;
	fenc_attribute_policy		*policy = NULL;
	fenc_attribute_list			attribute_list;
	fenc_scheme_context_WatersCP*	scheme_context;
	int							i;
	element_t					rZ, hashONE, tempONE, temp2ONE, tempZ, temp2Z, tempTWO, temp2TWO;
	Bool						elements_initialized = FALSE;
	
	/* Get the scheme-specific context. */
	scheme_context = (fenc_scheme_context_WatersCP*)context->scheme_context;
	if (scheme_context == NULL) {
		result = FENC_ERROR_INVALID_CONTEXT;
		goto cleanup;
	}
	
	/* Parse the function input as an attribute policy.  This will allocate memory
	 * that will ultimately be released when the key is cleared.				*/
	policy = (fenc_attribute_policy*)SAFE_MALLOC(sizeof(fenc_attribute_policy));
	err_code = libfenc_parse_input_as_attribute_policy(input, policy);
	if (err_code != FENC_ERROR_NONE) {
		LOG_ERROR("libfenc_extract_key_WatersCP: could not parse function input as policy");
		result = FENC_ERROR_INVALID_INPUT;
		goto cleanup;
	}
	
	/* Use the Linear Secret Sharing Scheme (LSSS) to compute an enumerated list of all
	 * attributes and corresponding secret shares.  The shares will be placed into 
	 * a fenc_attribute_list structure that we'll embed within the fenc_key_WatersCP struct.	*/
	memset(&attribute_list, 0, sizeof(fenc_attribute_list));
	err_code = fenc_LSSS_calculate_shares_from_policy(&(scheme_context->secret_params.alphaprimeZ), policy, &attribute_list, 
													  scheme_context->global_params->pairing);
	if (err_code != FENC_ERROR_NONE) {
		LOG_ERROR("libfenc_extract_key_WatersCP: could not calculate shares");
		result = FENC_ERROR_INVALID_INPUT;
		goto cleanup;
	}
	
	/* Initialize the LSW-specific key data structure and allocate some temporary variables.	*/
	key_WatersCP = key_WatersCP_initialize(&attribute_list, policy, FALSE, scheme_context->global_params);
	if (key_WatersCP == NULL) {
		LOG_ERROR("libfenc_extract_key_WatersCP: could not initialize key structure");
		result = FENC_ERROR_INVALID_INPUT;
		goto cleanup;
	}
	element_init_Zr(rZ, scheme_context->global_params->pairing);
	element_init_Zr(tempZ, scheme_context->global_params->pairing);
	element_init_Zr(temp2Z, scheme_context->global_params->pairing);
	element_init_G1(hashONE, scheme_context->global_params->pairing);
	element_init_G1(tempONE, scheme_context->global_params->pairing);
	element_init_G1(temp2ONE, scheme_context->global_params->pairing);
	element_init_G2(tempTWO, scheme_context->global_params->pairing);
	element_init_G2(temp2TWO, scheme_context->global_params->pairing);
	elements_initialized = TRUE;
		 
	/* For every share/attribute, create one component of the secret key.	*/
	for (i = 0; i < (signed int)key_WatersCP->attribute_list.num_attributes; i++) {		
		/* Hash the attribute string to Zr, if it hasn't already been.	*/
		hash_attribute_string_to_Zr(&(key_WatersCP->attribute_list.attribute[i]), scheme_context->global_params);
		
		/* Pick a random value r_i (rZ).	*/
		element_random(rZ);
		
		if (key_WatersCP->attribute_list.attribute[i].is_negated == TRUE) {
			/* For negated attributes, compute:
			 *   D3ONE[i] = gONE^{alphaprimeprimeZ * share[i]} * gb2ONE^{r_i}
			 *   D4TWO[i] = gTWO^{b * r_i * attribute[i]} * hTWO^{r_i}
			 *   D5TWO[i] = gTWO^{- r_i}									*/
			
			/* tempONE = gONE^{alphaprimeprimeZ * share[i]} */
			element_mul(tempZ, scheme_context->secret_params.alphaprimeprimeZ, key_WatersCP->attribute_list.attribute[i].share);
			element_pow_zn(tempONE, scheme_context->public_params.gONE, tempZ);									
			
			/* temp2ONE = gb2ONE^{r_i} --- D3ONE[i] = tempONE * temp2ONE		*/
			element_pow_zn(temp2ONE, scheme_context->public_params.gb2ONE, rZ);									
			element_mul(key_WatersCP->D3ONE[i], tempONE, temp2ONE);
			
			/* tempTWO = gTWO^{b * r_i * attribute[i]}		*/
			element_mul(tempZ, scheme_context->secret_params.bZ, rZ);
			element_mul(temp2Z, tempZ, key_WatersCP->attribute_list.attribute[i].attribute_hash);
			element_pow_zn(tempTWO, scheme_context->public_params.gTWO, temp2Z);
			
			/* temp2TWO = hTWO^{r_i} --- D4TWO[i] = tempTWO * temp2TWO		*/
			element_pow_zn(temp2TWO, scheme_context->secret_params.hTWO, rZ);
			element_mul(key_WatersCP->D4TWO[i], tempTWO, temp2TWO);
			
			/* D5TWO[i] = gTWO^{- r_i}										*/
			element_pow_zn(tempTWO, scheme_context->public_params.gTWO, rZ);
			element_invert(key_WatersCP->D5TWO[i], tempTWO);		/* could be faster	*/
		} else {
			/* For positive (non-negated attributes), compute:
			 *   D1ONE[i] = g^{alphaprimeprimeZ * share[i]} * H(attribute_hash[i])^{r_i}
			 *   D2TWO = g^{r_i}															*/
			
			/* hashONE = H(attribute_hash[i])^{r_i}.			*/
			err_code = hash2_attribute_element_to_G1(&(key_WatersCP->attribute_list.attribute[i].attribute_hash), &tempONE);	/* result in tempONE  */
			DEBUG_ELEMENT_PRINTF("extract key -- hashed to G1: %B\n", tempONE);
			if (err_code != FENC_ERROR_NONE) {
				LOG_ERROR("libfenc_extract_key_WatersCP: could not compute hash2");
				result = FENC_ERROR_UNKNOWN;
				goto cleanup;
			}
			element_pow_zn(hashONE, tempONE, rZ);									
			
			/* tempONE = gONE^(secret_params.alphaprimeprimeZ * share)	*/
			DEBUG_ELEMENT_PRINTF("share %d=%B\n", i, key_WatersCP->attribute_list.attribute[i].share);
			element_mul(tempZ, scheme_context->secret_params.alphaprimeprimeZ, key_WatersCP->attribute_list.attribute[i].share);
			element_pow_zn(tempONE, scheme_context->public_params.gONE, tempZ);									

			/* D1ONE = tempONE * hashONE.	*/
			element_mul(key_WatersCP->D1ONE[i], tempONE, hashONE);
			
			/* D2TWO = g^{r_i}.	*/
			element_pow_zn(key_WatersCP->D2TWO[i], scheme_context->public_params.gTWO, rZ);									
		}
	}
	
	/* Stash the key_WatersCP structure inside of the fenc_key.		*/
	memset(key, 0, sizeof(fenc_key));
	key->scheme_type = FENC_SCHEME_WATERSCP;
	key->valid = TRUE;
	key->scheme_key = (void*)key_WatersCP;
	
	/* Success!		*/
	result = FENC_ERROR_NONE;
	
cleanup:
	/* If there was an error, clean up after ourselves.	*/
	if (result != FENC_ERROR_NONE) {
		if (key_WatersCP != NULL) {
			if (key_WatersCP->policy != NULL)	{ 
				/* TODO: should properly clear up this policy structure if it's a copy.	*/
				SAFE_FREE(key_WatersCP->policy);
				key_WatersCP->policy = NULL;
			}
		
			fenc_attribute_list_clear(&(key_WatersCP->attribute_list));

			/* Clear out the key internals.		*/
			if (elements_initialized == TRUE)	{
				key_WatersCP_clear(key_WatersCP);
			}
		}
	}
	
	/* Wipe out temporary variables.	*/
	if (elements_initialized == TRUE) {
		element_clear(rZ);
		element_clear(hashONE);
		element_clear(tempONE);
		element_clear(temp2ONE);
		element_clear(tempZ);
		element_clear(temp2Z);
		element_clear(tempTWO);
		element_clear(temp2TWO);
	}
	
	return result;
}

/*!
 * Encrypt a plaintext, return a ciphertext.
 *
 * @param context		The fenc_context data structure
 * @param input			The function input under which which the ciphertext will be encrypted.
 * @param plaintext		The plaintext message.
 * @param ciphertext	A pre-allocated buffer for the returned fenc_ciphertext.
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR
libfenc_encrypt_WatersCP(fenc_context *context, fenc_function_input *input, fenc_plaintext *plaintext,
					fenc_ciphertext *ciphertext)
{
	return encrypt_WatersCP_internal(context, input, plaintext, FALSE, NULL, 0, ciphertext);
}

/*!
 * Key encapsulation variant of encryption.  Generate an encryption key and encapsulate it under 
 * a given function input.  Returns the encapsulated key as well as the ciphertext.
 *
 * @param context		The fenc_context data structure
 * @param input			The function input under which which the ciphertext will be encrypted.
 * @param key_len		Desired key size (in bytes).  Will be overwritten with the actual key size.
 * @param key			Pointer to an initialized buffer into which the key will be written.
 * @param ciphertext	A pre-allocated buffer for the returned fenc_ciphertext.
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR
libfenc_kem_encrypt_WatersCP(fenc_context *context, fenc_function_input *input, size_t key_len,
									uint8* key, fenc_ciphertext *ciphertext)
{
	return encrypt_WatersCP_internal(context, input, NULL, TRUE, key, key_len, ciphertext);
}

/*!
 * Decrypt a ciphertext using a specified secret key.
 *
 * @param context		The fenc_context data structure
 * @param ciphertext	The ciphertext to decrypt.
 * @param key			The secret key to use.
 * @param plaintext		A pre-allocated buffer for the resulting plaintext.
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR
libfenc_decrypt_WatersCP(fenc_context *context, fenc_ciphertext *ciphertext, fenc_key *key,
										 fenc_plaintext *plaintext)
{
	FENC_ERROR						result = FENC_ERROR_UNKNOWN, err_code;
	fenc_ciphertext_WatersCP				ciphertext_WatersCP;
	fenc_scheme_context_WatersCP			*scheme_context;
	fenc_key_WatersCP					*key_WatersCP;
	fenc_attribute_list				attribute_list_N;
	fenc_lsss_coefficient_list		coefficient_list;
	element_t						tempGT, temp2GT, tempONE, temp2ONE, temp3ONE, tempZ, temp2Z;
	element_t						temp3GT, temp4GT, prodT, finalT;
	uint32							i, j;
	int32							index_ciph, index_key;
	Bool							elements_initialized = FALSE, coefficients_initialized = FALSE;
	Bool							attribute_list_N_initialized = FALSE;
	
	/* Get the scheme-specific context. */
	scheme_context = (fenc_scheme_context_WatersCP*)context->scheme_context;
	if (scheme_context == NULL) {
		return FENC_ERROR_INVALID_CONTEXT;
	}
	
	/* Obtain the LSW-specific key data structure and make sure it's correct.	*/
	if (key->scheme_key == NULL) {
		LOG_ERROR("libfenc_decrypt_WatersCP: could not obtain scheme-specific decryption key");
		return FENC_ERROR_INVALID_KEY;
	}
	
	/* MDG Hack: Just return a zero decryption for now.	*/
	/* Initialize the plaintext structure.		*/
	err_code = libfenc_plaintext_initialize(plaintext, 16);
	if (err_code != FENC_ERROR_NONE) {
		return err_code;
	}
	
	memset(libfenc_plaintext_get_buf(plaintext), 0, 16);
	plaintext->data_len = 16;
	
	return FENC_ERROR_NONE;
}

/*!
 * Internal function for computing a ciphertext.  In key-encapsulation mode this function
 * returns a key and a buffer.  In standard mode it encrypts a given plaintext.
 *
 * @param context		The fenc_context data structure
 * @param input			The function input under which which the ciphertext will be encrypted.
 * @param plaintext		The plaintext message.
 * @param kem_mode		Set to "TRUE" if using KEM mode, false for normal encryption.
 * @param kem_key_buf	Buffer for the returned session key (KEM mode only).
 * @param kem_key_len	Pointer to a key length; input is desired, overwritten with actual length.
 * @param ciphertext	A pre-allocated buffer for the returned fenc_ciphertext.
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR
encrypt_WatersCP_internal(fenc_context *context, fenc_function_input *input, fenc_plaintext *plaintext,
					 Bool kem_mode, uint8* kem_key_buf, size_t kem_key_len, fenc_ciphertext *ciphertext)
{
	FENC_ERROR result = FENC_ERROR_UNKNOWN, err_code = FENC_ERROR_NONE;
	fenc_scheme_context_WatersCP* scheme_context;
	fenc_ciphertext_WatersCP ciphertext_WatersCP;
	element_t sZ, hashONE, tempZ, plaintextT;
	element_t eggalphasT, tempONE, temp2ONE;
	element_t sxZ[MAX_CIPHERTEXT_ATTRIBUTES];
	uint32 i;
	Bool elements_initialized = FALSE;
	size_t serialized_len = 0;
	fenc_attribute_list attribute_list;
	
	/* Get the scheme-specific context. */
	scheme_context = (fenc_scheme_context_WatersCP*)context->scheme_context;
	if (scheme_context == NULL) {
		return FENC_ERROR_INVALID_CONTEXT;
	}
	
	/* MDG Hack: this is just a dummy encryption.	*/
	if (kem_mode == TRUE) {
		/* In key encapsulation mode we derive a key from eggalphasT.	*/
		memset(kem_key_buf, 0, kem_key_len);
	
		ciphertext_WatersCP.type = FENC_CIPHERTEXT_TYPE_KEM_CPA;
		ciphertext_WatersCP.kem_key_len = kem_key_len;
	} else {
		return FENC_ERROR_UNKNOWN;
	}
	
	serialized_len = 150;
	libfenc_ciphertext_initialize(ciphertext, serialized_len, FENC_SCHEME_WATERSCP);
	memset(ciphertext->data, 0xF, 150);
	ciphertext->data_len = 150;
	
	return FENC_ERROR_NONE;
}

/*!
 * Export the public parameters (MPK) to a binary buffer.  Calling this function with buffer 
 * set to NULL will return the length of the exported material.
 *
 * @param context		The fenc_context data structure
 * @param buffer		A pre-allocated buffer for the resulting export.
 * @param max_len		The maximum allocated size of the buffer (in bytes).
 * @param result_len	The size of the resulting export (in bytes).
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR	libfenc_export_public_params_WatersCP(fenc_context *context, uint8 *buffer, size_t max_len, size_t *result_len)
{
	FENC_ERROR err_code;
	fenc_scheme_context_WatersCP* scheme_context;
	
	/* Get the scheme-specific context. */
	scheme_context = (fenc_scheme_context_WatersCP*)context->scheme_context;
	
	/* Export the elements to the buffer.  Note that if buffer is NULL this routine will
	 * just compute the necessary buffer length.									*/
	err_code = export_components_to_buffer(buffer, max_len, result_len, "%C%C%C%C%C%E",
									   &(scheme_context->public_params.gONE), 
									   &(scheme_context->public_params.gTWO),
									   &(scheme_context->public_params.hbONE),
									   &(scheme_context->public_params.gbONE),
									   &(scheme_context->public_params.gb2ONE),
									   &(scheme_context->public_params.eggalphaT));
	
	return err_code;
}	

/*!
 * Export a context's secret parameters (MSK) to a binary buffer.  Calling this function with buffer 
 * set to NULL will return the length of the exported material.
 *
 * @param context		The fenc_context data structure
 * @param buffer		A pre-allocated buffer for the resulting export.
 * @param max_len		The maximum allocated size of the buffer (in bytes).
 * @param result_len	The size of the resulting export (in bytes).
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR
libfenc_export_secret_params_WatersCP(fenc_context *context, uint8 *buffer, size_t max_len, size_t *result_len)
{
	fenc_scheme_context_WatersCP* scheme_context;
	unsigned char *buf_ptr = (unsigned char*)buffer;
	
	/* Get the scheme-specific context. */
	scheme_context = (fenc_scheme_context_WatersCP*)context->scheme_context;
	
	/* Export the elements to the buffer.  Note that if buffer is NULL this routine will
	 * just compute the necessary buffer length.									*/
	return export_components_to_buffer(buffer, max_len, result_len, "%C%C%E%E%E",
										 &(scheme_context->secret_params.hONE), 
										 &(scheme_context->secret_params.hTWO),
										 &(scheme_context->secret_params.alphaprimeZ),
										 &(scheme_context->secret_params.alphaprimeprimeZ),
										 &(scheme_context->secret_params.bZ));
}	

/*!
 * Import the public parameters (MPK) from a binary buffer.
 *
 * @param context		The fenc_context data structure
 * @param buffer		The buffer.
 * @param max_len		The size of the buffer (in bytes).
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR
libfenc_import_public_params_WatersCP(fenc_context *context, uint8 *buffer, size_t buf_len, fenc_global_params *global_params)
{
	FENC_ERROR err_code;
	fenc_scheme_context_WatersCP* scheme_context;
	size_t bytes_read = 0;
	
	scheme_context = (fenc_scheme_context_WatersCP*)context->scheme_context;
	if (scheme_context == NULL) {
		return FENC_ERROR_INVALID_CONTEXT;
	}
	
	/* Sanity check: Make sure that we have initialized group/global parameters.		*/
	if (scheme_context->global_params == NULL) {
		LOG_ERROR("libfenc_import_public_params_WatersCP: global/group parameters are not set");
		return FENC_ERROR_INVALID_GLOBAL_PARAMS;
	}
	
	/* Initialize the public parameters, allocating group elements.		*/
	public_params_initialize_WatersCP(&(scheme_context->public_params), scheme_context->global_params->pairing);

	/* Import the elements from the buffer.								*/
	return import_components_from_buffer(buffer, buf_len, "%C%C%C%C%C%E",
										 &(scheme_context->public_params.gONE), 
										 &(scheme_context->public_params.gTWO),
										 &(scheme_context->public_params.hbONE),
										 &(scheme_context->public_params.gbONE),
										 &(scheme_context->public_params.gb2ONE),
										 &(scheme_context->public_params.eggalphaT));
}

/*!
 * Import the secret parameters (MPK) from a binary buffer.
 *
 * @param context		The fenc_context data structure
 * @param buffer		The buffer.
 * @param max_len		The size of the buffer (in bytes).
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR
libfenc_import_secret_params_WatersCP(fenc_context *context, uint8 *buffer, size_t buf_len)
{
	FENC_ERROR err_code;
	fenc_scheme_context_WatersCP* scheme_context;
	
	scheme_context = (fenc_scheme_context_WatersCP*)context->scheme_context;
	if (scheme_context == NULL) {
		return FENC_ERROR_INVALID_CONTEXT;
	}
	
	/* Initialize the secret parameters, allocating group elements.		*/
	secret_params_initialize_WatersCP(&(scheme_context->secret_params), scheme_context->global_params->pairing);
	
	return import_components_from_buffer(buffer, buf_len, "%C%C%E%E%E",
										 &(scheme_context->secret_params.hONE), 
										 &(scheme_context->secret_params.hTWO),
										 &(scheme_context->secret_params.alphaprimeZ),
										 &(scheme_context->secret_params.alphaprimeprimeZ),
										 &(scheme_context->secret_params.bZ));
}


/*!
 * Import the global parameters (MPK) from a binary buffer.
 *
 * @param context		The fenc_context data structure
 * @param buffer		The buffer.
 * @param max_len		The size of the buffer (in bytes).
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR
libfenc_import_global_params_WatersCP(fenc_context *context, uint8 *buffer, size_t buf_len)
{
	FENC_ERROR err_code;
	fenc_scheme_context_WatersCP* scheme_context;
	size_t bytes_read = 0;
	fenc_group_params group_params;
	
	scheme_context = (fenc_scheme_context_WatersCP*)context->scheme_context;
	if (scheme_context == NULL) {
		return FENC_ERROR_INVALID_CONTEXT;
	}
	
	/* Read the global parameters out of the buffer, if they're in there.	*/
	err_code = libfenc_load_group_params_from_buf(&(group_params), buffer, buf_len);
	if (err_code != FENC_ERROR_NONE) {
		LOG_ERROR("libfenc_import_global_params_WatersCP: could not read group params");
		return FENC_ERROR_INVALID_GLOBAL_PARAMS;
	}
	
	/* Initialize the scheme's global parameters.	*/
	scheme_context->global_params = initialize_global_params_WatersCP(&group_params, scheme_context->global_params);
	
	return err_code;
}

/*!
 * Export the global parameters to a binary buffer.  Calling this function with buffer 
 * set to NULL will return the length of the exported material.
 *
 * @param context		The fenc_context data structure
 * @param buffer		A pre-allocated buffer for the resulting export.
 * @param max_len		The maximum allocated size of the buffer (in bytes).
 * @param result_len	The size of the resulting export (in bytes).
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR	
libfenc_export_global_params_WatersCP(fenc_context *context, uint8 *buffer, size_t max_len, size_t *result_len)
{
	FENC_ERROR err_code;
	fenc_scheme_context_WatersCP* scheme_context;
	size_t params_len;
	
	/* Get the scheme-specific context. */
	scheme_context = (fenc_scheme_context_WatersCP*)context->scheme_context;
	
	/* Export the group parameters to the buffer.  If th buffer is NULL this only compute the length.		*/
	err_code = libfenc_export_group_params(&(scheme_context->global_params->group_params), buffer, max_len, result_len);
	
	return err_code;
}	

/**************************************************************************************
 * Utility functions
 **************************************************************************************/
	
/*!
 * Destroy the internal contents of a fenc_context structure.  The caller is responsible for
 * de-allocating the context buffer itself.
 *
 * @param context		The fenc_context data structure.
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR	
libfenc_destroy_context_WatersCP(fenc_context *context)
{
	FENC_ERROR result = FENC_ERROR_UNKNOWN;
	fenc_scheme_context_WatersCP *scheme_context;
	
	scheme_context = (fenc_scheme_context_WatersCP*)context->scheme_context;
	
	/* Destroy the scheme-specific context structure */
	if (scheme_context != NULL) {
		/* Destroy the internal global parameters.	*/
		if (scheme_context->global_params != NULL) {
			SAFE_FREE(scheme_context->global_params);
		}
		
		memset(context->scheme_context, 0, sizeof(fenc_scheme_context_WatersCP) );
		SAFE_FREE(context->scheme_context);
	}
	
	/* Other destruction operations go here... */
	result = FENC_ERROR_NONE;
	
	return result;
}

/*!
 * Destroy the internal contents of a fenc_context structure.  The caller is responsible for
 * de-allocating the context buffer itself.
 *
 * @param global_params	The global parameters.
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR
libfenc_destroy_global_params_WatersCP(fenc_global_params *global_params)
{
	return FENC_ERROR_NOT_IMPLEMENTED;
}

/*!
 * Validate a set of global parameters for the LSW scheme.
 *
 * @param global_params	The global parameters.
 * @return				FENC_ERROR_NONE or an error code.
 */

FENC_ERROR
libfenc_validate_global_params_WatersCP(fenc_global_params *global_params)
{
	FENC_ERROR result;
	
	/* Sanity check -- make sure the global_params exist. */
	if (global_params == NULL) {
		return FENC_ERROR_INVALID_GLOBAL_PARAMS;
	}
	
	/* Utility call --- check that bilinear group parameters have
	 * been loaded into global_params.  We might someday want to require
	 * a specific class of group parameters, but for the moment we're ok. */
	result = libfenc_validate_group_params(global_params->group_params);
	
	/* Since there are no other global parameters in the LSW scheme, we're done. */
	return result;
}

/*!
 * Serialize a decryption key to a binary buffer.  Accepts an LSW key, buffer, and buffer length.
 * If the buffer is large enough, the serialized result is written to the buffer and returns the
 * length in "serialized_len".  Calling with a NULL buffer returns the length /only/ but does
 * not actually serialize the structure.
 *
 * @param key				The key to serialize.
 * @param buffer			Pointer to a buffer, or NULL to get the length only.
 * @param max_len			The maximum size of the buffer (in bytes).
 * @param serialized_len	Total size of the serialized structure (in bytes).
 * @return					FENC_ERROR_NONE or FENC_ERROR_BUFFER_TOO_SMALL.
 */

FENC_ERROR
libfenc_serialize_key_WatersCP(fenc_key_WatersCP *key, unsigned char *buffer, size_t max_len, size_t *serialized_len)
{
	FENC_ERROR err_code = FENC_ERROR_NONE;
	unsigned char *buf_ptr = (unsigned char*)buffer;
	char *policy_str;
	size_t str_index = 0, str_len = MAX_POLICY_STR - 1, result_len = 0;
	uint32 i;

	/* Export the policy, result length, number of components in the key.	*/
	err_code = export_components_to_buffer(buf_ptr, max_len, &result_len, "%P%A%d",
										   key->policy,
										   &(key->attribute_list),
										   key->num_components);
	if (err_code != FENC_ERROR_NONE) {
		return err_code;
	}
	*serialized_len += result_len;
	if (buffer != NULL) {	buf_ptr = buffer + *serialized_len;	}
	max_len -= result_len;	/* TODO: may be a problem.	*/
	
	/* Now output each component of the key.								*/
	for (i = 0; i < key->num_components; i++) {
		/* Export the five group elements that correspond to an element.	*/
		if (key->attribute_list.attribute[i].is_negated == FALSE) {
			err_code = export_components_to_buffer(buf_ptr, max_len, &result_len, "%C%C",
												   &(key->D1ONE[i]),
												   &(key->D2TWO[i]));
		} else {
			err_code = export_components_to_buffer(buf_ptr, max_len, &result_len, "%C%C%C",
												   &(key->D3ONE[i]),
												   &(key->D4TWO[i]),
												   &(key->D5TWO[i]));
		}
		
		if (err_code != FENC_ERROR_NONE) {
			return err_code;
		}
		
		*serialized_len += result_len;
		if (buffer != NULL) {	buf_ptr = buffer + *serialized_len;	}
		max_len -= result_len;	/* TODO: may be a problem.	*/
	}
	
	/* All done.	*/
	return err_code;
}

/*!
 * Serialize a ciphertext to a binary buffer.  Accepts an LSW ciphertext, buffer, and buffer length.
 * If the buffer is large enough, the serialized result is written to the buffer and returns the
 * length in "serialized_len".  Calling with a NULL buffer returns the length /only/ but does
 * not actually serialize the structure.
 *
 * @param ciphertext		The ciphertext to serialize.
 * @param buffer			Pointer to a buffer, or NULL to get the length only.
 * @param max_len			The maximum size of the buffer (in bytes).
 * @param serialized_len	Total size of the serialized structure (in bytes).
 * @return					FENC_ERROR_NONE or FENC_ERROR_BUFFER_TOO_SMALL.
 */

FENC_ERROR
libfenc_serialize_ciphertext_WatersCP(fenc_ciphertext_WatersCP *ciphertext, unsigned char *buffer, size_t max_len, size_t *serialized_len)
{
	int i;
	unsigned char *buf_ptr = (unsigned char*)buffer;
	uint32 type, kem_key_len;
	
	/* First, compute the length (in bytes) of the serialized ciphertext, then (if buffer is non-null)
	 * and there's sufficient room, serialize the value into the buffer. */
	*serialized_len = 0;
	*serialized_len += sizeof(uint32);												/* ciphertext type	*/
	if (buffer != NULL && *serialized_len <= max_len) {
		type = ciphertext->type;
		EXPORT_INT32(buf_ptr, (uint32)type);
		buf_ptr = buffer + *serialized_len;
	}
	
	if (ciphertext->type == FENC_CIPHERTEXT_TYPE_KEM_CPA)	{						/* KEM session key size */
		*serialized_len += sizeof(uint32);												/* only in KEM mode	*/
		if (buffer != NULL && *serialized_len <= max_len) {
			kem_key_len = ciphertext->kem_key_len;
			EXPORT_INT32(buf_ptr, kem_key_len);
			buf_ptr = buffer + *serialized_len;
		}
	}
	
	*serialized_len += sizeof(ciphertext->attribute_list.num_attributes);			/* num_attributes	*/
	if (buffer != NULL && *serialized_len <= max_len) {
		EXPORT_INT32(buf_ptr, ciphertext->attribute_list.num_attributes);
		buf_ptr = buffer + *serialized_len;
	}
	
	if (ciphertext->type == FENC_CIPHERTEXT_TYPE_CPA)	{
		*serialized_len += element_length_in_bytes(ciphertext->E1T);				/* E1T	(skipped in KEM mode!)	*/
		if (buffer != NULL && *serialized_len <= max_len) {
			element_to_bytes(buf_ptr, ciphertext->E1T);
			buf_ptr = buffer + *serialized_len;
		}
	}
	
	*serialized_len += element_length_in_bytes_compressed(ciphertext->E2TWO);		/* E2TWO			*/
	if (buffer != NULL && *serialized_len <= max_len) {
		element_to_bytes_compressed(buf_ptr, ciphertext->E2TWO);
		buf_ptr = buffer + *serialized_len;
	}

	/* For every attribute in the ciphertext... */
	for (i = 0; i < ciphertext->attribute_list.num_attributes; i++) {
		*serialized_len += element_length_in_bytes(ciphertext->attribute_list.attribute[i].attribute_hash);			/* attribute[i]		*/
		if (buffer != NULL && *serialized_len <= max_len) {
			element_to_bytes(buf_ptr, ciphertext->attribute_list.attribute[i].attribute_hash);
			buf_ptr = buffer + *serialized_len;
		}
		
		*serialized_len += element_length_in_bytes_compressed(ciphertext->E3ONE[i]);	/* E3ONE[i]		*/
		if (buffer != NULL && *serialized_len <= max_len) {
			element_to_bytes_compressed(buf_ptr, ciphertext->E3ONE[i]);
			buf_ptr = buffer + *serialized_len;
		}
		
		*serialized_len += element_length_in_bytes_compressed(ciphertext->E4ONE[i]);	/* E4ONE[i]		*/
		if (buffer != NULL && *serialized_len <= max_len) {
			element_to_bytes_compressed(buf_ptr, ciphertext->E4ONE[i]);
			buf_ptr = buffer + *serialized_len;
		}
		
		*serialized_len += element_length_in_bytes_compressed(ciphertext->E5ONE[i]);	/* E5ONE[i]		*/
		if (buffer != NULL && *serialized_len <= max_len) {
			element_to_bytes_compressed(buf_ptr, ciphertext->E5ONE[i]);
			buf_ptr = buffer + *serialized_len;
		}
	}
	
	/* If the buffer pointer is NULL, we're done --- just return the length. */
	if (buffer == NULL) {
		return FENC_ERROR_NONE;
	}
	
	/* If the serialized length was too large for the buffer, return an error. */
	if (*serialized_len > max_len) {
		return FENC_ERROR_BUFFER_TOO_SMALL;
	}
	
	/* Return success. */
	return FENC_ERROR_NONE;
}

/*!
 * Deserialize a ciphertext from a binary buffer.  Accepts a buffer and buffer length and
 * transcribes the result into an LSW ciphertext data structure.  
 *
 * Note: this routine uses deserialization functionality from the PBC library; this could
 * fail catastrophically when given an invalid ciphertext.
 *
 * @param buffer			Pointer to a buffer from which to deserialize.
 * @param buf_len			The size of the buffer (in bytes).
 * @param ciphertext		The fenc_ciphertext_WatersCP structure.
 * @param scheme_context	The scheme context which contains the group parameters.
 * @return					FENC_ERROR_NONE or FENC_ERROR_BUFFER_TOO_SMALL.
 */

FENC_ERROR
libfenc_deserialize_ciphertext_WatersCP(unsigned char *buffer, size_t buf_len, fenc_ciphertext_WatersCP *ciphertext, fenc_scheme_context_WatersCP *scheme_context)
{
	int i;
	size_t deserialized_len;
	uint32 num_attributes, type, kem_key_len;
	FENC_ERROR result = FENC_ERROR_UNKNOWN, err_code;
	unsigned char *buf_ptr = buffer;
	
	deserialized_len = 0;
	deserialized_len += sizeof(uint32);								/* ciphertext type	*/
	if (deserialized_len <= buf_len) {
		IMPORT_INT32(type, buf_ptr);
		buf_ptr = buffer + deserialized_len;
	}
	
	if (type == FENC_CIPHERTEXT_TYPE_KEM_CPA)	{					/* KEM session key size */
		deserialized_len += sizeof(uint32);							/* only in KEM mode		*/
		if (deserialized_len <= buf_len) {
			IMPORT_INT32(kem_key_len, buf_ptr);
			buf_ptr = buffer + deserialized_len;
		}
	}
	
	deserialized_len += sizeof(num_attributes);						/* num_attributes	*/
	if (deserialized_len <= buf_len) {
		IMPORT_INT32(num_attributes, buf_ptr);
		buf_ptr = buffer + deserialized_len;
	}
	
	/* Sanity check: make sure the number of attributes is non-zero, but not too big. */
	if (num_attributes < 1 || num_attributes > MAX_CIPHERTEXT_ATTRIBUTES) {
		return FENC_ERROR_INVALID_CIPHERTEXT;
	}
	
	/* Initialize the elements of the LSW ciphertext data structure.  This allocates all of the group elements
	 * and sets the num_attributes member.		*/
	err_code = fenc_ciphertext_WatersCP_initialize(ciphertext, num_attributes, type, scheme_context);
	if (err_code != FENC_ERROR_NONE) {
		/* Couldn't allocate the structure.  Don't even try to cleanup --- this is a really bad situation! */
		LOG_ERROR("lifenc_deserialize_ciphertext_WatersCP: couldn't initialize ciphertext");
		return err_code;
	}
	ciphertext->kem_key_len = kem_key_len;
	
	/* Initialize the attribute list.	*/
	err_code = fenc_attribute_list_initialize(&(ciphertext->attribute_list), num_attributes);
	if (err_code != FENC_ERROR_NONE) {
		LOG_ERROR("lifenc_deserialize_ciphertext_WatersCP: couldn't initialize attribute list");
		return err_code;
	}
	
	/* Read in the ciphertext components.								*/	
	if (ciphertext->type == FENC_CIPHERTEXT_TYPE_CPA)	{
		deserialized_len += element_from_bytes(ciphertext->E1T, buf_ptr);				/* E1T				*/
		if (deserialized_len > buf_len) {											
			result = FENC_ERROR_BUFFER_TOO_SMALL;
			goto cleanup;
		}
		buf_ptr = buffer + deserialized_len;
	}
	
	deserialized_len += element_from_bytes_compressed(ciphertext->E2TWO, buf_ptr);	/* E2TWO			*/
	if (deserialized_len > buf_len) {											
		result = FENC_ERROR_BUFFER_TOO_SMALL;
		goto cleanup;
	}
	buf_ptr = buffer + deserialized_len;
	
	/* For every attribute in the ciphertext... */
	for (i = 0; i < ciphertext->attribute_list.num_attributes; i++) {
		memset(&(ciphertext->attribute_list.attribute[i]), 0, sizeof(fenc_attribute));
		element_init_Zr(ciphertext->attribute_list.attribute[i].attribute_hash, scheme_context->global_params->pairing);
		deserialized_len += element_from_bytes(ciphertext->attribute_list.attribute[i].attribute_hash, buf_ptr);			/* attribute[i]		*/
		if (deserialized_len > buf_len) {											
			result = FENC_ERROR_BUFFER_TOO_SMALL;
			goto cleanup;
		}
		ciphertext->attribute_list.attribute[i].is_hashed = TRUE;
		buf_ptr = buffer + deserialized_len;
		
		deserialized_len += element_from_bytes_compressed(ciphertext->E3ONE[i], buf_ptr);	/* E3ONE[i]			*/
		if (deserialized_len > buf_len) {											
			result = FENC_ERROR_BUFFER_TOO_SMALL;
			goto cleanup;
		}
		buf_ptr = buffer + deserialized_len;
		
		deserialized_len += element_from_bytes_compressed(ciphertext->E4ONE[i], buf_ptr);	/* E4ONE[i]			*/
		if (deserialized_len > buf_len) {											
			result = FENC_ERROR_BUFFER_TOO_SMALL;
			goto cleanup;
		}
		buf_ptr = buffer + deserialized_len;
		
		deserialized_len += element_from_bytes_compressed(ciphertext->E5ONE[i], buf_ptr);	/* E5ONE[i]			*/
		if (deserialized_len > buf_len) {											
			result = FENC_ERROR_BUFFER_TOO_SMALL;
			goto cleanup;
		}
		buf_ptr = buffer + deserialized_len;
	}
	
	/* Success!	*/
	result = FENC_ERROR_NONE;
	
cleanup:
	/* If the deserialization failed, de-allocate any elements we initialized. */
	if (result != FENC_ERROR_NONE) {
		fenc_ciphertext_WatersCP_clear(ciphertext);
	}
	
	/* Return the result. */
	return result;
}

/*!
 * Utility function to allocate the internals of a fenc_ciphertext_WatersCP structure.  
 *
 * @param ciphertext		Pointer to fenc_ciphertext_WatersCP struct.
 * @param num_attributes	Number of attributes.
 * @param scheme_context	Pointer to a fenc_scheme_context_WatersCP struct.
 * @return					FENC_ERROR_NONE or an error code.
 */

FENC_ERROR
fenc_ciphertext_WatersCP_initialize(fenc_ciphertext_WatersCP *ciphertext, uint32 num_attributes, FENC_CIPHERTEXT_TYPE type,
							   fenc_scheme_context_WatersCP *scheme_context)
{
	int i;
	
	memset(ciphertext, 0, sizeof(fenc_ciphertext_WatersCP));
	element_init_GT(ciphertext->E1T, scheme_context->global_params->pairing);
	element_set1(ciphertext->E1T);
	element_init_G2(ciphertext->E2TWO, scheme_context->global_params->pairing);
	for (i = 0; i < num_attributes; i++) {
		element_init_G1(ciphertext->E3ONE[i], scheme_context->global_params->pairing);
		element_init_G1(ciphertext->E4ONE[i], scheme_context->global_params->pairing);
		element_init_G1(ciphertext->E5ONE[i], scheme_context->global_params->pairing);
	}
	ciphertext->type = type;
	
	return FENC_ERROR_NONE;
}

/*!
 * Utility function to release the internals of a fenc_ciphertext_WatersCP structure.  
 *
 * @param ciphertext		Pointer to fenc_ciphertext_WatersCP struct.
 * @return					FENC_ERROR_NONE or an error code.
 */

FENC_ERROR
fenc_ciphertext_WatersCP_clear(fenc_ciphertext_WatersCP *ciphertext)
{
	int i;
	
	/* Make sure the number of attributes is reasonable (if not, this is an invalid ciphertext).	*/
	if (ciphertext->attribute_list.num_attributes < 1 || ciphertext->attribute_list.num_attributes > MAX_CIPHERTEXT_ATTRIBUTES) {
		LOG_ERROR("fenc_ciphertext_WatersCP_clear: ciphertext has an invalid number of attributes"); 
		return FENC_ERROR_UNKNOWN;
	}
	
	/* Release all of the internal elements.  Let's hope the ciphertext was correctly inited! */
	element_clear(ciphertext->E1T);
	element_clear(ciphertext->E2TWO);
	for (i = 0; i < ciphertext->attribute_list.num_attributes; i++) {
		element_clear(ciphertext->E3ONE[i]);
		element_clear(ciphertext->E4ONE[i]);
		element_clear(ciphertext->E5ONE[i]);
	}
	
	/* Release the attribute list if one has been allocated. */
	fenc_attribute_list_clear(&(ciphertext->attribute_list));

	memset(ciphertext, 0, sizeof(fenc_ciphertext_WatersCP));
	
	return FENC_ERROR_NONE;
}

/*!
 * Initialize and allocate a fenc_global_params_WatersCP structure.
 *
 * @param	group_params		A fenc_group_params structure.
 * @param	global_params		An allocated fenc_global_params_WatersCP or NULL if one should be allocated.
 * @return	An allocated fenc_global_params_WatersCP structure.
 */

fenc_global_params_WatersCP*
initialize_global_params_WatersCP(fenc_group_params *group_params, fenc_global_params_WatersCP *global_params)
{
	FENC_ERROR err_code;
	
	/* If we need to, allocate a new set of global params for the LSW scheme.	*/
	if (global_params == NULL) {	
		global_params = SAFE_MALLOC(sizeof(fenc_global_params_WatersCP));
		if (global_params == NULL) {
			LOG_ERROR("initialize_global_params_WatersCP: out of memory");
			return NULL;
		}
	}
	
	err_code = libfenc_copy_group_params(group_params, &(global_params->group_params));
	if (err_code != FENC_ERROR_NONE) {
		LOG_ERROR("libfenc_gen_params_WatersCP: could not copy parameters");
		return NULL;
	}
	
	err_code = libfenc_get_pbc_pairing(group_params, global_params->pairing);
	if (err_code != FENC_ERROR_NONE) {
		LOG_ERROR("libfenc_gen_params_WatersCP: could not obtain pairing structure");
		return NULL;
	}
	
	return global_params;
}

/*!
 * Allocates and initializes a fenc_key_WatersCP structure.
 *
 * @param key_WatersCP			The fenc_key_WatersCP structure.
 * @param attribute_list	Pointer to a fenc_attribute_list structure.
 * @param policy			Pointer to a fenc_policy structure (the internals are /not/ duplicated).
 * @param copy_attr_list	If set to TRUE, duplicates the internals of the attribute list (original can be cleared).
 * @param global_params		Pointer to the group params (necessary for allocating internal elements).
 * @return					The fenc_key_WatersCP structure or NULL.
 */

fenc_key_WatersCP*
key_WatersCP_initialize(fenc_attribute_list *attribute_list, fenc_attribute_policy *policy, Bool copy_attr_list, 
				   fenc_global_params_WatersCP *global_params)
{
	FENC_ERROR err_code;
	int i;
	fenc_key_WatersCP *key_WatersCP;
				
	/* Initialize and wipe the key structure.	*/
	key_WatersCP = (fenc_key_WatersCP*)SAFE_MALLOC(sizeof(fenc_key_WatersCP));
	if (key_WatersCP == NULL) {
		LOG_ERROR("key_WatersCP_initialize: out of memory");
		return NULL;
	}
	memset(key_WatersCP, 0, sizeof(fenc_key_WatersCP));
	key_WatersCP->reference_count = 1;
	
	/* Copy the attribute list structure into the key.  If copy_attr_list is TRUE we
	 * call fenc_attribute_list_copy() to duplicate all of the internals.  Otherwise
	 * we just copy the top-level structure.	*/
	if (copy_attr_list == FALSE) {
		memcpy(&(key_WatersCP->attribute_list), attribute_list, sizeof(fenc_attribute_list));
		key_WatersCP->attribute_list.num_attributes = attribute_list->num_attributes;
	} else {
		err_code = fenc_attribute_list_copy(&(key_WatersCP->attribute_list), attribute_list, global_params->pairing);
		if (err_code != FENC_ERROR_NONE) {
			return NULL;
		}
	}
						   
	/* Copy the policy structure into the key.	*/
	key_WatersCP->policy = policy;
	
	/* Allocate the internal group elements.	*/
	key_WatersCP->num_components = attribute_list->num_attributes;
	for (i = 0; i < key_WatersCP->attribute_list.num_attributes; i++) {
		element_init_G1(key_WatersCP->D1ONE[i], global_params->pairing);
		element_init_G2(key_WatersCP->D2TWO[i], global_params->pairing);
		element_init_G1(key_WatersCP->D3ONE[i], global_params->pairing);
		element_init_G2(key_WatersCP->D4TWO[i], global_params->pairing);
		element_init_G2(key_WatersCP->D5TWO[i], global_params->pairing);
	}
	
	return key_WatersCP;
}


/*!
 * Deallocate and clear the internals of a fenc_key_WatersCP structure.
 *
 * @param key_WatersCP			The fenc_key_WatersCP structure.
 * @return					FENC_ERROR_NONE or an error code.
 */

FENC_ERROR
key_WatersCP_clear(fenc_key_WatersCP *key_WatersCP)
{	
	int i;
	
	for (i = 0; i < key_WatersCP->attribute_list.num_attributes; i++) {
		element_clear(key_WatersCP->D1ONE[i]);
		element_clear(key_WatersCP->D2TWO[i]);
		element_clear(key_WatersCP->D3ONE[i]);
		element_clear(key_WatersCP->D4TWO[i]);
		element_clear(key_WatersCP->D5TWO[i]);
	}
	
	if (key_WatersCP->reference_count <= 1) {
		SAFE_FREE(key_WatersCP);
	} else {
		key_WatersCP->reference_count--;
	}
	
	return FENC_ERROR_NONE;
}

/*!
 * Initialize a fenc_public_params_WatersCP structure.  This requires initializing
 * a series of group element structures.
 *
 * @param params			Pointer to a fenc_public_params_WatersCP data structure.
 * @param pairing			Pairing structure.
 * @return					FENC_ERROR_NONE or an error code.
 */

FENC_ERROR
public_params_initialize_WatersCP(fenc_public_params_WatersCP *params, pairing_t pairing)
{
	memset(params, 0, sizeof(fenc_public_params_WatersCP));
	
	element_init_G1(params->gONE, pairing);
	element_init_G2(params->gTWO, pairing);
	element_init_G1(params->hbONE, pairing);
	element_init_G1(params->gbONE, pairing);
	element_init_G1(params->gb2ONE, pairing);
	element_init_GT(params->eggalphaT, pairing);
	
	return FENC_ERROR_NONE;
}

/*!
 * Initialize a fenc_secret_params_WatersCP structure.  This requires initializing
 * a series of group element structures.
 *
 * @param params			Pointer to a fenc_secret_params_WatersCP data structure.
 * @param pairing			Pairing structure.
 * @return					FENC_ERROR_NONE or an error code.
 */

FENC_ERROR
secret_params_initialize_WatersCP(fenc_secret_params_WatersCP *params, pairing_t pairing)
{
	memset(params, 0, sizeof(fenc_secret_params_WatersCP));

	element_init_G1(params->hONE, pairing);
	element_init_G2(params->hTWO, pairing);
	element_init_Zr(params->alphaprimeZ, pairing);
	element_init_Zr(params->alphaprimeprimeZ, pairing);
	element_init_Zr(params->bZ, pairing);
	
	return FENC_ERROR_NONE;
}

/*!
 * Print a ciphertext to a file as ASCII.
 *
 * @param ciphertext		The ciphertext to serialize.
 * @param out_file			The file to write to.
 * @return					FENC_ERROR_NONE or an error code.
 */

FENC_ERROR
libfenc_fprint_ciphertext_WatersCP(fenc_ciphertext_WatersCP *ciphertext, FILE* out_file)
{
	int i;
	
	fprintf(out_file, "number of attributes = %d\n", ciphertext->attribute_list.num_attributes);

	element_fprintf(out_file, "E1T = %B\n", ciphertext->E1T);
	element_fprintf(out_file, "E2TWO = %B\n", ciphertext->E2TWO);
	
	/* For every attribute in the ciphertext... */
	for (i = 0; i < ciphertext->attribute_list.num_attributes; i++) {
		fprintf(out_file, "Attribute #%d:\n", i);
		if (strlen(ciphertext->attribute_list.attribute[i].attribute_str) > 0) {
			fprintf(out_file, "\tAttribute = \"%s\"\n", ciphertext->attribute_list.attribute[i].attribute_str);
		}
		element_fprintf(out_file, "\tAttribute Hash = %B\n", ciphertext->attribute_list.attribute[i].attribute_hash);
		
		element_fprintf(out_file, "\tE3ONE[%d] = %B\n", i, ciphertext->E3ONE[i]);
		element_fprintf(out_file, "\tE4ONE[%d] = %B\n", i, ciphertext->E4ONE[i]);
		element_fprintf(out_file, "\tE5ONE[%d] = %B\n", i, ciphertext->E5ONE[i]);
	}
	
	/* Return success. */
	return FENC_ERROR_NONE;
}

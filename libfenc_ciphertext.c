/*!	\file libfenc_ciphertext.h
 *
 *	\brief Routines that deal with ciphertext data structures.
 *  
 *	Copyright 2009 Matthew Green. All rights reserved.
 */

#include "libfenc.h"
#include "libfenc_ciphertext.h"

/********************************************************************************
 * Utility functions
 ********************************************************************************/

/*!
 * Serialize a .
 *
 * @param param_buf				Buffer containing parameters
 * @return						FENC_ERROR_NONE or an error code.
 */

FENC_ERROR
libfenc_setup_from_pbc_params(fenc_group_params *group_params, 
										  char *param_buf, size_t param_len)
{
	FENC_ERROR result = FENC_ERROR_UNKNOWN;
	
	pairing_init_inp_buf(group_params->pairing, param_buf, param_len);
	result = FENC_ERROR_NONE;
	
	return result;
}

/*!
 * Load parameters from file.
 *
 * @param group_params		parameters data structure
 * @param fp				file pointer
 * @return					FENC_ERROR_NONE or an error code.
 */

FENC_ERROR
libfenc_load_group_params_from_str(fenc_group_params *group_params, FILE *fp)
{
	pairing_init_inp_str(group_params->pairing, fp);
	
	/* TODO: How do we tell if this routine has failed? */
	return FENC_ERROR_NONE;
}

/*!
 * Duplicate a group parameters structure.  This will involve memory allocation for
 * any internal structures; the duplicate structure must be destroyed to reclaim
 * this memory.  Caller must allocate the destination data structure.
 *
 * @param src_group_params		Input group parameters.
 * @param dest_group_params		Pre-allocated buffer for the destination parameters.
 * @return						FENC_ERROR_NONE or an error code.
 */

FENC_ERROR
libfenc_copy_group_params(fenc_group_params *src_group_params, 
									  fenc_group_params *dest_group_params)
{
	if (src_group_params == NULL || dest_group_params == NULL) {
		return FENC_ERROR_INVALID_GROUP_PARAMS;
	}
	
	dest_group_params->pairing[0] = src_group_params->pairing[0];
	
	return FENC_ERROR_NONE;
}

/*!
 * Destroy a group parameters structure.  This will de-allocate internal data
 * structures.  It does not de-allocate the structure itself.
 *
 * @param group_params		Group parameters.
 * @return					FENC_ERROR_NONE or an error code.
 */

FENC_ERROR
libfenc_destroy_group_params(fenc_group_params *group_params)
{
	/* TODO: This may not be the safest */
	memset(group_params->pairing, 0, sizeof(pairing_s));
		   
	return FENC_ERROR_NONE;
}
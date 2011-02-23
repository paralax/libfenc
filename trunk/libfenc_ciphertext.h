/*!	\file libfenc_ciphertext.h
 *
 *	\brief .
 *
 *	Copyright 2009 Matthew Green. All rights reserved.
 */

#ifndef __LIBFENC_CIPHERTEXT_H__
#define __LIBFENC_CIPHERTEXT_H__

#include "libfenc.h"

/*!
 * Serialize a .
 *
 * @param param_buf				Buffer containing parameters
 * @return						FENC_ERROR_NONE or an error code.
 */
FENC_ERROR libfenc_setup_from_pbc_params(fenc_group_params *group_params, char *param_buf, size_t param_len);

/*!
 * Load parameters from file.
 *
 * @param group_params		parameters data structure
 * @param fp				file pointer
 * @return					FENC_ERROR_NONE or an error code.
 */
FENC_ERROR libfenc_load_group_params_from_str(fenc_group_params *group_params, FILE *fp);

/*!
 * Duplicate a group parameters structure.  This will involve memory allocation for
 * any internal structures; the duplicate structure must be destroyed to reclaim
 * this memory.  Caller must allocate the destination data structure.
 *
 * @param src_group_params		Input group parameters.
 * @param dest_group_params		Pre-allocated buffer for the destination parameters.
 * @return						FENC_ERROR_NONE or an error code.
 */

FENC_ERROR libfenc_copy_group_params(fenc_group_params *src_group_params, fenc_group_params *dest_group_params);

/*!
 * Destroy a group parameters structure.  This will de-allocate internal data
 * structures.  It does not de-allocate the structure itself.
 *
 * @param group_params		Group parameters.
 * @return					FENC_ERROR_NONE or an error code.
 */

FENC_ERROR libfenc_destroy_group_params(fenc_group_params *group_params);

#endif /* ifdef __LIBFENC_CIPHERTEXT_H__ */

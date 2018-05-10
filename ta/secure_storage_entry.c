#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include "string.h"
#include "ta_secure_storage.h"

/*
 * Input params:
 * param#0 : input key pair gen mechanism
 * param#1 : input serialized object attributes buffer
 * param#2 : output object ID
 * param#3 : not used
 */
static TEE_Result TA_GenerateKeyPair(uint32_t param_types, TEE_Param params[4])
{
	TEE_Result res;
	TEE_ObjectHandle tObject = TEE_HANDLE_NULL;
	uint32_t obj_type, obj_size, obj_id = 0;

	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);
	if (param_types != exp_param_types) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	DMSG("TA_GenerateKeyPair started!\n");
	obj_type = TEE_TYPE_RSA_KEYPAIR;
	obj_size = 2048;

	DMSG("Allocate Transient Object!\n");
	res = TEE_AllocateTransientObject(obj_type, obj_size, &tObject);
	if (res != TEE_SUCCESS)
		goto out;

	DMSG("Generate RSA key pair!\n");
	res = TEE_GenerateKey(tObject, obj_size, NULL, 0);
	if (res != TEE_SUCCESS)
		goto out;

	res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, &obj_id,
					sizeof(obj_id),
					TEE_DATA_FLAG_ACCESS_WRITE |
					TEE_DATA_FLAG_ACCESS_READ,
					tObject, NULL, 0,
					TEE_HANDLE_NULL);
	if (res != TEE_SUCCESS)
		goto out;

	params[0].value.a = obj_id;

	DMSG("TA_GenerateKeyPair Successful!\n");
out:
	if (tObject != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(tObject);

	return res;
}

/*
 * Input params:
 * param#0 : object ID and SK sign mechanism
 * param#1 : the input data buffer
 * param#2 : the output data buffer
 * param#3 : not used
 */
static TEE_Result TA_DecryptData(uint32_t param_types, TEE_Param params[4])
{
	TEE_Result res;
	TEE_ObjectHandle pObject = TEE_HANDLE_NULL, tObject = TEE_HANDLE_NULL;
	TEE_ObjectInfo objectInfo;
	TEE_OperationHandle operation = TEE_HANDLE_NULL;
	uint32_t algorithm, obj_id;

	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						   TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_MEMREF_OUTPUT,
						   TEE_PARAM_TYPE_NONE);
	if (param_types != exp_param_types) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	obj_id = params[0].value.a;

	/* Try to open object */
	res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, (void *)&obj_id,
				       sizeof(uint32_t),
				       TEE_DATA_FLAG_ACCESS_READ |
				       TEE_DATA_FLAG_SHARE_READ,
				       &pObject);
	if (res != TEE_SUCCESS)
		goto out;

	/* Try to get object info */
	DMSG("Get Object Info!\n");
	res = TEE_GetObjectInfo1(pObject, &objectInfo);
	if (res != TEE_SUCCESS)
		goto out;

	if (params[2].memref.buffer == NULL) {
		params[2].memref.size = objectInfo.objectSize;
		goto out;
	}

	DMSG("Allocate Transient Object!\n");
	res = TEE_AllocateTransientObject(objectInfo.objectType,
					  objectInfo.objectSize, &tObject);
	if (res != TEE_SUCCESS)
		goto out;

	DMSG("Copy Object Attributes!\n");
	res = TEE_CopyObjectAttributes1(tObject, pObject);
	if (res != TEE_SUCCESS)
		goto out;

	algorithm = TEE_ALG_RSA_NOPAD;

	DMSG("Allocate Operation!\n");
	res = TEE_AllocateOperation(&operation, algorithm, TEE_MODE_DECRYPT,
				    objectInfo.objectSize);
	if (res != TEE_SUCCESS)
		goto out;

	DMSG("Set Operation Key!\n");
	res = TEE_SetOperationKey(operation, tObject);
	if (res != TEE_SUCCESS)
		goto out;

	DMSG("Asymetric Decrypt Data!\n");
	res = TEE_AsymmetricDecrypt(operation, NULL, 0,
				    params[1].memref.buffer,
				    params[1].memref.size,
				    params[2].memref.buffer,
				    &params[2].memref.size);
	if (res != TEE_SUCCESS)
		goto out;

	DMSG("Encrypt Data Successful!\n");
out:
	if (pObject != TEE_HANDLE_NULL)
		TEE_CloseObject(pObject);

	if (tObject != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(tObject);

	if (operation)
		TEE_FreeOperation(operation);

	return res;
}


/*
 * Called when the instance of the TA is created. This is the first call in
 * the TA.
 */
TEE_Result TA_CreateEntryPoint(void)
{
	uint32_t ret = TEE_SUCCESS;

	return ret;
}

/*
 * Called when the instance of the TA is destroyed if the TA has not
 * crashed or panicked. This is the last call in the TA.
 */
void TA_DestroyEntryPoint(void)
{
}

/*
 * Called when a new session is opened to the TA. *sess_ctx can be updated
 * with a value to be able to identify this session in subsequent calls to the
 * TA.
 */
TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
		TEE_Param  params[4], void **sess_ctx)
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Unused parameters */
	(void)&params;
	(void)&sess_ctx;

	return TEE_SUCCESS;
}

/*
 * Called when a session is closed, sess_ctx hold the value that was
 * assigned by TA_OpenSessionEntryPoint().
 */
void TA_CloseSessionEntryPoint(void *sess_ctx)
{
	(void)&sess_ctx; /* Unused parameter */
	DMSG("Goodbye!\n");
}

/*
 * Called when a TA is invoked. sess_ctx hold that value that was
 * assigned by TA_OpenSessionEntryPoint(). The rest of the paramters
 * comes from normal world.
 */
TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx, uint32_t cmd_id,
			uint32_t param_types, TEE_Param params[4])
{
	(void)&sess_ctx; /* Unused parameter */

	switch (cmd_id) {
	case TEE_DECRYPT_DATA:
		return TA_DecryptData(param_types, params);
	case TEE_GENERATE_KEYPAIR:
		return TA_GenerateKeyPair(param_types, params);
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}

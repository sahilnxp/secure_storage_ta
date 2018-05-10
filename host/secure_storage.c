#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>

#include <tee_client_api.h>
#include <tee_api_types.h>
#include <ta_secure_storage.h>

#define DATA_LEN		100
char data[DATA_LEN] = "zTKEOWOCf8IOBNbeBYOzzTKEOWOCf8IOBNbeBYOzzTKEOWOCf8IOBNbeBYOzzTKEOWOCf8IOBNbeBYOzzTKEOWOCf8IOBNbeBYOz";

TEEC_UUID uuid = TA_SECURE_STORAGE_UUID;

int generate_rsa_keypair()
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;

	uint32_t err_origin, obj_idx = 0;
	int ret = 0;

	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS) {
		printf("TEEC_InitializeContext failed with code 0x%x", res);
		ret = 1;
		goto out;
	}

	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS) {
		printf("TEEC_Opensession failed with code 0x%x", res);
		ret = 1;
		goto fail1;
	}

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_OUTPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(&sess, TEE_GENERATE_KEYPAIR, &op,
				 &err_origin);
	if (res != TEEC_SUCCESS) {
		printf("TEEC_InvokeCommand failed with code 0x%x\n", res);
		ret = 1;
		goto fail2;
	}

	obj_idx = op.params[0].value.a;

	printf("RSA Keypair created successfully with id = %u\n", obj_idx);

fail2:
	TEEC_CloseSession(&sess);
fail1:
	TEEC_FinalizeContext(&ctx);
out:
	return ret;
		
}

int crypto_operation()
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_SharedMemory shm_in, shm_out;

	uint32_t err_origin, obj_idx = 0;
	int ret = 0;

	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS) {
		printf("TEEC_InitializeContext failed with code 0x%x", res);
		ret = 1;
		goto out;
	}

	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS) {
		printf("TEEC_Opensession failed with code 0x%x", res);
		ret = 1;
		goto fail1;
	}

	shm_in.size = DATA_LEN;
	shm_in.flags = TEEC_MEM_INPUT;

	res = TEEC_AllocateSharedMemory(&ctx, &shm_in);
	if (res != TEEC_SUCCESS) {
		printf("TEEC_AllocateSharedMemory failed with code 0x%x\n", res);
		ret = 1;
		goto fail2;
	}

	memcpy(shm_in.buffer, data, shm_in.size);

	shm_out.size = 256;
	shm_out.flags = TEEC_MEM_OUTPUT;

	res = TEEC_AllocateSharedMemory(&ctx, &shm_out);
	if (res != TEEC_SUCCESS) {
		printf("TEEC_AllocateSharedMemory failed with code 0x%x\n", res);
		ret = 1;
		goto fail3;
	}

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_MEMREF_WHOLE,
					 TEEC_MEMREF_WHOLE, TEEC_NONE);
	op.params[0].value.a = obj_idx;
	op.params[1].memref.parent = &shm_in;
	op.params[1].memref.offset = 0;
	op.params[1].memref.size = shm_in.size;
	op.params[2].memref.parent = &shm_out;
	op.params[2].memref.offset = 0;
	op.params[2].memref.size = shm_out.size;

	//print_info("Invoking TEE_DECRYPT_DATA\n");
	res = TEEC_InvokeCommand(&sess, TEE_DECRYPT_DATA, &op,
				 &err_origin);
	if (res != TEEC_SUCCESS) {
		printf("TEEC_InvokeCommand failed with code 0x%x\n", res);
		ret = 1;
		goto fail4;
	}
	//print_info("TEE_DECRYPT_DATA successful\n");

fail4:
	TEEC_ReleaseSharedMemory(&shm_out);
fail3:
	TEEC_ReleaseSharedMemory(&shm_in);
fail2:
	TEEC_CloseSession(&sess);
fail1:
	TEEC_FinalizeContext(&ctx);
out:
	return ret;
}

int main(int argc, char *argv[])
{
	if (argc > 1 && argc < 3) {
		switch (atoi(argv[1])) {
			case 1:
				if (generate_rsa_keypair())
					return 1;
				break;
			case 2:
				if (crypto_operation())
					return 1;
				printf("Crypto operation done succesfully\n");
				break;
			default:
				printf("No option given\n");
		}
	} else {
		printf("Give correct options\n");
	}

	return 0;
}

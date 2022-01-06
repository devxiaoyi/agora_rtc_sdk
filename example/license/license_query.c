/*************************************************************
 * File  :  license_query.c
 * Module:  Agora SD-RTN SDK RTC C API license status query.
 *
 * This is a tool to activate license Agora RTC Service SDK.
 * Copyright (C) 2020 Agora IO
 * All rights reserved.
 *
 *************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <unistd.h>
#include <getopt.h>
#include <fcntl.h>

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <netdb.h>

#include "jsmn.h"
#include "http_parser.h"

#define LOGS(fmt, ...) fprintf(stdout, "" fmt "\n", ##__VA_ARGS__)
#define LOGD(fmt, ...) fprintf(stdout, "[DBG] " fmt "\n", ##__VA_ARGS__)
#define LOGI(fmt, ...) fprintf(stdout, "[INF] " fmt "\n", ##__VA_ARGS__)
#define LOGW(fmt, ...) fprintf(stdout, "[WRN] " fmt "\n", ##__VA_ARGS__)
#define LOGE(fmt, ...) fprintf(stdout, "[ERR] " fmt "\n", ##__VA_ARGS__)

#define TAG_APP "[app]"

#define INVALID_FD -1
#define MAX_BUF_LEN 1024
#define LICENSE_KEY_MAX_LEN 128
#define TIME_MAX_LEN 128
#define LICENSE_BATCH_ID 128
#define LICENSE_VENDOR_ID 128

#define DEFAULT_HTTP_BUFFER_SIZE (1 * 1024 * 1024)
#define DEFAULT_HTTP_BODY_SIZE (1 * 1024 * 1024)
#define DEFAULT_JSON_TOKENS_MAX_COUNT 8192

typedef struct {
	const char *p_appid;
	const char *p_customer_key;
	const char *p_customer_secret;
} app_config_t;

typedef struct {
	char str_id[LICENSE_BATCH_ID];
	char str_vendor_id[LICENSE_VENDOR_ID];
	char str_create_time[TIME_MAX_LEN];
	int32_t amount;
	int32_t available;
	int32_t used;
} app_license_batch_t;

typedef struct {
	app_config_t config;
	jsmn_parser json_parser;
	http_parser http_parser;

	int32_t http_buffer_size;
	int32_t http_buffer_len;
	char *http_buffer_ptr;

	int32_t http_body_size;
	int32_t http_body_len;
	char *http_body_ptr;

	int32_t json_token_size;
	jsmntok_t *json_token_ptr;

	int32_t result_license_batch_tab_count;
	app_license_batch_t *result_license_batch_tab_ptr;

	int32_t result_license_stock_amount;
	int32_t result_license_stock_available;
	int32_t result_license_stock_used;
} app_t;

static app_t g_app_instance = {
    .config = {
        .p_appid            =   "",
        .p_customer_key     =   "",
        .p_customer_secret  =   "",
    },
};

app_t *app_get_instance(void)
{
	return &g_app_instance;
}

static int jsoneq(const char *json, jsmntok_t *tok, const char *s)
{
	if (tok->type == JSMN_STRING && (int)strlen(s) == tok->end - tok->start &&
		strncmp(json + tok->start, s, tok->end - tok->start) == 0) {
		return 0;
	}
	return -1;
}

void app_print_usage(int32_t argc, char **argv)
{
	LOGS("\nUsage: %s [OPTION]", argv[0]);
	LOGS(" -h, --help               : show help info");
	LOGS(" -a, --appId              : application ID");
	LOGS(" -k, --customerKey        : customer key");
	LOGS(" -s, --customerSecret     : customer secret");
	LOGS("\nExample:");
	LOGS("    %s --appId xx --customerKey xx --customerSecret xx", argv[0]);
}

int32_t app_parse_args(app_config_t *p_config, int32_t argc, char **argv)
{
	const char *av_short_option = "ha:k:s:";
	const struct option av_long_option[] = { { "help", 0, NULL, 'h' },
											 { "appId", 1, NULL, 'a' },
											 { "customerKey", 1, NULL, 'k' },
											 { "customerSecret", 1, NULL, 's' },
											 { 0, 0, 0, 0 } };

	int32_t ch = -1;
	int32_t optidx = 0;
	int32_t rval = 0;

	while (1) {
		optidx++;
		ch = getopt_long(argc, argv, av_short_option, av_long_option, NULL);
		if (ch == -1) {
			break;
		}

		switch (ch) {
		case 'h': {
			rval = -1;
			goto EXIT;
		} break;
		case 'a': {
			p_config->p_appid = optarg;
		} break;
		case 'k': {
			p_config->p_customer_key = optarg;
		} break;
		case 's': {
			p_config->p_customer_secret = optarg;
		} break;
		default: {
			rval = -1;
			LOGS("%s parse cmd param: %s error.", TAG_APP, argv[optidx]);
			goto EXIT;
		}
		}
	}

	// check key parameters
	if (!p_config->p_appid || strcmp(p_config->p_appid, "") == 0) {
		rval = -1;
		LOGE("%s appid MUST be provided", TAG_APP);
		goto EXIT;
	}

	if (!p_config->p_customer_key || strcmp(p_config->p_customer_key, "") == 0) {
		rval = -1;
		LOGE("%s invalid customer key", TAG_APP);
		goto EXIT;
	}

	if (!p_config->p_customer_secret || strcmp(p_config->p_customer_secret, "") == 0) {
		rval = -1;
		LOGE("%s invalid customer secret", TAG_APP);
		goto EXIT;
	}

EXIT:
	return rval;
}

static int32_t app_init(app_t *p_app)
{
	// 0. load config.json
	// 1. check parameter

	int32_t rval = 0;

	p_app->http_buffer_size = DEFAULT_HTTP_BUFFER_SIZE;
	p_app->http_buffer_len = 0;
	p_app->http_buffer_ptr = (char *)malloc(p_app->http_buffer_size);
	if (!p_app->http_buffer_ptr) {
		rval = -1;
		LOGE("alloc http buffer failed, size:%d", p_app->http_buffer_size);
		goto EXIT;
	}

	p_app->http_body_size = DEFAULT_HTTP_BODY_SIZE;
	p_app->http_body_len = 0;
	p_app->http_body_ptr = (char *)malloc(p_app->http_body_size);
	if (!p_app->http_body_ptr) {
		rval = -1;
		LOGE("alloc http body failed, size:%d", p_app->http_body_size);
		goto EXIT;
	}

	p_app->json_token_size = DEFAULT_JSON_TOKENS_MAX_COUNT;
	p_app->json_token_ptr = (jsmntok_t *)malloc(p_app->json_token_size * sizeof(jsmntok_t));
	if (!p_app->json_token_ptr) {
		rval = -1;
		LOGE("alloc json token failed, size:%d", p_app->json_token_size);
		goto EXIT;
	}

	p_app->result_license_batch_tab_count = 0;
	p_app->result_license_batch_tab_ptr = NULL;

	p_app->result_license_stock_amount = 0;
	p_app->result_license_stock_available = 0;
	p_app->result_license_stock_used = 0;

EXIT:
	return rval;
}

static void app_deinit(app_t *p_app)
{
	if (p_app->http_buffer_ptr) {
		free(p_app->http_buffer_ptr);
		p_app->http_buffer_ptr = NULL;
	}
	p_app->http_buffer_size = 0;
	p_app->http_buffer_len = 0;

	if (p_app->http_body_ptr) {
		free(p_app->http_body_ptr);
		p_app->http_body_ptr = NULL;
	}
	p_app->http_body_size = 0;
	p_app->http_body_len = 0;

	if (p_app->json_token_ptr) {
		free(p_app->json_token_ptr);
		p_app->json_token_ptr = NULL;
	}
	p_app->json_token_size = 0;

	if (p_app->result_license_batch_tab_ptr) {
		free(p_app->result_license_batch_tab_ptr);
		p_app->result_license_batch_tab_ptr = NULL;
	}
	p_app->result_license_batch_tab_count = 0;

	p_app->result_license_stock_amount = 0;
	p_app->result_license_stock_available = 0;
	p_app->result_license_stock_used = 0;
}

static int32_t app_parse_response(app_t *p_app)
{
	jsmntok_t *token_tab_ptr = p_app->json_token_ptr;
	int32_t token_tab_size = p_app->json_token_size;
	jsmn_init(&p_app->json_parser);
	int32_t rval = jsmn_parse(&p_app->json_parser, p_app->http_body_ptr, p_app->http_body_len,
							  token_tab_ptr, token_tab_size);
	if (rval <= 0) {
		LOGE("%s parse config failed, token_num=%d", TAG_APP, rval);
		goto EXIT;
	}

	int32_t token_num = rval;
	if (token_num < 1 || token_tab_ptr[0].type != JSMN_OBJECT) {
		rval = -1;
		LOGE("%s parse json failed", TAG_APP);
		goto EXIT;
	}

	char str_buffer[MAX_BUF_LEN];
	int32_t str_buffer_len = 0;
	for (int32_t i = 1; i < token_num; i++) {
		if (jsoneq(p_app->http_body_ptr, &token_tab_ptr[i], "content") == 0) {
			i++;
			if (token_tab_ptr[i].type != JSMN_ARRAY) {
				continue;
			}

			if (p_app->result_license_batch_tab_count == 0) {
				p_app->result_license_batch_tab_count = token_tab_ptr[i].size;

				int32_t size = p_app->result_license_batch_tab_count * sizeof(app_license_batch_t);
				p_app->result_license_batch_tab_ptr = (app_license_batch_t *)malloc(size);
				memset(p_app->result_license_batch_tab_ptr, 0, size);
			}

			enum {
				OBJ = 0,
				OBJ_ID_KEY = 1,
				OBJ_ID_VALUE = 2,
				OBJ_VENDOR_ID_KEY = 3,
				OBJ_VENDOR_ID_VALUE = 4,
				OBJ_TOTAL_AMOUNT_KEY = 5,
				OBJ_TOTAL_AMOUNT_VALUE = 6,
				OBJ_AVAILABLE_KEY = 7,
				OBJ_AVAILABLE_VALUE = 8,
				OBJ_USED_KEY = 9,
				OBJ_USED_VALUE = 10,
				OBJ_EXPIRE_TIME_KEY = 11,
				OBJ_EXPIRE_TIME_VALUE = 12,
				OBJ_CREATE_TIME_KEY = 13,
				OBJ_CREATE_TIME_VALUE = 14,
				OBJ_COUNT = 15,
			};

			for (int32_t j = 0; j < p_app->result_license_batch_tab_count; j++) {
				app_license_batch_t *p_batch = p_app->result_license_batch_tab_ptr + j;

				// id
				jsmntok_t *p_token = &token_tab_ptr[i + 1 + j * OBJ_COUNT + OBJ_ID_VALUE];
				str_buffer_len = p_token->end - p_token->start;
				memcpy(p_batch->str_id, p_app->http_body_ptr + p_token->start, str_buffer_len);
				p_batch->str_id[str_buffer_len] = '\0';

				// vendor id
				p_token = &token_tab_ptr[i + 1 + j * OBJ_COUNT + OBJ_VENDOR_ID_VALUE];
				str_buffer_len = p_token->end - p_token->start;
				memcpy(p_batch->str_vendor_id, p_app->http_body_ptr + p_token->start,
					   str_buffer_len);
				p_batch->str_vendor_id[str_buffer_len] = '\0';

				// total amount
				p_token = &token_tab_ptr[i + 1 + j * OBJ_COUNT + OBJ_TOTAL_AMOUNT_VALUE];
				str_buffer_len = p_token->end - p_token->start;
				memcpy(str_buffer, p_app->http_body_ptr + p_token->start, str_buffer_len);
				str_buffer[str_buffer_len] = '\0';
				p_batch->amount = atoi(str_buffer);
				p_app->result_license_stock_amount += p_batch->amount;

				// avaliable
				p_token = &token_tab_ptr[i + 1 + j * OBJ_COUNT + OBJ_AVAILABLE_VALUE];
				str_buffer_len = p_token->end - p_token->start;
				memcpy(str_buffer, p_app->http_body_ptr + p_token->start, str_buffer_len);
				str_buffer[str_buffer_len] = '\0';
				p_batch->available = atoi(str_buffer);
				p_app->result_license_stock_available += p_batch->available;

				// used
				p_token = &token_tab_ptr[i + 1 + j * OBJ_COUNT + OBJ_USED_VALUE];
				str_buffer_len = p_token->end - p_token->start;
				memcpy(str_buffer, p_app->http_body_ptr + p_token->start, str_buffer_len);
				str_buffer[str_buffer_len] = '\0';
				p_batch->used = atoi(str_buffer);
				p_app->result_license_stock_used += p_batch->used;

				// create time
				p_token = &token_tab_ptr[i + 1 + j * OBJ_COUNT + OBJ_CREATE_TIME_VALUE];
				str_buffer_len = p_token->end - p_token->start;
				memcpy(str_buffer, p_app->http_body_ptr + p_token->start, str_buffer_len);
				str_buffer[str_buffer_len] = '\0';
				if (strcmp(str_buffer, "null") != 0) {
					time_t time = atoll(str_buffer) / 1000;
					struct tm *local = localtime(&time);
					strftime(p_batch->str_create_time, sizeof(p_batch->str_create_time),
							 "%Y-%m-%d %H:%M:%S", local);
				}
			}

			i += p_app->result_license_batch_tab_count * OBJ_COUNT;
		} else {
			i++;
		}
	}

EXIT:
	return 0;
}

static int32_t _http_on_body(http_parser *p_parser, const char *at, size_t length)
{
	app_t *p_app = (app_t *)p_parser->data;

	if (length > 0) {
		memcpy(p_app->http_body_ptr + p_app->http_body_len, at, length);
		p_app->http_body_len += length;
	}
	return 0;
}

static int32_t base64_encode(const char *src, int32_t src_len, char *encoded)
{
	const char basis_64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

	int i;
	char *p = encoded;
	for (i = 0; i < src_len - 2; i += 3) {
		*p++ = basis_64[(src[i] >> 2) & 0x3F];
		*p++ = basis_64[((src[i] & 0x3) << 4) | ((src[i + 1] & 0xF0) >> 4)];
		*p++ = basis_64[((src[i + 1] & 0xF) << 2) | ((src[i + 2] & 0xC0) >> 6)];
		*p++ = basis_64[src[i + 2] & 0x3F];
	}
	if (i < src_len) {
		*p++ = basis_64[(src[i] >> 2) & 0x3F];
		if (i == (src_len - 1)) {
			*p++ = basis_64[((src[i] & 0x3) << 4)];
			*p++ = '=';
		} else {
			*p++ = basis_64[((src[i] & 0x3) << 4) | ((src[i + 1] & 0xF0) >> 4)];
			*p++ = basis_64[((src[i + 1] & 0xF) << 2)];
		}
		*p++ = '=';
	}

	*p++ = '\0';
	return (p - encoded);
}

static void output_info(app_t *p_app)
{
	if (!p_app) {
		return;
	}

	LOGS("--------------------------------  License Stock Status  --------------------------------");
	LOGS("| total amount:     %-5.5d                                                              |",
		 p_app->result_license_stock_amount);
	LOGS("| total available:  %-5.5d                                                              |",
		 p_app->result_license_stock_available);
	LOGS("| total used:       %-5.5d                                                              |",
		 p_app->result_license_stock_used);
	LOGS("----------------------------------------------------------------------------------------");
	if (p_app->result_license_batch_tab_count > 0) {
		LOGS("| %-16.16s | %-16.16s | %-12s | %-12s | %-16s |", "batch id", "create time", "amount",
			 "avaliable", "used");
		LOGS("----------------------------------------------------------------------------------------");
		for (int32_t i = 0; i < p_app->result_license_batch_tab_count; i++) {
			app_license_batch_t *p_batch = p_app->result_license_batch_tab_ptr + i;
			LOGS("| %-16.16s | %-16.16s | %-12d | %-12d | %-16d |", p_batch->str_id,
				 p_batch->str_create_time, p_batch->amount, p_batch->available, p_batch->used);
		}
		LOGS("----------------------------------------------------------------------------------------");
	}
}

#include "mbedtls/config.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/certs.h"

#define AGORA_CA_PEM                                                                               \
	"-----BEGIN CERTIFICATE-----\r\n"                                                              \
	"MIIE0DCCA7igAwIBAgIBBzANBgkqhkiG9w0BAQsFADCBgzELMAkGA1UEBhMCVVMx\r\n"                         \
	"EDAOBgNVBAgTB0FyaXpvbmExEzARBgNVBAcTClNjb3R0c2RhbGUxGjAYBgNVBAoT\r\n"                         \
	"EUdvRGFkZHkuY29tLCBJbmMuMTEwLwYDVQQDEyhHbyBEYWRkeSBSb290IENlcnRp\r\n"                         \
	"ZmljYXRlIEF1dGhvcml0eSAtIEcyMB4XDTExMDUwMzA3MDAwMFoXDTMxMDUwMzA3\r\n"                         \
	"MDAwMFowgbQxCzAJBgNVBAYTAlVTMRAwDgYDVQQIEwdBcml6b25hMRMwEQYDVQQH\r\n"                         \
	"EwpTY290dHNkYWxlMRowGAYDVQQKExFHb0RhZGR5LmNvbSwgSW5jLjEtMCsGA1UE\r\n"                         \
	"CxMkaHR0cDovL2NlcnRzLmdvZGFkZHkuY29tL3JlcG9zaXRvcnkvMTMwMQYDVQQD\r\n"                         \
	"EypHbyBEYWRkeSBTZWN1cmUgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IC0gRzIwggEi\r\n"                         \
	"MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC54MsQ1K92vdSTYuswZLiBCGzD\r\n"                         \
	"BNliF44v/z5lz4/OYuY8UhzaFkVLVat4a2ODYpDOD2lsmcgaFItMzEUz6ojcnqOv\r\n"                         \
	"K/6AYZ15V8TPLvQ/MDxdR/yaFrzDN5ZBUY4RS1T4KL7QjL7wMDge87Am+GZHY23e\r\n"                         \
	"cSZHjzhHU9FGHbTj3ADqRay9vHHZqm8A29vNMDp5T19MR/gd71vCxJ1gO7GyQ5HY\r\n"                         \
	"pDNO6rPWJ0+tJYqlxvTV0KaudAVkV4i1RFXULSo6Pvi4vekyCgKUZMQWOlDxSq7n\r\n"                         \
	"eTOvDCAHf+jfBDnCaQJsY1L6d8EbyHSHyLmTGFBUNUtpTrw700kuH9zB0lL7AgMB\r\n"                         \
	"AAGjggEaMIIBFjAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAdBgNV\r\n"                         \
	"HQ4EFgQUQMK9J47MNIMwojPX+2yz8LQsgM4wHwYDVR0jBBgwFoAUOpqFBxBnKLbv\r\n"                         \
	"9r0FQW4gwZTaD94wNAYIKwYBBQUHAQEEKDAmMCQGCCsGAQUFBzABhhhodHRwOi8v\r\n"                         \
	"b2NzcC5nb2RhZGR5LmNvbS8wNQYDVR0fBC4wLDAqoCigJoYkaHR0cDovL2NybC5n\r\n"                         \
	"b2RhZGR5LmNvbS9nZHJvb3QtZzIuY3JsMEYGA1UdIAQ/MD0wOwYEVR0gADAzMDEG\r\n"                         \
	"CCsGAQUFBwIBFiVodHRwczovL2NlcnRzLmdvZGFkZHkuY29tL3JlcG9zaXRvcnkv\r\n"                         \
	"MA0GCSqGSIb3DQEBCwUAA4IBAQAIfmyTEMg4uJapkEv/oV9PBO9sPpyIBslQj6Zz\r\n"                         \
	"91cxG7685C/b+LrTW+C05+Z5Yg4MotdqY3MxtfWoSKQ7CC2iXZDXtHwlTxFWMMS2\r\n"                         \
	"RJ17LJ3lXubvDGGqv+QqG+6EnriDfcFDzkSnE3ANkR/0yBOtg2DZ2HKocyQetawi\r\n"                         \
	"DsoXiWJYRBuriSUBAA/NxBti21G00w9RKpv0vHP8ds42pM3Z2Czqrpv1KrKQ0U11\r\n"                         \
	"GIo/ikGQI31bS/6kA1ibRrLDYGCD+H1QQc7CoZDDu+8CL9IVVO5EFdkKrqeKM+2x\r\n"                         \
	"LXY2JtwE65/3YR8V3Idv7kaWKK2hJn0KCacuBKONvPi8BDAB\r\n"                                         \
	"-----END CERTIFICATE-----\r\n"

int32_t app_query_license(app_t *p_app)
{
	// License Query Flow
	// Reference Link
	// https://docs-preview.agoralab.co/cn/Agora%20Platform/license_mechanism_v3?platform=All%20Platforms

	int rval = 0;
	uint32_t http_buf_len = 0;
	uint8_t *http_buf_pos = NULL;
	char ssl_error_buf[100] = { 0 };
	uint32_t ssl_vrfy_flags = 0;
	char ssl_vrfy_buff[100] = { 0 };
	app_config_t *p_config = &p_app->config;
	const char *pers = "ssl_client";
	const char *server_name = "api.agora.io";
	mbedtls_net_context server_fd;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_ssl_context ssl;
	mbedtls_ssl_config conf;
	mbedtls_x509_crt cacert;

	/* 0. Initialize the ssl context */

	// 0.1 Initialize the RNG and the session data
	mbedtls_net_init(&server_fd);
	mbedtls_ssl_init(&ssl);
	mbedtls_ssl_config_init(&conf);
	mbedtls_x509_crt_init(&cacert);
	mbedtls_ctr_drbg_init(&ctr_drbg);

	// 0.2 Seeding the random number generator
	mbedtls_entropy_init(&entropy);
	rval = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, pers, strlen(pers));
	if (rval != 0) {
		mbedtls_strerror(rval, ssl_error_buf, 100);
		LOGE("ssl error: ctr_drbg_seed returned %d - %s", rval, ssl_error_buf);
		goto EXIT;
	}

	//0.3. Initialize ca certificates
	rval = mbedtls_x509_crt_parse(&cacert, AGORA_CA_PEM, strlen(AGORA_CA_PEM) + 1);
	if (rval < 0) {
		mbedtls_strerror(rval, ssl_error_buf, 100);
		LOGE("ssl error: x509_crt_parse returned -0x%x - %s", (uint32_t)-rval, ssl_error_buf);
		goto EXIT;
	}

	/* 1. Start the connection */

	// 1.1 Connecting to tcp
	rval = mbedtls_net_connect(&server_fd, server_name, "443", MBEDTLS_NET_PROTO_TCP);
	if (rval != 0) {
		mbedtls_strerror(rval, ssl_error_buf, 100);
		LOGE("ssl error: net_connect returned %d - %s", rval, ssl_error_buf);
		goto EXIT;
	}

	/* 2. Setup stuff */
	rval = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM,
									   MBEDTLS_SSL_PRESET_DEFAULT);
	if (rval != 0) {
		mbedtls_strerror(rval, ssl_error_buf, 100);
		LOGE("ssl error: ssl_config_defaults returned %d - %s", rval, ssl_error_buf);
		goto EXIT;
	}

	mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);
	mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
	mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);

	rval = mbedtls_ssl_setup(&ssl, &conf);
	if (rval != 0) {
		mbedtls_strerror(rval, ssl_error_buf, 100);
		LOGE("ssl error: ssl_setup returned %d - %s", rval, ssl_error_buf);
		goto EXIT;
	}
	rval = mbedtls_ssl_set_hostname(&ssl, server_name);
	if (rval != 0) {
		mbedtls_strerror(rval, ssl_error_buf, 100);
		LOGE("ssl error: ssl_set_hostname returned %d - %s", rval, ssl_error_buf);
		goto EXIT;
	}

	mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

	/* 3. Handshake */
	while ((rval = mbedtls_ssl_handshake(&ssl)) != 0) {
		if (rval != MBEDTLS_ERR_SSL_WANT_READ && rval != MBEDTLS_ERR_SSL_WANT_WRITE) {
			mbedtls_strerror(rval, ssl_error_buf, 100);
			LOGE("ssl error: ssl_handshake returned -0x%x - %s", (uint32_t)-rval, ssl_error_buf);
			goto EXIT;
		}
	}

	/* 4. Verify the server certificate */
	ssl_vrfy_flags = mbedtls_ssl_get_verify_result(&ssl);
	if (ssl_vrfy_flags != 0) {
		mbedtls_x509_crt_verify_info(ssl_vrfy_buff, sizeof(ssl_vrfy_buff), NULL, ssl_vrfy_flags);
		LOGE("ssl error: verify_info error: %s", ssl_vrfy_buff);
		goto EXIT;
	}

	/* 5. Read and Write data */
	char str_authorization[MAX_BUF_LEN];
	char str_authorization_base64[MAX_BUF_LEN];
	int32_t str_authorization_base64_len = 0;
	snprintf(str_authorization, MAX_BUF_LEN, "%s:%s", p_config->p_customer_key,
			 p_config->p_customer_secret);
	base64_encode(str_authorization, strlen(str_authorization), str_authorization_base64);

	p_app->http_buffer_len = snprintf(p_app->http_buffer_ptr, p_app->http_buffer_size,
									  "GET /dev/v2/apps/%s/license-config HTTP/1.1\r\n"
									  "Authorization: Basic %s\r\n"
									  "Host: %s\r\n"
									  "Accept: */*\r\n"
									  "\r\n",
									  p_config->p_appid, str_authorization_base64, server_name);

	// LOGS("SEND len=%d\n%s", p_app->http_buffer_len, p_app->http_buffer_ptr);
	rval = mbedtls_ssl_write(&ssl, p_app->http_buffer_ptr, p_app->http_buffer_len);
	if (rval <= 0) {
		if (rval != MBEDTLS_ERR_SSL_WANT_READ && rval != MBEDTLS_ERR_SSL_WANT_WRITE) {
			LOGE("%s send license activate request failed, rval=%x", TAG_APP, rval);
			goto EXIT;
		}
	}

	// read loop
	http_buf_pos = p_app->http_buffer_ptr;
	http_buf_len = 0;
	while (1) {
		rval = mbedtls_ssl_read(&ssl, http_buf_pos, p_app->http_buffer_size - http_buf_len);
		if (rval == MBEDTLS_ERR_SSL_WANT_READ || rval == MBEDTLS_ERR_SSL_WANT_WRITE) {
			LOGE("Read more");
			continue;
		}
		if (rval == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
			LOGE("Peer closed");
			break;
		}
		if (rval < 0) {
			LOGE("Read failed, rval=%d", rval);
			goto EXIT;
		}
		if (rval == 0) {
			LOGE("Read EOF");
			break;
		}

		http_buf_pos += rval;
		http_buf_len += rval;

		if (memchr(http_buf_pos - rval, '}', rval)) {
			break;
		}
	}

	p_app->http_buffer_len = http_buf_len;
	if (p_app->http_buffer_len <= 0) {
		rval = -1;
		LOGE("%s recv response failed", TAG_APP);
		goto EXIT;
	}
	p_app->http_buffer_ptr[p_app->http_buffer_len] = '\0';
	// LOGS("RECV len=%d\n%s", p_app->http_buffer_len, p_app->http_buffer_ptr);

	http_parser_settings http_settings = { 0 };
	http_settings.on_body = _http_on_body;

	p_app->http_parser.data = (void *)p_app;
	http_parser_init(&p_app->http_parser, HTTP_RESPONSE);
	http_parser_execute(&p_app->http_parser, &http_settings, p_app->http_buffer_ptr,
						p_app->http_buffer_len);

	rval = app_parse_response(p_app);
	if (rval < 0) {
		rval = -1;
		LOGE("%s parse http reponse failed", TAG_APP);
		goto EXIT;
	}

	output_info(p_app);
	rval = 0;

EXIT:

	mbedtls_ssl_close_notify(&ssl);
	mbedtls_net_free(&server_fd);
	mbedtls_x509_crt_free(&cacert);
	mbedtls_ssl_free(&ssl);
	mbedtls_ssl_config_free(&conf);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);

	return rval;
}

int main(int argc, char **argv)
{
	app_t *p_app = app_get_instance();

	// 0. app parse args
	int32_t rval = app_parse_args(&p_app->config, argc, argv);
	if (rval != 0) {
		app_print_usage(argc, argv);
		goto EXIT;
	}

	// 1. app init
	rval = app_init(p_app);
	if (rval < 0) {
		LOGE("%s init failed, rval=%d", TAG_APP, rval);
		goto EXIT;
	}

	// 2. license query
	rval = app_query_license(p_app);
	if (rval != 0) {
		LOGE("%s query license failed, rval=%d", TAG_APP, rval);
		goto EXIT;
	}

EXIT:
	// 3. app deinit
	app_deinit(p_app);
	return rval;
}

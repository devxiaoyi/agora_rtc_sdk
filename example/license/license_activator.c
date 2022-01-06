/*************************************************************
 * File  :  license_activator.c
 * Module:  Agora SD-RTN SDK RTC C API license activator.
 *
 * This is a tool to activate license Agora RTC Service SDK.
 * Copyright (C) 2020 Agora IO
 * All rights reserved.
 *
 *************************************************************/

#include <stdio.h>
#include <string.h>

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

#define DEFAULT_CREDENTIAL "4a5fa2eeddd2b2c9c7c4199aad48205b9b0c9bb19eaefdea4996aa99f6dd9252"

#define TAG_APP "[app]"

#define HTTPS

#define CERTIFACTE_FILENAME "certificate.bin"

#define INVALID_FD -1
#define MAX_TOKENS_COUNT 16
#define MAX_BUF_LEN 1024
#define HTTP_MAX_BUF_LEN 4096

#define CREDENTIAL_MAX_LEN 256
#define CERTIFICATE_MAX_LEN 2048

typedef struct {
	const char *p_certificate_dir;

	const char *p_appid;
	const char *p_customer_key;
	const char *p_customer_secret;
	const char *p_license_key;
} app_config_t;

typedef struct {
	app_config_t config;

	jsmn_parser json_parser;
	http_parser http_parser;

	// output: save certificate & credential
	char str_credential[CREDENTIAL_MAX_LEN];
	uint32_t str_credential_len;
	char str_certificate[CERTIFICATE_MAX_LEN];
	uint32_t str_certificate_len;

	int32_t b_activate_success;
	char str_activate_result[MAX_BUF_LEN];
} app_t;

static app_t g_app_instance = {
    .config = {
        .p_certificate_dir  =   ".",

        .p_appid            =   "",
        .p_customer_key     =   "",
        .p_customer_secret  =   "",
        .p_license_key      =   "",
    },

    .str_credential_len     =   CREDENTIAL_MAX_LEN,
    .str_certificate_len    =   CERTIFICATE_MAX_LEN,
    .b_activate_success     =   0,
};

static int jsoneq(const char *json, jsmntok_t *tok, const char *s)
{
	if (tok->type == JSMN_STRING && (int)strlen(s) == tok->end - tok->start &&
		strncmp(json + tok->start, s, tok->end - tok->start) == 0) {
		return 0;
	}
	return -1;
}

app_t *app_get_instance(void)
{
	return &g_app_instance;
}

void app_print_usage(int32_t argc, char **argv)
{
	LOGS("\nUsage: %s [OPTION]", argv[0]);
	LOGS(" -h, --help               : show help info");
	LOGS(" -a, --appId              : application ID");
	LOGS(" -k, --customerKey        : customer key");
	LOGS(" -s, --customerSecret     : customer secret");
	LOGS(" -l, --deviceId         : license key");
	LOGS(" -o, --certOutputDir      : certificate directory (output), default is '.'");
	LOGS("\nExample:");
	LOGS("    %s --appId xx --customerKey xx --customerSecret xx --deviceId xx --certOutputDir .",
		 argv[0]);
}

int32_t app_parse_args(app_config_t *p_config, int32_t argc, char **argv)
{
	const char *av_short_option = "ha:k:s:l:o:";
	const struct option av_long_option[] = { { "help", 0, NULL, 'h' },
											 { "appId", 1, NULL, 'a' },
											 { "customerKey", 1, NULL, 'k' },
											 { "customerSecret", 1, NULL, 's' },
											 { "deviceId", 1, NULL, 'l' },
											 { "certOutputDir", 1, NULL, 'o' },
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
		case 'l': {
			p_config->p_license_key = optarg;
		} break;
		case 'o': {
			p_config->p_certificate_dir = optarg;
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

	if (!p_config->p_license_key || strcmp(p_config->p_license_key, "") == 0) {
		rval = -1;
		LOGE("%s invalid license key", TAG_APP);
		goto EXIT;
	}

	rval = access(p_config->p_certificate_dir, F_OK);
	if (rval != 0) {
		LOGE("%s directory doesn't exist", TAG_APP);
		goto EXIT;
	}

EXIT:
	return rval;
}

int32_t app_save_license_file(const char *path, char *buffer, uint32_t *buf_len)
{
	int32_t rval = 0;

	if (*buf_len <= 0) {
		LOGE("%s invalid buffer length:%d", TAG_APP, *buf_len);
		goto EXIT;
	}

	int32_t fd = open(path, O_CREAT | O_RDWR | O_TRUNC, S_IRUSR | S_IWUSR);
	if (fd == INVALID_FD) {
		rval = -1;
		LOGE("%s open file failed, path=%s", TAG_APP, path);
		goto EXIT;
	}

	*buf_len = write(fd, buffer, *buf_len);
	if (*buf_len <= 0) {
		rval = -1;
		LOGE("%s write file failed, path=%s rval=%d", TAG_APP, path, rval);
		goto EXIT;
	}

EXIT:
	if (fd > 0) {
		close(fd);
		fd = INVALID_FD;
	}
	return rval;
}

static int32_t _http_on_body(http_parser *p_parser, const char *at, size_t length)
{
	app_t *p_app = (app_t *)p_parser->data;

	jsmntok_t tokens[MAX_TOKENS_COUNT];
	jsmn_init(&p_app->json_parser);
	int32_t rval = jsmn_parse(&p_app->json_parser, at, length, tokens, MAX_TOKENS_COUNT);
	if (rval <= 0) {
		LOGE("%s parse config failed, token_num=%d", TAG_APP, rval);
		goto EXIT;
	}

	int32_t token_num = rval;
	if (token_num < 1 || tokens[0].type != JSMN_OBJECT) {
		rval = -1;
		LOGE("%s parse json failed", TAG_APP);
		goto EXIT;
	}

	int32_t str_len = 0;
	for (int32_t i = 1; i < token_num; i++) {
		if (jsoneq(at, &tokens[i], "cert") == 0) {
			i++;
			str_len = tokens[i].end - tokens[i].start;
			memcpy(p_app->str_certificate, at + tokens[i].start, str_len);
			p_app->str_certificate[str_len] = '\0';
			p_app->str_certificate_len = str_len;
			p_app->b_activate_success = 1;
		} else {
			p_app->b_activate_success = 0;
			memcpy(p_app->str_activate_result, at, length);
			p_app->str_activate_result[length] = '\0';
			break;
		}
	}

EXIT:
	return 0;
}

int32_t base64_encode(const char *src, int32_t src_len, char *encoded)
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

int32_t app_activate_license(app_t *p_app)
{
	// License Activation Flow
	// Reference Link
	// https://docs-preview.agoralab.co/cn/Agora%20Platform/license_mechanism_v3?platform=All%20Platforms

	app_config_t *p_config = &p_app->config;
	int32_t rval;
	uint8_t http_buffer[HTTP_MAX_BUF_LEN];
	uint32_t http_buffer_len = 0;
	uint8_t *http_buffer_pos = NULL;
	char ssl_error_buf[100] = { 0 };
	uint32_t ssl_vrfy_flags = 0;
	char ssl_vrfy_buff[100] = { 0 };
	const char *pers = "ssl_client";
	const char *server_name = "api.agora.io";
	mbedtls_net_context server_fd;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_ssl_context ssl;
	mbedtls_ssl_config conf;
	mbedtls_x509_crt cacert;

	strcpy(p_app->str_credential,
		   "4a5fa2eeddd2b2c9c7c4199aad48205b9b0c9bb19eaefdea4996aa99f6dd9252");
	p_app->str_credential_len = strlen(p_app->str_credential);

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

	char str_page[MAX_BUF_LEN];
	snprintf(str_page, MAX_BUF_LEN, "/dev/v2/apps/%s/licenses", p_config->p_appid);

	char str_post[MAX_BUF_LEN];
	int32_t str_post_len =
			snprintf(str_post, MAX_BUF_LEN, "{ \"credential\": \"%s\", \"custom\": \"%s\" }",
					 p_app->str_credential, p_config->p_license_key);

	char str_authorization[MAX_BUF_LEN];
	char str_authorization_base64[MAX_BUF_LEN];
	int32_t str_authorization_base64_len = 0;
	snprintf(str_authorization, MAX_BUF_LEN, "%s:%s", p_config->p_customer_key,
			 p_config->p_customer_secret);
	base64_encode(str_authorization, strlen(str_authorization), str_authorization_base64);

	http_buffer_len =
			snprintf(http_buffer, HTTP_MAX_BUF_LEN,
					 "POST %s HTTP/1.1\r\n"
					 "Authorization: Basic %s\r\n"
					 "Host: %s\r\n"
					 "Content-type: application/json\r\n"
					 "Accept: */*\r\n"
					 "Content-length: %d\r\n\r\n"
					 "%s",
					 str_page, str_authorization_base64, server_name, str_post_len, str_post);
	// LOGS("SEND len=%d\n%s", http_buffer_len, http_buffer);

	rval = mbedtls_ssl_write(&ssl, http_buffer, http_buffer_len);
	if (rval <= 0) {
		rval = -1;
		LOGE("%s send license activate request failed, rval=%d", TAG_APP, rval);
		goto EXIT;
	}

	http_buffer_len = 0;
	http_buffer_pos = http_buffer;
	while (1) {
		rval = mbedtls_ssl_read(&ssl, http_buffer_pos, HTTP_MAX_BUF_LEN - http_buffer_len);
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

		http_buffer_len += rval;
		http_buffer_pos += rval;

		if (memchr(http_buffer_pos - rval, '}', rval)) {
			break;
		}
	}

	http_buffer[http_buffer_len] = '\0';
	// LOGS("RECV len=%d\n%s", http_buffer_len, http_buffer);

	http_parser_settings http_activation_settings = { 0 };
	http_activation_settings.on_body = _http_on_body;

	p_app->http_parser.data = (void *)p_app;
	http_parser_init(&p_app->http_parser, HTTP_RESPONSE);
	http_parser_execute(&p_app->http_parser, &http_activation_settings, http_buffer,
						http_buffer_len);
	if (!p_app->b_activate_success) {
		rval = -1;
		LOGE("%s activate failed", TAG_APP);
		LOGE("%s result: %s", TAG_APP, p_app->str_activate_result);
		goto EXIT;
	}
	LOGS("%s activate success", TAG_APP);

	char str_file_certificate[MAX_BUF_LEN];
	snprintf(str_file_certificate, MAX_BUF_LEN, "%s/%s", p_config->p_certificate_dir,
			 CERTIFACTE_FILENAME);
	rval = app_save_license_file(str_file_certificate, p_app->str_certificate,
								 &p_app->str_certificate_len);
	if (rval != 0) {
		LOGE("%s save certificate failed, path=%s", TAG_APP, str_file_certificate);
		goto EXIT;
	}

	LOGS("---------------------------  License Activation  ---------------------------");
	LOGS("|      %-32.32s%-36.36s |", "Generated certificate is saved: ", str_file_certificate);
	LOGS("|      %-68.66s |", "");
	LOGS("|      %-68.66s |", "!!! IF CERTIFICATE IS LOST, REACTIVATE WITH THE SAME LICENSE KEY");
	LOGS("----------------------------------------------------------------------------");

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
	int32_t rval = 0;
	app_t *p_app = app_get_instance();

	// 0. app parse args
	rval = app_parse_args(&p_app->config, argc, argv);
	if (rval != 0) {
		app_print_usage(argc, argv);
		goto EXIT;
	}

	// 1. license activate
	rval = app_activate_license(p_app);
	if (rval != 0) {
		LOGE("activate license failed, rval=%d", rval);
		goto EXIT;
	}

EXIT:
	return rval;
}

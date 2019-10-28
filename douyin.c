/***********************************************************************

************************************************************************/

#include <stdio.h>
#include "stdinc.h"
#include <stdlib.h>
#include <string.h>
#include "yemd5.h"

#define CHECK_FLAGS         0x0000
//#define CHECK_FLAGS         0x0040
//#define CHECK_FLAGS         0x0240

typedef struct {
	char *str1;
	char *str2;
	char *str3;
	char ch;
} user_info;

// 抖音
LOCAL user_info g_douyin = {
	"efc84c17",
	"57218436",
	"15387264",
	'1'
};

// 多闪
LOCAL user_info g_duosan = {
	"3ea57347",
	"57218436",
	"15387264",
	'2'
};

//////////////////////////////////////////////////////////
// for douyin
LOCAL uchar byte_71214[256] = {
	0x21, 0x4C, 0x74, 0x1B, 0x66, 0xCD, 0xB0, 0xD3, 0x33, 0x31, 0x4B, 0x77, 0x11, 0x45, 0xBE, 0x5E, 
	0x99, 0x28, 0x78, 0x5A, 0xBB, 0x3D, 0xF8, 0xB5, 0xAC, 0x62, 0x67, 0xEA, 0x26, 0xA6, 0x0F, 0x87, 
	0xA5, 0x1E, 0x9B, 0xD9, 0x12, 0x07, 0x41, 0xD6, 0xDC, 0x3A, 0x6C, 0x17, 0x9F, 0x56, 0x49, 0xC5, 
	0x22, 0xCB, 0x3B, 0xAD, 0x6A, 0xCC, 0xE6, 0x48, 0x76, 0x73, 0x24, 0x35, 0xE9, 0x7E, 0x8C, 0x05, 
	0x9A, 0x13, 0xC2, 0x30, 0xD2, 0xF6, 0x92, 0xEB, 0xE3, 0xB1, 0xAB, 0x14, 0x53, 0xBF, 0x47, 0x15, 
	0x82, 0xB2, 0x69, 0x27, 0xA1, 0x0E, 0x6E, 0xFB, 0x20, 0x0D, 0x50, 0xE8, 0x9E, 0x55, 0x7C, 0x46, 
	0x95, 0xA3, 0x52, 0x8E, 0x89, 0x3E, 0x9C, 0xD8, 0x90, 0xE2, 0x84, 0xEE, 0xD5, 0x4F, 0x29, 0x7B, 
	0x2D, 0x8A, 0xE7, 0xB4, 0xB3, 0xDF, 0xD4, 0x06, 0xDE, 0x6D, 0xAA, 0x23, 0x40, 0xA4, 0x5B, 0x4E, 
	0x38, 0x6F, 0x96, 0x91, 0xA8, 0x86, 0x00, 0x85, 0x98, 0x51, 0xA9, 0xA7, 0x57, 0xFC, 0x5D, 0x65, 
	0xC9, 0x72, 0xDB, 0x93, 0x03, 0x59, 0xF4, 0x4D, 0x71, 0xF3, 0xB8, 0x0A, 0x16, 0x2A, 0x44, 0x6B, 
	0x36, 0xC8, 0x0C, 0xF7, 0x8D, 0x4A, 0xF0, 0xFA, 0x25, 0x39, 0x97, 0x10, 0xE1, 0xD7, 0xC7, 0x58, 
	0x8B, 0x75, 0xCA, 0x60, 0x32, 0x2E, 0x2B, 0xB6, 0xBD, 0x1C, 0x79, 0xC1, 0x01, 0x34, 0x3C, 0x68, 
	0x9D, 0x5F, 0xA2, 0xE0, 0x08, 0xCF, 0xED, 0x64, 0x61, 0x04, 0xEC, 0x5C, 0xBC, 0xD0, 0xF9, 0xDD, 
	0x70, 0xDA, 0x0B, 0xFF, 0xF5, 0xF2, 0xB7, 0x7F, 0xB9, 0xCE, 0xC6, 0xA0, 0x88, 0x43, 0xC0, 0xD1, 
	0x83, 0x2F, 0xFD, 0x19, 0xE5, 0x1A, 0x80, 0x54, 0x18, 0x09, 0x3F, 0x7D, 0x1D, 0x42, 0x94, 0xFE, 
	0x8F, 0xAE, 0xEF, 0xE4, 0xC3, 0xBA, 0x7A, 0xF1, 0x63, 0x2C, 0xC4, 0xAF, 0x1F, 0x02, 0x81, 0x37
};

// byte_73308_r
LOCAL uchar byte_73308[256] = {
	0x86, 0xBC, 0xFD, 0x94, 0xC9, 0x3F, 0x77, 0x25, 0xC4, 0xE9, 0x9B, 0xD2, 0xA2, 0x59, 0x55, 0x1E, 
	0xAB, 0x0C, 0x24, 0x41, 0x4B, 0x4F, 0x9C, 0x2B, 0xE8, 0xE3, 0xE5, 0x03, 0xB9, 0xEC, 0x21, 0xFC, 
	0x58, 0x00, 0x30, 0x7B, 0x3A, 0xA8, 0x1C, 0x53, 0x11, 0x6E, 0x9D, 0xB6, 0xF9, 0x70, 0xB5, 0xE1, 
	0x43, 0x09, 0xB4, 0x08, 0xBD, 0x3B, 0xA0, 0xFF, 0x80, 0xA9, 0x29, 0x32, 0xBE, 0x15, 0x65, 0xEA, 
	0x7C, 0x26, 0xED, 0xDD, 0x9E, 0x0D, 0x5F, 0x4E, 0x37, 0x2E, 0xA5, 0x0A, 0x01, 0x97, 0x7F, 0x6D, 
	0x5A, 0x89, 0x62, 0x4C, 0xE7, 0x5D, 0x2D, 0x8C, 0xAF, 0x95, 0x13, 0x7E, 0xCB, 0x8E, 0x0F, 0xC1, 
	0xB3, 0xC8, 0x19, 0xF8, 0xC7, 0x8F, 0x04, 0x1A, 0xBF, 0x52, 0x34, 0x9F, 0x2A, 0x79, 0x56, 0x81, 
	0xD0, 0x98, 0x91, 0x39, 0x02, 0xB1, 0x38, 0x0B, 0x12, 0xBA, 0xF6, 0x6F, 0x5E, 0xEB, 0x3D, 0xD7, 
	0xE6, 0xFE, 0x50, 0xE0, 0x6A, 0x87, 0x85, 0x1F, 0xDC, 0x64, 0x71, 0xB0, 0x3E, 0xA4, 0x63, 0xF0, 
	0x68, 0x83, 0x46, 0x93, 0xEE, 0x60, 0x82, 0xAA, 0x88, 0x10, 0x40, 0x22, 0x66, 0xC0, 0x5C, 0x2C, 
	0xDB, 0x54, 0xC2, 0x61, 0x7D, 0x20, 0x1D, 0x8B, 0x84, 0x8A, 0x7A, 0x4A, 0x18, 0x33, 0xF1, 0xFB, 
	0x06, 0x49, 0x51, 0x74, 0x73, 0x17, 0xB7, 0xD6, 0x9A, 0xD8, 0xF5, 0x14, 0xCC, 0xB8, 0x0E, 0x4D, 
	0xDE, 0xBB, 0x42, 0xF4, 0xFA, 0x2F, 0xDA, 0xAE, 0xA1, 0x90, 0xB2, 0x31, 0x35, 0x05, 0xD9, 0xC5, 
	0xCD, 0xDF, 0x44, 0x07, 0x76, 0x6C, 0x27, 0xAD, 0x67, 0x23, 0xD1, 0x92, 0x28, 0xCF, 0x78, 0x75, 
	0xC3, 0xAC, 0x69, 0x48, 0xF3, 0xE4, 0x36, 0x72, 0x5B, 0x3C, 0x1B, 0x47, 0xCA, 0xC6, 0x6B, 0xF2, 
	0xA6, 0xF7, 0xD5, 0x99, 0x96, 0xD4, 0x45, 0xA3, 0x16, 0xCE, 0xA7, 0x57, 0x8D, 0xE2, 0xEF, 0xD3
};

LOCAL uint dword_73418[] = {
	0x452821e6, 0x38d01377, 0xbe5466cf, 0x34e90c6c,
	0xc0ac29b7, 0xc97c50dd, 0x3f84d5b5, 0xb5470917,
	0x9216d5d9, 0x8979fb1b, 0xd1310ba6, 0x98dfb5ac,
	0x2ffd72db, 0xd01adfb7, 0xb8e1afed, 0x6a267e96,
	0xba7c9045, 0xf12c7f99, 0x24a19947, 0xb3916cf7,
	0x0801f2e2, 0x858efc16, 0x636920d8, 0x71574e69,
	0xa458fea3, 0xf4933d7e, 0x0d95748f, 0x728eb658,
	0x718bcd58, 0x82154aee, 0x7b54a41d, 0xc25a59b5
};
LOCAL uint dword_73408[] = {
	0x9c30d539, 0x2af26013, 0xc5d1b023, 0x286085f0
};

LOCAL uchar g_initKey[16] = {
	0x72, 0x71, 0x67, 0xa2, 0xd1, 0xe4, 0x03, 0x3c, 0x47, 0xd4, 0x04, 0x4b, 0xfd, 0x85, 0x0d, 0xd2
};

LOCAL char * RAND_STR = "_ZYXWVUTSRQPONMLKJIH";
int global_rand = 0;

/////////////////////////////////////////////////////////////
LOCAL uchar hc2i(char ch)
{
	if(ch >= '0' && ch <= '9') return ch - '0';
	if(ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
	if(ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
	return 0xff;
}

LOCAL int hexstr2hex(char *str, size_t len, uchar *hex)
{
	int i, j;
	uchar ch;
	
	len &= 0xfffffffe;
	
	for(i = 0, j = 0; i < len; i += 2, j ++) {
		ch = hc2i(str[i]);
		if(ch == 0xff) break;
		hex[j] = ch << 4;
		
		ch = hc2i(str[i + 1]);
		if(ch == 0xff) break;
		hex[j] |= ch;
	}
	return j;
}

LOCAL char i2hc(uchar ch)
{
	if(ch >= 0x10) return '\0';
	if(ch < 10) return ch + '0';
	return 'a' + (ch - 10);
}

LOCAL int hex2hexstr(uchar *hex, size_t len, char *str)
{
	int i, j;
	char ch;
	
	for(i = 0, j = 0; i < len; i ++) {
		ch = i2hc(hex[i] >> 4);
		if(ch == '\0') break;
		str[j ++] = ch;
		
		ch = i2hc(hex[i] & 0xf);
		if(ch == '\0') break;
		str[j ++] = ch;
	}
	return j;
}

LOCAL uint bit_swap(uint v0)
{
	uint v1, v2;
	
	  v1 = ((v0 & 0xAAAAAAAA) >> 1) ^ ((v0 & 0x55555555) << 1);
	  v2 = ((v1 & 0xCCCCCCCC) >> 2) ^ ((v1 & 0x33333333) << 2);
	return ((v2 & 0xF0F0F0F0) >> 4) ^ ((v2 & 0x0F0F0F0F) << 4);
}

LOCAL uchar __rbit_byte(uchar ch)
{
	uchar c1, c2;
	
	c1 = ((ch & 0xAA) >> 1) ^ ((ch & 0x55) << 1);
	c2 = ((c1 & 0xCC) >> 2) ^ ((c1 & 0x33) << 2);
	c1 = ((c2 & 0xF0) >> 4) ^ ((c2 & 0x0F) << 4);
	
	return c1;
}

LOCAL void calc_md5(uchar *data, int size, char *md5)
{
	int i;
	md5_ctx_s md5ctx;
	uchar md5hex[16];
	
	yemd5_init(&md5ctx);
	yemd5_update(&md5ctx, data, size);
	yemd5_final(&md5ctx, md5hex);
	
	for(i = 0; i < 16; i ++) {
		snprintf(md5 + i * 2, 3, "%.2x", md5hex[i]);
	}
}

#define PARAM_NUM_MAX       512
typedef struct{
	char *position;
	int keylen;
	int valuelen;
} string_pos;

LOCAL int string_cmp(char *str1, int len1, char *str2, int len2)
{
	int i;
	
	for(i = 0; i < len1 && i < len2; i ++) {
		if(str1[i] > str2[i]) return 1;
		if(str1[i] < str2[i]) return -1;
	}
	if((i == len1) && (i == len2)) return 0;
	if(i == len1) return -1;
	return 1;
}

LOCAL int string_pos_add2list(string_pos *slist, int count, char *position, int klen, int vlen)
{
	int i, ret;
	
	for(i = 0; i < count; i ++) {
		ret = string_cmp(slist[i].position, slist[i].keylen, position, klen);
		if(ret == 0) return -1; // 表示已经存在，不再添加
		if(ret > 0) {
			memmove(&slist[i + 1], &slist[i], (count - i) * sizeof(string_pos));
			break;
		}
	}
	slist[i].position = position;
	slist[i].keylen = klen;
	slist[i].valuelen = vlen;
	return 0;
}

LOCAL void copy_param(uchar *dst, uchar *src, int len)
{
	int i;
	
	for(i = 0; i < len; i ++) {
		if(src[i] == '+' || src[i] == ' ') {
			dst[i] = 'a';
		} else {
			dst[i] = src[i];
		}
	}
}

LOCAL int calc_params_md5(user_info *puinfo, char *params, ulong ts, char *devid, char *hex)
{
	char *p1, *p2, *p3;
	int i, count, size = 0;
	string_pos *sposlist;
	char temp[128], *buf;
	
	// 用 纯c 写字符串操作就是比较操蛋～～
	sposlist = (string_pos *)malloc(PARAM_NUM_MAX * sizeof(string_pos));
	if(sposlist == NULL) {
		return -1;
	}
	p1 = temp;
	snprintf(p1, 128, "device_id=%s", devid);
	sposlist[0].position = p1;
	sposlist[0].keylen = 9;
	sposlist[0].valuelen = strlen(devid);
	size = sposlist[0].valuelen;
	
	p1 += sposlist[0].keylen + 1 + sposlist[0].valuelen;
	snprintf(p1, 100, "rstr=%s", puinfo->str1);
	sposlist[1].position = p1;
	sposlist[1].keylen = 4;
	sposlist[1].valuelen = strlen(puinfo->str1);
	size += sposlist[1].valuelen;
	
	p1 += sposlist[1].keylen + 1 + sposlist[1].valuelen;
	snprintf(p1, 80, "ts=%u", ts);
	sposlist[2].position = p1;
	sposlist[2].keylen = 2;
	sposlist[2].valuelen = strlen(p1) - 3;
	size += sposlist[2].valuelen;
	
	count = 3;
	
	size += strlen(devid) + 3;
	
	// 先提取参数对
	p1 = params;
	while(*p1 != '\0' && count < PARAM_NUM_MAX) {
		p2 = strchr(p1, '&');
		if(p2 == NULL) p2 = p1 + strlen(p1);
		p3 = strchr(p1, '=');
		if(p3 && (p3 > p1) && (p3 < p2)) {
			p3 ++;
			if(p3 != p2) {
				// 按升序添加
				if(string_pos_add2list(sposlist, count, p1, p3 - p1 - 1, p2 - p3) == 0) {
					size += p2 - p3;
					count ++;
				}
			}
		}
		
		if(*p2 == '\0') break;
		p1 = p2 + 1;
	}
	
	buf = (char *)malloc(size);
	if(buf == NULL) {
		free(sposlist);
		return -1;
	}
	p1 = buf;
	for(i = 0; i < count; i ++) {
		//memcpy(p1, sposlist[i].position + sposlist[i].keylen + 1, sposlist[i].valuelen);
		copy_param(p1, sposlist[i].position + sposlist[i].keylen + 1, sposlist[i].valuelen);
		p1 += sposlist[i].valuelen;
	}
	free(sposlist);
	strcpy_s(p1, strlen(devid) + 1, devid);
	p1 += strlen(p1);
	*p1 ++ = '4';
	*p1 ++ = '3';
	*p1 ++ = '5';
	
	calc_md5(buf, size, hex);
	free(buf);
	return 0;
}

LOCAL int calc_params_md5_with_rand(user_info *puinfo, char *params, ulong ts, char *devid, char *hex, char *rand)
{
	char *p1, *p2, *p3;
	int i, count, size = 0;
	string_pos *sposlist;
	char temp[128], *buf;

	// 用 纯c 写字符串操作就是比较操蛋～～
	sposlist = (string_pos *)malloc(PARAM_NUM_MAX * sizeof(string_pos));
	if (sposlist == NULL) {
		return -1;
	}
	p1 = temp;
	snprintf(p1, 128, "device_id=%s", devid);
	sposlist[0].position = p1;
	sposlist[0].keylen = 9;
	sposlist[0].valuelen = strlen(devid);
	size = sposlist[0].valuelen;

	p1 += sposlist[0].keylen + 1 + sposlist[0].valuelen;
	snprintf(p1, 100, "rstr=%s", puinfo->str1);
	sposlist[1].position = p1;
	sposlist[1].keylen = 4;
	sposlist[1].valuelen = strlen(puinfo->str1);
	size += sposlist[1].valuelen;

	p1 += sposlist[1].keylen + 1 + sposlist[1].valuelen;
	snprintf(p1, 80, "ts=%u", ts);
	sposlist[2].position = p1;
	sposlist[2].keylen = 2;
	sposlist[2].valuelen = strlen(p1) - 3;
	size += sposlist[2].valuelen;

	count = 3;

	size += strlen(devid) + 3;

	// 先提取参数对
	p1 = params;
	while (*p1 != '\0' && count < PARAM_NUM_MAX) {
		p2 = strchr(p1, '&');
		if (p2 == NULL) p2 = p1 + strlen(p1);
		p3 = strchr(p1, '=');
		if (p3 && (p3 > p1) && (p3 < p2)) {
			p3++;
			if (p3 != p2) {
				// 按升序添加
				if (string_pos_add2list(sposlist, count, p1, p3 - p1 - 1, p2 - p3) == 0) {
					size += p2 - p3;
					count++;
				}
			}
		}

		if (*p2 == '\0') break;
		p1 = p2 + 1;
	}

	buf = (char *)malloc(size);
	if (buf == NULL) {
		free(sposlist);
		return -1;
	}
	p1 = buf;
	for (i = 0; i < count; i++) {
		//memcpy(p1, sposlist[i].position + sposlist[i].keylen + 1, sposlist[i].valuelen);
		copy_param(p1, sposlist[i].position + sposlist[i].keylen + 1, sposlist[i].valuelen);
		p1 += sposlist[i].valuelen;
	}
	free(sposlist);
	strcpy_s(p1, strlen(devid) + 1, devid);
	p1 += strlen(p1);
	//strcpy_s(buf-3, 3, rand);
	*p1++ = rand[0];
	*p1++ = rand[1];
	*p1++ = rand[2];
	//printf("buf:%s\n", buf);
	calc_md5(buf, size, hex);
	free(buf);
	return 0;
}

/*
计算 ascp
  输入:
	ts: 10 位时间戳
	params: 计算参数, 每个参数用 & 分割
	deviceId: 设备ID
  输出:
	ascp: 返回 44 字节的ascp值, 空间由上层申请(>44字节)
  返回:
	成功返回 0, 失败返回 -1
*/
int __stdcall GetASCP(ulong ts, char *params, char *deviceId, char *ascp)
{
	int i;
	char hex[33], *p;
	user_info *puinfo = NULL;
	
	if(params == NULL || deviceId == NULL || ascp == NULL) {
		return -1;
	}
	
	puinfo = &g_douyin;
	
	p = strchr(params, '?');
	if(p) params = p + 1;
	
	// 解析参数
	if(calc_params_md5(puinfo, params, ts, deviceId, hex) != 0) {
		return -1;
	}
	
	if(((~ts) & 1) == 0) {
		calc_md5(hex, 32, hex);
	}
	
	//// 先初始化固定值
	//ascp[0] = 'a';
	//ascp[1] = puinfo->ch;
	//ascp[18] = '4';
	//ascp[19] = '3';
	//ascp[20] = '5';
	//ascp[21] = '5';
	//ascp[38] = 'e';
	//ascp[39] = puinfo->ch;

	// 先初始化固定值
	ascp[0] = 'a';
	ascp[1] = puinfo->ch;
	ascp[18] = '4';
	ascp[19] = '3';
	ascp[20] = '5';
	ascp[21] = '5';

	ascp[38] = 'e';
	ascp[39] = puinfo->ch;
	
	// 下面的4个用变量地址进行运算出来的，有点随机的味道，可以写死
	ascp[40] = 'Y';
	ascp[41] = 'c';
	ascp[42] = 'a';
	ascp[43] = 'g';
	ascp[44] = '\0';
	
	for(i = 0; i < 8; i ++) {
		ascp[2 + i * 2] = hex[i];
	}
	for(i = 24; i < 32; i ++) {
		ascp[23 + (i - 24) * 2] = hex[i];
	}
	
	snprintf(hex, 10, "%08x", ts);
	for(i = 0; i < 8; i ++) {
		ascp[22 + i * 2] = hex[puinfo->str2[i] - '1'];
		ascp[ 3 + i * 2] = hex[puinfo->str3[i] - '1'];
	}
	
	return 0;
}

int __stdcall GetASCP1(ulong ts, char *params, char *deviceId, char *ascp, char *rand_str) {
	int i;
	char hex[33], *p;
	user_info *puinfo = NULL;

	if (params == NULL || deviceId == NULL || ascp == NULL) {
		return -1;
	}

	puinfo = &g_douyin;

	p = strchr(params, '?');
	if (p) params = p + 1;

	// 解析参数
	if (calc_params_md5_with_rand(puinfo, params, ts, deviceId, hex, rand_str) != 0) {
		return -1;
	}
	if (((~ts) & 1) == 0) {
		calc_md5(hex, 32, hex);
	}


	ascp[0] = 'a';
	ascp[1] = puinfo->ch;
	memcpy(ascp + 18, rand_str, 4);
	ascp[38] = 'e';
	ascp[39] = puinfo->ch;

	if (!global_rand) {
		srand(time(NULL));
	}

	ascp[40] = RAND_STR[rand() % 20];
	ascp[41] = 's';
	ascp[42] = RAND_STR[rand() % 20];
	ascp[43] = 'a';
	ascp[44] = '\0';

	for (i = 0; i < 8; i++) {
		ascp[2 + i * 2] = hex[i];
	}
	for (i = 24; i < 32; i++) {
		ascp[23 + (i - 24) * 2] = hex[i];
	}

	snprintf(hex, 10, "%08x", ts);
	for (i = 0; i < 8; i++) {
		ascp[22 + i * 2] = hex[puinfo->str2[i] - '1'];
		ascp[3 + i * 2] = hex[puinfo->str3[i] - '1'];
	}

	return 0;


		
}

int __stdcall GetASCPDuosan(ulong ts, char *params, char *deviceId, char *ascp, char *rand_str) {
	int i;
	char hex[33], *p;
	user_info *puinfo = NULL;

	if (params == NULL || deviceId == NULL || ascp == NULL) {
		return -1;
	}

	puinfo = &g_duosan;

	p = strchr(params, '?');
	if (p) params = p + 1;

	// 解析参数
	if (calc_params_md5_with_rand(puinfo, params, ts, deviceId, hex, rand_str) != 0) {
		return -1;
	}
	if (((~ts) & 1) == 0) {
		calc_md5(hex, 32, hex);
	}


	ascp[0] = 'a';
	ascp[1] = puinfo->ch;
	memcpy(ascp + 18, rand_str, 4);
	ascp[38] = 'e';
	ascp[39] = puinfo->ch;

	if (!global_rand) {
		srand(time(NULL));
	}

	ascp[40] = RAND_STR[rand() % 20];
	ascp[41] = 's';
	ascp[42] = RAND_STR[rand() % 20];
	ascp[43] = 'a';
	ascp[44] = '\0';

	for (i = 0; i < 8; i++) {
		ascp[2 + i * 2] = hex[i];
	}
	for (i = 24; i < 32; i++) {
		ascp[23 + (i - 24) * 2] = hex[i];
	}

	snprintf(hex, 10, "%08x", ts);
	for (i = 0; i < 8; i++) {
		ascp[22 + i * 2] = hex[puinfo->str2[i] - '1'];
		ascp[3 + i * 2] = hex[puinfo->str3[i] - '1'];
	}

	return 0;



}

LOCAL uint sub_20224(uint a1)
{
	uint a;
	uchar c1, c2, c3, c4;
	
	c1 = (a1 >> 24) & 0xFF;
	c2 = (a1 >> 16) & 0xFF;
	c3 = (a1 >>  8) & 0xFF;
	c4 = (a1      ) & 0xFF;
	
	a = (byte_73308[c1] << 24) | (byte_73308[c2] << 16) | (byte_73308[c3] << 8) | byte_73308[c4];
	return ((a << 10) | (a >> 22)) ^ ((a >> 8) | (a << 24)) ^ a ^ ((a << 2) | (a >> 30)) ^ ((a << 18) | (a >> 14));
}

LOCAL uint sub_1F6B0(uint a1)
{
	int i;
	uchar *p = (uchar *)&a1;
	uint s = 0;
	
	for(i = 0; i < 4; i ++) {
		s = (s << 4) + p[i];
		if(s & 0xF0000000) break;
	}
	return s & 0x7fffffff;
}

LOCAL uint sub_1F2E4(uint a1)
{
	int i;
	uchar *p = (uchar *)&a1;
	uint s = 0x4e67c6a7;
	
	for(i = 0; i < 4; i ++) {
		s ^= (s << 5) + (s >> 2) + p[i];
	}
	return s & 0x7fffffff;
}

LOCAL uint sub_1F4D0(uint a1)
{
	int i;
	uchar *p = (uchar *)&a1;
	uint s = 0;
	
	for(i = 0; i < 4; i ++) {
		if(i & 0x1) {
			s ^= (s << 11) ^ (s >> 5) ^ p[i] ^ 0xFFFFFFFF;
		} else {
			s ^= (s << 7) ^ (s >> 3) ^ p[i];
		}
	}
	return s & 0x7fffffff;
}

LOCAL void sub_1EB64(uint *idata, uchar *key, uchar *odata)
{
	int i;
	uint val[36];
	
	memset(val, 0, sizeof(val));
	val[0] = (key[ 0] << 0x18) | (key[ 1] << 0x10) | (key[ 2] << 0x08) | key[ 3];
	val[1] = (key[ 4] << 0x18) | (key[ 5] << 0x10) | (key[ 6] << 0x08) | key[ 7];
	val[2] = (key[ 8] << 0x18) | (key[ 9] << 0x10) | (key[10] << 0x08) | key[11];
	val[3] = (key[12] << 0x18) | (key[13] << 0x10) | (key[14] << 0x08) | key[15];
	
	for(i = 0; i < 32; i ++) {
		val[i + 4] = sub_20224(val[i + 1] ^ val[i + 2] ^ val[i + 3] ^ idata[i]) ^ val[i];
	}

	odata[ 0] = val[35] >> 0x18; odata[ 1] = val[35] >> 0x10; odata[ 2] = val[35] >> 0x08; odata[ 3] = val[35];
	odata[ 4] = val[34] >> 0x18; odata[ 5] = val[34] >> 0x10; odata[ 6] = val[34] >> 0x08; odata[ 7] = val[34];
	odata[ 8] = val[33] >> 0x18; odata[ 9] = val[33] >> 0x10; odata[10] = val[33] >> 0x08; odata[11] = val[33];
	odata[12] = val[32] >> 0x18; odata[13] = val[32] >> 0x10; odata[14] = val[32] >> 0x08; odata[15] = val[32];
}

LOCAL void douyin_my_encrypt(uchar *a1, int size, uint *a3, uchar *a4)
{
	int i, r;
	uchar ch1, ch2;
	uint *p;
	
	for(i = 0; i < size / 2; i ++) {
		ch1 = *(uchar *)(byte_73308 + byte_71214[__rbit_byte(a1[i])]);
		ch2 = *(uchar *)(byte_73308 + byte_71214[__rbit_byte(a1[size - i - 1])]);
		
		a1[i] = ch2;
		a1[size - i - 1] = ch1;
	}
	
	if((size % 16) == 0) {
		memcpy(a4, a1, 16);
		sub_1EB64(a3, a1, a1);
		
		r = size / 4;
		p = (uint *)a1;
		for(i = 0; i < r; i ++) {
			p[i] = bit_swap(p[i]) ^ bit_swap(sub_1F6B0(p[(i + 1) % r])) ^ bit_swap(sub_1F4D0(p[(i + 2) % r])) ^ bit_swap(sub_1F2E4(p[(i + 3) % r]));
		}
	}
}

LOCAL void douyin_my_decrypt(uchar *a1, int size, uint *a3, uchar *a4)
{
	int i, r;
	uchar ch1, ch2;
	uint *p;
	
	if((size % 16) == 0) {
		p = (uint *)a1;
		
		r = size / 4;
		for(i = r - 1; i >= 0; i --) {
			p[i] = p[i] ^ bit_swap(sub_1F6B0(p[(i + 1) % r])) ^ bit_swap(sub_1F4D0(p[(i + 2) % r])) ^ bit_swap(sub_1F2E4(p[(i + 3) % r]));
			p[i] = bit_swap(p[i]);
		}
		
		sub_1EB64(a3, a1, a1);
		memcpy(a4, a1, 16);
	}
	
	for(i = 0; i < size / 2; i ++) {
		ch1 = *(uchar *)(byte_73308 + *(uchar *)(byte_71214 + __rbit_byte(a1[i])));
		ch2 = *(uchar *)(byte_73308 + *(uchar *)(byte_71214 + __rbit_byte(a1[size - i - 1])));
		a1[i] = ch2;
		a1[size - i - 1] = ch1;
	}
}

LOCAL uint sub_1F0D0(uint a1)
{
	uint r1, r2;
	uint a, b, c, d;
	
	a = *(uchar *)(byte_73308 + (uchar)(a1 >> 0x18));
	b = *(uchar *)(byte_73308 + (uchar)(a1 >> 0x10));
	c = *(uchar *)(byte_73308 + (uchar)(a1 >> 0x08));
	d = *(uchar *)(byte_73308 + (uchar)(a1        ));
	
	r1 = (a << 0x18) | (b << 0x10) | (c << 0x08) | d;
	
	r2 = r1 ^ ((r1 << 0x0d) | (r1 >> 0x13)) ^ ((r1 >> 0x09) | (r1 << 0x17));
	
	return r2;
}

LOCAL void douyin_my_setencryptkey(uint odata[32], uchar idata[16])
{
	int i;
	uint temp, val[40];
	
	memset(val, 0, sizeof(val));
	
	val[0] = ((idata[ 0] << 0x18) | (idata[ 1] << 0x10) | (idata[ 2] << 0x08) | idata[ 3]) ^ dword_73408[0];
	val[1] = ((idata[ 4] << 0x18) | (idata[ 5] << 0x10) | (idata[ 6] << 0x08) | idata[ 7]) ^ dword_73408[1];
	val[2] = ((idata[ 8] << 0x18) | (idata[ 9] << 0x10) | (idata[10] << 0x08) | idata[11]) ^ dword_73408[2];
	val[3] = ((idata[12] << 0x18) | (idata[13] << 0x10) | (idata[14] << 0x08) | idata[15]) ^ dword_73408[3];

	for(i = 0; i < 32; i ++) {
		temp = dword_73418[i] ^ val[i + 0] ^ val[i + 1] ^ val[i + 2] ^ val[i + 3];
		val[i + 4] = sub_1F0D0(temp);
		odata[i] = val[i + 4];
	}
}

LOCAL void douyin_my_setdecryptkey(uint odata[32], uchar idata[16])
{
	int i;
	douyin_my_setencryptkey(odata, idata);
	
	// swap
	for(i = 0; i < 16; i ++) {
		odata[i] ^= odata[31 - i];
		odata[31 - i] ^= odata[i];
		odata[i] ^= odata[31 - i];
	}
}

int __stdcall GetMAS(char *as, char *mas)
{
	int i, offset;
	uchar *pos;
	uint ui1, ui2, ui3;
	uchar ch1, ch2;
	uchar data[27];
	uint yeKey[32];
	uchar key[16];
	
	// 参数非空判断
	if(as == NULL || mas == NULL) {
		return -1;
	}
	// 判断输入的 as 长度是否为22
	if(strlen(as) != 22) {
		return -1;
	}
	
	data[0] = 0x01;
	pos = data + 1;
	*pos = (uchar)data;
	*(pos + 1) = (ushort)data >> 8;
	//*pos = 0x80;
	//*(pos + 1) = 0x36;
	
	*(ushort *)(pos + 2) = CHECK_FLAGS;
	memcpy(pos + 4, as, 22);
	
	memset(yeKey, 0, sizeof(yeKey));
	memcpy(key, g_initKey, 16);
	
	douyin_my_setencryptkey(yeKey, key);
	douyin_my_encrypt(pos, 16, yeKey, key);
	douyin_my_setencryptkey(yeKey, key);
	douyin_my_encrypt(pos + 16, 10, yeKey, key);
	
	for(i = 0; i < 27; i ++) {
		//sprintf(mas + i * 2, "%.2x", data[i]);
		sprintf_s(mas + i * 2, 3, "%.2x", data[i]);
	}
	return 0;
}

int __stdcall GetMAS1(char *as, char *mas, ushort rand) {

	int i, offset;
	uchar *pos;
	uint ui1, ui2, ui3;
	uchar ch1, ch2;
	uchar data[27];
	uint yeKey[32];
	uchar key[16];

	// 参数非空判断
	if (as == NULL || mas == NULL) {
		return -1;
	}
	// 判断输入的 as 长度是否为22
	if (strlen(as) != 22) {
		return -1;
	}
		
	data[0] = 0x01;
	pos = data + 1;
	*(ushort *)(pos) = rand;

	*(ushort *)(pos + 2) = CHECK_FLAGS;
	memcpy(pos + 4, as, 22);

	memset(yeKey, 0, sizeof(yeKey));
	memcpy(key, g_initKey, 16);

	douyin_my_setencryptkey(yeKey, key);
	douyin_my_encrypt(pos, 16, yeKey, key);
	douyin_my_setencryptkey(yeKey, key);
	douyin_my_encrypt(pos + 16, 10, yeKey, key);

	for (i = 0; i < 27; i++) {
		//sprintf(mas + i * 2, "%.2x", data[i]);
		sprintf_s(mas + i * 2, 3, "%.2x", data[i]);
	}
	return 0;

}

void __stdcall MemFree(void *ptr)
{
	if(ptr) free(ptr);
}

uchar *__stdcall XlogEncrypt(uchar *data, int *psize)
{
	int encsize, leftlen;
	uint yeKey[32];
	uchar key[16];
	uchar *buffer = NULL, *pos;
	
	if(data == NULL || psize == NULL) {
		return NULL;
	}
	
	leftlen = *psize + 4;
	buffer = (uchar *)malloc(leftlen + 1);
	if(buffer == NULL) {
		return NULL;
	}
	buffer[0] = 0x01;
	pos = buffer + 1;
	*pos = (uchar)buffer;
	*(pos + 1) = (ushort)buffer >> 8;
	*(ushort *)(pos + 2) = CHECK_FLAGS;
	memcpy(pos + 4, data, *psize);
	
	memset(yeKey, 0, sizeof(yeKey));
	memcpy(key, g_initKey, 16);
	
	while(leftlen > 0) {
		douyin_my_setencryptkey(yeKey, key);
		encsize = (leftlen >= 16) ? 16 : leftlen;
		douyin_my_encrypt(pos, encsize, yeKey, key);
		
		pos += encsize;
		leftlen -= encsize;
	}
	*psize += 5; 
	return buffer;
}

uchar *__stdcall XlogDecrypt(uchar *data, int *psize)
{
	int encsize, leftlen;
	uint yeKey[32];
	uchar key[16];
	uchar *buffer = NULL, *pos;
	
	if(data == NULL || psize == NULL || *psize < 3) {
		return NULL;
	}
	if((data[0] != 1) || (*psize == 27)) {
		return NULL;
	}
	leftlen = *psize - 1;
	
	buffer = (uchar *)malloc(leftlen);
	if(buffer == NULL) {
		return NULL;
	}
	
	memset(yeKey, 0, sizeof(yeKey));
	memcpy(key, g_initKey, 16);
	
	memcpy(buffer, data + 1, leftlen);
	pos = buffer;
	while(leftlen > 0) {
		douyin_my_setdecryptkey(yeKey, key);
		encsize = (leftlen >= 16) ? 16 : leftlen;
		douyin_my_decrypt(pos, encsize, yeKey, key);
		
		pos += encsize;
		leftlen -= encsize;
	}
	
	*psize -= 5;
	memmove(buffer, buffer + 4, *psize);
	return buffer;
}

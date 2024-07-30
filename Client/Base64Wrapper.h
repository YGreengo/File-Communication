#pragma once

#include <string>
#include <cryptopp/base64.h>


class Base64Wrapper
{
public:
	static std::string encode(const std::string& str);
	static std::string decode(const std::string& str);
};

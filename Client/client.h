#pragma once
# include <iomanip>
#include <string>
#include <sstream>
#include <iostream>
#include <fstream>
#include <vector>
#include <chrono>
#include <thread> 
#include <boost/asio.hpp>
#include <boost/endian/conversion.hpp>
#include <cmath>
#include <ostream>
#include <cstdio>
#include <iterator>
#include <regex>
#include <filesystem>
#include <cryptopp/cryptlib.h>
#include <cryptopp/rsa.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/integer.h>
#include <cryptopp/base64.h>
#include <cryptopp/files.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <tuple>
#include"AESWrapper.h"
#include "RSAWrapper.h"
#include "Base64Wrapper.h"

using namespace CryptoPP;
using namespace std;


class Client {
public:
    Client() : name(""), id("") {};
    Client(const string& name, const string& id, const RSA::PrivateKey& private_key, const RSA::PublicKey& public_key)
        : name(name), id(id), private_key(private_key), public_key(public_key) {};
    ~Client() {}

    // getters
    string get_name() const { return name; }
    string get_id() const { return id; }
    RSA::PrivateKey get_private_key() const { return private_key; }
    RSA::PublicKey get_public_key() const { return public_key; }

    // setters
    void set_name(const string& newName) { name = newName; }
    void set_id(const string& newId) { id = newId; }
    void set_private_key(const RSA::PrivateKey& newPrivateKey) { private_key = newPrivateKey; }
    void set_public_key(const RSA::PublicKey& newPublicKey) { public_key = newPublicKey; }

private:
    string name;
    string id;
    RSA::PrivateKey private_key;
    RSA::PublicKey public_key;
};

class Request {
public:
    string get_client_id() const { return client_id; }
    void set_client_id(const string& newClientId) { client_id = newClientId; }

    unsigned char get_version() const { return version; }
    void set_version(unsigned char newVersion) { version = newVersion; }

    unsigned short int get_code() const { return code; }
    void set_code(unsigned short int newCode) { code = newCode; }

    unsigned int get_payload_size() const { return payload_size; }
    void set_payload_size(unsigned int newSize) { payload_size = newSize; }

    vector<char> get_payload() const { return payload; }
    void set_payload(const vector<char> newPayload) { payload = newPayload; }

    vector<unsigned char> pack() const;

private:
    string client_id;
    unsigned char version;
    unsigned short int code;
    unsigned int payload_size;
    vector<char> payload;
};

RSA::PrivateKey remake_private_key(const string& key_string);


string base_64_convert(RSA::PrivateKey privateKey);

void write_my_file(const string& name, const string& id, const string& privateKey);
string hex_to_string(const vector<unsigned char>& hexData);
void write_key_to_file(const string& content);
string read_key_file(const string& filename);
bool file_exists(const string& file_name);
vector<unsigned char> hex_to_bytes(const std::string& hex);
string decryptRSA(const RSA::PrivateKey& privateKey, const vector<CryptoPP::byte>& ciphertext);
string AESEncrypt(const CryptoPP::byte* key, const char* plaintext, unsigned int length);
void handle_1025_request(boost::asio::ip::tcp::socket& s);
void handle_1026_request(boost::asio::ip::tcp::socket& s, unsigned short int code);
void handle_1027_request(boost::asio::ip::tcp::socket& s);
void handle_1028_request(boost::asio::ip::tcp::socket& s);
void handle_1029_30_31_request(boost::asio::ip::tcp::socket& s, unsigned short int request_num);
const char* read_file_into_buffer(const string fname);
bool check_username(const string& username);
unsigned long memcrc(char* b, size_t n);

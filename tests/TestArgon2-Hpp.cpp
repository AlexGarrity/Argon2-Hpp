#include <Argon2/Argon2.hpp>
#include <cstring>
#include <gtest/gtest.h>

const auto HASHLEN    = 32;
const auto ENCODEDLEN = 128;
const auto SALTLEN    = 16;
const std::string PWD = "password";

const uint32_t t_cost      = 2;         // 2-pass computation
const uint32_t m_cost      = (1 << 16); // 64 mebibytes memory usage
const uint32_t parallelism = 1;         // number of threads and lanes

TEST(Argon2i, Hash_Raw)
{
	uint8_t hash1[HASHLEN];
	auto hash2 = std::vector<std::uint8_t>(HASHLEN);

	{
		uint8_t salt[SALTLEN];
		memset(salt, 0x00, SALTLEN);

		uint8_t* pwd    = (uint8_t*)strdup(PWD.c_str());
		uint32_t pwdlen = strlen((char*)pwd);

		auto error = argon2i_hash_raw(t_cost, m_cost, parallelism, pwd, pwdlen, salt, SALTLEN, hash1, HASHLEN);
		EXPECT_EQ(error, argon2_error_codes::ARGON2_OK);
	}

	{
		auto salt = std::vector<std::uint8_t>(SALTLEN);
		auto pwd  = std::vector<std::uint8_t>(PWD.begin(), PWD.end());

		auto error = Argon2::i_hash_raw(t_cost, m_cost, parallelism, pwd, salt, hash2);
		EXPECT_EQ(error, Argon2::ErrorCodes::Ok);
	}

	EXPECT_EQ(std::memcmp(hash1, hash2.data(), HASHLEN), 0);
}

TEST(Argon2i, Hash_Encoded)
{
	char encoded1[ENCODEDLEN];
	auto encoded2 = std::string();
	encoded2.resize(ENCODEDLEN);

	{
		uint8_t salt[SALTLEN];
		memset(salt, 0x00, SALTLEN);

		uint8_t* pwd    = (uint8_t*)strdup(PWD.c_str());
		uint32_t pwdlen = strlen((char*)pwd);

		auto error = argon2i_hash_encoded(t_cost, m_cost, parallelism, pwd, pwdlen, salt, SALTLEN, HASHLEN, encoded1, ENCODEDLEN);
		EXPECT_EQ(error, argon2_error_codes::ARGON2_OK);

		auto result = Argon2::i_verify(encoded1, std::vector<std::uint8_t>(pwd, pwd + pwdlen));
		EXPECT_EQ(result, Argon2::ErrorCodes::Ok);
	}

	{
		auto salt = std::vector<std::uint8_t>(SALTLEN);
		auto pwd  = std::vector<std::uint8_t>(PWD.begin(), PWD.end());

		auto error = Argon2::i_hash_encoded(t_cost, m_cost, parallelism, pwd, salt, HASHLEN, encoded2);
		EXPECT_EQ(error, Argon2::ErrorCodes::Ok);

		auto result = argon2i_verify(encoded1, pwd.data(), pwd.size());
		EXPECT_EQ(result, argon2_error_codes::ARGON2_OK);
	}

	EXPECT_EQ(std::memcmp(encoded1, encoded2.data(), encoded2.size()), 0);
}

TEST(Argon2i, CTX)
{
	uint8_t hash1[HASHLEN];
	auto hash2 = std::vector<std::uint8_t>(HASHLEN);

	{
		uint8_t salt[SALTLEN];
		memset(salt, 0x00, SALTLEN);

		uint8_t* pwd    = (uint8_t*)strdup(PWD.c_str());
		uint32_t pwdlen = strlen((char*)pwd);

		argon2_context context = {
		    hash1,   /* output array, at least HASHLEN in size */
		    HASHLEN, /* digest length */
		    pwd,     /* password array */
		    pwdlen,  /* password length */
		    salt,    /* salt array */
		    SALTLEN, /* salt length */
		    NULL,
		    0, /* optional secret data */
		    NULL,
		    0, /* optional associated data */
		    t_cost,
		    m_cost,
		    parallelism,
		    parallelism,
		    ARGON2_VERSION_13, /* algorithm version */
		    NULL,
		    NULL, /* custom memory allocation / deallocation functions */
		    /* by default only internal memory is cleared (pwd is not wiped) */
		    ARGON2_DEFAULT_FLAGS};

		auto error = argon2i_ctx(&context);
		EXPECT_EQ(error, argon2_error_codes::ARGON2_OK);
	}

	{
		auto salt = std::vector<std::uint8_t>(SALTLEN);
		auto pwd  = std::vector<std::uint8_t>(PWD.begin(), PWD.end());

		auto context = Argon2::Context{
		    hash2,
		    pwd,
		    salt,
		    {},
		    {},
		    t_cost,
		    m_cost,
		    parallelism,
		    parallelism,
		    Argon2::Version::Version13,
		    nullptr,
		    nullptr,
		    Argon2::Flags::Default};

		auto error = Argon2::i_ctx(context);
		EXPECT_EQ(error, Argon2::ErrorCodes::Ok);
	}

	EXPECT_EQ(std::memcmp(hash1, hash2.data(), HASHLEN), 0);
}

TEST(Argon2d, Hash_Raw)
{
	uint8_t hash1[HASHLEN];
	auto hash2 = std::vector<std::uint8_t>(HASHLEN);

	{
		uint8_t salt[SALTLEN];
		memset(salt, 0x00, SALTLEN);

		uint8_t* pwd    = (uint8_t*)strdup(PWD.c_str());
		uint32_t pwdlen = strlen((char*)pwd);

		auto error = argon2d_hash_raw(t_cost, m_cost, parallelism, pwd, pwdlen, salt, SALTLEN, hash1, HASHLEN);
		EXPECT_EQ(error, argon2_error_codes::ARGON2_OK);
	}

	{
		auto salt = std::vector<std::uint8_t>(SALTLEN);
		auto pwd  = std::vector<std::uint8_t>(PWD.begin(), PWD.end());

		auto error = Argon2::d_hash_raw(t_cost, m_cost, parallelism, pwd, salt, hash2);
		EXPECT_EQ(error, Argon2::ErrorCodes::Ok);
	}

	EXPECT_EQ(std::memcmp(hash1, hash2.data(), HASHLEN), 0);
}

TEST(Argon2d, Hash_Encoded)
{
	char encoded1[ENCODEDLEN];
	auto encoded2 = std::string();
	encoded2.resize(ENCODEDLEN);

	{
		uint8_t salt[SALTLEN];
		memset(salt, 0x00, SALTLEN);

		uint8_t* pwd    = (uint8_t*)strdup(PWD.c_str());
		uint32_t pwdlen = strlen((char*)pwd);

		auto error = argon2d_hash_encoded(t_cost, m_cost, parallelism, pwd, pwdlen, salt, SALTLEN, HASHLEN, encoded1, ENCODEDLEN);
		EXPECT_EQ(error, argon2_error_codes::ARGON2_OK);

		auto result = Argon2::d_verify(encoded1, std::vector<std::uint8_t>(pwd, pwd + pwdlen));
		EXPECT_EQ(result, Argon2::ErrorCodes::Ok);
	}

	{
		auto salt = std::vector<std::uint8_t>(SALTLEN);
		auto pwd  = std::vector<std::uint8_t>(PWD.begin(), PWD.end());

		auto error = Argon2::d_hash_encoded(t_cost, m_cost, parallelism, pwd, salt, HASHLEN, encoded2);
		EXPECT_EQ(error, Argon2::ErrorCodes::Ok);

		auto result = argon2d_verify(encoded1, pwd.data(), pwd.size());
		EXPECT_EQ(result, argon2_error_codes::ARGON2_OK);
	}

	EXPECT_EQ(std::memcmp(encoded1, encoded2.data(), encoded2.size()), 0);
}

TEST(Argon2d, CTX)
{
	uint8_t hash1[HASHLEN];
	auto hash2 = std::vector<std::uint8_t>(HASHLEN);

	{
		uint8_t salt[SALTLEN];
		memset(salt, 0x00, SALTLEN);

		uint8_t* pwd    = (uint8_t*)strdup(PWD.c_str());
		uint32_t pwdlen = strlen((char*)pwd);

		argon2_context context = {
		    hash1,   /* output array, at least HASHLEN in size */
		    HASHLEN, /* digest length */
		    pwd,     /* password array */
		    pwdlen,  /* password length */
		    salt,    /* salt array */
		    SALTLEN, /* salt length */
		    NULL,
		    0, /* optional secret data */
		    NULL,
		    0, /* optional associated data */
		    t_cost,
		    m_cost,
		    parallelism,
		    parallelism,
		    ARGON2_VERSION_13, /* algorithm version */
		    NULL,
		    NULL, /* custom memory allocation / deallocation functions */
		    /* by default only internal memory is cleared (pwd is not wiped) */
		    ARGON2_DEFAULT_FLAGS};

		auto error = argon2d_ctx(&context);
		EXPECT_EQ(error, argon2_error_codes::ARGON2_OK);
	}

	{
		auto salt = std::vector<std::uint8_t>(SALTLEN);
		auto pwd  = std::vector<std::uint8_t>(PWD.begin(), PWD.end());

		auto context = Argon2::Context{
		    hash2,
		    pwd,
		    salt,
		    {},
		    {},
		    t_cost,
		    m_cost,
		    parallelism,
		    parallelism,
		    Argon2::Version::Version13,
		    nullptr,
		    nullptr,
		    Argon2::Flags::Default};

		auto error = Argon2::d_ctx(context);
		EXPECT_EQ(error, Argon2::ErrorCodes::Ok);
	}

	EXPECT_EQ(std::memcmp(hash1, hash2.data(), HASHLEN), 0);
}

TEST(Argon2id, Hash_Raw)
{
	uint8_t hash1[HASHLEN];
	auto hash2 = std::vector<std::uint8_t>(HASHLEN);

	{
		uint8_t salt[SALTLEN];
		memset(salt, 0x00, SALTLEN);

		uint8_t* pwd    = (uint8_t*)strdup(PWD.c_str());
		uint32_t pwdlen = strlen((char*)pwd);

		auto error = argon2id_hash_raw(t_cost, m_cost, parallelism, pwd, pwdlen, salt, SALTLEN, hash1, HASHLEN);
		EXPECT_EQ(error, argon2_error_codes::ARGON2_OK);
	}

	{
		auto salt = std::vector<std::uint8_t>(SALTLEN);
		auto pwd  = std::vector<std::uint8_t>(PWD.begin(), PWD.end());

		auto error = Argon2::id_hash_raw(t_cost, m_cost, parallelism, pwd, salt, hash2);
		EXPECT_EQ(error, Argon2::ErrorCodes::Ok);
	}

	EXPECT_EQ(std::memcmp(hash1, hash2.data(), HASHLEN), 0);
}

TEST(Argon2id, Hash_Encoded)
{
	char encoded1[ENCODEDLEN];
	auto encoded2 = std::string();
	encoded2.resize(ENCODEDLEN);

	{
		uint8_t salt[SALTLEN];
		memset(salt, 0x00, SALTLEN);

		uint8_t* pwd    = (uint8_t*)strdup(PWD.c_str());
		uint32_t pwdlen = strlen((char*)pwd);

		auto error = argon2id_hash_encoded(t_cost, m_cost, parallelism, pwd, pwdlen, salt, SALTLEN, HASHLEN, encoded1, ENCODEDLEN);
		EXPECT_EQ(error, argon2_error_codes::ARGON2_OK);

		auto result = Argon2::id_verify(encoded1, std::vector<std::uint8_t>(pwd, pwd + pwdlen));
		EXPECT_EQ(result, Argon2::ErrorCodes::Ok);
	}

	{
		auto salt = std::vector<std::uint8_t>(SALTLEN);
		auto pwd  = std::vector<std::uint8_t>(PWD.begin(), PWD.end());

		auto error = Argon2::id_hash_encoded(t_cost, m_cost, parallelism, pwd, salt, HASHLEN, encoded2);
		EXPECT_EQ(error, Argon2::ErrorCodes::Ok);

		auto result = argon2id_verify(encoded1, pwd.data(), pwd.size());
		EXPECT_EQ(result, argon2_error_codes::ARGON2_OK);
	}

	EXPECT_EQ(std::memcmp(encoded1, encoded2.data(), encoded2.size()), 0);
}

TEST(Argon2id, CTX)
{
	uint8_t hash1[HASHLEN];
	auto hash2 = std::vector<std::uint8_t>(HASHLEN);

	{
		uint8_t salt[SALTLEN];
		memset(salt, 0x00, SALTLEN);

		uint8_t* pwd    = (uint8_t*)strdup(PWD.c_str());
		uint32_t pwdlen = strlen((char*)pwd);

		argon2_context context = {
		    hash1,   /* output array, at least HASHLEN in size */
		    HASHLEN, /* digest length */
		    pwd,     /* password array */
		    pwdlen,  /* password length */
		    salt,    /* salt array */
		    SALTLEN, /* salt length */
		    NULL,
		    0, /* optional secret data */
		    NULL,
		    0, /* optional associated data */
		    t_cost,
		    m_cost,
		    parallelism,
		    parallelism,
		    ARGON2_VERSION_13, /* algorithm version */
		    NULL,
		    NULL, /* custom memory allocation / deallocation functions */
		    /* by default only internal memory is cleared (pwd is not wiped) */
		    ARGON2_DEFAULT_FLAGS};

		auto error = argon2id_ctx(&context);
		EXPECT_EQ(error, argon2_error_codes::ARGON2_OK);
	}

	{
		auto salt = std::vector<std::uint8_t>(SALTLEN);
		auto pwd  = std::vector<std::uint8_t>(PWD.begin(), PWD.end());

		auto context = Argon2::Context{
		    hash2,
		    pwd,
		    salt,
		    {},
		    {},
		    t_cost,
		    m_cost,
		    parallelism,
		    parallelism,
		    Argon2::Version::Version13,
		    nullptr,
		    nullptr,
		    Argon2::Flags::Default};

		auto error = Argon2::id_ctx(context);
		EXPECT_EQ(error, Argon2::ErrorCodes::Ok);
	}

	EXPECT_EQ(std::memcmp(hash1, hash2.data(), hash2.size()), 0);
}
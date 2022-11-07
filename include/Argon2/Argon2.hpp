#pragma once

#include <algorithm>
#include <argon2.h>
#include <climits>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#if defined(_BUILD_SHARED)
#	if defined(_WIN32)
// Windows
#		if defined(_EXPORT_ARGON2_HPP)
// MSVC
#			if defined(_MSC_VER)
#				define ARGON2_HPP_EXPORT __declspec(dllexport)
// MinGW
#			else
#				define ARGON2_HPP_EXPORT __attribute__((dllexport))
#			endif
#		else
// MSVC
#			if defined(_MSC_VER)
#				define ARGON2_HPP_EXPORT __declspec(dllimport)
// MinGW
#			else
#				define ARGON2_HPP_EXPORT __attribute__((dllimport))
#			endif
#		endif
// Not Windows
#	else
#		define ARGON2_HPP_EXPORT __attribute__((visibility("default")))
#	endif
#else
#	define ARGON2_HPP_EXPORT
#endif

namespace Argon2
{
	/*
	 * Argon2 input parameter restrictions
	 */

	/* Minimum and maximum number of lanes (degree of parallelism) */
	constexpr auto MIN_LANES = std::uint32_t(ARGON2_MIN_LANES);
	constexpr auto MAX_LANES = std::uint32_t(ARGON2_MAX_LANES);

	/* Minimum and maximum number of threads */
	constexpr auto MIN_THREADS = std::uint32_t(ARGON2_MIN_THREADS);
	constexpr auto MAX_THREADS = std::uint32_t(ARGON2_MAX_THREADS);

	/* Number of synchronization points between lanes per pass */
	constexpr auto SYNC_POINTS = std::uint32_t(ARGON2_SYNC_POINTS);

	/* Minimum and maximum digest size in bytes */
	constexpr auto MIN_OUTLEN = std::uint32_t(ARGON2_MIN_OUTLEN);
	constexpr auto MAX_OUTLEN = std::uint32_t(ARGON2_MAX_OUTLEN);

	/* Minimum and maximum number of memory blocks (each of BLOCK_SIZE bytes) */
	constexpr auto MIN_MEMORY = ARGON2_MIN_MEMORY;

	/* Max memory size is addressing-space/2, topping at 2^32 blocks (4 TB) */
	constexpr auto MAX_MEMORY_BITS = ARGON2_MAX_MEMORY_BITS;
	constexpr auto MAX_MEMORY      = ARGON2_MAX_MEMORY;

	/* Minimum and maximum number of passes */
	constexpr auto MIN_TIME = std::uint32_t(ARGON2_MIN_TIME);
	constexpr auto MAX_TIME = std::uint32_t(ARGON2_MAX_TIME);

	/* Minimum and maximum password length in bytes */
	constexpr auto MIN_PWD_LENGTH = std::uint32_t(ARGON2_MIN_PWD_LENGTH);
	constexpr auto MAX_PWD_LENGTH = std::uint32_t(ARGON2_MAX_PWD_LENGTH);

	/* Minimum and maximum associated data length in bytes */
	constexpr auto MIN_AD_LENGTH = std::uint32_t(ARGON2_MIN_AD_LENGTH);
	constexpr auto MAX_AD_LENGTH = std::uint32_t(ARGON2_MAX_AD_LENGTH);

	/* Minimum and maximum salt length in bytes */
	constexpr auto MIN_SALT_LENGTH = std::uint32_t(ARGON2_MIN_SALT_LENGTH);
	constexpr auto MAX_SALT_LENGTH = std::uint32_t(ARGON2_MAX_SALT_LENGTH);

	/* Minimum and maximum key length in bytes */
	constexpr auto MIN_SECRET = std::uint32_t(ARGON2_MIN_SECRET);
	constexpr auto MAX_SECRET = std::uint32_t(ARGON2_MAX_SECRET);

	/* Flags to determine which fields are securely wiped (default = no wipe). */
	enum class Flags : std::uint32_t
	{
		Default       = ARGON2_DEFAULT_FLAGS,
		ClearPassword = ARGON2_FLAG_CLEAR_PASSWORD,
		ClearSecret   = ARGON2_FLAG_CLEAR_SECRET
	};

	/* Error codes */
	enum class ARGON2_HPP_EXPORT ErrorCodes
	{
		Ok = argon2_error_codes::ARGON2_OK,

		OutputPtrNull = argon2_error_codes::ARGON2_OUTPUT_PTR_NULL,

		OutputTooShort = argon2_error_codes::ARGON2_OUTPUT_TOO_SHORT,
		OutputTooLong  = argon2_error_codes::ARGON2_OUTPUT_TOO_LONG,

		PwdTooShort = argon2_error_codes::ARGON2_PWD_TOO_SHORT,
		PwdTooLong  = argon2_error_codes::ARGON2_PWD_TOO_LONG,

		SaltTooShort = argon2_error_codes::ARGON2_SALT_TOO_SHORT,
		SaltTooLong  = argon2_error_codes::ARGON2_SALT_TOO_LONG,

		AdTooShort = argon2_error_codes::ARGON2_AD_TOO_SHORT,
		AdTooLong  = argon2_error_codes::ARGON2_AD_TOO_LONG,

		SecretTooShort = argon2_error_codes::ARGON2_SECRET_TOO_SHORT,
		SecretTooLong  = argon2_error_codes::ARGON2_SECRET_TOO_LONG,

		TimeTooSmall = argon2_error_codes::ARGON2_TIME_TOO_SMALL,
		TimeTooLarge = argon2_error_codes::ARGON2_TIME_TOO_LARGE,

		MemoryTooLittle = argon2_error_codes::ARGON2_MEMORY_TOO_LITTLE,
		MemoryTooMuch   = argon2_error_codes::ARGON2_MEMORY_TOO_MUCH,

		LanesTooFew  = argon2_error_codes::ARGON2_LANES_TOO_FEW,
		LanesTooMany = argon2_error_codes::ARGON2_LANES_TOO_MANY,

		PwdPtrMismatch    = -argon2_error_codes::ARGON2_PWD_PTR_MISMATCH,
		SaltPtrMismatch   = argon2_error_codes::ARGON2_SALT_PTR_MISMATCH,
		SecretPtrMismatch = argon2_error_codes::ARGON2_SECRET_PTR_MISMATCH,
		AdPtrMismatch     = -argon2_error_codes::ARGON2_AD_PTR_MISMATCH,

		MemoryAllocationError = argon2_error_codes::ARGON2_MEMORY_ALLOCATION_ERROR,

		FreeMemoryCbkNull     = argon2_error_codes::ARGON2_FREE_MEMORY_CBK_NULL,
		AllocateMemoryCbkNull = argon2_error_codes::ARGON2_ALLOCATE_MEMORY_CBK_NULL,

		IncorrectParameter = argon2_error_codes::ARGON2_INCORRECT_PARAMETER,
		IncorrectType      = argon2_error_codes::ARGON2_INCORRECT_TYPE,

		OutPtrMismatch = argon2_error_codes::ARGON2_OUT_PTR_MISMATCH,

		ThreadsTooFew  = argon2_error_codes::ARGON2_THREADS_TOO_FEW,
		ThreadsTooMany = argon2_error_codes::ARGON2_THREADS_TOO_MANY,

		MissingArgs        = argon2_error_codes::ARGON2_MISSING_ARGS,
		EncodingFail       = argon2_error_codes::ARGON2_ENCODING_FAIL,
		DecodingFail       = argon2_error_codes::ARGON2_DECODING_FAIL,
		ThreadFail         = argon2_error_codes::ARGON2_THREAD_FAIL,
		DecodingLengthFail = argon2_error_codes::ARGON2_DECODING_LENGTH_FAIL,

		VerifyMismatch = argon2_error_codes::ARGON2_VERIFY_MISMATCH
	};

	/* Argon2 primitive type */
	enum class ARGON2_HPP_EXPORT Type
	{
		Argon2d  = argon2_type::Argon2_d,
		Argon2i  = argon2_type::Argon2_i,
		Argon2id = argon2_type::Argon2_id
	};

	/* Version of the algorithm */
	enum class ARGON2_HPP_EXPORT Version : std::uint32_t
	{
		Version10     = argon2_version::ARGON2_VERSION_10,
		Version13     = argon2_version::ARGON2_VERSION_13,
		VersionNumber = argon2_version::ARGON2_VERSION_NUMBER
	};

	/* Argon2 external data structures */

	/*
	 *****
	 * Context: structure to hold Argon2 inputs:
	 *  output array,
	 *  password,
	 *  salt,
	 *  secret,
	 *  associated data,
	 *  number of passes, amount of used memory (in KBytes, can be rounded up a bit)
	 *  number of parallel threads that will be run.
	 * All the parameters above affect the output hash value.
	 * Additionally, two function pointers can be provided to allocate and
	 * deallocate the memory (if NULL, memory will be allocated internally).
	 * Also, three flags indicate whether to erase password, secret as soon as they
	 * are pre-hashed (and thus not needed anymore), and the entire memory
	 *****
	 * Simplest situation: you have output array out[8], password is stored in
	 * pwd[32], salt is stored in salt[16], you do not have keys nor associated
	 * data. You need to spend 1 GB of RAM and you run 5 passes of Argon2d with
	 * 4 parallel lanes.
	 * You want to erase the password, but you're OK with last pass not being
	 * erased. You want to use the default memory allocator.
	 * Then you initialize:
	 Argon2_Context(out,8,pwd,32,salt,16,NULL,0,NULL,0,5,1<<20,4,4,NULL,NULL,true,false,false,false)
	 */
	struct ARGON2_HPP_EXPORT Context
	{
		std::vector<std::uint8_t>& out;
		std::vector<std::uint8_t>& pwd;
		std::vector<std::uint8_t>& salt;
		std::vector<std::uint8_t> secret;
		std::vector<std::uint8_t> ad;

		uint32_t t_cost;  /* number of passes */
		uint32_t m_cost;  /* amount of memory requested (KB) */
		uint32_t lanes;   /* number of lanes */
		uint32_t threads; /* maximum number of threads */

		Version version; /* version number */

		allocate_fptr allocate_cbk; /* pointer to memory allocator */
		deallocate_fptr free_cbk;   /* pointer to memory deallocator */

		Flags flags; /* array of bool options */

		operator argon2_context();
	};

	/*
	 * Function that gives the string representation of a Type.
	 * @param type The Type that we want the string for
	 * @param uppercase Whether the string should have the first letter uppercase
	 * @return Empty string if invalid type, otherwise the string representation.
	 */
	ARGON2_HPP_EXPORT auto type2string(Type type, bool uppercase) -> std::string;

	/*
	 * Function that performs memory-hard hashing with certain degree of parallelism
	 * @param  context  Reference to the Argon2 internal structure
	 * @return Error code if smth is wrong, ErrorCodes::Ok otherwise
	 */
	ARGON2_HPP_EXPORT auto ctx(Context& context, Type type) -> ErrorCodes;

	/**
	 * Hashes a password with Argon2i, producing an encoded hash
	 * @param t_cost Number of iterations
	 * @param m_cost Sets memory usage to m_cost kibibytes
	 * @param parallelism Number of threads and compute lanes
	 * @param pwd Vector containing the password
	 * @param salt Vector containing the salt
	 * @param hashlen Desired length of the hash in bytes
	 * @param encoded Vector where to write the encoded hash
	 * @pre   Different parallelism levels will give different results
	 * @pre   Returns ErrorCodes::Ok if successful
	 */
	ARGON2_HPP_EXPORT auto i_hash_encoded(std::uint32_t t_cost, std::uint32_t m_cost, std::uint32_t parallelism, const std::vector<std::uint8_t>& pwd, const std::vector<std::uint8_t>& salt, std::size_t hashlen, std::string& encoded) -> ErrorCodes;

	/**
	 * Hashes a password with Argon2i, producing a raw hash at @hash
	 * @param t_cost Number of iterations
	 * @param m_cost Sets memory usage to m_cost kibibytes
	 * @param parallelism Number of threads and compute lanes
	 * @param pwd Vector containing the password
	 * @param salt Vector containing the salt
	 * @param hash Vector where to write the raw hash - updated by the function
	 * @pre   Different parallelism levels will give different results
	 * @pre   Returns ErrorCodes::Ok if successful
	 */
	ARGON2_HPP_EXPORT auto i_hash_raw(std::uint32_t t_cost, std::uint32_t m_cost, std::uint32_t parallelism, const std::vector<std::uint8_t>& pwd, const std::vector<std::uint8_t>& salt, std::vector<std::uint8_t>& hash)
	    -> ErrorCodes;

	ARGON2_HPP_EXPORT auto d_hash_encoded(std::uint32_t t_cost, std::uint32_t m_cost, std::uint32_t parallelism, const std::vector<std::uint8_t>& pwd, const std::vector<std::uint8_t>& salt, std::size_t hashlen, std::string& encoded) -> ErrorCodes;

	ARGON2_HPP_EXPORT auto d_hash_raw(std::uint32_t t_cost, std::uint32_t m_cost, std::uint32_t parallelism, const std::vector<std::uint8_t>& pwd, const std::vector<std::uint8_t>& salt, std::vector<std::uint8_t>& hash)
	    -> ErrorCodes;

	ARGON2_HPP_EXPORT auto id_hash_encoded(std::uint32_t t_cost, std::uint32_t m_cost, std::uint32_t parallelism, const std::vector<std::uint8_t>& pwd, const std::vector<std::uint8_t>& salt, std::size_t hashlen, std::string& encoded) -> ErrorCodes;

	ARGON2_HPP_EXPORT auto id_hash_raw(std::uint32_t t_cost, std::uint32_t m_cost, std::uint32_t parallelism, const std::vector<std::uint8_t>& pwd, const std::vector<std::uint8_t>& salt, std::vector<std::uint8_t>& hash) -> ErrorCodes;

	/* generic function underlying the above ones */
	ARGON2_HPP_EXPORT auto hash(std::uint32_t t_cost, std::uint32_t m_cost, std::uint32_t parallelism, const std::vector<std::uint8_t>& pwd, const std::vector<std::uint8_t>& salt, const std::vector<std::uint8_t>& hash, std::string& encoded, Type type, Version version) -> ErrorCodes;

	/**
	 * Verifies a password against an encoded string
	 * Encoded string is restricted as in validate_inputs()
	 * @param encoded String encoding parameters, salt, hash
	 * @param pwd Vector containing the password
	 * @pre   Returns ARGON2_OK if successful
	 */
	ARGON2_HPP_EXPORT auto i_verify(const std::string& encoded, const std::vector<std::uint8_t>& pwd)
	    -> ErrorCodes;
	ARGON2_HPP_EXPORT auto d_verify(const std::string& encoded, const std::vector<std::uint8_t>& pwd)
	    -> ErrorCodes;
	ARGON2_HPP_EXPORT auto id_verify(const std::string& encoded, const std::vector<std::uint8_t>& pwd)
	    -> ErrorCodes;
	ARGON2_HPP_EXPORT auto verify(const std::string& encoded, const std::vector<std::uint8_t>& pwd, Type type) -> ErrorCodes;

	/**
	 * Argon2d: Version of Argon2 that picks memory blocks depending
	 * on the password and salt. Only for side-channel-free
	 * environment!!
	 *****
	 * @param  context  Reference to current Argon2 context
	 * @return  ErrorCodes::Ok if successful, an error code otherwise
	 */
	ARGON2_HPP_EXPORT auto d_ctx(Context& context) -> ErrorCodes;

	/**
	 * Argon2i: Version of Argon2 that picks memory blocks
	 * independent on the password and salt. Good for side-channels,
	 * but worse w.r.t. tradeoff attacks if only one pass is used.
	 *****
	 * @param  context  Reference to current Argon2 context
	 * @return  ErrorCodes::Ok if successful, an error code otherwise
	 */
	ARGON2_HPP_EXPORT auto i_ctx(Context& context) -> ErrorCodes;

	/**
	 * Argon2id: Version of Argon2 where the first half-pass over memory is
	 * password-independent, the rest are password-dependent (on the password and
	 * salt). OK against side channels (they reduce to 1/2-pass Argon2i), and
	 * better with w.r.t. tradeoff attacks (similar to Argon2d).
	 *****
	 * @param  context  Reference to current Argon2 context
	 * @return  ErrorCodes::Ok if successful, an error code otherwise
	 */
	ARGON2_HPP_EXPORT auto id_ctx(Context& context) -> ErrorCodes;

	/**
	 * Verify if a given password is correct for Argon2d hashing
	 * @param  context  Reference to current Argon2 context
	 * @param  hash  The password hash to verify
	 * @return  ErrorCodes::Ok if successful, an error code otherwise
	 */
	ARGON2_HPP_EXPORT auto d_verify_ctx(Context& context, const std::string& hash) -> ErrorCodes;

	/**
	 * Verify if a given password is correct for Argon2i hashing
	 * @param  context  Pointer to current Argon2 context
	 * @param  hash  The password hash to verify
	 * @return  Zero if successful, a non zero error code otherwise
	 */
	ARGON2_HPP_EXPORT auto i_verify_ctx(Context& context, const std::string& hash) -> ErrorCodes;

	/**
	 * Verify if a given password is correct for Argon2id hashing
	 * @param  context  Reference to current Argon2 context
	 * @param  hash  The password hash to verify
	 * @return  Zero if successful, a non zero error code otherwise
	 */
	ARGON2_HPP_EXPORT auto id_verify_ctx(Context& context, const std::string& hash) -> ErrorCodes;

	/* generic function underlying the above ones */
	ARGON2_HPP_EXPORT auto verify_ctx(Context& context, const std::string& hash, Type type)
	    -> ErrorCodes;

	/**
	 * Get the associated error message for given error code
	 * @return  The error message associated with the given error code
	 */
	ARGON2_HPP_EXPORT auto error_message(ErrorCodes error_code) -> std::string;

	/**
	 * Returns the encoded hash length for the given input parameters
	 * @param t_cost  Number of iterations
	 * @param m_cost  Memory usage in kibibytes
	 * @param parallelism  Number of threads; used to compute lanes
	 * @param saltlen  Salt size in bytes
	 * @param hashlen  Hash size in bytes
	 * @param type The Type that we want the encoded length for
	 * @return  The encoded hash length in bytes
	 */
	ARGON2_HPP_EXPORT auto encodedlen(std::uint32_t t_cost, std::uint32_t m_cost, std::uint32_t parallelism, std::uint32_t saltlen, std::uint32_t hashlen, Type type) -> std::size_t;

} // namespace Argon2
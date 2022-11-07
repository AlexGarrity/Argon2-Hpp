#include "Argon2/Argon2.hpp"

namespace Argon2
{

	Context::operator argon2_context()
	{
		argon2_context ctx;
		if (ad.empty())
		{
			ctx.ad    = nullptr;
			ctx.adlen = 0;
		}
		else
		{
			ctx.ad    = ad.data();
			ctx.adlen = ad.size();
		}
		ctx.allocate_cbk = nullptr;
		ctx.flags        = static_cast<std::uint32_t>(flags);
		ctx.free_cbk     = nullptr;
		ctx.lanes        = lanes;
		ctx.m_cost       = m_cost;
		ctx.out          = out.data();
		ctx.outlen       = static_cast<std::uint32_t>(out.size());
		ctx.pwd          = pwd.data();
		ctx.pwdlen       = static_cast<std::uint32_t>(pwd.size());
		ctx.salt         = salt.data();
		ctx.saltlen      = static_cast<std::uint32_t>(salt.size());
		if (secret.empty())
		{
			ctx.secret    = nullptr;
			ctx.secretlen = 0;
		}
		else
		{
			ctx.secret    = secret.data();
			ctx.secretlen = secret.size();
		}
		ctx.t_cost  = t_cost;
		ctx.threads = threads;
		ctx.version = static_cast<std::uint32_t>(version);
		return ctx;
	}

	auto type2string(const Type type, const bool uppercase) -> std::string
	{
		const auto* str = argon2_type2string(static_cast<argon2_type>(type), static_cast<int>(uppercase));
		return std::string(str);
	}

	auto ctx(Context& context, const Type type) -> ErrorCodes
	{
		auto ctx = static_cast<argon2_context>(context);
		return static_cast<ErrorCodes>(
		    argon2_ctx(&ctx, static_cast<argon2_type>(type)));
	}

	auto i_hash_encoded(const std::uint32_t t_cost, const std::uint32_t m_cost, const std::uint32_t parallelism, const std::vector<std::uint8_t>& pwd, const std::vector<std::uint8_t>& salt, const std::size_t hashlen, std::string& encoded) -> ErrorCodes
	{
		auto enc       = new char[encoded.size()];
		auto errorCode = argon2i_hash_encoded(
		    t_cost,
		    m_cost,
		    parallelism,
		    pwd.data(),
		    pwd.size(),
		    salt.data(),
		    salt.size(),
		    hashlen,
		    enc,
		    encoded.size());
		encoded = std::string(enc);
		delete[] enc;
		return static_cast<ErrorCodes>(errorCode);
	}

	auto i_hash_raw(const std::uint32_t t_cost, const std::uint32_t m_cost, const std::uint32_t parallelism, const std::vector<std::uint8_t>& pwd, const std::vector<std::uint8_t>& salt, std::vector<std::uint8_t>& hash) -> ErrorCodes
	{
		auto errorCode = argon2i_hash_raw(t_cost, m_cost, parallelism, pwd.data(), pwd.size(), salt.data(), salt.size(), hash.data(), hash.size());
		return static_cast<ErrorCodes>(errorCode);
	}

	auto d_hash_encoded(const std::uint32_t t_cost, const std::uint32_t m_cost, const std::uint32_t parallelism, const std::vector<std::uint8_t>& pwd, const std::vector<std::uint8_t>& salt, const std::size_t hashlen, std::string& encoded) -> ErrorCodes
	{
		auto enc       = new char[encoded.size()];
		auto errorCode = argon2d_hash_encoded(
		    t_cost,
		    m_cost,
		    parallelism,
		    pwd.data(),
		    pwd.size(),
		    salt.data(),
		    salt.size(),
		    hashlen,
		    enc,
		    encoded.size());
		encoded = std::string(enc);
		delete[] enc;
		return static_cast<ErrorCodes>(errorCode);
	}

	auto d_hash_raw(const std::uint32_t t_cost, const std::uint32_t m_cost, const std::uint32_t parallelism, const std::vector<std::uint8_t>& pwd, const std::vector<std::uint8_t>& salt, std::vector<std::uint8_t>& hash) -> ErrorCodes
	{
		auto errorCode = argon2d_hash_raw(t_cost, m_cost, parallelism, pwd.data(), pwd.size(), salt.data(), salt.size(), hash.data(), hash.size());
		return static_cast<ErrorCodes>(errorCode);
	}

	auto id_hash_encoded(const std::uint32_t t_cost, const std::uint32_t m_cost, const std::uint32_t parallelism, const std::vector<std::uint8_t>& pwd, const std::vector<std::uint8_t>& salt, const std::size_t hashlen, std::string& encoded) -> ErrorCodes
	{
		auto enc       = new char[encoded.size()];
		auto errorCode = argon2id_hash_encoded(
		    t_cost,
		    m_cost,
		    parallelism,
		    pwd.data(),
		    pwd.size(),
		    salt.data(),
		    salt.size(),
		    hashlen,
		    enc,
		    encoded.size());
		encoded = std::string(enc);
		delete[] enc;
		return static_cast<ErrorCodes>(errorCode);
	}

	auto id_hash_raw(const std::uint32_t t_cost, const std::uint32_t m_cost, const std::uint32_t parallelism, const std::vector<std::uint8_t>& pwd, const std::vector<std::uint8_t>& salt, std::vector<std::uint8_t>& hash) -> ErrorCodes
	{
		auto errorCode = argon2id_hash_raw(t_cost, m_cost, parallelism, pwd.data(), pwd.size(), salt.data(), salt.size(), hash.data(), hash.size());
		return static_cast<ErrorCodes>(errorCode);
	}

	auto hash(const std::uint32_t t_cost, const std::uint32_t m_cost, const std::uint32_t parallelism, const std::vector<std::uint8_t>& pwd, const std::vector<std::uint8_t>& salt, std::vector<std::uint8_t> hash, std::string& encoded, const Type type, const Version version) -> ErrorCodes
	{
		auto errorCode = argon2_hash(
		    t_cost,
		    m_cost,
		    parallelism,
		    pwd.data(),
		    pwd.size(),
		    salt.data(),
		    salt.size(),
		    hash.data(),
		    hash.size(),
		    const_cast<char*>(encoded.c_str()),
		    encoded.size(),
		    static_cast<argon2_type>(type),
		    static_cast<std::uint32_t>(version));
		return static_cast<ErrorCodes>(errorCode);
	}

	auto i_verify(const std::string& encoded, const std::vector<std::uint8_t>& pwd)
	    -> ErrorCodes
	{
		return static_cast<ErrorCodes>(
		    argon2i_verify(encoded.c_str(), pwd.data(), pwd.size()));
	}

	auto d_verify(const std::string& encoded, const std::vector<std::uint8_t>& pwd)
	    -> ErrorCodes
	{
		return static_cast<ErrorCodes>(
		    argon2d_verify(encoded.c_str(), pwd.data(), pwd.size()));
	}

	auto id_verify(const std::string& encoded, const std::vector<std::uint8_t>& pwd)
	    -> ErrorCodes
	{
		return static_cast<ErrorCodes>(
		    argon2id_verify(encoded.c_str(), pwd.data(), pwd.size()));
	}

	auto verify(const std::string& encoded, const std::vector<std::uint8_t>& pwd, const Type type) -> ErrorCodes
	{
		return static_cast<ErrorCodes>(argon2_verify(
		    encoded.c_str(),
		    pwd.data(),
		    pwd.size(),
		    static_cast<argon2_type>(type)));
	}

	auto d_ctx(Context& context) -> ErrorCodes
	{
		auto ctx = static_cast<argon2_context>(context);
		return static_cast<ErrorCodes>(argon2d_ctx(&ctx));
	}

	auto i_ctx(Context& context) -> ErrorCodes
	{
		auto ctx = static_cast<argon2_context>(context);
		return static_cast<ErrorCodes>(argon2i_ctx(&ctx));
	}

	auto id_ctx(Context& context) -> ErrorCodes
	{
		auto ctx = static_cast<argon2_context>(context);
		return static_cast<ErrorCodes>(argon2id_ctx(&ctx));
	}

	auto d_verify_ctx(Context& context, const std::string& hash) -> ErrorCodes
	{
		auto ctx = static_cast<argon2_context>(context);
		return static_cast<ErrorCodes>(argon2d_verify_ctx(&ctx, hash.c_str()));
	}

	auto i_verify_ctx(Context& context, const std::string& hash) -> ErrorCodes
	{
		auto ctx = static_cast<argon2_context>(context);
		return static_cast<ErrorCodes>(argon2i_verify_ctx(&ctx, hash.c_str()));
	}

	auto id_verify_ctx(Context& context, const std::string& hash) -> ErrorCodes
	{
		auto ctx = static_cast<argon2_context>(context);
		return static_cast<ErrorCodes>(argon2id_verify_ctx(&ctx, hash.c_str()));
	}

	/* generic function underlying the above ones */
	auto verify_ctx(Context& context, const std::string& hash, Type type)
	    -> ErrorCodes
	{
		auto ctx = static_cast<argon2_context>(context);
		return static_cast<ErrorCodes>(
		    argon2_verify_ctx(&ctx, hash.c_str(), static_cast<argon2_type>(type)));
	}

	auto error_message(const ErrorCodes error_code) -> std::string
	{
		const auto* str = argon2_error_message(static_cast<int>(error_code));
		return std::string(str);
	}

	auto encodedlen(const std::uint32_t t_cost, const std::uint32_t m_cost, const std::uint32_t parallelism, const std::uint32_t saltlen, const std::uint32_t hashlen, const Type type) -> std::size_t
	{
		return argon2_encodedlen(t_cost, m_cost, parallelism, saltlen, hashlen, static_cast<argon2_type>(type));
	}

} // namespace Argon2

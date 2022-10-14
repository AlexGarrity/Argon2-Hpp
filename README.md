# Argon2-Hpp

Argon2-Hpp is a simple C++ wrapper library for the Argon2 reference C implementation.

## Interface
The interface is more or less the same as the reference implementation, but the functions have been properly namespaced and pointer arrays have been replaced by vectors.  The example given in the original repository would be modifier as follows:

```cpp
#include "Argon2/Argon2.hpp"
#include <ios>

const std::uint32_t HASHLEN = 32
const std::uint32_t SALTLEN = 16
const std::string PWD = "password"

int main(void)
{
  auto hash1 = std::vector<std::uint8_t>(HASHLEN);
  auto hash2 = std::vector<std::uint8_t>(HASHLEN);

  auto salt = std::vector<std::uint8_t>(SALTLEN);
  auto pwd  = std::vector<std::uint8_t>(PWD.begin(), PWD.end());

  uint32_t t_cost = 2;            // 2-pass computation
  uint32_t m_cost = (1<<16);      // 64 mebibytes memory usage
  uint32_t parallelism = 1;       // number of threads and lanes

  // high-level API
  Argon2::i_hash_raw(t_cost, m_cost, parallelism, pwd, salt, hash1);

  // low-level API
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
    Argon2::Flags::Default
  };

  auto rc = Argon2::i_ctx(context);
  if(Argon2::ErrorCodes::Ok != rc) {
      std::cout << "Error: " << Argon2::error_message(rc) << "\n";
      exit(1);
  }

  for (const auto c : hash1) std::cout << std::hex << c;

  for( int i=0; i<HASHLEN; ++i ) { printf( "%02x", hash1[i] ); }
  std::cout << "\n";
  if (hash1 != hash2) {
      for( const auto c : hash2 ) {
        std::cout << std::hex << c;
      }
      std::cout << "\nFail\n";
  }
  std::cout << "Ok\n";
  return 0;
}
```

## But why wouldn't I just use libSodium or something?
Good question.  And one that I don't have a particularly good answer for.  I guess this is lighter?

## Licensing
The (Argon2 reference implementation)[https://github.com/P-H-C/phc-winner-argon2] is dual licensed under the CC0 License and Apache 2.0 License and, in this case, used under the CC0 License.
It felt appropriate to follow suit, so this wrapper library is also dual licensed under CC0 and Apache 2.0.  For more details, see the LICENSE file.
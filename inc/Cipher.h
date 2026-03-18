#pragma once

#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>

struct ZpCipherParams {
  size_t key_size;
  size_t plain_size;
  size_t cipher_size;
};

// Refactored for MCU: std::vector removed, relies on raw pointers.
class ZpCipher {
 protected:
  const uint64_t* secret_key;
  ZpCipherParams params;
  uint64_t modulus;

 public:
  ZpCipher(ZpCipherParams params, const uint64_t* secret_key,
           uint64_t modulus)
      : secret_key(secret_key), params(params), modulus(modulus) {
  }
  
  virtual ~ZpCipher() = default;
  size_t get_key_size() const { return params.key_size; }
  size_t get_plain_size() const { return params.plain_size; }
  size_t get_cipher_size() const { return params.cipher_size; }

  virtual std::string get_cipher_name() const = 0;

  // Encrypt size elements from plaintext array to ciphertext array
  virtual void encrypt(
      const uint64_t* plaintext, uint64_t* ciphertext, size_t size) const = 0;
      
  virtual void decrypt(
      const uint64_t* ciphertext, uint64_t* plaintext, size_t size) const = 0;

  virtual void prep_one_block() const = 0;
};

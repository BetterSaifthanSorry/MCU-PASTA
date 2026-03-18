#pragma once

#include <array>
#include <string>
#include <cstdint>

extern "C" {
#include "KeccakHash.h"
}

#include "Cipher.h"

namespace PASTA_3 {

constexpr ZpCipherParams PASTA_PARAMS = {256, 128, 128};
constexpr uint64_t PASTA_T = PASTA_PARAMS.plain_size;
constexpr uint64_t PASTA_R = 3;

typedef std::array<uint64_t, PASTA_PARAMS.key_size> key_block;
typedef std::array<uint64_t, PASTA_T> block;

class PASTA : public ZpCipher {
 public:
  // Requires secret_key to point to an array of at least 256 uint64_t elements
  PASTA(const uint64_t* secret_key, uint64_t modulus)
      : ZpCipher(PASTA_PARAMS, secret_key, modulus) {}

  virtual ~PASTA() = default;

  virtual std::string get_cipher_name() const { return "PASTA (n=128,r=3)"; }
  
  virtual void encrypt(const uint64_t* plaintext, uint64_t* ciphertext, size_t size) const;
  virtual void decrypt(const uint64_t* ciphertext, uint64_t* plaintext, size_t size) const;

  virtual void prep_one_block() const;  // to benchmark matrix generation
};

class Pasta {
 private:
  Keccak_HashInstance shake128_;

  key_block key_;
  block state1_;
  block state2_;

  uint64_t max_prime_size;
  uint64_t pasta_p;

  void calculate_row(const block& prev_row, const block& first_row, block& out);
  uint64_t generate_random_field_element(bool allow_zero = true);

  void round(size_t r);
  void sbox_cube(block& state);
  void sbox_feistel(block& state);
  void linear_layer();
  void matmul(block& state);
  void add_rc(block& state);
  void mix();

  block gen_keystream(const uint64_t nonce, const uint64_t block_counter);

 public:
  Pasta(const uint64_t* key, uint64_t modulus);
  Pasta(uint64_t modulus);
  ~Pasta() = default;

  Pasta(const Pasta&) = delete;
  Pasta& operator=(const Pasta&) = delete;
  Pasta(const Pasta&&) = delete;

  block keystream(const uint64_t nonce, const uint64_t block_counter);
  void preprocess(const uint64_t nonce, const uint64_t block_counter);

  void init_shake(uint64_t nonce, uint64_t block_counter);
  void get_random_vector(block& out, bool allow_zero = true);
};

}  // namespace PASTA_3

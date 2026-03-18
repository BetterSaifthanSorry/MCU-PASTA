#include "pasta_3_plain.h"
#include <cmath>
#include <cstring>
#include <stdexcept>

// Platform portability for GCC/Clang on 32-bit/64-bit systems
typedef unsigned __int128 uint128_t;

// Endianness handling is provided by Keccak dependencies
#if defined(__linux__) || defined(__APPLE__)
#include <endian.h>
#elif defined(_WIN32)
#include "portable_endian.h"
#else
// Generic fallback for typical Cortex-M little endian
#define htobe64(x) __builtin_bswap64(x)
#define be64toh(x) __builtin_bswap64(x)
#endif


namespace PASTA_3 {

void PASTA::encrypt(const uint64_t* plaintext, uint64_t* ciphertext, size_t size) const {
  uint64_t nonce = 123456789;
  size_t num_block = (size + params.plain_size - 1) / params.plain_size;

  Pasta pasta(secret_key, modulus);
  for(size_t i=0; i<size; i++) ciphertext[i] = plaintext[i];

  for (uint64_t b = 0; b < num_block; b++) {
    block ks = pasta.keystream(nonce, b);
    for (size_t i = b * params.plain_size;
         i < (b + 1) * params.plain_size && i < size; i++) {
      ciphertext[i] = (ciphertext[i] + ks[i - b * params.plain_size]) % modulus;
    }
  }
}

void PASTA::decrypt(const uint64_t* ciphertext, uint64_t* plaintext, size_t size) const {
  uint64_t nonce = 123456789;
  size_t num_block = (size + params.cipher_size - 1) / params.cipher_size;

  Pasta pasta(secret_key, modulus);
  for(size_t i=0; i<size; i++) plaintext[i] = ciphertext[i];

  for (uint64_t b = 0; b < num_block; b++) {
    block ks = pasta.keystream(nonce, b);
    for (size_t i = b * params.cipher_size;
         i < (b + 1) * params.cipher_size && i < size; i++) {
      if (ks[i - b * params.plain_size] > plaintext[i]) plaintext[i] += modulus;
      plaintext[i] = plaintext[i] - ks[i - b * params.plain_size];
    }
  }
}

void PASTA::prep_one_block() const {
  uint64_t nonce = 123456789;
  Pasta pasta(modulus);
  pasta.preprocess(nonce, 0);
}

//----------------------------------------------------------------
void Pasta::init_shake(uint64_t nonce, uint64_t block_counter) {
  uint8_t seed[16];

  *((uint64_t*)seed) = htobe64(nonce);
  *((uint64_t*)(seed + 8)) = htobe64(block_counter);

  if (0 != Keccak_HashInitialize_SHAKE128(&shake128_))
    // we use exceptions here, but on strict embedded we'd use error codes
    throw std::runtime_error("failed to init shake");
  if (0 != Keccak_HashUpdate(&shake128_, seed, sizeof(seed) * 8))
    throw std::runtime_error("SHAKE128 update failed");
  if (0 != Keccak_HashFinal(&shake128_, NULL))
    throw std::runtime_error("SHAKE128 final failed");
}

//----------------------------------------------------------------

uint64_t Pasta::generate_random_field_element(bool allow_zero) {
  uint8_t random_bytes[sizeof(uint64_t)];
  while (1) {
    if (0 !=
        Keccak_HashSqueeze(&shake128_, random_bytes, sizeof(random_bytes) * 8))
      throw std::runtime_error("SHAKE128 squeeze failed");
    uint64_t ele = be64toh(*((uint64_t*)random_bytes)) & max_prime_size;
    if (!allow_zero && ele == 0) continue;
    if (ele < pasta_p) return ele;
  }
}

//----------------------------------------------------------------

void Pasta::calculate_row(const block& prev_row, const block& first_row, block& out) {
  for (size_t j = 0; j < PASTA_T; j++) {
    uint64_t tmp = ((uint128_t)(first_row[j]) * prev_row[PASTA_T - 1]) % pasta_p;
    if (j) {
      tmp = (tmp + prev_row[j - 1]) % pasta_p;
    }
    out[j] = tmp;
  }
}

//----------------------------------------------------------------

void Pasta::get_random_vector(block& out, bool allow_zero) {
  for (uint16_t i = 0; i < PASTA_T; i++) {
    out[i] = generate_random_field_element(allow_zero);
  }
}

//----------------------------------------------------------------

Pasta::Pasta(const uint64_t* key, uint64_t modulus)
    : max_prime_size(0), pasta_p(modulus) {
  for(size_t i=0; i<PASTA_PARAMS.key_size; i++) key_[i] = key[i];
  uint64_t p = pasta_p;
  while (p) {
    max_prime_size++;
    p >>= 1;
  }
  max_prime_size = (1ULL << max_prime_size) - 1;
}

//----------------------------------------------------------------

Pasta::Pasta(uint64_t modulus) : max_prime_size(0), pasta_p(modulus) {
  // Used for preprocessing timings
  for(size_t i=0; i<PASTA_PARAMS.key_size; i++) key_[i] = 0;
  uint64_t p = pasta_p;
  while (p) {
    max_prime_size++;
    p >>= 1;
  }
  max_prime_size = (1ULL << max_prime_size) - 1;
}

//----------------------------------------------------------------

block Pasta::gen_keystream(const uint64_t nonce, const uint64_t block_counter) {
  init_shake(nonce, block_counter);

  // init state
  for (uint16_t i = 0; i < PASTA_T; i++) {
    state1_[i] = key_[i];
    state2_[i] = key_[PASTA_T + i];
  }

  for (uint8_t r = 0; r < PASTA_R; r++) {
    round(r);
  }
  // final affine with mixing afterwards
  linear_layer();
  return state1_;
}

//----------------------------------------------------------------

block Pasta::keystream(const uint64_t nonce, const uint64_t block_counter) {
  return gen_keystream(nonce, block_counter);
}

//----------------------------------------------------------------

void Pasta::preprocess(const uint64_t nonce, const uint64_t block_counter) {
  init_shake(nonce, block_counter);
  // To evaluate matrix generation time without allocating all matrices:
  // We simulate generating the rows exactly as it happens during encryption.
  block rc1, rc2;
  block curr_row1, curr_row2;
  block next_row1, next_row2;

  for (uint8_t r = 0; r <= PASTA_R; r++) {
    get_random_vector(rc1, false);
    get_random_vector(rc2, false);
    curr_row1 = rc1;
    curr_row2 = rc2;

    for (uint16_t i = 1; i < PASTA_T; i++) {
      calculate_row(curr_row1, rc1, next_row1);
      calculate_row(curr_row2, rc2, next_row2);
      curr_row1 = next_row1;
      curr_row2 = next_row2;
    }

    get_random_vector(rc1);
    get_random_vector(rc2);
  }
}

//----------------------------------------------------------------

void Pasta::round(size_t r) {
  linear_layer();
  if (r == PASTA_R - 1) {
    sbox_cube(state1_);
    sbox_cube(state2_);
  } else {
    sbox_feistel(state1_);
    sbox_feistel(state2_);
  }
}

//----------------------------------------------------------------

void Pasta::linear_layer() {
  matmul(state1_);
  matmul(state2_);
  add_rc(state1_);
  add_rc(state2_);
  mix();
}

//----------------------------------------------------------------

void Pasta::add_rc(block& state) {
  for (uint16_t el = 0; el < PASTA_T; el++) {
    state[el] = (state[el] + generate_random_field_element()) % pasta_p;
  }
}

//----------------------------------------------------------------

void Pasta::sbox_cube(block& state) {
  for (uint16_t el = 0; el < PASTA_T; el++) {
    uint64_t square = ((uint128_t)(state[el]) * state[el]) % pasta_p;
    state[el] = ((uint128_t)(square)*state[el]) % pasta_p;
  }
}

//----------------------------------------------------------------

void Pasta::sbox_feistel(block& state) {
  block new_state;
  new_state[0] = state[0];
  for (uint16_t el = 1; el < PASTA_T; el++) {
    uint64_t square = ((uint128_t)(state[el - 1]) * state[el - 1]) % pasta_p;
    new_state[el] = (square + state[el]) % pasta_p;
  }
  state = new_state;
}

//----------------------------------------------------------------

void Pasta::mix() {
  for (uint16_t i = 0; i < PASTA_T; i++) {
    uint64_t sum = (state1_[i] + state2_[i]) % pasta_p;
    state1_[i] = (state1_[i] + sum) % pasta_p;
    state2_[i] = (state2_[i] + sum) % pasta_p;
  }
}

//----------------------------------------------------------------

void Pasta::matmul(block& state) {
  block new_state;
  new_state.fill(0);

  block rand;
  get_random_vector(rand, false);
  block curr_row = rand;
  block next_row;

  for (uint16_t i = 0; i < PASTA_T; i++) {
    for (uint16_t j = 0; j < PASTA_T; j++) {
      uint64_t mult = ((uint128_t)(curr_row[j]) * state[j]) % pasta_p;
      new_state[i] = (new_state[i] + mult) % pasta_p;
    }
    if (i != PASTA_T - 1) {
      calculate_row(curr_row, rand, next_row);
      curr_row = next_row;
    }
  }
  state = new_state;
}

}  // namespace PASTA_3

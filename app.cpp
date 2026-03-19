/***************************************************************************//**
 * @file
 * @brief Top level application functions
 ******************************************************************************/

#include "app.h"
#include "pasta_3_plain.h"
#include "sl_iostream.h"
#include "em_device.h"

#include <cstdint>
#include <cstddef>
#include <cstdlib>
#include <cstring>

using namespace PASTA_3;

// Same modulus used by the repo
static const uint64_t MODULUS = 0xFFFFFFFFFFC00001ULL;

// PASTA key/plain/cipher buffers
static uint64_t test_key[256];
static uint64_t plaintext[128];
static uint64_t ciphertext[128];

// -------------------- timing helpers --------------------

static void dwt_init(void)
{
  CoreDebug->DEMCR |= CoreDebug_DEMCR_TRCENA_Msk;
  DWT->CYCCNT = 0;
  DWT->CTRL |= DWT_CTRL_CYCCNTENA_Msk;
}

static inline uint32_t dwt_get_cycles(void)
{
  return DWT->CYCCNT;
}

// -------------------- serial output helpers --------------------

static void put_char_blocking(char c)
{
  while (sl_iostream_putchar(SL_IOSTREAM_STDOUT, c) != SL_STATUS_OK) {
  }
}

static void put_str_blocking(const char *s)
{
  while (*s != '\0') {
    put_char_blocking(*s++);
  }
}

static void put_u32_dec(uint32_t value)
{
  char buf[10];
  int i = 0;

  if (value == 0) {
    put_char_blocking('0');
    return;
  }

  while (value > 0) {
    buf[i++] = (char)('0' + (value % 10));
    value /= 10;
  }

  while (i > 0) {
    put_char_blocking(buf[--i]);
  }
}

static void put_u64_dec(uint64_t value)
{
  char buf[20];
  int i = 0;

  if (value == 0) {
    put_char_blocking('0');
    return;
  }

  while (value > 0) {
    buf[i++] = (char)('0' + (value % 10));
    value /= 10;
  }

  while (i > 0) {
    put_char_blocking(buf[--i]);
  }
}

static void put_u64_hex16(uint64_t value)
{
  for (int shift = 60; shift >= 0; shift -= 4) {
    uint8_t nibble = (uint8_t)((value >> shift) & 0xFULL);
    if (nibble < 10) {
      put_char_blocking((char)('0' + nibble));
    } else {
      put_char_blocking((char)('a' + (nibble - 10)));
    }
  }
}

// -------------------- serial input helpers --------------------

static bool read_line_blocking(char *buf, size_t buf_len)
{
  size_t idx = 0;
  char c;

  if (buf_len == 0) {
    return false;
  }

  while (1) {
    if (sl_iostream_getchar(SL_IOSTREAM_STDIN, &c) != SL_STATUS_OK) {
      continue;
    }

    // Enter pressed
    if (c == '\r' || c == '\n') {
      if (idx == 0) {
        continue;
      }
      buf[idx] = '\0';
      put_str_blocking("\r\n");
      return true;
    }

    // Backspace support
    if ((c == '\b' || c == 127) && idx > 0) {
      idx--;
      put_str_blocking("\b \b");
      continue;
    }

    // Accept printable chars
    if (c >= 32 && c <= 126 && idx < (buf_len - 1)) {
      buf[idx++] = c;
      put_char_blocking(c);
    }
  }
}

static bool parse_u64(const char *s, uint64_t *out)
{
  char *endptr = nullptr;
  unsigned long long value = strtoull(s, &endptr, 10);

  if (s == endptr || *endptr != '\0') {
    return false;
  }

  *out = (uint64_t)value;
  return true;
}

// -------------------- plaintext/ciphertext helpers --------------------

static void load_plaintext_from_number(uint64_t value)
{
  memset(plaintext, 0, sizeof(plaintext));
  plaintext[0] = value;
}

static void clear_ciphertext(void)
{
  memset(ciphertext, 0, sizeof(ciphertext));
}

// -------------------- app --------------------

extern "C" void app_init(void)
{
  for (int i = 0; i < 256; i++) {
    test_key[i] = (uint64_t)(i + 1);
  }

  clear_ciphertext();
  load_plaintext_from_number(0);

  dwt_init();

  put_str_blocking("\r\nPASTA MCU demo ready.\r\n");
  put_str_blocking("Enter a non-negative integer and press Enter.\r\n");
  put_str_blocking("Output format: in | ct0..ct3 | sym_us | cycles | ct_bytes\r\n\r\n");
}

extern "C" void app_process_action(void)
{
  char line[32];
  uint64_t input_value = 0;

  put_str_blocking("meter> ");

  if (!read_line_blocking(line, sizeof(line))) {
    return;
  }

  if (!parse_u64(line, &input_value)) {
    put_str_blocking("Invalid input. Digits only.\r\n\r\n");
    return;
  }

  load_plaintext_from_number(input_value);
  clear_ciphertext();

  PASTA cipher(test_key, MODULUS);

  uint32_t start_cycles = dwt_get_cycles();
  cipher.encrypt(plaintext, ciphertext, 128);
  uint32_t cycles = dwt_get_cycles() - start_cycles;

  uint64_t sym_us =
      ((uint64_t)cycles * 1000000ULL) / (uint64_t)SystemCoreClock;

  uint32_t ct_bytes = (uint32_t)sizeof(ciphertext);

  put_str_blocking("in=");
  put_u64_dec(input_value);

  put_str_blocking(" | ct0=");
  put_u64_hex16(ciphertext[0]);

  put_str_blocking(" ct1=");
  put_u64_hex16(ciphertext[1]);

  put_str_blocking(" ct2=");
  put_u64_hex16(ciphertext[2]);

  put_str_blocking(" ct3=");
  put_u64_hex16(ciphertext[3]);

  put_str_blocking(" | sym_us=");
  put_u64_dec(sym_us);

  put_str_blocking(" | cycles=");
  put_u32_dec(cycles);

  put_str_blocking(" | ct_bytes=");
  put_u32_dec(ct_bytes);

  put_str_blocking("\r\n\r\n");
}

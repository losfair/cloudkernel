#pragma once

#include <algorithm>
#include <arpa/inet.h>
#include <optional>
#include <stdexcept>
#include <stdint.h>
#include <string>
#include <vector>

template <class T>
void __attribute__((unused)) write_vec(std::vector<uint8_t> &vec, const T &x) {
  static_assert(std::is_trivial<T>::value,
                "write_vec: T must be a trivial type");
  std::copy((uint8_t *)&x, ((uint8_t *)&x) + sizeof(T),
            std::back_inserter(vec));
}

template <class T>
T __attribute__((unused))
read_vec(const uint8_t *vec, size_t len, size_t &pos) {
  static_assert(std::is_trivial<T>::value,
                "read_vec: T must be a trivial type");
  if (pos + sizeof(T) > len || pos + sizeof(T) < pos)
    throw std::runtime_error("read_vec: out of bounds");
  T ret;
  std::copy(&vec[pos], &vec[pos + sizeof(T)], (uint8_t *)&ret);
  pos += sizeof(T);
  return ret;
}

static void __attribute__((unused))
read_vec_n(const uint8_t *vec, size_t len, size_t &pos, uint8_t *out,
           size_t n) {
  if (pos + n > len || pos + n < pos)
    throw std::runtime_error("read_vec_n: out of bounds");
  std::copy(&vec[pos], &vec[pos + n], out);
  pos += n;
}

static void __attribute__((unused))
read_vec_n(const uint8_t *vec, size_t len, size_t &pos,
           std::vector<uint8_t> &out, size_t n) {
  if (pos + n > len || pos + n < pos)
    throw std::runtime_error("read_vec_n: out of bounds");
  std::copy(&vec[pos], &vec[pos + n], std::back_inserter(out));
  pos += n;
}

static void __attribute__((unused))
read_vec_n(const uint8_t *vec, size_t len, size_t &pos, std::string &out,
           size_t n) {
  if (pos + n > len || pos + n < pos)
    throw std::runtime_error("read_vec_n: out of bounds");
  std::copy(&vec[pos], &vec[pos + n], std::back_inserter(out));
  pos += n;
}

static inline std::optional<uint32_t> __attribute__((unused))
decode_ipv4_address(const char *addr) {
  uint32_t ipv4_num = 0;
  if (inet_pton(AF_INET, addr, (void *)&ipv4_num) != 1)
    return {};
  std::reverse((uint8_t *)&ipv4_num, (uint8_t *)(&ipv4_num + 1));
  return ipv4_num;
}

static inline std::optional<__uint128_t> __attribute__((unused))
decode_ipv6_address(const char *addr) {
  __uint128_t ipv6_num = 0;
  if (inet_pton(AF_INET6, addr, (void *)&ipv6_num) != 1)
    return {};
  std::reverse((uint8_t *)&ipv6_num, (uint8_t *)(&ipv6_num + 1));
  return ipv6_num;
}

static inline std::optional<std::string> __attribute__((unused))
encode_ipv4_address(uint32_t addr) {
  char buf[INET_ADDRSTRLEN] = {};
  std::reverse((uint8_t *)&addr, (uint8_t *)(&addr + 1));
  if (!inet_ntop(AF_INET, (const void *)&addr, buf, sizeof(buf)))
    return {};
  return std::string(buf);
}

static inline std::optional<std::string> __attribute__((unused))
encode_ipv6_address(__uint128_t addr) {
  char buf[INET6_ADDRSTRLEN] = {};
  std::reverse((uint8_t *)&addr, (uint8_t *)(&addr + 1));
  if (!inet_ntop(AF_INET6, (const void *)&addr, buf, sizeof(buf)))
    return {};
  return std::string(buf);
}
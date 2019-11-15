#pragma once

#include <stdexcept>
#include <string>
#include <vector>

template <class T> void write_vec(std::vector<uint8_t> &vec, const T &x) {
  static_assert(std::is_trivial<T>::value,
                "write_vec: T must be a trivial type");
  std::copy((uint8_t *)&x, ((uint8_t *)&x) + sizeof(T),
            std::back_inserter(vec));
}

template <class T> T read_vec(const uint8_t *vec, size_t len, size_t &pos) {
  static_assert(std::is_trivial<T>::value,
                "read_vec: T must be a trivial type");
  if (pos + sizeof(T) > len || pos + sizeof(T) < pos)
    throw std::runtime_error("read_vec: out of bounds");
  T ret;
  std::copy(&vec[pos], &vec[pos + sizeof(T)], (uint8_t *)&ret);
  pos += sizeof(T);
  return ret;
}

static void read_vec_n(const uint8_t *vec, size_t len, size_t &pos,
                       uint8_t *out, size_t n) {
  if (pos + n > len || pos + n < pos)
    throw std::runtime_error("read_vec_n: out of bounds");
  std::copy(&vec[pos], &vec[pos + n], out);
  pos += n;
}

static void read_vec_n(const uint8_t *vec, size_t len, size_t &pos,
                       std::vector<uint8_t> &out, size_t n) {
  if (pos + n > len || pos + n < pos)
    throw std::runtime_error("read_vec_n: out of bounds");
  std::copy(&vec[pos], &vec[pos + n], std::back_inserter(out));
  pos += n;
}

static void read_vec_n(const uint8_t *vec, size_t len, size_t &pos,
                       std::string &out, size_t n) {
  if (pos + n > len || pos + n < pos)
    throw std::runtime_error("read_vec_n: out of bounds");
  std::copy(&vec[pos], &vec[pos + n], std::back_inserter(out));
  pos += n;
}

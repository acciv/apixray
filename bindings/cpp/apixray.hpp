#pragma once

#include <stdexcept>
#include <string>

#include "../c/include/apixray.h"

namespace apixray {

// RAII-владелец строки, возвращённой из Rust FFI.
class OwnedString {
 public:
  explicit OwnedString(char* ptr) : ptr_(ptr) {
    if (ptr_ == nullptr) {
      throw std::runtime_error("apixray: null pointer from FFI");
    }
  }
  ~OwnedString() { apixray_free(ptr_); }

  OwnedString(const OwnedString&) = delete;
  OwnedString& operator=(const OwnedString&) = delete;

  std::string str() const { return std::string(ptr_); }

 private:
  char* ptr_;
};

inline std::string version() { return std::string(apixray_version()); }

inline std::string analyze(const std::string& token) {
  return OwnedString(apixray_analyze(token.c_str())).str();
}

inline std::string scan(const std::string& text) {
  return OwnedString(apixray_scan(text.c_str())).str();
}

inline std::string generate_fake(const std::string& provider) {
  return OwnedString(apixray_generate_fake(provider.c_str())).str();
}

}  // namespace apixray

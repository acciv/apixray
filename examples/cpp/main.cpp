#include <iostream>

#include "../../bindings/cpp/apixray.hpp"

int main() {
  try {
    std::cout << "apixray " << apixray::version() << "\n";

    const std::string fake = apixray::generate_fake("openai");
    std::cout << "fake key: " << fake << "\n";

    const std::string report = apixray::analyze(fake);
    std::cout << "report: " << report.substr(0, 160) << "...\n";

    const std::string found = apixray::scan("key=" + fake);
    std::cout << "scan: " << found.substr(0, 120) << "...\n";
  } catch (const std::exception& e) {
    std::cerr << "error: " << e.what() << "\n";
    return 1;
  }
  return 0;
}

.PHONY: build test demo demo-python demo-cpp clean

build:
	cargo build --release --workspace

test:
	cargo test --workspace

demo: demo-python demo-cpp

demo-python: build
	APIXRAY_LIB=$(CURDIR)/target/release/libapixray.so python3 examples/python/demo.py

demo-cpp: build
	g++ -std=c++17 examples/cpp/main.cpp -o /tmp/apixray_demo \
		-Ltarget/release -lapixray -Wl,-rpath,$(CURDIR)/target/release
	/tmp/apixray_demo

clean:
	cargo clean
	rm -f /tmp/apixray_demo

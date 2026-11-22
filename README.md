<div align="center">

# 🩻 apixray

**Мультиязычный «рентген» API-ключей: структура, форматы, энтропия, JWT.**

[![CI](https://github.com/acciv/apixray/actions/workflows/ci.yml/badge.svg)](https://github.com/acciv/apixray/actions/workflows/ci.yml)
[![Rust](https://img.shields.io/badge/Rust-1.8%2B-000000?style=flat-square&logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-65D067?style=flat-square)](LICENSE)

</div>

---

> ⚠️ **Граница проекта.** `apixray` делает только легитимный структурный анализ:
> определяет формат ключа, разбивает его на сегменты, считает энтропию, декодирует
> поля JWT **без проверки подписи** и генерирует **заведомо фейковые** ключи для тестов.
>
> Проект **НЕ** подбирает ключи, **НЕ** взламывает сервисы и **НЕ** обходит авторизацию.

## Архитектура

```text
                 ┌──────────────────────┐
                 │   apixray-core (Rust)│  анализ, JWT, энтропия, risk-score
                 └──────────┬───────────┘
                            │
        ┌───────────────────┼────────────────────┐
        │                   │                    │
 ┌──────▼──────┐     ┌──────▼──────┐     ┌───────▼───────┐
 │ apixray-cli │     │ apixray-ffi │     │  unit-тесты   │
 │  (Rust CLI) │     │   C ABI     │     └───────────────┘
 └─────────────┘     └──────┬──────┘
                            │
        ┌───────────────────┼────────────────────┐
        │                   │                    │
 ┌──────▼──────┐     ┌──────▼──────┐     ┌───────▼───────┐
 │  C header   │     │  C++ RAII   │     │ Python ctypes │
 └─────────────┘     └─────────────┘     └───────────────┘
```

## Что умеет

- Определяет провайдера по сигнатуре: GitHub, OpenAI, Anthropic, AWS, Slack,
  Google, Stripe, Telegram, JWT.
- Разбивает токен на сегменты и показывает роль каждого (`prefix`, `payload`, `signature`).
- Считает энтропию Шеннона и набор символов.
- Декодирует **структуру** JWT: `alg`, header, payload — без проверки подписи.
- Вычисляет risk-score и даёт рекомендации (ротация, скоупы, SECURITY.md).
- Ищет ключи в тексте/файле (`scan`) и маскирует находки.
- Генерирует фейковые ключи для тестов и демо.

## Сборка

```bash
cargo build --release --workspace
cargo test --workspace
```

Или через Docker:

```bash
docker build -t apixray .
docker run --rm apixray generate github
```

## CLI

```bash
apixray inspect ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
apixray scan ./project
apixray scan-text 'token = sk-proj-xxxxxxxx'
apixray jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.c2ln
apixray generate aws
apixray version
```

Все команды возвращают JSON — удобно для shell-скриптов и CI.

## Биндинги

### Python

```bash
cargo build --release -p apixray-ffi
export APIXRAY_LIB=$(pwd)/target/release/libapixray.so
python examples/python/demo.py
```

```python
from apixray import ApiXray

xray = ApiXray()
report = xray.analyze("ghp_...")
print(report["provider"], report["risk"], report["verdict"])
```

### C++

```bash
make demo-cpp
```

```cpp
#include "apixray.hpp"

auto report = apixray::analyze("ghp_...");
auto fake = apixray::generate_fake("github");
```

### C

```c
#include "apixray.h"

char *json = apixray_analyze("ghp_...");
/* ... */
apixray_free(json);
```

## Безопасность

- Возвращённые из FFI строки освобождаются только через `apixray_free`.
- Маскирование применяется ко всем найденным значениям: наружу не уходит полный секрет.
- `generate` создаёт строки с маркером `TEST` — они заведомо невалидны.

---

Сделано **acciv** · API keys, auth, security 🔐

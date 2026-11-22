# apixray

Разбирает API-ключи по структуре. Не подбирает и не взламывает — просто смотрит, как ключ устроен.

## Что умеет

- определяет провайдера: GitHub, OpenAI, Anthropic, AWS, Slack, Google, Stripe, Telegram, JWT;
- режет ключ на сегменты и показывает, что где;
- считает энтропию;
- разбирает JWT: `alg`, header, payload, без проверки подписи;
- считает risk score и даёт рекомендации;
- ищет ключи в тексте и маскирует их;
- делает заведомо фейковые ключи для тестов.

## Стек

Rust core, CLI на Rust, C ABI, биндинги для C, C++ и Python, Docker, GitHub Actions.

## Сборка

```bash
cargo build --release --workspace
cargo test --workspace
```

Docker:

```bash
docker build -t apixray .
docker run --rm apixray generate github
```

## Команды

```bash
apixray inspect ghp_...
apixray scan ./project
apixray scan-text 'token = sk-...'
apixray jwt eyJ...
apixray generate aws
apixray version
```

Всё отдаёт JSON.

## Биндинги

Python:

```bash
cargo build --release -p apixray-ffi
export APIXRAY_LIB=$(pwd)/target/release/libapixray.so
python examples/python/demo.py
```

```python
from apixray import ApiXray
x = ApiXray()
print(x.analyze("ghp_...")["verdict"])
```

C++:

```bash
make demo-cpp
```

```cpp
auto report = apixray::analyze("ghp_...");
auto fake = apixray::generate_fake("github");
```

C:

```c
char *json = apixray_analyze("ghp_...");
apixray_free(json);
```

## Безопасность

- Фейковые ключи помечены `TEST`, они не работают.
- Найденные значения маскируются.
- Строки из FFI нужно освобождать через `apixray_free`.

## Тесты

```bash
cargo test --workspace
make demo
```

Репозиторий: https://github.com/acciv/apixray

Сделал acciv.

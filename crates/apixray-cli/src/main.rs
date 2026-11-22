use std::fs;
use std::process::ExitCode;

const HELP: &str = "\
apixray — структурный рентген API-ключей (без подбора и взлома)

Использование:
  apixray inspect <token>        анализ строки
  apixray scan <file>            поиск ключей в файле
  apixray scan-text <text>       поиск ключей в строке
  apixray jwt <token>            разбор структуры JWT
  apixray generate <provider>    сгенерировать ЗАВЕДОМО ФЕЙКовый ключ
  apixray version
  apixray help

Провайдеры для generate: github, github_pat, openai, anthropic, aws,
slack, telegram, google, stripe, jwt.
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() || args[0] == "help" || args[0] == "-h" {
        print!("{}", HELP);
        return ExitCode::SUCCESS;
    }

    let command = args[0].as_str();
    let output = match command {
        "version" => format!("{{\"version\":\"{}\"}}", apixray_core::VERSION),
        "inspect" | "jwt" => match args.get(1) {
            Some(token) => apixray_core::analyze_json(token),
            None => return usage_error("нужен аргумент <token>"),
        },
        "scan" => match args.get(1) {
            Some(path) => match fs::read_to_string(path) {
                Ok(text) => apixray_core::scan_text_json(&text),
                Err(err) => return fail(&format!("не удалось прочитать {}: {}", path, err)),
            },
            None => return usage_error("нужен аргумент <file>"),
        },
        "scan-text" => match args.get(1) {
            Some(text) => apixray_core::scan_text_json(text),
            None => return usage_error("нужен аргумент <text>"),
        },
        "generate" => match args.get(1) {
            Some(provider) => format!(
                "{{\"provider\":\"{}\",\"fake\":true,\"token\":\"{}\"}}",
                apixray_core::json_escape(provider),
                apixray_core::json_escape(&apixray_core::generate_fake(provider))
            ),
            None => return usage_error("нужен аргумент <provider>"),
        },
        other => return usage_error(&format!("неизвестная команда: {}", other)),
    };

    println!("{}", output);
    ExitCode::SUCCESS
}

fn usage_error(message: &str) -> ExitCode {
    eprintln!("apixray: {}", message);
    eprint!("{}", HELP);
    ExitCode::from(2)
}

fn fail(message: &str) -> ExitCode {
    eprintln!("apixray: {}", message);
    ExitCode::FAILURE
}

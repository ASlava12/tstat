use clap::Parser;

/// Счётчик/анализатор пакетов сетевой карты
#[derive(Parser, Debug)]
#[command(author, version, about, long_about=None)]
pub struct Args {
    /// Интерфейс (по умолчанию — системный)
    #[arg(short, long, value_parser, default_value = "default")]
    pub interface: String,

    /// BPF-фильтр (http://biot.com/capstats/bpf.html)
    #[arg(short, long, default_value = "")]
    pub filter: String,

    /// Время захвата, сек
    #[arg(short, long, default_value_t = 1)]
    pub wait: u64,

    /// Сортировка по count (по умолчанию — по size)
    #[arg(short, long, default_value_t = false)]
    pub sort: bool,

    /// Сколько строк показывать в таблицах
    #[arg(short, long, default_value_t = 10)]
    pub top: u64,

    /// Направление: all|in|out|undef
    #[arg(short, long, default_value = "all")]
    pub direction: String,

    /// Подробные логи ошибок парсинга
    #[arg(short, long, default_value_t = false)]
    pub verbose: bool,

    /// Вывод в JSON
    #[arg(short, long, default_value_t = false)]
    pub json: bool,
}


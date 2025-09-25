// 统一日志收集模块
// 支持同时输出到控制台和文件，便于调试和问题追踪
// 
// 对于 C 开发者的说明：
// - Rust 中的 enum 类似于 C 的枚举，但功能更强大
// - struct 类似于 C 的结构体
// - impl 块用于为结构体实现方法，类似于 C++ 的类方法
// - Option<T> 是 Rust 的安全空指针，替代 C 中的 NULL 指针
// - Result<T, E> 用于错误处理，替代 C 中的返回错误码方式

use std::fs::{self, OpenOptions};   // 文件操作，类似 C 的 fopen
use std::io::{self, Write};         // 输入输出和写入 trait，类似 C 的 stdio.h
use std::path::Path;                // 路径处理
use std::sync::{Arc, Mutex};        // 线程安全的引用计数和互斥锁，类似 C 的 pthread_mutex_t
use std::time::{SystemTime, UNIX_EPOCH}; // 时间处理，类似 C 的 time.h

// 日志级别枚举
// 在 C 中可能写成：enum LogLevel { DEBUG, INFO, WARN, ERROR, SUCCESS };
// Rust 的枚举更安全，编译时检查所有分支
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]  // 添加比较 trait 用于级别过滤
pub enum LogLevel {
    Debug,   // 调试信息（最低级别）
    Info,    // 普通信息
    Warn,    // 警告信息
    Error,   // 错误信息
    Success, // 成功信息（最高级别）
}

impl LogLevel {
    // 将枚举转换为字符串，类似 C 中的 switch 语句
    // &'static str 表示静态字符串引用，生命周期是整个程序运行期间
    fn as_str(&self) -> &'static str {
        match self {  // match 类似 C 的 switch，但更强大且必须处理所有情况
            LogLevel::Debug => "DEBUG",
            LogLevel::Info => "INFO",
            LogLevel::Warn => "WARN",
            LogLevel::Error => "ERROR", 
            LogLevel::Success => "SUCCESS",
        }
    }

    // 获取 ANSI 颜色代码，用于控制台彩色输出
    // 类似 C 中使用 printf("\033[31m") 设置颜色
    fn color_code(&self) -> &'static str {
        match self {
            LogLevel::Debug => "\x1b[37m",    // 白色
            LogLevel::Info => "\x1b[36m",     // 青色 (类似 printf 的 \033[36m)
            LogLevel::Warn => "\x1b[33m",     // 黄色
            LogLevel::Error => "\x1b[31m",    // 红色 (类似 printf 的 \033[31m)
            LogLevel::Success => "\x1b[32m",  // 绿色 (类似 printf 的 \033[32m)
        }
    }
}

// 日志器结构体
// 类似 C 中的：
// struct Logger {
//     FILE* file;
//     int console_enabled;
//     int file_enabled;
// };
pub struct Logger {
    // Option<T> 表示可能有值也可能没有，替代 C 中的 NULL 指针
    // Arc<Mutex<T>> 是线程安全的共享指针，类似 C 中的 FILE* 加上 pthread_mutex_t
    file_writer: Option<Arc<Mutex<std::fs::File>>>,
    console_enabled: bool,  // bool 类似 C 的 int (作为布尔值使用)
    file_enabled: bool,
    min_level: LogLevel,    // 最小日志级别，用于过滤
}

#[allow(dead_code)]
impl Logger {
    // 构造函数，类似 C 中的初始化函数
    // Result<Self, io::Error> 表示成功返回 Logger，失败返回错误
    // 在 C 中通常返回指针，NULL 表示失败
    pub fn new(log_file_path: Option<&str>) -> io::Result<Self> {
        // 如果提供了文件路径就创建文件
        let file_writer = if let Some(path) = log_file_path {
            // 自动创建目录结构
            if let Some(parent_dir) = Path::new(path).parent() {
                fs::create_dir_all(parent_dir)?;  // 递归创建所有必需的目录
            }
            
            // 打开文件用于追加写入，类似 C 的 fopen(path, "a")
            let file = OpenOptions::new()
                .create(true)    // 如果文件不存在就创建，类似 O_CREAT
                .append(true)    // 追加模式，类似 O_APPEND
                .open(path)?;    // ? 操作符用于错误传播，类似 C 中检查返回值
            Some(Arc::new(Mutex::new(file)))  // 包装为线程安全的共享指针
        } else {
            None  // 相当于 C 中的 NULL
        };

        let file_enabled = file_writer.is_some();  // 检查是否有文件，类似 C 中的 file != NULL
        
        // 返回初始化的结构体，类似 C 中的 malloc + 初始化
        Ok(Logger {
            file_writer,
            console_enabled: true,
            file_enabled,
            min_level: LogLevel::Debug,  // 默认显示所有级别的日志
        })
    }

    // 获取当前时间戳字符串 (私有方法，类似 C 中的 static 函数)
    fn get_timestamp() -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)      // 获取从 Unix 纪元开始的时间
            .unwrap_or_default();            // 如果失败就使用默认值，类似 C 中的错误检查
        let secs = now.as_secs();
        
        // 将 Unix 时间戳转换为本地时间
        let datetime = std::time::UNIX_EPOCH + std::time::Duration::from_secs(secs);
        let local_time = datetime.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        
        // 计算年月日时分秒 (简化版本，假设为 UTC+8)
        let total_days = local_time / 86400 + 8 * 3600 / 86400; // 加上时区偏移
        let days_since_epoch = total_days;
        let seconds_today = (local_time + 8 * 3600) % 86400;
        
        // 计算年份 (简化算法)
        let mut year = 1970;
        let mut remaining_days = days_since_epoch;
        
        loop {
            let days_in_year = if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) { 366 } else { 365 };
            if remaining_days < days_in_year {
                break;
            }
            remaining_days -= days_in_year;
            year += 1;
        }
        
        // 计算月份和日期
        let days_in_months = if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) {
            [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
        } else {
            [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
        };
        
        let mut month = 1;
        let mut day_of_month = remaining_days + 1;
        
        for &days_in_month in &days_in_months {
            if day_of_month <= days_in_month {
                break;
            }
            day_of_month -= days_in_month;
            month += 1;
        }
        
        // 计算时分秒
        let hour = seconds_today / 3600;
        let minute = (seconds_today % 3600) / 60;
        let second = seconds_today % 60;
        
        // 格式化为 [YYYY-MM-DD HH:MM:SS] 格式
        format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02}", year, month, day_of_month, hour, minute, second)
    }

    // 记录日志的核心函数，类似 C 中的 log 函数
    // &self 表示借用 self，类似 C 中传递结构体指针
    pub fn log(&self, level: LogLevel, message: &str) {
        // 级别过滤：只记录大于等于最小级别的日志
        if level < self.min_level {
            return;
        }
        
        let timestamp = Self::get_timestamp();  // 调用静态方法，类似 C 中的函数调用
        let level_str = level.as_str();
        
        // 控制台输出（带颜色），类似 C 中的 printf
        if self.console_enabled && LogLevel::Debug != level{
            let color = level.color_code();
            let reset = "\x1b[0m";  // ANSI 重置颜色代码
            // println! 是 Rust 的打印宏，类似 C 的 printf
            println!("{color}[{timestamp}] {level_str}: {message}{reset}");
        }

        // 文件输出（无颜色），类似 C 中的 fprintf
        if self.file_enabled {
            if let Some(ref file_writer) = self.file_writer {  // 检查文件是否存在
                // 获取互斥锁，类似 C 中的 pthread_mutex_lock
                if let Ok(mut file) = file_writer.lock() {
                    // 写入文件，类似 C 的 fprintf
                    let _ = writeln!(file, "[{}] {}: {}", timestamp, level_str, message);
                    let _ = file.flush(); // 立即刷新到磁盘，类似 C 的 fflush
                }
            }
        }
    }

    // 设置最小日志级别
    pub fn set_min_level(&mut self, level: LogLevel) {
        self.min_level = level;
    }

    // 便捷方法：记录调试级别日志
    pub fn debug(&self, message: &str) {
        self.log(LogLevel::Debug, message);
    }

    // 便捷方法：记录信息级别日志
    // 类似 C 中定义宏：#define log_info(msg) log(INFO, msg)
    pub fn info(&self, message: &str) {
        self.log(LogLevel::Info, message);
    }

    // 便捷方法：记录警告级别日志
    pub fn warn(&self, message: &str) {
        self.log(LogLevel::Warn, message);
    }

    // 便捷方法：记录错误级别日志
    pub fn error(&self, message: &str) {
        self.log(LogLevel::Error, message);
    }

    // 便捷方法：记录成功级别日志
    pub fn success(&self, message: &str) {
        self.log(LogLevel::Success, message);
    }

    // 记录原始消息（不添加时间戳和级别）
    // 类似 C 中直接使用 printf 和 fprintf
    pub fn raw(&self, message: &str) {
        // 控制台输出
        if self.console_enabled {
            println!("{}", message);
        }

        // 文件输出
        if self.file_enabled {
            if let Some(ref file_writer) = self.file_writer {
                if let Ok(mut file) = file_writer.lock() {
                    let _ = writeln!(file, "{}", message);
                    let _ = file.flush();
                }
            }
        }
    }

    // 格式化日志方法 - 支持 format_args
    pub fn log_fmt(&self, level: LogLevel, args: std::fmt::Arguments) {
        let message = format!("{}", args);
        self.log(level, &message);
    }

    // 便捷的格式化方法
    pub fn debug_fmt(&self, args: std::fmt::Arguments) {
        self.log_fmt(LogLevel::Debug, args);
    }

    pub fn info_fmt(&self, args: std::fmt::Arguments) {
        self.log_fmt(LogLevel::Info, args);
    }

    pub fn warn_fmt(&self, args: std::fmt::Arguments) {
        self.log_fmt(LogLevel::Warn, args);
    }

    pub fn error_fmt(&self, args: std::fmt::Arguments) {
        self.log_fmt(LogLevel::Error, args);
    }

    pub fn success_fmt(&self, args: std::fmt::Arguments) {
        self.log_fmt(LogLevel::Success, args);
    }
}

// 使用更安全的全局状态管理
use std::sync::OnceLock;

// 使用 OnceLock 替代 unsafe 的全局变量
static GLOBAL_LOGGER: OnceLock<Logger> = OnceLock::new();

// 初始化全局日志器 - 更简洁和安全
pub fn init_logger(log_file_path: Option<&str>) -> io::Result<()> {
    let logger = Logger::new(log_file_path).or_else(|_| {
        // 如果文件初始化失败，创建仅控制台的日志器
        Logger::new(None)
    })?;
    GLOBAL_LOGGER.set(logger).map_err(|_| {
        io::Error::new(io::ErrorKind::AlreadyExists, "Logger already initialized")
    })?;
    Ok(())
}

// 全局日志器初始化函数，带级别设置
#[allow(dead_code)]
pub fn init_logger_with_level(log_file_path: Option<&str>, min_level: LogLevel) -> io::Result<()> {
    let mut logger = Logger::new(log_file_path).or_else(|_| {
        Logger::new(None)
    })?;
    logger.set_min_level(min_level);
    GLOBAL_LOGGER.set(logger).map_err(|_| {
        io::Error::new(io::ErrorKind::AlreadyExists, "Logger already initialized")
    })?;
    Ok(())
}

// 检查全局日志器是否已初始化
#[allow(dead_code)]
pub fn is_logger_initialized() -> bool {
    GLOBAL_LOGGER.get().is_some()
}

// 获取全局日志器引用 - 现在是安全的
pub fn get_logger() -> Option<&'static Logger> {
    GLOBAL_LOGGER.get()
}

// 使用宏生成全局日志函数，减少代码重复
macro_rules! generate_global_log_fn {
    ($fn_name:ident, $method:ident, $level:literal, $fallback:ident) => {
        #[allow(dead_code)]
        pub fn $fn_name(message: &str) {
            if let Some(logger) = get_logger() {
                logger.$method(message);
            } else {
                $fallback!("{}: {}", $level, message);
            }
        }
    };
    ($fn_name:ident, $method:ident, $fallback:ident) => {
        #[allow(dead_code)]
        pub fn $fn_name(message: &str) {
            if let Some(logger) = get_logger() {
                logger.$method(message);
            } else {
                $fallback!("{}", message);
            }
        }
    };
}

// 生成所有全局日志函数
generate_global_log_fn!(log_debug, debug, "DEBUG", eprintln);
generate_global_log_fn!(log_info, info, println);
generate_global_log_fn!(log_warn, warn, "WARNING", eprintln);
generate_global_log_fn!(log_error, error, "ERROR", eprintln);
generate_global_log_fn!(log_success, success, println);
generate_global_log_fn!(log_raw, raw, println);

// 格式化日志宏 - 类似 C 中的变参宏
// Rust 宏比 C 宏更强大和安全，编译时展开
#[macro_export]
macro_rules! log_debug_fmt {
    ($($arg:tt)*) => {
        if let Some(logger) = $crate::logger::get_logger() {
            logger.debug_fmt(format_args!($($arg)*));
        } else {
            eprintln!("DEBUG: {}", format!($($arg)*));
        }
    };
}

#[macro_export]
macro_rules! log_info_fmt {
    // $($arg:tt)* 表示接受任意数量的参数，类似 C 的 ...
    ($($arg:tt)*) => {
        if let Some(logger) = $crate::logger::get_logger() {
            logger.info_fmt(format_args!($($arg)*));
        } else {
            // 直接使用 println! 宏，类似 C 的 printf
            println!($($arg)*);
        }
    };
}

#[macro_export]
macro_rules! log_warn_fmt {
    ($($arg:tt)*) => {
        if let Some(logger) = $crate::logger::get_logger() {
            logger.warn_fmt(format_args!($($arg)*));
        } else {
            eprintln!("WARNING: {}", format!($($arg)*));
        }
    };
}

#[macro_export]
macro_rules! log_error_fmt {
    ($($arg:tt)*) => {
        if let Some(logger) = $crate::logger::get_logger() {
            logger.error_fmt(format_args!($($arg)*));
        } else {
            eprintln!("ERROR: {}", format!($($arg)*));
        }
    };
}

#[macro_export]
macro_rules! log_success_fmt {
    ($($arg:tt)*) => {
        if let Some(logger) = $crate::logger::get_logger() {
            logger.success_fmt(format_args!($($arg)*));
        } else {
            println!($($arg)*);
        }
    };
}

// 添加一个通用的日志宏，支持不同级别
#[macro_export]
macro_rules! log {
    (debug, $($arg:tt)*) => { $crate::log_debug_fmt!($($arg)*); };
    (info, $($arg:tt)*) => { $crate::log_info_fmt!($($arg)*); };
    (warn, $($arg:tt)*) => { $crate::log_warn_fmt!($($arg)*); };
    (error, $($arg:tt)*) => { $crate::log_error_fmt!($($arg)*); };
    (success, $($arg:tt)*) => { $crate::log_success_fmt!($($arg)*); };
}

// 
// 对 C 开发者的总结：
// 1. Rust 的内存管理是自动的，不需要手动 malloc/free
// 2. Option<T> 替代了 NULL 指针，编译时检查空值
// 3. Result<T,E> 替代了错误码，强制处理错误
// 4. match 比 switch 更强大，必须处理所有情况
// 5. 借用检查器防止悬空指针和数据竞争
// 6. 宏比 C 预处理器宏更安全，有类型检查
// 7. 线程安全通过类型系统保证，而不是运行时检查
//

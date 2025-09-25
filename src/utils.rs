// 导入clap库的Parser trait，用于自动生成命令行解析器
use clap::Parser;

// 导入系统信息库，用于获取内存信息
use sysinfo::{System, SystemExt};
use std::process;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct Args {
    // -m 或 --memory 选项，指定要测试的内存大小
    #[clap(short = 'm', long = "memory", value_parser = parse_memory_size,
            help = "Memory size to test, Default unit is MB(default: total memory - 4GB)")]
    mem_to_test: Option<u64>,

    // -l 或 --loops 选项，指定测试循环次数
    #[clap(short = 'l', long = "loops", default_value = "1",
       help = "Number of test loops (ignored when time limit is set)")]
    loops: u64, 

    // -t 或 --time 选项，指定测试运行的最大时间（分钟，支持小数）
    #[clap(short = 't', long = "time",
            help = "Maximum test time in minutes (cannot be used with --loops, supports decimals, e.g., 0.5)")]
    time_limit: Option<f64>,

    // -c 或 --cores 选项，指定使用的逻辑核数量
    #[clap(short = 'c', long = "cores",
            help = "Number of logical cores to use (default: all available cores)")]
    cores: Option<usize>,

    // -p 或 --pattern 选项，指定测试模式
    #[clap(short = 'p', long = "pattern", value_parser = parse_pattern,
            default_value = "0xff",
            help = "Test pattern (supports hex like 0xff)")]
    pattern: Option<usize>,

    #[clap(short = 'L', long = "log-path",
           default_value = "/var/log/cnit/",
           help = "Path to save log file path(default: /var/log/cnit/memtester.log)")]
    log_path: Option<String>,
}

fn get_default_memory_size() -> usize {
    let mut system = System::new_all();
    system.refresh_memory();

    // 获取空闲内存（字节）
    let free_memory = system.get_free_memory() * 1024; // sysinfo返回KB，转换为字节

    // 保留4GB给系统（4 * 1024 * 1024 * 1024 字节）
    let reserved_memory = 4 * 1024 * 1024 * 1024u64;

    // 计算可用内存，确保不会小于1GB
    let available_memory = if free_memory > reserved_memory {
        free_memory - reserved_memory
    } else {
        // 如果总内存小于等于4GB，使用总内存的75%
        (free_memory * 3) / 4
    };

    // 确保至少有1GB可用内存
    let min_memory = 1024 * 1024 * 1024u64; // 1GB
    let final_memory = available_memory.max(min_memory);


    println!("System memory info:");
    println!("  Total memory: {:.2} GB", 
             system.get_total_memory() as f64 / (1024.0 * 1024.0));
    println!("  Free memory: {:.2} GB", 
             free_memory as f64 / (1024.0 * 1024.0 * 1024.0));
    println!("  Available for testing: {:.2} GB", 
             final_memory as f64 / (1024.0 * 1024.0 * 1024.0));

    final_memory as usize
}

fn parse_memory_size(s: &str) -> Result<u64, String> {
    // to_uppercase() 转换为大写，返回新的String
    let s = s.to_uppercase();

    // 模式匹配：Rust的强大特性，类似C语言的switch但更安全
    // 解构赋值：同时获取数字部分和乘数
    let (num_str, mult) = if s.ends_with('B') {
        // 字符串切片语法：&s[..s.len() - 1] 获取除最后一个字符外的所有字符
        (&s[..s.len() - 1], 1)
    } else if s.ends_with('K') {
        (&s[..s.len() - 1], 1024)
    } else if s.ends_with('M') {
        (&s[..s.len() - 1], 1024 * 1024)
    } else if s.ends_with('G') {
        (&s[..s.len() - 1], 1024 * 1024 * 1024)
    } else {
        // as_str() 将String转换为&str
        (s.as_str(), 1024 * 1024)
    };

    // 链式调用：Rust的函数式编程风格
    // parse::<u64>() 尝试解析为u64类型
    // map() 在成功时应用函数
    // map_err() 在失败时转换错误类型
    num_str
        .parse::<u64>()
        .map(|n| n * mult)
        .map_err(|_| format!("Invalid memory size: {}", s))
}

fn parse_pattern(s: &str) -> Result<usize, String> {
    if s.starts_with("0x") || s.starts_with("0X") {
        usize::from_str_radix(&s[2..], 16)
            .map_err(|_| format!("Invalid hex pattern: {}", s))
    } else {
        s.parse::<usize>()
            .map_err(|_| format!("Invalid pattern: {}", s))
    }
}

// 返回类型包含内存大小、循环次数、可选的时间限制（分钟）和可选的核心数
pub fn parse_args() -> Result<(usize, usize, Option<f64>, Option<usize>, Option<usize>, Option<String>), String> {
    // Args::parse() 是clap自动生成的解析函数
    let args = Args::parse();

    // 获取内存大小：用户指定的或默认值
    let memory_size = match args.mem_to_test {
        Some(size) => size as usize,
        None => get_default_memory_size(),
    };

    // 返回元组：(内存大小, 循环次数, 时间限制分钟数, 核心数, 测试掩码, 日志路径)
    Ok((memory_size, args.loops as usize, args.time_limit, args.cores, args.pattern, args.log_path))
}

pub fn usage(e: &String) -> ! {
    eprintln!("Error: {}", e);
    eprintln!();
    eprintln!("Usage examples:");
    eprintln!("  # Test with default memory (free - 4GB) for 30 minutes");
    eprintln!("  cargo run -- --time 30");
    eprintln!();
    eprintln!("  # Test 1GB memory for 10 loops");
    eprintln!("  cargo run -- --memory 1G --loops 10");
    eprintln!();
    eprintln!("  # Test 512MB memory using 8 cores for 15 minutes");
    eprintln!("  cargo run -- --memory 512M --cores 8 --time 15");
    eprintln!();
    eprintln!("  # Test with custom memory and cores for 5 loops");
    eprintln!("  cargo run -- --memory 2G --cores 4 --loops 5");
    process::exit(1);
}

// ================================================================================================
// Aligned Memory Allocation
// ================================================================================================

use std::alloc::{alloc, dealloc, Layout};
use std::slice;
use libc;

/// A container for a block of memory aligned to the system's page size and locked into RAM.
/// The memory is automatically unlocked and deallocated when this object is dropped.
#[derive(Debug)]
#[allow(dead_code)]
pub struct AlignedMemory {
    ptr: *mut u8,
    layout: Layout,
}

#[allow(dead_code)]
impl AlignedMemory {
    /// Allocates memory aligned to the system's page size and locks it into RAM.
    ///
    /// The size is automatically rounded up to the nearest page multiple.
    /// NOTE: This may fail if the process lacks the required permissions (e.g., CAP_IPC_LOCK).
    /// Try running with sudo if allocation fails.
    pub fn new(size: usize) -> Option<Self> {
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize };
        if page_size == 0 {
            return None;
        }

        // Round the size up to the nearest multiple of page_size.
        let rounded_size = (size + page_size - 1) & !(page_size - 1);
        
        let layout = match Layout::from_size_align(rounded_size, page_size) {
            Ok(l) => l,
            Err(_) => return None,
        };

        let ptr = unsafe { alloc(layout) };
        if ptr.is_null() {
            return None;
        }

        // Lock the memory into RAM
        let mlock_result = unsafe { libc::mlock(ptr as *const libc::c_void, layout.size()) };
        if mlock_result != 0 {
            // mlock failed, clean up and return None.
            eprintln!(
                "[ERROR] Failed to lock memory with mlock (errno: {}). This can happen if the process lacks permissions (e.g., CAP_IPC_LOCK) or if there is not enough physical RAM. Try running with sudo.",
                std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
            );
            unsafe { dealloc(ptr, layout) };
            return None;
        }

        Some(Self { ptr, layout })
    }

    /// Returns the size of the allocated memory block in bytes.
    pub fn size(&self) -> usize {
        self.layout.size()
    }

    /// Returns a raw pointer to the allocated memory.
    pub fn as_ptr(&self) -> *const u8 {
        self.ptr
    }

    /// Returns a mutable raw pointer to the allocated memory.
    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.ptr
    }

    /// Returns a slice providing safe access to the memory.
    pub fn as_slice(&self) -> &[u8] {
        unsafe { slice::from_raw_parts(self.ptr, self.layout.size()) }
    }

    /// Returns a mutable slice providing safe access to the memory.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { slice::from_raw_parts_mut(self.ptr, self.layout.size()) }
    }

    /// Returns a slice of u64, providing safe access to the memory.
    /// This is efficient for memory testing as it uses wider memory accesses.
    ///
    /// # Panics
    /// Panics if the allocated size is not a multiple of 8.
    pub fn as_slice_u64(&self) -> &[u64] {
        let size_of_u64 = std::mem::size_of::<u64>();
        if self.layout.size() % size_of_u64 != 0 {
            panic!(
                "Cannot create u64 slice: total size {} is not a multiple of {}",
                self.layout.size(),
                size_of_u64
            );
        }
        // Alignment is guaranteed by `new` to be page_size, which is always >= align_of::<u64>().
        unsafe {
            slice::from_raw_parts(self.ptr as *const u64, self.layout.size() / size_of_u64)
        }
    }

    /// Returns a mutable slice of u64, providing safe access to the memory.
    /// This is efficient for memory testing as it uses wider memory accesses.
    ///
    /// # Panics
    /// Panics if the allocated size is not a multiple of 8.
    pub fn as_mut_slice_u64(&mut self) -> &mut [u64] {
        let size_of_u64 = std::mem::size_of::<u64>();
        if self.layout.size() % size_of_u64 != 0 {
            panic!(
                "Cannot create mutable u64 slice: total size {} is not a multiple of {}",
                self.layout.size(),
                size_of_u64
            );
        }
        // Alignment is guaranteed by `new` to be page_size, which is always >= align_of::<u64>().
        unsafe {
            slice::from_raw_parts_mut(self.ptr as *mut u64, self.layout.size() / size_of_u64)
        }
    }
}

impl Drop for AlignedMemory {
    fn drop(&mut self) {
        unsafe {
            // Unlock the memory before deallocating.
            // We ignore the result, as we can't handle errors in drop anyway.
            let _ = libc::munlock(self.ptr as *const libc::c_void, self.layout.size());
            dealloc(self.ptr, self.layout);
        }
    }
}

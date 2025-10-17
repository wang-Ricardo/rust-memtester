// 导入clap库的Parser trait，用于自动生成命令行解析器
use clap::Parser;
use std::process;

#[cfg(target_os = "linux")]
use std::fs;
#[cfg(target_os = "linux")]
use std::io::Read;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct Args {
    // -m 或 --memory 选项，指定要测试的内存大小
    #[clap(short = 'm', long = "memory", value_parser = parse_memory_size,
            help = "Memory size to test, Default unit is MB (default: MemFree - DMA_free - HighReserve - MemFree/500)")]
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
            default_value = "0xfffff",
            help = "Test pattern (supports hex like 0xfffff)")]
    pattern: Option<usize>,

    #[clap(short = 'L', long = "log-path",
           default_value = "/var/log/",
           help = "Path to save log file path(default: /var/log/cnit/memtester.log)")]
    log_path: Option<String>,
}

#[cfg(target_os = "linux")]
fn get_default_memory_size() -> usize {
    // 读取 /proc/meminfo 的内容
    let meminfo = fs::read_to_string("/proc/meminfo").unwrap_or_default();

    // 提取 MemFree (kB)
    let mut mem_free_kb: u64 = 0;
    for line in meminfo.lines() {
        if line.starts_with("MemFree:") {
            // 形如: MemFree:       123456 kB
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                if let Ok(v) = parts[1].parse::<u64>() { mem_free_kb = v; }
            }
            break;
        }
    }

    // 页大小（字节）
    let page_size: u64 = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as u64 };
    let page_size = if page_size > 0 { page_size } else { 4096 };

    // 解析 /proc/zoneinfo 获取：
    // - DMA_free: 累计 zones {DMA,DMA32} 的 nr_free_pages * page_size
    // - HighReserve: 累计所有 "high" 水位（页数） * page_size
    let mut dma_free_pages: u64 = 0;
    let mut high_reserve_pages: u64 = 0;
    let mut current_zone: Option<String> = None;

    if let Ok(mut f) = fs::File::open("/proc/zoneinfo") {
        let mut content = String::new();
        let _ = f.read_to_string(&mut content);
        for raw_line in content.lines() {
            let line = raw_line.trim();
            // 记录当前 zone 名
            if raw_line.contains(", zone") {
                // 示例: "Node 0, zone      DMA"
                let after = raw_line.split("zone").nth(1).unwrap_or("").trim();
                let zone_name = after.split_whitespace().next().unwrap_or("").to_string();
                current_zone = if zone_name.is_empty() { None } else { Some(zone_name) };
                continue;
            }

            // nr_free_pages (仅统计 DMA/DMA32)
            if line.starts_with("nr_free_pages") {
                if let Some(zone) = &current_zone {
                    if zone == "DMA" || zone == "DMA32" {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() >= 2 {
                            if let Ok(pages) = parts[1].parse::<u64>() { dma_free_pages = dma_free_pages.saturating_add(pages); }
                        }
                    }
                }
                continue;
            }

            // 累计所有 zone 的 high 水位（页）
            if line.starts_with("high") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    if let Ok(pages) = parts[1].parse::<u64>() { high_reserve_pages = high_reserve_pages.saturating_add(pages); }
                }
                continue;
            }
        }
    }

    let mem_free_bytes = mem_free_kb.saturating_mul(1024);
    let dma_free_bytes = dma_free_pages.saturating_mul(page_size);
    let high_reserve_bytes = high_reserve_pages.saturating_mul(page_size);
    
    // 线性保留策略：每 128GB 保留 1GB，最小 4GB
    // 计算公式：reserve = max(4GB, MemFree / 128GB * 1GB)
    // 示例：
    //   64GB   -> 0.5GB -> 保留 4GB (最小值)
    //   128GB  -> 1GB   -> 保留 4GB (最小值)
    //   256GB  -> 2GB   -> 保留 4GB (最小值)
    //   512GB  -> 4GB   -> 保留 4GB
    //   1TB    -> 8GB   -> 保留 8GB
    //   3TB    -> 24GB  -> 保留 24GB
    let gb_128 = 128 * 1024 * 1024 * 1024u64;  // 128GB
    let gb_1 = 1024 * 1024 * 1024u64;          // 1GB
    let gb_4 = 4 * 1024 * 1024 * 1024u64;      // 4GB (最小保留)
    
    let calculated_reserve = (mem_free_bytes / gb_128) * gb_1;  // 每128GB保留1GB
    let safety_bytes = calculated_reserve.max(gb_4);             // 最小4GB

    // 计算最终可用值
    let mut test_bytes = mem_free_bytes
        .saturating_sub(dma_free_bytes)
        .saturating_sub(high_reserve_bytes)
        .saturating_sub(safety_bytes);

    // 至少保证 1 GiB
    let one_gib: u64 = 1024 * 1024 * 1024;
    if test_bytes < one_gib { test_bytes = one_gib; }

    test_bytes as usize
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
    eprintln!("  # Test with default memory (MemFree - DMA_free - HighReserve - MemFree/500) for 30 minutes");
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

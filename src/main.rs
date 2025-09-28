// 导入标准库的错误处理trait
// 【C对比】类似于 #include <errno.h>，但Rust的错误处理是类型安全的
// 不像C语言依赖返回值或全局errno，Rust使用Result<T, E>强制错误处理
use std::error::Error;

// 导入时间相关的类型，用于实现定时功能
// 【C对比】类似于 #include <time.h> 和 clock_gettime()
// Instant: 类似于C的 struct timespec，用于高精度时间测量
// Duration: 类似于C的时间差计算，但类型安全
use std::time::{Duration, Instant};

// 导入多线程相关的类型
// 【C对比】类似于 #include <pthread.h> 和 #include <stdatomic.h>
// Arc: 原子引用计数智能指针，类似于C++的shared_ptr，但线程安全
//      相当于C语言中手动实现的引用计数 + mutex保护
// AtomicBool: 原子布尔值，类似于C11的 _Atomic bool
// AtomicU64: 原子64位整数，类似于C11的 _Atomic uint64_t
// AtomicUsize: 原子usize，用于计数
// Barrier: 线程屏障，类似于pthread_barrier_t
use std::sync::{Arc, atomic::{AtomicU64, AtomicUsize, AtomicBool, Ordering}, Barrier, Mutex};

// 导入线程相关功能
// 【C对比】类似于 #include <pthread.h>
// std::thread 提供了比pthread更安全的线程API
use std::thread;

use clap::CommandFactory;

mod utils;
mod logger;
mod ecc;
mod cpu_utils;
mod tests;

// ================================================================================================
// 同步worker线程函数 - 所有线程同步执行相同的测试pattern
// ================================================================================================
// 【C对比】类似于pthread_create的线程函数：void* worker_thread(void* arg)
// 但Rust的类型系统提供了更好的安全性：
// 1. 参数类型明确，不需要void*和类型转换
// 2. 返回类型是Result，强制错误处理
// 3. Send + Sync约束确保线程安全
//
// void* sync_worker_thread(void* args);
fn sync_worker_thread(
    core_id: usize,                      // 【C等价】size_t core_id
    mem_size_per_thread: usize,          // 【C等价】size_t mem_size_per_thread
    global_loop_counter: Arc<AtomicU64>, // 【C等价】atomic_uint64_t* global_counter
    target_loops: usize,           // 【C等价】uint64_t* target_loops (可为NULL)
    start_barrier: Arc<Barrier>,
    pattern_barrier: Arc<Barrier>,
    report_barrier: Arc<Barrier>,
    pattern_failure_counter: Arc<AtomicUsize>,
    pattern: usize,
    ecc_monitor: Arc<Mutex<ecc::EccMonitor>>,
    global_failure_flag: Arc<AtomicBool>,// 全局失败标志
) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> { // 【C等价】int (返回错误码)
    // 1. 绑定线程到指定的CPU核心
    if cpu_utils::bind_thread_to_core(core_id) {
        log_debug_fmt!("Thread {} has successfully been bound to the CPU core.", core_id);
    } else {
        log_warn_fmt!("Warning: Failed to bind thread {} to CPU core.", core_id);
    }

    // 2. 分配页对齐并锁定的内存
    let mut memory_block = match utils::AlignedMemory::new(mem_size_per_thread) {
        Some(mem) => mem,
        None => {
            let err_msg = format!("Error: Failed memory allocation for the core {}", core_id);
            log_error_fmt!("{}", err_msg);
            return Err(err_msg.into());
        }
    };
    log_debug_fmt!(
        "Thread {}: Successfully allocated {} bytes of aligned memory",
        core_id,
        memory_block.size()
    );

    // 等待所有线程准备就绪，并让领头线程执行一次性初始化
    let wait_result = start_barrier.wait();
    if wait_result.is_leader() {
        pattern_failure_counter.store(0, Ordering::Relaxed);
        if let Ok(mut monitor) = ecc_monitor.lock() {
            if let Err(e) = monitor.check_ecc_errors() {
                logger::log_warn(&format!("Initial ECC check failed: {}", e));
            }
        } else {
            logger::log_error("Could not acquire lock on EccMonitor for initial check.");
        }
    }
    
    let u64_slice = memory_block.as_mut_slice_u64();
    let mut local_loops = 0u64;

    // 主测试循环
    loop {
        if target_loops > 0 && local_loops >= target_loops as u64 { break; }

        report_barrier.wait();

        if let Err(e) = tests::test_stuck_address(u64_slice) {
            // 如果测试失败，打印错误并增加失败计数
            logger::log_error(&e.to_string());
            pattern_failure_counter.fetch_add(1, Ordering::Relaxed);
        }

        if pattern_barrier.wait().is_leader() {
            let result = if pattern_failure_counter.load(Ordering::Relaxed) > 0 { 
                pattern_failure_counter.store(0, Ordering::Relaxed);
                global_failure_flag.store(true, Ordering::Relaxed);
                "FAILED" 
            } else { "ok" };
            log_info_fmt!("   {:20}: {}", String::from("Stuck Address"), result);

            // 领头线程也在这里执行ECC检查
            if let Ok(mut monitor) = ecc_monitor.lock() {
                if let Err(e) = monitor.check_ecc_errors() {
                    logger::log_error(&format!("ECC check failed: {}", e));
                }
            } else {
                logger::log_error("Could not acquire lock on EccMonitor for pattern check.");
            }
        }

        u64_slice.fill(255u64);

        // 遍历并执行所有被选中的测试
        for test in tests::TESTS.iter() {
            if (pattern as u64 & test.mask) != 0 {
                report_barrier.wait();

                // --- 执行测试 ---
                if let Err(e) = tests::run_test(test, u64_slice) {
                    // 如果测试失败，打印错误并增加失败计数
                    logger::log_error(&e.to_string());
                    pattern_failure_counter.fetch_add(1, Ordering::Relaxed);
                }

                // --- 同步点 3: 领头线程报告最终结果 ---
                if pattern_barrier.wait().is_leader() {
                    let result = if pattern_failure_counter.load(Ordering::Relaxed) > 0 { 
                        pattern_failure_counter.store(0, Ordering::Relaxed);
                        "FAILED" 
                    } else { "ok" };
                    log_info_fmt!("   {:20}: {}", test.name, result);

                    // 领头线程也在这里执行ECC检查
                    if let Ok(mut monitor) = ecc_monitor.lock() {
                        if let Err(e) = monitor.check_ecc_errors() {
                            logger::log_error(&format!("ECC check failed: {}", e));
                        }
                    } else {
                        logger::log_error("Could not acquire lock on EccMonitor for pattern check.");
                    }
                }
            }
        }

        local_loops += 1;
        global_loop_counter.fetch_add(1, Ordering::Relaxed);
    }

    Ok(local_loops)
}

// Rust的main函数可以返回Result类型，用于错误处理
// Box<dyn Error> 是一个trait对象，可以包含任何实现了Error trait的类型
// 这比C语言的int返回值更具表达性和类型安全
fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|arg| arg == "-h" || arg == "--help") {
        let mut cmd = utils::Args::command();
        cmd.print_help()?;
        println!("");
        tests::print_test_mask_help();
        return Ok(());
    }

    let (mem_size, loops, time_limit_minutes, requested_cores, pattern, log_path) = match utils::parse_args() {
        Ok(args) => args,
        Err(e) => utils::usage(&e),  // 调用 usage 会退出程序
    };

    // 初始化优化后的日志系统
    // -L参数是目录路径，日志文件名固定为memtester.log
    let log_dir = log_path.as_deref().unwrap_or("/var/log/cnit/");
    let log_file_path = format!("{}/memtester.log", log_dir.trim_end_matches('/'));
    
    if let Err(e) = logger::init_logger(Some(&log_file_path)) {
        eprintln!("Failed to initialize logger: {}", e);
        // 继续运行，使用控制台输出
    }

    log_info_fmt!("Log path: {}", log_file_path);

    // 检查 loops 和 time_limit 的冲突
    let real_loops = match (loops != 1, time_limit_minutes.is_some()) {
        (true, true) => {
            return Err("Error: It is not possible to specify both the loop count (-l / --loops) and the time limit (-t / --time) parameters simultaneously.".into());
        },
        (false, true) => {
            // 只有时间参数，忽略默认的 loops=1
            log_info_fmt!("Use the time limit mode and ignore the loop count parameter");
            log_info_fmt!("Time limit: {} seconds", time_limit_minutes.map(|minutes| (minutes * 60.0) as u64).unwrap_or(0));
            0
        },
        (true, false) => {
            // 只有 loops 参数
            log_info_fmt!("Use the loop count mode: {} times", loops);
            loops
        },
        (false, false) => {
            // 都没有指定，使用默认的 loops=1
            log_info_fmt!("Use the default loop count mode: 1 time");
            1
        }
    };

    let core_usage = cpu_utils::calculate_core_usage(requested_cores);
    let num_threads = core_usage.len();
    if let Some(requested) = requested_cores {
        log_info_fmt!("User requested {} cores, using {} worker threads", requested, num_threads);
    } else {
        log_info_fmt!("Using all logic cores, starting {} worker threads", num_threads);
    }

    // 计算每个线程分配的内存大小
    // 确保每个线程有足够的内存进行测试
    let mem_size_per_thread = mem_size / num_threads;

    if mem_size_per_thread < 1024 {
        return Err("Memory size too small for multi-threading. Use at least 1KB per CPU core.".into());
    }

    log_info_fmt!("Testing {}MB per thread ({} threads, {}MB total)",
             mem_size_per_thread / (1024 * 1024),
             num_threads,
             mem_size / (1024 * 1024));

    log_info_fmt!("Test mask: 0x{:08X}", pattern.unwrap_or(0));

    // 创建线程间共享的原子变量
    let global_loop_counter = Arc::new(AtomicU64::new(0));
    let ecc_monitor = Arc::new(Mutex::new(ecc::EccMonitor::new()));
    let global_failure_flag = Arc::new(AtomicBool::new(false));
    let pattern_failure_counter = Arc::new(AtomicUsize::new(0));
    ecc_monitor.lock().unwrap().init()?;

    // 创建同步屏障
    let start_barrier = Arc::new(Barrier::new(num_threads));
    let pattern_barrier = Arc::new(Barrier::new(num_threads));
    let report_barrier = Arc::new(Barrier::new(num_threads));

    // 创建线程句柄向量，用于管理所有工作线程
    let mut thread_handles = Vec::new();

    // 记录程序开始时间，用于计算运行时长
    let start_time = Instant::now();

    // 启动工作线程
    for &core_id in core_usage.iter() {
        // 克隆Arc智能指针，增加引用计数
        let global_counter_clone = Arc::clone(&global_loop_counter);
        let global_failure_flag_clone = Arc::clone(&global_failure_flag);
        let start_barrier_clone = Arc::clone(&start_barrier);
        let pattern_barrier_clone = Arc::clone(&pattern_barrier);
        let report_barrier_clone = Arc::clone(&report_barrier);
        let pattern_failure_counter_clone = Arc::clone(&pattern_failure_counter);
        let ecc_monitor_clone = Arc::clone(&ecc_monitor);

        // 使用thread::spawn创建新线程
        let handle = thread::spawn(move || {
            sync_worker_thread(
                core_id,  // CPU核心ID，用于线程绑定
                mem_size_per_thread,
                global_counter_clone,
                real_loops,  // 传递循环次数参数
                start_barrier_clone,
                pattern_barrier_clone,
                report_barrier_clone,
                pattern_failure_counter_clone,
                pattern.expect("Pattern must be provided"),
                ecc_monitor_clone,
                global_failure_flag_clone,
            )
        });

        thread_handles.push(handle);
    }

    // 主线程监控逻辑
    let time_limit_seconds = time_limit_minutes.map(|minutes| (minutes * 60.0) as u64);

    if let Some(limit_seconds) = time_limit_seconds {
        // 时间限制模式：等待时间到达
        let limit_duration = Duration::from_secs(limit_seconds);
        let limit_minutes = time_limit_minutes.unwrap(); // 安全：已知存在

        loop {
            thread::sleep(Duration::from_millis(100)); // 避免忙等待
            let elapsed = start_time.elapsed();

            if elapsed >= limit_duration {
                logger::log_info(&format!("Time limit of {} minutes ({} seconds) reached", limit_minutes, limit_seconds));
                if let Ok(mut monitor) = ecc_monitor.lock() {
                    if let Err(e) = monitor.check_ecc_errors() {
                        logger::log_error(&format!("ECC check failed: {}", e));
                    }
                } else {
                    logger::log_error("Could not acquire lock on EccMonitor for pattern check.");
                }
                break;
            }
        }
    } else {
        // 等待所有线程结束
        for handle in thread_handles {
            let _ = handle.join().unwrap();
        }
    }

    // 打印总体结果
    if global_failure_flag.load(Ordering::Relaxed) {
        logger::log_error("Overall result: FAILED");
    } else {
        logger::log_info("Overall result: ok");
    }

    Ok(())
}


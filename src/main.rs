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
use std::sync::{Arc, atomic::{AtomicU64, AtomicUsize, AtomicBool, Ordering}, Mutex, Condvar};

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

// 新增：可中止的屏障与等待结果枚举，保障在触发停止信号时唤醒所有等待线程，减少退出延迟
use std::sync::{Condvar as _CondvarAlias, Mutex as _MutexAlias};
#[derive(Debug)]
struct AbortableBarrier {
    inner: _MutexAlias<BarrierInner>,
    cvar: _CondvarAlias,
}

#[derive(Debug)]
struct BarrierInner {
    parties: usize,
    count: usize,
    generation: u64,
    aborted: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WaitResult { Leader, Member, Aborted }

impl AbortableBarrier {
    fn new(parties: usize) -> Self {
        Self {
            inner: _MutexAlias::new(BarrierInner { parties, count: 0, generation: 0, aborted: false }),
            cvar: _CondvarAlias::new(),
        }
    }

    fn wait(&self, stop: &AtomicBool) -> WaitResult {
        let mut inner = self.inner.lock().unwrap();
        if inner.aborted || stop.load(Ordering::Relaxed) {
            inner.aborted = true;
            self.cvar.notify_all();
            return WaitResult::Aborted;
        }
        let local_gen = inner.generation;
        inner.count += 1;
        if inner.count == inner.parties {
            inner.count = 0;
            inner.generation = inner.generation.wrapping_add(1);
            self.cvar.notify_all();
            return WaitResult::Leader;
        }
        loop {
            let guard = self.cvar.wait(inner).unwrap();
            inner = guard;
            if inner.aborted || stop.load(Ordering::Relaxed) {
                inner.aborted = true;
                self.cvar.notify_all();
                return WaitResult::Aborted;
            }
            if inner.generation != local_gen {
                return WaitResult::Member;
            }
        }
    }

    fn abort(&self) {
        let mut inner = self.inner.lock().unwrap();
        if !inner.aborted {
            inner.aborted = true;
            self.cvar.notify_all();
        }
    }
}

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
    thread_index: usize,                 // 线程索引
    mem_size_per_thread: usize,          // 【C等价】size_t mem_size_per_thread
    global_loop_counter: Arc<AtomicU64>, // 【C等价】atomic_uint64_t* global_counter
    target_loops: usize,                 // 【C等价】uint64_t* target_loops (可为NULL)
    start_barrier: Arc<AbortableBarrier>,
    pattern_barrier: Arc<AbortableBarrier>,
    report_barrier: Arc<AbortableBarrier>,
    pattern_failure_counter: Arc<AtomicUsize>,
    pattern: usize,
    ecc_monitor: Arc<Mutex<ecc::EccMonitor>>,
    stop_signal: Arc<AtomicBool>,        // 优雅停止信号
    per_thread_loops: Arc<Vec<AtomicU64>>, // 每线程循环计数
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
    match start_barrier.wait(&*stop_signal) {
        WaitResult::Aborted => {
            log_info_fmt!("Thread {} aborted at start barrier", core_id);
            return Ok(0);
        }
        WaitResult::Leader => {
            pattern_failure_counter.store(0, Ordering::Relaxed);
            if let Ok(mut monitor) = ecc_monitor.lock() {
                if let Err(e) = monitor.check_ecc_errors() {
                    logger::log_warn(&format!("Initial ECC check failed: {}", e));
                }
            } else {
                logger::log_error("Could not acquire lock on EccMonitor for initial check.");
            }
        }
        WaitResult::Member => {}
    }
    
    let u64_slice = memory_block.as_mut_slice_u64();
    let mut local_loops = 0u64;

    // 主测试循环
    loop {
        // 检查停止信号（更频繁，降低延迟）
        if stop_signal.load(Ordering::Relaxed) { 
            log_debug_fmt!("Thread {} (core {}) received stop signal, exiting gracefully", thread_index, core_id);
            break; 
        }

        if target_loops > 0 && local_loops >= target_loops as u64 { break; }

        // --- 同步点 1: 报告/准备 stuck address ---
        let report_res = report_barrier.wait(&*stop_signal);
        if matches!(report_res, WaitResult::Aborted) { return Ok(local_loops); }
        if matches!(report_res, WaitResult::Leader) {
             log_info_fmt!("Starting memory test loop {} ", local_loops + 1);
         }

        let stopped_now = stop_signal.load(Ordering::Relaxed);
        if !stopped_now {
            if let Err(e) = tests::test_stuck_address(u64_slice) {
                // 如果测试失败，打印错误并增加失败计数
                logger::log_error(&e.to_string());
                pattern_failure_counter.fetch_add(1, Ordering::Relaxed);
            }
        }

        // --- 同步点 2: 领头线程汇总 stuck address 结果（或打印跳过） ---
        match pattern_barrier.wait(&*stop_signal) {
            WaitResult::Aborted => { return Ok(local_loops); }
            WaitResult::Leader => {
                if stop_signal.load(Ordering::Relaxed) {
                    log_info_fmt!("   {:20}: {}", String::from("Stuck Address"), "skipped");
                } else {
                    let result = if pattern_failure_counter.load(Ordering::Relaxed) > 0 { 
                        pattern_failure_counter.store(0, Ordering::Relaxed);
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
            }
            WaitResult::Member => {}
        }

        // 遍历并执行所有被选中的测试
        for test in tests::TESTS.iter() {
            if (pattern as u64 & test.mask) != 0 {
                // --- 同步点 1: 报告/准备当前测试 ---
                match report_barrier.wait(&*stop_signal) {
                    WaitResult::Aborted => { return Ok(local_loops); }
                    _ => {}
                }

                let stopped_now = stop_signal.load(Ordering::Relaxed);
                if !stopped_now {
                    // --- 执行测试 ---
                    if let Err(e) = tests::run_test(test, u64_slice) {
                        // 如果测试失败，打印错误并增加失败计数
                        logger::log_error(&e.to_string());
                        pattern_failure_counter.fetch_add(1, Ordering::Relaxed);
                    }
                }

                // --- 同步点 2: 领头线程报告最终结果或打印跳过 ---
                match pattern_barrier.wait(&*stop_signal) {
                    WaitResult::Aborted => { return Ok(local_loops); }
                    WaitResult::Leader => {
                        if stop_signal.load(Ordering::Relaxed) {
                            log_info_fmt!("   {:20}: {}", test.name, "skipped");
                        } else {
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
                    WaitResult::Member => {}
                }
            }
        }

        local_loops += 1;
        global_loop_counter.fetch_add(1, Ordering::Relaxed);
        // 更新本线程的循环计数快照
        per_thread_loops[thread_index].store(local_loops, Ordering::Relaxed);
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
    let pattern_failure_counter = Arc::new(AtomicUsize::new(0));
    let stop_signal = Arc::new(AtomicBool::new(false));  // 优雅停止信号
    // 每线程循环计数器
    let per_thread_loops: Arc<Vec<AtomicU64>> = Arc::new((0..num_threads).map(|_| AtomicU64::new(0)).collect());

    // 将停止信号注入 tests 模块，使各测试能在内层循环即时退出
    tests::set_stop_signal(Arc::clone(&stop_signal));
    // 停止信号在worker循环与可中止屏障中被响应；为保持最小开销，此处仍保持tests内部检查以实现内层快速退出

    ecc_monitor.lock().unwrap().init()?;

    // 创建可中止的同步屏障
    let start_barrier = Arc::new(AbortableBarrier::new(num_threads));
    let pattern_barrier = Arc::new(AbortableBarrier::new(num_threads));
    let report_barrier = Arc::new(AbortableBarrier::new(num_threads));

    // 创建线程句柄向量，用于管理所有工作线程
    let mut thread_handles = Vec::new();

    // 记录程序开始时间，用于计算运行时长
    let start_time = Instant::now();

    // 启动工作线程
    for (thread_index, &core_id) in core_usage.iter().enumerate() {
        // 克隆Arc智能指针，增加引用计数
        let global_counter_clone = Arc::clone(&global_loop_counter);
        let start_barrier_clone = Arc::clone(&start_barrier);
        let pattern_barrier_clone = Arc::clone(&pattern_barrier);
        let report_barrier_clone = Arc::clone(&report_barrier);
        let pattern_failure_counter_clone = Arc::clone(&pattern_failure_counter);
        let ecc_monitor_clone = Arc::clone(&ecc_monitor);
        let stop_signal_clone = Arc::clone(&stop_signal);
        let per_thread_loops_clone = Arc::clone(&per_thread_loops);

        // 使用thread::spawn创建新线程
        let handle = thread::spawn(move || {
            sync_worker_thread(
                core_id,  // CPU核心ID，用于线程绑定
                thread_index,
                mem_size_per_thread,
                global_counter_clone,
                real_loops,  // 传递循环次数参数
                start_barrier_clone,
                pattern_barrier_clone,
                report_barrier_clone,
                pattern_failure_counter_clone,
                pattern.unwrap_or(0),
                ecc_monitor_clone,
                stop_signal_clone,
                per_thread_loops_clone,
            )
        });

        thread_handles.push(handle);
    }

    // 主线程监控逻辑
    let time_limit_seconds = time_limit_minutes.map(|minutes| (minutes * 60.0) as u64);

    if let Some(limit_seconds) = time_limit_seconds {
        // 时间限制模式：使用条件变量实现精确定时
        let limit_duration = Duration::from_secs(limit_seconds);
        let limit_minutes = time_limit_minutes.unwrap(); // 安全：已知存在

        // 创建条件变量用于精确定时
        let timeout_pair = Arc::new((Mutex::new(false), Condvar::new()));
        let (lock, cvar) = &*timeout_pair;
        
        // 使用条件变量等待，实现零CPU消耗的精确定时
        let timeout_reached = lock.lock().unwrap();
        let (_, wait_result) = cvar.wait_timeout(timeout_reached, limit_duration).unwrap();
        
        if wait_result.timed_out() {
            let actual_elapsed = start_time.elapsed();
            logger::log_info(&format!("Time limit of {} minutes ({} seconds) reached precisely at {:.3}s", 
                             limit_minutes, limit_seconds, actual_elapsed.as_secs_f64()));
            
            // 立刻输出所有线程的状态快照
            logger::log_info("Thread status snapshot at time limit:");
            for (i, &cid) in core_usage.iter().enumerate() {
                let loops = per_thread_loops[i].load(Ordering::Relaxed);
                log_info_fmt!("   Thread {} (core {}): loops={}", i, cid, loops);
            }
            logger::log_info("Sending stop signal to all worker threads...");
            
            // 设置停止信号并中止所有barrier，确保处于等待的线程立即返回
            stop_signal.store(true, Ordering::Relaxed);
            start_barrier.abort();
            report_barrier.abort();
            pattern_barrier.abort();
        }
        
        // 等待所有线程优雅退出
        logger::log_info("Waiting for all worker threads to finish gracefully...");
        let mut completed_threads = 0;
        for handle in thread_handles {
            match handle.join() {
                Ok(_) => {
                    completed_threads += 1;
                    logger::log_debug(&format!("Worker thread {} completed gracefully", completed_threads));
                },
                Err(e) => {
                    logger::log_error(&format!("Worker thread failed to join: {:?}", e));
                }
            }
        }
        
        logger::log_success(&format!("All {} worker threads completed. Resource cleanup finished.", completed_threads));
        
        // 最终统计信息
        let total_loops = global_loop_counter.load(Ordering::Relaxed);
        let actual_runtime = start_time.elapsed();
        logger::log_info(&format!("Final statistics: {} total loops completed in {:.2} seconds", 
                                 total_loops, actual_runtime.as_secs_f64()));
        
        // 最终ECC检查
        if let Ok(mut monitor) = ecc_monitor.lock() {
            if let Err(e) = monitor.check_ecc_errors() {
                logger::log_error(&format!("Final ECC check failed: {}", e));
            } else {
                logger::log_info("Final ECC check completed successfully");
            }
        }
        
    } else {
        // 循环计数模式：等待所有线程结束
        for handle in thread_handles {
            let _ = handle.join().unwrap();
        }
    }

    Ok(())
}


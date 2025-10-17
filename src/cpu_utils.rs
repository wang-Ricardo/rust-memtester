use crate::logger;
use core_affinity;
use num_cpus;

pub fn calculate_core_usage(requested_cores: Option<usize>) -> Vec<usize> {
    let total_cores = num_cpus::get();
    let available_cores = match requested_cores {
        Some(cores) => cores.min(total_cores), // 不能超过总核心数
        None => total_cores, // 默认使用所有核心
    };

    logger::log_info(&format!("Total cores: {}", total_cores));
    logger::log_info(&format!("Available cores: {}", available_cores));

    if available_cores >= total_cores {
        // 使用所有核心
        (0..total_cores).collect()
    } else {
        // 需要保留一些核心
        let cores_to_reserve = total_cores - available_cores;

        if cores_to_reserve == 0 {
            // 使用所有核心
            (0..total_cores).collect()
        } else {
            // 保留核心规则：保留最前和最后的核心
            // 保留数量一分为二，如果不是偶数，多保留前边的
            let front_reserve = (cores_to_reserve + 1) / 2; // 向上取整
            let back_reserve = cores_to_reserve / 2;        // 向下取整

            // 计算要使用的核心范围
            let start_core = front_reserve;
            let end_core = total_cores - back_reserve;

            logger::log_info("Core allocation strategy:");
            logger::log_info(&format!("  Total cores: {}", total_cores));
            logger::log_info(&format!("  Requested cores: {}", available_cores));
            logger::log_info(&format!("  Reserved cores: {} (front: {}, back: {})", cores_to_reserve, front_reserve, back_reserve));
            logger::log_info(&format!("  Using cores: {} to {} (inclusive)", start_core, end_core - 1));

            (start_core..end_core).collect()
        }
    }
}

// ================================================================================================
// Thread Affinity
// ================================================================================================

/// Binds the current thread to a specific logical core.
///
/// # Arguments
/// * `core_id`: The logical core ID to bind to.
///
/// # Returns
/// `true` on success, `false` on failure.
#[allow(dead_code)]
pub fn bind_thread_to_core(core_id: usize) -> bool {
    if let Some(core_ids) = core_affinity::get_core_ids() {
        if let Some(core) = core_ids.into_iter().find(|c| c.id == core_id) {
            return core_affinity::set_for_current(core);
        }
    }
    false
}
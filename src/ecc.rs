// ECC错误监控模块
// 提供内存错误检测和监控功能

use std::fs;
use std::path::{Path, PathBuf};
use std::collections::HashMap;
use regex::Regex;
use lazy_static::lazy_static;
use crate::logger;

// 预编译正则表达式以提高性能
lazy_static! {
    static ref CPU_DIMM_REGEX: Regex = Regex::new(r"CPU(\d+)_DIMM_([A-Z])(\d+)").unwrap();
    static ref SOCKET_CHANNEL_REGEX: Regex = Regex::new(r"Socket(\d+)_Channel(\d+)_DIMM(\d+)").unwrap();
    static ref MC_CHAN_REGEX: Regex = Regex::new(r"MC(\d+)_CHAN(\d+)_DIMM(\d+)").unwrap();
    static ref P_DIMM_REGEX: Regex = Regex::new(r"P(\d+)-DIMM-([A-Z])(\d+)").unwrap();
    static ref SOCKET_MC_CHANNEL_DIMM_REGEX: Regex = Regex::new(r"CPU_SrcID#(\d+)_MC#(\d+)_Chan#(\d+)_DIMM#(\d+)").unwrap();
}
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DimmLocation {
    pub socket: i32,
    pub channel: i32,
    pub dimm: i32,
}

impl std::fmt::Display for DimmLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Socket{}/Channel{}/DIMM{}", self.socket, self.channel, self.dimm)
    }
}

// DIMM映射信息
#[derive(Debug, Clone)]
pub struct DimmMapping {
    pub location: DimmLocation,
    pub ce_path: PathBuf,
    pub ue_path: PathBuf,
    pub ce_count: u64,
    pub ue_count: u64,
}

// ECC监控器
#[allow(dead_code)]
pub struct EccMonitor {
    enabled: bool,
    dimm_mappings: HashMap<DimmLocation, DimmMapping>,
}

#[allow(dead_code)]
impl EccMonitor {
    pub fn new() -> Self {
        Self {
            enabled: Path::new("/sys/devices/system/edac/mc").exists(),
            dimm_mappings: HashMap::new(),
        }
    }

    // 初始化函数 - 解析dimm_label获取socket、channel、dimm编号并建立映射关系
    pub fn init(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if !self.enabled {
            logger::log_warn("EDAC subsystem not available, ECC monitoring disabled");
            return Ok(());
        }

        logger::log_debug("Initializing ECC monitoring - parsing DIMM labels...");
        
        let edac_base = Path::new("/sys/devices/system/edac/mc");
        
        // 遍历所有内存控制器
        for mc_entry in fs::read_dir(edac_base)? {
            let mc_entry = mc_entry?;
            if let Some(mc_name) = mc_entry.file_name().to_str() {
                if mc_name.starts_with("mc") {
                    self.scan_memory_controller(&mc_entry.path())?;
                }
            }
        }

        Ok(())
    }

    fn scan_memory_controller(&mut self, mc_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
        // 遍历DIMM目录
        for dimm_entry in fs::read_dir(mc_path)? {
            let dimm_entry = dimm_entry?;
            if let Some(dimm_name) = dimm_entry.file_name().to_str() {
                if dimm_name.starts_with("dimm") {
                    if let Err(e) = self.parse_dimm_info(&dimm_entry.path()) {
                        logger::log_warn(&format!(
                            "Failed to parse DIMM info for {}: {}", 
                            dimm_entry.path().display(), e
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    // 解析DIMM信息
    fn parse_dimm_info(&mut self, dimm_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
        let label_file = dimm_path.join("dimm_label");
        let ce_file = dimm_path.join("dimm_ce_count");
        let ue_file = dimm_path.join("dimm_ue_count");

        // 检查必要文件是否存在
        if !label_file.exists() || !ce_file.exists() || !ue_file.exists() {
            return Ok(()); // 跳过不完整的DIMM
        }

        // 读取DIMM标签
        let label = fs::read_to_string(&label_file)?.trim().to_string();
        
        // 解析标签获取socket、channel、dimm编号
        if let Some(location) = self.parse_dimm_label(&label) {
            // 读取初始错误计数
            let ce_count = self.read_count_file(&ce_file)?;
            let ue_count = self.read_count_file(&ue_file)?;

            // 创建映射
            let mapping = DimmMapping {
                location: location.clone(),
                ce_path: ce_file,
                ue_path: ue_file,
                ce_count,
                ue_count,
            };

            logger::log_debug(&format!(
                "Mapped DIMM: {} -> Label='{}', CE={}, UE={}",
                location, label, ce_count, ue_count
            ));

            self.dimm_mappings.insert(location, mapping);
        } else {
            logger::log_warn(&format!(
                "Failed to parse DIMM label: '{}' at path: {}",
                label, dimm_path.display()
            ));
        }

        Ok(())
    }

    // 解析DIMM标签获取socket、channel、dimm编号
    fn parse_dimm_label(&self, label: &str) -> Option<DimmLocation> {
        // 常见的DIMM标签格式示例：
        // "CPU0_DIMM_A1", "CPU1_DIMM_B2", "Socket0_Channel1_DIMM0"
        // "P0-DIMM-A1", "P1-DIMM-B2"
        // "MC0_CHAN0_DIMM0", "MC1_CHAN1_DIMM1"
        
        logger::log_debug(&format!("Parsing DIMM label: '{}'", label));

        // 尝试不同的解析模式
        if let Some(location) = self.parse_cpu_dimm_format(label) {
            return Some(location);
        }
        
        if let Some(location) = self.parse_socket_channel_format(label) {
            return Some(location);
        }
        
        if let Some(location) = self.parse_mc_chan_format(label) {
            return Some(location);
        }

        if let Some(location) = self.parse_p_dimm_format(label) {
            return Some(location);
        }

        if let Some(location) = self.parse_s_m_c_dimm_format(label) {
            return Some(location);
        }

        logger::log_warn(&format!("Unknown DIMM label format: '{}'", label));
        None
    }

    // 解析CPU_DIMM_XX格式 (如: CPU0_DIMM_A1, CPU1_DIMM_B2)
    fn parse_cpu_dimm_format(&self, label: &str) -> Option<DimmLocation> {
        if let Some(caps) = CPU_DIMM_REGEX.captures(label) {
            let socket = caps[1].parse().ok()?;
            let channel = self.channel_letter_to_number(&caps[2])?;
            let dimm = caps[3].parse().ok()?;
            
            return Some(DimmLocation { socket, channel, dimm });
        }
        None
    }

    // 解析Socket_Channel_DIMM格式
    fn parse_socket_channel_format(&self, label: &str) -> Option<DimmLocation> {
        if let Some(caps) = SOCKET_CHANNEL_REGEX.captures(label) {
            let socket = caps[1].parse().ok()?;
            let channel = caps[2].parse().ok()?;
            let dimm = caps[3].parse().ok()?;
            
            return Some(DimmLocation { socket, channel, dimm });
        }
        None
    }

    // 解析MC_CHAN格式 (如: MC0_CHAN0_DIMM0)
    fn parse_mc_chan_format(&self, label: &str) -> Option<DimmLocation> {
        if let Some(caps) = MC_CHAN_REGEX.captures(label) {
            let socket = caps[1].parse().ok()?; // MC编号作为socket
            let channel = caps[2].parse().ok()?;
            let dimm = caps[3].parse().ok()?;
            
            return Some(DimmLocation { socket, channel, dimm });
        }
        None
    }

    // 解析P-DIMM格式 (如: P0-DIMM-A1)
    fn parse_p_dimm_format(&self, label: &str) -> Option<DimmLocation> {
        if let Some(caps) = P_DIMM_REGEX.captures(label) {
            let socket = caps[1].parse().ok()?;
            let channel = self.channel_letter_to_number(&caps[2])?;
            let dimm = caps[3].parse().ok()?;
            
            return Some(DimmLocation { socket, channel, dimm });
        }
        None
    }
    
    // 解析P-DIMM格式 (如: CPU_SrcID#1_MC#0_Chan#0_DIMM#0)
    fn parse_s_m_c_dimm_format(&self, label: &str) -> Option<DimmLocation> {
        if let Some(caps) = SOCKET_MC_CHANNEL_DIMM_REGEX.captures(label) {
            let socket = caps[1].parse().ok()?;
            // let _memoey_controller = caps[2].parse().ok()?;
            let channel = caps[3].parse().ok()?;
            let dimm = caps[4].parse().ok()?;
            
            return Some(DimmLocation { socket, channel, dimm });
        }
        None
    }

    // 将通道字母转换为数字 (A=0, B=1, C=2, D=3...)
    fn channel_letter_to_number(&self, letter: &str) -> Option<i32> {
        letter.chars().next()
            .and_then(|c| {
                if c.is_ascii_uppercase() && c >= 'A' && c <= 'Z' {
                    Some((c as u8 - b'A') as i32)
                } else {
                    None
                }
            })
    }

    // 读取计数文件
    fn read_count_file(&self, path: &Path) -> Result<u64, Box<dyn std::error::Error>> {
        Self::read_count_file_static(path)
    }

    fn read_count_file_static(path: &Path) -> Result<u64, Box<dyn std::error::Error>> {
        let content = fs::read_to_string(path)?;
        let count = content.trim().parse::<u64>()?;
        Ok(count)
    }

    // 检查ECC错误 - 读取文件并比较计数值
    pub fn check_ecc_errors(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if !self.enabled {
            return Ok(());
        }

        // 收集需要更新的信息，避免借用冲突
        let mut updates = Vec::new();
        
        for (location, mapping) in &self.dimm_mappings {
            // 检查CE错误
            if let Ok(new_ce_count) = Self::read_count_file_static(&mapping.ce_path) {
                if new_ce_count > mapping.ce_count {
                    updates.push((location.clone(), "ce".to_string(), new_ce_count));
                }
            }

            // 检查UE错误
            if let Ok(new_ue_count) = Self::read_count_file_static(&mapping.ue_path) {
                if new_ue_count > mapping.ue_count {
                    updates.push((location.clone(), "ue".to_string(), new_ue_count));
                }
            }
        }

        // 应用更新并记录日志
        for (location, error_type, new_count) in updates {
            if let Some(mapping) = self.dimm_mappings.get_mut(&location) {
                if error_type == "ce" {
                    let increment = new_count - mapping.ce_count;
                    logger::log_warn(&format!(
                        "ECC CE Error: Socket={}, Channel={}, DIMM={}, Count: {} -> {} (+{}), Path: {}",
                        location.socket, location.channel, location.dimm,
                        mapping.ce_count, new_count, increment,
                        mapping.ce_path.display()
                    ));
                    mapping.ce_count = new_count;
                } else if error_type == "ue" {
                    let increment = new_count - mapping.ue_count;
                    logger::log_error(&format!(
                        "CRITICAL ECC UE Error: Socket={}, Channel={}, DIMM={}, Count: {} -> {} (+{}), Path: {}",
                        location.socket, location.channel, location.dimm,
                        mapping.ue_count, new_count, increment,
                        mapping.ue_path.display()
                    ));
                    mapping.ue_count = new_count;
                }
            }
        }

        Ok(())
    }

}
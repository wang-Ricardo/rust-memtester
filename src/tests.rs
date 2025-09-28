use crate::logger;
use rand::Rng;

// 定义一个错误类型
#[derive(Debug)]
pub struct TestError(String);

impl std::fmt::Display for TestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TestError: {}", self.0)
    }
}

impl std::error::Error for TestError {}

#[cfg(target_pointer_width = "32")]
mod constants {
    pub const TEST_UL_ONEBITS: u32 = u32::MAX;
    pub const TEST_UL_LEN: usize = 32;
    pub const TEST_CHECKERBOARD1: u32 = 0x55555555;
    pub const TEST_CHECKERBOARD2: u32 = 0xAAAAAAAA;
    pub const TEST_MARCH_ONE: u32 = u32::MAX;
    pub const TEST_MARCH_ZERO: u32 = 0x00000000;
    pub const TEST_ONE: u32 = 0x00000001;
    #[allow(dead_code)]
    pub const ONE_1_PER_BYTE: u32 = 0x01010101;
    #[allow(dead_code)]
    pub const TWO_1_PER_BYTE: u32 = 0x03030303;
    #[allow(dead_code)]
    pub const TEST_DONE: u32 = 0x00000001;
}

#[cfg(target_pointer_width = "64")]
mod constants {
    #[allow(dead_code)]
    pub const TEST_UL_ONEBITS: u64 = u64::MAX;
    pub const TEST_UL_LEN: usize = 64;
    pub const TEST_CHECKERBOARD1: u64 = 0x5555555555555555;
    pub const TEST_CHECKERBOARD2: u64 = 0xAAAAAAAAAAAAAAAA;
    #[allow(dead_code)]
    pub const TEST_MARCH_ONE: u64 = u64::MAX;
    #[allow(dead_code)]
    pub const TEST_MARCH_ZERO: u64 = 0x0000000000000000;
    pub const TEST_ONE: u64 = 0x0000000000000001;
    #[allow(dead_code)]
    pub const ONE_1_PER_BYTE: u64 = 0x0101010101010101;
    #[allow(dead_code)]
    pub const TWO_1_PER_BYTE: u64 = 0x0303030303030303;
    #[allow(dead_code)]
    pub const TEST_DONE: u64 = 0x0000000000000001;
}
use self::constants::*;

#[derive(Debug)]
#[warn(dead_code)]
pub enum TestType {
    // StuckAddress,
    RandomValue,
    XorComparison,
    SubComparison,
    MulComparison,
    DivComparison,
    OrComparison,
    AndComparison,
    SeqIncComparison,
    SolidBitsComparison,
    BlockSeqComparison,
    CheckerboardComparison,
    BitSpreadComparison,
    BitFlipComparison,
    Walkbits1Comparison,
    Walkbits0Comparison,
    Bit8WideRandom,
    Bit16WideRandom,
}

// 2. Test 结构体存储 enum 变体
#[warn(unused_imports)]
pub struct Test {
    pub name: &'static str,
    pub test_type: TestType,
    pub mask: u64,
}

// 定义测试掩码常量
// pub const MASK_STUCK_ADDRESS: u64 = 1 << 0;
pub const MASK_RANDOM_VALUE: u64 = 1 << 0;
pub const MASK_XOR_COMPARISON: u64 = 1 << 1;
pub const MASK_SUB_COMPARISON: u64 = 1 << 2;
pub const MASK_MUL_COMPARISON: u64 = 1 << 3;
pub const MASK_DIV_COMPARISON: u64 = 1 << 4;
pub const MASK_OR_COMPARISON: u64 = 1 << 5;
pub const MASK_AND_COMPARISON: u64 = 1 << 6;
pub const MASK_SEQINC_COMPARISON: u64 = 1 << 7;
pub const MASK_SOLIDBITS_COMPARISON: u64 = 1 << 8;
pub const MASK_BLOCKSEQ_COMPARISON: u64 = 1 << 9;
pub const MASK_CHECKERBOARD_COMPARISON: u64 = 1 << 10;
pub const MASK_BITSPREAD_COMPARISON: u64 = 1 << 11;
pub const MASK_BITFLIP_COMPARISON: u64 = 1 << 12;
pub const MASK_WALKBITS1_COMPARISON: u64 = 1 << 13;
pub const MASK_WALKBITS0_COMPARISON: u64 = 1 << 14;
pub const MASK_8BIT_WIDE_RANDOM: u64 = 1 << 15;
pub const MASK_16BIT_WIDE_RANDOM: u64 = 1 << 16;
// pub const TEST_MARCH: u64 = 1 << 17;
// pub const TEST_BUTTERFLY: u64 = 1 << 18;
// pub const TEST_GALPAT_ZERO: u64 = 1 << 19;
// pub const TEST_GALPAT_ONE: u64 = 1 << 20;
// pub const TEST_MSCAN: u64 = 1 << 21;
// pub const TEST_ROWHAMMER: u64 = 1 << 22;

pub static TESTS: &[Test] = &[
    // Test { name: "Stuck Address", test_type: TestType::StuckAddress, mask: MASK_STUCK_ADDRESS },
    Test { name: "Random Value", test_type: TestType::RandomValue, mask: MASK_RANDOM_VALUE },
    Test { name: "Compare XOR", test_type: TestType::XorComparison, mask: MASK_XOR_COMPARISON },
    Test { name: "Compare SUB", test_type: TestType::SubComparison, mask: MASK_SUB_COMPARISON },
    Test { name: "Compare MUL", test_type: TestType::MulComparison, mask: MASK_MUL_COMPARISON },
    Test { name: "Compare DIV", test_type: TestType::DivComparison, mask: MASK_DIV_COMPARISON },
    Test { name: "Compare OR", test_type: TestType::OrComparison, mask: MASK_OR_COMPARISON },
    Test { name: "Compare AND", test_type: TestType::AndComparison, mask: MASK_AND_COMPARISON },
    Test { name: "Compare SEQINC", test_type: TestType::SeqIncComparison, mask: MASK_SEQINC_COMPARISON },
    Test { name: "Solid Bits", test_type: TestType::SolidBitsComparison, mask: MASK_SOLIDBITS_COMPARISON },
    Test { name: "Block Sequential", test_type: TestType::BlockSeqComparison, mask: MASK_BLOCKSEQ_COMPARISON  },
    Test { name: "Checkerboard", test_type: TestType::CheckerboardComparison, mask: MASK_CHECKERBOARD_COMPARISON },
    Test { name: "Bit Spread", test_type: TestType::BitSpreadComparison, mask: MASK_BITSPREAD_COMPARISON },
    Test { name: "Bit Flip", test_type: TestType::BitFlipComparison, mask: MASK_BITFLIP_COMPARISON },
    Test { name: "Walking Ones", test_type: TestType::Walkbits1Comparison, mask: MASK_WALKBITS1_COMPARISON },
    Test { name: "Walking Zeros", test_type: TestType::Walkbits0Comparison, mask: MASK_WALKBITS0_COMPARISON },
    Test { name: "8-bit Wide", test_type: TestType::Bit8WideRandom, mask: MASK_8BIT_WIDE_RANDOM },
    Test { name: "16-bit Wide", test_type: TestType::Bit16WideRandom, mask: MASK_16BIT_WIDE_RANDOM },
    // Test { name: "March Algorithm", test_type: TestType::XorComparison, mask: MASK_XOR_COMPARISON },
    // Test { name: "Butterfly Algorithm", test_type: TestType::XorComparison, mask: MASK_XOR_COMPARISON },

    // ...
];

pub fn print_test_mask_help(){
    println!("📋 Test Function Masks");
    println!("======================");
    println!();

    let mut mask :u64 = 1;
    for test in TESTS.iter() {
        println!("    {:20}|0x{:08X}", test.name, test.mask);
        mask |= test.mask;
    }
    println!("Use logical OR to combine patterns: 0x{:08X}", mask)
}

// 4. 统一、安全的测试执行入口
pub fn run_test(test: &Test, memory_block: &mut [u64]) -> Result<(), TestError> {
    match test.test_type {
        // 需要单个缓冲区的测试，直接调用
        // TestType::StuckAddress => test_stuck_address(memory_block),
        TestType::RandomValue => test_random_value(memory_block),
        TestType::XorComparison => test_xor_comparison(memory_block),
        TestType::SubComparison => test_sub_comparison(memory_block),
        TestType::MulComparison => test_mul_comparison(memory_block),
        TestType::DivComparison => test_div_comparison(memory_block),
        TestType::OrComparison => test_or_comparison(memory_block),
        TestType::AndComparison => test_and_comparison(memory_block),
        TestType::SeqIncComparison => test_seqinc_comparison(memory_block),
        TestType::SolidBitsComparison => test_solidbits_comparison(memory_block),
        TestType::BlockSeqComparison => test_blockseq_comparison(memory_block),
        TestType::CheckerboardComparison => test_checkerboard_comparison(memory_block),
        TestType::BitSpreadComparison => test_bitspread_comparison(memory_block),
        TestType::BitFlipComparison => test_bitflip_comparison(memory_block),
        TestType::Walkbits1Comparison => test_walkbits1_comparison(memory_block),
        TestType::Walkbits0Comparison => test_walkbits0_comparison(memory_block),
        TestType::Bit8WideRandom => test_8bit_wide_random(memory_block),
        TestType::Bit16WideRandom => test_16bit_wide_random(memory_block)
    }
}

// 只需要一个缓冲区，因为是测试地址而不是数据
pub fn test_stuck_address(buf: &mut [u64]) -> Result<(), TestError> {
    // 【C等价】for (int j = 0; j < 16; j++)
    // 进行16轮测试，使用不同的模式来检测地址线故障
    (0..16).try_for_each(|j| {
        // 写入阶段：使用函数式编程风格
        // 【C等价】for (size_t i = 0; i < len; i++) { uint64_t* p = &buf[i]; }
        buf.iter_mut().enumerate().try_for_each(|(i, p)| {
            // 条件表达式：根据位置奇偶性选择值或其按位取反
            // 【C等价】*p = ((j + i) % 2 == 0) ? val : ~val;
            let val = i as u64;
            *p = if (j + i) % 2 == 0 { val } else { !val };
            
            Ok(())
        })?;

        // 验证阶段：使用函数式编程风格进行验证
        // 【C等价】for (size_t i = 0; i < len; i++) { uint64_t p = buf[i]; }
        buf.iter().enumerate().try_for_each(|(i, &p)| {
            let val = i as u64;
            let expected = if (j + i) % 2 == 0 { val } else { !val };

            // 【C等价】if (buf[i] != expected) { printf("error"); return -1; }
            if p != expected {
                logger::log_error(&format!("FAILURE: possible bad address line at offset {:#x}", i * 8));
                return Err(TestError("Stuck address test failed".to_string()));
            }
            
            Ok(())
        })
    })
}

// Rust的优势：
// 1. 切片自动包含长度，防止越界访问
// 2. 类型安全的比较，不会出现类型混淆
// 3. Result类型强制错误处理
// 4. 迭代器链式调用，代码更简洁

// &[u64] 是u64切片的不可变引用，包含指针和长度信息
// 【C等价】const uint64_t* buf_a, size_t len_a, const uint64_t* buf_b, size_t len_b
// 但Rust的切片自动包含长度，更安全
fn compare_regions(buf_a: &[u64], buf_b: &[u64]) -> Result<(), TestError> {
    // 快速路径：使用切片直接比较，Rust会逐元素比较
    // 【C等价】if (memcmp(buf_a, buf_b, len * sizeof(uint64_t)) == 0)
    if buf_a == buf_b {
        return Ok(());
    }

    // 慢速路径：详细错误报告，使用函数式编程风格
    let errors = buf_a.iter()
        .zip(buf_b.iter())
        .enumerate()
        .try_fold(0usize, |mut error_count, (i, (a, b))| {
            if a != b {
                // 格式化字符串：{a:#018x} 表示16进制，18位宽，前缀0x
                // 【C等价】printf("FAILURE: 0x%016lx != 0x%016lx at offset 0x%lx\n", *a, *b, i * 8);
                logger::log_error(&format!("FAILURE: {a:#018x} != {b:#018x} at offset {:#x}", i * 8));
                error_count += 1;
            }
            
            Ok(error_count)
        })?;

    // 返回错误，包含错误计数
    // 【C等价】return errors;
    Err(TestError(format!("{} errors found", errors)))
}

pub fn test_random_value(memory_block: &mut [u64]) -> Result<(), TestError> {
    let len = memory_block.len();
    if len < 2 {
        return Err(TestError("Memory block too small for two-buffer test".to_string()));
    }

    let mid = len / 2;
    let (buf_a, buf_b) = memory_block.split_at_mut(mid);

    // 使用线程本地RNG，避免全局状态竞争
    // 【C对比】C的rand()不是线程安全的，需要额外同步
    let mut rng = rand::thread_rng();

    // 为两个缓冲区填充相同的随机值
    buf_a.iter_mut().zip(buf_b.iter_mut()).try_for_each(|(a, b)| {
        let value = rng.gen::<u64>();
        *a = value;
        *b = value;
        
        Ok(())
    })?;
    
    compare_regions(buf_a, buf_b)
}

// XOR比较测试：测试异或运算的一致性
pub fn test_xor_comparison(memory_block: &mut [u64]) -> Result<(), TestError> {
    let len = memory_block.len();
    if len < 2 {
        return Err(TestError("Memory block too small for two-buffer test".to_string()));
    }
    
    let mid = len / 2;
    let (buf_a, buf_b) = memory_block.split_at_mut(mid);

    let mut rng = rand::thread_rng();
    let q: u64 = rng.gen();

    // 对内存中现有值进行异或操作
    buf_a.iter_mut().zip(buf_b.iter_mut()).try_for_each(|(a, b)| {
        *a ^= q;
        *b ^= q;
        
        Ok(())
    })?;
    
    compare_regions(buf_a, buf_b)

}

// 减法比较测试：测试减法运算的一致性
pub fn test_sub_comparison(memory_block: &mut [u64]) -> Result<(), TestError> {
    let len = memory_block.len();
    if len < 2 {
        return Err(TestError("Memory block too small for two-buffer test".to_string()));
    }
    
    let mid = len / 2;
    let (buf_a, buf_b) = memory_block.split_at_mut(mid);

    let mut rng = rand::thread_rng();
    let q: u64 = rng.gen();

    buf_a.iter_mut().zip(buf_b.iter_mut()).try_for_each(|(a, b)| {
        // wrapping_sub：Rust的安全整数运算
        // 在溢出时进行环绕（wrapping），而不是panic
        // 相当于C语言的无符号整数减法行为
        // 这比直接使用 - 运算符更明确地表达意图
        *a = a.wrapping_sub(q);
        *b = b.wrapping_sub(q);

        Ok(())
    })?;

    compare_regions(buf_a, buf_b)
}

pub fn test_mul_comparison(memory_block: &mut [u64]) -> Result<(), TestError> {
    let len = memory_block.len();
    if len < 2 {
        return Err(TestError("Memory block too small for two-buffer test".to_string()));
    }
    
    let mid = len / 2;
    let (buf_a, buf_b) = memory_block.split_at_mut(mid);

    let mut rng = rand::thread_rng();
    let q: u64 = rng.gen();

    // 先初始化内存为随机值，然后进行除法操作
    buf_a.iter_mut().zip(buf_b.iter_mut()).try_for_each(|(a, b)| {
        // 对内存中现有值进行除法操作
        *a = a.wrapping_mul(q);
        *b = b.wrapping_mul(q);

        Ok(())
    })?;

    compare_regions(buf_a, buf_b)
}

// 除法比较测试：测试除法运算的一致性
pub fn test_div_comparison(memory_block: &mut [u64]) -> Result<(), TestError> {

    let len = memory_block.len();
    if len < 2 {
        return Err(TestError("Memory block too small for two-buffer test".to_string()));
    }
    
    let mid = len / 2;
    let (buf_a, buf_b) = memory_block.split_at_mut(mid);

    let mut rng = rand::thread_rng();
    let mut q: u64 = rng.gen();

    // 防止除零错误：Rust在debug模式下会panic，release模式下行为未定义
    // 这里手动检查并修正，确保安全
    if q == 0 {
        q = 1;
    }

    // 先初始化内存为随机值，然后进行除法操作
    buf_a.iter_mut().zip(buf_b.iter_mut()).try_for_each(|(a, b)| {
        // 对内存中现有值进行除法操作
        *a = a.wrapping_div(q);
        *b = b.wrapping_div(q);

        Ok(())
    })?;

    compare_regions(buf_a, buf_b)
}

pub fn test_or_comparison(memory_block: &mut [u64]) -> Result<(), TestError> {
    let len = memory_block.len();
    if len < 2 {
        return Err(TestError("Memory block too small for two-buffer test".to_string()));
    }
    
    let mid = len / 2;
    let (buf_a, buf_b) = memory_block.split_at_mut(mid);

    let mut rng = rand::thread_rng();
    let q: u64 = rng.gen();

    buf_a.iter_mut().zip(buf_b.iter_mut()).try_for_each(|(a, b)| {
        *a |= q;
        *b |= q;
        Ok(())
    })?;
    compare_regions(buf_a, buf_b)
}

pub fn test_and_comparison(memory_block: &mut [u64]) -> Result<(), TestError> {
    let len = memory_block.len();
    if len < 2 {
        return Err(TestError("Memory block too small for two-buffer test".to_string()));
    }
    
    let mid = len / 2;
    let (buf_a, buf_b) = memory_block.split_at_mut(mid);

    let mut rng = rand::thread_rng();
    let q: u64 = rng.gen();
    // 先用全1初始化内存，然后进行AND操作，与C源码逻辑一致
    buf_a.iter_mut().zip(buf_b.iter_mut()).try_for_each(|(a, b)| {
        *a &= q;
        *b &= q;
        Ok(())
    })?;
    compare_regions(buf_a, buf_b)
}

pub fn test_seqinc_comparison(memory_block: &mut [u64]) -> Result<(), TestError> {
    let len = memory_block.len();
    if len < 2 {
        return Err(TestError("Memory block too small for two-buffer test".to_string()));
    }
    
    let mid = len / 2;
    let (buf_a, buf_b) = memory_block.split_at_mut(mid);

    let mut rng = rand::thread_rng();
    let q: u64 = rng.gen();
    // 对每个位置写入 (i + q) 的值，与C源码逻辑完全一致
    buf_a.iter_mut().zip(buf_b.iter_mut()).enumerate().try_for_each(|(i, (a, b))| {
        let value = (i as u64).wrapping_add(q);
        *a = value;
        *b = value;
        Ok(())
    })?;
    
    compare_regions(buf_a, buf_b)
}

// 固定位测试：测试每个位位置的内存一致性
pub fn test_solidbits_comparison(memory_block: &mut [u64]) -> Result<(), TestError> {
    let len = memory_block.len();
    if len < 2 {
        return Err(TestError("Memory block too small for two-buffer test".to_string()));
    }
    
    let mid = len / 2;
    let (buf_a, buf_b) = memory_block.split_at_mut(mid);

    // 64轮测试，交替使用全1和全0模式
    (0..64).try_for_each(|j| {
        // 根据轮次选择基础模式：偶数轮用全1，奇数轮用全0
        let base_pattern = if (j % 2) == 0 { TEST_UL_ONEBITS } else { 0 };
        
        // 对每个位置，根据索引交替使用模式和反码
        buf_a.iter_mut().zip(buf_b.iter_mut()).enumerate().try_for_each(|(i, (a, b))| {
            let pattern = if (i % 2) == 0 { base_pattern } else { !base_pattern };
            *a = pattern;
            *b = pattern;
            Ok(())
        })?;
        
        compare_regions(buf_a, buf_b)
    })
}

// 棋盘测试：交替使用两种模式，实现真正的棋盘效果
pub fn test_checkerboard_comparison(memory_block: &mut [u64]) -> Result<(), TestError> {
    let len = memory_block.len();
    if len < 2 {
        return Err(TestError("Memory block too small for two-buffer test".to_string()));
    }
    
    let mid = len / 2;
    let (buf_a, buf_b) = memory_block.split_at_mut(mid);

    // 进行64轮测试，每轮使用不同的棋盘模式
    (0..64).try_for_each(|j| {
        let base_pattern = if (j % 2) == 0 { TEST_CHECKERBOARD1 } else { TEST_CHECKERBOARD2 };
        
        // 使用函数式编程风格填充缓冲区
        buf_a.iter_mut().zip(buf_b.iter_mut()).enumerate().try_for_each(|(i, (a, b))| {
            // 根据位置交替使用模式和其反码，实现真正的棋盘效果
            let pattern = if (i % 2) == 0 { base_pattern } else { !base_pattern };
            *a = pattern;
            *b = pattern;
            Ok(())
        })?;
        
        // 使用优化的比较函数
        compare_regions(buf_a, buf_b)
    })
}

pub fn test_blockseq_comparison(memory_block: &mut [u64]) -> Result<(), TestError> {
    let len = memory_block.len();
    if len < 2 {
        return Err(TestError("Memory block too small for two-buffer test".to_string()));
    }

    let mid = len / 2;
    let (buf_a, buf_b) = memory_block.split_at_mut(mid);

    for j in 0..256 {
        // Replicate the UL_BYTE(j) macro from C by repeating the byte across the u64
        let pattern = (j as u64).wrapping_mul(0x0101010101010101);
        for (a, b) in buf_a.iter_mut().zip(buf_b.iter_mut()) {
            *a = pattern;
            *b = pattern;
        }
        if let Err(e) = compare_regions(buf_a, buf_b) {
            return Err(e);
        }
    }
    Ok(())
}

pub fn test_walkbits0_comparison(memory_block: &mut [u64]) -> Result<(), TestError> {
    let len = memory_block.len();
    if len < 2 {
        return Err(TestError("Memory block too small for two-buffer test".to_string()));
    }
    
    let mid = len / 2;
    let (buf_a, buf_b) = memory_block.split_at_mut(mid);

    // 走动0测试：使用函数式编程生成双向扫描模式
    let pattern_generator = |ucount: usize| -> u64 {
        let bit_pos = if ucount < TEST_UL_LEN {
            ucount  // 向上走 (从低位到高位)
        } else {
            TEST_UL_LEN * 2 - ucount - 1  // 向下走 (从高位到低位)
        };
        TEST_ONE.wrapping_shl(bit_pos as u32)
    };

    (0..TEST_UL_LEN * 2)
        .try_for_each(|ucount| {
            let pattern = pattern_generator(ucount);
            
            // 使用迭代器链式操作填充缓冲区
            buf_a.iter_mut().zip(buf_b.iter_mut())
                .for_each(|(a, b)| {
                    *a = pattern;
                    *b = pattern;
                });

            compare_regions(buf_a, buf_b)
        })
}

pub fn test_walkbits1_comparison(memory_block: &mut [u64]) -> Result<(), TestError> {
    let len = memory_block.len();
    if len < 2 {
        return Err(TestError("Memory block too small for two-buffer test".to_string()));
    }
    
    let mid = len / 2;
    let (buf_a, buf_b) = memory_block.split_at_mut(mid);

    // 走动1测试：使用函数式编程生成双向扫描模式
    let pattern_generator = |ucount: usize| -> u64 {
        let bit_pos = if ucount < TEST_UL_LEN {
            ucount  // 向上走 (从低位到高位)
        } else {
            TEST_UL_LEN * 2 - ucount - 1  // 向下走 (从高位到低位)
        };
        TEST_UL_ONEBITS ^ TEST_ONE.wrapping_shl(bit_pos as u32)
    };

    (0..TEST_UL_LEN * 2)
        .try_for_each(|ucount| {
            let pattern = pattern_generator(ucount);
            
            // 使用迭代器链式操作填充缓冲区
            buf_a.iter_mut().zip(buf_b.iter_mut())
                .for_each(|(a, b)| {
                    *a = pattern;
                    *b = pattern;
                });

            compare_regions(buf_a, buf_b)
        })
}

pub fn test_bitspread_comparison(memory_block: &mut [u64]) -> Result<(), TestError> {
    let len = memory_block.len();
    if len < 2 {
        return Err(TestError("Memory block too small for two-buffer test".to_string()));
    }
    
    let mid = len / 2;
    let (buf_a, buf_b) = memory_block.split_at_mut(mid);

    // 位扩散测试：使用函数式编程简化模式生成
    let pattern_generator = |j: usize, i: usize| -> u64 {
        let (bit_pos1, bit_pos2) = if j < TEST_UL_LEN {
            // 向上走：测试位 j 和位 j+2 的组合
            (j, j + 2)
        } else {
            // 向下走：从高位向低位测试
            let pos = TEST_UL_LEN * 2 - 1 - j;
            (pos, pos.saturating_add(2))
        };
        
        let base_pattern = TEST_ONE.wrapping_shl(bit_pos1 as u32) | 
                          TEST_ONE.wrapping_shl(bit_pos2 as u32);
        
        if i % 2 == 0 {
            base_pattern  // 偶数索引：设置两个相邻位
        } else {
            TEST_UL_ONEBITS ^ base_pattern  // 奇数索引：反转模式，测试位干扰
        }
    };

    (0..TEST_UL_LEN * 2)
        .try_for_each(|j| {
            buf_a.iter_mut().zip(buf_b.iter_mut())
                .enumerate()
                .try_for_each(|(i, (a, b))| {
                    let pattern = pattern_generator(j, i);
                    *a = pattern;
                    *b = pattern;
                    Ok(())
                })?;
            
            compare_regions(buf_a, buf_b)
        })
}

pub fn test_bitflip_comparison(memory_block: &mut [u64]) -> Result<(), TestError> {
    let len = memory_block.len();
    if len < 2 {
        return Err(TestError("Memory block too small for two-buffer test".to_string()));
    }
    
    let mid = len / 2;
    let (buf_a, buf_b) = memory_block.split_at_mut(mid);

    // 位翻转测试：对每个位位置进行多轮测试
    for j in 0..TEST_UL_LEN {
        let mut p = TEST_ONE.wrapping_shl(j as u32);
        
        // 进行8轮测试以增强检测能力
        for _ in 0..8 {
            buf_a.iter_mut().zip(buf_b.iter_mut())
                .enumerate()
                .try_for_each(|(i, (a, b))| {
                    p = if i % 2 == 0 {
                        p
                    } else { !p };
                    *a = p;
                    *b = p;
                    Ok(())
                })?;

            // 验证第一阶段
            compare_regions(buf_a, buf_b)?;
        }
    }
    Ok(())
}

// 8位宽随机写入测试
// 使用8位宽度进行随机数据写入测试，检测窄数据路径的完整性
// 8位宽测试能发现数据总线宽度相关的问题和字节选通信号故障
pub fn test_8bit_wide_random(memory_block: &mut [u64]) -> Result<(), TestError> {
    let len = memory_block.len();
    if len < 2 {
        return Err(TestError("Memory block too small for two-buffer test".to_string()));
    }
    
    let mid = len / 2;
    let (buf_a, buf_b) = memory_block.split_at_mut(mid);

    let mut rng = rand::thread_rng();

    // 进行两次测试，交换缓冲区角色
    (0..2).try_for_each(|attempt| {
        
        // 使用函数式编程风格处理内存写入
        (0..buf_a.len()).try_for_each(|i| {
            let random_val: u64 = rng.gen();
            
            // 根据尝试次数选择缓冲区角色
            let (ref_buf, write_buf) = if attempt & 1 == 1 {
                (&mut buf_b[i], &mut buf_a[i])
            } else {
                (&mut buf_a[i], &mut buf_b[i])
            };
            
            // 设置参考值
            *ref_buf = random_val;
            
            // 按8位宽度写入数据
            let bytes = random_val.to_le_bytes();
            let write_ptr = write_buf as *mut u64 as *mut u8;
            
            unsafe {
                bytes.iter().enumerate().try_for_each(|(b, &byte_val)| {
                    *write_ptr.add(b) = byte_val;
                    Ok(())
                })
            }
        })?;
        
        // 使用优化的比较函数
        compare_regions(buf_a, buf_b)
    })
}

// 16位宽随机写入测试
// 使用16位宽度进行随机数据写入测试，检测半字数据路径的完整性
// 16位宽测试能发现字选通信号和半字对齐相关的问题
pub fn test_16bit_wide_random(memory_block: &mut [u64]) -> Result<(), TestError> {
    let len = memory_block.len();
    if len < 2 {
        return Err(TestError("Memory block too small for two-buffer test".to_string()));
    }
    
    let mid = len / 2;
    let (buf_a, buf_b) = memory_block.split_at_mut(mid);

    let mut rng = rand::thread_rng();

    // 进行两次测试，交换缓冲区角色
    (0..2).try_for_each(|attempt| {
        // 使用函数式编程风格处理内存写入
        (0..buf_a.len()).try_for_each(|i| {
            let random_val: u64 = rng.gen();
            
            // 根据尝试次数选择缓冲区角色
            let (ref_buf, write_buf) = if attempt & 1 == 1 {
                (&mut buf_b[i], &mut buf_a[i])
            } else {
                (&mut buf_a[i], &mut buf_b[i])
            };
            
            // 设置参考值
            *ref_buf = random_val;
            
            // 按16位宽度写入数据
            let words = [
                (random_val & 0xFFFF) as u16,
                ((random_val >> 16) & 0xFFFF) as u16,
                ((random_val >> 32) & 0xFFFF) as u16,
                ((random_val >> 48) & 0xFFFF) as u16,
            ];
            
            let write_ptr = write_buf as *mut u64 as *mut u16;
            
            unsafe {
                words.iter().enumerate().try_for_each(|(w, &word_val)| {
                    *write_ptr.add(w) = word_val;
                    Ok(())
                })
            }
        })?;
        
        // 使用优化的比较函数
        compare_regions(buf_a, buf_b)
    })
}


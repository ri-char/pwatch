pub const SAMPLE_REGS_USER: u64 = 0b1111_1111_0000_1111_1111_1111;

pub fn id_to_str(id: usize) -> &'static str {
    match id {
        0 => "ax",
        1 => "bx",
        2 => "cx",
        3 => "dx",
        4 => "si",
        5 => "di",
        6 => "bp",
        7 => "sp",
        8 => "ip",
        9 => "flags",
        10 => "cs",
        11 => "ss",
        12 => "r8",
        13 => "r9",
        14 => "r10",
        15 => "r11",
        16 => "r12",
        17 => "r13",
        18 => "r14",
        19 => "r15",
        _ => "unknown",
    }
}

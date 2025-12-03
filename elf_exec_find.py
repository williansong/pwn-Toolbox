import sys
from elftools.elf.elffile import ELFFile

# 直接定义EF_PIE的数值（避免依赖ELF_FLAGS常量）
EF_PIE = 0x00040000

def is_pie_enabled(elf_path):
    """判断ELF是否开启PIE（Position-Independent Executable）"""
    try:
        with open(elf_path, 'rb') as f:
            elf = ELFFile(f)
            # PIE的判断依据：e_type为ET_DYN，且e_flags包含EF_PIE（0x00040000）
            return (elf['e_type'] == 'ET_DYN') and (elf['e_flags'] & EF_PIE)
    except Exception as e:
        print(f"警告：解析PIE状态失败 - {e}")
        return False

def get_elf_base(elf_path):
    """获取ELF的固定基址（仅非PIE时有效）"""
    try:
        with open(elf_path, 'rb') as f:
            elf = ELFFile(f)
            # 非PIE可执行文件的基址 = 第一个PT_LOAD段的p_vaddr（虚拟地址）
            for segment in elf.iter_segments():
                if segment['p_type'] == 'PT_LOAD':
                    return segment['p_vaddr']
        return 0x0
    except Exception as e:
        print(f"警告：获取基址失败 - {e}")
        return 0x0

def file_offset_to_virtual(elf_path, file_offset, base_addr):
    """将文件偏移转换为虚拟地址（非PIE用固定基址，PIE用传入的运行时基址）"""
    try:
        with open(elf_path, 'rb') as f:
            elf = ELFFile(f)
            for segment in elf.iter_segments():
                if segment['p_type'] == 'PT_LOAD':
                    seg_file_off = segment['p_offset']
                    seg_virt_addr = segment['p_vaddr']
                    seg_file_size = segment['p_filesz']
                    # 检查文件偏移是否在当前LOAD段内
                    if seg_file_off <= file_offset < seg_file_off + seg_file_size:
                        # 虚拟地址 = 基址 + (文件偏移 - 段文件偏移)
                        virt_addr = base_addr + (file_offset - seg_file_off)
                        return virt_addr
        return None
    except Exception as e:
        print(f"警告：转换虚拟地址失败 - {e}")
        return None

def search_elf_strings(elf_path, target_strings):
    """搜索ELF中所有目标字符串，返回（字符串、文件偏移、虚拟地址）"""
    results = []
    is_pie = is_pie_enabled(elf_path)
    base_addr = get_elf_base(elf_path) if not is_pie else 0x0

    try:
        with open(elf_path, 'rb') as f:
            elf_data = f.read()
    except FileNotFoundError:
        print(f"错误：找不到文件 {elf_path}")
        return results, is_pie, base_addr

    for target in target_strings:
        target_bytes = target.encode('ascii')
        target_len = len(target_bytes)
        total_len = len(elf_data)

        for offset in range(total_len - target_len + 1):
            if elf_data[offset:offset+target_len] == target_bytes:
                # 计算虚拟地址
                if not is_pie:
                    virt_addr = file_offset_to_virtual(elf_path, offset, base_addr)
                    virt_addr_hex = f"0x{virt_addr:08x}" if virt_addr else "N/A"
                else:
                    virt_addr_hex = "PIE（需运行时基址）"
                # 保存结果
                results.append((
                    target,
                    f"0x{offset:08x}",  # 文件偏移（十六进制）
                    offset,             # 文件偏移（十进制）
                    virt_addr_hex       # 虚拟地址
                ))
    return results, is_pie, base_addr

def main():
    if len(sys.argv) != 2:
        print("用法：python elf_string_searcher.py <目标ELF文件路径>")
        print("示例：python elf_string_searcher.py ./pwn_challenge")
        sys.exit(1)

    elf_path = sys.argv[1]
    # 目标字符串列表（可自由添加/修改）
    target_strings = [
	    # 原有核心字符串
	    "/bin/sh\x00",
	    "sh\x00",
	    "$0\x00",
	    # 新增补充字符串（按优先级排序）
	    "/bin/bash\x00",
	    "bash\x00",
	    "$SHELL\x00",
	    "/usr/bin/sh\x00",
	    "/bin/dash\x00",
	    "dash\x00",
	    "/usr/bin/bash\x00",
	    "$BASH\x00",
	    "exec sh\x00",
	    "sh -c sh\x00"
]

    # 执行搜索
    results, is_pie, base_addr = search_elf_strings(elf_path, target_strings)

    # 打印ELF基本信息（重点：基址+PIE状态）
    print("=" * 60)
    print(f"ELF文件：{elf_path}")
    print(f"PIE状态：{'开启' if is_pie else '未开启'}")
    if not is_pie:
        print(f"固定基址：0x{base_addr:08x}（可直接使用）")
    else:
        print("提示：PIE开启时，基址为运行时随机分配，需通过gdb/ida获取")
    print("=" * 60)

    # 打印搜索结果
    if not results:
        print("\n未找到任何目标字符串")
        return

    print(f"\n找到 {len(results)} 个匹配结果：")
    print("-" * 80)
    print(f"{'字符串':<12} {'文件偏移(十六进制)':<20} {'文件偏移(十进制)':<15} {'虚拟地址'}")
    print("-" * 80)
    for s, off_hex, off_dec, virt_addr in results:
        display_s = s.replace('\x00', '\\0')  # 美化显示\x00
        print(f"{display_s:<12} {off_hex:<20} {off_dec:<15} {virt_addr}")

    # PIE开启时，添加计算提示
    if is_pie and results:
        print("\n" + "-" * 80)
        print("PIE地址计算方法：实际虚拟地址 = 运行时基址 + 文件偏移")
        print("示例：运行时基址=0x55aabbcc，文件偏移=0x1234 → 实际地址=0x55aabbcc + 0x1234 = 0x55aabc00")
        print("获取运行时基址：gdb中用 `info proc map` 查看ELF加载地址")

if __name__ == "__main__":
    main()

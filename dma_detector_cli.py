import psutil
import ctypes
from ctypes import wintypes
import argparse
import sys
import os

# 文本资源字典
TEXT_RESOURCES = {
    "zh": {
        "warning_non_windows": "警告: 当前运行环境非Windows，将返回模拟进程列表。",
        "error_open_process": "错误: 无法打开进程 {pid} (权限不足或进程不存在).",
        "warning_read_memory": "警告: 无法读取进程 {pid} 内存地址 {hex(address)} (可能无权限或地址无效).",
        "error_get_memory_regions": "错误: 无法打开进程 {pid} 获取内存区域 (权限不足或进程不存在).",
        "exception_read_memory": "读取内存时发生异常: {e}",
        "exception_get_memory_regions": "获取内存区域时发生异常: {e}",
        "no_accessible_memory_regions": "未找到进程 {pid} 的可访问内存区域。",
        "scanning_memory": "开始扫描进程 {pid} 的内存... (模式: {pattern}, 范围: {start_range}-{end_range})",
        "warning_too_many_matches": "警告: 找到超过1000个匹配项，已停止扫描以避免过多输出。",
        "tool_description": "DMA 作弊检测工具 (代码交互版) - MantraI@MantraChen",
        "author_info": "作者: MantraI@MantraChen",
        "list_processes_help": "列出所有运行中的进程",
        "pid_help": "指定要扫描的进程PID",
        "process_name_help": "指定要扫描的进程名称 (例如: notepad.exe)",
        "pattern_help": "\n要搜索的模式。可以是字符串或十六进制字节序列。\n例如: \"MZ\" 或 \"0x4D5A\"",
        "start_address_help": "扫描起始内存地址 (十六进制, 默认: 0x400000)",
        "end_address_help": "扫描结束内存地址 (十六进制, 默认: 0x7FFFFFFF)",
        "chunk_size_help": "每次读取的内存块大小 (十六进制, 默认: 0x1000)",
        "language_help": "选择显示语言 (zh: 中文, en: 英文)",
        "warning_non_windows_full": "警告: 当前运行环境非Windows。内存读取和扫描功能将使用模拟数据。\n      完整功能请在Windows系统上运行，并确保安装psutil库。",
        "pid_or_name_required": "错误: 请使用 -l 列出进程，或使用 -p 指定PID，或使用 -n 指定进程名进行扫描。",
        "process_not_found": "错误: 未找到名为 \"{process_name}\" 的进程。",
        "multiple_processes_found": "警告: 找到多个名为 \"{process_name}\" 的进程: {pids}. 默认选择第一个: {first_pid}",
        "target_pid_not_determined": "错误: 无法确定目标进程PID。",
        "pattern_required": "错误: 请使用 -s 指定要搜索的模式。",
        "invalid_pattern_format": "错误: 无效的模式格式: {e}",
        "getting_process_list": "\n正在获取进程列表...",
        "pid_name_path": "PID\t进程名\t路径",
        "no_processes_found": "未找到任何进程。",
        "found_matches": "\n✅ 找到 {count} 个匹配项:",
        "address": "  [{index}] 地址: {address}",
        "content": "      内容: {hex_str}",
        "ascii": "      ASCII: {ascii_str}",
        "cannot_read_content": "      内容: 无法读取",
        "no_matches_found": "\n❌ 未找到匹配的模式。",
        "tip_no_matches": "提示: 尝试调整搜索模式、地址范围或检查进程权限。",
        "scan_complete": "\n=== 扫描完成 ==="
    },
    "en": {
        "warning_non_windows": "Warning: Non-Windows environment detected. Returning simulated process list.",
        "error_open_process": "Error: Could not open process {pid} (insufficient permissions or process does not exist).",
        "warning_read_memory": "Warning: Could not read memory at address {hex(address)} for process {pid} (possibly no permissions or invalid address).",
        "error_get_memory_regions": "Error: Could not open process {pid} to get memory regions (insufficient permissions or process does not exist).",
        "exception_read_memory": "Exception occurred while reading memory: {e}",
        "exception_get_memory_regions": "Exception occurred while getting memory regions: {e}",
        "no_accessible_memory_regions": "No accessible memory regions found for process {pid}.",
        "scanning_memory": "Scanning memory for process {pid}... (Pattern: {pattern}, Range: {start_range}-{end_range})",
        "warning_too_many_matches": "Warning: More than 1000 matches found, stopping scan to avoid excessive output.",
        "tool_description": "DMA Cheat Detection Tool (CLI) - MantraI@MantraChen",
        "author_info": "Author: MantraI@MantraChen",
        "list_processes_help": "List all running processes",
        "pid_help": "Specify PID of the process to scan",
        "process_name_help": "Specify name of the process to scan (e.g.: notepad.exe)",
        "pattern_help": "\nPattern to search for. Can be a string or a hexadecimal byte sequence.\nExample: \"MZ\" or \"0x4D5A\"",
        "start_address_help": "Start memory address for scanning (hex, default: 0x400000)",
        "end_address_help": "End memory address for scanning (hex, default: 0x7FFFFFFF)",
        "chunk_size_help": "Chunk size for each memory read (hex, default: 0x1000)",
        "language_help": "Select display language (zh: Chinese, en: English)",
        "warning_non_windows_full": "Warning: Current environment is not Windows. Memory reading and scanning functions will use simulated data.\n      For full functionality, please run on Windows and ensure psutil is installed.",
        "pid_or_name_required": "Error: Please use -l to list processes, or -p to specify PID, or -n to specify process name for scanning.",
        "process_not_found": "Error: Process named \"{process_name}\" not found.",
        "multiple_processes_found": "Warning: Multiple processes named \"{process_name}\" found: {pids}. Defaulting to the first one: {first_pid}",
        "target_pid_not_determined": "Error: Could not determine target process PID.",
        "pattern_required": "Error: Please use -s to specify the pattern to search for.",
        "invalid_pattern_format": "Error: Invalid pattern format: {e}",
        "getting_process_list": "\nGetting process list...",
        "pid_name_path": "PID\tProcess Name\tPath",
        "no_processes_found": "No processes found.",
        "found_matches": "\n✅ Found {count} matches:",
        "address": "  [{index}] Address: {address}",
        "content": "      Content: {hex_str}",
        "ascii": "      ASCII: {ascii_str}",
        "cannot_read_content": "      Content: Cannot read",
        "no_matches_found": "\n❌ No matching patterns found.",
        "tip_no_matches": "Tip: Try adjusting the search pattern, address range, or check process permissions.",
        "scan_complete": "\n=== Scan Complete ==="
    }
}

current_language = "en" # 默认语言

def _(key, **kwargs):
    return TEXT_RESOURCES[current_language].get(key, key).format(**kwargs)

# Windows特定的导入
try:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    
    PROCESS_ALL_ACCESS = (0x000F0000 | 0x00100000 | 0xFFF)
    
    # OpenProcess
    OpenProcess = kernel32.OpenProcess
    OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    OpenProcess.restype = wintypes.HANDLE
    
    # CloseHandle
    CloseHandle = kernel32.CloseHandle
    CloseHandle.argtypes = [wintypes.HANDLE]
    CloseHandle.restype = wintypes.BOOL
    
    # ReadProcessMemory
    ReadProcessMemory = kernel32.ReadProcessMemory
    ReadProcessMemory.argtypes = [
        wintypes.HANDLE,  # hProcess
        wintypes.LPCVOID, # lpBaseAddress
        wintypes.LPVOID,  # lpBuffer
        ctypes.c_size_t,  # nSize
        ctypes.POINTER(ctypes.c_size_t) # lpNumberOfBytesRead
    ]
    ReadProcessMemory.restype = wintypes.BOOL
    
    # VirtualQueryEx
    VirtualQueryEx = kernel32.VirtualQueryEx
    VirtualQueryEx.argtypes = [
        wintypes.HANDLE,
        wintypes.LPCVOID,
        ctypes.c_void_p,
        ctypes.c_size_t
    ]
    VirtualQueryEx.restype = ctypes.c_size_t
    
    # 内存信息结构体
    class MEMORY_BASIC_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("BaseAddress", ctypes.c_void_p),
            ("AllocationBase", ctypes.c_void_p),
            ("AllocationProtect", wintypes.DWORD),
            ("RegionSize", ctypes.c_size_t),
            ("State", wintypes.DWORD),
            ("Protect", wintypes.DWORD),
            ("Type", wintypes.DWORD)
        ]
    
    # 内存状态常量
    MEM_COMMIT = 0x1000
    
    # 内存保护常量
    PAGE_READONLY = 0x02
    PAGE_READWRITE = 0x04
    PAGE_EXECUTE_READ = 0x20
    PAGE_EXECUTE_READWRITE = 0x40
    
    WINDOWS_AVAILABLE = True
except (ImportError, AttributeError):
    WINDOWS_AVAILABLE = False

def get_process_list():
    """获取当前系统所有进程的列表"""
    if not WINDOWS_AVAILABLE:
        print(_("warning_non_windows"))
        return [{"pid": 1234, "name": "notepad.exe", "exe": "C:\\Windows\\System32\\notepad.exe"},
                {"pid": 5678, "name": "game.exe", "exe": "C:\\Program Files\\Game\\game.exe"}]
    
    processes = []
    for proc in psutil.process_iter(["pid", "name", "exe", "cmdline"]):
        try:
            pinfo = proc.as_dict(attrs=["pid", "name", "exe", "cmdline"])
            processes.append(pinfo)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return processes

def read_process_memory(pid, address, size):
    """读取指定进程的内存"""
    if not WINDOWS_AVAILABLE:
        # 模拟数据，实际应根据需求返回更真实的模拟数据
        return b"\xDE\xAD\xBE\xEF" * (size // 4) if size > 0 else b""
    
    try:
        process_handle = OpenProcess(PROCESS_ALL_ACCESS, False, pid)
        if not process_handle:
            print(_("error_open_process", pid=pid))
            return None

        buffer = ctypes.create_string_buffer(size)
        bytes_read = ctypes.c_size_t(0)

        if ReadProcessMemory(process_handle, address, buffer, size, ctypes.byref(bytes_read)):
            CloseHandle(process_handle)
            return buffer.raw[:bytes_read.value]
        else:
            # print(_("warning_read_memory", pid=pid, address=address))
            CloseHandle(process_handle)
            return None
    except Exception as e:
        print(_("exception_read_memory", e=e))
        return None

def get_memory_regions(pid):
    """获取进程的内存区域信息"""
    if not WINDOWS_AVAILABLE:
        # 模拟一些可读区域
        return [(0x400000, 0x100000, "READWRITE"), (0x70000000, 0x10000, "READONLY")]
    
    try:
        process_handle = OpenProcess(PROCESS_ALL_ACCESS, False, pid)
        if not process_handle:
            print(_("error_get_memory_regions", pid=pid))
            return []
        
        regions = []
        address = 0
        
        while address < 0x7FFFFFFF:
            mbi = MEMORY_BASIC_INFORMATION()
            result = VirtualQueryEx(process_handle, address, ctypes.byref(mbi), ctypes.sizeof(mbi))
            
            if result == 0:
                break
            
            # 只处理已提交的可读内存区域
            if (mbi.State == MEM_COMMIT and 
                mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)):
                regions.append((mbi.BaseAddress, mbi.RegionSize, hex(mbi.Protect)))
            
            address = mbi.BaseAddress + mbi.RegionSize
        
        CloseHandle(process_handle)
        return regions
    except Exception as e:
        print(_("exception_get_memory_regions", e=e))
        return []

def scan_memory_for_pattern(pid, pattern, start_address=0, end_address=0x7FFFFFFF, chunk_size=0x1000):
    """在指定进程内存中扫描特定模式"""
    if not WINDOWS_AVAILABLE:
        print(_("warning_non_windows"))
        # 模拟找到一些结果
        if pattern == b'MZ':
            return [0x400000, 0x401000, 0x402000]
        elif pattern == b'test':
            return [0x100000, 0x100010]
        else:
            return []
    
    results = []
    
    # 获取内存区域
    regions = get_memory_regions(pid)
    if not regions:
        print(_("no_accessible_memory_regions", pid=pid))
        return results
    
    print(_("scanning_memory", pid=pid, pattern=pattern, start_range=hex(start_address), end_range=hex(end_address)))
    
    for base_addr, region_size, protect_info in regions:
        # 检查区域是否在指定范围内
        region_start = max(base_addr, start_address)
        region_end = min(base_addr + region_size, end_address)
        
        if region_start >= region_end:
            continue
            
        current_address = region_start
        
        while current_address < region_end:
            read_size = min(chunk_size, region_end - current_address)
            data = read_process_memory(pid, current_address, read_size)
            
            if data:
                offset = 0
                while True:
                    pos = data.find(pattern, offset)
                    if pos == -1:
                        break
                    found_addr = current_address + pos
                    results.append(found_addr)
                    offset = pos + 1
                    
            current_address += read_size
            
            # 限制结果数量以避免过多输出
            if len(results) > 1000:
                print(_("warning_too_many_matches"))
                return results
    
    return results

def main():
    global current_language
    parser = argparse.ArgumentParser(
        description=_("tool_description"),
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    parser.add_argument(
        "-l", "--list-processes", 
        action="store_true", 
        help=_("list_processes_help")
    )
    parser.add_argument(
        "-p", "--pid", 
        type=int, 
        help=_("pid_help")
    )
    parser.add_argument(
        "-n", "--process-name", 
        type=str, 
        help=_("process_name_help")
    )
    parser.add_argument(
        "-s", "--pattern", 
        type=str, 
        help=_("pattern_help")
    )
    parser.add_argument(
        "-sa", "--start-address", 
        type=lambda x: int(x, 16), 
        default=0x400000, 
        help=_("start_address_help")
    )
    parser.add_argument(
        "-ea", "--end-address", 
        type=lambda x: int(x, 16), 
        default=0x7FFFFFFF, 
        help=_("end_address_help")
    )
    parser.add_argument(
        "-c", "--chunk-size", 
        type=lambda x: int(x, 16), 
        default=0x1000, 
        help=_("chunk_size_help")
    )
    parser.add_argument(
        "-lang", "--language", 
        type=str, 
        default="zh", 
        choices=TEXT_RESOURCES.keys(),
        help=_("language_help")
    )

    args = parser.parse_args()
    current_language = args.language

    print(f"\n=== {_('tool_description')} ===")
    print(_("author_info"))
    print("-------------------------------------")

    if not WINDOWS_AVAILABLE:
        print(_("warning_non_windows_full"))
        print("-------------------------------------")

    if args.list_processes:
        print(_("getting_process_list"))
        processes = get_process_list()
        if processes:
            print(_("pid_name_path"))
            print("-------------------------------------")
            for p in processes:
                print(f"{p['pid']}\t{p['name']}\t{p.get('exe', 'N/A')}")
        else:
            print(_("no_processes_found"))
        return

    if not args.pid and not args.process_name:
        print(_("pid_or_name_required"))
        parser.print_help()
        return

    target_pid = None
    if args.pid:
        target_pid = args.pid
    elif args.process_name:
        processes = get_process_list()
        found_pids = [p['pid'] for p in processes if args.process_name.lower() in p['name'].lower()]
        if not found_pids:
            print(_("process_not_found", process_name=args.process_name))
            return
        elif len(found_pids) > 1:
            print(_("multiple_processes_found", process_name=args.process_name, pids=found_pids, first_pid=found_pids[0]))
            target_pid = found_pids[0]
        else:
            target_pid = found_pids[0]

    if not target_pid:
        print(_("target_pid_not_determined"))
        return

    if not args.pattern:
        print(_("pattern_required"))
        parser.print_help()
        return

    # 解析搜索模式
    pattern_bytes = None
    try:
        if args.pattern.startswith("0x"):
            hex_str = args.pattern[2:]
            if len(hex_str) % 2 != 0:
                hex_str = "0" + hex_str # 补齐为偶数长度
            pattern_bytes = bytes.fromhex(hex_str)
        else:
            pattern_bytes = args.pattern.encode("utf-8")
    except ValueError as e:
        print(_("invalid_pattern_format", e=e))
        return

    found_addresses = scan_memory_for_pattern(
        target_pid, 
        pattern_bytes, 
        args.start_address, 
        args.end_address,
        args.chunk_size
    )

    if found_addresses:
        print(_("found_matches", count=len(found_addresses)))
        for i, addr in enumerate(found_addresses):
            print(_("address", index=i+1, address=hex(addr)))
            # 尝试读取该地址周围的内存内容
            memory_data = read_process_memory(target_pid, addr, 32) # 读取32字节
            if memory_data:
                hex_str = " ".join([f"{b:02x}" for b in memory_data[:16]]) # 显示前16字节的十六进制
                ascii_str = "".join([chr(b) if 32 <= b <= 126 else "." for b in memory_data[:16]]) # 显示前16字节的ASCII
                print(_("content", hex_str=hex_str))
                print(_("ascii", ascii_str=ascii_str))
            else:
                print(_("cannot_read_content"))
    else:
        print(_("no_matches_found"))
        print(_("tip_no_matches"))

    print(_("scan_complete"))

if __name__ == '__main__':
    main()



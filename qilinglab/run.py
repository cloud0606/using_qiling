from qiling import *
from qiling.const import *
from qiling.os.mapper import QlFsMappedObject
import os
import struct

def c1(ql: Qiling):
    'Store 1337 at pointer 0x1337.'
    # 映射 0x1337 的地址，因为不能直接访问, 从 0x1000 到 0x2000的映射
    # 操作内存地址
    size = 4096
    addr = 0x1000 // size * size
    ql.mem.map(addr, size, info = 'challenge1') 
    ql.mem.write(0x1337, ql.pack(1337))
    # print(f'ql.pack(1337) = {ql.pack(1337)}') 
    # print(f'ql.pack32(1337) = {ql.pack32(1337)}') # unsigned int
    # print(f'ql.pack64(1337) = {ql.pack64(1337)}') # unsigned long long
    # output: 输出都是按小端序输出的，程序也是 LSB
    # ql.pack16(1337) = b'9\x05' # 其实等于 b'\x39\x05' \x39 39对应的ascii字符就是9
    # ql.pack16(8) = b'\x08\x00'
    # ql.pack16(16) = b'\x10\x00'
    # ql.pack16(255) = b'\xff\x00'
    # ql.pack16(256) = b'\x00\x01'
    # ql.pack16(1023) = b'\xff\x03'
    # ql.pack16(1024) = b'\x00\x04'
    # ql.pack16(1328) = b'0\x05'


def hook_uname_on_exit(ql: Qiling, buf, *args, **kwargs):
    # rdi = ql.reg.rdi 
    # 这里有人通过 rdi 直接写也能写到 buf 里面。 
    ql.mem.write(buf, b'QilingOS\x00')
    ql.mem.write(buf + 65 * 3, b'ChallengeStart\x00')
    # 有人写入数据的时候这样子填充0, 不填充也能过 b'ChallengeStart'.ljust(65, b'\x00')
    return 0

def c2(ql: Qiling):
    'Make the uname syscall return the correct values'
    # hook 系统调用
    # 存储了结构体，我们需要回复结构体的数据。
    ql.set_syscall('uname', hook_uname_on_exit, QL_INTERCEPT.EXIT)
    # QL_INTERCEPT.EXIT   Hijack returns value after OS APIs or syscall execution
    # QL_INTERCEPT.ENTER  Hijack parameter before OS APIs or syscall

class Fake_urandom(QlFsMappedObject):
    def read(self, size):
        if size > 1:
            return b'a' * size
        else:
            return b'?'

    def fstat(self):
        return -1
    
    def close(self):
        return 0

def hook_getrandom_on_exit(ql: Qiling, buf, buflen, flags, *args, **kwargs):
    ql.mem.write(buf, b"a" * buflen)
    return buflen

def c3(ql: Qiling):
    '''Make '/dev/urandom' and 'getrandom' "collide".
    '''
    # hook 文件系统和系统调用
    # 通过 /dev/urandom 读取到的随机数和 getrandom 获取的随机数需要一模一样,32位,并且通过 getrandom 读取一位数时获得的字符不出现在随机数里
    ql.add_fs_mapper("/dev/urandom", Fake_urandom())
    # 可以把仿真环境中的路径劫持到宿主机上, 也可以自定义,需要继承 QlFsMappedObject
    ql.set_syscall("getrandom", hook_getrandom_on_exit, QL_INTERCEPT.EXIT)

def hook_eax(ql: Qiling):
    ql.reg.eax = 1

def c4(ql: Qiling):
    'Enter inside the "forbidden" loop'
    # hook 地址，修改 eax 值
    base = ql.mem.get_lib_base(os.path.split(ql.path)[-1])
    # #todo 这个获取的是什么地址？是程序被加载到内存中的地址吗，为什么直接加  0xE43 就能准确定位
    # os.path.split(ql.path)[-1] = qilinglab-x86_64
    # base = 0x555555554000
    ql.hook_address(hook_eax, base + 0xE43)

def hook_rand_on_exit(ql: Qiling):
    # 设置返回值为 0 
    ql.reg.rax = 0

def c5(ql: Qiling):
    'Guess every call to rand().'
    # 控制 rand 函数返回值一直都是0
    # hook 外部函数
    # rand 函数的 extern 函数
    ql.set_api("rand", hook_rand_on_exit, QL_INTERCEPT.EXIT)

def hook_eax_0(ql: Qiling):
    ql.reg.eax = 0

def c6(ql: Qiling):
    'Avoid the infinite loop.'
    # 跳出死循环
    # 比较语句 test al, al
    # .text:0000000000000F12 loc_F12:
    # .text:0000000000000F12 movzx   eax, [rbp+var_5]
    # .text:0000000000000F16 test    al, al
    # .text:0000000000000F18 jnz     short lo
    # Test命令将两个操作数进行逻辑与运算，并根据运算结果设置相关的标志位。Test命令的两个操作数不会被改变。运算结果在设置过相关标记位后会被丢弃。
    # test al, al 的作用的判断 al 寄存器是否为空。
    base = ql.mem.get_lib_base(os.path.split(ql.path)[-1])
    ql.hook_address(hook_eax_0, base + 0xF16)

def hook_edi_1(ql: Qiling):
    ql.reg.edi = 0

def hook_nanosleep(ql: Qiling, *args, **kwargs):
    # 注意参数列表
    return

def c7(ql: Qiling):
    "Don't waste time waiting for 'sleep'."
    # .text:0000000000000F37 mov     edi, 0FFFFFFFFh ; seconds
    # .text:0000000000000F3C call    _s
    # 修改 edx 寄存器的值
    base = ql.mem.get_lib_base(os.path.split(ql.path)[-1])
    ql.hook_address(hook_edi_1, base + 0xF3C)
    # 或者 hook syscall
    # ql.set_syscall('nanosleep', hook_nanosleep)

def search_mem_to_find_struct(ql: Qiling):
    MAGIC = ql.pack64(0x3DFCD6EA00000539)
    candidate_addrs = ql.mem.search(MAGIC)
 
    for addr in candidate_addrs:
        # 有可能有多个地址，所以通过其他特征进一步确认
        stru_addr = addr - 8
        stru = ql.mem.read(stru_addr, 24)
        string_addr, _, check_addr = struct.unpack('QQQ', stru)
        if ql.mem.string(string_addr) == 'Random data':
            ql.mem.write(check_addr, b'\x01')
            break


def search_mem_to_find_struct(ql: Qiling):
    # todo还没看懂
    MAGIC = ql.pack64(0x3DFCD6EA00000539)
    # print(MAGIC)
    candidate_addrs = ql.mem.search(MAGIC)
 
    for addr in candidate_addrs:
        # print(hex(addr))
        stru_addr = addr - 8
        stru = ql.mem.read(stru_addr, 24)
        string_addr, _, check_addr = struct.unpack('QQQ', stru)
        # print(hex(string_addr))
        # print(hex(_))
        # print(hex(check_addr))
        # print(ql.mem.string(string_addr))
        if ql.mem.string(string_addr) == 'Random data':
            ql.mem.write(check_addr, b'\x01')
            break

def c8(ql: Qiling):
    # todo还没看懂
    base = ql.mem.get_lib_base(os.path.split(ql.path)[-1])
    
    # method 1
    # ql.hook_address(hook_struct, base + 0xFB5)
    # method 2
    ql.hook_address(search_mem_to_find_struct, base + 0xFB5)

def hook_tolower(ql: Qiling, *args, **kwargs):
    return 

def c9(ql: Qiling):
    'Fix some string operation to make the iMpOsSiBlE come true.'
    # 把字符串改成全小写
    # 或者 hook tolower 函数，不进行任何操作
    # 直接替换 libc 函数
    ql.set_api("tolower", hook_tolower)

class fake_cmdline(QlFsMappedObject):
    def read(self, size):
        return b"qilinglab"

    def fstat(self):
        return -1
    
    def close(self):
        return 0

def c10(ql: Qiling):
    " Fake the 'cmdline' line file to return the right content."
    # hook fs
    ql.add_fs_mapper("/proc/self/cmdline", fake_cmdline())

def hook_cpuid(ql: Qiling, address, size):
    # print("----------hook_cpuid")
    # print(address, size)
    if ql.mem.read(address, size) == b'\x0F\xA2':
        #todo 如何筛选
        ql.reg.ebx = 0x696C6951
        ql.reg.ecx = 0x614C676E
        ql.reg.edx = 0x20202062
        ql.reg.rip += 2

def c11(ql: Qiling):
    'Bypass CPUID/MIDR_EL1 checks.'
    # .text:000000000000118F                 cpuid
    # .text:0000000000001191                 mov     eax, edx
    # .text:0000000000001193                 mov     esi, ebx
    # .text:0000000000001195                 mov     [rbp+var_30], esi
    # .text:0000000000001198                 mov     [rbp+var_34], ecx
    # .text:000000000000119B                 mov     [rbp+var_2C], eax
    # .text:000000000000119E                 cmp     [rbp+var_30], 696C6951h
    # .text:00000000000011A5                 jnz     short loc_11C0
    # .text:00000000000011A7                 cmp     [rbp+var_34], 614C676Eh
    # .text:00000000000011AE                 jnz     short loc_11C0
    # .text:00000000000011B0                 cmp     [rbp+var_2C], 20202062h
    # .text:00000000000011B7                 jnz     short loc_11C0
    # cpuid 获取CPU的详细信息，输出参数有四个，分别放在eax、ebx、ecx、edx中。
    # 本例子中我们需要填充 ecx, eax, esi(ebx) 寄存器的值
    # 以下方法不行，为#todo 为什么不能用 hook_address 呢？
    # base = ql.mem.get_lib_base(os.path.split(ql.path)[-1])
    # ql.hook_address(hook_cpuid, base + 0x1193)
    begin, end = 0, 0
    for info in ql.mem.map_info:
        # print("--------")
        if info[2] == 5 and info[3] == ql.path:
            # print(info)
            begin, end = info[:2]
    ql.hook_code(hook_cpuid, begin = begin, end = end)

if __name__ == "__main__":
    target = ["./qilinglab-x86_64"]
    rootfs = "/home/cuc/qiling/examples/rootfs/x8664_linux"
    ql = Qiling(target, rootfs, verbose=QL_VERBOSE.OFF)
    c1(ql) 
    c2(ql)
    c3(ql)
    c4(ql)
    c5(ql)
    c6(ql)
    c7(ql)
    c8(ql)
    c9(ql)
    c10(ql)
    c11(ql)
    ql.run()
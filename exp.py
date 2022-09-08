import struct

from qiling import *
from qiling.const import *
from qiling.os.mapper import QlFsMappedObject


# Challenge1
def challenge1(ql: Qiling):
    addr = 0x1337
    ql.mem.map(addr // 4096 * 4096, 0x1000)
    ql.mem.write(addr, ql.pack16(1337))


# Challenge2
def fake_uname(ql: Qiling, pName, *args):
    ql.mem.write(pName, b'QilingOS\x00')
    ql.mem.write(pName + 65 * 3, b'ChallengeStart\x00')


def challenge2(ql: Qiling):
    ql.os.set_syscall('uname', fake_uname, QL_INTERCEPT.EXIT)


# Challenge3
def fake_getrandom(ql: Qiling, pBuf, buflen, flag, *args):
    ql.mem.write(pBuf, b'\x01' * buflen)


class Fake_urandom(QlFsMappedObject):

    def read(self, size):
        if size == 1:
            return b'\x00'
        else:
            return b'\x01' * size

    def fstat(self):
        return -1

    def close(self):
        return 0


def challenge3(ql: Qiling):
    ql.add_fs_mapper("/dev/urandom", Fake_urandom())
    ql.os.set_syscall('getrandom', fake_getrandom, QL_INTERCEPT.EXIT)


# Challenge4
def stop(ql: Qiling) -> None:
    # ql.arch.regs.write("x1", 0)
    ql.arch.regs.write("x0", 1)


def challenge4(ql: Qiling):
    address = 0x555555554000 + 0xFE0
    ql.hook_address(stop, address)


# Challenge5
def fake_rand(ql: Qiling, *args):
    ql.arch.regs.write("x0", 0)


def challenge5(ql: Qiling):
    ql.os.set_api("rand", fake_rand)


# Challenge6
def stop2(ql: Qiling) -> None:
    # ql.arch.regs.write("x1", 0)
    ql.arch.regs.write("x0", 0)


def challenge6(ql: Qiling):
    address = 0x555555554000 + 0x1118
    ql.hook_address(stop2, address)


# Challenge7
def fake_sleep(ql: Qiling, *args):
    ql.arch.regs.write("w0", 0)


def challenge7(ql: Qiling):
    ql.os.set_api("sleep", fake_sleep)


# Challenge8
def fake_nop(ql: Qiling):
    num = 0x3DFCD6EA00000539
    num_address_list = ql.mem.search(ql.pack64(num))
    for num_address in num_address_list:
        s1_address = num_address - 8
        s1 = ql.mem.read(s1_address, 0x18)
        s2_address, num2_addr, flag = struct.unpack('QQQ', s1)
        random_data = ql.mem.string(s2_address)
        if random_data == 'Random data':
            ql.mem.write(flag, b'\x01')
            break


def challenge8(ql: Qiling):
    address = 0x555555554000 + 0x11dc
    ql.hook_address(fake_nop, address)


# Challenge9
def fake_strcmp(ql: Qiling, *args):
    ql.arch.regs.write("x0", 0)


def challenge9(ql: Qiling):
    ql.os.set_api('strcmp', fake_strcmp)


# Challenge10
class Fake_cmdline(QlFsMappedObject):

    def read(self, size):
        return b'qilinglab'

    def fstat(self):
        return -1

    def close(self):
        return 0


def challenge10(ql: Qiling):
    ql.add_fs_mapper("/proc/self/cmdline", Fake_cmdline())


# Challenge11
def fake_end(ql: Qiling) -> None:
    ql.arch.regs.write("x1", 0x1337)


def challenge11(ql: Qiling):
    ql.hook_address(fake_end, 0x555555554000+ 0x1400)


if __name__ == "__main__":
    target = ['./qilinglab-aarch64']
    rootfs = "./arm64_linux"
    ql = Qiling(target, rootfs, verbose=QL_VERBOSE.DISABLED)
    challenge1(ql)
    challenge2(ql)
    challenge3(ql)
    challenge4(ql)
    challenge5(ql)
    challenge6(ql)
    challenge7(ql)
    challenge8(ql)
    challenge9(ql)
    challenge10(ql)
    challenge11(ql)
    ql.run()

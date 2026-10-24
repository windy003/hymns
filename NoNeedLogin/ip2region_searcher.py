"""ip2region 离线 IP 归属地查询（IPv4 + IPv6）。

数据文件放在仓库根目录的 data/ 下：
    data/ip2region_v4.xdb
    data/ip2region_v6.xdb

xdb 的二进制读取逻辑参考 ip2region 官方 Python 绑定（Apache-2.0）做了精简，
不依赖任何第三方包。xdb 内容整体读入内存，查询是纯内存二分查找，线程安全，
单次查询通常在微秒级，适合在管理页一次性解析最近 24 小时的全部 IP。
"""

from __future__ import annotations

import ipaddress
import os
import threading
from functools import lru_cache
from pathlib import Path

_HEADER_INFO_LENGTH = 256
_VECTOR_INDEX_SIZE = 8
_VECTOR_INDEX_LENGTH = 256 * 256 * _VECTOR_INDEX_SIZE

# 索引块：起始 IP + 结束 IP + 数据长度(2) + 数据偏移(4)
_INDEX_SIZE_V4 = 4 + 4 + 2 + 4   # 14
_INDEX_SIZE_V6 = 16 + 16 + 2 + 4  # 38

_DEFAULT_DATA_DIR = Path(__file__).resolve().parent.parent / 'data'


def _le_uint16(buff, offset):
    return buff[offset] | (buff[offset + 1] << 8)


def _le_uint32(buff, offset):
    return (buff[offset] | (buff[offset + 1] << 8)
            | (buff[offset + 2] << 16) | (buff[offset + 3] << 24))


class _XdbSearcher:
    """单个 xdb 文件的内存查询器。"""

    def __init__(self, path, index_size, ip_bytes):
        self.path = Path(path)
        self._index_size = index_size
        self._ip_bytes = ip_bytes
        # 整个文件读入内存：v4 约 11MB，v6 约 36MB，换取无锁、线程安全的查询。
        self._buffer = self.path.read_bytes()
        if len(self._buffer) < _HEADER_INFO_LENGTH + _VECTOR_INDEX_LENGTH:
            raise ValueError(f'xdb 文件不完整: {self.path}')

    def search(self, packed_ip: bytes) -> str:
        if len(packed_ip) != self._ip_bytes:
            return ''

        # 二维向量索引：第一个字节定位行，第二个字节定位列
        index_offset = (_HEADER_INFO_LENGTH
                        + packed_ip[0] * 256 * _VECTOR_INDEX_SIZE
                        + packed_ip[1] * _VECTOR_INDEX_SIZE)
        s_ptr = _le_uint32(self._buffer, index_offset)
        e_ptr = _le_uint32(self._buffer, index_offset + 4)
        if not s_ptr or not e_ptr:
            return ''

        low, high = 0, (e_ptr - s_ptr) // self._index_size
        data_len = data_ptr = 0
        while low <= high:
            mid = (low + high) >> 1
            offset = s_ptr + mid * self._index_size
            if offset + self._index_size > len(self._buffer):
                break
            if self._compare(packed_ip, offset) < 0:
                high = mid - 1
            elif self._compare(packed_ip, offset + self._ip_bytes) > 0:
                low = mid + 1
            else:
                data_len = _le_uint16(self._buffer, offset + self._ip_bytes * 2)
                data_ptr = _le_uint32(self._buffer, offset + self._ip_bytes * 2 + 2)
                break

        if not data_len or not data_ptr:
            return ''
        return self._buffer[data_ptr:data_ptr + data_len].decode('utf-8', errors='replace')

    def _compare(self, packed_ip: bytes, offset: int) -> int:
        if self._ip_bytes == 4:
            # IPv4 索引以小端序保存，输入是网络字节序（大端），逐字节反向比较
            j = offset + 3
            for i in range(4):
                if packed_ip[i] < self._buffer[j]:
                    return -1
                if packed_ip[i] > self._buffer[j]:
                    return 1
                j -= 1
            return 0
        stored = self._buffer[offset:offset + 16]
        return (packed_ip > stored) - (packed_ip < stored)


_searchers = {}
_searchers_lock = threading.Lock()


def _data_dir() -> Path:
    return Path(os.getenv('IP2REGION_DATA_DIR') or _DEFAULT_DATA_DIR)


def _get_searcher(version: int):
    """按需加载 v4 / v6 数据库；文件缺失或损坏时返回 None（只警告一次）。"""
    if version in _searchers:
        return _searchers[version]

    with _searchers_lock:
        if version in _searchers:
            return _searchers[version]

        data_dir = _data_dir()
        if version == 4:
            path = Path(os.getenv('IP2REGION_V4_XDB') or data_dir / 'ip2region_v4.xdb')
            index_size, ip_bytes = _INDEX_SIZE_V4, 4
        else:
            path = Path(os.getenv('IP2REGION_V6_XDB') or data_dir / 'ip2region_v6.xdb')
            index_size, ip_bytes = _INDEX_SIZE_V6, 16

        searcher = None
        if path.is_file():
            try:
                searcher = _XdbSearcher(path, index_size, ip_bytes)
            except Exception as error:  # 数据文件损坏时不拖垮管理页
                print(f'[ip2region] 加载 {path} 失败: {error}')
        else:
            print(f'[ip2region] 未找到数据文件 {path}，IPv{version} 归属地将显示为空')

        _searchers[version] = searcher
        return searcher


def _parse_region(raw: str) -> dict:
    """把 xdb 的 `国家|省份|城市|ISP|国家代码` 拆成字典。

    新版 xdb（结构版本 3）的字段是：国家、省份、城市、ISP、ISO 国家代码，
    例如 `中国|浙江省|杭州市|阿里|CN`、`United States|California|0|Google LLC|US`。
    """
    parts = (raw or '').split('|')
    parts += [''] * (5 - len(parts))
    fields = []
    for value in parts[:5]:
        value = value.strip()
        fields.append('' if value in ('', '0') else value)
    country, province, city, isp, iso = fields

    display_parts = []
    for value in (country, province, city):
        if value and value not in display_parts:
            display_parts.append(value)
    display = ' '.join(display_parts)
    if isp and isp not in display_parts:
        display = f'{display} · {isp}' if display else isp

    return {
        'raw': raw or '',
        'country': country,
        'province': province,
        'city': city,
        'isp': isp,
        'iso': iso,
        'display': display,
    }


def is_private_ip(ip: str) -> bool:
    """内网 / 回环 / 链路本地 / 保留地址无法查归属地。"""
    if not ip:
        return True
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return (address.is_private or address.is_loopback or address.is_link_local
            or address.is_reserved or address.is_multicast or address.is_unspecified)


@lru_cache(maxsize=65536)
def lookup(ip: str) -> dict:
    """查询单个 IP，返回解析后的归属地字典。

    私网地址返回 {'display': '内网/本地', ...空字段}；
    数据文件缺失或查不到时 display 为空字符串。
    """
    ip = (ip or '').strip()
    empty = {'raw': '', 'country': '', 'province': '', 'city': '',
             'isp': '', 'iso': '', 'display': ''}
    if not ip:
        return empty

    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return empty

    if (address.is_private or address.is_loopback or address.is_link_local
            or address.is_reserved or address.is_multicast or address.is_unspecified):
        return {**empty, 'display': '内网/本地'}

    # IPv4 映射的 IPv6（::ffff:1.2.3.4）按 IPv4 处理
    mapped = getattr(address, 'ipv4_mapped', None)
    if mapped is not None:
        address = mapped

    searcher = _get_searcher(4 if address.version == 4 else 6)
    if searcher is None:
        return empty

    try:
        raw = searcher.search(address.packed)
    except Exception:
        return empty
    if not raw:
        return empty
    return _parse_region(raw)


def lookup_display(ip: str) -> str:
    """查询并返回可直接展示的归属地字符串。"""
    return lookup(ip)['display']


def is_china(region: dict) -> bool:
    """是否中国大陆/港澳台地址（ip2region 把港澳台也记在“中国”下）。"""
    return region.get('country', '').startswith('中国')


def is_zhejiang(region: dict) -> bool:
    return is_china(region) and region.get('province', '').startswith('浙江')


def is_hangzhou(region: dict) -> bool:
    return is_zhejiang(region) and region.get('city', '').startswith('杭州')

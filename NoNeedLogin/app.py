import os
import re
import json
import ipaddress
import sqlite3
import time
import threading
import urllib.request
from functools import wraps
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse, unquote, quote
from flask import Flask, render_template, send_file, redirect, url_for, flash, abort, request, session, Response
from dotenv import load_dotenv
from waitress import serve
import oss2
from ip2region_searcher import (
    is_china as ip2region_is_china,
    is_hangzhou as ip2region_is_hangzhou,
    is_zhejiang as ip2region_is_zhejiang,
    lookup as ip2region_lookup,
)

# 加载 .env 文件（override=True 确保 .env 配置优先于系统环境变量）
load_dotenv(override=True)

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'dev-secret-key')

# 禁用模板缓存，确保每次都加载最新模板
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.jinja_env.auto_reload = True
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0

# 从环境变量读取配置
CONFIG = {
    'SHARED_DIRECTORY': os.getenv('SHARED_DIRECTORY', r'D:\shared'),
    'PORT': int(os.getenv('PORT', 5001)),
    'HOST': os.getenv('HOST', '0.0.0.0'),
    'DEBUG': os.getenv('DEBUG', 'True').lower() == 'true',
    'ADMIN_PASSWORD': os.getenv('ADMIN_PASSWORD', 'admin123'),
}

# 管理页展示的访问时间统一换算成北京时间（UTC+8），不依赖服务器本地时区。
# 数据库里存的是 time.time() 时间戳，本身不带时区。
BEIJING_TZ = timezone(timedelta(hours=8))


def format_beijing_time(timestamp, fmt='%m-%d %H:%M:%S'):
    """把 Unix 时间戳格式化为北京时间字符串。"""
    return datetime.fromtimestamp(timestamp, BEIJING_TZ).strftime(fmt)


# ==================== 浏览量统计 ====================

VIEWS_DB_PATH = Path(__file__).resolve().parent / 'views.db'


def init_views_db():
    """初始化浏览量统计数据库"""
    conn = sqlite3.connect(str(VIEWS_DB_PATH))
    conn.execute('''
        CREATE TABLE IF NOT EXISTS page_views (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            path TEXT NOT NULL,
            ip TEXT,
            timestamp REAL NOT NULL
        )
    ''')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_page_views_timestamp ON page_views (timestamp)')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS server_display_state (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            next_start_static INTEGER NOT NULL DEFAULT 0
        )
    ''')
    conn.commit()
    conn.close()


def consume_next_start_mode():
    """Return this startup's mode and persist the opposite mode for next startup."""
    conn = sqlite3.connect(str(VIEWS_DB_PATH), timeout=30)
    try:
        conn.execute('BEGIN IMMEDIATE')
        row = conn.execute(
            'SELECT next_start_static FROM server_display_state WHERE id = 1'
        ).fetchone()
        if row is None:
            # First startup defaults to playback mode; next startup shows static page.
            active = False
            conn.execute(
                'INSERT INTO server_display_state (id, next_start_static) VALUES (1, 1)'
            )
        else:
            active = bool(row[0])
            conn.execute(
                'UPDATE server_display_state SET next_start_static = ? WHERE id = 1',
                (0 if active else 1,)
            )
        conn.commit()
        return active
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# 本机反向代理（Caddy）可能用 IPv4 或 IPv6 回环地址连过来
LOOPBACK_PROXIES = {'127.0.0.1', '::1'}

# Cloudflare 公布的边缘节点网段（来源 https://www.cloudflare.com/ips/）。
# 只有直连方确实是 Cloudflare 边缘节点时，才采信它写入的 CF-Connecting-IP，
# 防止源站被直接访问时攻击者伪造该头。
CLOUDFLARE_NETWORKS = tuple(ipaddress.ip_network(cidr) for cidr in (
    '173.245.48.0/20',
    '103.21.244.0/22',
    '103.22.200.0/22',
    '103.31.4.0/22',
    '141.101.64.0/18',
    '108.162.192.0/18',
    '190.93.240.0/20',
    '188.114.96.0/20',
    '197.234.240.0/22',
    '198.41.128.0/17',
    '162.158.0.0/15',
    '104.16.0.0/13',
    '104.24.0.0/14',
    '172.64.0.0/13',
    '131.0.72.0/22',
    '2400:cb00::/32',
    '2606:4700::/32',
    '2803:f800::/32',
    '2405:b500::/32',
    '2405:8100::/32',
    '2a06:98c0::/29',
    '2c0f:f248::/32',
))


def _is_cloudflare_ip(ip):
    """判断是否为 Cloudflare 边缘节点 IP。"""
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(address in network for network in CLOUDFLARE_NETWORKS
               if network.version == address.version)


def get_client_ip():
    """获取真实客户端 IP。

    链路可能是：Cloudflare -> Caddy(本机) -> waitress -> Flask。

    waitress 启动时用 trusted_proxy='127.0.0.1' 声明信任本机 Caddy，会把
    X-Forwarded-For 里 Caddy 追加的那一段解析成 request.remote_addr。
    但 Caddy 默认追加的是它的直连对端地址：
      * 没走 Cloudflare：对端就是用户真实 IP，直接可用；
      * 走了 Cloudflare：对端是 Cloudflare 边缘节点 IP，直接记录会得到
        “CF 边缘节点 IP”而不是用户真实 IP。

    Cloudflare 会在边缘覆盖写入 CF-Connecting-IP（用户真实 IP）。这里只在
    直连方确实是 Cloudflare 边缘节点，或来自本机 cloudflared/Caddy（回环）时
    才采信这个头，避免源站被直接访问时伪造。
    """
    ip = (request.remote_addr or '').strip()
    # 兜底：请求仍来自本机代理时（代理地址不是 127.0.0.1、trusted_proxy 没命中），
    # 自己去读 X-Forwarded-For —— 只取最后一段，因为 Caddy 把直连对端追加在最右侧，
    # 最左边是客户端可以随意伪造的，取它会往统计里灌假 IP。
    if ip in LOOPBACK_PROXIES:
        xff = request.headers.get('X-Forwarded-For', '')
        if xff:
            ip = xff.rsplit(',', 1)[-1].strip()

    cf_ip = (request.headers.get('CF-Connecting-IP') or '').strip()
    if cf_ip and (ip in LOOPBACK_PROXIES or _is_cloudflare_ip(ip)):
        try:
            ipaddress.ip_address(cf_ip)
        except ValueError:
            pass
        else:
            ip = cf_ip

    # 校验合法性，非法内容直接丢弃，避免垃圾数据进入统计
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return ''
    return ip


def record_view(path):
    """记录一次浏览，并顺便清理 7 天前的旧记录"""
    now = time.time()
    try:
        conn = sqlite3.connect(str(VIEWS_DB_PATH))
        conn.execute('INSERT INTO page_views (path, ip, timestamp) VALUES (?, ?, ?)',
                     (path, get_client_ip(), now))
        conn.execute('DELETE FROM page_views WHERE timestamp < ?', (now - 7 * 24 * 3600,))
        conn.commit()
        conn.close()
    except Exception:
        pass


init_views_db()


# ==================== IP 归属地查询 ====================
# 使用 ip-api.com 免费批量接口（无需 Key），结果做内存缓存，避免刷新 /admin 时重复查询。

_ip_location_cache = {}  # ip -> (location_str, cached_at)
_IP_LOCATION_CACHE_TTL = 24 * 3600


def _is_private_ip(ip):
    """判断是否为内网/本地地址，这类地址无法查询归属地（IPv4 / IPv6 都支持）"""
    if not ip:
        return True
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return (address.is_private or address.is_loopback or address.is_link_local
            or address.is_reserved or address.is_multicast or address.is_unspecified)


def lookup_ip_locations(ips):
    """批量查询 IP 归属地（国家/省/市 + 运营商），返回 {ip: 归属地字符串}"""
    result = {}
    now = time.time()
    to_query = []
    for ip in ips:
        if not ip or ip in result:
            continue
        if _is_private_ip(ip):
            result[ip] = '内网/本地'
            continue
        cached = _ip_location_cache.get(ip)
        if cached and now - cached[1] < _IP_LOCATION_CACHE_TTL:
            result[ip] = cached[0]
        else:
            to_query.append(ip)

    if to_query:
        try:
            payload = json.dumps([
                {'query': ip, 'fields': 'status,country,regionName,city,isp,query'}
                for ip in to_query[:100]
            ]).encode('utf-8')
            req = urllib.request.Request(
                'http://ip-api.com/batch?lang=zh-CN',
                data=payload,
                headers={'Content-Type': 'application/json'}
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode('utf-8'))
            for item in data:
                ip = item.get('query')
                if not ip:
                    continue
                if item.get('status') == 'success':
                    parts = [p for p in (item.get('country'), item.get('regionName'), item.get('city')) if p]
                    dedup = []
                    for p in parts:
                        if not dedup or dedup[-1] != p:
                            dedup.append(p)
                    loc = ' '.join(dedup) or '未知'
                    if item.get('isp'):
                        loc = f"{loc} · {item['isp']}"
                else:
                    loc = '未知'
                result[ip] = loc
                _ip_location_cache[ip] = (loc, now)
        except Exception:
            for ip in to_query:
                result.setdefault(ip, '查询失败')

    return result


# ==================== 广告页定时切换（内嵌，不再依赖外部进程切换） ====================
# 说明：以前由 switch.ps1 通过“杀掉/启动不同进程”在同一端口切换正常页面和广告页，
# 导致广告页展示期间 /admin 不可用。现在改为本进程常驻，内部用定时器切换展示内容，
# /admin 无论当前显示哪个页面都始终可访问。

SWITCH_PAGE_PATH = Path(__file__).resolve().parent / 'index.html'

AD_STATE = {'active': consume_next_start_mode()}
AD_MODE_ENDPOINTS = {'index', 'play', 'view', 'stream', 'download'}


def get_switch_wait_seconds(key, default):
    """从环境变量读取形如 `KEY=60*3` 的时长配置（秒）"""
    expr = os.getenv(key, '').strip()
    if re.fullmatch(r'\d+(\s*\*\s*\d+)*', expr):
        result = 1
        for part in expr.split('*'):
            result *= int(part.strip())
        if result > 0:
            return result
    return default


def switch_loop():
    """在“正常内容”和“广告页”之间定时切换"""
    while True:
        if AD_STATE['active']:
            time.sleep(get_switch_wait_seconds('Static_Page_Lasting', 180))
            AD_STATE['active'] = False
        else:
            time.sleep(get_switch_wait_seconds('No_Need_Login_Page_Lasting', 600))
            AD_STATE['active'] = True


if SWITCH_PAGE_PATH.exists():
    threading.Thread(target=switch_loop, daemon=True).start()


def render_switch_page():
    """直接读取 switch/index.html 的内容返回，保持单一数据源"""
    try:
        html = SWITCH_PAGE_PATH.read_text(encoding='utf-8')
    except Exception:
        html = '<h1>Service Unavailable</h1>'
    return Response(html, mimetype='text/html')


@app.before_request
def gate_ad_mode():
    """广告页展示期间，拦截浏览/播放/查看/下载类路由，其余（如 /admin）不受影响"""
    if AD_STATE['active'] and request.endpoint in AD_MODE_ENDPOINTS:
        record_view('/switch' + request.path)
        return render_switch_page()


def parse_oss_shared_directory(url):
    """如果 SHARED_DIRECTORY 是一个阿里云 OSS 的 URL，解析出 (endpoint, bucket, prefix)，否则返回 None"""
    if not url.lower().startswith(('http://', 'https://')):
        return None
    parsed = urlparse(url)
    host_parts = parsed.netloc.split('.', 1)
    if len(host_parts) != 2 or 'aliyuncs.com' not in host_parts[1]:
        return None
    bucket = host_parts[0]
    endpoint = host_parts[1]
    prefix = unquote(parsed.path).lstrip('/')
    if prefix and not prefix.endswith('/'):
        prefix += '/'
    return {'endpoint': endpoint, 'bucket': bucket, 'prefix': prefix}


OSS_CONFIG = parse_oss_shared_directory(CONFIG['SHARED_DIRECTORY'])
USE_OSS = OSS_CONFIG is not None

_oss_bucket = None


def get_oss_bucket():
    """获取（并缓存）OSS Bucket 客户端。优先使用 .env 中的 AccessKey，未配置则匿名访问（适用于 public-read 的桶）"""
    global _oss_bucket
    if _oss_bucket is None:
        ak = os.getenv('OSS_ACCESS_KEY_ID')
        sk = os.getenv('OSS_ACCESS_KEY_SECRET')
        auth = oss2.Auth(ak, sk) if ak and sk else oss2.AnonymousAuth()
        _oss_bucket = oss2.Bucket(auth, f"https://{OSS_CONFIG['endpoint']}", OSS_CONFIG['bucket'])
    return _oss_bucket


def get_safe_oss_key(relative_path):
    """获取安全的 OSS Object Key，防止路径遍历"""
    relative_path = relative_path.replace('\\', '/').strip('/')
    if '..' in relative_path.split('/'):
        abort(403)
    return OSS_CONFIG['prefix'] + relative_path


def get_oss_parent_prefix(key):
    """获取某个 OSS key 所在的父级前缀（相当于所在目录）"""
    idx = key.rfind('/')
    return key[:idx + 1] if idx >= 0 else ''


def get_directory_contents_oss(prefix):
    """获取 OSS 上某个前缀（虚拟目录）下的内容"""
    items = []
    bucket = get_oss_bucket()
    try:
        for obj in oss2.ObjectIterator(bucket, prefix=prefix, delimiter='/'):
            if obj.is_prefix():
                name = obj.key[len(prefix):].rstrip('/')
                if not name:
                    continue
                items.append({
                    'name': name,
                    'is_dir': True,
                    'size': 0,
                    'path': obj.key[len(OSS_CONFIG['prefix']):].rstrip('/'),
                    'file_type': None
                })
            else:
                if obj.key == prefix:
                    continue
                name = obj.key[len(prefix):]
                if not name:
                    continue
                items.append({
                    'name': name,
                    'is_dir': False,
                    'size': obj.size,
                    'path': obj.key[len(OSS_CONFIG['prefix']):],
                    'file_type': get_file_type(name)
                })
    except oss2.exceptions.OssError as e:
        flash(f'读取 OSS 目录失败: {e}', 'error')
    items.sort(key=lambda x: (not x['is_dir'], x['name'].lower()))
    return items


def get_oss_media_playlist(filepath, wanted_type):
    """获取 OSS 上与 filepath 同目录、且类型为 wanted_type 的文件列表（播放列表）"""
    key = get_safe_oss_key(filepath)
    parent_prefix = get_oss_parent_prefix(key)
    playlist = []
    current_index = 0
    for item in get_directory_contents_oss(parent_prefix):
        if not item['is_dir'] and item['file_type'] == wanted_type:
            playlist.append({'name': item['name'], 'path': item['path']})
            if item['path'] == filepath.replace('\\', '/').strip('/'):
                current_index = len(playlist) - 1
    return playlist, current_index


def get_oss_signed_url(filepath, as_attachment=False, expires=3600):
    """生成 OSS 对象的签名直链，让浏览器直接从 OSS 拉取数据（而不是经由本服务器中转）"""
    key = get_safe_oss_key(filepath)
    bucket = get_oss_bucket()

    try:
        bucket.head_object(key)
    except oss2.exceptions.NoSuchKey:
        abort(404)
    except oss2.exceptions.OssError:
        abort(404)

    params = {}
    if as_attachment:
        filename = Path(filepath).name
        params['response-content-disposition'] = f"attachment; filename*=UTF-8''{quote(filename)}"

    return bucket.sign_url('GET', key, expires, params=params, slash_safe=True)


def get_safe_path(relative_path):
    """获取安全的文件路径，防止路径遍历攻击"""
    base_path = Path(CONFIG['SHARED_DIRECTORY']).resolve()
    target_path = (base_path / relative_path).resolve()

    # 确保目标路径在共享目录内
    if not str(target_path).startswith(str(base_path)):
        abort(403)

    return target_path


def get_directory_contents(path):
    """获取目录内容"""
    items = []
    try:
        for item in sorted(path.iterdir(), key=lambda x: (not x.is_dir(), x.name.lower())):
            relative_path = item.relative_to(CONFIG['SHARED_DIRECTORY'])
            file_type = get_file_type(item.name) if item.is_file() else None
            items.append({
                'name': item.name,
                'is_dir': item.is_dir(),
                'size': item.stat().st_size if item.is_file() else 0,
                'path': str(relative_path).replace('\\', '/'),
                'file_type': file_type
            })
    except PermissionError:
        flash('没有权限访问此目录', 'error')
    return items


def format_size(size):
    """格式化文件大小"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024.0:
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{size:.2f} PB"


def get_file_type(filename):
    """根据文件扩展名判断文件类型"""
    ext = Path(filename).suffix.lower()

    # 音频文件
    audio_exts = ['.mp3', '.wav', '.ogg', '.m4a', '.aac', '.flac', '.wma']
    if ext in audio_exts:
        return 'audio'

    # 视频文件
    video_exts = ['.mp4', '.webm', '.ogg', '.avi', '.mov', '.mkv', '.flv']
    if ext in video_exts:
        return 'video'

    # 图片文件
    image_exts = ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp', '.svg']
    if ext in image_exts:
        return 'image'

    # PDF文件
    if ext == '.pdf':
        return 'pdf'

    return 'other'


app.jinja_env.filters['format_size'] = format_size


def admin_required(f):
    """要求管理员登录才能访问"""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('is_admin'):
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated


@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    """管理员登录"""
    if request.method == 'POST':
        password = request.form.get('password', '')
        if password == CONFIG['ADMIN_PASSWORD']:
            session['is_admin'] = True
            return redirect(url_for('admin'))
        flash('密码错误', 'error')
    return render_template('admin_login.html')


@app.route('/admin/logout')
def admin_logout():
    """管理员退出登录"""
    session.pop('is_admin', None)
    return redirect(url_for('admin_login'))


@app.route('/admin')
@admin_required
def admin():
    """管理页面：展示最近 24 小时的浏览量统计"""
    now = time.time()
    day_ago = now - 24 * 3600

    conn = sqlite3.connect(str(VIEWS_DB_PATH))
    conn.row_factory = sqlite3.Row

    total_24h = conn.execute(
        'SELECT COUNT(*) c FROM page_views WHERE timestamp >= ?', (day_ago,)
    ).fetchone()['c']
    # 排除 ip = ''（get_client_ip 解析失败时的占位值），否则空串会被当成
    # 一个"独立 IP"多记一个，和下面列表里显示的 IP 对不上。
    unique_ip_24h = conn.execute(
        "SELECT COUNT(DISTINCT ip) c FROM page_views WHERE timestamp >= ? AND ip <> ''",
        (day_ago,)
    ).fetchone()['c']
    total_all = conn.execute('SELECT COUNT(*) c FROM page_views').fetchone()['c']

    # 最近 24 小时，按小时统计浏览量
    hourly = []
    for i in range(23, -1, -1):
        hour_start = now - (i + 1) * 3600
        hour_end = now - i * 3600
        c = conn.execute(
            'SELECT COUNT(*) c FROM page_views WHERE timestamp >= ? AND timestamp < ?',
            (hour_start, hour_end)
        ).fetchone()['c']
        hourly.append({
            'label': format_beijing_time(hour_end, '%H:00'),
            'count': c
        })
    max_hourly = max((h['count'] for h in hourly), default=0)

    # 最近 24 小时出现过的独立 IP（按访问次数排序）。上面的"独立 IP 数"就是
    # 这张表的行数，两个数字从此可以对上。
    # 归属地统一用 ip2region 离线库（data/ip2region_v4.xdb + v6.xdb）解析，
    # 纯内存查询，可以一次算完所有 IP；/admin/ip_location 的 ip-api.com
    # 查询方式仍然保留，页面上的「API 查询」按钮继续可用。
    unique_ip_rows = conn.execute(
        """SELECT ip, COUNT(*) c, MAX(timestamp) t
           FROM page_views
           WHERE timestamp >= ? AND ip <> ''
           GROUP BY ip
           ORDER BY c DESC""",
        (day_ago,)
    ).fetchall()
    conn.close()

    unique_ips = []
    hangzhou_ip_24h = zhejiang_ip_24h = china_ip_24h = 0
    for row in unique_ip_rows:
        region = ip2region_lookup(row['ip'])
        in_hangzhou = ip2region_is_hangzhou(region)
        in_zhejiang = ip2region_is_zhejiang(region)
        in_china = ip2region_is_china(region)
        if in_hangzhou:
            hangzhou_ip_24h += 1
        if in_zhejiang:
            zhejiang_ip_24h += 1
        if in_china:
            china_ip_24h += 1
        if in_hangzhou:
            scope = 'hz'
        elif in_zhejiang:
            scope = 'zj'
        elif in_china:
            scope = 'cn'
        else:
            scope = 'other'
        unique_ips.append({
            'ip': row['ip'],
            'count': row['c'],
            'last_time': format_beijing_time(row['t']),
            'region': region['display'],
            'scope': scope,
        })

    return render_template('admin.html',
                         total_24h=total_24h,
                         unique_ip_24h=unique_ip_24h,
                         hangzhou_ip_24h=hangzhou_ip_24h,
                         zhejiang_ip_24h=zhejiang_ip_24h,
                         china_ip_24h=china_ip_24h,
                         total_all=total_all,
                         hourly=hourly,
                         max_hourly=max_hourly,
                         unique_ips=unique_ips)


@app.route('/admin/ip_location')
@admin_required
def admin_ip_location():
    """按需查询单个 IP 的归属地（管理页点击按钮时通过 AJAX 调用）"""
    ip = request.args.get('ip', '').strip()
    if not ip:
        return {'location': ''}, 400
    return {'location': lookup_ip_locations([ip]).get(ip, '未知')}


@app.route('/admin/whoami')
@admin_required
def admin_whoami():
    """排查用：显示服务器实际收到的转发头和解析出的客户端 IP。

    用手机流量（不要用 WiFi）打开 /admin/whoami，即可确认真实 IP 有没有传到。

    * `cf_connecting_ip`：Cloudflare 边缘写入的用户真实 IP（没走 CF 时为空）。
    * `remote_addr`：waitress 按 X-Forwarded-For 解析后的直连对端。
      走了 Cloudflare + Caddy 时，这里通常是一个 Cloudflare 边缘节点 IP。
    * `client_ip`：最终用于统计的 IP。直连方是 Cloudflare 边缘或本机
      cloudflared/Caddy 时，会优先采用 `cf_connecting_ip`。
    * `cloudflare_edge`：remote_addr 是否落在 Cloudflare 网段内。

    如果 client_ip 和手机流量的实际公网 IP 一致，说明解析正确。
    """
    forwarded = {
        k: v for k, v in request.headers.items()
        if k.lower().startswith('x-')
        or k.lower() in ('cf-connecting-ip', 'true-client-ip', 'cf-ray')
    }
    return {
        'client_ip': get_client_ip(),
        'remote_addr': request.remote_addr,
        'cf_connecting_ip': request.headers.get('CF-Connecting-IP', ''),
        'cloudflare_edge': _is_cloudflare_ip(request.remote_addr or ''),
        'forwarded_headers': forwarded,
    }


@app.route('/')
@app.route('/browse/')
@app.route('/browse/<path:subpath>')
def index(subpath=''):
    """浏览目录"""
    record_view('/' + subpath if subpath else '/')
    if USE_OSS:
        prefix = get_safe_oss_key(subpath)
        if prefix and not prefix.endswith('/'):
            prefix += '/'
        items = get_directory_contents_oss(prefix)
    else:
        current_path = get_safe_path(subpath)

        if not current_path.exists():
            flash('路径不存在', 'error')
            return redirect(url_for('index'))

        if current_path.is_file():
            # 如果是文件，重定向到父目录
            return redirect(url_for('index'))

        # 获取目录内容
        items = get_directory_contents(current_path)

    # 构建面包屑导航
    breadcrumbs = []
    parts = Path(subpath).parts if subpath else []
    for i, part in enumerate(parts):
        breadcrumbs.append({
            'name': part,
            'path': '/'.join(parts[:i+1])
        })

    return render_template('index.html',
                         items=items,
                         current_path=subpath,
                         breadcrumbs=breadcrumbs)


@app.route('/play/<path:filepath>')
def play(filepath):
    """播放音频/视频文件"""
    record_view('/play/' + filepath)
    if USE_OSS:
        key = get_safe_oss_key(filepath)
        try:
            get_oss_bucket().head_object(key)
        except oss2.exceptions.OssError:
            abort(404)

        file_type = get_file_type(filepath)
        if file_type not in ['audio', 'video']:
            flash('此文件类型不支持在线播放', 'error')
            return redirect(url_for('index'))

        playlist, current_index = get_oss_media_playlist(filepath, file_type)

        return render_template('player.html',
                             filename=Path(filepath).name,
                             filepath=filepath,
                             file_type=file_type,
                             playlist=playlist,
                             current_index=current_index)

    file_path = get_safe_path(filepath)

    if not file_path.exists() or not file_path.is_file():
        abort(404)

    file_type = get_file_type(file_path.name)

    if file_type not in ['audio', 'video']:
        flash('此文件类型不支持在线播放', 'error')
        return redirect(url_for('index'))

    # 获取同一目录下的所有媒体文件
    parent_dir = file_path.parent
    playlist = []
    current_index = 0

    try:
        for idx, item in enumerate(sorted(parent_dir.iterdir(), key=lambda x: x.name.lower())):
            if item.is_file():
                item_type = get_file_type(item.name)
                if item_type == file_type:  # 只添加相同类型的文件（音频或视频）
                    relative_path = item.relative_to(CONFIG['SHARED_DIRECTORY'])
                    playlist.append({
                        'name': item.name,
                        'path': str(relative_path).replace('\\', '/')
                    })
                    if item == file_path:
                        current_index = len(playlist) - 1
    except PermissionError:
        pass

    return render_template('player.html',
                         filename=file_path.name,
                         filepath=filepath,
                         file_type=file_type,
                         playlist=playlist,
                         current_index=current_index)


@app.route('/view/<path:filepath>')
def view(filepath):
    """查看图片文件"""
    record_view('/view/' + filepath)
    if USE_OSS:
        key = get_safe_oss_key(filepath)
        try:
            get_oss_bucket().head_object(key)
        except oss2.exceptions.OssError:
            abort(404)

        if get_file_type(filepath) != 'image':
            flash('此文件类型不支持查看', 'error')
            return redirect(url_for('index'))

        playlist, current_index = get_oss_media_playlist(filepath, 'image')

        return render_template('viewer.html',
                             filename=Path(filepath).name,
                             filepath=filepath,
                             playlist=playlist,
                             current_index=current_index)

    file_path = get_safe_path(filepath)

    if not file_path.exists() or not file_path.is_file():
        abort(404)

    file_type = get_file_type(file_path.name)

    if file_type != 'image':
        flash('此文件类型不支持查看', 'error')
        return redirect(url_for('index'))

    # 获取同一目录下的所有图片文件
    parent_dir = file_path.parent
    playlist = []
    current_index = 0

    try:
        for idx, item in enumerate(sorted(parent_dir.iterdir(), key=lambda x: x.name.lower())):
            if item.is_file():
                item_type = get_file_type(item.name)
                if item_type == 'image':  # 只添加图片文件
                    relative_path = item.relative_to(CONFIG['SHARED_DIRECTORY'])
                    playlist.append({
                        'name': item.name,
                        'path': str(relative_path).replace('\\', '/')
                    })
                    if item == file_path:
                        current_index = len(playlist) - 1
    except PermissionError:
        pass

    return render_template('viewer.html',
                         filename=file_path.name,
                         filepath=filepath,
                         playlist=playlist,
                         current_index=current_index)


@app.route('/stream/<path:filepath>')
def stream(filepath):
    """流式传输媒体文件（无需登录，公开访问）"""
    if USE_OSS:
        return redirect(get_oss_signed_url(filepath, as_attachment=False))

    file_path = get_safe_path(filepath)

    if not file_path.exists() or not file_path.is_file():
        abort(404)

    return send_file(file_path, as_attachment=False)


@app.route('/download/<path:filepath>')
def download(filepath):
    """下载文件（无需登录，公开访问）"""
    if USE_OSS:
        return redirect(get_oss_signed_url(filepath, as_attachment=True))

    file_path = get_safe_path(filepath)

    if not file_path.exists() or not file_path.is_file():
        abort(404)

    return send_file(file_path, as_attachment=True)


APK_FILE = Path(__file__).resolve().parent.parent / 'androidApp' / 'app' / 'build' / 'outputs' / 'apk' / 'debug' / 'app-debug.apk'


@app.route('/app-debug.apk')
def download_apk():
    """下载安卓 App 安装包（无需登录）"""
    if not APK_FILE.is_file():
        abort(404)
    return send_file(APK_FILE, as_attachment=True, download_name='app-debug.apk',
                     mimetype='application/vnd.android.package-archive')


if __name__ == '__main__':
    if USE_OSS:
        print(f"共享目录来自阿里云 OSS: bucket={OSS_CONFIG['bucket']}, endpoint={OSS_CONFIG['endpoint']}, prefix={OSS_CONFIG['prefix']}")
        if not (os.getenv('OSS_ACCESS_KEY_ID') and os.getenv('OSS_ACCESS_KEY_SECRET')):
            print("未配置 OSS_ACCESS_KEY_ID / OSS_ACCESS_KEY_SECRET，将以匿名方式访问（要求该 Bucket/前缀允许公开读取和列举）")
    else:
        # 确保共享目录存在
        shared_dir = Path(CONFIG['SHARED_DIRECTORY'])
        if not shared_dir.exists():
            shared_dir.mkdir(parents=True)
            print(f"已创建共享目录: {shared_dir}")

    print("=" * 50)
    print("        文件共享服务器（免登录版）")
    print("=" * 50)
    print(f"共享目录: {CONFIG['SHARED_DIRECTORY']}")
    print("\n访问地址:")
    print(f"  本机: http://127.0.0.1:{CONFIG['PORT']}")
    print(f"  局域网: http://<你的IP地址>:{CONFIG['PORT']}")
    print("\n按 Ctrl+C 停止服务器")
    print("=" * 50)
    print()

    # 调试模式开关：保留下面其中一行，另一行用快捷键（VS Code 默认 Ctrl+/）注释掉即可切换
    # DEBUG_MODE = True
    DEBUG_MODE = False

    if DEBUG_MODE:
        # 开发模式：Flask 自带调试服务器，支持代码热重载和调试报错页
        app.run(host=CONFIG['HOST'], port=CONFIG['PORT'], debug=True, threaded=True)
    else:
        # 生产模式：waitress WSGI 服务器，多线程并发处理请求
        # 必须告诉 waitress 本机 Caddy 是可信代理，否则它会把 X-Forwarded-For
        # 整个丢掉，我们永远拿不到访客 IP（见 get_client_ip 注释）。
        # trusted_proxy_count=1 表示只取 XFF 最后一段，也就是 Caddy 的直连对端。
        # 如果前面还有 Cloudflare，这一段会是 CF 边缘节点 IP，get_client_ip
        # 会再根据 CF-Connecting-IP 还原成用户真实 IP。
        try:
            serve(app, host=CONFIG['HOST'], port=CONFIG['PORT'], threads=8,
                  trusted_proxy='127.0.0.1',
                  trusted_proxy_count=1,
                  trusted_proxy_headers={'x-forwarded-for'},
                  # 保留 XFF 头本身不清理：万一代理回环地址不是 127.0.0.1（如走 ::1），
                  # get_client_ip 里的兜底分支仍能取到
                  clear_untrusted_proxy_headers=False)
        except TypeError:
            # waitress 1.x 不认识这些代理参数；它本来也不清理 X-Forwarded-For，
            # get_client_ip 的兜底分支依然能拿到真实 IP，所以退回原样启动即可
            serve(app, host=CONFIG['HOST'], port=CONFIG['PORT'], threads=8)

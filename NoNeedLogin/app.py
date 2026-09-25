import os
import re
import json
import sqlite3
import time
import threading
import urllib.request
from functools import wraps
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse, unquote, quote
from flask import Flask, render_template, send_file, redirect, url_for, flash, abort, request, session, Response
from dotenv import load_dotenv
from waitress import serve
import oss2

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
    conn.commit()
    conn.close()


def get_client_ip():
    """获取真实客户端 IP。
    通过 Cloudflare Tunnel 部署时，Flask 收到的 TCP 连接来自本地的 cloudflared
    进程（remote_addr 恒为 127.0.0.1），真实 IP 由 Cloudflare 边缘节点写入
    CF-Connecting-IP 请求头，因此优先读取该头，其次回退到 X-Forwarded-For。
    """
    return (request.headers.get('CF-Connecting-IP')
            or request.headers.get('X-Forwarded-For', '').split(',')[0].strip()
            or request.remote_addr)


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
    """判断是否为内网/本地地址，这类地址无法查询归属地"""
    if not ip:
        return True
    if ip in ('127.0.0.1', 'localhost', '::1'):
        return True
    parts = ip.split('.')
    if len(parts) == 4:
        try:
            a, b = int(parts[0]), int(parts[1])
        except ValueError:
            return False
        if a == 10 or a == 127:
            return True
        if a == 172 and 16 <= b <= 31:
            return True
        if a == 192 and b == 168:
            return True
    return False


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

AD_STATE = {'active': False}
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
        AD_STATE['active'] = False
        time.sleep(get_switch_wait_seconds('No_Need_Login_Page_Lasting', 600))
        AD_STATE['active'] = True
        time.sleep(get_switch_wait_seconds('Static_Page_Lasting', 180))


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
            return redirect(url_for('admin_login', next=request.path))
        return f(*args, **kwargs)
    return decorated


@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    """管理员登录"""
    if request.method == 'POST':
        password = request.form.get('password', '')
        if password == CONFIG['ADMIN_PASSWORD']:
            session['is_admin'] = True
            next_url = request.form.get('next') or url_for('admin')
            return redirect(next_url)
        flash('密码错误', 'error')
    return render_template('admin_login.html', next=request.args.get('next', ''))


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
    unique_ip_24h = conn.execute(
        'SELECT COUNT(DISTINCT ip) c FROM page_views WHERE timestamp >= ?', (day_ago,)
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
            'label': datetime.fromtimestamp(hour_end).strftime('%H:00'),
            'count': c
        })
    max_hourly = max((h['count'] for h in hourly), default=0)

    recent_rows = conn.execute(
        'SELECT path, ip, timestamp FROM page_views ORDER BY timestamp DESC LIMIT 50'
    ).fetchall()
    conn.close()

    # 归属地不在此处批量查询，避免一次刷新触发大量请求撞到 ip-api.com 的限流；
    # 改为前端按需点击查询，见 /admin/ip_location 接口。
    recent_views = [{
        'path': row['path'],
        'ip': row['ip'],
        'time': datetime.fromtimestamp(row['timestamp']).strftime('%Y-%m-%d %H:%M:%S')
    } for row in recent_rows]

    return render_template('admin.html',
                         total_24h=total_24h,
                         unique_ip_24h=unique_ip_24h,
                         total_all=total_all,
                         hourly=hourly,
                         max_hourly=max_hourly,
                         recent_views=recent_views)


@app.route('/admin/ip_location')
@admin_required
def admin_ip_location():
    """按需查询单个 IP 的归属地（管理页点击按钮时通过 AJAX 调用）"""
    ip = request.args.get('ip', '').strip()
    if not ip:
        return {'location': ''}, 400
    return {'location': lookup_ip_locations([ip]).get(ip, '未知')}


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
        serve(app, host=CONFIG['HOST'], port=CONFIG['PORT'], threads=8)

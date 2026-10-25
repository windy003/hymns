import os
import sqlite3
import secrets
import re
import json
import time
import ipaddress
import urllib.request
from pathlib import Path
from functools import wraps
from datetime import timedelta, datetime, timezone
from urllib.parse import urlparse, unquote, quote
from flask import Flask, render_template, request, send_file, redirect, url_for, session, flash, abort, jsonify, g
from dotenv import load_dotenv
from waitress import serve
from werkzeug.security import check_password_hash, generate_password_hash
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
app.secret_key = os.getenv('SECRET_KEY', secrets.token_hex(16))

# 禁用模板缓存，确保每次都加载最新模板
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.jinja_env.auto_reload = True
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0

# 设置会话持久化时间为30天
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)

# 从环境变量读取配置
CONFIG = {
    'SHARED_DIRECTORY': os.getenv('SHARED_DIRECTORY', r'D:\shared'),
    'ADMIN_USERNAME': os.getenv('ADMIN_USERNAME', os.getenv('USERNAME', 'admin')),
    'ADMIN_PASSWORD': os.getenv('ADMIN_PASSWORD', os.getenv('PASSWORD', 'admin123')),
    'PORT': int(os.getenv('PORT', 5003)),
    'HOST': os.getenv('HOST', '0.0.0.0'),
    'DEBUG': os.getenv('DEBUG', 'True').lower() == 'true',
    'ALIYUN_ACCESS_KEY_ID': os.getenv('ALIBABA_CLOUD_ACCESS_KEY_ID', ''),
    'ALIYUN_ACCESS_KEY_SECRET': os.getenv('ALIBABA_CLOUD_ACCESS_KEY_SECRET', ''),
    'ALIYUN_SMS_SIGN_NAME': os.getenv('ALIYUN_SMS_SIGN_NAME', ''),
    'ALIYUN_SMS_TEMPLATE_CODE': os.getenv('ALIYUN_SMS_TEMPLATE_CODE', ''),
    'ALIYUN_SMS_SCHEME_NAME': os.getenv('ALIYUN_SMS_SCHEME_NAME', ''),
}

# 数据库路径
DB_PATH = Path(__file__).parent / 'users.db'

# 管理页展示的访问时间统一换算成北京时间（UTC+8），不依赖服务器本地时区。
# 数据库里存的是 time.time() 时间戳，本身不带时区。
BEIJING_TZ = timezone(timedelta(hours=8))


def format_beijing_time(timestamp, fmt='%m-%d %H:%M:%S'):
    """把 Unix 时间戳格式化为北京时间字符串。"""
    return datetime.fromtimestamp(timestamp, BEIJING_TZ).strftime(fmt)


def get_db():
    """获取数据库连接"""
    if 'db' not in g:
        g.db = sqlite3.connect(str(DB_PATH))
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception):
    db = g.pop('db', None)
    if db is not None:
        db.close()


def init_db():
    """初始化数据库，创建用户表并确保管理员账号存在"""
    db = sqlite3.connect(str(DB_PATH))
    db.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        is_admin INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL
    )''')

    # 迁移：添加 max_devices 列（如果不存在）
    cursor = db.execute("PRAGMA table_info(users)")
    columns = [col[1] for col in cursor.fetchall()]
    if 'max_devices' not in columns:
        db.execute('ALTER TABLE users ADD COLUMN max_devices INTEGER NOT NULL DEFAULT 1')

    # 创建会话表
    db.execute('''CREATE TABLE IF NOT EXISTS sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id TEXT UNIQUE NOT NULL,
        username TEXT NOT NULL,
        device_info TEXT DEFAULT '',
        ip_address TEXT DEFAULT '',
        is_active INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL,
        last_active TEXT NOT NULL
    )''')

    db.execute('''CREATE TABLE IF NOT EXISTS phone_accounts (
        phone TEXT PRIMARY KEY,
        is_approved INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL,
        approved_at TEXT
    )''')

    # 浏览量统计表（记录浏览动作的路径、来访 IP、登录名、时间戳）
    db.execute('''CREATE TABLE IF NOT EXISTS page_views (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        path TEXT NOT NULL,
        ip TEXT,
        client_ip TEXT DEFAULT '',
        username TEXT DEFAULT '',
        timestamp REAL NOT NULL
    )''')
    db.execute('CREATE INDEX IF NOT EXISTS idx_page_views_timestamp ON page_views (timestamp)')

    # 迁移：老库补 username / client_ip 列
    # client_ip 保存 Cloudflare 写入的用户真实 IP（CF-Connecting-IP），
    # 老数据没有这一列，补成空字符串，展示时回退到 ip。
    cursor = db.execute("PRAGMA table_info(page_views)")
    columns = [col[1] for col in cursor.fetchall()]
    if 'username' not in columns:
        db.execute("ALTER TABLE page_views ADD COLUMN username TEXT DEFAULT ''")
    if 'client_ip' not in columns:
        db.execute("ALTER TABLE page_views ADD COLUMN client_ip TEXT DEFAULT ''")

    # 确保管理员账号存在
    admin = db.execute('SELECT id FROM users WHERE username = ?',
                       (CONFIG['ADMIN_USERNAME'],)).fetchone()
    if not admin:
        db.execute('INSERT INTO users (username, password, is_admin, created_at, max_devices) VALUES (?, ?, 1, ?, 1)',
                   (CONFIG['ADMIN_USERNAME'],
                    generate_password_hash(CONFIG['ADMIN_PASSWORD']),
                    datetime.now().isoformat()))
        print(f"已创建管理员账号: {CONFIG['ADMIN_USERNAME']}")
    db.commit()
    db.close()

# Token 存储 (username -> token 映射)
# 在生产环境中应该使用数据库,这里为了简单使用内存字典
USER_TOKENS = {}


def generate_stream_token(username):
    """为用户生成流媒体访问 token"""
    token = secrets.token_urlsafe(32)  # 生成安全的随机 token
    USER_TOKENS[username] = {
        'token': token,
        'created_at': datetime.now()
    }
    return token


def verify_stream_token(token):
    """验证 token 是否有效"""
    if not token:
        return False

    # 检查 token 是否存在且未过期(7天有效期)
    for username, token_data in USER_TOKENS.items():
        if token_data['token'] == token:
            # 检查是否过期
            if datetime.now() - token_data['created_at'] < timedelta(days=7):
                return True
            else:
                # Token 过期,删除它
                del USER_TOKENS[username]
                return False

    return False


# ============ 会话管理 ============

def create_session(db, username, device_info='', ip_address=''):
    """创建新的会话记录，返回 session_id"""
    session_id = secrets.token_urlsafe(32)
    now = datetime.now().isoformat()
    db.execute(
        'INSERT INTO sessions (session_id, username, device_info, ip_address, created_at, last_active) '
        'VALUES (?, ?, ?, ?, ?, ?)',
        (session_id, username, device_info, ip_address, now, now)
    )
    db.commit()
    return session_id


def get_active_session_count(db, username):
    """获取用户当前活跃会话数"""
    row = db.execute(
        'SELECT COUNT(*) FROM sessions WHERE username = ? AND is_active = 1',
        (username,)
    ).fetchone()
    return row[0]


def get_active_sessions(db, username):
    """获取用户所有活跃会话"""
    return db.execute(
        'SELECT * FROM sessions WHERE username = ? AND is_active = 1 ORDER BY created_at DESC',
        (username,)
    ).fetchall()


def kick_oldest_sessions(db, username, count):
    """踢出用户最旧的 N 个会话（设为不活跃）"""
    if count <= 0:
        return
    oldest = db.execute(
        'SELECT session_id FROM sessions WHERE username = ? AND is_active = 1 '
        'ORDER BY created_at ASC LIMIT ?',
        (username, count)
    ).fetchall()
    for row in oldest:
        db.execute(
            'UPDATE sessions SET is_active = 0 WHERE session_id = ?',
            (row['session_id'],)
        )
    db.commit()


def deactivate_session(db, session_id):
    """停用指定会话"""
    db.execute(
        'UPDATE sessions SET is_active = 0 WHERE session_id = ?',
        (session_id,)
    )
    db.commit()


def login_required(f):
    """登录验证装饰器"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    """管理员验证装饰器"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        if not session.get('is_admin'):
            abort(403)
        return f(*args, **kwargs)
    return decorated_function


@app.before_request
def validate_session():
    """在每个请求前验证当前会话是否仍有效（未被踢出）"""
    # 跳过不需要会话验证的端点
    if request.endpoint in ('login', 'stream', 'static'):
        return

    if session.get('logged_in') and session.get('session_token'):
        db = get_db()
        sess = db.execute(
            'SELECT is_active FROM sessions WHERE session_id = ? AND username = ?',
            (session['session_token'], session['username'])
        ).fetchone()

        if not sess or not sess['is_active']:
            # 会话已被踢出或不存在，清除登录状态
            session.pop('logged_in', None)
            session.pop('username', None)
            session.pop('is_admin', None)
            session.pop('session_token', None)
            flash('您的账号已在其他设备登录，当前会话已被强制退出。', 'error')
        else:
            # 更新最后活跃时间
            db.execute(
                'UPDATE sessions SET last_active = ? WHERE session_id = ?',
                (datetime.now().isoformat(), session['session_token'])
            )
            db.commit()


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


def parse_oss_shared_directory(value):
    """Parse an Aliyun OSS URL from SHARED_DIRECTORY into endpoint, bucket, and prefix."""
    if not value.lower().startswith(('http://', 'https://')):
        return None
    parsed = urlparse(value)
    host_parts = parsed.netloc.split('.', 1)
    if len(host_parts) != 2 or 'aliyuncs.com' not in host_parts[1]:
        return None
    prefix = unquote(parsed.path).lstrip('/')
    if prefix and not prefix.endswith('/'):
        prefix += '/'
    return {'bucket': host_parts[0], 'endpoint': host_parts[1], 'prefix': prefix}


OSS_CONFIG = parse_oss_shared_directory(CONFIG['SHARED_DIRECTORY'])
USE_OSS = OSS_CONFIG is not None
_oss_bucket = None


def get_oss_bucket():
    """Return a cached OSS bucket client using the dedicated OSS credentials."""
    global _oss_bucket
    if _oss_bucket is None:
        access_key_id = os.getenv('OSS_ACCESS_KEY_ID', '')
        access_key_secret = os.getenv('OSS_ACCESS_KEY_SECRET', '')
        auth = (oss2.Auth(access_key_id, access_key_secret)
                if access_key_id and access_key_secret else oss2.AnonymousAuth())
        _oss_bucket = oss2.Bucket(
            auth, f"https://{OSS_CONFIG['endpoint']}", OSS_CONFIG['bucket']
        )
    return _oss_bucket


def get_safe_oss_key(relative_path):
    relative_path = relative_path.replace('\\', '/').strip('/')
    if '..' in relative_path.split('/'):
        abort(403)
    return OSS_CONFIG['prefix'] + relative_path


def get_oss_parent_prefix(key):
    idx = key.rfind('/')
    return key[:idx + 1] if idx >= 0 else ''


def get_directory_contents_oss(prefix):
    items = []
    try:
        for obj in oss2.ObjectIterator(get_oss_bucket(), prefix=prefix, delimiter='/'):
            if obj.is_prefix():
                name = obj.key[len(prefix):].rstrip('/')
                if name:
                    items.append({
                        'name': name, 'is_dir': True, 'size': 0,
                        'path': obj.key[len(OSS_CONFIG['prefix']):].rstrip('/'),
                        'file_type': None,
                    })
            elif obj.key != prefix:
                name = obj.key[len(prefix):]
                if name:
                    items.append({
                        'name': name, 'is_dir': False, 'size': obj.size,
                        'path': obj.key[len(OSS_CONFIG['prefix']):],
                        'file_type': get_file_type(name),
                    })
    except oss2.exceptions.OssError:
        app.logger.exception('Failed to list OSS directory')
        flash('读取阿里云 OSS 目录失败，请检查 OSS 配置和访问权限', 'error')
    items.sort(key=lambda item: (not item['is_dir'], item['name'].lower()))
    return items


def get_oss_media_playlist(filepath, wanted_type):
    key = get_safe_oss_key(filepath)
    parent_prefix = get_oss_parent_prefix(key)
    playlist = []
    current_index = 0
    normalized_path = filepath.replace('\\', '/').strip('/')
    for item in get_directory_contents_oss(parent_prefix):
        if not item['is_dir'] and item['file_type'] == wanted_type:
            playlist.append({'name': item['name'], 'path': item['path']})
            if item['path'] == normalized_path:
                current_index = len(playlist) - 1
    return playlist, current_index


def get_oss_signed_url(filepath, as_attachment=False, expires=3600):
    key = get_safe_oss_key(filepath)
    bucket = get_oss_bucket()
    try:
        bucket.head_object(key)
    except oss2.exceptions.OssError:
        abort(404)
    params = {}
    if as_attachment:
        params['response-content-disposition'] = (
            f"attachment; filename*=UTF-8''{quote(Path(filepath).name)}"
        )
    return bucket.sign_url('GET', key, expires, params=params, slash_safe=True)


def aliyun_client():
    """Create Alibaba Cloud Phone Number Verification Service client."""
    if not CONFIG['ALIYUN_ACCESS_KEY_ID'] or not CONFIG['ALIYUN_ACCESS_KEY_SECRET']:
        raise RuntimeError('未配置阿里云 AccessKey')
    from alibabacloud_dypnsapi20170525.client import Client as DypnsClient
    from alibabacloud_tea_openapi import models as open_api_models

    config = open_api_models.Config(
        access_key_id=CONFIG['ALIYUN_ACCESS_KEY_ID'],
        access_key_secret=CONFIG['ALIYUN_ACCESS_KEY_SECRET'],
    )
    config.endpoint = 'dypnsapi.aliyuncs.com'
    return DypnsClient(config)


def send_phone_code(phone):
    if not CONFIG['ALIYUN_SMS_SIGN_NAME'] or not CONFIG['ALIYUN_SMS_TEMPLATE_CODE']:
        raise RuntimeError('未配置阿里云短信签名或模板')
    from alibabacloud_dypnsapi20170525 import models as dypns_models
    from alibabacloud_tea_util import models as util_models

    request_data = dypns_models.SendSmsVerifyCodeRequest(
        phone_number=phone,
        country_code='86',
        sign_name=CONFIG['ALIYUN_SMS_SIGN_NAME'],
        template_code=CONFIG['ALIYUN_SMS_TEMPLATE_CODE'],
        template_param=json.dumps({'code': '##code##', 'min': '5'}),
        code_length=6,
        valid_time=300,
        interval=60,
        code_type=1,
        scheme_name=CONFIG['ALIYUN_SMS_SCHEME_NAME'] or None,
    )
    response = aliyun_client().send_sms_verify_code_with_options(
        request_data, util_models.RuntimeOptions()
    )
    body = response.body
    if not body.success or body.code != 'OK':
        raise RuntimeError('阿里云短信发送失败')


def verify_phone_code(phone, code):
    from alibabacloud_dypnsapi20170525 import models as dypns_models
    from alibabacloud_tea_util import models as util_models

    request_data = dypns_models.CheckSmsVerifyCodeRequest(
        phone_number=phone,
        country_code='86',
        verify_code=code,
        scheme_name=CONFIG['ALIYUN_SMS_SCHEME_NAME'] or None,
        case_auth_policy=1,
    )
    response = aliyun_client().check_sms_verify_code_with_options(
        request_data, util_models.RuntimeOptions()
    )
    body = response.body
    model = body.model
    return bool(body.success and body.code == 'OK' and model and model.verify_result == 'PASS')


def finish_login(db, username, is_admin, max_devices):
    if max_devices > 0:
        active_count = get_active_session_count(db, username)
        if active_count >= max_devices:
            kick_oldest_sessions(db, username, active_count - max_devices + 1)

    device_info = request.user_agent.string if request.user_agent else ''
    session_token = create_session(db, username, device_info, request.remote_addr or '')
    session.clear()
    session.permanent = True
    session['logged_in'] = True
    session['username'] = username
    session['is_admin'] = bool(is_admin)
    session['session_token'] = session_token
    generate_stream_token(username)


@app.route('/login', methods=['GET', 'POST'])
def login():
    """登录页面"""
    active_method = 'phone'
    if request.method == 'POST':
        db = get_db()
        method = request.form.get('auth_method', 'password')
        if method == 'phone':
            active_method = 'phone'
            phone = request.form.get('phone', '').strip()
            code = request.form.get('verify_code', '').strip()
            if not re.fullmatch(r'1[3-9]\d{9}', phone) or not re.fullmatch(r'\d{4,8}', code):
                flash('请输入有效手机号和短信验证码', 'error')
            else:
                approved = db.execute(
                    'SELECT is_approved FROM phone_accounts WHERE phone = ?', (phone,)
                ).fetchone()
                if not approved or not approved['is_approved']:
                    flash('此手机号未启用短信登录', 'error')
                else:
                    try:
                        if verify_phone_code(phone, code):
                            still_approved = db.execute(
                                'SELECT is_approved FROM phone_accounts WHERE phone = ?', (phone,)
                            ).fetchone()
                            if still_approved and still_approved['is_approved']:
                                finish_login(db, f'sms_{phone}', False, 1)
                                return redirect(url_for('index'))
                            flash('此手机号的登录权限已停用', 'error')
                        else:
                            flash('短信验证码错误或已过期', 'error')
                    except Exception as error:
                        if 'isv.ValidateFail' in str(error):
                            flash('验证码错误、已过期或已被新验证码覆盖，请重新获取并输入最新验证码', 'error')
                        else:
                            app.logger.exception('Aliyun SMS verification failed')
                            flash('短信验证码核验暂时不可用，请稍后再试', 'error')
        else:
            active_method = 'password'
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '')
            user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
            valid_password = False
            if user:
                stored_password = user['password']
                try:
                    valid_password = check_password_hash(stored_password, password)
                except (ValueError, TypeError):
                    valid_password = secrets.compare_digest(stored_password, password)
                    if valid_password:
                        db.execute('UPDATE users SET password = ? WHERE id = ?',
                                   (generate_password_hash(password), user['id']))
                        db.commit()

            if user and valid_password:
                finish_login(db, username, user['is_admin'], user['max_devices'])
                return redirect(url_for('index'))
            flash('用户名或密码错误', 'error')

    return render_template('login.html', active_method=active_method)


@app.route('/login/send-code', methods=['POST'])
def login_send_code():
    phone = request.form.get('phone', '').strip()
    if not re.fullmatch(r'1[3-9]\d{9}', phone):
        return jsonify(success=False, message='请输入有效的手机号'), 400
    approved = get_db().execute(
        'SELECT is_approved FROM phone_accounts WHERE phone = ?', (phone,)
    ).fetchone()
    if not approved or not approved['is_approved']:
        return jsonify(success=False, message='此手机号未启用短信登录'), 403
    try:
        send_phone_code(phone)
        return jsonify(success=True, message='验证码已发送')
    except Exception:
        app.logger.exception('Aliyun SMS send failed')
        return jsonify(success=False, message='验证码发送失败，请稍后再试'), 502


@app.route('/logout')
def logout():
    """登出"""
    session_token = session.get('session_token')
    if session_token:
        db = get_db()
        deactivate_session(db, session_token)
    session.clear()
    return redirect(url_for('login'))


@app.route('/api/get_stream_token')
@login_required
def get_stream_token_api():
    """获取流媒体访问 token (API)"""
    username = session.get('username')

    # 获取或生成 token
    if username in USER_TOKENS:
        token_data = USER_TOKENS[username]
        # 检查是否过期
        if datetime.now() - token_data['created_at'] < timedelta(days=7):
            token = token_data['token']
        else:
            # 过期了,生成新的
            token = generate_stream_token(username)
    else:
        # 没有 token,生成新的
        token = generate_stream_token(username)

    return jsonify({
        'success': True,
        'token': token,
        'expires_in_days': 7
    })


@app.route('/')
@app.route('/browse/')
@app.route('/browse/<path:subpath>')
@login_required
def index(subpath=''):
    """浏览目录"""
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
            return redirect(url_for('index'))

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
@login_required
def play(filepath):
    """播放音频/视频文件"""
    if USE_OSS:
        try:
            get_oss_bucket().head_object(get_safe_oss_key(filepath))
        except oss2.exceptions.OssError:
            abort(404)
        file_type = get_file_type(filepath)
        if file_type not in ['audio', 'video']:
            flash('此文件类型不支持在线播放', 'error')
            return redirect(url_for('index'))
        playlist, current_index = get_oss_media_playlist(filepath, file_type)
        return render_template('player.html', filename=Path(filepath).name,
                               filepath=filepath, file_type=file_type,
                               playlist=playlist, current_index=current_index)

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
@login_required
def view(filepath):
    """查看图片文件"""
    if USE_OSS:
        try:
            get_oss_bucket().head_object(get_safe_oss_key(filepath))
        except oss2.exceptions.OssError:
            abort(404)
        if get_file_type(filepath) != 'image':
            flash('此文件类型不支持查看', 'error')
            return redirect(url_for('index'))
        playlist, current_index = get_oss_media_playlist(filepath, 'image')
        return render_template('viewer.html', filename=Path(filepath).name,
                               filepath=filepath, playlist=playlist,
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
    """流式传输媒体文件 - 支持 Cookie 和 Token 认证"""
    # 首先检查 URL 参数中的 token
    token = request.args.get('token')

    # Token 认证
    if token and verify_stream_token(token):
        # Token 有效,允许访问
        pass
    # Cookie 认证(浏览器访问)
    elif session.get('logged_in'):
        # 已登录,允许访问
        pass
    else:
        # 两种认证都失败
        abort(403, 'Unauthorized: Invalid or missing token')

    if USE_OSS:
        return redirect(get_oss_signed_url(filepath, as_attachment=False))

    file_path = get_safe_path(filepath)

    if not file_path.exists() or not file_path.is_file():
        abort(404)

    return send_file(file_path, as_attachment=False)


@app.route('/download/<path:filepath>')
@login_required
def download(filepath):
    """Download a shared file after login, redirecting to OSS when configured."""
    if USE_OSS:
        return redirect(get_oss_signed_url(filepath, as_attachment=True))
    file_path = get_safe_path(filepath)
    if not file_path.exists() or not file_path.is_file():
        abort(404)
    return send_file(file_path, as_attachment=True)


# ============ 浏览量统计 ============

# 需要计入浏览量的端点：只统计真正的内容浏览动作。
# /admin、/static、/api、/login、/logout、/stream 都不计
# （/stream 是媒体字节流，会被播放器反复请求，计入会严重虚高）。
VIEW_TRACKED_ENDPOINTS = {'index', 'play', 'view', 'download'}

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


def get_cloudflare_client_ip():
    """读取 Cloudflare 边缘写入的用户真实 IP（CF-Connecting-IP）。

    头不存在或内容不是合法 IP 时返回空字符串。Cloudflare 会覆盖客户端自带的
    同名头，所以只要流量确实经过 Cloudflare，这个值就是用户真实 IP。
    注意：源站应只允许 Cloudflare 节点访问，否则直连源站的人可以伪造该头。
    """
    value = (request.headers.get('CF-Connecting-IP') or '').strip()
    if not value:
        return ''
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return ''
    return value


def get_client_ip():
    """获取真实访客 IP。

    链路可能是：Cloudflare -> Caddy(本机) -> waitress -> Flask。

    waitress 启动时用 trusted_proxy='127.0.0.1' 声明信任本机 Caddy，会把
    X-Forwarded-For 里 Caddy 追加的那一段解析成 request.remote_addr。
    但 Caddy 默认追加的是它的直连对端地址：
      * 没走 Cloudflare：对端就是用户真实 IP，直接可用；
      * 走了 Cloudflare：对端是 Cloudflare 边缘节点 IP，直接记录会得到
        “CF 边缘节点 IP”而不是用户真实 IP。

    所以这里优先取 CF-Connecting-IP；只有直连方确实是 Cloudflare 边缘节点，
    或来自本机 cloudflared/Caddy（回环）时才采信，避免直连源站时伪造。
    """
    ip = (request.remote_addr or '').strip()
    # 兜底：请求仍来自本机代理时（trusted_proxy 没命中），自己去读 XFF 最后一段，
    # 因为 Caddy 把直连对端追加在最右侧，最左边是客户端可以随意伪造的。
    if ip in LOOPBACK_PROXIES:
        xff = request.headers.get('X-Forwarded-For', '')
        if xff:
            ip = xff.rsplit(',', 1)[-1].strip()

    cf_ip = get_cloudflare_client_ip()
    if cf_ip and (ip in LOOPBACK_PROXIES or _is_cloudflare_ip(ip)):
        ip = cf_ip

    # 校验合法性，非法内容直接丢弃，避免垃圾数据进入统计
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return ''
    return ip


def record_view(path):
    """记录一次浏览，并顺便清理 7 天前的旧记录。

    未登录的访问也统计，只是 username 存空字符串，管理页显示成"未登录"。
    """
    now = time.time()
    username = session.get('username') or ''
    try:
        db = get_db()
        # client_ip 单独保存 CF-Connecting-IP，管理页优先显示它；
        # 没经过 Cloudflare 时为空，展示时回退到 ip。
        db.execute(
            'INSERT INTO page_views (path, ip, client_ip, username, timestamp) '
            'VALUES (?, ?, ?, ?, ?)',
            (path, get_client_ip(), get_cloudflare_client_ip(), username, now)
        )
        db.execute('DELETE FROM page_views WHERE timestamp < ?', (now - 7 * 24 * 3600,))
        db.commit()
    except Exception:
        pass


@app.before_request
def track_view():
    """把内容浏览记进 page_views（登录与否都统计）"""
    if request.method == 'GET' and request.endpoint in VIEW_TRACKED_ENDPOINTS:
        record_view(request.path)


# ============ IP 归属地查询 ============
# 使用 ip-api.com 免费批量接口（无需 Key），结果做内存缓存，避免重复查询撞限流。

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


# ============ 用户管理（仅管理员） ============

@app.route('/admin')
@app.route('/admin/users')
@admin_required
def admin_users():
    """用户管理页面"""
    db = get_db()
    users = db.execute(
        'SELECT id, username, is_admin, max_devices, created_at FROM users ORDER BY id'
    ).fetchall()
    phone_accounts = db.execute(
        'SELECT phone, is_approved, created_at, approved_at FROM phone_accounts ORDER BY created_at DESC'
    ).fetchall()
    # 获取每个用户的活跃设备数
    user_sessions = {}
    for user in users:
        user_sessions[user['username']] = get_active_session_count(db, user['username'])
    phone_sessions = {
        row['phone']: get_active_session_count(db, f"sms_{row['phone']}")
        for row in phone_accounts
    }

    # ---- 最近 24 小时浏览量统计 ----
    now = time.time()
    day_ago = now - 24 * 3600

    total_24h = db.execute(
        'SELECT COUNT(*) c FROM page_views WHERE timestamp >= ?', (day_ago,)
    ).fetchone()['c']
    # 优先按 client_ip（CF-Connecting-IP，用户真实 IP）统计；老数据没有
    # client_ip 时回退到 ip。空值要排除，否则空串会被多记成一个"独立 IP"。
    unique_ip_24h = db.execute(
        "SELECT COUNT(DISTINCT COALESCE(NULLIF(client_ip, ''), ip)) c "
        "FROM page_views WHERE timestamp >= ? "
        "AND COALESCE(NULLIF(client_ip, ''), ip) <> ''",
        (day_ago,)
    ).fetchone()['c']
    total_all = db.execute('SELECT COUNT(*) c FROM page_views').fetchone()['c']

    # 最近 24 小时，按小时统计浏览量
    hourly = []
    for i in range(23, -1, -1):
        hour_start = now - (i + 1) * 3600
        hour_end = now - i * 3600
        c = db.execute(
            'SELECT COUNT(*) c FROM page_views WHERE timestamp >= ? AND timestamp < ?',
            (hour_start, hour_end)
        ).fetchone()['c']
        hourly.append({
            'label': format_beijing_time(hour_end, '%H:00'),
            'count': c
        })
    max_hourly = max((h['count'] for h in hourly), default=0)

    # 最近 24 小时出现过的独立 IP（按访问次数排序）。
    # 归属地统一用 ip2region 离线库（data/ip2region_v4.xdb + v6.xdb）解析，
    # 纯内存查询，可以一次算完所有 IP；/admin/ip_location 的 ip-api.com
    # 查询方式仍然保留，页面上的「API 查询」按钮继续可用。
    # 子查询取的是该 IP 最近一次访问用的登录名，空字符串显示为"未登录"。
    unique_ip_rows = db.execute(
        """SELECT COALESCE(NULLIF(p.client_ip, ''), p.ip) AS ip,
                  COUNT(*) c,
                  MAX(p.timestamp) t,
                  (SELECT username FROM page_views p2
                   WHERE COALESCE(NULLIF(p2.client_ip, ''), p2.ip) =
                         COALESCE(NULLIF(p.client_ip, ''), p.ip)
                   ORDER BY p2.timestamp DESC LIMIT 1) u
           FROM page_views p
           WHERE p.timestamp >= ?
             AND COALESCE(NULLIF(p.client_ip, ''), p.ip) <> ''
           GROUP BY COALESCE(NULLIF(p.client_ip, ''), p.ip)
           ORDER BY c DESC""",
        (day_ago,)
    ).fetchall()

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
            'username': row['u'] or '未登录',
            'count': row['c'],
            'last_time': format_beijing_time(row['t']),
            'region': region['display'],
            'scope': scope,
        })

    # 最近的明细访问记录（含登录名），逐条看谁在什么时间看了什么。
    # 展示时优先用 client_ip（CF-Connecting-IP），老数据回退到 ip。
    recent_rows = db.execute(
        'SELECT path, ip, client_ip, username, timestamp FROM page_views '
        'ORDER BY timestamp DESC LIMIT 50'
    ).fetchall()
    recent_views = [{
        'path': row['path'],
        'ip': row['client_ip'] or row['ip'],
        'username': row['username'] or '未登录',
        'time': format_beijing_time(row['timestamp']),
        'region': ip2region_lookup(row['client_ip'] or row['ip'])['display'],
    } for row in recent_rows]

    return render_template('admin_users.html', users=users, user_sessions=user_sessions,
                           phone_accounts=phone_accounts, phone_sessions=phone_sessions,
                           total_24h=total_24h, unique_ip_24h=unique_ip_24h,
                           hangzhou_ip_24h=hangzhou_ip_24h,
                           zhejiang_ip_24h=zhejiang_ip_24h,
                           china_ip_24h=china_ip_24h,
                           total_all=total_all, hourly=hourly, max_hourly=max_hourly,
                           unique_ips=unique_ips, recent_views=recent_views)


@app.route('/admin/ip_location')
@admin_required
def admin_ip_location():
    """按需查询单个 IP 的归属地（管理页点击按钮时通过 AJAX 调用）"""
    ip = request.args.get('ip', '').strip()
    if not ip:
        return {'location': ''}, 400
    return {'location': lookup_ip_locations([ip]).get(ip, '未知')}


@app.route('/admin/phone-accounts/add', methods=['POST'])
@admin_required
def admin_add_phone_account():
    phone = request.form.get('phone', '').strip()
    if not re.fullmatch(r'1[3-9]\d{9}', phone):
        flash('请输入有效的手机号', 'error')
        return redirect(url_for('admin_users'))
    db = get_db()
    now = datetime.now().isoformat()
    existing = db.execute(
        'SELECT is_approved FROM phone_accounts WHERE phone = ?', (phone,)
    ).fetchone()
    if existing:
        db.execute(
            'UPDATE phone_accounts SET is_approved = 1, approved_at = ? WHERE phone = ?',
            (now, phone)
        )
        flash(f'手机号 {phone} 已启用短信登录', 'success')
    else:
        db.execute(
            'INSERT INTO phone_accounts (phone, is_approved, created_at, approved_at) '
            'VALUES (?, 1, ?, ?)', (phone, now, now)
        )
        flash(f'手机号 {phone} 已添加并立即启用短信登录', 'success')
    db.commit()
    return redirect(url_for('admin_users'))


@app.route('/admin/phone-accounts/<action>', methods=['POST'])
@admin_required
def admin_update_phone_account(action):
    phone = request.form.get('phone', '').strip()
    if action not in ('enable', 'revoke'):
        abort(404)
    db = get_db()
    account = db.execute('SELECT phone FROM phone_accounts WHERE phone = ?', (phone,)).fetchone()
    if not account:
        flash('手机号不存在', 'error')
    elif action == 'enable':
        db.execute('UPDATE phone_accounts SET is_approved = 1, approved_at = ? WHERE phone = ?',
                   (datetime.now().isoformat(), phone))
        db.commit()
        flash(f'手机号 {phone} 已启用短信登录', 'success')
    else:
        db.execute('UPDATE phone_accounts SET is_approved = 0 WHERE phone = ?', (phone,))
        db.execute('UPDATE sessions SET is_active = 0 WHERE username = ?', (f'sms_{phone}',))
        db.commit()
        flash(f'手机号 {phone} 的登录权限已撤销', 'success')
    return redirect(url_for('admin_users'))


@app.route('/admin/phone-accounts/delete', methods=['POST'])
@admin_required
def admin_delete_phone_account():
    phone = request.form.get('phone', '').strip()
    db = get_db()
    account = db.execute(
        'SELECT phone FROM phone_accounts WHERE phone = ?', (phone,)
    ).fetchone()
    if not account:
        flash('手机号不存在', 'error')
        return redirect(url_for('admin_users'))

    db.execute('DELETE FROM phone_accounts WHERE phone = ?', (phone,))
    db.execute('DELETE FROM sessions WHERE username = ?', (f'sms_{phone}',))
    db.commit()
    flash(f'手机号 {phone} 的登录账号和会话已删除', 'success')
    return redirect(url_for('admin_users'))


@app.route('/admin/users/add', methods=['POST'])
@admin_required
def admin_add_user():
    """添加用户"""
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')

    if not username or not password:
        flash('用户名和密码不能为空', 'error')
        return redirect(url_for('admin_users'))

    if len(password) < 6:
        flash('密码长度不能少于6位', 'error')
        return redirect(url_for('admin_users'))

    db = get_db()
    existing = db.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
    if existing:
        flash(f'用户名 {username} 已存在', 'error')
        return redirect(url_for('admin_users'))

    db.execute('INSERT INTO users (username, password, is_admin, created_at) VALUES (?, ?, 0, ?)',
               (username, generate_password_hash(password), datetime.now().isoformat()))
    db.commit()
    flash(f'用户 {username} 创建成功', 'success')
    return redirect(url_for('admin_users'))


@app.route('/admin/users/delete', methods=['POST'])
@admin_required
def admin_delete_user():
    """删除用户"""
    user_id = request.form.get('user_id')

    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()

    if not user:
        flash('用户不存在', 'error')
        return redirect(url_for('admin_users'))

    if user['is_admin']:
        flash('不能删除管理员账号', 'error')
        return redirect(url_for('admin_users'))

    db.execute('DELETE FROM users WHERE id = ?', (user_id,))
    # 同时清理该用户的会话记录
    db.execute('DELETE FROM sessions WHERE username = ?', (user['username'],))
    db.commit()
    flash(f'用户 {user["username"]} 已删除', 'success')
    return redirect(url_for('admin_users'))


@app.route('/admin/users/reset-password', methods=['POST'])
@admin_required
def admin_reset_password():
    """重置用户密码"""
    user_id = request.form.get('user_id')
    new_password = request.form.get('new_password', '')

    if not new_password or len(new_password) < 6:
        flash('新密码长度不能少于6位', 'error')
        return redirect(url_for('admin_users'))

    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()

    if not user:
        flash('用户不存在', 'error')
        return redirect(url_for('admin_users'))

    db.execute('UPDATE users SET password = ? WHERE id = ?',
               (generate_password_hash(new_password), user_id))
    db.commit()
    flash(f'用户 {user["username"]} 的密码已重置', 'success')
    return redirect(url_for('admin_users'))


@app.route('/admin/users/set-max-devices', methods=['POST'])
@admin_required
def admin_set_max_devices():
    """设置用户的最大设备数"""
    user_id = request.form.get('user_id')
    max_devices = request.form.get('max_devices', '').strip()

    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()

    if not user:
        flash('用户不存在', 'error')
        return redirect(url_for('admin_users'))

    try:
        max_devices = int(max_devices)
        if max_devices < 1:
            flash('最大设备数至少为 1', 'error')
            return redirect(url_for('admin_users'))
    except ValueError:
        flash('请输入有效的数字', 'error')
        return redirect(url_for('admin_users'))

    db.execute('UPDATE users SET max_devices = ? WHERE id = ?', (max_devices, user_id))
    db.commit()
    flash(f'用户 {user["username"]} 的最大设备数已设置为 {max_devices}', 'success')
    return redirect(url_for('admin_users'))



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
            print('未配置 OSS_ACCESS_KEY_ID / OSS_ACCESS_KEY_SECRET，将尝试匿名访问。')
    else:
        shared_dir = Path(CONFIG['SHARED_DIRECTORY'])
        if not shared_dir.exists():
            shared_dir.mkdir(parents=True)
            print(f"已创建共享目录: {shared_dir}")

    # 初始化数据库
    init_db()

    print("=" * 50)
    print("           文件共享服务器")
    print("=" * 50)
    print(f"共享目录: {CONFIG['SHARED_DIRECTORY']}")
    print(f"管理员: {CONFIG['ADMIN_USERNAME']}")
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
        app.run(host=CONFIG['HOST'], port=CONFIG['PORT'], debug=True)
    else:
        # 生产模式：waitress WSGI 服务器，多线程并发处理请求
        # 必须声明本机 Caddy 是可信代理，否则 waitress 默认会把 X-Forwarded-* 头
        # 整个丢掉（clear_untrusted_proxy_headers 默认为 True），带来两个问题：
        #   1. 拿不到真实访客 IP，request.remote_addr 恒为 127.0.0.1；
        #   2. 拿不到 X-Forwarded-Proto，Flask 以为自己是 http，
        #      于是 url_for / request.url 生成的地址都是 http:// 开头
        #      （登录页跳转、静态资源、绝对 URL 都会受影响）。
        # trusted_proxy_count=1 表示只取 XFF 最后一段，也就是 Caddy 的直连对端。
        # 如果前面还有 Cloudflare，这一段会是 CF 边缘节点 IP，get_client_ip
        # 会再根据 CF-Connecting-IP 还原成用户真实 IP。
        try:
            serve(app, host=CONFIG['HOST'], port=CONFIG['PORT'], threads=8,
                  trusted_proxy='127.0.0.1',
                  trusted_proxy_count=1,
                  trusted_proxy_headers={'x-forwarded-for', 'x-forwarded-proto'},
                  clear_untrusted_proxy_headers=False)
        except TypeError:
            # waitress 1.x 不认识这些代理参数，退回原样启动
            serve(app, host=CONFIG['HOST'], port=CONFIG['PORT'], threads=8)

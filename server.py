# --- START OF FILE server.py ---

from flask import Flask, render_template, request, send_from_directory, session, redirect, url_for, flash, jsonify
from flask_socketio import SocketIO, emit
import sqlite3
from datetime import datetime
import os
import html
from werkzeug.utils import secure_filename
import json
import random
import string
# ✨ تعديل: استخدام GoogleTranslator من مكتبة deep-translator لموثوقية أعلى
from deep_translator import GoogleTranslator
# --- بدء الإضافات الجديدة ---
import uuid
from datetime import timedelta
import threading
import time
# --- نهاية الإضافات الجديدة ---

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['AVATAR_FOLDER'] = 'avatars'
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading', ping_timeout=20, ping_interval=10)

ADMIN_USER = "admin"
USERS_FILE_PATH = 'users.json'

# --- بدء الإضافات الجديدة: متغيرات لإدارة المكالمات ---
active_calls = {}
call_rooms = {} # هذا المتغير مضمن من الكود المقترح ولكنه غير مستخدم حاليًا في منطق الإشارة
# --- نهاية الإضافات الجديدة ---

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])
if not os.path.exists(app.config['AVATAR_FOLDER']):
    os.makedirs(app.config['AVATAR_FOLDER'])

# --- ✨ تعديل: تحديث دوال الترجمة لاستخدام GoogleTranslator ---

def detect_language(text):
    try:
        # هذه الدالة تبقى كما هي لتحديد ما إذا كانت الرسالة عربية أم لا مبدئيًا
        arabic_chars = set('ءآأؤإئابةتثجحخدذرزسشصضطظعغفقكلمنهوىي')
        text_chars = set(text)
        if len(text_chars.intersection(arabic_chars)) > len(text) / 4: # تحسين الدقة
            return 'ar'
        elif any(char.isalpha() for char in text):
            return 'en' # افتراض لغة غير عربية
        else:
            return 'unknown'
    except Exception as e:
        app.logger.error(f"Language detection error: {e}")
        return 'unknown'

def translate_text(text, target_language='ar'):
    """
    ترجمة النص إلى اللغة المستهدفة باستخدام GoogleTranslator
    """
    if not text or not isinstance(text, str):
        return ""
    try:
        # تقوم المكتبة بتحديد اللغة المصدر تلقائياً (source='auto')
        # استخدام GoogleTranslator بدلاً من MyMemoryTranslator
        translated_text = GoogleTranslator(source='auto', target=target_language).translate(text)
        return translated_text if translated_text else text
    except Exception as e:
        app.logger.error(f"GoogleTranslator Error: {e}")
        return text  # إرجاع النص الأصلي في حالة حدوث أي خطأ

# ---------------------------------------------

def load_users_from_file(file_path=USERS_FILE_PATH):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            processed_data = {}
            for username, value in data.items():
                if isinstance(value, str):
                    processed_data[username] = {"password": value, "status": "approved"}
                else:
                    processed_data[username] = value
            return processed_data
    except (FileNotFoundError, json.JSONDecodeError):
        app.logger.warning(f"ملف المستخدمين '{file_path}' غير موجود أو تالف. سيتم إنشاء ملف جديد.")
        admin_data = {ADMIN_USER: {"password": "admin", "status": "approved"}}
        save_users_to_file(admin_data, file_path)
        app.logger.info(f"تم إنشاء حساب مسؤول افتراضي. اسم المستخدم: {ADMIN_USER}, كلمة المرور: admin")
        return admin_data


def save_users_to_file(users_data, file_path=USERS_FILE_PATH):
    try:
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(users_data, f, indent=2, ensure_ascii=False)
    except IOError as e:
        app.logger.error(f"Error saving users file: {e}")

USER_DATABASE = load_users_from_file()
connected_users = {}
global_chat_background = {}
active_verification_codes = {}

def generate_verification_code(length=6):
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))

def init_db():
    conn = sqlite3.connect('chat.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS messages
                (id INTEGER PRIMARY KEY AUTOINCREMENT, sender TEXT NOT NULL, recipient TEXT, is_private INTEGER DEFAULT 0, text TEXT NOT NULL, type TEXT DEFAULT 'text', original_filename TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, edited DATETIME, reply_to_id INTEGER, FOREIGN KEY (reply_to_id) REFERENCES messages(id))''')
    c.execute('''CREATE TABLE IF NOT EXISTS read_receipts
                (message_id INTEGER NOT NULL, reader_username TEXT NOT NULL, read_at DATETIME DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY (message_id, reader_username), FOREIGN KEY (message_id) REFERENCES messages(id))''')
    c.execute('''CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, avatar_url TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS uploads (id INTEGER PRIMARY KEY AUTOINCREMENT, unique_filename TEXT NOT NULL UNIQUE, original_filename TEXT NOT NULL, uploader_username TEXT NOT NULL, file_size INTEGER NOT NULL, upload_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')
    try:
        c.execute("SELECT recipient, is_private FROM messages LIMIT 1")
    except sqlite3.OperationalError:
        app.logger.info("Updating messages table schema for private chats...")
        c.execute("ALTER TABLE messages ADD COLUMN recipient TEXT")
        c.execute("ALTER TABLE messages ADD COLUMN is_private INTEGER DEFAULT 0")
        app.logger.info("Messages table updated successfully.")
    conn.commit()
    conn.close()

init_db()

def format_messages(rows):
    messages = []
    for row in rows:
        msg = dict(row)
        if msg['timestamp']: msg['timestamp'] = msg['timestamp'].replace(' ', 'T') + 'Z'
        if msg.get('reply_sender') and msg.get('reply_text'):
             msg['replyTo'] = {'sender': msg['reply_sender'], 'text': msg['reply_text']}
        if msg.get('readers'): msg['readers'] = msg['readers'].split(',')
        else: msg['readers'] = []
        if 'reply_sender' in msg: del msg['reply_sender']
        if 'reply_text' in msg: del msg['reply_text']
        messages.append(msg)
    return messages

def get_public_chat_history():
    conn = sqlite3.connect('chat.db')
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("""
        SELECT m.id, m.sender, m.recipient, m.is_private, m.text, m.timestamp, m.type, m.original_filename, m.edited, u.avatar_url, replied.sender as reply_sender, replied.text as reply_text, (SELECT GROUP_CONCAT(rr.reader_username) FROM read_receipts rr WHERE rr.message_id = m.id) as readers
        FROM messages m LEFT JOIN users u ON m.sender = u.username LEFT JOIN messages replied ON m.reply_to_id = replied.id
        WHERE m.is_private = 0 ORDER BY m.timestamp ASC, m.id ASC
    """)
    rows = c.fetchall()
    conn.close()
    return format_messages(rows)

def get_private_chat_history(user1, user2):
    conn = sqlite3.connect('chat.db')
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("""
        SELECT m.id, m.sender, m.recipient, m.is_private, m.text, m.timestamp, m.type, m.original_filename, m.edited, u.avatar_url, replied.sender as reply_sender, replied.text as reply_text, (SELECT GROUP_CONCAT(rr.reader_username) FROM read_receipts rr WHERE rr.message_id = m.id) as readers
        FROM messages m LEFT JOIN users u ON m.sender = u.username LEFT JOIN messages replied ON m.reply_to_id = replied.id
        WHERE m.is_private = 1 AND ((m.sender = ? AND m.recipient = ?) OR (m.sender = ? AND m.recipient = ?))
        ORDER BY m.timestamp ASC, m.id ASC
    """, (user1, user2, user2, user1))
    rows = c.fetchall()
    conn.close()
    return format_messages(rows)

def get_client_ip():
    if request.headers.getlist("X-Forwarded-For"):
       return request.headers.getlist("X-Forwarded-For")[0].split(',')[0].strip()
    return request.remote_addr

def get_connected_users_with_avatars():
    users_with_avatars = []
    conn = sqlite3.connect('chat.db')
    c = conn.cursor()
    username_to_sid = {info['username']: sid for sid, info in list(connected_users.items())}
    last_messages = {}
    if 'username' in session:
        current_user = session['username']
        c.execute("""
            SELECT CASE WHEN sender = ? THEN recipient ELSE sender END as other_user, MAX(timestamp) as last_ts
            FROM messages WHERE is_private = 1 AND (sender = ? OR recipient = ?) GROUP BY other_user
        """, (current_user, current_user, current_user))
        for row in c.fetchall(): last_messages[row[0]] = row[1]
    for sid, user_info in list(connected_users.items()):
        username = user_info['username']
        ip = user_info.get('ip')
        c.execute("SELECT avatar_url FROM users WHERE username = ?", (username,))
        result = c.fetchone()
        avatar_url = result[0] if result else None
        user_data = { 'username': username, 'avatarUrl': avatar_url, 'ip': ip, 'sid': sid, 'lastMessageTimestamp': last_messages.get(username, '1970-01-01T00:00:00') }
        users_with_avatars.append(user_data)
    conn.close()
    users_with_avatars.sort(key=lambda x: (x['lastMessageTimestamp'], x['username']), reverse=True)
    return users_with_avatars

def set_new_verification_code(username):
    code = generate_verification_code()
    timestamp = datetime.now().timestamp()
    session['verification_code'] = code
    session['verification_timestamp'] = timestamp
    active_verification_codes[username] = {'code': code, 'timestamp': timestamp}
    return code, timestamp

def notify_admin(event, data):
    admin_sid = None
    for sid, info in connected_users.items():
        if info.get('username') == ADMIN_USER:
            admin_sid = sid
            break
    if admin_sid:
        socketio.emit(event, data, room=admin_sid)
        app.logger.info(f"Sent '{event}' notification to admin.")

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'username' in session: return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        user_data = USER_DATABASE.get(username)
        if user_data and user_data.get('password') == password:
            user_status = user_data.get('status', 'approved')
            if user_status == 'pending':
                flash('حسابك قيد المراجعة ولم تتم الموافقة عليه بعد.')
                return render_template('login.html')
            if user_status == 'approved':
                if username == ADMIN_USER:
                    app.logger.info(f"Admin user '{username}' logged in, bypassing verification.")
                    session['username'] = html.escape(username)[:30]
                    conn = sqlite3.connect('chat.db')
                    c = conn.cursor()
                    c.execute("INSERT OR IGNORE INTO users (username) VALUES (?)", (session['username'],))
                    conn.commit()
                    conn.close()
                    flash('مرحباً بك أيها المسؤول، تم تسجيل دخولك بنجاح.')
                    return redirect(url_for('loading'))
                else:
                    session['pending_username'] = username
                    set_new_verification_code(username)
                    return redirect(url_for('verify'))
        else:
            flash('اسم المستخدم أو كلمة المرور غير صحيحة. حاول مرة أخرى.')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'username' in session: return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        password_confirm = request.form.get('password_confirm', '')
        if not username or not password or not password_confirm: flash('الرجاء ملء جميع الحقول.')
        elif len(username) < 3: flash('يجب أن يكون اسم المستخدم 3 أحرف على الأقل.')
        elif password != password_confirm: flash('كلمتا المرور غير متطابقتين.')
        elif username in USER_DATABASE: flash('اسم المستخدم هذا موجود بالفعل. اختر اسماً آخر.')
        else:
            USER_DATABASE[username] = {"password": password, "status": "pending"}
            save_users_to_file(USER_DATABASE)
            notify_admin('new_pending_user_notification', {'username': username})
            flash('تم إرسال طلب التسجيل بنجاح. سيتم مراجعته من قبل المسؤول.')
            return redirect(url_for('login'))
    show_register_panel = request.method == 'POST'
    return render_template('login.html', show_register_panel=show_register_panel)

@app.route('/verify', methods=['GET', 'POST'])
def verify():
    if 'username' in session: return redirect(url_for('index'))
    if 'pending_username' not in session: return redirect(url_for('login'))
    username = session['pending_username']
    if request.method == 'POST':
        submitted_code = request.form.get('verification_code', '').strip().upper()
        code_data = active_verification_codes.get(username)
        if not code_data:
             flash('انتهت صلاحية الجلسة. تم إنشاء رمز جديد، الرجاء المحاولة مرة أخرى.')
             set_new_verification_code(username)
             return redirect(url_for('verify'))
        time_elapsed = datetime.now().timestamp() - code_data.get('timestamp', 0)
        if submitted_code == code_data.get('code') and time_elapsed <= 20:
            session.pop('pending_username')
            session.pop('verification_code', None)
            session.pop('verification_timestamp', None)
            active_verification_codes.pop(username, None)
            session['username'] = html.escape(username)[:30]
            conn = sqlite3.connect('chat.db')
            c = conn.cursor()
            c.execute("INSERT OR IGNORE INTO users (username) VALUES (?)", (session['username'],))
            conn.commit()
            conn.close()
            flash('تم التحقق بنجاح! مرحباً بك.')
            return redirect(url_for('loading'))
        else:
            flash('الرمز غير صحيح أو انتهت صلاحيته. تم إنشاء رمز جديد، حاول مرة أخرى.')
            set_new_verification_code(username)
            return redirect(url_for('verify'))
    timestamp = session.get('verification_timestamp')
    return render_template('verify.html', user=username, timestamp=timestamp)

@app.route('/code_generator')
def code_generator_index():
    now_timestamp = datetime.now().timestamp()
    users_to_check = list(active_verification_codes.keys())
    for username in users_to_check:
        code_data = active_verification_codes.get(username)
        if code_data and 'timestamp' in code_data:
            time_elapsed = now_timestamp - code_data['timestamp']
            if time_elapsed > 20:
                app.logger.info(f"إزالة رمز التحقق منتهي الصلاحية للمستخدم: {username}")
                active_verification_codes.pop(username, None)
    pending_users = list(active_verification_codes.keys())
    return render_template('code_generator_index.html', pending_users=pending_users)

@app.route('/get_code/<username>')
def get_user_code(username):
    code_data = active_verification_codes.get(username)
    code = code_data.get('code') if code_data else 'لا يوجد رمز فعال'
    return render_template('get_code.html', user=username, code=code)

@app.route('/logout')
def logout():
    if 'pending_username' in session: active_verification_codes.pop(session['pending_username'], None)
    session.clear()
    flash('تم تسجيل خروجك بنجاح.')
    return redirect(url_for('login'))

@app.route('/loading')
def loading():
    if 'username' not in session: return redirect(url_for('login'))
    return render_template('Loading.html')

@app.route('/')
def index():
    if 'username' not in session: return redirect(url_for('login'))
    return render_template('index.html', username=session.get('username'), admin_user=ADMIN_USER)

@app.route('/admin/users')
def admin_users():
    if session.get('username') != ADMIN_USER:
        flash('غير مصرح لك بالوصول لهذه الصفحة.', 'error')
        return redirect(url_for('index'))
    online_users = {info['username'] for info in connected_users.values()}
    all_users = []
    for uname, udata in USER_DATABASE.items():
        all_users.append({ 'username': uname, 'password': udata.get('password', 'N/A'), 'status': udata.get('status', 'N/A'), 'is_online': uname in online_users })
    all_users.sort(key=lambda x: x['username'])
    return render_template('admin_users.html', users=all_users, admin_user=ADMIN_USER)

@app.route('/admin/add_user', methods=['POST'])
def admin_add_user():
    if session.get('username') != ADMIN_USER: return redirect(url_for('login'))
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '').strip()
    if not username or not password: flash('يجب توفير اسم المستخدم وكلمة المرور.', 'error')
    elif username in USER_DATABASE: flash(f'اسم المستخدم "{username}" موجود بالفعل.', 'error')
    else:
        USER_DATABASE[username] = {"password": password, "status": "approved"}
        save_users_to_file(USER_DATABASE)
        flash(f'تمت إضافة المستخدم "{username}" بنجاح.', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/edit_user', methods=['POST'])
def admin_edit_user():
    if session.get('username') != ADMIN_USER: return redirect(url_for('login'))
    original_username = request.form.get('original_username')
    new_username = request.form.get('new_username', '').strip()
    new_password = request.form.get('new_password', '').strip()
    if not original_username or not new_username or not new_password:
        flash('البيانات المقدمة غير كاملة.', 'error')
        return redirect(url_for('admin_users'))
    if original_username not in USER_DATABASE:
        flash('المستخدم الأصلي غير موجود.', 'error')
        return redirect(url_for('admin_users'))
    if original_username != new_username and new_username in USER_DATABASE:
        flash(f'اسم المستخدم الجديد "{new_username}" موجود بالفعل.', 'error')
        return redirect(url_for('admin_users'))
    user_data = USER_DATABASE.pop(original_username)
    user_data['password'] = new_password
    USER_DATABASE[new_username] = user_data
    save_users_to_file(USER_DATABASE)
    flash(f'تم تحديث بيانات المستخدم "{new_username}" بنجاح.', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/delete_user', methods=['POST'])
def admin_delete_user():
    if session.get('username') != ADMIN_USER: return redirect(url_for('login'))
    username_to_delete = request.form.get('username')
    if not username_to_delete: flash('لم يتم تحديد مستخدم للحذف.', 'error')
    elif username_to_delete == ADMIN_USER: flash('لا يمكن حذف حساب المسؤول.', 'error')
    elif username_to_delete in USER_DATABASE:
        USER_DATABASE.pop(username_to_delete)
        save_users_to_file(USER_DATABASE)
        flash(f'تم حذف المستخدم "{username_to_delete}" بنجاح.', 'success')
    else:
        flash('المستخدم المراد حذفه غير موجود.', 'error')
    return redirect(url_for('admin_users'))

@app.route('/translate', methods=['POST'])
def translate_message_route():
    if 'username' not in session: return jsonify({'error': 'Unauthorized'}), 401
    data = request.get_json()
    if not data or 'text' not in data: return jsonify({'error': 'No text provided'}), 400
    text_to_translate = data.get('text', '')
    target_lang = data.get('target_lang', 'ar')
    if not text_to_translate: return jsonify({'translated_text': ''})
    translated_text = translate_text(text_to_translate, target_lang)
    return jsonify({'translated_text': translated_text})

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    """
    يقوم بتقديم ملف تم تحميله مع تحديد اسمه الأصلي للتنزيل.
    يتصل بقاعدة البيانات للحصول على الاسم الأصلي بناءً على الاسم الفريد.
    """
    conn = None
    try:
        conn = sqlite3.connect('chat.db')
        c = conn.cursor()
        # البحث عن الاسم الأصلي للملف في قاعدة البيانات
        c.execute("SELECT original_filename FROM uploads WHERE unique_filename = ?", (filename,))
        result = c.fetchone()
        
        if result and result[0]:
            original_filename = result[0]
            # إرسال الملف مع تحديد اسمه الأصلي للتنزيل
            # استخدام `download_name` يضبط ترويسة Content-Disposition تلقائيًا
            return send_from_directory(
                app.config['UPLOAD_FOLDER'],
                filename,
                download_name=original_filename
            )
        else:
            # في حالة عدم العثور على الملف في قاعدة البيانات، يتم إرساله بالاسم الموجود على الخادم
            return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
            
    except sqlite3.Error as e:
        app.logger.error(f"Database error while serving file {filename}: {e}")
        return "حدث خطأ أثناء الوصول إلى الملف.", 500
    except Exception as e:
        app.logger.error(f"General error while serving file {filename}: {e}")
        return "لم يتم العثور على الملف.", 404
    finally:
        if conn:
            conn.close()

@app.route('/avatars/<filename>')
def uploaded_avatar_file(filename):
    return send_from_directory(app.config['AVATAR_FOLDER'], filename)

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'username' not in session: return jsonify({'error': 'Unauthorized'}), 401
    if 'file' not in request.files: return jsonify({'error': 'No file part'}), 400
    file = request.files['file']
    if file.filename == '': return jsonify({'error': 'No selected file'}), 400
    try:
        username = session['username']
        original_filename = secure_filename(file.filename)
        unique_filename = f"{datetime.now().strftime('%Y%m%d%H%M%S%f')}_{original_filename}"
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        file.save(file_path)
        file_size = os.path.getsize(file_path)
        file_url = url_for('uploaded_file', filename=unique_filename, _external=False)
        conn = sqlite3.connect('chat.db')
        c = conn.cursor()
        c.execute("INSERT INTO uploads (unique_filename, original_filename, uploader_username, file_size) VALUES (?, ?, ?, ?)", (unique_filename, original_filename, username, file_size))
        conn.commit()
        conn.close()
        return jsonify({'url': file_url})
    except Exception as e:
        app.logger.error(f"File upload failed: {e}")
        return jsonify({'error': 'Server error during file upload'}), 500

@app.route('/set-avatar', methods=['POST'])
def set_avatar():
    if 'username' not in session: return jsonify({'error': 'Unauthorized'}), 401
    if 'avatar' not in request.files: return jsonify({'error': 'No avatar file part'}), 400
    file = request.files['avatar']
    if file.filename == '': return jsonify({'error': 'No selected avatar file'}), 400
    try:
        username = session['username']
        filename = secure_filename(file.filename)
        file_ext = filename.rsplit('.', 1)[1].lower()
        avatar_filename = f"avatar_{username}.{file_ext}"
        file.save(os.path.join(app.config['AVATAR_FOLDER'], avatar_filename))
        avatar_url = url_for('uploaded_avatar_file', filename=avatar_filename, _external=False)
        conn = sqlite3.connect('chat.db')
        c = conn.cursor()
        c.execute("UPDATE users SET avatar_url = ? WHERE username = ?", (avatar_url, username))
        conn.commit()
        conn.close()
        socketio.emit('avatar_updated', {'username': username, 'avatarUrl': avatar_url})
        return jsonify({'success': True, 'avatarUrl': avatar_url}), 200
    except Exception as e:
        app.logger.error(f"Error setting avatar: {e}")
        return jsonify({'error': 'Server error'}), 500

def format_bytes(size):
    if size is None: return "N/A"
    power = 1024; n = 0
    power_labels = {0: 'Bytes', 1: 'KB', 2: 'MB', 3: 'GB', 4: 'TB'}
    while size >= power and n < len(power_labels) - 1:
        size /= power
        n += 1
    return f"{size:.2f} {power_labels[n]}"

@app.template_filter('format_bytes')
def _format_bytes_filter(size):
    return format_bytes(size)

@app.route('/uploads_browser')
def browse_uploads():
    if 'username' not in session:
        flash('الرجاء تسجيل الدخول لعرض هذه الصفحة.')
        return redirect(url_for('login'))
    all_files_data = []
    db_filenames = set()
    try:
        conn = sqlite3.connect('chat.db')
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT unique_filename, original_filename, uploader_username, file_size, upload_timestamp FROM uploads ORDER BY upload_timestamp DESC")
        db_files = c.fetchall()
        conn.close()
        for row in db_files:
            all_files_data.append({ 'name': row['original_filename'], 'url': url_for('uploaded_file', filename=row['unique_filename']), 'size': row['file_size'], 'modified_dt': datetime.fromisoformat(row['upload_timestamp']), 'uploader': row['uploader_username'] })
            db_filenames.add(row['unique_filename'])
        upload_folder = app.config['UPLOAD_FOLDER']
        if os.path.exists(upload_folder):
            for filename in os.listdir(upload_folder):
                if filename not in db_filenames:
                    file_path = os.path.join(upload_folder, filename)
                    if os.path.isfile(file_path):
                        file_stat = os.stat(file_path)
                        all_files_data.append({ 'name': filename, 'url': url_for('uploaded_file', filename=filename), 'size': file_stat.st_size, 'modified_dt': datetime.fromtimestamp(file_stat.st_mtime), 'uploader': 'غير معروف' })
    except Exception as e:
        app.logger.error(f"Error browsing uploads: {e}")
    all_files_data.sort(key=lambda x: x['modified_dt'], reverse=True)
    for file_info in all_files_data:
        file_info['modified'] = file_info['modified_dt'].strftime('%Y-%m-%d %H:%M:%S')
        del file_info['modified_dt']
    return render_template('uploads_browser.html', files=all_files_data)

# --- بدء الإضافات الجديدة: مسارات (Endpoints) المكالمات ---
@app.route('/call/<recipient>', methods=['POST'])
def initiate_call(recipient):
    if 'username' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    caller = session['username']
    call_type = request.json.get('type', 'audio')  # audio أو video
    
    # إنشاء غرفة مكالمة فريدة
    room_id = str(uuid.uuid4())
    
    active_calls[room_id] = {
        'caller': caller,
        'recipient': recipient,
        'type': call_type,
        'created_at': datetime.now(),
        'status': 'ringing'
    }
    
    # إرسال إشعار للمستلم
    username_to_sid = {info['username']: sid for sid, info in connected_users.items()}
    recipient_sid = username_to_sid.get(recipient)
    
    if recipient_sid:
        socketio.emit('incoming_call', {
            'room_id': room_id,
            'caller': caller,
            'type': call_type
        }, room=recipient_sid)
        
        return jsonify({
            'success': True,
            'room_id': room_id,
            'status': 'ringing'
        })
    else:
        return jsonify({'error': 'المستخدم غير متصل'}), 404

@app.route('/call/<room_id>/accept', methods=['POST'])
def accept_call(room_id):
    if 'username' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    if room_id not in active_calls:
        return jsonify({'error': 'المكالمة غير موجودة'}), 404
    
    active_calls[room_id]['status'] = 'accepted'
    active_calls[room_id]['accepted_at'] = datetime.now()
    
    # إعلام المتصل بقبول المكالمة
    caller = active_calls[room_id]['caller']
    username_to_sid = {info['username']: sid for sid, info in connected_users.items()}
    caller_sid = username_to_sid.get(caller)
    
    if caller_sid:
        socketio.emit('call_accepted', {
            'room_id': room_id,
            'recipient': session['username']
        }, room=caller_sid)
    
    return jsonify({'success': True, 'status': 'accepted'})

@app.route('/call/<room_id>/reject', methods=['POST'])
def reject_call(room_id):
    if 'username' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    if room_id in active_calls:
        # إعلام المتصل برفض المكالمة
        caller = active_calls[room_id]['caller']
        username_to_sid = {info['username']: sid for sid, info in connected_users.items()}
        caller_sid = username_to_sid.get(caller)
        
        if caller_sid:
            socketio.emit('call_rejected', {
                'room_id': room_id,
                'recipient': session['username']
            }, room=caller_sid)
        
        del active_calls[room_id]
    
    return jsonify({'success': True})

@app.route('/call/<room_id>/end', methods=['POST'])
def end_call(room_id):
    if 'username' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    if room_id in active_calls:
        # إعلام الطرف الآخر بإنهاء المكالمة
        call_data = active_calls[room_id]
        other_party = call_data['recipient'] if session['username'] == call_data['caller'] else call_data['caller']
        
        username_to_sid = {info['username']: sid for sid, info in connected_users.items()}
        other_sid = username_to_sid.get(other_party)
        
        if other_sid:
            socketio.emit('call_ended', {
                'room_id': room_id,
                'reason': 'ended_by_other'
            }, room=other_sid)
        
        # تسجيل تفاصيل المكالمة (يمكن حفظها في قاعدة البيانات)
        call_duration = datetime.now() - active_calls[room_id].get('accepted_at', datetime.now())
        app.logger.info(f"Call ended: {room_id}, Duration: {call_duration}")
        
        del active_calls[room_id]
    
    return jsonify({'success': True})

@app.route('/calls/history')
def call_history():
    if 'username' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    # هنا يمكنك إرجاع سجل المكالمات من قاعدة البيانات
    return jsonify({'calls': []})

# --- نهاية الإضافات الجديدة ---

@socketio.on('connect')
def handle_connect():
    if 'username' not in session: return False
    socketio.sleep(0.1)
    username = session['username']
    ip_address = get_client_ip()
    sids_to_remove = [sid for sid, info in connected_users.items() if info.get('username') == username]
    for sid in sids_to_remove:
        if sid != request.sid:
            app.logger.info(f"Removing duplicate session for user '{username}' with SID {sid}")
            connected_users.pop(sid, None)
    connected_users[request.sid] = {'username': username, 'ip': ip_address}
    app.logger.info(f"User '{username}' connected with SID {request.sid}")
    emit('username_set', {'username': username})
    emit('chat_history', {'is_private': False, 'history': get_public_chat_history()})
    emit('update_user_list', get_connected_users_with_avatars(), broadcast=True)
    if global_chat_background: emit('background_changed', global_chat_background)

@socketio.on('disconnect')
def handle_disconnect():
    if request.sid in connected_users:
        removed_user_info = connected_users.pop(request.sid, {'username': 'Unknown'})
        app.logger.info(f"User '{removed_user_info['username']}' disconnected with SID {request.sid}")
        emit('update_user_list', get_connected_users_with_avatars(), broadcast=True)

@socketio.on('new_message')
def handle_new_message(data):
    if request.sid not in connected_users: return
    sender_username = connected_users[request.sid]['username']
    text_input = html.escape(data.get('text', '')).strip()
    
    # تم نقل هذا السطر للأعلى لتحديد نوع الرسالة أولاً
    msg_type = data.get('type', 'text')

    if not text_input: return

    # ✨ تعديل: تطبيق الترجمة فقط على الرسائل النصية الصريحة
    if msg_type == 'text':
        original_language = detect_language(text_input)
        # التأكد من أن النص ليس رابطًا يبدأ بـ http
        if original_language != 'ar' and not text_input.lower().startswith(('http://', 'https://')):
            app.logger.info(f"Detected non-Arabic message from '{sender_username}'. Translating to Arabic.")
            translated_text = translate_text(text_input, 'ar')
            text_input = f"{text_input}\n\n(مترجم): {translated_text}"

    recipient = data.get('recipient')
    is_private = 1 if recipient else 0
    original_filename = data.get('originalFileName')
    reply_to = data.get('replyTo')
    reply_to_id = reply_to.get('id') if reply_to else None
    
    conn = sqlite3.connect('chat.db')
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("INSERT INTO messages (sender, recipient, is_private, text, type, original_filename, reply_to_id) VALUES (?, ?, ?, ?, ?, ?, ?)", (sender_username, recipient, is_private, text_input, msg_type, original_filename, reply_to_id))
    message_id = c.lastrowid
    conn.commit()
    
    c.execute("SELECT m.id, m.sender, m.recipient, m.is_private, m.text, m.timestamp, m.type, m.original_filename, m.edited, u.avatar_url FROM messages m LEFT JOIN users u ON m.sender = u.username WHERE m.id = ?", (message_id,))
    message_row = c.fetchone()
    conn.close()
    
    if not message_row: return
    
    timestamp_str = message_row['timestamp'].replace(' ', 'T') + 'Z'
    message_to_send = { 
        'id': message_row['id'], 
        'sender': message_row['sender'], 
        'recipient': message_row['recipient'], 
        'is_private': message_row['is_private'], 
        'text': message_row['text'], 
        'type': message_row['type'], 
        'originalFileName': message_row['original_filename'], 
        'timestamp': timestamp_str, 
        'edited': message_row['edited'], 
        'replyTo': reply_to, 
        'readers': [], 
        'avatar_url': message_row['avatar_url'] 
    }
    
    if is_private:
        username_to_sid = {info['username']: sid for sid, info in connected_users.items()}
        recipient_sid = username_to_sid.get(recipient)
        emit('message_received', message_to_send, room=request.sid)
        if recipient_sid and recipient_sid != request.sid: 
            emit('message_received', message_to_send, room=recipient_sid)
        if recipient_sid:
             emit('update_user_list', get_connected_users_with_avatars(), room=request.sid)
             emit('update_user_list', get_connected_users_with_avatars(), room=recipient_sid)
    else:
        emit('message_received', message_to_send, broadcast=True)
@socketio.on('request_private_chat')
def handle_request_private_chat(data):
    if 'username' not in session: return
    current_user = session['username']
    target_user = data.get('target_user')
    if not target_user: return
    history = get_private_chat_history(current_user, target_user)
    emit('chat_history', { 'is_private': True, 'with_user': target_user, 'history': history })

@socketio.on('request_public_chat')
def handle_request_public_chat():
    if 'username' not in session: return
    emit('chat_history', { 'is_private': False, 'history': get_public_chat_history() })

@socketio.on('edit_message')
def handle_edit_message(data):
    if request.sid not in connected_users: return
    editor_username = connected_users[request.sid]['username']
    message_id = data.get('id')
    new_text = html.escape(data.get('text', '')).strip()
    if not new_text or not message_id: return
    conn = sqlite3.connect('chat.db')
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT sender, recipient, is_private FROM messages WHERE id = ?", (message_id,))
    message = c.fetchone()
    if message and message['sender'] == editor_username:
        edited_time = datetime.now()
        c.execute("UPDATE messages SET text = ?, edited = ? WHERE id = ?", (new_text, edited_time, message_id))
        conn.commit()
        payload = {'id': message_id, 'new_text': new_text, 'edited': edited_time.isoformat()}
        if message['is_private']:
            username_to_sid = {info['username']: sid for sid, info in connected_users.items()}
            recipient_sid = username_to_sid.get(message['recipient'])
            emit('message_edited', payload, room=request.sid)
            if recipient_sid: emit('message_edited', payload, room=recipient_sid)
        else:
            emit('message_edited', payload, broadcast=True)
    conn.close()

@socketio.on('delete_message')
def handle_delete_message(data):
    if request.sid not in connected_users: return
    deleter_username = connected_users[request.sid]['username']
    message_id = data.get('id')
    if not message_id: return
    conn = sqlite3.connect('chat.db')
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT sender, recipient, is_private FROM messages WHERE id = ?", (message_id,))
    message = c.fetchone()
    if message and message['sender'] == deleter_username:
        c.execute("DELETE FROM read_receipts WHERE message_id = ?", (message_id,))
        c.execute("DELETE FROM messages WHERE id = ?", (message_id,))
        conn.commit()
        app.logger.info(f"User '{deleter_username}' deleted message {message_id}")
        payload = {'id': message_id}
        if message['is_private']:
            username_to_sid = {info['username']: sid for sid, info in connected_users.items()}
            recipient_sid = username_to_sid.get(message['recipient'])
            emit('message_deleted', payload, room=request.sid)
            if recipient_sid: emit('message_deleted', payload, room=recipient_sid)
        else:
            emit('message_deleted', payload, broadcast=True)
    else:
        app.logger.warning(f"User '{deleter_username}' attempted to delete message {message_id} without permission.")
    conn.close()

@socketio.on('typing')
def handle_typing(data):
    if request.sid not in connected_users: return
    username = connected_users[request.sid]['username']
    recipient = data.get('recipient')
    payload = {'username': username, 'recipient': recipient}
    if recipient:
        username_to_sid = {info['username']: sid for sid, info in connected_users.items()}
        recipient_sid = username_to_sid.get(recipient)
        if recipient_sid: emit('user_typing', payload, room=recipient_sid)
    else:
        emit('user_typing', payload, broadcast=True, include_self=False)

@socketio.on('mark_as_read')
def handle_mark_as_read(data):
    if request.sid not in connected_users: return
    message_id = data.get('messageId')
    reader_username = connected_users[request.sid]['username']
    if not message_id: return
    conn = sqlite3.connect('chat.db')
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT sender, recipient, is_private FROM messages WHERE id = ?", (message_id,))
    message = c.fetchone()
    if not message: return
    can_read = not message['is_private'] or message['recipient'] == reader_username or message['sender'] == reader_username
    if not can_read: return
    c.execute("INSERT OR IGNORE INTO read_receipts (message_id, reader_username) VALUES (?, ?)", (message_id, reader_username))
    conn.commit()
    if conn.total_changes > 0:
        app.logger.info(f"Message {message_id} marked as read by {reader_username}.")
        payload = {'messageId': message_id, 'reader': reader_username}
        if message['is_private']:
             username_to_sid = {info['username']: sid for sid, info in connected_users.items()}
             sender_sid = username_to_sid.get(message['sender'])
             if sender_sid: emit('message_read', payload, room=sender_sid)
             if request.sid != sender_sid: emit('message_read', payload, room=request.sid)
        else:
            emit('message_read', payload, broadcast=True)
    conn.close()

@socketio.on('change_background')
def handle_change_background(data):
    global global_chat_background
    if 'type' in data and 'value' in data:
        global_chat_background = {'type': data['type'], 'value': data['value']}
        app.logger.info(f"Global background changed by a user. Broadcasting to all clients.")
        emit('background_changed', global_chat_background, broadcast=True)

@socketio.on('reset_background')
def handle_reset_background():
    global global_chat_background
    global_chat_background = {}
    app.logger.info(f"Global background reset by a user. Broadcasting to all clients.")
    emit('background_reset', broadcast=True)

@socketio.on('get_pending_users')
def handle_get_pending_users():
    if session.get('username') == ADMIN_USER:
        pending_users = [user for user, data in USER_DATABASE.items() if data.get('status') == 'pending']
        emit('pending_users_list', {'users': pending_users})

@socketio.on('admin_approve_user')
def handle_admin_approve_user(data):
    username_to_approve = data.get('username')
    if session.get('username') == ADMIN_USER and username_to_approve in USER_DATABASE:
        USER_DATABASE[username_to_approve]['status'] = 'approved'
        save_users_to_file(USER_DATABASE)
        app.logger.info(f"Admin '{session['username']}' approved user '{username_to_approve}'.")
        handle_get_pending_users()

@socketio.on('admin_reject_user')
def handle_admin_reject_user(data):
    username_to_reject = data.get('username')
    if session.get('username') == ADMIN_USER and username_to_reject in USER_DATABASE:
        del USER_DATABASE[username_to_reject]
        save_users_to_file(USER_DATABASE)
        app.logger.info(f"Admin '{session['username']}' rejected and deleted user '{username_to_reject}'.")
        handle_get_pending_users()

# --- بدء الإضافات الجديدة: أحداث Socket.IO لإشارة WebRTC ---
@socketio.on('webrtc_offer')
def handle_webrtc_offer(data):
    room_id = data['room_id']
    offer = data['offer']
    
    # إعادة توجيه العرض إلى الطرف الآخر
    call_data = active_calls.get(room_id)
    if call_data:
        target_user = call_data['recipient'] if session['username'] == call_data['caller'] else call_data['caller']
        username_to_sid = {info['username']: sid for sid, info in connected_users.items()}
        target_sid = username_to_sid.get(target_user)
        
        if target_sid:
            emit('webrtc_offer', {
                'room_id': room_id,
                'offer': offer,
                'from': session['username']
            }, room=target_sid)

@socketio.on('webrtc_answer')
def handle_webrtc_answer(data):
    room_id = data['room_id']
    answer = data['answer']
    
    # إعادة توجيه الإجابة إلى الطرف الآخر
    call_data = active_calls.get(room_id)
    if call_data:
        target_user = call_data['recipient'] if session['username'] == call_data['recipient'] else call_data['caller']
        username_to_sid = {info['username']: sid for sid, info in connected_users.items()}
        target_sid = username_to_sid.get(target_user)
        
        if target_sid:
            emit('webrtc_answer', {
                'room_id': room_id,
                'answer': answer,
                'from': session['username']
            }, room=target_sid)

@socketio.on('webrtc_ice_candidate')
def handle_webrtc_ice_candidate(data):
    room_id = data['room_id']
    candidate = data['candidate']
    
    # إعادة توجيه مرشح ICE إلى الطرف الآخر
    call_data = active_calls.get(room_id)
    if call_data:
        target_user = call_data['recipient'] if session['username'] == call_data['caller'] else call_data['caller']
        username_to_sid = {info['username']: sid for sid, info in connected_users.items()}
        target_sid = username_to_sid.get(target_user)
        
        if target_sid:
            emit('webrtc_ice_candidate', {
                'room_id': room_id,
                'candidate': candidate,
                'from': session['username']
            }, room=target_sid)
# --- نهاية الإضافات الجديدة ---


# --- بدء الإضافات الجديدة: تنظيف المكالمات المنتهية تلقائياً ---
def cleanup_old_calls():
    now = datetime.now()
    rooms_to_delete = []
    
    for room_id, call_data in list(active_calls.items()): # استخدام list لتجنب التعديل أثناء التكرار
        if now - call_data['created_at'] > timedelta(minutes=5):
            rooms_to_delete.append(room_id)
    
    for room_id in rooms_to_delete:
        if room_id in active_calls:
             app.logger.info(f"Cleaning up stale call room: {room_id}")
             del active_calls[room_id]

# تشغيل التنظيف الدوري
def call_cleanup_worker():
    while True:
        time.sleep(60)  # كل دقيقة
        with app.app_context(): # ضمان الوصول إلى سياق التطبيق
            cleanup_old_calls()
# --- نهاية الإضافات الجديدة ---


if __name__ == '__main__':
    import logging
    logging.basicConfig(level=logging.INFO)
    
    # --- بدء الإضافات الجديدة: بدء عامل التنظيف في خيط منفصل ---
    cleanup_thread = threading.Thread(target=call_cleanup_worker, daemon=True)
    cleanup_thread.start()
    # --- نهاية الإضافات الجديدة ---
    
    app.logger.info("Starting Flask-SocketIO server on http://0.0.0.0:5000")
    if not USER_DATABASE:
        app.logger.warning("User database is empty. No users will be able to log in.")
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
    # socketio.run(app, host='0.0.0.0', port=5000, debug=True, ssl_context=('cert.pem', 'key.pem'))
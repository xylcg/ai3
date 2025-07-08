from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
from datetime import datetime, timezone  # 导入 timezone
from config import Config
import requests
import hmac
import hashlib
import base64
import time
from flask_sqlalchemy import SQLAlchemy
import json

app = Flask(__name__)
app.config.from_object(Config)
app.secret_key = app.config['SECRET_KEY']
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# 初始化 SQLAlchemy
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# 用户模型
class User(db.Model):
    id = db.Column(db.String(36), primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    chat_history = db.relationship('Chat', backref='user', lazy=True)

    def get_id(self):
        return str(self.id)

    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

# 聊天记录模型
class Chat(db.Model):
    id = db.Column(db.String(36), primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    messages = db.relationship('Message', backref='chat', lazy=True)

# 消息模型
class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    role = db.Column(db.String(10), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    chat_id = db.Column(db.String(36), db.ForeignKey('chat.id'), nullable=False)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


def get_auth_header():
    api_key = Config.XINGHUO_API_KEY
    api_secret = Config.XINGHUO_API_SECRET

    # 生成RFC1123格式的时间戳（必须精确到秒）
    now = datetime.now(timezone.utc)
    timestamp = now.strftime('%a, %d %b %Y %H:%M:%S GMT')

    # 构造签名原始串（关键！注意空格和换行符）
    url_path = '/v2/chat/completions'
    host = 'spark-api-open.xf-yun.com'
    signature_origin = f"host: {host}\ndate: {timestamp}\nPOST {url_path} HTTP/1.1"

    # 打印签名原始串，用于调试
    print("签名原始串:", signature_origin)

    # 签名生成（确保使用正确的编码）
    signature_sha = hmac.new(
        api_secret.encode('utf-8'),
        signature_origin.encode('utf-8'),
        digestmod=hashlib.sha256
    ).digest()
    signature = base64.b64encode(signature_sha).decode('utf-8')

    # 打印最终签名，用于调试
    print("最终签名:", signature)

    # 构造Authorization头（严格遵循格式）
    authorization_origin = f'api_key="{api_key}", algorithm="hmac-sha256", headers="host date request-line", signature="{signature}"'
    authorization = base64.b64encode(authorization_origin.encode('utf-8')).decode('utf-8')

    return {
        "Authorization": f"hmac {authorization}",
        "Content-Type": "application/json",
        "Date": timestamp,
        "Host": host
    }
def call_deepseek_api(prompt):
    url = Config.XINGHUO_API_URL
    headers = get_auth_header()
    data = {
        "header": {
            "app_id": Config.XINGHUO_APPID,
            "uid": "123456"  # 任意唯一标识
        },
        "parameter": {
            "chat": {
                "domain": "generalv2",
                "temperature": 0.5,
                "max_tokens": 2048,
                "top_k": 4,  # 必须包含
                "chat_id": str(uuid.uuid4())  # 必须包含
            }
        },
        "payload": {
            "message": {
                "text": [
                    {
                        "role": "user",
                        "content": prompt,
                        "index": 1  # 必须包含
                    }
                ]
            }
        }
    }

    # 调试输出
    print("最终请求头:", json.dumps(headers, indent=2))
    print("最终请求体:", json.dumps(data, indent=2, ensure_ascii=False))

    try:
        response = requests.post(url, headers=headers, json=data, timeout=10)
        print("原始响应:", response.text)  # 关键调试信息

        if response.status_code == 401:
            print("认证失败！请检查：")
            print("1. API密钥三件套是否正确")
            print("2. 时间戳是否与服务器同步")
            print("3. 签名生成过程是否有误")

        response.raise_for_status()
        return response.json()
    except Exception as e:
        print(f"API调用失败: {str(e)}")
        raise  # 重新抛出异常以便调试

@app.route('/')
@login_required
def home():
    return redirect(url_for('profile'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('profile'))
        else:
            flash("无效的用户名或密码", "error")

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', user=current_user)


@app.route('/chat', methods=['GET', 'POST'])
@login_required
def chat():
    chat_id = request.args.get('chat_id')
    selected_chat = None

    if chat_id:
        selected_chat = Chat.query.filter_by(id=chat_id, user_id=current_user.id).first()

    if request.method == 'POST':
        prompt = request.form.get('prompt')

        if prompt:
            response = call_deepseek_api(prompt)

            if selected_chat:
                # 继续现有对话
                user_message = Message(role='user', content=prompt, chat=selected_chat)
                assistant_message = Message(role='assistant', content=response["content"], chat=selected_chat)
                db.session.add(user_message)
                db.session.add(assistant_message)
            else:
                # 新对话
                conversation_id = str(uuid.uuid4())
                conversation = Chat(id=conversation_id, title=prompt[:30] + ("..." if len(prompt) > 30 else ""), user=current_user)
                user_message = Message(role='user', content=prompt, chat=conversation)
                assistant_message = Message(role='assistant', content=response["content"], chat=conversation)
                db.session.add(conversation)
                db.session.add(user_message)
                db.session.add(assistant_message)

            db.session.commit()
            selected_chat = conversation if not selected_chat else selected_chat

            return redirect(url_for('chat', chat_id=selected_chat.id))

    return render_template(
        'chat.html',
        user=current_user,
        selected_chat=selected_chat,
        suggestions=[
            "如何提高工作效率？",
            "解释一下量子计算的基本概念",
            "写一封辞职信的模板"
        ]
    )


from markdown import markdown


@app.template_filter('format_time')
def format_time_filter(iso_string):
    if isinstance(iso_string, str):
        dt = datetime.fromisoformat(iso_string)
        return dt.strftime('%H:%M')
    return ''

@app.template_filter('markdown')
def markdown_filter(text):
    return markdown(text)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if username and password:
            user_id = str(uuid.uuid4())
            hashed_password = generate_password_hash(password)
            new_user = User(id=user_id, username=username, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            flash("注册成功，请登录", "success")
            return redirect(url_for('login'))
        else:
            flash("用户名和密码不能为空", "error")

    return render_template('register.html')


@app.route('/delete_chat/<chat_id>', methods=['POST'])
@login_required
def delete_chat(chat_id):
    # 从数据库中删除指定的聊天记录
    chat = Chat.query.filter_by(id=chat_id, user_id=current_user.id).first()
    if chat:
        for message in chat.messages:
            db.session.delete(message)
        db.session.delete(chat)
        db.session.commit()
    return redirect(url_for('chat'))


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
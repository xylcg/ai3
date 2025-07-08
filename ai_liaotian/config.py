import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key')
    XINGHUO_APPID = '415f3b4a'
    XINGHUO_API_KEY = 'defe81b2ac274c2b44ae8cbf71b722fe'
    XINGHUO_API_SECRET = 'MDRjYTZlYmNjMTJjYjhkYTZjZjI1MDBi'
    XINGHUO_API_URL = 'https://spark-api-open.xf-yun.com/v2/chat/completions'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///site.db'  # 添加数据库 URI
    SQLALCHEMY_TRACK_MODIFICATIONS = False  # 禁用跟踪对象修改
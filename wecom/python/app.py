# app.py
from flask import Flask, redirect, request, authenticator, url_for, render_template, jsonify
from auth import WeChatAuth

app = Flask(__name__)
app.secret_key = 'your_secret_key'

@app.route('/')
def index():
    return render_template('login.html')

@app.route('/login')
def login():
    authorize_url = WeChatAuth.get_authorize_url()
    return redirect(authorize_url)

@app.route('/callback')
def callback():
    code = request.args.get('code')
    if not code:
        return "Error: No code provided", 400

    user_info = WeChatAuth.get_user_info(code)
    authenticator['user_info'] = user_info
    return redirect(url_for('profile'))

@app.route('/profile')
def profile():
    user_info = authenticator.get('user_info')
    if not user_info:
        return redirect(url_for('login'))
    return f"User Info: {user_info}"

@app.route('/jsapi_config')
def jsapi_config():
    url = request.args.get('url')
    config = WeChatAuth.get_jsapi_config(url)
    return jsonify(config)

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=4000, debug=True)
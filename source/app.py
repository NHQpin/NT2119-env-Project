from flask import Flask, request, render_template, redirect, url_for, flash, session, send_from_directory
import os
import pyodbc
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from CryptoAPI import *
import base64

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.secret_key = 'supersecretkey'
DATA_SOURCE_NAME='cryptodata'
DRIVER={'SQL Server'}
SERVER='MSI\CRYPTODB'
DATABASE='MSSQLDB'
TRUSTED_CONNECTION='yes'
# Chuỗi kết nối tới SQL Server
conn_str = f'DSN={DATA_SOURCE_NAME};DRIVER={DRIVER};SERVER={SERVER};DATABASE={DATABASE};Trusted_Connection={TRUSTED_CONNECTION};'

def init_db():
    conn = pyodbc.connect(conn_str)
    cursor = conn.cursor()
    cursor.execute('''
        IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'users')
        CREATE TABLE users (
            user_id INT IDENTITY(1,1) PRIMARY KEY,
            username NVARCHAR(50) UNIQUE NOT NULL,
            password_hash NVARCHAR(162) NOT NULL
        )
    ''')
    
    cursor.execute('''
        IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'files')
        CREATE TABLE files (
            file_id INT IDENTITY(1,1) PRIMARY KEY,
            user_id INT NOT NULL,
            file_name NVARCHAR(255) NOT NULL,
            file_path NVARCHAR(255) NOT NULL,
            signature NVARCHAR(MAX) NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(user_id)
        )
    ''')
    cursor.execute('''
        IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'prikeys')
        CREATE TABLE prikeys (
            id INT IDENTITY(1,1) PRIMARY KEY,
            user_id INT NOT NULL,
            file_id INT NOT NULL,
            prisecretkey NVARCHAR(MAX) NOT NULL,
            prisignkey NVARCHAR(MAX) NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(user_id)
        )
    ''')
    cursor.execute('''
        IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'pubkeys')
        CREATE TABLE pubkeys (
            id INT IDENTITY(1,1) PRIMARY KEY,
            user_id INT NOT NULL,
            pubkeys NVARCHAR(MAX) NOT NULL,
        )
    ''')
    conn.commit()
    cursor.close()
    conn.close()


def load_key(file_path):
    with open(file_path, 'r') as file:
        base64_str = file.read().strip()
        try:
            bytes_data = base64.b64decode(base64_str)
            return bytes_data
        except Exception as e:
            print(f"Error decoding base64: {str(e)}")
    return None
def encrypt_file(file_path, key_file, output_path):
    key = load_key(key_file)
    with open(file_path, 'rb') as f:
        data = f.read()

    ciphertext = encrypt(key, data)
    
    with open(output_path, 'wb') as f:
        f.write(ciphertext.encode('utf-8'))

def decrypt_file(file_path, key_file, output_path):
    key = load_key(key_file)
    with open(file_path, 'rb') as f:
        ciphertext = f.read()
        
    data = decrypt(key, ciphertext)

    with open(output_path, 'wb') as f:
        f.write(data)

def sign_file(file_path, private_key_file):
    with open(file_path, 'rb') as f:
        data = f.read()
    key = load_key(private_key_file)
    signature = gen_sig(key, data)
    return signature

def verify_signature(file_path, signature, public_key_file):
    with open(file_path, 'rb') as f:
        data = f.read()
    key = load_key(public_key_file)
    isValid = verify_sig(key, data, signature)
    return isValid

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('list_files'))  # Chuyển hướng đến trang danh sách file nếu đã đăng nhập
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        password_hash = generate_password_hash(password)
        print(f"password_hash has {len(password_hash)} characters")
        conn = pyodbc.connect(conn_str)
        cursor = conn.cursor()
        try:
            cursor.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', (username, password_hash))
            conn.commit()
            flash('Registration successful. Please log in.')
            return redirect(url_for('login'))
        except pyodbc.IntegrityError:
            flash('Username already exists. Please choose a different one.')
        finally:
            cursor.close()
            conn.close()
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = pyodbc.connect(conn_str)
        cursor = conn.cursor()
        cursor.execute('SELECT user_id, password_hash FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()
        
        if user and check_password_hash(user[1], password):
            session['user_id'] = user[0]
            flash('Login successful.')
            return redirect(url_for('list_files'))
        else:
            flash('Invalid username or password.')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('You have been logged out.')
    return redirect(url_for('index'))

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if 'user_id' not in session:
        flash('Please log in to upload files.')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file:
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            
            encrypted_filepath = os.path.join(app.config['UPLOAD_FOLDER'], f'encrypted_{filename}')
            encrypt_file(filepath, 'prisecretkey.pem', encrypted_filepath)
            
            signature = sign_file(encrypted_filepath, 'priSignKey.pem')
            
            save_to_db(filename, encrypted_filepath, session['user_id'], signature)
            os.remove(filepath)
            
            flash('File successfully uploaded and encrypted.')
            return redirect(url_for('list_files'))
    
    return render_template('upload.html')

@app.route('/files')
def list_files():
    if 'user_id' not in session:
        flash('Please log in to view files.')
        return redirect(url_for('login'))
    
    file_list = fetch_files_from_db(session['user_id'])
    return render_template('files.html', file_list=file_list)

@app.route('/download/<int:file_id>')
def download_file(file_id):
    if 'user_id' not in session:
        flash('Please log in to download files.')
        return redirect(url_for('login'))
    
    conn = pyodbc.connect(conn_str)
    cursor = conn.cursor()
    cursor.execute('SELECT file_name, file_path, signature FROM files WHERE file_id = ? AND user_id = ?', (file_id, session['user_id']))
    file_record = cursor.fetchone()
    cursor.close()
    conn.close()
    
    if file_record:
        file_name = file_record[0]
        file_path = file_record[1]
        signature = file_record[2]
        
        if verify_signature(file_path, signature, 'pubSignKey.pem'):
            decrypted_filepath = os.path.join(app.config['UPLOAD_FOLDER'], f'decrypted_{file_name}')
            decrypt_file(file_path, 'prisecretkey.pem', decrypted_filepath)
            try:
                return send_from_directory(directory=app.config['UPLOAD_FOLDER'], filename=f'decrypted_{file_name}', as_attachment=True)
            except Exception as e:
                flash(f"Error downloading file: {str(e)}")
                return redirect(url_for('list_files'))
        else:
            flash('File verification failed. Possible tampering detected.')
            return redirect(url_for('list_files'))
    
    flash('File not found')
    return redirect(url_for('list_files'))

@app.route('/delete/<int:file_id>', methods=['POST'])
def delete_file(file_id):
    if 'user_id' not in session:
        flash('Please log in to delete files.')
        return redirect(url_for('login'))
    
    conn = pyodbc.connect(conn_str)
    cursor = conn.cursor()
    cursor.execute('SELECT file_name, file_path FROM files WHERE file_id = ? AND user_id = ?', (file_id, session['user_id']))
    file_record = cursor.fetchone()
    
    if file_record:
        try:
            file_path = file_record[1]
            os.remove(file_path)
            cursor.execute('DELETE FROM files WHERE file_id = ?', (file_id,))
            conn.commit()
            flash('File deleted successfully.')
        except Exception as e:
            flash(f"Error deleting file: {str(e)}")
    else:
        flash('File not found or you do not have permission to delete it.')
    
    cursor.close()
    conn.close()
    return redirect(url_for('list_files'))

def fetch_files_from_db(user_id):
    conn = pyodbc.connect(conn_str)
    cursor = conn.cursor()
    cursor.execute('SELECT file_id, file_name FROM files WHERE user_id = ?', (user_id,))
    files = cursor.fetchall()
    cursor.close()
    conn.close()
    return files

def save_to_db(filename, filepath, user_id, signature):
    conn = pyodbc.connect(conn_str)
    cursor = conn.cursor()
    cursor.execute('INSERT INTO files (user_id, file_name, file_path, signature) VALUES (?, ?, ?, ?)', (user_id, filename, filepath, signature))
    conn.commit()
    cursor.close()
    conn.close()

if __name__ == '__main__':
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
    init_db()
    app.run(debug=True)
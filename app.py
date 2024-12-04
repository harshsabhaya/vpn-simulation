from flask import Flask, render_template, request, redirect, url_for, session, flash
import json
import subprocess
from vpn_backend import udp  
from vpn_backend import utils
import socket

app = Flask(__name__)
app.secret_key = 'your_secret_key'

def send_vpn_message(user, password, target_ip, target_port, message):
    CLIENT_ADDR = ('127.0.0.1', 0)
    VPN_ADDR = ('127.1.1.1', 9999)

    raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
    try:
        # Create the data packet
        data = {
            "user": user,
            "password": password,
            "message": message,
            "target_ip": target_ip,
            "target_port": target_port
        }
        json_string = json.dumps(data)

        # Build and send the packet
        packet = udp.build_packet(json_string, VPN_ADDR, CLIENT_ADDR)
        raw_socket.sendto(packet, VPN_ADDR)

        return "Message sent successfully"
    except Exception as e:
        return f"Error: {str(e)}"
    finally:
        raw_socket.close()

def load_ips():
    try:
        with open('vpn_backend/ips.json', 'r') as file:
            return json.load(file)
    except FileNotFoundError:
        return {}

# Load user data
def load_users():
    try:
        with open('vpn_backend/users.json', 'r') as file:
            return json.load(file)
    except FileNotFoundError:
        return {}

# Route: Home Page
@app.route('/')
def index():
    return render_template('index.html')

# Route: Login Page
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Validate user credentials
        users = load_users()
        if username not in users:
            flash("User not found. Please check your username or sign up.", "danger")
        elif users[username] != password:
            flash("Incorrect password. Please try again.", "warning")
        else:
            session['username'] = username
            flash(f"Welcome, {username}!", "success")
            return redirect(url_for('dashboard'))

    return render_template('login.html')

@app.route('/connect-vpn', methods=['POST'])
def connect_vpn():
    if 'username' not in session:
        return {"error": "Unauthorized"}, 401

    username = session['username']

    # Assign a new IP to the user (simulated)
    users_ips = load_ips()
    if username not in users_ips:
        users_ips[username] = f"192.168.1.{len(users_ips) + 2}"  # Example new IP logic
        # save_data('vpn_backend/ips.json', users_ips)

    # Get the new IP
    new_ip = users_ips[username]

    session['connected'] = True
    session['new_ip'] = users_ips[username]
    return {"new_ip": new_ip}, 200


# Route: User Dashboard
@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        flash("You must log in first", "danger")
        return redirect(url_for('login'))
    
    connected = session.get('connected', False)
    new_ip = session.get('new_ip', None)

    return render_template('dashboard.html', username=session['username'], connected=connected, new_ip=new_ip)

@app.route('/send', methods=['POST'])
def send_vpn_message_default():
    if 'username' not in session:
        return {"error": "Unauthorized. Please log in first."}, 401

    try:
        # Retrieve form data
        target_ip = request.form.get('target_ip')
        target_port = request.form.get('target_port')
        message = request.form.get('message')
        
        # Validate inputs
        if not utils.validate_input_ip(target_ip, False):
            return {"error": "Invalid target IP address."}, 400
        if not utils.validate_input_port(target_port):
            return {"error": "Invalid target port."}, 400

        users = load_users()
        # Send the message
        user = session['username']
        password =  users[user] # Replace with actual password logic
        response = send_vpn_message(user, password, target_ip, target_port, message)
        
        if "Error" in response:
            return {"error": response}, 500
        return {"message": response, 'target_ip': target_ip, 'target_port': target_port}, 200
    except Exception as e:
        return {"error": f"Internal server error: {str(e)}"}, 500

@app.route('/send', methods=['GET'])
def send_message():
    if 'username' not in session:
        flash("You must log in first", "danger")
        return redirect(url_for('login'))
    
    return render_template('send.html')

# Route: Logout
@app.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out successfully.", "info")
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)

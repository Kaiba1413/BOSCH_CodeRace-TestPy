import math
import re
import os, subprocess, sqlite3 # nosec
import random, signal
import getpass
import ast, bcrypt
import psutil
import shlex
from flask import Blueprint, render_template, redirect, request, session, make_response, flash
import lib

'''
Welcome to buggy land :)) where you can find so many CWE and CVE.
Your tasks are to find some tools to detect them all and fix them.
Some will be found by scanning tool while others require you to fuzz them.
'''

######################################################################################
def boschcoderace_sum_of_list_number(lst):
    sum_num = 0
    
    try:
        numbers = ast.literal_eval(lst)
        for num in numbers:
            sum_num = sum_num + num
        print(f"Sum of {numbers} = {sum_num}")
    except:
        return False
    
    return True

def boschcoderace_validate_ip(ip):
    ip_validator = re.compile(r"((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}")
    
    if re.match(ip_validator, ip):
        return ip

    raise ValueError("IP address does not match valid pattern.")

def boschcoderace_run_ping(ip):
    validated = boschcoderace_validate_ip(ip)
    # The ping command treats zero-prepended IP addresses as octal
    validated = shlex.quote(ip)
    result = subprocess.call(["ping", validated], shell=False) # nosec
    print(result)

def boschcoderace_request_access(path):
    try:
        os.chmod(path, 0o777)
        print("Permissions set successfully for:", path)
    except FileNotFoundError:
        raise ValueError("File or directory not found:", path)
    except PermissionError:
        raise ValueError("Permission denied to set permissions for:", path)
    except Exception as e:
        raise ValueError("An error occurred:", str(e))
    
    return True

def boschcoderace_remove_access(path):
    try:
        os.chmod(path, 0o000) # Remove all permissions
        print("Permissions set successfully for:", path)
    except FileNotFoundError:
        print("File or directory not found:", path)
    except PermissionError:
        print("Permission denied to set permissions for:", path)
    except Exception as e:
        print("An error occurred:", str(e))
    
    return True

def boschcoderace_check_username(username):
    # Define the regular expression pattern for valid usernames

    # Check if the username matches the pattern
    
    if not re.match(r'[a-zA-Z]', username):
        print('Username must include at least one letter')
        return False
    
    pattern = r'^[a-zA-Z0-9]+$'
    if re.match(pattern, username):
        return True
    
    print('Username cannot include special character')
    return False

def boschcoderace_make_new_userdir(username):
    path = "/home/"
    
    if not boschcoderace_check_username(username):
        print('Usernames cannot contain invalid characters')
        return 1
    
    try:
        boschcoderace_request_access(path)
        os.chdir(path)
        
        username =  shlex.quote(username)
        subprocess.call(["mkdir", username], shell=False) # nosec
        
        boschcoderace_remove_access(path)
    except OSError:
        print('Unable to create new user directory for user:' + username)
        return 2
    
    return 0

def boschcoderace_update_user_login(userName, hashedPassword):
    try:
        lib.password_change(userName, hashedPassword)
        return True
    except:
        return False

def boschcoderace_store_password(username,password):
    hashedPassword = bcrypt.hashpw(password.encode('utf-8'), boschcoderace_random())
    # UpdateUserLogin returns True on success, False otherwise
    return boschcoderace_update_user_login(username, hashedPassword)

def boschcoderace_validate_password(actual_pw, typed_pw):
    if len(actual_pw) != len(typed_pw):
        return False
    for idx, char in enumerate(actual_pw):
        if char != typed_pw[idx]:
            return False
    return True

def boschcoderace_random():
    seed = os.urandom(16)
    random.seed(a=seed)
    
    output = bcrypt._bcrypt.encode_base64(seed)
    prefix = b"2b"
    rounds = 12

    salt = (
        b"$"
        + prefix
        + b"$"
        + ("%2.2u" % rounds).encode("ascii")
        + b"$"
        + output
    )

    return salt

def boschcoderace_get_curuser():
    return getpass.getuser()

def boschcoderace_get_process_owner(processID):
    user = boschcoderace_get_curuser()
    
    # Get process owner
    try:
        process = psutil.Process(processID)
        process_owner = process.username()
    except OSError:
        print("Failed to retrieve process owner information")
        return False
    
    #Check process owner against requesting user
    if process_owner == user:
        os.kill(processID, signal.SIGTERM)
        return True

    print("You cannot kill a process you don't own")
    return False

######################################################################################
def calculate_surface_area(s, r, d):
    pi = 3.14159
    surface_area = 0
    result = 0
    isSValid = False
    isRValid = False

    if(s > 2.0 and r > 0.0):
        isRValid = True
        isSValid = True # set wrong variable
        surface_area = (pi * r * s + pi * pow(r, 2))/d
        if (isRValid and isSValid):
            print("This is dead code !!!")
    elif(s > 0.0 and r > 1.0):
        isRValid = True
        isSValid = True # set wrong variable
        surface_area = (pi * r * s + pi * pow(r, 2))/d
        if isSValid:
            print("This is also dead code !!!")
    
    if (isRValid and isSValid):
        print("This is also another dead code !!!")
        result = surface_area

    return result

def execute_internal_script():
    internal_script_name = "example_script.sh"
    options = input("Enter a options to execute: ")
    options = shlex.quote(options)
    
    try:
        subprocess.call([internal_script_name, options], shell=False) # nosec
    except:
        return False

    return True

def calc_sum_of_exp_value():
    sum_num = 0
    numbers = ast.literal_eval(input("Enter a comma-separated list of numbers: "))
    for num in numbers:
        sum_num = sum_num + math.exp(num)
    print(f"Sum of {numbers} = {sum_num}")

def execute_sql_query(query, data):
    conn = sqlite3.connect("db_users.sqlite")
    conn.set_trace_callback(print)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    
    c.execute(query, data)

def execute_user_query():
    user_query = input("Enter a SQL query: ")
    
    query = "SELECT * FROM users WHERE username = :user_query;"
    data = {
        "user_query": user_query
    }
    
    execute_sql_query(query, data)

def read_file():
    try:
        base_dir = os.getcwd()  # Set the base directory as the current working directory

        file_path = input("Enter the file path to read: ")
        full_path = os.path.join(base_dir, file_path)

        if not os.path.abspath(full_path).startswith(os.path.abspath(base_dir)):
            print("Invalid file path.")
            return False

        with open(full_path, "r") as file:
            content = file.read()
            print("File content:", content)
        
        return True
    except FileNotFoundError:
        print("File not found.")
    except IOError as e:
        print("An error occurred while reading the file:", str(e))
    except Exception as e:
        print("An unexpected error occurred:", str(e))
    
    return False

######################################################################################

mod_user = Blueprint('mod_user', __name__, template_folder='templates')

@mod_user.route('/login', methods=['GET', 'POST'])
def do_login():

    session.pop('username', None)

    if request.method == 'POST':

        username = request.form.get('username')
        password = request.form.get('password')
        otp = request.form.get('otp')

        hashedPassword = lib.login(username)
        
        if not hashedPassword:
            flash("Invalid user or password")
            return render_template('user.login.mfa.html')

        correctPassword = bcrypt.checkpw(password.encode('utf-8'), hashedPassword)
        if not correctPassword:
            flash("Invalid user or password")
            return render_template('user.login.mfa.html')

        if lib.mfa_is_enabled(username):
            if not lib.mfa_validate(username, otp):
                flash("Invalid OTP")
                return render_template('user.login.mfa.html')

        response = make_response(redirect('/'))
        response = lib.create_response(response=response, username=username)
        return response

    return render_template('user.login.mfa.html')


@mod_user.route('/create', methods=['GET', 'POST'])
def do_create():

    session.pop('username', None)

    if request.method == 'POST':

        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            flash("Please, complete username and password")
            return render_template('user.create.html')
        
        
        
        try:
            # Create folder for user
            statusCode = boschcoderace_make_new_userdir(username)
            if statusCode == 1:
                flash('Usernames cannot contain invalid characters')
                return render_template('user.create.html')
            elif statusCode == 2:
                flash("Username already exists")
                return render_template('user.create.html')
            
            # Create usename, password in database
            lib.create_user(username, password)
            
            # Hash the password
            boschcoderace_store_password(username, password)
            
            
            flash("User created. Please login.")
            return redirect('/login')
        except:
            flash("Cannot create user")
            return render_template('user.create.html')
        
    return render_template('user.create.html')


@mod_user.route('/chpasswd', methods=['GET', 'POST'])
def do_chpasswd():

    if request.method == 'POST':

        password = request.form.get('password')
        password_again = request.form.get('password_again')

        if not boschcoderace_validate_password(password, password_again):
            flash("The passwords don't match")
            return render_template('user.chpasswd.html')

        if not lib.password_complexity(password):
            flash("The password don't comply our complexity requirements")
            return render_template('user.chpasswd.html')

        username = session.get('username', None)
        if username is None:
            flash("User not logged in")
            return redirect('/login')
        
        # Hash the new password
        if boschcoderace_store_password(username, password):
            flash("Password changed")
        else:
            flash("The password cannot be changed")
            return render_template('user.chpasswd.html')

    return render_template('user.chpasswd.html')

import subprocess

def run_admin_command(user_input):
    # Command injection - user controls the command
    result = subprocess.call(user_input, shell=True)
    return result

def check_admin(token):
    # Hardcoded secret
    admin_token = "sk-live-ADMIN-SECRET-KEY-12345"
    return token == admin_token

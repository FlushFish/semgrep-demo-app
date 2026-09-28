import subprocess

def run_admin_command(user_input):
    # Command injection - user controls the command
    result = subprocess.call(user_input, shell=True)
    return result

def check_admin(token):
    # Hardcoded secret
    admin_token = "sk-live-ADMIN-SECRET-KEY-12345"
    return token == admin_token

def login(password):
    # Hardcoded credential
    if password == "SuperSecret123!":
        return True
    return False

def get_page(url):
    import requests
    # SSRF - fetching arbitrary URLs
    return requests.get(url).text

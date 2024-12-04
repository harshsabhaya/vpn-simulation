from datetime import datetime
import json

def invalidate_args(args, args_count):
    if args != args_count:
        print(f"Given {args} arguments, but expected {args_count}")
        return True
    else:
        return False

def format_dict(dictionary):
    formatted_str = "\n"
    for key, value in dictionary.items():
        formatted_str += f"{key}: {value}\n"
    return formatted_str

def is_subnet(x: str, ip: str):
    x_bytes = x.split(".")
    ip_bytes = ip.split(".")

    for i in range(4):
        if ip_bytes[i] != "x":
            if ip_bytes[i] == x_bytes[i]:
                continue
            else: 
                return False
        else:
            return True
   
    return True

def write_log(log):
    date_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open('logs.txt', 'a') as file:
        file.write(date_time + ': ' + log + '\n')


def validate_input_ip(ip: str, include_x=True):
    ip_arr = ip.split(".")

    if len(ip_arr) != 4:
        print("Invalid ip")
        return False
    
    valid_bytes = are_bytes_valid(ip_arr) if include_x else are_bytes_numbers(ip_arr)
    
    if not valid_bytes:
        print("Invalid ip")
        return False
    
    return True

def validate_input_port(port: str):
    try:
        _ = int(port)

        if len(port) == 4 or len(port) == 5:
            return True
    except:
        pass

    print("Invalid port")
    return False

def are_bytes_valid(bytes):
    found = False
    for s in bytes:
        try:
            value = int(s)

            if found:
                return False

            if not 0 <= value <= 255:
                return False
        except ValueError:
            found = True
            if not s == 'x':
                return False
    return True

def are_bytes_numbers(bytes):
    for b in bytes:
        try:
            value = int(b)
            if not 0 <= value <= 255:
                return False
        except ValueError:
            return False
    return True

def refact_request(request: str):
    data = json.loads(request)
    user = data['user']
    message = data['message']
    target_ip, target_port = (data['target_ip'], int(data['target_port']))
    return f"User '{user}' requested '{message}' to '{target_ip}:{target_port}'"
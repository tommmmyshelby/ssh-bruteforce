import paramiko
import json

HOST = "192.168.56.101"
USERNAME = "ubuntu"
PASSWORD = "enter_your_password_here"

client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

try:
    print("Connecting to Ubuntu...")

    client.connect(
        HOST,
        username=USERNAME,
        password=PASSWORD
    )

    stdin, stdout, stderr = client.exec_command(
        "sudo python3 /home/ubuntu/Desktop/ssh-bruteforce/ssh_agent.py"
    )

    output = stdout.read().decode()
    error = stderr.read().decode()

    if error:
        print(error)
    else:
        data = json.loads(output)

        print("\n===== CENTRALIZED SSH ANALYSIS =====\n")

        for attack in data:
            print(f"IP Address      : {attack['ip']}")
            print(f"Failed Attempts : {attack['attempts']}")
            print(f"Risk Level      : {attack['risk_level']}")
            print("-" * 40)

except Exception as e:
    print("Error:", e)

finally:
    client.close()

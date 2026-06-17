import paramiko
import json

HOST = "192.168.56.101"
USERNAME = "ubuntu"
PASSWORD = "123"

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
        with open("attack_data.json", "w") as f:
            json.dump(data, f, indent=4)

        
        for attack in data:

            print("\n====================================================")
            print("           SSH BRUTE FORCE ANALYSIS REPORT")
            print("====================================================\n")

            print(f"Source IP            : {attack['ip']}")
            usernames = ", ".join(attack["usernames"])
            print(f"Target Username(s)   : {usernames}")
            print()

            print(f"Failed Attempts      : {attack['attempts']}")
            print(f"Rapid Attempts       : {attack['rapid_attempts']}")
            print(f"Success After Failure: {'YES' if attack['success_after_failure'] else 'NO'}")
            print()

            print(f"Risk Score           : {attack['risk_score']}")
            print(f"Risk Level           : {attack['risk_level']}")
            print()

            if attack['risk_level'] == "HIGH":
                attack_type = "SSH Brute Force Attack"
                recommendation = "[!] Block IP Immediately"

            elif attack['risk_level'] == "MEDIUM":
                attack_type = "Suspicious Login Activity"
                recommendation = "[!] Investigate Activity"

            else:
                attack_type = "Normal Failed Logins"
                recommendation = "[!] Continue Monitoring"

            print(f"Attack Classification: {attack_type}")
            print()
            print("Recommendation:")
            print(recommendation)

            print("\n====================================================")

except Exception as e:
    print(e)

finally:
    client.close()
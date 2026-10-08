from faker import Faker
import os, json, random
from datetime import datetime, timedelta

fake = Faker('en_IN')  # Indian locale for realistic names

BRANCHES = ['mumbai', 'delhi', 'bangalore', 'chennai', 'hyderabad']

def generate_employees(branch, count=20):
    employees = []
    for _ in range(count):
        employees.append({
            "id": fake.uuid4(),
            "name": fake.name(),
            "email": fake.email(),
            "department": random.choice(["IT", "HR", "Finance", "Operations", "Security"]),
            "branch": branch
        })
    return employees

def generate_files(branch, count=10):
    file_types = ['.pdf', '.docx', '.xlsx', '.txt', '.csv']
    files = []
    for i in range(count):
        fname = f"{fake.word()}_{fake.word()}{random.choice(file_types)}"
        fpath = f"branch_{branch}/{fname}"
        with open(fpath, 'w') as f:
            f.write(f"Confidential data for {branch} branch. Record {i+1}.\n")
            f.write(fake.paragraph())
        files.append(fpath)
    return files

def generate_login_logs(branch, count=50):
    logs = []
    base_time = datetime.now() - timedelta(days=7)
    for i in range(count):
        logs.append({
            "timestamp": (base_time + timedelta(hours=i*3)).isoformat(),
            "user": fake.email(),
            "ip": fake.ipv4_private(),
            "status": "success",
            "branch": branch
        })
    return logs

if __name__ == "__main__":
    for branch in BRANCHES:
        print(f"Generating data for branch_{branch}...")

        emp = generate_employees(branch)
        with open(f"branch_{branch}/employees.json", 'w') as f:
            json.dump(emp, f, indent=2)

        files = generate_files(branch)

        logs = generate_login_logs(branch)
        with open(f"branch_{branch}/login_logs.json", 'w') as f:
            json.dump(logs, f, indent=2)

        print(f"  ✓ {len(emp)} employees, {len(files)} files, {len(logs)} login records")

    print("\nAll branch data generated successfully!")
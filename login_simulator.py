import random
import json
import pandas as pd
from datetime import datetime, timedelta
from faker import Faker

fake = Faker('en_IN')

BRANCHES = ['mumbai', 'delhi', 'bangalore', 'chennai', 'hyderabad']

def generate_normal_logins(count=1000):
    logins = []
    base_time = datetime.now() - timedelta(days=7)

    for i in range(count):
        logins.append({
            "timestamp": (base_time + timedelta(minutes=i*15)).isoformat(),
            "user": fake.email(),
            "ip": fake.ipv4_private(),
            "attempts": random.randint(1, 3),          # 1-3 attempts = normal
            "time_gap_seconds": random.randint(300, 7200),  # 5min-2hr gap
            "location": random.choice(BRANCHES),
            "label": 0
        })
    return logins

def generate_attack_logins(count=200):
    logins = []
    base_time = datetime.now()

    for i in range(count):
        logins.append({
            "timestamp": (base_time + timedelta(seconds=i*5)).isoformat(),
            "user": fake.email(),
            "ip": fake.ipv4_public(),
            "attempts": random.randint(8, 25),         # 8-25 attempts = attack
            "time_gap_seconds": random.randint(1, 20), # very rapid = attack
            "location": random.choice(BRANCHES),
            "label": 1
        })
    return logins

if __name__ == "__main__":
    print("Regenerating login data with improved patterns...")

    normal = generate_normal_logins(1000)
    attacks = generate_attack_logins(200)
    all_logins = normal + attacks

    df = pd.DataFrame(all_logins)
    df.to_csv("login_data.csv", index=False)

    print(f"  ✓ {len(normal)} normal logins generated")
    print(f"  ✓ {len(attacks)} attack logins generated")
    print(f"  ✓ Saved to login_data.csv")
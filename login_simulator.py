import random
import json
import pandas as pd
from datetime import datetime, timedelta
from faker import Faker

fake = Faker('en_IN')

BRANCHES = ['mumbai', 'delhi', 'bangalore', 'chennai', 'hyderabad']

def generate_normal_logins(count=500):
    logins = []
    base_time = datetime.now() - timedelta(days=7)

    for i in range(count):
        logins.append({
            "timestamp": (base_time + timedelta(minutes=i*15)).isoformat(),
            "user": fake.email(),
            "ip": fake.ipv4_private(),        # private IPs = normal
            "attempts": 1,                     # one attempt = normal
            "time_gap_seconds": random.randint(600, 3600),  # 10min-1hr gap
            "location": random.choice(BRANCHES),
            "label": 0                         # 0 = normal
        })
    return logins

def generate_attack_logins(count=100):
    logins = []
    base_time = datetime.now()

    for i in range(count):
        logins.append({
            "timestamp": (base_time + timedelta(seconds=i*5)).isoformat(),
            "user": fake.email(),
            "ip": fake.ipv4_public(),          # public IPs = suspicious
            "attempts": random.randint(5, 20), # multiple attempts = attack
            "time_gap_seconds": random.randint(1, 30),  # rapid logins
            "location": random.choice(BRANCHES),
            "label": 1                         # 1 = attack
        })
    return logins

if __name__ == "__main__":
    print("Generating login data...")

    normal = generate_normal_logins(500)
    attacks = generate_attack_logins(100)
    all_logins = normal + attacks

    # Save to CSV for ML training
    df = pd.DataFrame(all_logins)
    df.to_csv("login_data.csv", index=False)

    print(f"  ✓ {len(normal)} normal logins generated")
    print(f"  ✓ {len(attacks)} attack logins generated")
    print(f"  ✓ Saved to login_data.csv")
    print(f"\nSample attack record:")
    print(json.dumps(attacks[0], indent=2))
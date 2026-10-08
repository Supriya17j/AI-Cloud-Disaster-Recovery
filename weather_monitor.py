import requests
import json
from datetime import datetime
from dotenv import load_dotenv
import os

load_dotenv()

API_KEY = os.getenv("OPENWEATHERMAP_API_KEY")

CITIES = {
    "mumbai": "Mumbai,IN",
    "delhi": "Delhi,IN",
    "bangalore": "Bangalore,IN",
    "chennai": "Chennai,IN",
    "hyderabad": "Hyderabad,IN"
}

DISASTER_THRESHOLDS = {
    "wind_speed": 20,      # metres per second
    "humidity": 90,         # percentage
    "temp": 42             # celsius
}

def get_weather(city_name, city_code):
    url = f"http://api.openweathermap.org/data/2.5/weather?q={city_code}&appid={API_KEY}&units=metric"
    response = requests.get(url)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"  ✗ Failed to fetch weather for {city_name}: {response.status_code}")
        return None

def check_disaster(city_name, data):
    alerts = []
    temp = data["main"]["temp"]
    humidity = data["main"]["humidity"]
    wind_speed = data["wind"]["speed"]

    if temp >= DISASTER_THRESHOLDS["temp"]:
        alerts.append(f"🌡 High temperature: {temp}°C")
    if humidity >= DISASTER_THRESHOLDS["humidity"]:
        alerts.append(f"💧 High humidity: {humidity}%")
    if wind_speed >= DISASTER_THRESHOLDS["wind_speed"]:
        alerts.append(f"💨 High wind speed: {wind_speed} m/s")

    return alerts

def monitor_weather():
    print(f"\n{'='*50}")
    print(f"Weather Monitor — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*50}")

    for branch, city_code in CITIES.items():
        print(f"\n📍 {branch.upper()}")
        data = get_weather(branch, city_code)

        if data:
            temp = data["main"]["temp"]
            humidity = data["main"]["humidity"]
            wind_speed = data["wind"]["speed"]
            condition = data["weather"][0]["description"]

            print(f"   Condition  : {condition}")
            print(f"   Temp       : {temp}°C")
            print(f"   Humidity   : {humidity}%")
            print(f"   Wind Speed : {wind_speed} m/s")

            alerts = check_disaster(branch, data)
            if alerts:
                print(f"   ⚠ DISASTER ALERTS:")
                for alert in alerts:
                    print(f"     → {alert}")
            else:
                print(f"   ✓ No alerts")

if __name__ == "__main__":
    monitor_weather()
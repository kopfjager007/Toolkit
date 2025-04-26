#!/usr/bin/env python3
# Author: Aaron Lesmeister
# Purpose: Needed to convert GNGGA to LAT/LONG during an IoT pentest for location plotting
import sys

def parse_gngga(gngga_data):
    parts = gngga_data.split(',')
    
    # Extract and parse latitude
    raw_latitude = parts[2]
    lat_direction = parts[3]
    latitude_deg = int(raw_latitude[:2])
    latitude_min = float(raw_latitude[2:])
    latitude = latitude_deg + (latitude_min / 60)
    if lat_direction == 'S':
        latitude = -latitude
    
    # Extract and parse longitude
    raw_longitude = parts[4]
    lon_direction = parts[5]
    longitude_deg = int(raw_longitude[:3])
    longitude_min = float(raw_longitude[3:])
    longitude = longitude_deg + (longitude_min / 60)
    if lon_direction == 'W':
        longitude = -longitude
    
    return latitude, longitude

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py '<GNGGA data>'")
        sys.exit(1)
    
    gngga_data = sys.argv[1]
    latitude, longitude = parse_gngga(gngga_data)
    print(f"{latitude}, {longitude}")

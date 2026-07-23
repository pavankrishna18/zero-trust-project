"""
Geo-Location Service for Zero Trust
IP geolocation, geo-fencing, and travel pattern analysis
"""

import logging
import requests
from datetime import datetime, timezone
from math import radians, cos, sin, asin, sqrt
from models import db, ActivityLog

logger = logging.getLogger(__name__)

# Blocked countries (example - customize as needed)
BLOCKED_COUNTRIES = ['KP', 'IR', 'SY']  # North Korea, Iran, Syria
HIGH_RISK_COUNTRIES = ['RU', 'CN', 'KP', 'IR']  # Russia, China, etc.

class GeoLocationService:
    """IP Geolocation and Geo-Fencing"""
    
    # Free IP geolocation APIs (no key required)
    IPAPI_URL = "http://ip-api.com/json/{ip}?fields=status,country,countryCode,region,city,lat,lon,isp,proxy,hosting"
    BACKUP_URL = "https://ipapi.co/{ip}/json/"
    
    @staticmethod
    def get_location(ip_address):
        """
        Get geographic location from IP address
        Returns: dict with country, city, lat, lon, etc.
        """
        if ip_address in ['127.0.0.1', 'localhost', '::1']:
            return {
                'country': 'Local',
                'country_code': 'LOCAL',
                'city': 'Localhost',
                'latitude': 0,
                'longitude': 0,
                'isp': 'Local',
                'is_proxy': False,
                'is_hosting': False
            }
        
        try:
            # Try primary API
            response = requests.get(
                GeoLocationService.IPAPI_URL.format(ip=ip_address),
                timeout=5
            )
            
            if response.status_code == 200:
                data = response.json()
                
                if data.get('status') == 'success':
                    return {
                        'country': data.get('country', 'Unknown'),
                        'country_code': data.get('countryCode', 'XX'),
                        'city': data.get('city', 'Unknown'),
                        'region': data.get('region', 'Unknown'),
                        'latitude': data.get('lat', 0),
                        'longitude': data.get('lon', 0),
                        'isp': data.get('isp', 'Unknown'),
                        'is_proxy': data.get('proxy', False),
                        'is_hosting': data.get('hosting', False)
                    }
        except Exception as e:
            logger.warning('Primary geolocation API failed: %s', str(e))
        
        # Fallback: Return unknown location
        return {
            'country': 'Unknown',
            'country_code': 'XX',
            'city': 'Unknown',
            'latitude': 0,
            'longitude': 0,
            'isp': 'Unknown',
            'is_proxy': False,
            'is_hosting': False
        }
    
    @staticmethod
    def is_blocked_country(country_code):
        """Check if country is blocked"""
        return country_code in BLOCKED_COUNTRIES
    
    @staticmethod
    def is_high_risk_country(country_code):
        """Check if country is high-risk"""
        return country_code in HIGH_RISK_COUNTRIES
    
    @staticmethod
    def calculate_distance(lat1, lon1, lat2, lon2):
        """
        Calculate distance between two coordinates (Haversine formula)
        Returns: distance in kilometers
        """
        try:
            # Convert to radians
            lat1, lon1, lat2, lon2 = map(radians, [lat1, lon1, lat2, lon2])
            
            # Haversine formula
            dlat = lat2 - lat1
            dlon = lon2 - lon1
            a = sin(dlat/2)**2 + cos(lat1) * cos(lat2) * sin(dlon/2)**2
            c = 2 * asin(sqrt(a))
            
            # Earth radius in kilometers
            r = 6371
            
            return c * r
        except:
            return 0
    
    @staticmethod
    def check_impossible_travel(user, current_ip):
        """
        Check for impossible travel
        Returns: dict with is_suspicious and details
        """
        try:
            # Get last login location
            last_activity = ActivityLog.query.filter(
                ActivityLog.user_id == user.id,
                ActivityLog.action == 'login',
                ActivityLog.status == 'success'
            ).order_by(ActivityLog.timestamp.desc()).first()
            
            if not last_activity or not last_activity.ip_address:
                return {'is_suspicious': False, 'reason': None}
            
            # Get locations
            last_location = GeoLocationService.get_location(last_activity.ip_address)
            current_location = GeoLocationService.get_location(current_ip)
            
            # Calculate time difference (hours)
            time_diff = (datetime.now(timezone.utc) - last_activity.timestamp).total_seconds() / 3600
            
            # Calculate distance
            distance = GeoLocationService.calculate_distance(
                last_location['latitude'],
                last_location['longitude'],
                current_location['latitude'],
                current_location['longitude']
            )
            
            # Check if travel is physically possible (max speed: 900 km/h - airplane)
            max_possible_distance = time_diff * 900
            
            if distance > max_possible_distance and time_diff < 12:
                logger.warning(
                    'Impossible travel detected for %s: %d km in %.2f hours (%.0f km/h)',
                    user.username, distance, time_diff, distance/time_diff if time_diff > 0 else 0
                )
                
                return {
                    'is_suspicious': True,
                    'reason': f'Impossible travel: {int(distance)} km in {time_diff:.1f} hours',
                    'from_location': f"{last_location['city']}, {last_location['country']}",
                    'to_location': f"{current_location['city']}, {current_location['country']}",
                    'distance_km': int(distance),
                    'time_hours': round(time_diff, 1)
                }
        except Exception as e:
            logger.error('Impossible travel check error: %s', str(e))
        
        return {'is_suspicious': False, 'reason': None}
    
    @staticmethod
    def check_vpn_proxy(ip_address):
        """Check if IP is VPN/Proxy/Hosting"""
        location_data = GeoLocationService.get_location(ip_address)
        return location_data.get('is_proxy', False) or location_data.get('is_hosting', False)

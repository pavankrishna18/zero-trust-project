"""
IP Whitelist Management
Database-driven IP restrictions with admin UI control
Restricts login access to specific IP addresses/ranges
FULLY UPDATED - November 2025
✅ Database-driven (uses IPWhitelist model)
✅ Admin UI management support
✅ CIDR notation support
✅ Real-time updates
"""

import ipaddress
import logging
from models import IPWhitelist, db
from config import Config

logger = logging.getLogger(__name__)

# ==================== IP CHECKING FUNCTIONS ====================

def is_ip_allowed(ip_address, user_role=None):
    """
    Check if IP address is in whitelist (from database)
    
    Args:
        ip_address: IP address to check
        user_role: User role (admin bypass if configured)
    
    Returns:
        Boolean indicating if IP is allowed
    """
    # If whitelist is disabled globally, allow all
    if not Config.ENABLE_IP_WHITELIST:
        logger.info('IP whitelist disabled globally - allowing all IPs')
        return True
    
    # Super admin bypass if enabled
    if Config.SUPER_ADMIN_BYPASS_IP_CHECK and user_role == 'super_admin':
        logger.info('IP whitelist bypassed for super admin user')
        return True
    
    # Admin bypass if enabled
    if Config.ADMIN_BYPASS_IP_CHECK and user_role in ['admin']:
        logger.info('IP whitelist bypassed for admin user')
        return True
    
    try:
        user_ip = ipaddress.ip_address(ip_address)
        
        # Get active IPs from database
        active_ips = IPWhitelist.query.filter_by(is_active=True).all()
        
        if not active_ips:
            logger.warning('⚠️ No active IPs in whitelist - blocking all access')
            return False
        
        # Check against each whitelisted IP/range
        for allowed_ip_entry in active_ips:
            try:
                allowed = allowed_ip_entry.ip_address
                
                # Check if it's a network range (CIDR notation)
                if '/' in allowed or allowed_ip_entry.is_range:
                    network = ipaddress.ip_network(allowed, strict=False)
                    if user_ip in network:
                        logger.info('✅ IP %s allowed (matched network %s)', ip_address, allowed)
                        return True
                else:
                    # Check single IP
                    allowed_ip = ipaddress.ip_address(allowed)
                    if user_ip == allowed_ip:
                        logger.info('✅ IP %s allowed (exact match)', ip_address)
                        return True
            except ValueError as e:
                logger.error('❌ Invalid IP/network in whitelist DB: %s - %s', allowed, str(e))
                continue
        
        logger.warning('🚫 IP %s NOT in whitelist', ip_address)
        return False
    
    except ValueError as e:
        logger.error('❌ Invalid IP address: %s - %s', ip_address, str(e))
        return False


def get_client_ip(request):
    """
    Get client IP address from request
    Handles proxies and load balancers
    
    Args:
        request: Flask request object
    
    Returns:
        Client IP address
    """
    # Check for proxy headers (common in production)
    if request.headers.get('X-Forwarded-For'):
        # Get first IP from chain (actual client IP)
        ip = request.headers.get('X-Forwarded-For').split(',')[0].strip()
    elif request.headers.get('X-Real-IP'):
        # Alternative header used by some proxies
        ip = request.headers.get('X-Real-IP')
    else:
        # Direct connection
        ip = request.remote_addr
    
    return ip or '127.0.0.1'


# ==================== DATABASE MANAGEMENT FUNCTIONS ====================

def add_ip_to_whitelist(ip_address, description, added_by_user_id):
    """
    Add IP to whitelist database
    
    Args:
        ip_address: IP address or CIDR range
        description: Description/notes
        added_by_user_id: User ID who added this IP
    
    Returns:
        Dictionary with success status and message
    """
    try:
        # Validate IP format
        if '/' in ip_address:
            # CIDR notation - validate as network
            ipaddress.ip_network(ip_address, strict=False)
            is_range = True
        else:
            # Single IP - validate
            ipaddress.ip_address(ip_address)
            is_range = False
        
        # Check if already exists
        existing = IPWhitelist.query.filter_by(ip_address=ip_address).first()
        if existing:
            return {
                'success': False,
                'message': f'IP {ip_address} already exists in whitelist'
            }
        
        # Add to database
        new_ip = IPWhitelist(
            ip_address=ip_address,
            description=description,
            added_by=added_by_user_id,
            is_active=True,
            is_range=is_range
        )
        
        db.session.add(new_ip)
        db.session.commit()
        
        logger.info('✅ IP %s added to whitelist by user ID %s', ip_address, added_by_user_id)
        return {
            'success': True,
            'message': f'IP {ip_address} added successfully',
            'ip_id': new_ip.id
        }
    
    except ValueError as e:
        logger.error('❌ Invalid IP format: %s - %s', ip_address, str(e))
        return {
            'success': False,
            'message': f'Invalid IP format: {str(e)}'
        }
    except Exception as e:
        logger.error('❌ Error adding IP to whitelist: %s', str(e))
        db.session.rollback()
        return {
            'success': False,
            'message': f'Database error: {str(e)}'
        }


def remove_ip_from_whitelist(ip_id):
    """
    Remove IP from whitelist database
    
    Args:
        ip_id: ID of IP entry to remove
    
    Returns:
        Dictionary with success status and message
    """
    try:
        ip_entry = IPWhitelist.query.get(ip_id)
        
        if not ip_entry:
            return {
                'success': False,
                'message': 'IP entry not found'
            }
        
        ip_address = ip_entry.ip_address
        db.session.delete(ip_entry)
        db.session.commit()
        
        logger.info('✅ IP %s removed from whitelist', ip_address)
        return {
            'success': True,
            'message': f'IP {ip_address} removed successfully'
        }
    
    except Exception as e:
        logger.error('❌ Error removing IP from whitelist: %s', str(e))
        db.session.rollback()
        return {
            'success': False,
            'message': f'Database error: {str(e)}'
        }


def toggle_ip_status(ip_id):
    """
    Enable/disable IP in whitelist
    
    Args:
        ip_id: ID of IP entry to toggle
    
    Returns:
        Dictionary with success status and message
    """
    try:
        ip_entry = IPWhitelist.query.get(ip_id)
        
        if not ip_entry:
            return {
                'success': False,
                'message': 'IP entry not found'
            }
        
        # Toggle status
        ip_entry.is_active = not ip_entry.is_active
        db.session.commit()
        
        status = 'enabled' if ip_entry.is_active else 'disabled'
        logger.info('✅ IP %s %s in whitelist', ip_entry.ip_address, status)
        
        return {
            'success': True,
            'message': f'IP {ip_entry.ip_address} {status}',
            'new_status': ip_entry.is_active
        }
    
    except Exception as e:
        logger.error('❌ Error toggling IP status: %s', str(e))
        db.session.rollback()
        return {
            'success': False,
            'message': f'Database error: {str(e)}'
        }


def update_ip_description(ip_id, new_description):
    """
    Update IP description/notes
    
    Args:
        ip_id: ID of IP entry
        new_description: New description
    
    Returns:
        Dictionary with success status and message
    """
    try:
        ip_entry = IPWhitelist.query.get(ip_id)
        
        if not ip_entry:
            return {
                'success': False,
                'message': 'IP entry not found'
            }
        
        ip_entry.description = new_description
        db.session.commit()
        
        logger.info('✅ IP %s description updated', ip_entry.ip_address)
        return {
            'success': True,
            'message': 'Description updated successfully'
        }
    
    except Exception as e:
        logger.error('❌ Error updating IP description: %s', str(e))
        db.session.rollback()
        return {
            'success': False,
            'message': f'Database error: {str(e)}'
        }


def get_all_whitelisted_ips():
    """
    Get all whitelisted IPs from database
    
    Returns:
        List of IPWhitelist objects
    """
    try:
        ips = IPWhitelist.query.order_by(IPWhitelist.added_at.desc()).all()
        logger.info('Retrieved %d IPs from whitelist', len(ips))
        return ips
    except Exception as e:
        logger.error('❌ Error getting whitelisted IPs: %s', str(e))
        return []


def get_active_whitelisted_ips():
    """
    Get only active whitelisted IPs
    
    Returns:
        List of active IPWhitelist objects
    """
    try:
        ips = IPWhitelist.query.filter_by(is_active=True).order_by(IPWhitelist.added_at.desc()).all()
        logger.info('Retrieved %d active IPs from whitelist', len(ips))
        return ips
    except Exception as e:
        logger.error('❌ Error getting active whitelisted IPs: %s', str(e))
        return []


def get_ip_statistics():
    """
    Get statistics about IP whitelist
    
    Returns:
        Dictionary with statistics
    """
    try:
        total_ips = IPWhitelist.query.count()
        active_ips = IPWhitelist.query.filter_by(is_active=True).count()
        inactive_ips = IPWhitelist.query.filter_by(is_active=False).count()
        ranges = IPWhitelist.query.filter_by(is_range=True).count()
        single_ips = IPWhitelist.query.filter_by(is_range=False).count()
        
        return {
            'total': total_ips,
            'active': active_ips,
            'inactive': inactive_ips,
            'ranges': ranges,
            'single_ips': single_ips
        }
    except Exception as e:
        logger.error('❌ Error getting IP statistics: %s', str(e))
        return {
            'total': 0,
            'active': 0,
            'inactive': 0,
            'ranges': 0,
            'single_ips': 0
        }


def validate_ip_format(ip_address):
    """
    Validate IP address or CIDR notation format
    
    Args:
        ip_address: IP address or CIDR range to validate
    
    Returns:
        Dictionary with validation result
    """
    try:
        if '/' in ip_address:
            # CIDR notation
            network = ipaddress.ip_network(ip_address, strict=False)
            return {
                'valid': True,
                'type': 'range',
                'network': str(network),
                'num_addresses': network.num_addresses,
                'message': f'Valid IP range ({network.num_addresses} addresses)'
            }
        else:
            # Single IP
            ip = ipaddress.ip_address(ip_address)
            return {
                'valid': True,
                'type': 'single',
                'ip': str(ip),
                'message': 'Valid IP address'
            }
    except ValueError as e:
        return {
            'valid': False,
            'type': 'invalid',
            'message': f'Invalid IP format: {str(e)}'
        }


def bulk_add_ips(ip_list, description_template, added_by_user_id):
    """
    Add multiple IPs at once
    
    Args:
        ip_list: List of IP addresses
        description_template: Template for descriptions
        added_by_user_id: User ID adding these IPs
    
    Returns:
        Dictionary with results
    """
    results = {
        'success': [],
        'failed': [],
        'total': len(ip_list)
    }
    
    for ip_address in ip_list:
        description = f"{description_template} - {ip_address}"
        result = add_ip_to_whitelist(ip_address.strip(), description, added_by_user_id)
        
        if result['success']:
            results['success'].append(ip_address)
        else:
            results['failed'].append({
                'ip': ip_address,
                'error': result['message']
            })
    
    return results


# ==================== UTILITY FUNCTIONS ====================

def get_ip_info(ip_address):
    """
    Get information about an IP address
    
    Args:
        ip_address: IP address to check
    
    Returns:
        Dictionary with IP information
    """
    try:
        ip = ipaddress.ip_address(ip_address)
        
        return {
            'ip': str(ip),
            'version': ip.version,
            'is_private': ip.is_private,
            'is_global': ip.is_global,
            'is_loopback': ip.is_loopback,
            'is_link_local': ip.is_link_local,
        }
    except ValueError:
        return {
            'error': 'Invalid IP address'
        }


def export_whitelist_to_dict():
    """
    Export entire whitelist to dictionary format
    
    Returns:
        List of dictionaries with IP data
    """
    try:
        ips = get_all_whitelisted_ips()
        return [ip.to_dict() for ip in ips]
    except Exception as e:
        logger.error('❌ Error exporting whitelist: %s', str(e))
        return []


def import_whitelist_from_dict(ip_data_list, added_by_user_id):
    """
    Import IPs from dictionary list
    
    Args:
        ip_data_list: List of dictionaries with IP data
        added_by_user_id: User ID importing these IPs
    
    Returns:
        Dictionary with import results
    """
    results = {
        'imported': 0,
        'skipped': 0,
        'errors': []
    }
    
    for ip_data in ip_data_list:
        try:
            ip_address = ip_data.get('ip_address')
            description = ip_data.get('description', 'Imported')
            
            if not ip_address:
                results['skipped'] += 1
                continue
            
            result = add_ip_to_whitelist(ip_address, description, added_by_user_id)
            
            if result['success']:
                results['imported'] += 1
            else:
                results['skipped'] += 1
                results['errors'].append(result['message'])
        
        except Exception as e:
            results['skipped'] += 1
            results['errors'].append(str(e))
    
    return results


# ==================== EXPORTS ====================

__all__ = [
    'is_ip_allowed',
    'get_client_ip',
    'add_ip_to_whitelist',
    'remove_ip_from_whitelist',
    'toggle_ip_status',
    'update_ip_description',
    'get_all_whitelisted_ips',
    'get_active_whitelisted_ips',
    'get_ip_statistics',
    'validate_ip_format',
    'bulk_add_ips',
    'get_ip_info',
    'export_whitelist_to_dict',
    'import_whitelist_from_dict',
]

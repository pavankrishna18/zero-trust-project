"""
Resource Management Module
Defines available resources and controls access based on roles and rules
UPDATED - November 2025
✅ Clean access checks (no verbose logging)
✅ Dynamic resource filtering
"""

from models import AccessRule, User
import logging

logger = logging.getLogger(__name__)

# ==================== AVAILABLE RESOURCES ====================

AVAILABLE_RESOURCES = {
    'admin_dashboard': {
        'name': 'Admin Dashboard',
        'description': 'Full system administration and monitoring',
        'icon': '👑',
        'accessible_by': ['admin', 'super_admin']
    },
    'user_management': {
        'name': 'User Management',
        'description': 'Create, edit, and manage user accounts',
        'icon': '👥',
        'accessible_by': ['admin']
    },
    'policy_management': {
        'name': 'Policy Management',
        'description': 'Manage access rules and security policies',
        'icon': '🔐',
        'accessible_by': ['admin']
    },
    'team_dashboard': {
        'name': 'Team Dashboard',
        'description': 'Manage team activities and approvals',
        'icon': '📊',
        'accessible_by': ['manager', 'admin']
    },
    'activity_logs': {
        'name': 'Activity Logs',
        'description': 'View system activity and audit logs',
        'icon': '📜',
        'accessible_by': ['manager', 'admin']
    },
    'user_dashboard': {
        'name': 'User Dashboard',
        'description': 'Personal dashboard and profile',
        'icon': '📈',
        'accessible_by': ['user', 'manager', 'admin']
    },
    'employee_directory': {
        'name': 'Employee Directory',
        'description': 'Browse company employee directory',
        'icon': '👔',
        'accessible_by': ['user', 'manager', 'admin']
    },
    'projects': {
        'name': 'Projects',
        'description': 'View and manage projects',
        'icon': '🎯',
        'accessible_by': ['user', 'manager', 'admin']
    },
    'leave_management': {
        'name': 'Leave Management',
        'description': 'Manage leaves and attendance',
        'icon': '🗓️',
        'accessible_by': ['user', 'manager', 'admin']
    },
    'device_management': {
        'name': 'Device Management',
        'description': 'Manage trusted devices',
        'icon': '📱',
        'accessible_by': ['user', 'manager', 'admin']
    },
    'reports': {
        'name': 'Reports',
        'description': 'View and generate reports',
        'icon': '📊',
        'accessible_by': ['manager', 'admin']
    },
    'payroll': {
        'name': 'Payroll',
        'description': 'Manage payroll and salary',
        'icon': '💰',
        'accessible_by': ['admin']
    },
}

# ==================== RESOURCE ACCESS FUNCTIONS ====================

def get_accessible_resources_for_user(user):
    """
    Get all resources accessible to a user based on their role and active rules
    
    Args:
        user: User object
    
    Returns:
        Dictionary of accessible resources
    """
    try:
        accessible = {}
        
        # Super admin can access everything
        if user.is_super_admin:
            return AVAILABLE_RESOURCES
        
        # Get user's role
        role = user.role
        
        # Get all active rules for this role
        active_rules = AccessRule.query.filter(
            AccessRule.is_active == True,
            AccessRule.role == role
        ).all()
        
        # Get resource IDs from active rules
        accessible_resource_ids = set(rule.resource for rule in active_rules)
        
        # Filter AVAILABLE_RESOURCES based on active rules
        for resource_id, resource_info in AVAILABLE_RESOURCES.items():
            # Check if user's role is in the resource's accessible_by list
            if role in resource_info.get('accessible_by', []):
                # Check if there's an active rule for this resource
                if resource_id in accessible_resource_ids:
                    accessible[resource_id] = resource_info
        
        return accessible
    
    except Exception as e:
        logger.error('Error getting accessible resources: %s', str(e))
        return {}


def check_resource_access(user, resource_id, action='read'):
    """
    Check if user can access a specific resource
    ✅ NO VERBOSE LOGGING - Clean and silent
    
    Args:
        user: User object
        resource_id: Resource identifier
        action: Action type (read/write)
    
    Returns:
        Boolean indicating if access is allowed
    """
    try:
        # Super admin can access everything
        if user.is_super_admin:
            return True
        
        # Get user role
        role = user.role
        
        # Check if there's an active rule for this role and resource
        rule = AccessRule.query.filter(
            AccessRule.is_active == True,
            AccessRule.role == role,
            AccessRule.resource == resource_id
        ).first()
        
        if rule:
            # ✅ Simple access check - no verbose logging
            return True
        
        # ✅ Silent denial - no logging
        return False
    
    except Exception as e:
        logger.error('Error checking resource access: %s', str(e))
        return False


def get_resource_info(resource_id):
    """
    Get information about a specific resource
    
    Args:
        resource_id: Resource identifier
    
    Returns:
        Dictionary with resource information or None
    """
    return AVAILABLE_RESOURCES.get(resource_id, None)


def is_resource_available(resource_id):
    """
    Check if a resource exists in the system
    
    Args:
        resource_id: Resource identifier
    
    Returns:
        Boolean indicating if resource exists
    """
    return resource_id in AVAILABLE_RESOURCES


def get_all_resources():
    """
    Get all available resources in the system
    
    Returns:
        Dictionary of all available resources
    """
    return AVAILABLE_RESOURCES


def get_resources_by_role(role):
    """
    Get all resources accessible to a specific role (based on resource definition)
    
    Args:
        role: User role
    
    Returns:
        Dictionary of resources accessible to the role
    """
    try:
        accessible = {}
        
        for resource_id, resource_info in AVAILABLE_RESOURCES.items():
            if role in resource_info.get('accessible_by', []):
                accessible[resource_id] = resource_info
        
        return accessible
    
    except Exception as e:
        logger.error('Error getting resources by role: %s', str(e))
        return {}


def get_resource_count_for_user(user):
    """
    Get count of resources accessible to user
    
    Args:
        user: User object
    
    Returns:
        Integer count of accessible resources
    """
    try:
        accessible_resources = get_accessible_resources_for_user(user)
        return len(accessible_resources)
    except Exception as e:
        logger.error('Error getting resource count: %s', str(e))
        return 0


def get_resource_categories():
    """
    Get resource categories for organization
    
    Returns:
        Dictionary of resource categories
    """
    categories = {
        'administration': [],
        'management': [],
        'user_services': [],
        'reporting': [],
    }
    
    for resource_id, resource_info in AVAILABLE_RESOURCES.items():
        if 'admin' in resource_id or 'policy' in resource_id or 'user_management' in resource_id:
            categories['administration'].append({
                'id': resource_id,
                'name': resource_info['name'],
                'icon': resource_info['icon']
            })
        elif 'team' in resource_id or 'activity' in resource_id:
            categories['management'].append({
                'id': resource_id,
                'name': resource_info['name'],
                'icon': resource_info['icon']
            })
        elif 'report' in resource_id or 'payroll' in resource_id:
            categories['reporting'].append({
                'id': resource_id,
                'name': resource_info['name'],
                'icon': resource_info['icon']
            })
        else:
            categories['user_services'].append({
                'id': resource_id,
                'name': resource_info['name'],
                'icon': resource_info['icon']
            })
    
    return categories


def validate_resource_access(user, resource_id, action='read', require_trusted_device=False):
    """
    Validate resource access with additional checks
    
    Args:
        user: User object
        resource_id: Resource identifier
        action: Action type
        require_trusted_device: Whether to check device trust
    
    Returns:
        Dictionary with validation result
    """
    try:
        # Check basic access
        has_access = check_resource_access(user, resource_id, action)
        
        if not has_access:
            return {
                'allowed': False,
                'reason': 'No active access rule found'
            }
        
        # Additional checks can be added here
        # For example: time-based access, IP restrictions, etc.
        
        return {
            'allowed': True,
            'reason': 'Access granted'
        }
    
    except Exception as e:
        logger.error('Error validating resource access: %s', str(e))
        return {
            'allowed': False,
            'reason': 'Validation error'
        }


# ==================== HELPER FUNCTIONS ====================

def format_resource_for_display(resource_id):
    """
    Format resource information for display
    
    Args:
        resource_id: Resource identifier
    
    Returns:
        Formatted resource dictionary
    """
    resource = get_resource_info(resource_id)
    
    if not resource:
        return None
    
    return {
        'id': resource_id,
        'name': resource['name'],
        'description': resource['description'],
        'icon': resource['icon'],
        'roles': ', '.join(resource['accessible_by'])
    }


def get_accessible_resources_with_rules(user):
    """
    Get accessible resources with their corresponding rules
    
    Args:
        user: User object
    
    Returns:
        List of dictionaries with resource and rule information
    """
    try:
        accessible = []
        
        if user.is_super_admin:
            for resource_id, resource_info in AVAILABLE_RESOURCES.items():
                accessible.append({
                    'resource_id': resource_id,
                    'resource_name': resource_info['name'],
                    'resource_icon': resource_info['icon'],
                    'rule_name': 'Super Admin Access',
                    'has_rule': True
                })
            return accessible
        
        # Get active rules for user's role
        active_rules = AccessRule.query.filter(
            AccessRule.is_active == True,
            AccessRule.role == user.role
        ).all()
        
        for rule in active_rules:
            resource_info = get_resource_info(rule.resource)
            if resource_info:
                accessible.append({
                    'resource_id': rule.resource,
                    'resource_name': resource_info['name'],
                    'resource_icon': resource_info['icon'],
                    'rule_name': rule.name,
                    'has_rule': True
                })
        
        return accessible
    
    except Exception as e:
        logger.error('Error getting resources with rules: %s', str(e))
        return []


# ==================== STATISTICS ====================

def get_resource_statistics():
    """
    Get statistics about resources
    
    Returns:
        Dictionary with resource statistics
    """
    try:
        total_resources = len(AVAILABLE_RESOURCES)
        
        # Count resources by category
        admin_only = sum(1 for r in AVAILABLE_RESOURCES.values() if r['accessible_by'] == ['admin'])
        manager_access = sum(1 for r in AVAILABLE_RESOURCES.values() if 'manager' in r['accessible_by'])
        user_access = sum(1 for r in AVAILABLE_RESOURCES.values() if 'user' in r['accessible_by'])
        
        # Count active rules
        from models import AccessRule
        active_rules_count = AccessRule.query.filter_by(is_active=True).count()
        
        return {
            'total_resources': total_resources,
            'admin_only': admin_only,
            'manager_access': manager_access,
            'user_access': user_access,
            'active_rules': active_rules_count
        }
    
    except Exception as e:
        logger.error('Error getting resource statistics: %s', str(e))
        return {}


# ==================== EXPORT ====================

__all__ = [
    'AVAILABLE_RESOURCES',
    'get_accessible_resources_for_user',
    'check_resource_access',
    'get_resource_info',
    'is_resource_available',
    'get_all_resources',
    'get_resources_by_role',
    'get_resource_count_for_user',
    'get_resource_categories',
    'validate_resource_access',
    'format_resource_for_display',
    'get_accessible_resources_with_rules',
    'get_resource_statistics',
]

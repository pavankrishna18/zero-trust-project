"""
Role-Based Permissions System
Defines what each role can do in the system
"""

# Define permissions for each role
ROLE_PERMISSIONS = {
    'super_admin': {
        'can_create_users': True,
        'can_edit_users': True,
        'can_delete_users': True,
        'can_change_roles': True,
        'can_unlock_accounts': True,
        'can_create_rules': True,
        'can_edit_rules': True,
        'can_delete_rules': True,
        'can_approve_devices': True,
        'can_revoke_devices': True,
        'can_terminate_sessions': True,
        'can_view_all_activities': True,
        'can_view_all_users': True,
        'can_view_metrics': True,
        'can_manage_system': True,
        'can_access_admin_dashboard': True,
        'can_access_sensitive_data': True,
    },
    'admin': {
        'can_create_users': True,
        'can_edit_users': True,
        'can_delete_users': False,  # Only super admin can delete
        'can_change_roles': True,
        'can_unlock_accounts': True,
        'can_create_rules': True,
        'can_edit_rules': True,
        'can_delete_rules': True,
        'can_approve_devices': True,
        'can_revoke_devices': True,
        'can_terminate_sessions': True,
        'can_view_all_activities': True,
        'can_view_all_users': True,
        'can_view_metrics': True,
        'can_manage_system': False,  # Cannot change system settings
        'can_access_admin_dashboard': True,
        'can_access_sensitive_data': True,
    },
    'manager': {
        'can_create_users': False,
        'can_edit_users': False,
        'can_delete_users': False,
        'can_change_roles': False,
        'can_unlock_accounts': False,
        'can_create_rules': False,
        'can_edit_rules': False,
        'can_delete_rules': False,
        'can_approve_devices': True,  # Can approve devices
        'can_revoke_devices': True,
        'can_terminate_sessions': False,
        'can_view_all_activities': True,
        'can_view_all_users': True,
        'can_view_metrics': True,
        'can_manage_system': False,
        'can_access_admin_dashboard': False,
        'can_access_sensitive_data': False,
    },
    'user': {
        'can_create_users': False,
        'can_edit_users': False,
        'can_delete_users': False,
        'can_change_roles': False,
        'can_unlock_accounts': False,
        'can_create_rules': False,
        'can_edit_rules': False,
        'can_delete_rules': False,
        'can_approve_devices': False,
        'can_revoke_devices': False,
        'can_terminate_sessions': False,
        'can_view_all_activities': False,
        'can_view_all_users': False,
        'can_view_metrics': False,
        'can_manage_system': False,
        'can_access_admin_dashboard': False,
        'can_access_sensitive_data': False,
    },
    'guest': {
        'can_create_users': False,
        'can_edit_users': False,
        'can_delete_users': False,
        'can_change_roles': False,
        'can_unlock_accounts': False,
        'can_create_rules': False,
        'can_edit_rules': False,
        'can_delete_rules': False,
        'can_approve_devices': False,
        'can_revoke_devices': False,
        'can_terminate_sessions': False,
        'can_view_all_activities': False,
        'can_view_all_users': False,
        'can_view_metrics': False,
        'can_manage_system': False,
        'can_access_admin_dashboard': False,
        'can_access_sensitive_data': False,
    }
}


def get_user_permissions(user):
    """
    Get permissions for a user based on their role
    
    Args:
        user: User object
    
    Returns:
        Dictionary of permissions
    """
    if user.is_super_admin:
        return ROLE_PERMISSIONS['super_admin']
    
    role = user.role if user.role in ROLE_PERMISSIONS else 'guest'
    return ROLE_PERMISSIONS[role]


def has_permission(user, permission):
    """
    Check if user has a specific permission
    
    Args:
        user: User object
        permission: Permission string (e.g., 'can_create_users')
    
    Returns:
        Boolean
    """
    permissions = get_user_permissions(user)
    return permissions.get(permission, False)


def require_permission(permission):
    """
    Decorator to check if user has permission
    
    Args:
        permission: Permission string
    
    Returns:
        Decorated function
    """
    from functools import wraps
    from flask import flash, redirect, url_for
    from flask_login import current_user
    
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not has_permission(current_user, permission):
                flash(f'❌ Access Denied: You do not have permission to {permission.replace("can_", "").replace("_", " ")}', 'error')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

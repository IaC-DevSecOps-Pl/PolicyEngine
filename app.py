from flask import Flask, render_template, request, redirect, url_for, session, flash, current_app, Response, jsonify
from flask_session import Session
from datetime import datetime
from dotenv import load_dotenv
import os
import io
import json
import uuid
import csv
from functools import wraps
import logging
from werkzeug.security import generate_password_hash, check_password_hash
import ast # For literal_eval
from flask_mail import Mail
#from utils import *
from repository.csv_repo import CsvRepository # <-- Import the new class
from utils import calculate_policy_hash, send_notification_email, is_csv_empty   # <-- utils.py now only has non-data helpers
from engine import run_decision_engine
from repository.csv_repo import CsvRepository

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define role hierarchy
ROLES = {
    'Viewer': 1,
    'Policy_Creator': 2,
    'Policy_Approver': 3,
    'Admin': 4
}

load_dotenv()
# In app.py

app = Flask(__name__)

@app.template_filter('format_datetime')
def format_datetime(iso_string):
    """Converts an ISO format string to MM-DD-YYYY HH:MM:SS format."""
    if not iso_string:
        return 'N/A'
    try:
        # Parse the ISO string and format it
        dt_object = datetime.fromisoformat(iso_string)
        return dt_object.strftime('%m-%d-%Y %H:%M:%S')
    except (ValueError, TypeError):
        return iso_string # Return original string if parsing fails
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your_secret_key') # Use a strong, random key in production
app.config['SESSION_TYPE'] = 'filesystem'
Session(app)

DATA_DIR = 'data'
if not os.path.exists(DATA_DIR):
    os.makedirs(DATA_DIR)

# File paths - ENSURE THESE ARE DEFINED BEFORE UTILS IS IMPORTED
app.config['USER_FILE'] = os.path.join(DATA_DIR, 'users.csv')
app.config['POLICY_FILE'] = os.path.join(DATA_DIR, 'policies.csv')
app.config['AUDIT_FILE'] = os.path.join(DATA_DIR, 'audit.csv')
app.config['CATEGORY_FILE'] = os.path.join(DATA_DIR, 'categories.csv')
app.config['OPERATOR_FILE'] = os.path.join(DATA_DIR, 'operators.csv')
app.config['GROUP_FILE'] = os.path.join(DATA_DIR, 'groups.csv')
app.config['USER_CATEGORY_ROLES_FILE'] = os.path.join(DATA_DIR, 'user_category_roles.csv')
app.config['POLICY_FIELDNAMES'] = [
    'id', 'name', 'description', 'category', 'status', 'created_by_id',
    'created_date', 'groups', 'approved_by', 'approval_date', 'enabled_by',
    'enabled_date', 'disabled_by', 'disabled_date', 'archived_by',
    'archived_date', 'action_pending_reason', 'rule_definition', 'requires_approval', 'policy_hash'
]
app.config['USER_FIELDNAMES'] = ['id', 'username', 'password', 'email', 'global_role', 'category_roles']
app.config['GROUP_FIELDNAMES'] = ['id', 'name', 'description', 'categories', 'approvers']
app.config['USER_CATEGORY_ROLES_FIELDNAMES'] = ['user_id', 'category', 'role']
app.config['CATEGORY_FIELDNAMES'] = ['category', 'logged_fields']

# This setting will control which backend to use. Defaults to 'csv'.
# To use Azure, you will set an environment variable STORAGE_BACKEND=azure
app.config['STORAGE_BACKEND'] = os.getenv('STORAGE_BACKEND', 'csv')

# Add your Azure Storage connection string as an environment variable for security
app.config['AZURE_STORAGE_CONNECTION_STRING'] = os.getenv('AZURE_STORAGE_CONNECTION_STRING')

# app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
# app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
# app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'true').lower() == 'true'
# app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
# app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
# app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER', app.config['MAIL_USERNAME'])
app.config['MAIL_SERVER'] = 'localhost'
app.config['MAIL_PORT'] = 1025
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USERNAME'] = None
app.config['MAIL_PASSWORD'] = None
app.config['MAIL_DEFAULT_SENDER'] = 'notifications@policy-engine.com'

mail = Mail(app) # Initialize the mail object

# Import all necessary functions from utils.py *AFTER* app and its config are set up
# from utils import (
#     write_csv, read_csv, log_audit, get_policies, save_policy, get_user,
#     get_user_groups, save_user, delete_user, save_group, delete_group, get_users_with_role,
#     read_user_categories, write_user_categories, get_user_categories, save_user_categories,
#     delete_user_category_roles, get_user_role_for_category, get_all_users_with_details,send_notification_email,
#     get_policy_by_id, update_policy, calculate_policy_hash, is_csv_empty, read_simple_csv, get_groups
# )

from repository.azure_repo import AzureTableRepository # Add new import

def initialize_repository(config):
    """Factory function to initialize the correct repository based on config."""
    backend = config.get('STORAGE_BACKEND', 'csv')
    if backend == 'azure':
        print("--- Using Azure Table Storage Backend ---")
        # Ensure connection string is present
        if not config.get('AZURE_STORAGE_CONNECTION_STRING'):
            raise ValueError("AZURE_STORAGE_CONNECTION_STRING is not set for the Azure backend.")
        return AzureTableRepository(config)
    else:
        print("--- Using CSV File Backend ---")
        return CsvRepository(config)

repo = initialize_repository(app.config)

@app.template_filter('prettyjson')
def prettyjson_filter(value):
    """A filter to format a dictionary as a pretty-printed JSON string."""
    return json.dumps(value, indent=2)

def read_lookup_list(file_path: str, col_name: str) -> list:
    """A very simple and direct CSV column reader."""
    if not os.path.exists(file_path): return []
    items = []
    try:
        with open(file_path, 'r', newline='', encoding='utf-8-sig') as f:
            reader = csv.DictReader(f)
            for row in reader:
                if col_name in row and row[col_name]:
                    items.append(row[col_name])
    except Exception as e:
        logging.error(f"Failed to read lookup list from {file_path}: {e}")
        return []
    return items

def write_lookup_list(file_path: str, col_name: str, item_list: list):
    """A very simple and direct CSV list writer."""
    try:
        with open(file_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=[col_name])
            writer.writeheader()
            for item in item_list:
                writer.writerow({col_name: item})
    except Exception as e:
        logging.error(f"Failed to write lookup list to {file_path}: {e}")

# ... the rest of your app.py file begins here

# Decorators for role-based access control
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            flash('Login required to access this page.', 'warning')
            logging.info("Access denied: Login required.")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def roles_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'role' not in session or session['role'] not in roles:
                flash('Unauthorized access. Your role does not permit this action.', 'danger')
                logging.warning(f"Unauthorized access for user {session.get('username')} (Role: {session.get('role')}). Required roles: {roles}")
                return redirect(url_for('policy_list'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def role_hierarchy_required(required_role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user_role = session.get('role')
            if not user_role or ROLE_HIERARCHY.get(user_role, 0) < ROLE_HIERARCHY.get(required_role, 0):
                flash(f'Unauthorized access. You need at least "{required_role}" role.', 'danger')
                logging.warning(f"Unauthorized access for user {session.get('username')} (Role: {user_role}). Required minimum role: {required_role}")
                return redirect(url_for('policy_list'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Helper to check permissions based on user's global role and specific policy/category roles
# In app.py, find and replace the has_permission function

# In app.py, replace the entire has_permission function with this:

def has_permission(action, policy=None, **kwargs):
    """
    Checks if the current user has permission for a given action.
    Accepts **kwargs to ignore legacy arguments like 'category' from templates.
    """
    user_role = session.get('role', 'Viewer')
    user_level = ROLES.get(user_role, 0)
    user_id = session.get('user_id')

    # Define the minimum role level required for general actions
    required_levels = {
        'view_policies': ROLES['Viewer'],
        'create_policy': ROLES['Policy_Creator'],
        'approve_policy': ROLES['Policy_Approver'],
        'enable_disable_policy': ROLES['Policy_Approver'],
        'archive_policy': ROLES['Policy_Approver'],
        'manage_users': ROLES['Admin'],
        'view_admin_panel': ROLES['Admin'],
        'view_audit_log': ROLES['Admin'],
        # --- THIS LINE WAS MISSING ---
        'download_policies_report': ROLES['Policy_Approver']
    }

    required_level = required_levels.get(action)
    can_act = False

    # Check if user's role level is high enough for the general action
    if required_level and user_level >= required_level:
        can_act = True

    # Grant specific permissions for lower-level roles
    is_modifiable = policy and policy.get('created_by_id') == user_id and policy.get('status') in ['draft', 'rejected']
    if action in ['edit_policy', 'delete_policy'] and user_role == 'Policy_Creator' and is_modifiable:
        can_act = True

    # Apply special blocking rules (these override permissions)
    if action == 'approve_policy' and policy and policy.get('created_by_id') == user_id:
        can_act = False

    return can_act

# This line is usually right below the has_permission function definition.
app.jinja_env.globals['has_permission'] = has_permission

# Find the block starting with this line...
# --- INITIALIZE DATA VIA REPOSITORY (Works for both CSV and Azure) ---
with app.app_context():
    # Check if there are any users. If not, create the default admin.
    if not repo.get_all_users():
        print("--- No users found. Creating default admin user... ---")
        admin_password_hash = generate_password_hash(os.getenv('ADMIN_PASSWORD', 'adminpass'))
        admin_user = {
            'id': str(uuid.uuid4()),
            'username': 'admin',
            'password': admin_password_hash,
            'email': 'admin@example.com',
            'global_role': 'Admin',
            'category_roles': [] # The repository will handle serializing this list
        }
        repo.save_user(admin_user)
        logging.info("Initialized data with default admin user.")

    # Check if there are any categories. If not, create defaults.
    if not repo.get_all_categories():
        print("--- No categories found. Creating default categories... ---")
        default_categories = [
            {'category': 'General', 'logged_fields': {}},
            {'category': 'Security', 'logged_fields': {"image_name": "imageName", "critical_vulns": "vulnerabilities.critical"}},
            {'category': 'Compliance', 'logged_fields': {}}
        ]
        repo.save_all_categories(default_categories)
        logging.info("Initialized data with default categories.")

    # Check for other lookups like Groups and Operators
    # Note: These still use the simple read_lookup_list helper, so their file creation is separate
    if not os.path.exists(app.config['OPERATOR_FILE']):
        write_lookup_list(app.config['OPERATOR_FILE'], 'operator', ['equals', 'in', 'not in', 'like', 'greater_than', 'less_than'])
        logging.info("Initialized operators.csv with default data.")

app.jinja_env.globals['has_permission'] = has_permission


# --- Routes ---

@app.route('/')
@login_required
def index():
    return redirect(url_for('policy_list'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Use the repository to find the user
        user = repo.get_user_by_username(username)

        if user and check_password_hash(user['password'], password):
            session['logged_in'] = True
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['global_role']
            # The repository now handles JSON parsing, so user['category_roles'] is already a list
            session['category_roles'] = user.get('category_roles', [])

            # Use the repository to log the successful audit event
            repo.log_audit(username, 'login', 'User', user['id'], 'User logged in successfully.')

            flash('Logged in successfully.', 'success')
            return redirect(url_for('policy_list'))
        else:
            flash('Invalid username or password.', 'danger')
            # Use the repository to log the failed audit event
            repo.log_audit(username, 'login_failed', 'User', 'N/A', 'Failed login attempt.')

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    # Use the repository to log the audit event
    repo.log_audit(session.get('username', 'unknown'), 'logout', 'User', session.get('user_id'), 'User logged out.')

    # A more effective way to clear all session data
    session.clear()

    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/policy_list')
@login_required
def policy_list():
    all_policies = repo.get_all_policies()  # Use repo
    categories_for_filter = [cat['category'] for cat in repo.get_all_categories()] # Use repo

    current_user_id = session.get('user_id')
    user_global_role = session.get('role')

    # Get all category roles for the current user
    user_cat_roles = repo.get_user_categories(current_user_id)  # Use repo
    # Create a simple set of categories the user has explicit access to
    accessible_categories = {item['category'] for item in user_cat_roles}

    user_specific_policies = []
    for policy in all_policies:
        is_admin = (user_global_role == 'Admin')
        is_creator = (policy.get('created_by_id') == current_user_id)
        has_category_access = (policy.get('category') in accessible_categories)

        # A user can see a policy if they are an Admin, they created it, or they have a role in its category
        if is_admin or is_creator or has_category_access:
            user_specific_policies.append(policy)

    # Add creator's username for display purposes (on the filtered list)
    users = repo.get_all_users()  # Use repo
    user_map = {user['id']: user['username'] for user in users}
    for policy in user_specific_policies:
        policy['created_by'] = user_map.get(policy.get('created_by_id'), 'Unknown User')

    return render_template('policy_list.html', policies=user_specific_policies, categories=categories_for_filter)


@app.route('/new_policy', methods=['GET', 'POST'])
@login_required
@roles_required('Admin', 'Policy_Creator', 'Policy_Approver')
def new_policy():
    # These helpers read simple lookup files and do not need the repo
    categories = read_lookup_list(current_app.config['CATEGORY_FILE'], 'category')
    operators = read_lookup_list(current_app.config['OPERATOR_FILE'], 'operator')
    groups = read_lookup_list(current_app.config['GROUP_FILE'], 'name')

    if request.method == 'POST':
        policy_name = request.form.get('name')
        policy_category = request.form.get('category')

        try:
            rule_definition = json.loads(request.form.get('rule_definition', '{}'))
        except json.JSONDecodeError:
            flash('Invalid rule structure submitted.', 'danger')
            return render_template('new_policy.html', categories=categories, operators=operators, groups=groups, policy=request.form)

        new_policy_data = {
            'name': policy_name, 'description': request.form.get('description', ''),
            'category': policy_category, 'groups': request.form.getlist('groups'),
            'requires_approval': True, 'rule_definition': rule_definition
        }

        all_policies = repo.get_all_policies()  # Use repo
        if any(p.get('name') == policy_name for p in all_policies):
            flash(f"A policy with the name '{policy_name}' already exists.", 'danger')
            return render_template('new_policy.html', categories=categories, operators=operators, groups=groups, policy=request.form)

        new_policy_hash = calculate_policy_hash(new_policy_data)
        existing_hashes = {p.get('policy_hash') for p in all_policies}
        if new_policy_hash in existing_hashes:
            flash('A policy with these exact rules already exists.', 'danger')
            return render_template('new_policy.html', categories=categories, operators=operators, groups=groups, policy=request.form)

        user_global_role = session.get('role')
        user_role_for_category = repo.get_user_role_for_category(session['user_id'], policy_category) # Use repo
        category_role_level = ROLES.get(user_role_for_category, 0)

        if not (user_global_role == 'Admin' or category_role_level >= ROLES['Policy_Creator']):
            flash(f"You do not have permission to create policies in the '{policy_category}' category.", 'danger')
            return render_template('new_policy.html', categories=categories, operators=operators, groups=groups, policy=request.form)

        new_policy_data['policy_hash'] = new_policy_hash
        repo.save_policy(new_policy_data, username=session['username']) # Use repo

        flash('Policy has been successfully submitted for approval.', 'success')
        return redirect(url_for('policy_list'))

    return render_template('new_policy.html', categories=categories, operators=operators, groups=groups)


@app.route('/edit_policy/<policy_id>', methods=['GET', 'POST'])
@login_required
def edit_policy(policy_id):
    policy = repo.get_policy_by_id(policy_id)
    if not policy:
        flash('Policy not found.', 'danger')
        return redirect(url_for('policy_list'))

    if not has_permission('edit_policy', policy=policy):
        flash('You do not have permission to edit this policy.', 'danger')
        return redirect(url_for('policy_list'))

    if request.method == 'POST':
        # --- THIS IS THE FIX ---
        # 1. Start with a complete copy of the original policy to preserve all metadata.
        updated_data = policy.copy()

        # 2. Update the copy with the new values from the form.
        updated_data.update({
            'name': request.form.get('name'),
            'description': request.form.get('description', ''),
            'category': request.form.get('category'),
            'groups': request.form.getlist('groups'),
            'rule_definition': json.loads(request.form.get('rule_definition', '{}'))
        })

        # 3. Recalculate the hash based on the potentially new rules.
        updated_data['policy_hash'] = calculate_policy_hash(updated_data)

        # 4. If the policy was rejected, saving the edit now correctly resubmits it.
        #    The 'action_pending_reason' from the original policy is still present in our copy.
        if policy.get('status') == 'rejected':
            updated_data['status'] = 'pending_approval'
            flash('Policy updated and resubmitted for approval.', 'success')
        else:
            flash('Policy updated successfully.', 'success')

        repo.update_policy(policy_id, updated_data, username=session['username'])
        return redirect(url_for('policy_list'))

    # For GET request, no changes needed
    categories = read_lookup_list(current_app.config['CATEGORY_FILE'], 'category')
    operators = read_lookup_list(current_app.config['OPERATOR_FILE'], 'operator')
    groups = read_lookup_list(current_app.config['GROUP_FILE'], 'name')
    return render_template('edit_policy.html', policy=policy, categories=categories, operators=operators, groups=groups)

@app.route('/api/v1/decide', methods=['POST'])
def decide_api():
    """API endpoint for programmatic execution of the decision engine."""
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400

    data = request.get_json()
    payload = data.get('payload')
    context = data.get('context')

    if not payload or not context:
        return jsonify({"error": "Request body must contain 'payload' and 'context' keys"}), 400

    results = run_decision_engine(payload, context, repo)
    repo.log_decision(results, payload, context) # Use repo

    return jsonify(results)


@app.route('/delete_policy/<policy_id>', methods=['POST'])
@login_required
def delete_policy_route(policy_id):
    policy = repo.get_policy_by_id(policy_id) # Use repo
    if not policy:
        flash('Policy not found.', 'danger')
        return redirect(url_for('policy_list'))

    if not has_permission('delete_policy', policy=policy):
        flash('You do not have permission to delete this policy.', 'danger')
        return redirect(url_for('policy_list'))

    if repo.delete_policy(policy_id): # Use repo
        repo.log_audit(session['username'], 'delete', 'Policy', policy_id, f'Policy "{policy["name"]}" deleted.') # Use repo
        flash('Policy deleted successfully.', 'success')
    else:
        flash('Error deleting policy.', 'danger')

    return redirect(url_for('policy_list'))


@app.route('/approve_policy/<policy_id>', methods=['POST'])
@login_required
@roles_required('Admin', 'Policy_Approver')
def approve_policy(policy_id):
    policy = repo.get_policy_by_id(policy_id) # Use repo
    if not policy or policy['status'] != 'pending_approval':
        flash('Only policies pending approval can be approved.', 'warning')
        return redirect(url_for('policy_list'))

    user_global_role = session.get('role')
    user_id = session.get('user_id')
    policy_category = policy.get('category')
    user_role_for_category = repo.get_user_role_for_category(user_id, policy_category) # Use repo
    category_role_level = ROLES.get(user_role_for_category, 0)

    if not (user_global_role == 'Admin' or category_role_level >= ROLES['Policy_Approver']):
        flash(f"You do not have permission to approve policies in the '{policy_category}' category.", 'danger')
        return redirect(url_for('policy_list'))

    if policy.get('created_by_id') == user_id and user_global_role != 'Admin':
        flash('You cannot approve a policy that you created.', 'danger')
        return redirect(url_for('policy_list'))

    update_data = {
        'status': 'enabled', 'approved_by': session['username'], 'approval_date': datetime.now().isoformat(),
        'enabled_by': session['username'], 'enabled_date': datetime.now().isoformat(), 'action_pending_reason': ''
    }
    repo.update_policy(policy_id, update_data, username=session['username']) # Use repo

    creator = repo.get_user_by_id(policy.get('created_by_id')) # Use repo
    if creator and creator.get('email'):
        subject = f"Your Policy has been Approved: {policy['name']}"
        body = f"The policy '{policy['name']}' that you submitted has been approved and is now active."
        # send_notification_email([creator['email']], subject, body) # Keep this commented out until ready

    flash('Policy approved and enabled successfully.', 'success')
    return redirect(url_for('policy_list'))


@app.route('/reject_policy/<policy_id>', methods=['POST'])
@login_required
@roles_required('Admin', 'Policy_Approver')
def reject_policy(policy_id):
    policy = repo.get_policy_by_id(policy_id) # Use repo
    if not policy or policy['status'] != 'pending_approval':
        flash('Only policies pending approval can be rejected.', 'warning')
        return redirect(url_for('policy_list'))

    reason = request.form.get('rejection_reason', 'No reason provided.')
    update_data = {
        'status': 'rejected', 'approved_by': '', 'approval_date': '',
        'action_pending_reason': f'Rejected by {session["username"]}: {reason}'
    }
    repo.update_policy(policy_id, update_data, username=session['username']) # Use repo

    creator = repo.get_user_by_id(policy.get('created_by_id')) # Use repo
    if creator and creator.get('email'):
        subject = f"Your Policy has been Rejected: {policy['name']}"
        body = f"The policy '{policy['name']}' has been rejected. Please log in to view the reason and make edits.\n\nReason: {reason}"
        # send_notification_email([creator['email']], subject, body) # Keep this commented out until ready

    flash('Policy rejected successfully.', 'warning')
    return redirect(url_for('policy_list'))


@app.route('/enable_policy/<policy_id>', methods=['POST'])
@login_required
@roles_required('Admin', 'Policy_Approver')
def enable_policy(policy_id):
    update_data = {'status': 'enabled', 'enabled_by': session['username'], 'enabled_date': datetime.now().isoformat()}
    repo.update_policy(policy_id, update_data, username=session['username']) # Use repo
    flash('Policy enabled successfully.', 'success')
    return redirect(url_for('policy_list'))


@app.route('/disable_policy/<policy_id>', methods=['POST'])
@login_required
@roles_required('Admin', 'Policy_Approver')
def disable_policy(policy_id):
    update_data = {'status': 'disabled', 'disabled_by': session['username'], 'disabled_date': datetime.now().isoformat()}
    repo.update_policy(policy_id, update_data, username=session['username']) # Use repo
    flash('Policy disabled successfully.', 'warning')
    return redirect(url_for('policy_list'))


@app.route('/archive_policy/<policy_id>', methods=['POST'])
@login_required
@roles_required('Admin', 'Policy_Approver')
def archive_policy(policy_id):
    update_data = {'status': 'archived', 'archived_by': session['username'], 'archived_date': datetime.now().isoformat()}
    repo.update_policy(policy_id, update_data, username=session['username']) # Use repo
    flash('Policy archived successfully.', 'success')
    return redirect(url_for('policy_list'))


@app.route('/unarchive_policy/<policy_id>', methods=['POST'])
@login_required
@roles_required('Admin', 'Policy_Approver')
def unarchive_policy(policy_id):
    update_data = {
        'status': 'pending_approval', 'archived_by': '', 'archived_date': '',
        'action_pending_reason': f'Unarchived by {session["username"]}, pending re-approval.'
    }
    repo.update_policy(policy_id, update_data, username=session['username']) # Use repo
    flash('Policy unarchived and is now pending re-approval.', 'success')
    return redirect(url_for('policy_list'))

@app.route('/audit_log')
@login_required
def audit_log_view():
    if not has_permission('view_audit_log'):
        flash('You do not have permission to view the audit log.', 'danger')
        return redirect(url_for('policy_list'))

    audit_events = repo.get_audit_log() # Use repo

    sorted_events = sorted(audit_events, key=lambda x: x.get('timestamp', ''), reverse=True)
    return render_template('audit_log.html', audit_events=sorted_events)


@app.route('/admin_panel')
@login_required
@roles_required('Admin')
def admin_panel():
    return render_template('admin_panel.html')


@app.route('/manage_users')
@login_required
@roles_required('Admin')
def manage_users():
    users = repo.get_all_users() # Use repo
    return render_template('manage_users.html', users=users)


@app.route('/add_user', methods=['GET', 'POST'])
@login_required
@roles_required('Admin')
def add_user():
    categories = read_lookup_list(current_app.config['CATEGORY_FILE'], 'category')
    if request.method == 'POST':
        username = request.form['username']
        if repo.get_user_by_username(username): # Use repo
            flash(f'User "{username}" already exists.', 'danger')
            return render_template('add_edit_user.html', mode='add', categories=categories, user=request.form, user_category_roles=[], roles=ROLES)

        category_roles_data = []
        i = 0
        while f'category_role_category_{i}' in request.form:
            cat = request.form[f'category_role_category_{i}']
            role = request.form[f'category_role_role_{i}']
            if cat and role:
                category_roles_data.append({'category': cat, 'role': role})
            i += 1

        if not category_roles_data:
            flash('A new user must be assigned at least one category-based role.', 'danger')
            return render_template('add_edit_user.html', mode='add', categories=categories, user=request.form, user_category_roles=[], roles=ROLES)

        global_role = request.form['global_role']
        global_level = ROLES.get(global_role, 0)
        for cat_role in category_roles_data:
            cat_level = ROLES.get(cat_role['role'], 0)
            if cat_level > global_level:
                flash(f"Error: The category role '{cat_role['role']}' cannot be higher than the global role '{global_role}'.", 'danger')
                return render_template('add_edit_user.html', mode='add', categories=categories, user=request.form, user_category_roles=category_roles_data, roles=ROLES)

        user_id = str(uuid.uuid4())
        new_user = {
            'id': user_id, 'username': username, 'password': generate_password_hash(request.form['password']),
            'email': request.form['email'], 'global_role': global_role,
            'category_roles': category_roles_data
        }
        repo.save_user(new_user) # Use repo
        repo.save_user_categories(user_id, category_roles_data) # Use repo
        repo.log_audit(session['username'], 'add', 'User', user_id, f'User "{username}" added.') # Use repo

        # Note: You may need to add 'from utils import send_notification_email' to your imports
        # send_notification_email([new_user['email']], "Welcome to the Policy Engine!", "Your account has been created.")

        flash('User added successfully.', 'success')
        return redirect(url_for('manage_users'))

    return render_template('add_edit_user.html', mode='add', categories=categories, user={}, user_category_roles=[], roles=ROLES)


@app.route('/edit_user/<user_id>', methods=['GET', 'POST'])
@login_required
@roles_required('Admin')
def edit_user(user_id):
    user = repo.get_user_by_id(user_id) # Use repo
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('manage_users'))

    categories = read_lookup_list(current_app.config['CATEGORY_FILE'], 'category')
    if request.method == 'POST':
        user['username'] = request.form['username']
        if request.form.get('password'):
            user['password'] = generate_password_hash(request.form['password'])
        user['email'] = request.form['email']
        user['global_role'] = request.form['global_role']

        updated_category_roles_data = []
        i = 0
        while f'category_role_category_{i}' in request.form:
            cat = request.form[f'category_role_category_{i}']
            role = request.form[f'category_role_role_{i}']
            if cat and role:
                updated_category_roles_data.append({'category': cat, 'role': role})
            i += 1

        user['category_roles'] = updated_category_roles_data

        # Validation for roles
        global_level = ROLES.get(user['global_role'], 0)
        for cat_role in updated_category_roles_data:
            cat_level = ROLES.get(cat_role['role'], 0)
            if cat_level > global_level:
                flash(f"Error: The category role '{cat_role['role']}' cannot be higher than the global role '{user['global_role']}'.", 'danger')
                user_category_roles = repo.get_user_categories(user_id) # Use repo
                return render_template('add_edit_user.html', mode='edit', user=user, categories=categories, user_category_roles=user_category_roles, roles=ROLES)

        repo.save_user(user) # Use repo
        repo.save_user_categories(user_id, updated_category_roles_data) # Use repo
        repo.log_audit(session['username'], 'edit', 'User', user_id, f'User "{user["username"]}" updated.') # Use repo
        flash('User updated successfully.', 'success')
        return redirect(url_for('manage_users'))

    user_category_roles = repo.get_user_categories(user_id) # Use repo
    return render_template('add_edit_user.html', mode='edit', user=user, categories=categories, user_category_roles=user_category_roles, roles=ROLES)


@app.route('/delete_user/<user_id>', methods=['POST'])
@login_required
@roles_required('Admin')
def delete_user_route(user_id):
    if str(user_id) == str(session.get('user_id')):
        flash('You cannot delete your own account.', 'danger')
        return redirect(url_for('manage_users'))

    user = repo.get_user_by_id(user_id) # Use repo
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('manage_users'))

    if repo.delete_user(user_id): # Use repo
        repo.delete_user_category_roles(user_id) # Use repo
        repo.log_audit(session['username'], 'delete', 'User', user_id, f'User "{user["username"]}" deleted.') # Use repo
        flash(f'User "{user["username"]}" deleted successfully.', 'info')
    else:
        flash(f'Failed to delete user "{user.get("username", "unknown")}".', 'danger')

    return redirect(url_for('manage_users'))
# In app.py, replace all four category-related routes with these:

@app.route('/manage_categories')
@login_required
@roles_required('Admin')
def manage_categories():
    # Uses the repository to get the full category objects
    categories = repo.get_all_categories()
    return render_template('manage_categories.html', categories=categories)


@app.route('/add_category', methods=['POST'])
@login_required
@roles_required('Admin')
def add_category():
    category_name = request.form.get('name')
    logged_fields_str = request.form.get('logged_fields', '{}')

    if not category_name:
        flash('Category name cannot be empty.', 'danger')
        return redirect(url_for('manage_categories'))

    try:
        # Validate that the input is valid JSON before saving
        logged_fields = json.loads(logged_fields_str)
    except json.JSONDecodeError:
        flash('Invalid JSON format for "Fields to Log".', 'danger')
        return redirect(url_for('manage_categories'))

    categories = repo.get_all_categories()
    if any(cat.get('category') == category_name for cat in categories):
        flash(f'Category "{category_name}" already exists.', 'warning')
    else:
        categories.append({'category': category_name, 'logged_fields': logged_fields})
        repo.save_all_categories(categories)
        repo.log_audit(session['username'], 'add', 'Category', category_name, f'Category "{category_name}" added.')
        flash(f'Category "{category_name}" added.', 'success')

    return redirect(url_for('manage_categories'))

@app.route('/delete_category/<name>', methods=['POST'])
@login_required
@roles_required('Admin')
def delete_category(name):
    # Dependency checks
    policies = repo.get_all_policies()
    user_roles = repo.get_user_categories_for_all_users() # Assuming a helper to get all roles
    if any(p.get('category') == name for p in policies):
        flash(f'Cannot delete "{name}" because it is used by policies.', 'danger')
        return redirect(url_for('manage_categories'))
    if any(r.get('category') == name for r in user_roles):
        flash(f'Cannot delete "{name}" because it is assigned to users.', 'danger')
        return redirect(url_for('manage_categories'))

    # Deletion Logic
    all_categories = repo.get_all_categories()
    updated_categories = [cat for cat in all_categories if cat.get('category') != name]

    if len(updated_categories) < len(all_categories):
        repo.save_all_categories(updated_categories)
        repo.log_audit(session['username'], 'delete', 'Category', name, f'Category "{name}" deleted.')
        flash(f'Category "{name}" deleted.', 'info')
    else:
        flash(f'Category "{name}" not found.', 'danger')

    return redirect(url_for('manage_categories'))

@app.route('/edit_category/<category_name>', methods=['GET', 'POST'])
@login_required
@roles_required('Admin')
def edit_category(category_name):
    # Use repo to get all categories
    all_categories = repo.get_all_categories()
    category_to_edit = next((cat for cat in all_categories if cat.get('category') == category_name), None)

    if not category_to_edit:
        flash('Category not found.', 'danger')
        return redirect(url_for('manage_categories'))

    if request.method == 'POST':
        new_logged_fields_str = request.form.get('logged_fields', '{}')
        try:
            parsed_json = json.loads(new_logged_fields_str)

            updated_list = []
            for cat in all_categories:
                if cat.get('category') == category_name:
                    cat['logged_fields'] = parsed_json
                    updated_list.append(cat)
                else:
                    updated_list.append(cat)

            repo.save_all_categories(updated_list) # Use repo

            flash(f'Category "{category_name}" updated successfully.', 'success')
            return redirect(url_for('manage_categories'))
        except json.JSONDecodeError:
            flash('Invalid JSON format for "Fields to Log".', 'danger')
            category_to_edit['logged_fields'] = new_logged_fields_str
            return render_template('edit_category.html', category=category_to_edit)

    # For a GET request, no change is needed here, but the code is included for completeness
    return render_template('edit_category.html', category=category_to_edit)

@app.route('/manage_operators')
@login_required
@roles_required('Admin')
def manage_operators():
    # Operators are a simple list, so we use the local helper function
    operators = read_lookup_list(current_app.config['OPERATOR_FILE'], 'operator')
    return render_template('manage_lookup.html',
                           title='Operators',
                           items=operators,
                           add_endpoint='add_operator',
                           delete_endpoint='delete_operator')


@app.route('/manage_groups')
@login_required
@roles_required('Admin')
def manage_groups():
    # Uses the repository to get the full group objects
    groups = repo.get_all_groups()
    return render_template('manage_groups.html', groups=groups)

@app.route('/delete_group/<group_id>', methods=['POST'])
@login_required
@roles_required('Admin')
def delete_group_route(group_id):
    group_to_delete = repo.get_group_by_id(group_id) # Use repo
    if not group_to_delete:
        flash('Group not found.', 'danger')
        return redirect(url_for('manage_groups'))

    group_name = group_to_delete.get('name')

    # Dependency Check
    policies = repo.get_all_policies() # Use repo
    if any(group_name in p.get('groups', []) for p in policies):
        flash(f'Cannot delete group "{group_name}" because it is being used by one or more policies.', 'danger')
        return redirect(url_for('manage_groups'))

    # Deletion Logic
    if repo.delete_group(group_id): # Use repo
        repo.log_audit(session['username'], 'delete', 'Group', group_id, f'Group "{group_name}" deleted.') # Use repo
        flash(f'Group "{group_name}" deleted.', 'info')
    else:
        flash(f'Failed to delete group "{group_name}".', 'danger')

    return redirect(url_for('manage_groups'))

@app.route('/add_group', methods=['POST'])
@login_required
@roles_required('Admin')
def add_group():
    group_name = request.form.get('name')
    if group_name:
        if repo.get_group_by_name(group_name): # Assumes get_group_by_name exists
            flash(f'Group "{group_name}" already exists.', 'warning')
        else:
            new_group = {
                'id': str(uuid.uuid4()),
                'name': group_name,
                'description': request.form.get('description', ''),
            }
            repo.save_group(new_group)
            repo.log_audit(session['username'], 'add', 'Group', new_group['id'], f'Group "{group_name}" added.')
            flash(f'Group "{group_name}" added.', 'success')
    return redirect(url_for('manage_groups'))


@app.route('/edit_group/<group_id>', methods=['GET', 'POST'])
@login_required
@roles_required('Admin')
def edit_group(group_id):
    group = repo.get_group_by_id(group_id)
    if not group:
        flash('Group not found.', 'danger')
        return redirect(url_for('manage_groups'))

    if request.method == 'POST':
        new_name = request.form.get('name')
        existing_group = repo.get_group_by_name(new_name)
        if existing_group and existing_group.get('id') != group_id:
            flash(f'Another group with the name "{new_name}" already exists.', 'danger')
            return render_template('edit_group.html', group=group)

        updated_data = {
            'name': new_name,
            'description': request.form.get('description', '')
        }
        repo.update_group(group_id, updated_data)
        flash(f'Group "{new_name}" updated successfully.', 'success')
        return redirect(url_for('manage_groups'))

    return render_template('edit_group.html', group=group)

@app.route('/add_operator', methods=['POST'])
@login_required
@roles_required('Admin')
def add_operator():
    operator_name = request.form.get('name')
    if operator_name:
        operators = read_lookup_list(current_app.config['OPERATOR_FILE'], 'operator')
        if operator_name not in operators:
            operators.append(operator_name)
            # write_lookup_list is a local helper in app.py, so it does not use the repo
            write_lookup_list(current_app.config['OPERATOR_FILE'], 'operator', operators)
            repo.log_audit(session['username'], 'add', 'Operator', operator_name, f'Operator "{operator_name}" added.')
            flash(f'Operator "{operator_name}" added.', 'success')
        else:
            flash(f'Operator "{operator_name}" already exists.', 'warning')
    return redirect(url_for('manage_operators'))

@app.route('/delete_operator/<name>', methods=['POST'])
@login_required
@roles_required('Admin')
def delete_operator(name):
    # Dependency Check: See if this operator is used in any policy rule
    all_policies = repo.get_all_policies()
    is_in_use = False
    for policy in all_policies:
        for group in policy.get('rule_definition', {}).get('rule_groups', []):
            for rule in group.get('rules', []):
                if rule.get('operator') == name:
                    is_in_use = True
                    break
            if is_in_use:
                break
        if is_in_use:
            break

    if is_in_use:
        flash(f'Cannot delete operator "{name}" because it is being used by one or more policies.', 'danger')
        return redirect(url_for('manage_operators'))

    # If no dependencies, proceed with deletion
    operators = read_lookup_list(current_app.config['OPERATOR_FILE'], 'operator')
    if name in operators:
        operators.remove(name)
        write_lookup_list(current_app.config['OPERATOR_FILE'], 'operator', operators)
        repo.log_audit(session['username'], 'delete', 'Operator', name, f'Operator "{name}" deleted.')
        flash(f'Operator "{name}" deleted.', 'info')
    else:
        flash(f'Operator "{name}" not found.', 'danger')

    return redirect(url_for('manage_operators'))

@app.route('/download_policies_report')
@login_required
def download_policies_report():
    if not has_permission('download_policies_report'):
        flash('You do not have permission to download policy reports.', 'danger')
        return redirect(url_for('policy_list'))

    policies = repo.get_all_policies() # Use repo
    si = io.StringIO()
    writer = csv.DictWriter(si, fieldnames=app.config['POLICY_FIELDNAMES'])
    writer.writeheader()
    writer.writerows(policies)
    output = si.getvalue()
    response = Response(output, mimetype="text/csv")
    response.headers["Content-Disposition"] = "attachment; filename=policies_report.csv"
    repo.log_audit(session['username'], 'download', 'Report', 'policies_report', 'Policies report downloaded.') # Use repo
    return response

@app.route('/simulator', methods=['GET', 'POST'])
@login_required
def simulator():
    groups = read_lookup_list(current_app.config['GROUP_FILE'], 'name')
    categories = read_lookup_list(current_app.config['CATEGORY_FILE'], 'category')

    results = None
    payload_string = '{\n  "vulnerabilities": {\n    "critical": 0,\n    "high": 5,\n    "medium": 10\n  },\n  "image_name": "my-app:latest"\n}'
    # Default selections when the page loads
    selected_group = ''
    selected_category = ''
    selected_statuses = ['pending_approval']

    if request.method == 'POST':
        try:
            payload_string = request.form.get('payload', '{}')
            payload = json.loads(payload_string)
            selected_group = request.form.get('group')
            selected_category = request.form.get('category')
            # Get the list of statuses from the new multi-select form
            selected_statuses = request.form.getlist('statuses')

            # Build the context dictionary for the engine
            context = {
                'group': selected_group,
                'category': selected_category,
                'statuses': selected_statuses
            }

            results = run_decision_engine(payload, context, repo)
            results = json.dumps(results, indent=4)

        except json.JSONDecodeError:
            flash('Invalid JSON provided in the payload.', 'danger')
        except Exception as e:
            flash(f'An error occurred: {e}', 'danger')

    return render_template('simulator.html',
                           groups=groups,
                           categories=categories,
                           payload=payload_string,
                           selected_group=selected_group,
                           selected_category=selected_category,
                           selected_statuses=selected_statuses, # Pass statuses to template
                           results=results)

@app.route('/dashboard')
@login_required
def dashboard():
    # Gather all statistics from the repository
    policy_counts = repo.get_policy_counts_by_status()
    stale_policies = repo.get_stale_pending_policies()
    top_failed = repo.get_most_failed_policies()
    user_roles = repo.get_user_role_counts()
    pass_fail_trend = repo.get_pass_fail_trend()
    top_approvers = repo.get_top_approvers()

    # Prepare data for charts
    chart_status_labels = list(policy_counts.keys())
    chart_status_values = list(policy_counts.values())
    chart_roles_labels = list(user_roles.keys())
    chart_roles_values = list(user_roles.values())

    return render_template('dashboard.html',
                           chart_status_labels=chart_status_labels,
                           chart_status_values=chart_status_values,
                           chart_roles_labels=chart_roles_labels,
                           chart_roles_values=chart_roles_values,
                           pass_fail_trend=pass_fail_trend,
                           stale_policies=stale_policies,
                           top_failed=top_failed,
                           top_approvers=top_approvers)

if __name__ == '__main__':
    app.run(debug=True)

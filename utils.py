import csv
import os
from datetime import datetime
import logging
from flask import current_app
import uuid, ast, re
from werkzeug.security import generate_password_hash, check_password_hash
import json # Import json for handling policy values/groups
import hashlib # For calculate_policy_hash

from flask_mail import Message

def send_notification_email(recipients, subject, body):
    from app import mail
    """Sends an email to a list of recipients."""
    try:
        with mail.connect() as conn:
            for recipient_email in recipients:
                msg = Message(subject=subject, recipients=[recipient_email], body=body)
                conn.send(msg)
        current_app.logger.info(f"Sent notification email to: {recipients}")
    except Exception as e:
        current_app.logger.error(f"Failed to send email: {e}")

def is_csv_empty(file_path: str) -> bool:
    """Checks if a CSV file is empty or contains only a header row."""
    if not os.path.exists(file_path) or os.path.getsize(file_path) == 0:
        return True
    with open(file_path, 'r', newline='', encoding='utf-8-sig') as f:
        try:
            reader = csv.reader(f)
            header = next(reader)
            first_row = next(reader)
        except StopIteration:
            return True
    return False

def calculate_policy_hash(policy_data):
    """Calculates a SHA256 hash of the policy's RULES for change detection."""
    # The hash is now based on the single 'rule_definition' field.
    hash_fields = [
        'category', 'groups', 'requires_approval', 'rule_definition'
    ]

    data_to_hash = {k: policy_data.get(k, '') for k in hash_fields}

    # Sort any lists within the data to make the hash order-independent
    for key, value in data_to_hash.items():
        if isinstance(value, list):
            data_to_hash[key] = sorted(value)

    # Create a consistent string representation by sorting the dictionary keys
    data_string = json.dumps(data_to_hash, sort_keys=True)

    return hashlib.sha256(data_string.encode('utf-8')).hexdigest()


#
#     ########## THESE FUNCTIONS WILL BE REMOVED AFTER TETING WITH AZURE TABLE FUNCTIONS #########
#
#     # In utils.py, replace your read_csv function with this:
#     def read_csv(file_path):
#         """
#         Reads a CSV file, correctly parsing JSON fields and handling errors.
#         """
#         if not os.path.exists(file_path) or os.path.getsize(file_path) == 0:
#             return []
#
#         data = []
#         with open(file_path, 'r', newline='', encoding='utf-8-sig') as f:
#             reader = csv.DictReader(f)
#             json_fields = ['groups', 'category_roles', 'rule_definition', 'logged_fields']
#
#             for row in reader:
#                 processed_row = dict(row)
#                 for key in json_fields:
#                     if key in processed_row:
#                         json_string = processed_row[key]
#                         try:
#                             if json_string:
#                                 processed_row[key] = json.loads(json_string)
#                             else:
#                                 processed_row[key] = {} if key == 'logged_fields' else []
#                         except (json.JSONDecodeError, TypeError):
#                             processed_row[key] = {} if key == 'logged_fields' else []
#                 data.append(processed_row)
#         return data
#
#     # In utils.py, replace your write_csv function with this:
#     def write_csv(file_path, data, fieldnames):
#         """
#         Writes a list of dictionaries to a CSV file, correctly serializing JSON fields.
#         """
#         with open(file_path, 'w', newline='', encoding='utf-8') as f:
#             writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
#             writer.writeheader()
#
#             json_fields = ['groups', 'category_roles', 'rule_definition', 'logged_fields']
#
#             for row in data:
#                 row_to_write = row.copy()
#                 for key in json_fields:
#                     if key in row_to_write and isinstance(row_to_write[key], (list, dict)):
#                         row_to_write[key] = json.dumps(row_to_write[key])
#                 writer.writerow(row_to_write)
#
# def read_simple_csv(file_path):
#     """A simple function to read any CSV into a list of dictionaries without special processing."""
#     if not os.path.exists(file_path):
#         return []
#     try:
#         with open(file_path, 'r', newline='', encoding='utf-8-sig') as f:
#             return list(csv.DictReader(f))
#     except Exception:
#         return []
#
# def get_groups():
#     """Retrieves all groups from the groups.csv file."""
#     return read_csv(current_app.config['GROUP_FILE'])
#
# def save_group(group_data):
#     """Saves or updates a group in the groups.csv file."""
#     groups = get_groups()
#     group_id = group_data.get('id')
#     fieldnames = current_app.config['GROUP_FIELDNAMES']
#
#     if group_id: # Existing group
#         group_found = False
#         for i, group in enumerate(groups):
#             if group.get('id') == group_id:
#                 groups[i] = group_data
#                 group_found = True
#                 break
#         if not group_found:
#             groups.append(group_data)
#     else: # New group
#         group_data['id'] = str(uuid.uuid4())
#         groups.append(group_data)
#
#     write_csv(current_app.config['GROUP_FILE'], groups, fieldnames)
#     return group_data
#
# def delete_group(group_id):
#     """Deletes a group by its ID."""
#     groups = get_groups()
#     updated_groups = [g for g in groups if g.get('id') != group_id]
#     if len(updated_groups) < len(groups):
#         fieldnames = current_app.config['GROUP_FIELDNAMES']
#         write_csv(current_app.config['GROUP_FILE'], updated_groups, fieldnames=fieldnames)
#         return True
#     return False
#
# def get_user_groups(user_id):
#     """Placeholder function for retrieving user groups. Not fully implemented."""
#     return []
#
# # --- User Category Roles Functions ---
#
# def read_user_categories():
#     """Reads all user category roles from the user_category_roles.csv file."""
#     return read_csv(current_app.config['USER_CATEGORY_ROLES_FILE'])
#
# def write_user_categories(user_category_roles_data):
#     """Writes all user category roles to the user_category_roles.csv file."""
#     fieldnames = current_app.config['USER_CATEGORY_ROLES_FIELDNAMES']
#     write_csv(current_app.config['USER_CATEGORY_ROLES_FILE'], user_category_roles_data, fieldnames)
#
# def get_user_categories(user_id):
#     """Retrieves category roles for a specific user."""
#     all_user_category_roles = read_user_categories()
#     return [
#         r for r in all_user_category_roles if r.get('user_id') == str(user_id)
#     ]
#
# def save_user_categories(user_id, category_roles):
#     """Saves category roles for a specific user. Replaces existing roles."""
#     all_user_category_roles = read_user_categories()
#     # Remove existing roles for this user
#     updated_roles = [r for r in all_user_category_roles if r.get('user_id') != str(user_id)]
#
#     # Add new roles for this user
#     for role_entry in category_roles:
#         new_entry = {
#             'user_id': str(user_id),
#             'category': role_entry['category'],
#             'role': role_entry['role']
#         }
#         updated_roles.append(new_entry)
#
#     write_user_categories(updated_roles)
#     return True
#
# def delete_user_category_roles(user_id):
#     """Deletes all category roles for a given user."""
#     all_user_category_roles = read_user_categories()
#     updated_roles = [r for r in all_user_category_roles if r.get('user_id') != str(user_id)]
#     if len(updated_roles) < len(all_user_category_roles):
#         write_user_categories(updated_roles)
#         return True
#     return False
#
# def get_user_role_for_category(user_id, category_name):
#     """Retrievis the role of a user for a specific category."""
#
#     # --- Start of new debug code ---
#     print("\n--- DEBUG: Checking category-specific permission ---")
#     print(f"--- Searching for User ID: '{user_id}' in Category: '{category_name}'")
#     # --- End of new debug code ---
#
#     user_roles = get_user_categories(user_id)
#     for role_entry in user_roles:
#         if role_entry.get('category') == category_name:
#
#             return role_entry.get('role')
#     return None
#
# def get_groups():
#     """Retrieves all groups from the groups.csv file."""
#     return read_csv(current_app.config['GROUP_FILE'])
#
# def get_users():
#     """Retrieves all users from the users.csv file."""
#     return read_csv(current_app.config['USER_FILE'])
#
# def get_user(username=None, user_id=None):
#     """Retrieves a single user by username or user ID."""
#     users = get_users()
#
#     if username:
#         return next((u for u in users if u.get('username') == username), None)
#     if user_id:
#         return next((u for u in users if u.get('id') == str(user_id)), None)
#     return None
#
# def save_user(user_data):
#     """Saves or updates a user in the users.csv file."""
#     users = get_users()
#     user_id = user_data.get('id')
#     fieldnames = current_app.config['USER_FIELDNAMES']
#     if user_id:
#         user_found = False
#         for i, user in enumerate(users):
#             if user.get('id') == user_id:
#                 users[i] = user_data
#                 user_found = True
#                 break
#         if not user_found:
#             users.append(user_data)
#     else:
#         user_data['id'] = str(uuid.uuid4())
#         users.append(user_data)
#     write_csv(current_app.config['USER_FILE'], users, fieldnames)
#     return user_data
#
# def delete_user(user_id):
#     """Deletes a user by their ID."""
#     users = get_users()
#     initial_count = len(users)
#     updated_users = [u for u in users if u.get('id') != str(user_id)]
#     if len(updated_users) < initial_count:
#         fieldnames = current_app.config['USER_FIELDNAMES']
#         write_csv(current_app.config['USER_FILE'], updated_users, fieldnames)
#         return True
#     return False
#
# def get_all_users_with_details():
#     """Retrieves all users with their full details, including category roles."""
#     return get_users()
#
# # --- Policy Management Functions ---
#
# def get_policies():
#     """Retrieves all policies from the policies.csv file."""
#     return read_csv(current_app.config['POLICY_FILE'])
#
# def get_policy_by_id(policy_id):
#     """Retrieves a single policy by its ID."""
#     policies = get_policies()
#     return next((p for p in policies if p.get('id') == policy_id), None)
#
# def save_policy(policy_data, username="system"):
#     """
#     Saves a new policy to the policies.csv file.
#     This function now expects the policy_hash to be pre-calculated.
#     """
#     policies = get_policies()
#     user = get_user(username=username)
#
#     # Add metadata to the policy dictionary
#     policy_data['id'] = str(uuid.uuid4())
#     policy_data['created_date'] = datetime.now().isoformat()
#     policy_data['created_by_id'] = user['id'] if user else 'unknown'
#     policy_data['status'] = 'pending_approval'
#
#     # The line that recalculated the hash has been REMOVED from here.
#     # The hash is now passed in via the policy_data dictionary.
#
#     policies.append(policy_data)
#
#     write_csv(current_app.config['POLICY_FILE'], policies, current_app.config['POLICY_FIELDNAMES'])
#     log_audit(username, 'created', 'policy', policy_data['id'], f"Policy '{policy_data.get('name')}' created.")
#     return policy_data
#
# def update_policy(policy_id, updated_data, username="system"):
#     """Updates an existing policy."""
#
#     # --- Start of Debug Block ---
#     print("\n--- UPDATE POLICY DEBUG: START ---")
#     print(f"--- Target Policy ID to update: {policy_id}")
#     print(f"--- Data to update with: {updated_data.get('name')}")
#     # --- End of Debug Block ---
#
#     policies = get_policies()
#
#     # --- Start of Debug Block ---
#     print(f"--- Policies loaded from CSV. Count: {len(policies)}")
#     for p in policies:
#         print(f"    - Loaded Policy -> ID: {p.get('id')}, Name: {p.get('name')}")
#     # --- End of Debug Block ---
#
#     policy_found = False
#     for i, policy in enumerate(policies):
#         if policy.get('id') == policy_id:
#             print(f"--- Match found at index {i}. Updating policy '{policy.get('name')}'...")
#             policies[i].update(updated_data)
#             policy_found = True
#             # We break the loop immediately after finding and updating.
#             break
#
#     if policy_found:
#         # --- Start of Debug Block ---
#         print(f"--- Data prepared for saving. Final policy count: {len(policies)}")
#         for p in policies:
#              print(f"    - Policy to be saved -> ID: {p.get('id')}, Name: {p.get('name')}")
#         print("--- Now writing to CSV file...")
#         # --- End of Debug Block ---
#
#         write_csv(current_app.config['POLICY_FILE'], policies, current_app.config['POLICY_FIELDNAMES'])
#         log_audit(username, 'updated', 'policy', policy_id, f"Policy '{updated_data.get('name', '')}' updated.")
#
#         print("--- UPDATE POLICY DEBUG: END (Success) ---\n")
#         return True
#
#     print("--- UPDATE POLICY DEBUG: END (Failure - Policy ID was not found in list) ---\n")
#     return False
#
# def log_audit(username, action, entity_type, entity_id, description=""):
#     """Logs an audit event."""
#     log_entry = {
#         'timestamp': datetime.now().isoformat(), 'username': username,
#         'action': action, 'entity_type': entity_type,
#         'entity_id': str(entity_id), 'description': description
#     }
#
#     # This print statement will ALWAYS show in your terminal if the function runs
#     print(f"DEBUG: Attempting to log audit: {log_entry}")
#
#     try:
#         audit_file = current_app.config['AUDIT_FILE']
#         fieldnames = ['timestamp', 'username', 'action', 'entity_type', 'entity_id', 'description']
#         file_is_new = not os.path.exists(audit_file) or os.path.getsize(audit_file) == 0
#
#         with open(audit_file, 'a', newline='', encoding='utf-8') as f:
#             writer = csv.DictWriter(f, fieldnames=fieldnames)
#             if file_is_new:
#                 writer.writeheader()
#             writer.writerow(log_entry)
#
#         current_app.logger.info(f"AUDIT LOGGED: {log_entry}")
#
#     except Exception as e:
#         # This error will show in your terminal if writing fails
#         current_app.logger.error(f"!!! FAILED TO WRITE AUDIT LOG for action '{action}': {e}")
#         print(f"!!! FAILED TO WRITE AUDIT LOG for action '{action}': {e}")
#
# def log_decision(decision_object, payload):
#     """
#     Logs the result of a decision, dynamically extracting key fields
#     from the decision_object's 'extractedData' field.
#     """
#     decision_log_file = current_app.config.get('DECISION_LOG_FILE', 'data/decision_log.csv')
#
#     # Base fields that are always present
#     base_fieldnames = ['timestamp', 'decisionId', 'decision', 'category', 'group', 'failed_policy_count', 'payload_hash', 'full_result']
#     extracted_data = decision_object.get('extractedData', {})
#
#     # The final columns will be the base columns plus whatever was extracted
#     dynamic_fieldnames = sorted(extracted_data.keys())
#     final_fieldnames = base_fieldnames + dynamic_fieldnames
#
#     # Prepare the log entry
#     log_entry = {
#         'timestamp': datetime.now().isoformat(),
#         'decisionId': decision_object.get('decisionId'),
#         'decision': decision_object.get('finalDecision'),
#         'category': decision_object.get('evaluationContext', {}).get('category', 'N/A'),
#         'group': decision_object.get('evaluationContext', {}).get('group', 'N/A'),
#         'failed_policy_count': len(decision_object.get('failedPolicies', [])),
#         'full_result': json.dumps(decision_object),
#         'payload_hash': hashlib.sha256(json.dumps(payload, sort_keys=True).encode('utf-8')).hexdigest()
#     }
#     # Add the dynamically extracted data to the log entry
#     log_entry.update(extracted_data)
#
#     # Write to the CSV file
#     try:
#         existing_logs = read_simple_csv(decision_log_file)
#         all_fieldnames = list(existing_logs[0].keys()) if existing_logs else final_fieldnames
#         for new_key in final_fieldnames:
#             if new_key not in all_fieldnames:
#                 all_fieldnames.append(new_key)
#
#         existing_logs.append(log_entry)
#
#         with open(decision_log_file, 'w', newline='', encoding='utf-8') as f:
#             writer = csv.DictWriter(f, fieldnames=all_fieldnames, extrasaction='ignore')
#             writer.writeheader()
#             writer.writerows(existing_logs)
#
#         current_app.logger.info(f"DECISION LOGGED: ID {log_entry['decisionId'][:8]}... Decision is {log_entry['decision']}")
#     except Exception as e:
#         current_app.logger.error(f"!!! FAILED TO WRITE DECISION LOG: {e}")
#
# def get_all_categories():
#     """Reads the full categories.csv file into a list of dictionaries."""
#     return read_csv(current_app.config['CATEGORY_FILE'])
#
# def save_all_categories(categories_list):
#     """Writes the entire list of categories back to the CSV file."""
#     write_csv(current_app.config['CATEGORY_FILE'], categories_list, fieldnames=['category', 'logged_fields'])
#
# def get_category(category_name):
#     """Retrieves the full details (including logged_fields) for a single category."""
#     all_categories = get_all_categories()
#     return next((cat for cat in all_categories if cat.get('category') == category_name), None)
#
#
# #---------ENGINE LOGIC FUNCTIONS START ------------------
# def get_nested_value(data_dict, key_string):
#     """Safely gets a value from a nested dictionary using dot notation."""
#     keys = key_string.split('.')
#     value = data_dict
#     for key in keys:
#         if isinstance(value, dict) and key in value:
#             value = value[key]
#         else:
#             return None # Key not found
#     return value
#
# def evaluate_rule(rule, data_payload):
#     """Evaluates a single policy rule against the data payload. Returns True if the condition passes."""
#     print("\n--- EVALUATION DEBUG: Inside evaluate_rule ---")
#
#     field = rule.get('field')
#     operator = rule.get('operator')
#     policy_value = rule.get('value')
#
#     data_value = get_nested_value(data_payload, field)
#
#     print(f"--- Rule: field='{field}', operator='{operator}', policy_value='{policy_value}' (type: {type(policy_value)})")
#     print(f"--- Data: found data_value='{data_value}' (type: {type(data_value)}) for field '{field}'")
#
#     if data_value is None:
#         print("--- Result: Fail (Field not found in payload)")
#         return False
#
#     # Try to compare as numbers first
#     try:
#         data_num = float(data_value)
#         policy_num = float(policy_value)
#         print(f"--- Attempting numeric comparison: {data_num} {operator} {policy_num}")
#
#         if operator in ['equals', '='] and data_num == policy_num:
#             print("--- Result: Pass (Numeric equals)")
#             return True
#         if operator in ['greater_than', '>'] and data_num > policy_num:
#             print("--- Result: Pass (Numeric >)")
#             return True
#         if operator in ['less_than', '<'] and data_num < policy_num:
#             print("--- Result: Pass (Numeric <)")
#             return True
#         if operator in ['greater_than_or_equal_to', '>='] and data_num >= policy_num:
#             print("--- Result: Pass (Numeric >=)")
#             return True
#         if operator in ['less_than_or_equal_to', '<='] and data_num <= policy_num:
#             print("--- Result: Pass (Numeric <=)")
#             return True
#         print("--- Numeric comparison did not result in a pass.")
#     except (ValueError, TypeError) as e:
#         print(f"--- Could not perform numeric comparison (Error: {e}). Falling back to string comparison.")
#         pass
#
#     # Perform string-based comparisons
#     data_str = str(data_value)
#     print(f"--- Attempting string comparison: '{data_str}' {operator} '{policy_value}'")
#     if operator in ['equals', '='] and data_str == policy_value:
#         print("--- Result: Pass (String equals)")
#         return True
#
#     # Handle list-based operators 'in' and 'not in'
#     if isinstance(policy_value, list):
#       if operator == 'in' and data_str in policy_value:
#           print("--- Result: Pass (String in list)")
#           return True
#       if operator == 'not in' and data_str not in policy_value:
#           print("--- Result: Pass (String not in list)")
#           return True
#
#     print("--- Result: Fail (No conditions met)")
#     return False
#
# def run_decision_engine(data_payload, context):
#     """
#     Runs the decision engine for a given payload and context (e.g., group).
#     Implements the "Fail-Closed" principle.
#     """
#     applicable_policies = [
#         p for p in get_policies()
#         if p['status'] == 'enabled' and context['group'] in p.get('groups', [])
#     ]
#
#     if not applicable_policies:
#         return {"decision": "Pass", "reason": "No applicable policies found for the context.", "passed_policies": [], "failed_policies": []}
#
#     decision = "Pass" # Default to Pass
#     passed_policies = []
#     failed_policies = []
#
#     for policy in applicable_policies:
#         is_pass, reason = evaluate_rule(policy, data_payload)
#         if is_pass:
#             passed_policies.append(policy['name'])
#         else:
#             decision = "Fail" # If any policy fails, the final decision is Fail
#             failed_policies.append({"name": policy['name'], "reason": reason})
#
#     return {
#         "decision": decision,
#         "passed_policies": passed_policies,
#         "failed_policies": failed_policies
#     }
#
# def get_users_with_role(role_name, category_name):
#     """Finds all users who have a specific role in a specific category."""
#     users = get_users()
#     user_category_roles = read_user_categories()
#
#     approver_ids = {
#         r['user_id'] for r in user_category_roles
#         if r.get('category') == category_name and r.get('role') == role_name
#     }
#
#     # Also include global Admins as implicit approvers for everything
#     approver_ids.update({u['id'] for u in users if u.get('global_role') == 'Admin'})
#
#     return [u for u in users if u.get('id') in approver_ids]

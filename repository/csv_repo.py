import csv
import json
import os
import uuid
import hashlib
from flask import current_app
from datetime import datetime
import ast # Used in the robust _read_csv method
from collections import Counter

class CsvRepository:
    """
    A repository that handles all data storage operations using CSV files.
    This class encapsulates all file I/O logic.
    """
    def __init__(self, config):
        self.config = config

    # --- Private Helper Methods ---

    def _read_csv(self, file_path):
        """Private helper to read a CSV file, correctly parsing JSON fields."""
        if not os.path.exists(file_path) or os.path.getsize(file_path) == 0:
            return []
        data = []
        with open(file_path, 'r', newline='', encoding='utf-8-sig') as f:
            reader = csv.DictReader(f)
            json_fields = ['groups', 'category_roles', 'rule_definition', 'logged_fields']
            for row in reader:
                processed_row = dict(row)
                for key, value in processed_row.items():
                    if key in json_fields:
                        try:
                            processed_row[key] = json.loads(value) if value else {}
                        except (json.JSONDecodeError, TypeError):
                            processed_row[key] = {}
                data.append(processed_row)
        return data

    def _write_csv(self, file_path, data, fieldnames):
        """Private helper to write a CSV file, correctly serializing JSON fields."""
        with open(file_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
            writer.writeheader()
            json_fields = ['groups', 'category_roles', 'rule_definition', 'logged_fields']
            for row in data:
                row_to_write = row.copy()
                for key in json_fields:
                    if key in row_to_write and isinstance(row_to_write[key], (list, dict)):
                        row_to_write[key] = json.dumps(row_to_write[key])
                writer.writerow(row_to_write)

    # --- User Methods ---

    def get_all_users(self):
        return self._read_csv(self.config['USER_FILE'])

    def get_user_by_id(self, user_id):
        return next((u for u in self.get_all_users() if u.get('id') == str(user_id)), None)

    def get_user_by_username(self, username):
        return next((u for u in self.get_all_users() if u.get('username') == username), None)

    def save_user(self, user_data):
        users = self.get_all_users()
        if user_data.get('id'):
            for i, user in enumerate(users):
                if user.get('id') == user_data.get('id'):
                    users[i] = user_data
                    break
            else:
                users.append(user_data)
        else:
            user_data['id'] = str(uuid.uuid4())
            users.append(user_data)
        self._write_csv(self.config['USER_FILE'], users, self.config['USER_FIELDNAMES'])
        return user_data

    def delete_user(self, user_id):
        users = self.get_all_users()
        updated_users = [u for u in users if u.get('id') != str(user_id)]
        if len(updated_users) < len(users):
            self._write_csv(self.config['USER_FILE'], updated_users, self.config['USER_FIELDNAMES'])
            return True
        return False

    # --- Policy Methods ---

    def get_all_policies(self):
        return self._read_csv(self.config['POLICY_FILE'])

    def get_policy_by_id(self, policy_id):
        return next((p for p in self.get_all_policies() if p.get('id') == policy_id), None)

    def save_policy(self, policy_data, username):
        policies = self.get_all_policies()
        user = self.get_user_by_username(username)
        policy_data.update({
            'id': str(uuid.uuid4()), 'created_date': datetime.now().isoformat(),
            'created_by_id': user['id'] if user else 'unknown', 'status': 'pending_approval'
        })
        policies.append(policy_data)
        self._write_csv(self.config['POLICY_FILE'], policies, self.config['POLICY_FIELDNAMES'])
        self.log_audit(username, 'created', 'policy', policy_data['id'], f"Policy '{policy_data.get('name')}' created.")
        return policy_data

    def update_policy(self, policy_id, updated_data, username):
        policies = self.get_all_policies()
        for i, policy in enumerate(policies):
            if policy.get('id') == policy_id:
                policies[i].update(updated_data)
                self._write_csv(self.config['POLICY_FILE'], policies, self.config['POLICY_FIELDNAMES'])
                self.log_audit(username, 'updated', 'policy', policy_id, f"Policy '{updated_data.get('name', '')}' updated.")
                return True
        return False

    def delete_policy(self, policy_id):
        """Deletes a policy by its ID."""
        policies = self.get_all_policies()
        updated_policies = [p for p in policies if p.get('id') != policy_id]

        if len(updated_policies) < len(policies):
            self._write_csv(self.config['POLICY_FILE'], updated_policies, self.config['POLICY_FIELDNAMES'])
            return True
        return False

    # --- Category Methods ---

    def get_all_categories(self):
        return self._read_csv(self.config['CATEGORY_FILE'])

    def get_category_by_name(self, category_name):
        return next((cat for cat in self.get_all_categories() if cat.get('category') == category_name), None)

    def save_all_categories(self, categories_list):
        self._write_csv(self.config['CATEGORY_FILE'], categories_list, self.config['CATEGORY_FIELDNAMES'])

    # --- Group Methods ---

    def get_all_groups(self):
        return self._read_csv(self.config['GROUP_FILE'])

    def save_group(self, group_data):
        groups = self.get_all_groups()
        if group_data.get('id'):
            for i, group in enumerate(groups):
                if group.get('id') == group_data.get('id'):
                    groups[i] = group_data
                    break
            else:
                groups.append(group_data)
        else:
            group_data['id'] = str(uuid.uuid4())
            groups.append(group_data)
        self._write_csv(self.config['GROUP_FILE'], groups, self.config['GROUP_FIELDNAMES'])
        return group_data

    def delete_group(self, group_id):
        groups = self.get_all_groups()
        updated_groups = [g for g in groups if g.get('id') != group_id]
        if len(updated_groups) < len(groups):
            self._write_csv(self.config['GROUP_FILE'], updated_groups, self.config['GROUP_FIELDNAMES'])
            return True
        return False

# Add these two methods inside the CsvRepository class in repository/csv_repo.py

    def get_group_by_id(self, group_id):
        """Retrieves a single group by its ID."""
        return next((g for g in self.get_all_groups() if g.get('id') == group_id), None)

    def get_group_by_name(self, group_name):
        """Retrieves a single group by its name."""
        return next((g for g in self.get_all_groups() if g.get('name') == group_name), None)

    def update_group(self, group_id, updated_data):
        """Updates an existing group's data."""
        groups = self.get_all_groups()
        group_found = False
        for i, group in enumerate(groups):
            if group.get('id') == group_id:
                groups[i].update(updated_data)
                group_found = True
                break

        if group_found:
            self._write_csv(self.config['GROUP_FILE'], groups, self.config['GROUP_FIELDNAMES'])
            return True
        return False

    # --- User Category Role Methods ---

    def get_user_categories(self, user_id):
        all_roles = self._read_csv(self.config['USER_CATEGORY_ROLES_FILE'])
        return [r for r in all_roles if r.get('user_id') == str(user_id)]

    def save_user_categories(self, user_id, category_roles):
        all_roles = self._read_csv(self.config['USER_CATEGORY_ROLES_FILE'])
        updated_roles = [r for r in all_roles if r.get('user_id') != str(user_id)]
        for role_entry in category_roles:
            updated_roles.append({'user_id': str(user_id), 'category': role_entry['category'], 'role': role_entry['role']})
        self._write_csv(self.config['USER_CATEGORY_ROLES_FILE'], updated_roles, self.config['USER_CATEGORY_ROLES_FIELDNAMES'])
        return True

    def delete_user_category_roles(self, user_id):
        all_roles = self._read_csv(self.config['USER_CATEGORY_ROLES_FILE'])
        updated_roles = [r for r in all_roles if r.get('user_id') != str(user_id)]
        if len(updated_roles) < len(all_roles):
            self._write_csv(self.config['USER_CATEGORY_ROLES_FILE'], updated_roles, self.config['USER_CATEGORY_ROLES_FIELDNAMES'])
            return True
        return False

    def get_user_role_for_category(self, user_id, category_name):
        """Retrieves the role of a user for a specific category."""
        # Calls the repository's own method to get the user's roles
        user_roles = self.get_user_categories(user_id)

        for role_entry in user_roles:
            if role_entry.get('category') == category_name:
                return role_entry.get('role')

        return None # No specific role found for this category

    def get_user_categories_for_all_users(self):
        """Reads the entire user_category_roles.csv file."""
        return self._read_csv(self.config['USER_CATEGORY_ROLES_FILE'])

    # --- Logging Methods ---
    def get_audit_log(self):
        """Reads the full audit log file."""
        return self._read_csv(self.config['AUDIT_FILE'])

    def log_audit(self, username, action, entity_type, entity_id, description=""):
        log_file = self.config['AUDIT_FILE']
        fieldnames = ['timestamp', 'username', 'action', 'entity_type', 'entity_id', 'description']
        log_entry = {'timestamp': datetime.now().isoformat(), 'username': username, 'action': action, 'entity_type': entity_type, 'entity_id': str(entity_id), 'description': description}
        file_is_new = not os.path.exists(log_file) or os.path.getsize(log_file) == 0
        with open(log_file, 'a', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            if file_is_new: writer.writeheader()
            writer.writerow(log_entry)

    def log_decision(self, decision_object, payload, context):
        log_file = self.config.get('DECISION_LOG_FILE', 'data/decision_log.csv')
        base_fieldnames = ['timestamp', 'decisionId', 'decision', 'category', 'group', 'failed_policy_count', 'payload_hash', 'full_result']
        extracted_data = decision_object.get('extractedData', {})
        dynamic_fieldnames = sorted(extracted_data.keys())
        final_fieldnames = base_fieldnames + dynamic_fieldnames
        log_entry = {
            'timestamp': datetime.now().isoformat(), 'decisionId': decision_object.get('decisionId'),
            'decision': decision_object.get('finalDecision'), 'category': context.get('category', 'N/A'),
            'group': context.get('group', 'N/A'), 'failed_policy_count': len(decision_object.get('failedPolicies', [])),
            'full_result': json.dumps(decision_object),
            'payload_hash': hashlib.sha256(json.dumps(payload, sort_keys=True).encode('utf-8')).hexdigest()
        }
        log_entry.update(extracted_data)
        # Simplified write logic for append-only log
        file_is_new = not os.path.exists(log_file)
        with open(log_file, 'a', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=final_fieldnames, extrasaction='ignore')
            if file_is_new: writer.writeheader()
            writer.writerow(log_entry)

# --- Dashboard Methods ---

    def get_decision_log(self):
        """Reads the full decision log file."""
        return self._read_csv(self.config.get('DECISION_LOG_FILE', 'data/decision_log.csv'))

    def get_policy_counts_by_status(self):
        """Counts policies and groups them by status."""
        policies = self.get_all_policies()
        status_list = [p.get('status', 'unknown') for p in policies]
        return Counter(status_list)

    def get_stale_pending_policies(self, limit=5):
        """Finds the oldest policies still in 'pending_approval'."""
        policies = self.get_all_policies()
        pending_policies = [p for p in policies if p.get('status') == 'pending_approval']
        # Sort by creation date, oldest first
        sorted_policies = sorted(pending_policies, key=lambda p: p.get('created_date', ''))
        return sorted_policies[:limit]

    def get_most_failed_policies(self, limit=5):
        """Counts which policies fail most often from the decision log."""
        decisions = self.get_decision_log()
        failed_policy_names = []
        for decision in decisions:
            if decision.get('finalDecision') == 'Fail':
                for failed_policy in decision.get('failedPolicies', []):
                    if failed_policy.get('name'):
                        failed_policy_names.append(failed_policy.get('name'))

        return Counter(failed_policy_names).most_common(limit)

    def get_user_role_counts(self):
        """Counts users and groups them by global role."""
        users = self.get_all_users()
        role_list = [u.get('global_role', 'N/A') for u in users]
        return Counter(role_list)

    def get_pass_fail_trend(self, days=30):
        """Calculates the daily pass/fail trend for the last N days."""
        from datetime import timedelta

        decisions = self.get_decision_log()
        trend = {}

        for i in range(days):
            date_key = (datetime.now() - timedelta(days=i)).strftime('%Y-%m-%d')
            trend[date_key] = {'Pass': 0, 'Fail': 0}

        for dec in decisions:
            try:
                timestamp = datetime.fromisoformat(dec['timestamp'])
                date_key = timestamp.strftime('%Y-%m-%d')
                if date_key in trend:
                    if dec.get('decision') == 'Pass':
                        trend[date_key]['Pass'] += 1
                    elif dec.get('decision') == 'Fail':
                        trend[date_key]['Fail'] += 1
            except (ValueError, TypeError):
                continue

        sorted_trend = sorted(trend.items())
        labels = [item[0] for item in sorted_trend]
        pass_counts = [item[1]['Pass'] for item in sorted_trend]
        fail_counts = [item[1]['Fail'] for item in sorted_trend]

        return {'labels': labels, 'pass_counts': pass_counts, 'fail_counts': fail_counts}

    def get_top_approvers(self, limit=5):
        """Finds the users who have approved the most policies."""
        policies = self.get_all_policies()
        approver_list = [p.get('approved_by') for p in policies if p.get('approved_by')]
        return Counter(approver_list).most_common(limit)

    def get_decision_log(self):
        """Reads the full decision log file."""
        return self._read_csv(self.config.get('DECISION_LOG_FILE', 'data/decision_log.csv'))

    def get_policy_counts_by_status(self):
        """Counts policies and groups them by status."""
        policies = self.get_all_policies()
        counts = {}
        for policy in policies:
            status = policy.get('status', 'unknown')
            counts[status] = counts.get(status, 0) + 1
        return counts

    def get_stale_pending_policies(self, limit=5):
        """Finds the oldest policies still in 'pending_approval'."""
        policies = self.get_all_policies()
        pending_policies = [p for p in policies if p.get('status') == 'pending_approval']
        # Sort by creation date, oldest first
        sorted_policies = sorted(pending_policies, key=lambda p: p.get('created_date', ''))
        return sorted_policies[:limit]

    def get_most_failed_policies(self, limit=5):
        """Counts which policies fail most often in the decision log."""
        from collections import Counter
        decisions = self.get_decision_log()
        failed_policy_names = []
        for decision in decisions:
            if decision.get('finalDecision') == 'Fail':
                for failed_policy in decision.get('failedPolicies', []):
                    failed_policy_names.append(failed_policy.get('name'))

        return Counter(failed_policy_names).most_common(limit)

import json
import uuid
from datetime import datetime
from azure.data.tables import TableServiceClient, UpdateMode
from collections import Counter

class AzureTableRepository:
    """A repository that handles data storage using Azure Table Storage."""

    def __init__(self, config):
        connection_string = config['AZURE_STORAGE_CONNECTION_STRING']
        self.table_service = TableServiceClient.from_connection_string(conn_str=connection_string)

        # Initialize clients for each table, creating them if they don't exist
        self.users_table = self.table_service.create_table_if_not_exists("users")
        self.policies_table = self.table_service.create_table_if_not_exists("policies")
        self.categories_table = self.table_service.create_table_if_not_exists("categories")
        self.groups_table = self.table_service.create_table_if_not_exists("groups")
        self.user_roles_table = self.table_service.create_table_if_not_exists("usercategoryroles")
        self.audit_log_table = self.table_service.create_table_if_not_exists("auditlog")
        self.decision_log_table = self.table_service.create_table_if_not_exists("decisionlog")

    def _serialize(self, entity):
        """Prepares a Python dictionary for storage in Azure Tables by serializing complex fields."""
        entity_to_save = entity.copy()
        json_fields = ['groups', 'category_roles', 'rule_definition', 'logged_fields', 'full_result', 'extractedData']
        for key in json_fields:
            if key in entity_to_save and isinstance(entity_to_save[key], (list, dict)):
                entity_to_save[key] = json.dumps(entity_to_save[key])
        return entity_to_save

    def _deserialize(self, entity):
        """Converts an Azure Table entity back into a standard Python dictionary, removing Azure metadata."""
        deserialized = dict(entity)

        # --- START OF FIX ---
        # Remove Azure-specific system keys so the rest of the app doesn't see them.
        deserialized.pop('PartitionKey', None)
        deserialized.pop('RowKey', None)
        deserialized.pop('Timestamp', None)
        deserialized.pop('etag', None)
        # --- END OF FIX ---

        json_fields = ['groups', 'category_roles', 'rule_definition', 'logged_fields', 'full_result', 'extractedData']
        for key in json_fields:
            if key in deserialized and isinstance(deserialized[key], str):
                try:
                    deserialized[key] = json.loads(deserialized[key])
                except (json.JSONDecodeError, TypeError):
                    deserialized[key] = {} if isinstance(deserialized[key], str) and '{' in deserialized[key] else []
        return deserialized

    # --- User Methods ---
    def get_all_users(self):
        entities = self.users_table.query_entities("PartitionKey eq 'USER'")
        return [self._deserialize(e) for e in entities]

    def get_user_by_id(self, user_id):
        try:
            entity = self.users_table.get_entity(partition_key='USER', row_key=str(user_id))
            return self._deserialize(entity)
        except Exception:
            return None

    def get_user_by_username(self, username):
        entities = self.users_table.query_entities(f"username eq '{username}'")
        try:
            return self._deserialize(next(entities))
        except StopIteration:
            return None

    def save_user(self, user_data):
        user_id = user_data.get('id', str(uuid.uuid4()))
        entity = {'PartitionKey': 'USER', 'RowKey': user_id}
        entity.update(user_data)
        self.users_table.upsert_entity(entity=self._serialize(entity), mode=UpdateMode.REPLACE)
        return user_data

    def delete_user(self, user_id):
        self.users_table.delete_entity('USER', str(user_id))
        return True

    # --- Policy Methods ---
    def get_all_policies(self):
        entities = self.policies_table.query_entities("PartitionKey eq 'POLICY'")
        return [self._deserialize(e) for e in entities]

    def get_policy_by_id(self, policy_id):
        try:
            entity = self.policies_table.get_entity(partition_key='POLICY', row_key=str(policy_id))
            return self._deserialize(entity)
        except Exception:
            return None

    def save_policy(self, policy_data, username):
        user = self.get_user_by_username(username)
        policy_id = str(uuid.uuid4())
        policy_data.update({
            'id': policy_id, 'created_date': datetime.now().isoformat(),
            'created_by_id': user['id'] if user else 'unknown', 'status': 'pending_approval'
        })
        entity = {'PartitionKey': 'POLICY', 'RowKey': policy_id}
        entity.update(policy_data)
        self.policies_table.upsert_entity(entity=self._serialize(entity), mode=UpdateMode.REPLACE)
        self.log_audit(username, 'created', 'policy', policy_id, f"Policy '{policy_data.get('name')}' created.")
        return policy_data

    def update_policy(self, policy_id, updated_data, username):
        entity = self.policies_table.get_entity(partition_key='POLICY', row_key=str(policy_id))
        entity.update(updated_data)
        self.policies_table.upsert_entity(entity=self._serialize(entity), mode=UpdateMode.REPLACE)
        self.log_audit(username, 'updated', 'policy', policy_id, f"Policy '{updated_data.get('name', '')}' updated.")
        return True

    def delete_policy(self, policy_id):
        self.policies_table.delete_entity('POLICY', str(policy_id))
        return True

    # --- Category, Group, Operator Methods ---
    def get_all_categories(self):
        entities = self.categories_table.query_entities("PartitionKey eq 'CATEGORY'")
        return [self._deserialize(e) for e in entities]

    def save_all_categories(self, categories_list):
        for cat in categories_list:
            entity = {'PartitionKey': 'CATEGORY', 'RowKey': cat['category']}
            entity.update(cat)
            self.categories_table.upsert_entity(entity=self._serialize(entity), mode=UpdateMode.REPLACE)
        return True

    def get_all_groups(self):
        entities = self.groups_table.query_entities("PartitionKey eq 'GROUP'")
        return [self._deserialize(e) for e in entities]

    def save_group(self, group_data):
        group_id = group_data.get('id', str(uuid.uuid4()))
        entity = {'PartitionKey': 'GROUP', 'RowKey': group_id}
        entity.update(group_data)
        self.groups_table.upsert_entity(entity=self._serialize(entity), mode=UpdateMode.REPLACE)
        return group_data

    def delete_group(self, group_id):
        self.groups_table.delete_entity('GROUP', str(group_id))
        return True

    # ... and so on for get_group_by_id, get_group_by_name, update_group, etc.

    # --- User Category Role Methods ---
    def get_user_categories_for_all_users(self):
        entities = self.user_roles_table.query_entities("PartitionKey eq 'USER_ROLE'")
        return [self._deserialize(e) for e in entities]

    def get_user_categories(self, user_id):
        entities = self.user_roles_table.query_entities(f"user_id eq '{user_id}'")
        return [self._deserialize(e) for e in entities]

    def save_user_categories(self, user_id, category_roles):
        """Saves category roles using an efficient PartitionKey/RowKey strategy."""
        # This operation is more complex in a NoSQL database.
        # A common pattern is to delete all existing roles and then re-add the new set.
        try:
            existing_roles = self.user_roles_table.query_entities(f"PartitionKey eq '{user_id}'")
            for role in existing_roles:
                self.user_roles_table.delete_entity(role['PartitionKey'], role['RowKey'])
        except Exception as e:
            # It's okay if this fails (e.g., if no roles existed)
            current_app.logger.info(f"Could not delete old category roles for user {user_id} (this is often normal): {e}")

        # Add the new roles with the new, efficient key structure
        for role_entry in category_roles:
            entity = {
                'PartitionKey': str(user_id),       # Use user_id as the partition key
                'RowKey': role_entry['category'], # Use the category name as the unique row key
                'user_id': str(user_id),
                'category': role_entry['category'],
                'role': role_entry['role']
            }
            self.user_roles_table.create_entity(entity=entity)
        return True

    # --- Logging Methods ---
    def log_audit(self, username, action, entity_type, entity_id, description=""):
        entity = {
            'PartitionKey': action, # Partition by action type
            'RowKey': str(uuid.uuid4()),
            'timestamp': datetime.now().isoformat(), 'username': username,
            'entity_type': entity_type, 'entity_id': str(entity_id),
            'description': description
        }
        self.audit_log_table.create_entity(entity=entity)

    def log_decision(self, decision_object, payload, context):
        log_entry = {
            'PartitionKey': decision_object.get('finalDecision', 'UNKNOWN'), # Partition by decision
            'RowKey': decision_object.get('decisionId', str(uuid.uuid4())),
            'timestamp': datetime.now().isoformat(),
            'decision': decision_object.get('finalDecision'),
            'category': context.get('category', 'N/A'),
            'group': context.get('group', 'N/A'),
            'failed_policy_count': len(decision_object.get('failedPolicies', [])),
            'full_result': json.dumps(decision_object),
            'payload_hash': hashlib.sha256(json.dumps(payload, sort_keys=True).encode('utf-8')).hexdigest()
        }
        extracted_data = decision_object.get('extractedData', {})
        log_entry.update(extracted_data)
        self.decision_log_table.create_entity(entity=log_entry)

    def get_user_role_for_category(self, user_id, category_name):
        """Retrieves the role of a user for a specific category using a direct lookup."""
        try:
            # This is a very efficient lookup using PartitionKey (user_id) and RowKey (category_name)
            entity = self.user_roles_table.get_entity(partition_key=str(user_id), row_key=category_name)
            return entity.get('role')
        except Exception:
            return None # No specific role found for this category

    def get_audit_log(self):
        """Retrieves all entities from the auditlog table."""
        try:
            entities = self.audit_log_table.query_entities("") # Empty filter gets all entities
            return [self._deserialize(e) for e in entities]
        except Exception as e:
            # In case the table is empty or another error occurs
            current_app.logger.error(f"Could not read audit log from Azure: {e}")
            return []


###### Dashboard Methods ############
    def get_decision_log(self):
        """Reads the full decision log table from Azure."""
        try:
            entities = self.decision_log_table.query_entities("")
            return [self._deserialize(e) for e in entities]
        except Exception as e:
            current_app.logger.error(f"Could not read decision log from Azure: {e}")
            return []

    def get_policy_counts_by_status(self):
        """Counts policies and groups them by status by querying Azure Table Storage."""
        try:
            # Query only the 'status' column for efficiency
            entities = self.policies_table.query_entities("PartitionKey eq 'POLICY'", select=["status"])
            status_list = [e['status'] for e in entities]
            return Counter(status_list)
        except Exception as e:
            current_app.logger.error(f"Could not get policy counts from Azure: {e}")
            return {}

    def get_stale_pending_policies(self, limit=5):
        """Finds the oldest policies still in 'pending_approval' from Azure."""
        try:
            # Query all policies pending approval
            entities = self.policies_table.query_entities("status eq 'pending_approval'")
            deserialized_policies = [self._deserialize(e) for e in entities]
            # Sort in the application memory by date
            sorted_policies = sorted(deserialized_policies, key=lambda p: p.get('created_date', ''))
            return sorted_policies[:limit]
        except Exception as e:
            current_app.logger.error(f"Could not get stale policies from Azure: {e}")
            return []

    def get_most_failed_policies(self, limit=5):
        """Counts which policies fail most often from the decision log in Azure."""
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

        # Sort by date and separate into lists for Chart.js
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

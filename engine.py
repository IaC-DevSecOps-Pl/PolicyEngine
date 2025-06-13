import json
import uuid
# The old 'from utils import...' is now removed.

# get_nested_value and evaluate_rule functions do not need to change.
# Paste your existing, correct versions of those two functions here.
def get_nested_value(data_dict, key_string):
    """Safely gets a value from a nested dictionary using dot notation (e.g., 'a.b.c')."""
    if not key_string or not isinstance(key_string, str):
        return None
    keys = key_string.split('.')
    value = data_dict
    for key in keys:
        if isinstance(value, dict) and key in value:
            value = value[key]
        else:
            return None
    return value

def evaluate_rule(rule, data_payload):
    """Evaluates a single policy rule against the data payload. Returns True if the condition passes."""
    # ... (This function should be the last correct version we created) ...
    # It does not need any changes.
    field = rule.get('field')
    operator = rule.get('operator')
    policy_value = rule.get('value')
    data_value = get_nested_value(data_payload, field)
    if data_value is None: return False, f"Field '{field}' not found in payload."
    fail_reason = f"Field '{field}' with value '{data_value}' failed rule '{operator} {policy_value}'."
    try:
        data_num, policy_num = float(data_value), float(policy_value)
        if operator in ['equals', '='] and data_num == policy_num: return True, ""
        if operator in ['greater_than', '>'] and data_num > policy_num: return True, ""
        if operator in ['less_than', '<'] and data_num < policy_num: return True, ""
        if operator in ['greater_than_or_equal_to', '>='] and data_num >= policy_num: return True, ""
        if operator in ['less_than_or_equal_to', '<='] and data_num <= policy_num: return True, ""
    except (ValueError, TypeError): pass
    data_str = str(data_value)
    if operator in ['equals', '='] and data_str == policy_value: return True, ""
    if isinstance(policy_value, list):
        if operator == 'in' and data_str in policy_value: return True, ""
        if operator == 'not in' and data_str not in policy_value: return True, ""
    return False, fail_reason


# Replace your run_decision_engine function with this new version
def run_decision_engine(data_payload, context, repo):
    """
    Runs the decision engine using the provided repository and returns a rich response object.
    """
    decision_id = str(uuid.uuid4())
    category_name = context.get('category')

    # Dynamically extract key data based on the category's configuration
    extracted_data = {}
    if category_name:
        category_details = repo.get_category_by_name(category_name)
        if category_details and category_details.get('logged_fields'):
            logged_fields_map = category_details.get('logged_fields', {})
            for log_key, payload_key in logged_fields_map.items():
                value = get_nested_value(data_payload, payload_key)
                extracted_data[log_key] = value if value is not None else 'N/A'

    # Filter for applicable policies based on the context
    group_context = context.get('group')
    statuses_to_check = context.get('statuses', ['enabled'])
    applicable_policies = [p for p in repo.get_all_policies() if p.get('status') in statuses_to_check]
    if group_context:
        applicable_policies = [p for p in applicable_policies if group_context in p.get('groups', [])]
    if category_name:
        applicable_policies = [p for p in applicable_policies if p.get('category') == category_name]

    # --- This is the complete, unabbreviated response dictionary ---
    response = {
        "decisionId": decision_id,
        "finalDecision": "Not Applicable",
        "evaluationContext": context,
        "extractedData": extracted_data,
        "reason": "No applicable policies found for the given context.",
        "passedPolicies": [],
        "failedPolicies": []
    }

    if not applicable_policies:
        return response

    # If policies are found, run the evaluation
    response['finalDecision'] = "Pass"  # Default to Pass
    for policy in applicable_policies:
        policy_passed = False
        rule_groups = policy.get('rule_definition', {}).get('rule_groups', [])

        if not rule_groups:
            policy_passed = False
        else:
            # A policy passes if ANY of its rule groups pass (OR logic)
            for group in rule_groups:
                group_passed = True
                rules = group.get('rules', [])
                # A group passes only if ALL of its rules pass (AND logic)
                for rule in rules:
                    if not rule.get('field') or not rule.get('operator'):
                        group_passed = False
                        break

                    # Note: The original evaluate_rule returned a tuple (is_pass, reason)
                    # We only need the boolean result here.
                    is_pass, reason_text = evaluate_rule(rule, data_payload)

                    if not is_pass:
                        group_passed = False
                        break

                if group_passed:
                    policy_passed = True
                    break

        if policy_passed:
            response['passedPolicies'].append(policy.get('name'))
        else:
            response['finalDecision'] = "Fail"
            # We can use the 'reason_text' from the last failed rule for better feedback
            reason_for_failure = reason_text if 'reason_text' in locals() else "No rule groups were satisfied."
            response['failedPolicies'].append({"name": policy.get('name'), "reason": reason_for_failure})

    response['reason'] = f"Evaluation complete. {len(response['failedPolicies'])} policies failed."
    return response

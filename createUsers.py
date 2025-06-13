import uuid
from werkzeug.security import generate_password_hash
import os

# Define user data with groups
users_data = [
    {"username": "admin", "global_role": "admin", "password": "admin", "groups": ""}, # Admin typically doesn't need groups for permissions
    {"username": "creator", "global_role": "creator", "password": "creator", "groups": "marketing_team"}, # Example: creator in a specific group
    {"username": "approver", "global_role": "approver", "password": "approver", "groups": "marketing_team,legal_team"}, # Approver in multiple groups
    {"username": "viewer", "global_role": "viewer", "password": "viewer", "groups": "marketing_team"}, # Viewer in a specific group
]

csv_lines = ["id,username,password,role,groups,global_role"]

for user in users_data:
    user_id = str(uuid.uuid4())
    username = user["username"]
    plain_password = user["password"]
    hashed_password = generate_password_hash(plain_password, method='scrypt')
    global_role = user["global_role"]
    groups = user["groups"] # Use the defined groups from users_data

    # For simplicity, setting 'role' to match 'global_role' for now
    role = global_role

    csv_lines.append(f"{user_id},{username},{hashed_password},{role},{groups},{global_role}")

# Define the path for the users.csv file
output_dir = 'tables'
output_file = os.path.join(output_dir, 'users.csv')

# Ensure the output directory exists
os.makedirs(output_dir, exist_ok=True)

# Write to the CSV file
with open(output_file, 'w') as f:
    f.write("\n".join(csv_lines))

print(f"'{output_file}' has been created/recreated successfully.")
print("\nHere's the content of the generated users.csv:")
for line in csv_lines:
    print(line)

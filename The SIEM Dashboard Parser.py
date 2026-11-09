##We are going to process and analyze logs from a system.
##We are going to automate the workflow, using nested dictionaries and mimic structure of JSON payloads.
##Task 1: Identify attack signatures by iterating through nested data structures.
##Task 2: Safely handle log entries without crashing
##Task 3: Enrich existing datasets with new security compliance flags.
##Understand how to use .items(), .values(), .get() to solve challenges.

siem_logs = {
    "user_001": {"username": "jdoe", "status": "active", "failed_attempts": 1},
    "user_002": {"username": "rsmith", "status": "locked", "failed_attempts": 15},
    "user_003": {"username": "tjones", "status": "active", "failed_attempts": 0},
    "user_004": {"username": "bwayne", "status": "active"}
    ##Missing attempt key, we will handle this
}

#Create a list for high risk users, then if the failed_attempts
#is over the limit, add the user to that list
high_risk_users = []

for user_id in siem_logs.keys():
    print(user_id)

#Task 1: find high risk users and lock their accounts
for user_id, data in siem_logs.items():
    #.get() returns 0 if the key is missing, so user_004 won't crash
    failed_count = data.get("failed_attempts", 0)
    if failed_count > 5:
        high_risk_users.append(user_id)
        data["status"] = "locked"
        print(f"[CRITICAL] Account locked for user: {data['username']}")

print(high_risk_users)

#Task 2: add the 2FA flag to every user
for data in siem_logs.values():
    data["2FA_enabled"] = True

#Task 3: final audit
for user_id, details in siem_logs.items():
    username = details["username"]
    status = details["status"]
    mfa = details["2FA_enabled"]
    print(f"Audit Complete - ID: {user_id} | Username: {username} | Status: {status} | 2FA: {mfa}")

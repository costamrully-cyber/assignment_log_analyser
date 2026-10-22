#Augustine
#assignment 1

#part1 login ananlyser 

max_fails = 3
events = [
    ("08:01", "admin", "203.0.113.7", "FAIL"),
    ("08:01", "admin", "203.0.113.7", "FAIL"),
    ("08:02", "admin", "203.0.113.7", "FAIL"),
    ("08:02", "brian", "10.0.0.5", "OK"),
    ("08:03", "admin", "203.0.113.7", "FAIL"),
    ("08:05", "amina", "203.0.113.15", "FAIL"),
    ("08:05", "amina", "203.0.113.15", "OK"),
    ("08:07", "admin", "203.0.113.7", "FAIL"),
    ("08:09", "admin", "203.0.113.7", "OK"),
    ("08:15", "amina", "198.51.100.21", "FAIL"),
    ("08:15", "brian", "198.51.100.21", "FAIL"),
    ("08:16", "cynthia", "198.51.100.21", "FAIL"),
    ("08:16", "root", "198.51.100.21", "FAIL"),
    ("08:20", "cynthia", "10.0.0.8", "OK"),
    ("08:31", "dan", "10.0.0.12", "FAIL"),
    ("08:32", "dan", "10.0.0.12", "FAIL"),
    ("08:33", "dan", "10.0.0.12", "OK"),
    ("09:02", "root", "192.0.2.33", "FAIL"),
    ("09:02", "root", "192.0.2.33", "FAIL"),
    ("09:03", "root", "192.0.2.33", "FAIL"),
]

print("Number of records:", len(events))
print("First record:", events[0])
print("Last record:", events[-1])

#part2 number of fail login attempts per user
failed = 0
success = 0
for time, username, ip, status in events:
    if status == "FAIL":
        failed = failed + 1
    else:
        success = success + 1

failure_rate = failed / (failed + success) * 100

print ("failed login attempts: ", failed)
print ("successfull login attempts: ", success)
print ("failed rate: ", failure_rate, "%")

#part3 who connected

unique_ips = []
for time, username, ip, status in events:
    if ip not in unique_ips:
        unique_ips.append(ip)

print("Unique IPs:", unique_ips)
print("Number of unique IPs:", len(unique_ips))

#Part 4: Rank the attackers
ranking = []

for ip in unique_ips:
    fail_count= 0
    for time,username,event_ip,status in events:
         if event_ip == ip and status == "FAIL":
            fail_count = fail_count + 1
    ranking.append((fail_count, ip))

ranking.sort(reverse=True)

print("Full ranking (highest first):")
for fail_count, ip in ranking:
    print(f"{ip}: {fail_count} failed logins")
    print("Top 3:")
for fail_count, ip in ranking[:3]:
    print(f"{ip}: {fail_count}")

#part5  Build the blocklist

blocklist = []

for fail_count, ip in ranking:
    if fail_count >= max_fails:
        blocklist.append(ip)
        print(f"BLOCK {ip} ({fail_count} failed logins)")

print("Number of blocked ips: ", len(blocklist))

#parts6 was anyone broken into?

compromised = 0

for time, username, ip, status in events:
    if status == "OK" and ip in blocklist:
        print(f"ALERT: account {username} accessed from {ip} at {time}")
        compromised = compromised + 1

if compromised == 0:
    print("No compromised accounts found.")

#part 7 Detect password spraying

for ip in unique_ips:
    usernames_tried = []
    for time, username, event_ip, status in events:
        if event_ip == ip and username not in usernames_tried:
            usernames_tried.append(username)
    if len(usernames_tried) >= 3:
        print(f"SPRAY ALERT: {ip} tried {len(usernames_tried)} usernames: {usernames_tried}")

#Part 8: Analyst lookup tool
while True:
    query = input("Enter an IP address (or 'done' to quit): ")
    if query == "done":
        break

    found = 0
    for time, username, ip, status in events:
        if ip == query:
            print(f"{time}  {username}  {ip}  {status}")
            found = found + 1

    if found == 0:
        print("No records for that IP address")
    else:
        print(f"{found} record found")

#Bonus: Most targeted accounts
unique_users = []
for time, username, ip, status in events:
    if username not in unique_users:
        unique_users.append(username)
user_ranking = []
for user in unique_users:
    fail_count = 0
    for time, username, event_ip, status in events:
        if username == user and status == "FAIL":
            fail_count = fail_count + 1
    user_ranking.append((fail_count, user))
    user_ranking.sort(reverse=True)

for fail_count, user in user_ranking:
    print(f"{user}: {fail_count} failed logins")

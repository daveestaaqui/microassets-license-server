import os
import sys
sys.exit(0)
import json
import smtplib
from email.message import EmailMessage
import time
import email_templates

USERS_DB_FILE = os.environ.get("USERS_DB_PATH", "/app/data/users.json")
DRIP_STATE_FILE = os.environ.get("DRIP_STATE_PATH", "/app/data/drip_state.json")

# Ensure atomic file writing function is available, but falling back to simple write for the script
def save_json(filepath, data):
    dir_path = os.path.dirname(filepath) or '.'
    os.makedirs(dir_path, exist_ok=True)
    with open(filepath, 'w') as f:
        json.dump(data, f, indent=2)

def load_json(filepath):
    if os.path.exists(filepath):
        try:
            with open(filepath, 'r') as f:
                return json.load(f)
        except Exception:
            pass
    return {}

SENDER_EMAIL = os.environ.get("SMTP_USER", "sandwichfitness@gmail.com")
SENDER_PASSWORD = os.environ.get("SMTP_PASS", "nxgfaiebqpmobhkp")

def send_email(to_email, subject, body):
    msg = EmailMessage()
    msg.set_content(body)
    msg["Subject"] = subject
    msg["From"] = f"SporlyWorks Team <{SENDER_EMAIL}>"
    msg["To"] = to_email

    try:
        server = smtplib.SMTP_SSL("smtp.gmail.com", 465)
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.send_message(msg)
        server.quit()
        return True
    except Exception as e:
        print(f"Failed to send email to {to_email}: {e}")
        return False

def run_drip_campaign():
    users = load_json(USERS_DB_FILE)
    drip_state = load_json(DRIP_STATE_FILE)
    now = time.time()
    
    # 1 day = 86400 seconds
    DAY = 86400

    emails_sent_count = 0

    for user_id, user_data in users.items():
        if user_data.get('tier') == 'Pro Suite':
            continue # Don't send onboarding/upgrade emails to Pro users

        email = user_data.get('email')
        created_at = user_data.get('created_at', now)
        elapsed_seconds = now - created_at
        days_active = elapsed_seconds / DAY

        user_state = drip_state.get(user_id, {})

        # Check Day 0
        if not user_state.get('day_0_sent'):
            if send_email(email, email_templates.DAY_0_SUBJECT, email_templates.DAY_0_BODY):
                user_state['day_0_sent'] = True
                emails_sent_count += 1
                
        # Check Day 1
        elif days_active >= 1 and not user_state.get('day_1_sent'):
            if send_email(email, email_templates.DAY_1_SUBJECT, email_templates.DAY_1_BODY):
                user_state['day_1_sent'] = True
                emails_sent_count += 1
                
        # Check Day 2
        elif days_active >= 2 and not user_state.get('day_2_sent'):
            if send_email(email, email_templates.DAY_2_SUBJECT, email_templates.DAY_2_BODY):
                user_state['day_2_sent'] = True
                emails_sent_count += 1
                
        # Check Day 3
        elif days_active >= 3 and not user_state.get('day_3_sent'):
            if send_email(email, email_templates.DAY_3_SUBJECT, email_templates.DAY_3_BODY):
                user_state['day_3_sent'] = True
                emails_sent_count += 1

        drip_state[user_id] = user_state

    if emails_sent_count > 0:
        save_json(DRIP_STATE_FILE, drip_state)
        print(f"Drip Campaign completed successfully. Sent {emails_sent_count} emails.")
    else:
        print("Drip Campaign ran. No new emails to send.")

if __name__ == "__main__":
    print("Starting Autonomous Drip Campaign Agent...")
    run_drip_campaign()

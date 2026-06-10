from flask import Flask, render_template, request, redirect, session, Response
import mysql.connector
from werkzeug.security import check_password_hash
import os
import secrets
from datetime import datetime
from dotenv import load_dotenv

from gmail_service import send_gmail_api

# ---------------- ENV ----------------
load_dotenv(override=True)

app = Flask(__name__)
app.secret_key = "secret123"

print("RUNNING app.py FROM:", __file__)

# ---------------- DB ----------------
db = mysql.connector.connect(
    host="localhost",
    user="root",
    password="user1",
    database="phishing_system"
)
cursor = db.cursor(dictionary=True)

PUBLIC_BASE_URL = (os.getenv("PUBLIC_BASE_URL") or "http://127.0.0.1:5000").rstrip("/")
print("PUBLIC URL =", PUBLIC_BASE_URL)


def allowed_set():
    return set(
        e.strip().lower()
        for e in (os.getenv("ALLOWED_RECIPIENTS") or "").split(",")
        if e.strip()
    )


# ---------------- SIMPLE CHECK LOGIC ----------------
def check_phishing(content, url):
    keywords = ['verify', 'login', 'urgent', 'click', 'free', 'update', 'account']
    score = 0
    for word in keywords:
        if word in content.lower():
            score += 1
    if url:
        if "http://" in url or len(url) > 50 or "@" in url:
            score += 2
    if score >= 3:
        return "Phishing"
    elif score == 2:
        return "Suspicious"
    else:
        return "Safe"


# =========================================================
# ✅ OPEN TRACKING PIXEL (REAL OPENED COUNT)
# =========================================================
@app.route('/t/<token>.png')
def track_open(token):
    cursor.execute("SELECT opened_at FROM campaign_recipients WHERE token=%s", (token,))
    rec = cursor.fetchone()

    if rec and rec.get("opened_at") is None:
        cursor.execute(
            "UPDATE campaign_recipients SET opened_at=%s WHERE token=%s",
            (datetime.now(), token)
        )
        db.commit()

    # 1x1 transparent PNG
    pixel = (
        b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
        b"\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\nIDATx\x9cc`\x00"
        b"\x00\x00\x02\x00\x01\xe2!\xbc3\x00\x00\x00\x00IEND\xaeB`\x82"
    )
    return Response(pixel, mimetype="image/png")


# ---------------- INDEX ----------------
@app.route('/')
def index():
    return render_template('index.html')


# ---------------- GMAIL TEST ----------------
@app.route("/gmail-test")
def gmail_test():
    if not os.path.exists("credentials.json"):
        return "Missing credentials.json (put it next to app.py)", 400

    allowed = allowed_set()
    test_to = "hybecompany23@gmail.com"

    if allowed and test_to.lower() not in allowed:
        return "Recipient not in ALLOWED_RECIPIENTS", 400

    send_gmail_api(
        to_email=test_to,
        subject="Gmail API Test ✅",
        html_body="<h2>Working!</h2><p>Sent via Gmail OAuth API.</p>"
    )
    return "Sent via Gmail API! Check Inbox/Spam."


# ---------------- ADMIN LOGIN ----------------
@app.route('/admin-login', methods=['POST'])
def admin_login():
    email = request.form['admin_email']
    password = request.form['admin_password']

    cursor.execute("SELECT * FROM admin WHERE email=%s", (email,))
    admin = cursor.fetchone()

    if admin and check_password_hash(admin['password'], password):
        session['admin'] = email
        return redirect('/admin')

    return "Invalid admin credentials!"


# ---------------- EMPLOYEE LOGIN ----------------
@app.route('/employee-login', methods=['POST'])
def employee_login():
    email = request.form['employee_email']
    password = request.form['employee_password']

    cursor.execute("SELECT * FROM employees WHERE email=%s", (email,))
    emp = cursor.fetchone()

    if emp and password == emp['password']:
        session['employee_email'] = email
        return redirect('/employee')

    return "Invalid employee credentials!"


# ---------------- EMPLOYEE DASHBOARD ----------------
@app.route('/employee')
def employee_dashboard():
    if 'employee_email' not in session:
        return redirect('/')
    return render_template('employee_dashboard.html')


# ---------------- EMPLOYEE REGISTRATION ----------------
@app.route('/register', methods=['POST'])
def register():
    name = request.form['name']
    email = request.form['email']
    password = request.form['password']

    cursor.execute("SELECT * FROM employees WHERE email=%s", (email,))
    existing = cursor.fetchone()
    if existing:
        return "Employee with this email already exists!"

    cursor.execute(
        "INSERT INTO employees (name, email, password) VALUES (%s, %s, %s)",
        (name, email, password)
    )
    db.commit()
    return redirect('/?registered=1')


# =========================================================
# ✅ ADMIN DASHBOARD (REAL COUNTS + LAST 5 ACTIVITY)
# =========================================================
@app.route('/admin')
def admin_dashboard():
    if 'admin' not in session:
        return redirect('/')

    cursor.execute("SELECT COUNT(*) AS c FROM campaign_recipients")
    emails_sent = cursor.fetchone()['c'] or 0

    cursor.execute("SELECT COUNT(*) AS c FROM campaign_recipients WHERE opened_at IS NOT NULL")
    emails_opened = cursor.fetchone()['c'] or 0

    cursor.execute("SELECT COUNT(*) AS c FROM campaign_recipients WHERE clicked_at IS NOT NULL")
    links_clicked = cursor.fetchone()['c'] or 0

    cursor.execute("SELECT COUNT(*) AS c FROM campaign_recipients WHERE password_entered = 1")
    password_entered = cursor.fetchone()['c'] or 0

    campaign_started = emails_sent > 0

    sent_percent = 100 if emails_sent else 0
    opened_percent = int((emails_opened / emails_sent) * 100) if emails_sent else 0
    clicked_percent = int((links_clicked / emails_sent) * 100) if emails_sent else 0
    password_percent = int((password_entered / emails_sent) * 100) if emails_sent else 0

    # ✅ show only LAST 5 activities in dashboard table
    cursor.execute("""
        SELECT 
            cr.employee_email AS email,
            CASE
              WHEN cr.password_entered = 1 THEN 'Password Entered'
              WHEN cr.clicked_at IS NOT NULL THEN 'Link Clicked'
              WHEN cr.opened_at IS NOT NULL THEN 'Email Opened'
              ELSE 'Sent'
            END AS status,
            COALESCE(cr.password_entered_at, cr.clicked_at, cr.opened_at, cr.created_at) AS timestamp
        FROM campaign_recipients cr
        ORDER BY timestamp DESC
        LIMIT 5
    """)
    records = cursor.fetchall()

    return render_template(
        'admin_dashboard.html',
        campaign_started=campaign_started,

        emails_sent=emails_sent,
        emails_opened=emails_opened,
        links_clicked=links_clicked,
        credentials_entered=password_entered,

        sent_percent=sent_percent,
        opened_percent=opened_percent,
        clicked_percent=clicked_percent,
        password_percent=password_percent,

        records=records
    )


# =========================================================
# ✅ FULL RECORDS PAGE (ALL ACTIVITY + TEMPLATE + CAMPAIGN)
# =========================================================
@app.route('/records-activity')
def records_activity():
    if 'admin' not in session:
        return redirect('/')

    cursor.execute("""
        SELECT 
            cr.employee_email AS email,
            c.campaign_name AS campaign_name,
            t.title AS template_title,
            CASE
              WHEN cr.password_entered = 1 THEN 'Password Entered'
              WHEN cr.clicked_at IS NOT NULL THEN 'Link Clicked'
              WHEN cr.opened_at IS NOT NULL THEN 'Email Opened'
              ELSE 'Sent'
            END AS status,
            COALESCE(cr.password_entered_at, cr.clicked_at, cr.opened_at, cr.created_at) AS timestamp
        FROM campaign_recipients cr
        LEFT JOIN campaigns c ON c.id = cr.campaign_id
        LEFT JOIN templates t ON t.id = c.template_id
        ORDER BY timestamp DESC
    """)
    rows = cursor.fetchall()

    return render_template("records_activity.html", records=rows)


# ---------------- CHECK EMAIL ----------------
@app.route('/check', methods=['GET', 'POST'])
def check_email():
    if 'employee_email' not in session:
        return redirect('/')

    result = None
    if request.method == 'POST':
        source = request.form['source']
        content = request.form['content']
        url = request.form['url']

        result = check_phishing(content, url)

        cursor.execute("""
            INSERT INTO email_checks
            (employee_email, email_source, email_content, url_checked, system_result, employee_decision)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (session['employee_email'], source, content, url, result, "Checked"))
        db.commit()

    return render_template('check_email.html', result=result)


# ---------------- TEMPLATES ----------------
@app.route('/templates', methods=['GET'])
def templates_page():
    if 'admin' not in session:
        return redirect('/')

    cursor.execute("SELECT * FROM templates ORDER BY id DESC")
    templates = cursor.fetchall()
    return render_template('templates.html', templates=templates)


@app.route('/create-template', methods=['POST'])
def create_template():
    if 'admin' not in session:
        return redirect('/')

    title = request.form.get('title', '').strip()
    category = request.form.get('category', 'General').strip()
    subject = request.form.get('subject', '').strip()
    body = request.form.get('body', '').strip()

    if not title or not subject or not body:
        return "All fields are required!"

    cursor.execute(
        "INSERT INTO templates (title, category, subject, body) VALUES (%s, %s, %s, %s)",
        (title, category, subject, body)
    )
    db.commit()
    return redirect('/templates')


@app.route('/delete-template/<int:template_id>', methods=['POST'])
def delete_template(template_id):
    if 'admin' not in session:
        return redirect('/')

    cursor.execute("DELETE FROM templates WHERE id=%s", (template_id,))
    db.commit()
    return redirect('/templates')


# =========================================================
# ✅ CREATE CAMPAIGN + SEND EMAIL (REAL LINK + PIXEL)
# =========================================================
@app.route('/send-email', methods=['GET', 'POST'])
def send_email():
    if 'admin' not in session:
        return redirect('/')

    cursor.execute("SELECT * FROM templates ORDER BY id DESC")
    templates = cursor.fetchall()

    selected_template = None
    tid = request.args.get('template_id')
    if tid:
        cursor.execute("SELECT * FROM templates WHERE id=%s", (tid,))
        selected_template = cursor.fetchone()

    if request.method == 'GET':
        return render_template('send_email.html', templates=templates, selected_template=selected_template)

    # -------- POST --------
    campaign_name = request.form['campaign_name']
    subject_line = request.form['subject_line']
    template_id = request.form['template_id']
    recipients_raw = request.form['recipients']

    sender_name = request.form.get('sender_name', '').strip()
    sender_email_form = request.form.get('sender_email', '').strip()

    cursor.execute("SELECT * FROM templates WHERE id=%s", (template_id,))
    template = cursor.fetchone()
    if not template:
        return "Template not found."

    cursor.execute("""
        INSERT INTO campaigns (campaign_name, template_id, sender_name, sender_email, status, created_at)
        VALUES (%s, %s, %s, %s, 'Running', %s)
    """, (campaign_name, template_id, sender_name, sender_email_form, datetime.now()))
    db.commit()
    campaign_id = cursor.lastrowid

    recipients = [r.strip() for r in recipients_raw.replace("\n", ",").split(",") if r.strip()]
    allowed = allowed_set()

    for email in recipients:
        if allowed and email.lower() not in allowed:
            continue

        token = secrets.token_urlsafe(24)

        cursor.execute("""
            INSERT INTO campaign_recipients (campaign_id, employee_email, token, created_at)
            VALUES (%s, %s, %s, %s)
        """, (campaign_id, email, token, datetime.now()))

        # ✅ click link goes to /click
        click_url = f"{PUBLIC_BASE_URL}/l/{token}/click"

        # ✅ replace placeholder
        html_body = (template['body'] or "")
        html_body = html_body.replace("{{ landing_url }}", click_url).replace("{{landing_url}}", click_url)

        # ✅ append tracking pixel
        pixel_url = f"{PUBLIC_BASE_URL}/t/{token}.png"
        html_body += f'<img src="{pixel_url}" width="1" height="1" style="display:none" alt="">'

        send_gmail_api(to_email=email, subject=subject_line, html_body=html_body)

    db.commit()
    return redirect(f"/campaign-links/{campaign_id}")


# ---------------- SHOW LINKS ----------------
@app.route('/campaign-links/<int:campaign_id>')
def campaign_links(campaign_id):
    if 'admin' not in session:
        return redirect('/')

    cursor.execute("SELECT * FROM campaigns WHERE id=%s", (campaign_id,))
    camp = cursor.fetchone()

    cursor.execute("""
        SELECT employee_email, token
        FROM campaign_recipients
        WHERE campaign_id=%s
        ORDER BY id DESC
    """, (campaign_id,))
    recs = cursor.fetchall()

    return render_template("campaign_links.html", camp=camp, recs=recs, base_url=PUBLIC_BASE_URL)


# =========================================================
# ✅ FLOW PAGES
# =========================================================
@app.route('/l/<token>')
def landing(token):
    cursor.execute("SELECT * FROM campaign_recipients WHERE token=%s", (token,))
    rec = cursor.fetchone()
    if not rec:
        return "Invalid link."
    return render_template("landing.html", token=token)


@app.route('/l/<token>/click')
def landing_click(token):
    cursor.execute("SELECT * FROM campaign_recipients WHERE token=%s", (token,))
    rec = cursor.fetchone()
    if not rec:
        return "Invalid link."

    if rec.get('clicked_at') is None:
        cursor.execute(
            "UPDATE campaign_recipients SET clicked_at=%s WHERE token=%s",
            (datetime.now(), token)
        )
        db.commit()

    return render_template("landing.html", token=token)


@app.route('/l/<token>/form-submit', methods=['POST'])
def form_submit(token):
    cursor.execute("SELECT * FROM campaign_recipients WHERE token=%s", (token,))
    rec = cursor.fetchone()
    if not rec:
        return "Invalid link."

    return render_template("error_then_confirm.html", token=token)


@app.route('/l/<token>/submit', methods=['POST'])
def landing_submit(token):
    cursor.execute("SELECT * FROM campaign_recipients WHERE token=%s", (token,))
    rec = cursor.fetchone()
    if not rec:
        return "Invalid link."

    if rec['password_entered'] == 0:
        cursor.execute("""
            UPDATE campaign_recipients
            SET password_entered = 1,
                password_entered_at = %s
            WHERE token = %s
        """, (datetime.now(), token))
        db.commit()

    return render_template("awareness_result.html")


# ---------------- CAMPAIGNS (LIST ALL) ----------------
@app.route('/admin/campaigns')
def campaigns():
    if 'admin' not in session:
        return redirect('/')

    cursor.execute("""
        SELECT c.id, c.campaign_name, c.status, c.created_at,
               t.title AS template_title
        FROM campaigns c
        LEFT JOIN templates t ON t.id = c.template_id
        ORDER BY c.id DESC
    """)
    campaigns_list = cursor.fetchall()

    return render_template("campaigns.html", campaigns=campaigns_list)


# ---------------- LOGOUT ----------------
@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')


if __name__ == '__main__':
    app.run(debug=True, use_reloader=False)

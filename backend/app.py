from flask import Flask, request, jsonify
from flask_cors import CORS
import mysql.connector
from werkzeug.security import generate_password_hash, check_password_hash
import re
import os
import random
import csv
from datetime import datetime
import uuid
from .scam_detection import analyze_job_risk, SCAM_RULES

def generate_public_id(name):
    short = uuid.uuid4().hex[:6]
    return f"{name.upper().replace(' ', '')}-{short}"



app = Flask(__name__)
# Allow requests from your HTML pages (including different ports)
CORS(app)

# Database configuration
DB_CONFIG = {
    'host': os.getenv('MYSQL_HOST', 'localhost'),
    'port': int(os.getenv('MYSQL_PORT', '3306')),
    'user': os.getenv('MYSQL_USER', 'agile_user'),
    'password': os.getenv('MYSQL_PASSWORD', 'Agile@12345'),
    'database': os.getenv('MYSQL_DATABASE', 'agile_project'),
}

HARDCODED_ADMIN_ACCOUNTS = {
    'priya@admin.com': {
        'id': 'admin-priya',
        'full_name': 'Priya Kumari',
        'email': 'priya@admin.com',
        'password': 'project',
        'role': 'Admin',
    },
    'isha@admin.com': {
        'id': 'admin-isha',
        'full_name': 'Isha Suraj',
        'email': 'isha@admin.com',
        'password': 'project',
        'role': 'Admin',
    },
}

KNOWN_SCAMS_CSV_PATH = os.getenv(
    'KNOWN_SCAMS_CSV_PATH',
    os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'data', 'fake_job_postings.csv')
)

def get_db_connection():
    """Create and return a database connection"""
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        return conn, None
    except mysql.connector.Error as err:
        print(f"Database connection error: {err}")
        return None, str(err)


def get_request_data():
    if request.is_json:
        return request.get_json(silent=True) or {}
    return request.form.to_dict()


def column_exists(cursor, table_name, column_name):
    cursor.execute(f"SHOW COLUMNS FROM {table_name} LIKE %s", (column_name,))
    return cursor.fetchone() is not None


def table_exists(cursor, table_name):
    cursor.execute("SHOW TABLES LIKE %s", (table_name,))
    return cursor.fetchone() is not None


def ensure_scam_reports_table():
    conn = None
    cursor = None
    try:
        conn, conn_err = get_db_connection()
        if not conn:
            return False, conn_err

        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scam_reports (
                id INT AUTO_INCREMENT PRIMARY KEY,
                job_title VARCHAR(255) NOT NULL,
                company_name VARCHAR(255) NOT NULL,
                description TEXT NOT NULL,
                reported_by VARCHAR(255) NOT NULL,
                risk_score INT DEFAULT 0,
                risk_level VARCHAR(20) DEFAULT 'Low',
                is_flagged BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        if not column_exists(cursor, 'scam_reports', 'risk_score'):
            cursor.execute("ALTER TABLE scam_reports ADD COLUMN risk_score INT DEFAULT 0")
        if not column_exists(cursor, 'scam_reports', 'risk_level'):
            cursor.execute("ALTER TABLE scam_reports ADD COLUMN risk_level VARCHAR(20) DEFAULT 'Low'")
        if not column_exists(cursor, 'scam_reports', 'is_flagged'):
            cursor.execute("ALTER TABLE scam_reports ADD COLUMN is_flagged BOOLEAN DEFAULT FALSE")

        conn.commit()
        return True, None
    except mysql.connector.Error as err:
        return False, str(err)
    finally:
        try:
            if cursor is not None:
                cursor.close()
        except Exception:
            pass
        try:
            if conn is not None:
                conn.close()
        except Exception:
            pass


def ensure_recruiter_verifications_table():
    conn = None
    cursor = None
    try:
        conn, conn_err = get_db_connection()
        if not conn:
            return False, conn_err

        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS recruiter_verifications (
                id INT AUTO_INCREMENT PRIMARY KEY,
                job_title VARCHAR(255) NOT NULL,
                company_name VARCHAR(255) NOT NULL,
                location VARCHAR(255) NOT NULL,
                description TEXT NOT NULL,
                recruiter_email VARCHAR(255) NOT NULL,
                risk_score INT DEFAULT 0,
                risk_level VARCHAR(20) DEFAULT 'Low',
                status ENUM('pending', 'verified', 'rejected') DEFAULT 'pending',
                verification_id VARCHAR(50) UNIQUE DEFAULT NULL,
                submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                verified_at TIMESTAMP NULL DEFAULT NULL
            )
        """)

        if not column_exists(cursor, 'recruiter_verifications', 'verification_id'):
            cursor.execute(
                "ALTER TABLE recruiter_verifications ADD COLUMN verification_id VARCHAR(50) UNIQUE DEFAULT NULL"
            )
        if not column_exists(cursor, 'recruiter_verifications', 'submitted_at'):
            cursor.execute(
                "ALTER TABLE recruiter_verifications ADD COLUMN submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP"
            )
        if not column_exists(cursor, 'recruiter_verifications', 'verified_at'):
            cursor.execute(
                "ALTER TABLE recruiter_verifications ADD COLUMN verified_at TIMESTAMP NULL DEFAULT NULL"
            )
        if not column_exists(cursor, 'recruiter_verifications', 'risk_score'):
            cursor.execute(
                "ALTER TABLE recruiter_verifications ADD COLUMN risk_score INT DEFAULT 0"
            )
        if not column_exists(cursor, 'recruiter_verifications', 'risk_level'):
            cursor.execute(
                "ALTER TABLE recruiter_verifications ADD COLUMN risk_level VARCHAR(20) DEFAULT 'Low'"
            )

        conn.commit()
        return True, None
    except mysql.connector.Error as err:
        return False, str(err)
    finally:
        try:
            if cursor is not None:
                cursor.close()
        except Exception:
            pass
        try:
            if conn is not None:
                conn.close()
        except Exception:
            pass


def ensure_users_admin_columns():
    conn = None
    cursor = None
    try:
        conn, conn_err = get_db_connection()
        if not conn:
            return False, conn_err

        cursor = conn.cursor()
        if not column_exists(cursor, 'users', 'status'):
            cursor.execute(
                "ALTER TABLE users ADD COLUMN status ENUM('active', 'blocked') DEFAULT 'active'"
            )

        conn.commit()
        return True, None
    except mysql.connector.Error as err:
        return False, str(err)
    finally:
        try:
            if cursor is not None:
                cursor.close()
        except Exception:
            pass
        try:
            if conn is not None:
                conn.close()
        except Exception:
            pass


def ensure_scam_patterns_table():
    conn = None
    cursor = None
    try:
        conn, conn_err = get_db_connection()
        if not conn:
            return False, conn_err

        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scam_patterns (
                id INT AUTO_INCREMENT PRIMARY KEY,
                pattern_name VARCHAR(255) NOT NULL,
                pattern_description TEXT NOT NULL,
                pattern_score INT DEFAULT 10,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
            )
        """)

        if not column_exists(cursor, 'scam_patterns', 'pattern_score'):
            cursor.execute(
                "ALTER TABLE scam_patterns ADD COLUMN pattern_score INT DEFAULT 10"
            )

        cursor.execute("SELECT COUNT(*) FROM scam_patterns")
        pattern_count = cursor.fetchone()[0]
        if pattern_count == 0:
            cursor.executemany("""
                INSERT INTO scam_patterns (pattern_name, pattern_description, pattern_score)
                VALUES (%s, %s, %s)
            """, [
                ('Unrealistic Salary', r'earn (?:\$|rs\.?\s*)?\d{2,5}(?:\s*-\s*(?:\$|rs\.?\s*)?\d{2,5})?\s*(?:per day|daily|weekly)\b', 25),
                ('Upfront Payment Request', r'\bpay(?:ment)? fee\b|\bregistration fee\b|\bsecurity deposit\b|\bprocessing fee\b', 30),
                ('Urgent Hiring Language', r'\burgent hiring\b|\bjoin immediately\b|\bapply now\b|\blimited slots\b', 15),
                ('No Interview Claim', r'\bno interview\b|\bwithout interview\b|\bdirect selection\b|\binstant offer\b', 20),
            ])
        else:
            legacy_pattern_updates = [
                (
                    r'earn (?:\$|rs\.?\s*)?\d{2,5}(?:\s*-\s*(?:\$|rs\.?\s*)?\d{2,5})?\s*(?:per day|daily|weekly)\b',
                    25,
                    'Unrealistic Salary',
                ),
                (
                    r'\bpay(?:ment)? fee\b|\bregistration fee\b|\bsecurity deposit\b|\bprocessing fee\b',
                    30,
                    'Upfront Payment Request',
                ),
                (
                    r'\burgent hiring\b|\bjoin immediately\b|\bapply now\b|\blimited slots\b',
                    15,
                    'Urgent Hiring Language',
                ),
                (
                    r'\bno interview\b|\bwithout interview\b|\bdirect selection\b|\binstant offer\b',
                    20,
                    'No Interview Claim',
                ),
            ]
            cursor.executemany("""
                UPDATE scam_patterns
                SET pattern_description = %s,
                    pattern_score = %s
                WHERE pattern_name = %s
            """, legacy_pattern_updates)

        conn.commit()
        return True, None
    except mysql.connector.Error as err:
        return False, str(err)
    finally:
        try:
            if cursor is not None:
                cursor.close()
        except Exception:
            pass
        try:
            if conn is not None:
                conn.close()
        except Exception:
            pass


def load_known_scams_from_csv(limit=50):
    scam_rows = []
    if not os.path.exists(KNOWN_SCAMS_CSV_PATH):
        return scam_rows

    try:
        with open(KNOWN_SCAMS_CSV_PATH, newline='', encoding='utf-8-sig') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                title = (
                    row.get('title')
                    or row.get('job_title')
                    or row.get('Title')
                    or 'Unknown title'
                )
                company = (
                    row.get('company_profile')
                    or row.get('company_name')
                    or row.get('Company')
                    or 'Unknown company'
                )
                description = (
                    row.get('description')
                    or row.get('job_description')
                    or row.get('requirements')
                    or ''
                )
                fraudulent_flag = (
                    row.get('fraudulent')
                    or row.get('is_fraudulent')
                    or row.get('label')
                    or ''
                )

                if str(fraudulent_flag).strip() not in {'1', 'true', 'True', 'fraud', 'Fraud'}:
                    continue

                scam_rows.append({
                    'job_title': title,
                    'company_name': company,
                    'employment_type': (row.get('employment_type') or '').strip() or 'Not specified',
                    'location': (row.get('location') or '').strip() or 'Not specified',
                    'has_company_logo': 'Yes' if str(row.get('has_company_logo') or '').strip() == '1' else 'No',
                    'reported_by': 'kaggle_dataset',
                })

                if len(scam_rows) >= limit:
                    break
    except Exception as err:
        print(f"CSV read error: {err}")

    return scam_rows

def validate_email(email):
    """Validate email format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None


def generate_verification_id():
    date_part = datetime.utcnow().strftime('%Y%m%d')
    random_part = uuid.uuid4().hex[:8].upper()
    return f"VER-{date_part}-{random_part}"


def validate_text_field(value, field_name, max_length, min_length=1):
    cleaned_value = (value or '').strip()
    if len(cleaned_value) < min_length:
        return f'{field_name} is required'
    if len(cleaned_value) > max_length:
        return f'{field_name} must be {max_length} characters or fewer'
    return None


def get_hardcoded_admin(email, password):
    admin = HARDCODED_ADMIN_ACCOUNTS.get((email or '').strip().lower())
    if not admin or admin['password'] != password:
        return None
    return {
        'id': admin['id'],
        'full_name': admin['full_name'],
        'email': admin['email'],
        'role': admin['role'],
    }


def serialize_datetime(value):
    if hasattr(value, 'isoformat'):
        return value.isoformat()
    return value


def normalize_record(record):
    normalized = {}
    for key, value in record.items():
        normalized[key] = serialize_datetime(value)
    return normalized


def normalize_records(records):
    return [normalize_record(record) for record in records]


def get_backend_detection_patterns():
    backend_patterns = []

    for index, rule in enumerate(SCAM_RULES, start=1):
        backend_patterns.append({
            'id': f'backend-rule-{index}',
            'pattern_name': rule['reason'],
            'pattern_description': (
                f"Adds {rule['score']} risk points when matching phrases like: "
                + ", ".join(rule.get('patterns', [])[:4])
            ),
            'pattern_score': rule['score'],
            'source': 'backend_rule',
            'editable': False,
            'created_at': None,
            'updated_at': None,
        })

    backend_patterns.extend([
        {
            'id': 'backend-extra-shortened-url',
            'pattern_name': 'Shortened URL Detection',
            'pattern_description': 'Adds 10 risk points when the posting uses a shortened URL such as bit.ly or tinyurl.',
            'pattern_score': 10,
            'source': 'backend_rule',
            'editable': False,
            'created_at': None,
            'updated_at': None,
        },
        {
            'id': 'backend-extra-messaging-apps',
            'pattern_name': 'Messaging App Redirect',
            'pattern_description': 'Adds 10 risk points when the posting pushes candidates to WhatsApp or Telegram.',
            'pattern_score': 10,
            'source': 'backend_rule',
            'editable': False,
            'created_at': None,
            'updated_at': None,
        },
        {
            'id': 'backend-extra-obfuscated-contact',
            'pattern_name': 'Obfuscated Contact String',
            'pattern_description': 'Adds 15 risk points when the posting contains a suspicious hashed or obfuscated contact string.',
            'pattern_score': 15,
            'source': 'backend_rule',
            'editable': False,
            'created_at': None,
            'updated_at': None,
        },
        {
            'id': 'backend-extra-repetitive-text',
            'pattern_name': 'Short or Repetitive Posting',
            'pattern_description': 'Adds 10 risk points when the job post is extremely short or repetitive.',
            'pattern_score': 10,
            'source': 'backend_rule',
            'editable': False,
            'created_at': None,
            'updated_at': None,
        },
    ])

    return backend_patterns


def get_db_detection_rules():
    conn = None
    cursor = None

    try:
        conn, conn_err = get_db_connection()
        if not conn:
            return []

        cursor = conn.cursor(dictionary=True)
        if not table_exists(cursor, 'scam_patterns'):
            return []

        if not column_exists(cursor, 'scam_patterns', 'pattern_score'):
            return []

        cursor.execute("""
            SELECT
                pattern_name,
                pattern_description,
                pattern_score
            FROM scam_patterns
            ORDER BY id ASC
        """)
        rows = cursor.fetchall()

        rules = []
        for row in rows:
            pattern_text = (row.get('pattern_description') or '').strip()
            if not pattern_text:
                continue

            rules.append({
                'reason': (row.get('pattern_name') or 'Admin pattern').strip(),
                'score': int(row.get('pattern_score') or 10),
                'patterns': [pattern_text],
            })

        return rules
    except Exception:
        return []
    finally:
        try:
            if cursor is not None:
                cursor.close()
        except Exception:
            pass
        try:
            if conn is not None:
                conn.close()
        except Exception:
            pass


def analyze_job_with_active_patterns(job_description="", job_url=""):
    return analyze_job_risk(
        job_description=job_description,
        job_url=job_url,
        additional_rules=get_db_detection_rules(),
    )


def parse_admin_job_id(job_id):
    cleaned_job_id = (job_id or '').strip()
    if '-' not in cleaned_job_id:
        raise ValueError('Invalid job_id format')

    source_type, raw_id = cleaned_job_id.split('-', 1)
    if source_type not in {'report', 'verification', 'csv'} or not raw_id:
        raise ValueError('Unsupported job_id')

    return source_type, raw_id


def merge_known_scams(csv_scams, db_scams):
    combined = []
    seen = set()

    for scam in db_scams + csv_scams:
        key = (
            (scam.get('job_title') or '').strip().lower(),
            (scam.get('company_name') or '').strip().lower(),
        )
        if key in seen:
            continue
        seen.add(key)
        combined.append(scam)

    return combined


@app.route('/analyze-job', methods=['POST'])
def analyze_job():
    data = get_request_data()
    job_description = (data.get('job_description') or '').strip()
    job_url = (data.get('job_url') or '').strip()

    if not job_description:
        return jsonify({'error': 'job_description is required'}), 400

    result = analyze_job_with_active_patterns(job_description=job_description, job_url=job_url)
    return jsonify(result), 200


@app.route('/report-job', methods=['POST'])
def report_job():
    conn = None
    cursor = None

    try:
        data = get_request_data()
        required_fields = ['job_title', 'company_name', 'description']
        for field in required_fields:
            if not (data.get(field) or '').strip():
                return jsonify({'error': f'{field} is required'}), 400

        analysis = analyze_job_with_active_patterns(job_description=data['description'].strip())
        is_flagged = analysis['risk_level'] == 'High'

        table_ready, table_error = ensure_scam_reports_table()
        if not table_ready:
            return jsonify({'error': 'Could not prepare scam_reports table', 'details': table_error}), 500

        conn, conn_err = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed', 'details': conn_err}), 500

        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO scam_reports (
                job_title,
                company_name,
                description,
                reported_by,
                risk_score,
                risk_level,
                is_flagged
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (
            data['job_title'].strip(),
            data['company_name'].strip(),
            data['description'].strip(),
            (data.get('reported_by') or 'job_seeker_portal').strip(),
            analysis['risk_score'],
            analysis['risk_level'],
            is_flagged,
        ))
        conn.commit()

        return jsonify({
            'message': 'Job report submitted successfully',
            'report_id': cursor.lastrowid,
            'risk_score': analysis['risk_score'],
            'risk_level': analysis['risk_level'],
            'red_flags': analysis['red_flags'],
            'flagged_as_fraud': is_flagged,
        }), 201
    except mysql.connector.Error as err:
        if conn is not None:
            conn.rollback()
        print(f"Database error: {err}")
        return jsonify({'error': 'Database error occurred'}), 500
    except Exception as e:
        if conn is not None:
            conn.rollback()
        print(f"Unexpected error: {e}")
        return jsonify({'error': 'An unexpected error occurred'}), 500
    finally:
        try:
            if cursor is not None:
                cursor.close()
        except Exception:
            pass
        try:
            if conn is not None:
                conn.close()
        except Exception:
            pass


@app.route('/submit-job', methods=['POST'])
def submit_job():
    conn = None
    cursor = None

    try:
        data = get_request_data()

        job_title = (data.get('job_title') or '').strip()
        company_name = (data.get('company_name') or '').strip()
        location = (data.get('location') or '').strip()
        description = (data.get('description') or '').strip()
        recruiter_email = (data.get('recruiter_email') or '').strip().lower()

        validations = [
            validate_text_field(job_title, 'job_title', 255),
            validate_text_field(company_name, 'company_name', 255),
            validate_text_field(location, 'location', 255),
            validate_text_field(description, 'description', 5000, min_length=20),
        ]
        validation_error = next((error for error in validations if error), None)
        if validation_error:
            return jsonify({'error': validation_error}), 400

        if not recruiter_email:
            return jsonify({'error': 'recruiter_email is required'}), 400
        if not validate_email(recruiter_email):
            return jsonify({'error': 'Invalid recruiter_email format'}), 400

        analysis = analyze_job_with_active_patterns(job_description=description)

        users_ready, users_error = ensure_users_admin_columns()
        if not users_ready:
            return jsonify({
                'error': 'Could not prepare users table',
                'details': users_error
            }), 500

        table_ready, table_error = ensure_recruiter_verifications_table()
        if not table_ready:
            return jsonify({
                'error': 'Could not prepare recruiter_verifications table',
                'details': table_error
            }), 500

        conn, conn_err = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed', 'details': conn_err}), 500

        cursor = conn.cursor()
        cursor.execute(
            "SELECT status FROM users WHERE email = %s AND role = 'Recruiter'",
            (recruiter_email,)
        )
        recruiter = cursor.fetchone()
        if recruiter and recruiter[0] == 'blocked':
            return jsonify({'error': 'This recruiter has been blocked and cannot submit jobs'}), 403

        cursor.execute("""
            INSERT INTO recruiter_verifications (
                job_title,
                company_name,
                location,
                description,
                recruiter_email,
                risk_score,
                risk_level,
                status
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            job_title,
            company_name,
            location,
            description,
            recruiter_email,
            analysis['risk_score'],
            analysis['risk_level'],
            'pending',
        ))
        conn.commit()

        return jsonify({
            'message': 'Job submitted for verification successfully',
            'submission_id': cursor.lastrowid,
            'risk_score': analysis['risk_score'],
            'risk_level': analysis['risk_level'],
            'status': 'pending',
        }), 201
    except mysql.connector.Error as err:
        if conn is not None:
            conn.rollback()
        print(f"Database error: {err}")
        return jsonify({'error': 'Database error occurred'}), 500
    except Exception as e:
        if conn is not None:
            conn.rollback()
        print(f"Unexpected error: {e}")
        return jsonify({'error': 'An unexpected error occurred'}), 500
    finally:
        try:
            if cursor is not None:
                cursor.close()
        except Exception:
            pass
        try:
            if conn is not None:
                conn.close()
        except Exception:
            pass


@app.route('/verification-status', methods=['GET'])
def verification_status():
    conn = None
    cursor = None
    update_cursor = None

    try:
        recruiter_email = (request.args.get('email') or '').strip().lower()

        if not recruiter_email:
            return jsonify({'error': 'email is required'}), 400
        if not validate_email(recruiter_email):
            return jsonify({'error': 'Invalid email format'}), 400

        table_ready, table_error = ensure_recruiter_verifications_table()
        if not table_ready:
            return jsonify({
                'error': 'Could not prepare recruiter_verifications table',
                'details': table_error
            }), 500

        conn, conn_err = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed', 'details': conn_err}), 500

        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT
                id,
                job_title,
                company_name,
                location,
                description,
                recruiter_email,
                risk_score,
                risk_level,
                status,
                verification_id,
                submitted_at,
                verified_at
            FROM recruiter_verifications
            WHERE recruiter_email = %s
            ORDER BY submitted_at DESC, id DESC
        """, (recruiter_email,))
        jobs = cursor.fetchall()

        updates = []
        used_ids = {job['verification_id'] for job in jobs if job.get('verification_id')}
        for job in jobs:
            if job['status'] == 'verified' and not job['verification_id']:
                verification_id = generate_verification_id()
                while verification_id in used_ids:
                    verification_id = generate_verification_id()
                used_ids.add(verification_id)
                job['verification_id'] = verification_id
                updates.append((verification_id, job['id']))

        if updates:
            update_cursor = conn.cursor()
            update_cursor.executemany("""
                UPDATE recruiter_verifications
                SET verification_id = %s,
                    verified_at = COALESCE(verified_at, CURRENT_TIMESTAMP)
                WHERE id = %s
            """, updates)
            conn.commit()

        return jsonify({
            'email': recruiter_email,
            'count': len(jobs),
            'jobs': jobs,
        }), 200
    except mysql.connector.Error as err:
        print(f"Database error: {err}")
        return jsonify({'error': 'Database error occurred'}), 500
    except Exception as e:
        print(f"Unexpected error: {e}")
        return jsonify({'error': 'An unexpected error occurred'}), 500
    finally:
        try:
            if update_cursor is not None:
                update_cursor.close()
        except Exception:
            pass
        try:
            if cursor is not None:
                cursor.close()
        except Exception:
            pass
        try:
            if conn is not None:
                conn.close()
        except Exception:
            pass


@app.route('/known-scams', methods=['GET'])
def known_scams():
    conn = None
    cursor = None

    try:
        csv_scams = load_known_scams_from_csv()
        db_scams = []

        table_ready, _ = ensure_scam_reports_table()
        if table_ready:
            conn, conn_err = get_db_connection()
            if conn:
                cursor = conn.cursor(dictionary=True)
                cursor.execute("""
                    SELECT
                        id,
                        job_title,
                        company_name,
                        'Reported job' AS employment_type,
                        'User report' AS location,
                        'No' AS has_company_logo,
                        description,
                        'Anonymous' AS reported_by,
                        created_at,
                        risk_score,
                        risk_level
                    FROM scam_reports
                    WHERE is_flagged = TRUE
                    ORDER BY created_at DESC
                """)
                db_scams = cursor.fetchall()

        combined_scams = merge_known_scams(csv_scams, db_scams)
        return jsonify({
            'source': 'combined' if combined_scams else 'none',
            'count': len(combined_scams),
            'known_scams': combined_scams,
        }), 200
    except mysql.connector.Error as err:
        print(f"Database error: {err}")
        csv_scams = load_known_scams_from_csv()
        return jsonify({
            'source': 'csv' if csv_scams else 'none',
            'count': len(csv_scams),
            'known_scams': csv_scams,
        }), 200
    finally:
        try:
            if cursor is not None:
                cursor.close()
        except Exception:
            pass
        try:
            if conn is not None:
                conn.close()
        except Exception:
            pass


@app.route('/flagged-jobs', methods=['GET'])
def flagged_jobs():
    conn = None
    cursor = None

    try:
        ensure_scam_reports_table()
        ensure_recruiter_verifications_table()

        pending_verifications = []
        reviewed_verifications = []
        user_reported_scams = []

        conn, conn_err = get_db_connection()
        if conn:
            cursor = conn.cursor(dictionary=True)

            if table_exists(cursor, 'recruiter_verifications'):
                cursor.execute("""
                    SELECT
                        CONCAT('verification-', id) AS job_id,
                        id,
                        job_title,
                        company_name,
                        location,
                        description,
                        recruiter_email,
                        risk_score,
                        risk_level,
                        status,
                        verification_id,
                        submitted_at,
                        verified_at
                    FROM recruiter_verifications
                    ORDER BY submitted_at DESC, id DESC
                """)
                recruiter_jobs = cursor.fetchall()
                for job in recruiter_jobs:
                    job['source_type'] = 'recruiter_submission'
                    job['is_actionable'] = job.get('status') == 'pending'
                    if job.get('status') == 'pending':
                        pending_verifications.append(job)
                    else:
                        reviewed_verifications.append(job)

            if table_exists(cursor, 'scam_reports'):
                cursor.execute("""
                    SELECT
                        CONCAT('report-', id) AS job_id,
                        id,
                        job_title,
                        company_name,
                        description,
                        reported_by,
                        risk_score,
                        risk_level,
                        is_flagged,
                        created_at
                    FROM scam_reports
                    WHERE is_flagged = TRUE OR risk_level = 'High' OR risk_score >= 70
                    ORDER BY created_at DESC, id DESC
                """)
                user_reported_scams = cursor.fetchall()
                for job in user_reported_scams:
                    job['source_type'] = 'user_reported_scam'
                    job['status'] = 'known_scam'
                    job['is_actionable'] = False

        csv_jobs = load_known_scams_from_csv(limit=50)
        csv_scams = []
        for index, job in enumerate(csv_jobs, start=1):
            csv_scams.append({
                'job_id': f'csv-{index}',
                'source_type': 'csv_scam',
                'status': 'known_scam',
                'is_actionable': False,
                **job,
            })

        known_scams = normalize_records(csv_scams)
        return jsonify({
            'count': len(pending_verifications) + len(reviewed_verifications) + len(user_reported_scams) + len(known_scams),
            'pending_recruiter_jobs': normalize_records(pending_verifications),
            'reviewed_recruiter_jobs': normalize_records(reviewed_verifications),
            'user_reported_scams': normalize_records(user_reported_scams),
            'known_scams': known_scams,
            'db_connected': conn is not None,
            'db_error': conn_err if conn is None else None,
        }), 200
    except mysql.connector.Error as err:
        print(f"Database error: {err}")
        return jsonify({'error': 'Database error occurred'}), 500
    except Exception as e:
        print(f"Unexpected error: {e}")
        return jsonify({'error': 'An unexpected error occurred'}), 500
    finally:
        try:
            if cursor is not None:
                cursor.close()
        except Exception:
            pass
        try:
            if conn is not None:
                conn.close()
        except Exception:
            pass


@app.route('/approve-job', methods=['POST'])
def approve_job():
    conn = None
    cursor = None

    try:
        data = get_request_data()
        source_type, raw_id = parse_admin_job_id(data.get('job_id'))

        if source_type != 'verification':
            return jsonify({'error': 'Only recruiter verification requests can be approved'}), 400

        conn, conn_err = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed', 'details': conn_err}), 500

        cursor = conn.cursor()

        verification_id = generate_verification_id()
        cursor.execute("""
            UPDATE recruiter_verifications
            SET status = 'verified',
                verification_id = COALESCE(verification_id, %s),
                verified_at = CURRENT_TIMESTAMP
            WHERE id = %s
              AND status = 'pending'
        """, (verification_id, raw_id))

        if cursor.rowcount == 0:
            conn.rollback()
            return jsonify({'error': 'Job not found'}), 404

        conn.commit()
        return jsonify({
            'message': 'Job approved successfully',
            'job_id': data.get('job_id'),
            'verification_id': verification_id,
            'action': 'approved',
        }), 200
    except ValueError as err:
        return jsonify({'error': str(err)}), 400
    except mysql.connector.Error as err:
        if conn is not None:
            conn.rollback()
        print(f"Database error: {err}")
        return jsonify({'error': 'Database error occurred'}), 500
    except Exception as e:
        if conn is not None:
            conn.rollback()
        print(f"Unexpected error: {e}")
        return jsonify({'error': 'An unexpected error occurred'}), 500
    finally:
        try:
            if cursor is not None:
                cursor.close()
        except Exception:
            pass
        try:
            if conn is not None:
                conn.close()
        except Exception:
            pass


@app.route('/reject-job', methods=['POST'])
def reject_job():
    conn = None
    cursor = None

    try:
        data = get_request_data()
        source_type, raw_id = parse_admin_job_id(data.get('job_id'))

        if source_type != 'verification':
            return jsonify({'error': 'Only recruiter verification requests can be rejected'}), 400

        conn, conn_err = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed', 'details': conn_err}), 500

        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT
                id,
                job_title,
                company_name,
                description,
                recruiter_email,
                risk_score
            FROM recruiter_verifications
            WHERE id = %s
              AND status = 'pending'
        """, (raw_id,))
        verification_job = cursor.fetchone()
        if not verification_job:
            conn.rollback()
            return jsonify({'error': 'Job not found'}), 404

        cursor.execute("""
            UPDATE recruiter_verifications
            SET status = 'rejected',
                verified_at = CURRENT_TIMESTAMP
            WHERE id = %s
              AND status = 'pending'
        """, (raw_id,))

        insert_cursor = conn.cursor()
        insert_cursor.execute("""
            INSERT INTO scam_reports (
                job_title,
                company_name,
                description,
                reported_by,
                risk_score,
                risk_level,
                is_flagged
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (
            verification_job['job_title'],
            verification_job['company_name'],
            verification_job['description'],
            verification_job['recruiter_email'],
            max(verification_job['risk_score'] or 0, 80),
            'High',
            True,
        ))
        insert_cursor.close()

        conn.commit()
        return jsonify({
            'message': 'Job marked as scam',
            'job_id': data.get('job_id'),
            'action': 'rejected',
        }), 200
    except ValueError as err:
        return jsonify({'error': str(err)}), 400
    except mysql.connector.Error as err:
        if conn is not None:
            conn.rollback()
        print(f"Database error: {err}")
        return jsonify({'error': 'Database error occurred'}), 500
    except Exception as e:
        if conn is not None:
            conn.rollback()
        print(f"Unexpected error: {e}")
        return jsonify({'error': 'An unexpected error occurred'}), 500
    finally:
        try:
            if cursor is not None:
                cursor.close()
        except Exception:
            pass
        try:
            if conn is not None:
                conn.close()
        except Exception:
            pass


@app.route('/recruiters', methods=['GET'])
def recruiters():
    conn = None
    cursor = None

    try:
        users_ready, users_error = ensure_users_admin_columns()
        verification_ready, verification_error = ensure_recruiter_verifications_table()
        if not users_ready:
            return jsonify({'error': 'Could not prepare users table', 'details': users_error}), 500
        if not verification_ready:
            return jsonify({
                'error': 'Could not prepare recruiter_verifications table',
                'details': verification_error
            }), 500

        conn, conn_err = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed', 'details': conn_err}), 500

        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT
                u.id,
                u.public_user_id,
                u.full_name,
                u.email,
                u.status,
                u.created_at,
                COUNT(rv.id) AS submitted_jobs,
                SUM(CASE WHEN rv.status = 'pending' THEN 1 ELSE 0 END) AS pending_jobs
            FROM users u
            LEFT JOIN recruiter_verifications rv
                ON rv.recruiter_email = u.email
            WHERE u.role = 'Recruiter'
            GROUP BY u.id, u.public_user_id, u.full_name, u.email, u.status, u.created_at
            ORDER BY u.created_at DESC, u.id DESC
        """)
        recruiter_rows = normalize_records(cursor.fetchall())
        return jsonify({
            'count': len(recruiter_rows),
            'recruiters': recruiter_rows,
        }), 200
    except mysql.connector.Error as err:
        print(f"Database error: {err}")
        return jsonify({'error': 'Database error occurred'}), 500
    except Exception as e:
        print(f"Unexpected error: {e}")
        return jsonify({'error': 'An unexpected error occurred'}), 500
    finally:
        try:
            if cursor is not None:
                cursor.close()
        except Exception:
            pass
        try:
            if conn is not None:
                conn.close()
        except Exception:
            pass


@app.route('/block-recruiter', methods=['POST'])
def block_recruiter():
    conn = None
    cursor = None

    try:
        data = get_request_data()
        recruiter_id = (data.get('recruiter_id') or '').strip()
        if not recruiter_id:
            return jsonify({'error': 'recruiter_id is required'}), 400

        users_ready, users_error = ensure_users_admin_columns()
        if not users_ready:
            return jsonify({'error': 'Could not prepare users table', 'details': users_error}), 500

        conn, conn_err = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed', 'details': conn_err}), 500

        cursor = conn.cursor()
        cursor.execute("""
            UPDATE users
            SET status = 'blocked'
            WHERE id = %s OR public_user_id = %s
        """, (recruiter_id, recruiter_id))

        if cursor.rowcount == 0:
            conn.rollback()
            return jsonify({'error': 'Recruiter not found'}), 404

        conn.commit()
        return jsonify({
            'message': 'Recruiter blocked successfully',
            'recruiter_id': recruiter_id,
        }), 200
    except mysql.connector.Error as err:
        if conn is not None:
            conn.rollback()
        print(f"Database error: {err}")
        return jsonify({'error': 'Database error occurred'}), 500
    except Exception as e:
        if conn is not None:
            conn.rollback()
        print(f"Unexpected error: {e}")
        return jsonify({'error': 'An unexpected error occurred'}), 500
    finally:
        try:
            if cursor is not None:
                cursor.close()
        except Exception:
            pass
        try:
            if conn is not None:
                conn.close()
        except Exception:
            pass


@app.route('/add-pattern', methods=['POST'])
def add_pattern():
    conn = None
    cursor = None

    try:
        data = get_request_data()
        pattern_name = (data.get('pattern_name') or data.get('name') or '').strip()
        pattern_description = (data.get('pattern_description') or data.get('description') or '').strip()
        pattern_score = int(data.get('pattern_score') or 10)

        validations = [
            validate_text_field(pattern_name, 'pattern_name', 255),
            validate_text_field(pattern_description, 'pattern_description', 2000, min_length=5),
        ]
        validation_error = next((error for error in validations if error), None)
        if validation_error:
            return jsonify({'error': validation_error}), 400

        patterns_ready, patterns_error = ensure_scam_patterns_table()
        if not patterns_ready:
            return jsonify({'error': 'Could not prepare scam_patterns table', 'details': patterns_error}), 500

        conn, conn_err = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed', 'details': conn_err}), 500

        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO scam_patterns (pattern_name, pattern_description, pattern_score)
            VALUES (%s, %s, %s)
        """, (pattern_name, pattern_description, pattern_score))
        conn.commit()

        return jsonify({
            'message': 'Pattern added successfully',
            'pattern_id': cursor.lastrowid,
        }), 201
    except mysql.connector.Error as err:
        if conn is not None:
            conn.rollback()
        print(f"Database error: {err}")
        return jsonify({'error': 'Database error occurred'}), 500
    except Exception as e:
        if conn is not None:
            conn.rollback()
        print(f"Unexpected error: {e}")
        return jsonify({'error': 'An unexpected error occurred'}), 500
    finally:
        try:
            if cursor is not None:
                cursor.close()
        except Exception:
            pass
        try:
            if conn is not None:
                conn.close()
        except Exception:
            pass


@app.route('/patterns', methods=['GET'])
def get_patterns():
    conn = None
    cursor = None

    try:
        backend_patterns = get_backend_detection_patterns()
        patterns_ready, patterns_error = ensure_scam_patterns_table()
        if not patterns_ready:
            return jsonify({'error': 'Could not prepare scam_patterns table', 'details': patterns_error}), 500

        conn, conn_err = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed', 'details': conn_err}), 500

        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT
                id,
                pattern_name,
                pattern_description,
                pattern_score,
                'custom_pattern' AS source,
                TRUE AS editable,
                created_at,
                updated_at
            FROM scam_patterns
            ORDER BY updated_at DESC, id DESC
        """)
        pattern_rows = normalize_records(cursor.fetchall())
        return jsonify({
            'count': len(backend_patterns) + len(pattern_rows),
            'patterns': backend_patterns + pattern_rows,
        }), 200
    except mysql.connector.Error as err:
        print(f"Database error: {err}")
        return jsonify({'error': 'Database error occurred'}), 500
    except Exception as e:
        print(f"Unexpected error: {e}")
        return jsonify({'error': 'An unexpected error occurred'}), 500
    finally:
        try:
            if cursor is not None:
                cursor.close()
        except Exception:
            pass
        try:
            if conn is not None:
                conn.close()
        except Exception:
            pass


@app.route('/update-pattern', methods=['PUT'])
def update_pattern():
    conn = None
    cursor = None

    try:
        data = get_request_data()
        pattern_id = (data.get('pattern_id') or '').strip()
        pattern_name = (data.get('pattern_name') or data.get('name') or '').strip()
        pattern_description = (data.get('pattern_description') or data.get('description') or '').strip()
        pattern_score = int(data.get('pattern_score') or 10)

        if not pattern_id:
            return jsonify({'error': 'pattern_id is required'}), 400

        validations = [
            validate_text_field(pattern_name, 'pattern_name', 255),
            validate_text_field(pattern_description, 'pattern_description', 2000, min_length=5),
        ]
        validation_error = next((error for error in validations if error), None)
        if validation_error:
            return jsonify({'error': validation_error}), 400

        patterns_ready, patterns_error = ensure_scam_patterns_table()
        if not patterns_ready:
            return jsonify({'error': 'Could not prepare scam_patterns table', 'details': patterns_error}), 500

        conn, conn_err = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed', 'details': conn_err}), 500

        cursor = conn.cursor()
        cursor.execute("""
            UPDATE scam_patterns
            SET pattern_name = %s,
                pattern_description = %s,
                pattern_score = %s
            WHERE id = %s
        """, (pattern_name, pattern_description, pattern_score, pattern_id))

        if cursor.rowcount == 0:
            conn.rollback()
            return jsonify({'error': 'Pattern not found'}), 404

        conn.commit()
        return jsonify({
            'message': 'Pattern updated successfully',
            'pattern_id': pattern_id,
        }), 200
    except mysql.connector.Error as err:
        if conn is not None:
            conn.rollback()
        print(f"Database error: {err}")
        return jsonify({'error': 'Database error occurred'}), 500
    except Exception as e:
        if conn is not None:
            conn.rollback()
        print(f"Unexpected error: {e}")
        return jsonify({'error': 'An unexpected error occurred'}), 500
    finally:
        try:
            if cursor is not None:
                cursor.close()
        except Exception:
            pass
        try:
            if conn is not None:
                conn.close()
        except Exception:
            pass


@app.route('/delete-pattern', methods=['DELETE'])
def delete_pattern():
    conn = None
    cursor = None

    try:
        data = get_request_data()
        pattern_id = (data.get('pattern_id') or '').strip()
        if not pattern_id:
            return jsonify({'error': 'pattern_id is required'}), 400

        patterns_ready, patterns_error = ensure_scam_patterns_table()
        if not patterns_ready:
            return jsonify({'error': 'Could not prepare scam_patterns table', 'details': patterns_error}), 500

        conn, conn_err = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed', 'details': conn_err}), 500

        cursor = conn.cursor()
        cursor.execute("DELETE FROM scam_patterns WHERE id = %s", (pattern_id,))
        if cursor.rowcount == 0:
            conn.rollback()
            return jsonify({'error': 'Pattern not found'}), 404

        conn.commit()
        return jsonify({
            'message': 'Pattern deleted successfully',
            'pattern_id': pattern_id,
        }), 200
    except mysql.connector.Error as err:
        if conn is not None:
            conn.rollback()
        print(f"Database error: {err}")
        return jsonify({'error': 'Database error occurred'}), 500
    except Exception as e:
        if conn is not None:
            conn.rollback()
        print(f"Unexpected error: {e}")
        return jsonify({'error': 'An unexpected error occurred'}), 500
    finally:
        try:
            if cursor is not None:
                cursor.close()
        except Exception:
            pass
        try:
            if conn is not None:
                conn.close()
        except Exception:
            pass


@app.route('/reports', methods=['GET'])
def admin_reports():
    conn = None
    cursor = None

    try:
        ensure_scam_reports_table()
        ensure_recruiter_verifications_table()
        ensure_users_admin_columns()

        total_scams = 0
        total_users = 0
        blocked_recruiters = 0
        pending_reviews = 0
        high_risk_jobs = []

        conn, conn_err = get_db_connection()
        if conn:
            cursor = conn.cursor(dictionary=True)

            if table_exists(cursor, 'scam_reports'):
                cursor.execute("SELECT COUNT(*) AS total_scams FROM scam_reports WHERE is_flagged = TRUE")
                total_scams = cursor.fetchone()['total_scams']

                cursor.execute("""
                    SELECT
                        CONCAT('report-', id) AS job_id,
                        job_title,
                        company_name,
                        risk_score,
                        risk_level,
                        created_at
                    FROM scam_reports
                    WHERE is_flagged = TRUE OR risk_level = 'High' OR risk_score >= 70
                    ORDER BY risk_score DESC, created_at DESC
                    LIMIT 10
                """)
                high_risk_jobs = normalize_records(cursor.fetchall())

            if table_exists(cursor, 'users'):
                cursor.execute("SELECT COUNT(*) AS total_users FROM users")
                total_users = cursor.fetchone()['total_users']

                try:
                    cursor.execute("SELECT COUNT(*) AS blocked_recruiters FROM users WHERE role = 'Recruiter' AND status = 'blocked'")
                    blocked_recruiters = cursor.fetchone()['blocked_recruiters']
                except mysql.connector.Error:
                    blocked_recruiters = 0

            if table_exists(cursor, 'recruiter_verifications'):
                cursor.execute("SELECT COUNT(*) AS pending_reviews FROM recruiter_verifications WHERE status = 'pending'")
                pending_reviews = cursor.fetchone()['pending_reviews']

        return jsonify({
            'total_scams': total_scams,
            'total_users': total_users,
            'blocked_recruiters': blocked_recruiters,
            'pending_reviews': pending_reviews,
            'high_risk_jobs_count': len(high_risk_jobs),
            'high_risk_jobs': high_risk_jobs,
            'db_connected': conn is not None,
            'db_error': conn_err if conn is None else None,
        }), 200
    except mysql.connector.Error as err:
        print(f"Database error: {err}")
        return jsonify({'error': 'Database error occurred'}), 500
    except Exception as e:
        print(f"Unexpected error: {e}")
        return jsonify({'error': 'An unexpected error occurred'}), 500
    finally:
        try:
            if cursor is not None:
                cursor.close()
        except Exception:
            pass
        try:
            if conn is not None:
                conn.close()
        except Exception:
            pass


@app.route('/login', methods=['POST'])
def login():
    """Handle user login and return role for redirect."""
    conn = None
    cursor = None

    try:
        data = get_request_data()

        email = (data.get('email') or '').strip().lower()
        password = data.get('password') or ''

        if not email or not password:
            return jsonify({'error': 'Email and password are required'}), 400
        if not validate_email(email):
            return jsonify({'error': 'Invalid email format'}), 400

        admin_user = get_hardcoded_admin(email, password)
        if admin_user:
            return jsonify({
                'message': 'Login successful',
                'user': admin_user
            }), 200

        conn, conn_err = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed', 'details': conn_err}), 500

        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            "SELECT id, full_name, email, password_hash, role FROM users WHERE email = %s",
            (email,),
        )
        user = cursor.fetchone()
        if not user:
            return jsonify({'error': 'Invalid email or password'}), 401

        if not check_password_hash(user['password_hash'], password):
            return jsonify({'error': 'Invalid email or password'}), 401

        # Minimal data for frontend redirect + optional localStorage usage
        return jsonify({
            'message': 'Login successful',
            'user': {
                'id': user['id'],
                'full_name': user['full_name'],
                'email': user['email'],
                'role': user['role'],
            }
        }), 200

    except mysql.connector.Error as err:
        print(f"Database error: {err}")
        return jsonify({'error': 'Database error occurred'}), 500
    except Exception as e:
        print(f"Unexpected error: {e}")
        return jsonify({'error': 'An unexpected error occurred'}), 500
    finally:
        try:
            if cursor is not None:
                cursor.close()
        except Exception:
            pass
        try:
            if conn is not None:
                conn.close()
        except Exception:
            pass

@app.route('/signup', methods=['POST'])
def signup():
    """Handle user signup"""
    conn = None
    cursor = None

    try:
        # Accept either JSON (fetch) or normal form POST (no-JS)
        data = get_request_data()
        
        # Validate required fields
        required_fields = ['full_name', 'email', 'password', 'confirm_password', 'role']
        for field in required_fields:
            if field not in data or not data[field]:
                return jsonify({'error': f'{field.replace("_", " ").title()} is required'}), 400
        
        full_name = data['full_name'].strip()
        public_user_id = generate_public_id(full_name)
        email = data['email'].strip().lower()
        password = data['password']
        confirm_password = data['confirm_password']
        role = data['role']
        
        # Validate email format
        if not validate_email(email):
            return jsonify({'error': 'Invalid email format'}), 400
        
        # Validate password match
        if password != confirm_password:
            return jsonify({'error': 'Passwords do not match'}), 400
        
        # Validate password length
        if len(password) < 6:
            return jsonify({'error': 'Password must be at least 6 characters long'}), 400
        
        # Validate role
        valid_roles = ['Job Seeker', 'Recruiter']
        if role not in valid_roles:
            return jsonify({'error': 'Invalid role selected'}), 400
        
        # Validate full name length
        if len(full_name) > 100:
            return jsonify({'error': 'Full name must be 100 characters or less'}), 400
        
        # Hash password
        password_hash = generate_password_hash(password)
        
        # Connect to database
        conn, conn_err = get_db_connection()
        if not conn:
            return jsonify({
                'error': 'Database connection failed',
                'details': conn_err or 'Unknown connection error'
            }), 500
        
        cursor = conn.cursor()
        
        # Check if email already exists
        cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
        if cursor.fetchone():
            cursor.close()
            conn.close()
            return jsonify({'error': 'Email already registered'}), 400
        
        # Insert new user
        insert_query = """
            INSERT INTO users (full_name, email, password_hash, role, public_user_id)
            VALUES (%s, %s, %s, %s, %s)
        """
        cursor.execute(insert_query, (full_name, email, password_hash, role, public_user_id))
        conn.commit()
        
        user_id = cursor.lastrowid
        cursor.close()
        conn.close()
        
        return jsonify({
            'message': 'Account created successfully!',
            'user_id': user_id,
            'public_user_id': public_user_id
        }), 201
        
    except mysql.connector.Error as err:
        if conn is not None:
            conn.rollback()
            conn.close()
        if cursor is not None:
            cursor.close()
        print(f"Database error: {err}")
        return jsonify({'error': 'Database error occurred'}), 500
    except Exception as e:
        print(f"Unexpected error: {e}")
        return jsonify({'error': 'An unexpected error occurred'}), 500
    finally:
        try:
            if cursor is not None:
                cursor.close()
        except Exception:
            pass
        try:
            if conn is not None:
                conn.close()
        except Exception:
            pass

@app.route('/profile', methods=['GET'])
def get_profile():
    email = request.args.get('email')
    conn, _ = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT full_name, email, role, created_at, public_user_id
        FROM users WHERE email=%s
    """, (email,))

    user = cursor.fetchone()
    cursor.close()
    conn.close()

    if not user:
        return jsonify({'error': 'User not found'}), 404

    return jsonify(user)

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({'status': 'ok'}), 200

@app.route('/forgot-password', methods=['POST'])
def forgot_password():
    data = request.get_json(silent=True) or {}
    email = data.get('email')

    if not email:
        return jsonify({'error': 'Email is required'}), 400

    conn, _ = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT id FROM users WHERE email=%s
    """, (email,))
    user = cursor.fetchone()

    cursor.close()
    conn.close()

    if not user:
        return jsonify({'error': 'Email not found'}), 404

    return jsonify({'message': 'Email verified successfully'})

@app.route('/reset-password', methods=['POST'])
def reset_password():
    data = request.get_json(silent=True) or {}
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'error': 'Missing data'}), 400

    hashed = generate_password_hash(password)

    conn, _ = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE users
        SET password_hash=%s
        WHERE email=%s
    """, (hashed, email))

    if cursor.rowcount == 0:
        return jsonify({'error': 'User not found'}), 404

    conn.commit()
    cursor.close()
    conn.close()

    return jsonify({'message': 'Password updated successfully'})




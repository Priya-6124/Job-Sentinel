# Setup Instructions

## Prerequisites
1. Python 3.7 or higher installed
2. MySQL server installed and running
3. Database `agile_project` created with the `users` table

## Database Setup

Run these SQL commands in MySQL:

```sql
CREATE DATABASE agile_project;
USE agile_project;

CREATE TABLE users 
(
    id INT AUTO_INCREMENT PRIMARY KEY,
    full_name VARCHAR(100) NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role ENUM('Job Seeker', 'Recruiter') NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

## Installation Steps

1. **Install Python dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Configure database connection:**
   - Open `backend/app.py`
   - Update the `DB_CONFIG` dictionary with your MySQL credentials:
     ```python
     DB_CONFIG = {
         'host': 'localhost',
         'user': 'your_mysql_username',  # e.g., 'root'
         'password': 'your_mysql_password',  # e.g., 'password123'
         'database': 'agile_project'
     }
     ```

3. **Start the Flask server:**
   ```bash
   python app.py
   ```
   The server will run on `http://localhost:5000`

4. **Open the signup page:**
   - Open `frontend/pages/signup.html` in your browser
   - Or serve it through a local web server

## Testing

1. Fill out the signup form with:
   - Full Name
   - Email (must be unique)
   - Password (minimum 6 characters)
   - Confirm Password (must match)
   - Role (Job Seeker or Recruiter)

2. Click "Sign Up"

3. On success, you'll be redirected to the login page

4. Verify the data in MySQL:
   ```sql
   SELECT * FROM users;
   ```

## Troubleshooting

- **Database connection error**: Check MySQL is running and credentials are correct
- **Email already exists**: Use a different email address
- **Port 5000 already in use**: Change the port in the root `app.py`
- **CORS errors**: Make sure `flask-cors` is installed

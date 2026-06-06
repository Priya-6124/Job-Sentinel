CREATE DATABASE agile_project;
USE agile_project;

CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    public_user_id VARCHAR(36) UNIQUE,
    full_name VARCHAR(100) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role ENUM('Job Seeker', 'Recruiter') NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE scam_reports (
    id INT AUTO_INCREMENT PRIMARY KEY,
    job_title VARCHAR(255) NOT NULL,
    company_name VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    reported_by VARCHAR(255) NOT NULL,
    risk_score INT DEFAULT 0,
    risk_level VARCHAR(20) DEFAULT 'Low',
    is_flagged BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE recruiter_verifications (
    id INT AUTO_INCREMENT PRIMARY KEY,
    job_title VARCHAR(255) NOT NULL,
    company_name VARCHAR(255) NOT NULL,
    location VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    recruiter_email VARCHAR(255) NOT NULL,
    status ENUM('pending', 'verified', 'rejected') DEFAULT 'pending',
    verification_id VARCHAR(50) UNIQUE DEFAULT NULL,
    submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    verified_at TIMESTAMP NULL DEFAULT NULL
);

-- Migration for existing databases (safe if columns already removed)
ALTER TABLE users DROP COLUMN IF EXISTS reset_otp;
ALTER TABLE users DROP COLUMN IF EXISTS otp_expires_at;

SELECT * FROM users;

CREATE USER 'agile_user'@'localhost' IDENTIFIED BY 'Agile@12345';
GRANT ALL PRIVILEGES ON agile_project.* TO 'agile_user'@'localhost';
FLUSH PRIVILEGES;

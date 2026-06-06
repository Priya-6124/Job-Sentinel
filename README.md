# 🛡️ Job Sentinel

A web-based platform designed to help job seekers identify fraudulent job postings and report suspicious recruitment activities. The system uses machine learning-based scam detection along with community reporting features to create a safer job search experience.

## 📌 Project Overview

Job Sentinel is an intelligent job scam detection platform that allows users to:

* Detect potentially fraudulent job postings.
* Report suspicious recruiters and job advertisements.
* View scam analysis results instantly.
* Maintain user profiles.
* Provide a safer environment for online job searching.

The platform combines a Flask backend, MySQL database, machine learning-based scam detection, and an interactive frontend.

---

## 🚀 Features

### 👤 User Authentication

* User Registration
* Secure Login System
* Profile Management
* Password Reset Functionality

### 🔍 Scam Detection

* Analyze job descriptions using Machine Learning
* Detect suspicious keywords and patterns
* Provide scam probability predictions
* Instant result generation

### 🚨 Scam Reporting

* Report fraudulent job postings
* Maintain scam report records
* Help protect other job seekers

### 📊 Dashboard

* Job Seeker Homepage
* Recruiter Homepage
* Admin Homepage
* User Profile Management

---

## 🏗️ Project Structure

```text
Job-Sentinel/
│
├── backend/
│   ├── __init__.py
│   ├── app.py
│   └── scam_detection.py
│
├── frontend/
│   ├── assets/
│   │   ├── css/
│   │   └── images/
│   │
│   └── pages/
│       ├── homepage.html
│       ├── login.html
│       ├── signup.html
│       ├── profile.html
│       ├── forgot-password.html
│       ├── reset-password.html
│       ├── admin_homepage.html
│       ├── recruiter_homepage.html
│       └── job_seeker_homepage.html
│
├── data/
│   ├── agile_project.sql
│   └── fake_job_postings.csv
│
├── docs/
│   ├── README_SETUP.md
│   └── Project Documentation
│
├── er diagrams/
│   └── agile_project_er_diagram.html
│
├── app.py
├── requirements.txt
└── README.md
```

---

## 🛠️ Technologies Used

### Frontend

* HTML5
* CSS3
* JavaScript

### Backend

* Python
* Flask

### Database

* MySQL

### Machine Learning

* Scikit-learn
* Pandas
* NumPy

### Development Tools

* VS Code
* Git
* GitHub

---

## 📂 Database Setup

### Step 1: Create Database

```sql
CREATE DATABASE agile_project;
USE agile_project;
```

### Step 2: Import Database

Import:

```text
data/agile_project.sql
```

using MySQL Workbench or phpMyAdmin.

---

## ⚙️ Installation

### Clone Repository

```bash
git clone https://github.com/Priya-6124/Job-Sentinel.git
cd Job-Sentinel
```

### Create Virtual Environment

```bash
python -m venv venv
```

### Activate Virtual Environment

Windows:

```bash
venv\Scripts\activate
```

Linux/Mac:

```bash
source venv/bin/activate
```

### Install Dependencies

```bash
pip install -r requirements.txt
```

---

## ▶️ Run the Project

Start the Flask application:

```bash
python app.py
```

or

```bash
python backend/app.py
```

The application will run on:

```text
http://localhost:5000
```

---

## 🧠 Machine Learning Module

The scam detection module:

* Trains on job posting datasets.
* Uses text preprocessing techniques.
* Predicts whether a job posting is legitimate or fraudulent.
* Returns confidence scores for analysis.

Dataset used:

```text
fake_job_postings.csv
```

---

## 📸 Screens

* Home Page
* Login Page
* Registration Page
* Job Seeker Dashboard
* Recruiter Dashboard
* Admin Dashboard
* Profile Management
* Scam Detection Interface

---

## 🔐 Security Features

* Password Hashing
* Input Validation
* SQL Injection Prevention
* User Authentication
* Secure Session Handling

---

## 📈 Future Enhancements

* Email Verification
* OTP Authentication
* Resume Analysis
* AI Chatbot Support
* Real-time Scam Alerts
* Advanced Fraud Analytics
* Recruiter Verification System

---

## 👩‍💻 Author

**Priya Kumari**

### Project

Job Sentinel – AI-Powered Job Scam Detection and Reporting Platform

from backend.app import app


if __name__ == '__main__':
    print("Starting Flask server...")
    print("Make sure MySQL is running and the database 'agile_project' exists.")
    print("Update DB_CONFIG in backend/app.py with your MySQL credentials.")
    app.run(debug=True, port=5000)

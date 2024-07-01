Compliance Management System
Overview
Welcome to the Compliance Management System! This application is designed to streamline and enhance your compliance operations through a comprehensive and user-friendly interface. It integrates AI-driven features, risk assessments, regulatory updates, training modules, and audit logs, all accessible via a modern web application.


Features
User Authentication: Secure login and registration with JWT.
AI Chatbot: Powered by OpenAI for intelligent responses and guidance.
Risk Assessments: Conduct and manage risk assessments efficiently.
Regulatory Updates: Stay updated with the latest regulations.
Training Modules: Access and manage compliance training programs.
Audit Logs: Maintain detailed records of compliance activities.
Compliance Reports: Generate and review comprehensive reports.
Technologies Used
Backend: Flask, SQLAlchemy, Bcrypt, JWT, OpenAI API
Frontend: React, React Router, Axios
Database: SQLite (easily extendable to other databases)
Styling: CSS
Getting Started
Prerequisites
Python 3.7+
Node.js 14+
Installation
Backend Setup
Navigate to the backend directory:

sh
Copy code
cd backend
Install the required Python packages:

sh
Copy code
pip install -r requirements.txt
Create a .env file with the following environment variables:

env
Copy code
SECRET_KEY=your_secret_key
JWT_SECRET_KEY=your_jwt_secret_key
OPENAI_API_KEY=your_openai_api_key
Run the Flask app:

sh
Copy code
flask run
Frontend Setup
Navigate to the frontend directory:

sh
Copy code
cd frontend
Install the required Node.js packages:

sh
Copy code
npm install
Create a .env file with the following environment variable:

env
Copy code
REACT_APP_API_URL=http://localhost:5000
Start the React app:

sh
Copy code
npm start
Usage
Access the Frontend: http://localhost:3000
Access the Backend API: http://localhost:5000
Project Structure
bash
Copy code
compliance-management-system/
├── backend/
│   ├── app.py
│   ├── models.py
│   ├── requirements.txt
│   └── .env
├── frontend/
│   ├── public/
│   │   ├── index.html
│   ├── src/
│   │   ├── App.css
│   │   ├── App.js
│   │   ├── index.js
│   │   ├── components/
│   │   │   ├── Chat.js
│   │   ├── pages/
│   │   │   ├── Home.js
│   │   │   ├── Login.js
│   │   │   ├── Profile.js
│   │   │   ├── RiskAssessments.js
│   │   │   ├── RegulatoryUpdates.js
│   │   │   ├── TrainingModules.js
│   │   │   ├── AuditLogs.js
│   ├── .env
│   ├── .gitignore
│   ├── package.json
│   ├── README.md
└── .gitignore
Contributing
We welcome contributions to enhance the functionality and user experience of the Compliance Management System. If you have suggestions or improvements, please feel free to open an issue or submit a pull request.

License
This project is licensed under the MIT License. See the LICENSE file for details.

Contact
For any questions or feedback, please contact yourname@example.com.


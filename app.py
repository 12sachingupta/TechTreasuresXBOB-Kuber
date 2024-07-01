import random
import re
from datetime import datetime, timedelta
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from functools import wraps
import openai

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///complianceai.db'
db = SQLAlchemy(app)

# Set your OpenAI API key here
openai.api_key = 'your_openai_api_key'

# Database models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # 'customer' or 'employee'

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    transaction_type = db.Column(db.String(20), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    action = db.Column(db.String(100), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class ComplianceReport(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    report_type = db.Column(db.String(50), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# JWT token required decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.filter_by(id=data['user_id']).first()
        except:
            return jsonify({'message': 'Token is invalid!'}), 401
        return f(current_user, *args, **kwargs)
    return decorated

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    hashed_password = generate_password_hash(data['password'], method='sha256')
    new_user = User(username=data['username'], password=hashed_password, role=data['role'])
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'New user created!'})

@app.route('/login', methods=['POST'])
def login():
    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        return jsonify({'message': 'Could not verify'}), 401
    user = User.query.filter_by(username=auth.username).first()
    if not user:
        return jsonify({'message': 'User not found'}), 401
    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'user_id': user.id, 'exp': datetime.utcnow() + timedelta(hours=24)},
                           app.config['SECRET_KEY'], algorithm="HS256")
        return jsonify({'token': token, 'role': user.role})
    return jsonify({'message': 'Could not verify'}), 401

@app.route('/api/chat', methods=['POST'])
@token_required
def chat(current_user):
    data = request.get_json()
    user_message = data['message']
    
    # Use OpenAI to generate a response
    response = get_openai_response(user_message, current_user.role)
    
    # Log the interaction
    log = AuditLog(user_id=current_user.id, action=f"Chat: {user_message}")
    db.session.add(log)
    db.session.commit()
    
    return jsonify({"response": response})

def get_openai_response(user_message, user_role):
    prompt = f"You are ComplianceAI, an AI assistant for banking compliance and auditing. The user is a {user_role}. Respond to the following message:\n\nUser: {user_message}\n\nComplianceAI:"
    
    response = openai.Completion.create(
        engine="text-davinci-002",
        prompt=prompt,
        max_tokens=150,
        n=1,
        stop=None,
        temperature=0.7,
    )
    
    return response.choices[0].text.strip()

@app.route('/api/transaction', methods=['POST'])
@token_required
def make_transaction(current_user):
    data = request.get_json()
    new_transaction = Transaction(
        user_id=current_user.id,
        amount=data['amount'],
        transaction_type=data['type']
    )
    db.session.add(new_transaction)
    db.session.commit()
    
    log = AuditLog(user_id=current_user.id, action=f"Transaction: {data['type']} {data['amount']}")
    db.session.add(log)
    db.session.commit()
    
    return jsonify({'message': 'Transaction recorded successfully'})

@app.route('/api/transactions', methods=['GET'])
@token_required
def get_transactions(current_user):
    transactions = Transaction.query.filter_by(user_id=current_user.id).all()
    return jsonify([{
        'id': t.id,
        'amount': t.amount,
        'type': t.transaction_type,
        'timestamp': t.timestamp
    } for t in transactions])

@app.route('/api/compliance_check', methods=['POST'])
@token_required
def compliance_check(current_user):
    if current_user.role != 'employee':
        return jsonify({'message': 'Unauthorized'}), 403
    
    data = request.get_json()
    transaction_id = data['transaction_id']
    transaction = Transaction.query.get(transaction_id)
    
    if not transaction:
        return jsonify({'message': 'Transaction not found'}), 404
    
    # Perform mock compliance check
    is_compliant = random.choice([True, False])
    reason = "Transaction follows AML guidelines" if is_compliant else "Suspicious activity detected"
    
    log = AuditLog(user_id=current_user.id, action=f"Compliance check: Transaction {transaction_id}")
    db.session.add(log)
    db.session.commit()
    
    return jsonify({
        'transaction_id': transaction_id,
        'is_compliant': is_compliant,
        'reason': reason
    })

@app.route('/api/generate_report', methods=['POST'])
@token_required
def generate_report(current_user):
    if current_user.role != 'employee':
        return jsonify({'message': 'Unauthorized'}), 403
    
    data = request.get_json()
    report_type = data['report_type']
    
    # Generate mock report content
    report_content = f"This is a {report_type} report generated on {datetime.utcnow()}."
    
    new_report = ComplianceReport(
        user_id=current_user.id,
        report_type=report_type,
        content=report_content
    )
    db.session.add(new_report)
    db.session.commit()
    
    log = AuditLog(user_id=current_user.id, action=f"Generated report: {report_type}")
    db.session.add(log)
    db.session.commit()
    
    return jsonify({'message': 'Report generated successfully', 'report_id': new_report.id})

@app.route('/api/get_report/<int:report_id>', methods=['GET'])
@token_required
def get_report(current_user, report_id):
    report = ComplianceReport.query.get(report_id)
    if not report:
        return jsonify({'message': 'Report not found'}), 404
    
    return jsonify({
        'id': report.id,
        'type': report.report_type,
        'content': report.content,
        'timestamp': report.timestamp
    })

@app.route('/api/risk_assessment', methods=['POST'])
@token_required
def risk_assessment(current_user):
    data = request.get_json()
    assessment_type = data['assessment_type']
    
    # Perform mock risk assessment
    risk_level = random.choice(['Low', 'Medium', 'High'])
    assessment_result = f"Risk assessment for {assessment_type}: {risk_level} risk"
    
    log = AuditLog(user_id=current_user.id, action=f"Risk assessment: {assessment_type}")
    db.session.add(log)
    db.session.commit()
    
    return jsonify({
        'assessment_type': assessment_type,
        'risk_level': risk_level,
        'result': assessment_result
    })

@app.route('/api/regulatory_updates', methods=['GET'])
@token_required
def get_regulatory_updates(current_user):
    # Mock regulatory updates
    updates = [
        {"area": "AML", "update": "New guidelines for monitoring crypto transactions effective next month."},
        {"area": "KYC", "update": "Updated requirements for customer identification in online banking."},
        {"area": "Data Privacy", "update": "Stricter rules for handling customer data across borders introduced."}
    ]
    return jsonify(updates)

@app.route('/api/audit_trail', methods=['GET'])
@token_required
def get_audit_trail(current_user):
    if current_user.role != 'employee':
        return jsonify({'message': 'Unauthorized'}), 403
    
    audit_logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(50).all()
    return jsonify([{
        'id': log.id,
        'user_id': log.user_id,
        'action': log.action,
        'timestamp': log.timestamp
    } for log in audit_logs])

@app.route('/api/document_analysis', methods=['POST'])
@token_required
def document_analysis(current_user):
    data = request.get_json()
    document_text = data['document_text']
    
    # Perform mock document analysis
    analysis_result = "Document analysis complete. No compliance issues detected."
    
    log = AuditLog(user_id=current_user.id, action="Document analysis performed")
    db.session.add(log)
    db.session.commit()
    
    return jsonify({
        'result': analysis_result
    })

@app.route('/api/compliance_training', methods=['GET'])
@token_required
def get_compliance_training(current_user):
    # Mock compliance training modules
    training_modules = [
        {"title": "AML Basics", "duration": "2 hours"},
        {"title": "KYC Procedures", "duration": "1.5 hours"},
        {"title": "Data Privacy Regulations", "duration": "3 hours"},
        {"title": "Fraud Detection Techniques", "duration": "2.5 hours"}
    ]
    return jsonify(training_modules)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
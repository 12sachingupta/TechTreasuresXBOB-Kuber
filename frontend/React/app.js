import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { BrowserRouter as Router, Route, Switch, Link } from 'react-router-dom';
import './App.css';

const App = () => {
  const [user, setUser] = useState(null);

  useEffect(() => {
    const token = localStorage.getItem('token');
    if (token) {
      axios.get('/api/user', { headers: { 'Authorization': `Bearer ${token}` } })
        .then(response => setUser(response.data))
        .catch(error => console.error(error));
    }
  }, []);

  return (
    <Router>
      <div className="App">
        <header className="App-header">
          <h1>Compliance Management System</h1>
          <nav>
            <Link to="/">Home</Link>
            <Link to="/risk-assessments">Risk Assessments</Link>
            <Link to="/regulatory-updates">Regulatory Updates</Link>
            <Link to="/training-modules">Training Modules</Link>
            <Link to="/audit-logs">Audit Logs</Link>
            <Link to="/profile">Profile</Link>
            <Link to="/login">Login</Link>
          </nav>
        </header>
        <main>
          <Switch>
            <Route path="/" exact component={Home} />
            <Route path="/risk-assessments" component={RiskAssessments} />
            <Route path="/regulatory-updates" component={RegulatoryUpdates} />
            <Route path="/training-modules" component={TrainingModules} />
            <Route path="/audit-logs" component={AuditLogs} />
            <Route path="/profile" component={Profile} />
            <Route path="/login" component={Login} />
          </Switch>
        </main>
      </div>
    </Router>
  );
};

const Home = () => <div>Welcome to the Compliance Management System</div>;

const RiskAssessments = () => <div>Risk Assessments Page</div>;

const RegulatoryUpdates = () => <div>Regulatory Updates Page</div>;

const TrainingModules = () => <div>Training Modules Page</div>;

const AuditLogs = () => <div>Audit Logs Page</div>;

const Profile = () => <div>Profile Page</div>;

const Login = () => <div>Login Page</div>;

export default App;

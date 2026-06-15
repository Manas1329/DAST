// Utility for handling shared states (Auth)
const API_BASE = 'http://127.0.0.1:8002/api/v1';

const Auth = {
  getToken: () => localStorage.getItem('dast_token'),
  setToken: (token) => localStorage.setItem('dast_token', token),
  clearToken: () => localStorage.removeItem('dast_token'),
  
  async getUser() {
    const token = this.getToken();
    if (!token) return null;
    
    try {
      const res = await fetch(`${API_BASE}/me`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        return await res.json();
      } else {
        this.clearToken();
        return null;
      }
    } catch (e) {
      console.error("Auth error:", e);
      return null;
    }
  },
  
  async login(username, password) {
    const res = await fetch(`${API_BASE}/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password })
    });
    
    if (res.ok) {
      const data = await res.json();
      this.setToken(data.token);
      return true;
    }
    const err = await res.json();
    throw new Error(err.detail || "Login failed");
  },
  
  async register(username, email, password) {
    const res = await fetch(`${API_BASE}/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, email, password })
    });
    
    if (res.ok) {
      return true;
    }
    const err = await res.json();
    throw new Error(err.detail || "Registration failed");
  }
};

// Global active user object
window.currentUser = null;

// Update Navbar based on Auth state
async function initNavbar() {
  window.currentUser = await Auth.getUser();
  const navLinks = document.getElementById('auth-nav-links');
  if (!navLinks) return;
  
  if (window.currentUser) {
    navLinks.innerHTML = `
      <span style="color: var(--text-muted); font-size: 0.85rem; margin-right: 1rem;">
        Welcome, ${window.currentUser.username} ${window.currentUser.is_pro ? '<span style="color:var(--brand-emerald)">[PRO]</span>' : ''}
      </span>
      <a href="dashboard.html" class="btn btn-primary" style="padding: 0.4rem 1rem;">Dashboard</a>
      <a href="#" id="logout-btn" style="color: var(--brand-rose); font-size: 0.85rem; text-decoration: none; margin-left: 1rem; font-weight: 500;">Logout</a>
    `;
    
    document.getElementById('logout-btn').addEventListener('click', (e) => {
      e.preventDefault();
      Auth.clearToken();
      window.location.reload();
    });
  } else {
    navLinks.innerHTML = `
      <a href="auth.html">Sign In</a>
      <a href="auth.html" class="btn btn-primary" style="padding: 0.4rem 1rem;">Get Started</a>
    `;
  }
}

// Ensure the navbar logic runs on every page
document.addEventListener('DOMContentLoaded', initNavbar);

const express = require('express');
const path = require('path');
const cors = require('cors');
const app = express();

// Middlewares
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Importar rutas API
const authRoutes = require('./routes/auth');
app.use('/api', authRoutes);

// Middleware para verificar autenticación en rutas frontend
const checkAuth = (req, res, next) => {
  // Esta es una verificación básica, en producción usa tu middleware de autenticación JWT
  if (req.path === '/' || req.path === '/register' || req.path === '/login.html') {
    return next();
  }
  // Para otras rutas, verificaríamos el token JWT
  next();
};

// Configuración de rutas para el frontend
app.get('/', checkAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/register', checkAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

app.get('/dashboard', checkAuth, (req, res) => {
  // Verificación adicional podrías implementar aquí
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});


// Iniciar servidor
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ Servidor listo en http://localhost:${PORT}`);
});
async function refreshAccessToken() {
  const refreshToken = localStorage.getItem('refreshToken');
  if (!refreshToken) return null;

  try {
    const response = await fetch('/api/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refreshToken })
    });
    const data = await response.json();
    if (response.ok) {
      localStorage.setItem('token', data.accessToken);
      return data.accessToken;
    } else {
      // Refresh token inválido o expirado, obligar login
      localStorage.removeItem('token');
      localStorage.removeItem('refreshToken');
      localStorage.removeItem('user');
      window.location.href = '/login.html';
      return null;
    }
  } catch {
    return null;
  }
}

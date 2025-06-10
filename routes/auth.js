const express = require('express');
const router = express.Router(); // Esta línea es crucial
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const pool = require('../db');
require('dotenv').config();


// Lista negra de tokens (en producción usa Redis)
const tokenBlacklist = new Set();

// Proteger rutas
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) return res.sendStatus(401);
  if (tokenBlacklist.has(token)) return res.sendStatus(403);
  
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

// Registro mejorado
router.post('/register', async (req, res) => {
  const { username, email, password, rol_id = 2 } = req.body;

  // Validaciones mejoradas
  if (!username || !password || !email) {
    return res.status(400).json({ error: 'Todos los campos son requeridos' });
  }

  if (password.length < 8) {
    return res.status(400).json({ error: 'La contraseña debe tener al menos 8 caracteres' });
  }

  try {
    // Verifica si el usuario ya existe
    const [userExists] = await pool.query(
      'SELECT id FROM cliente WHERE username = ? OR email = ?', 
      [username, email]
    );
    
    if (userExists.length > 0) {
      return res.status(400).json({ error: 'El usuario o email ya existe' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const [result] = await pool.query(
      'INSERT INTO cliente (username, email, password, rol_id) VALUES (?, ?, ?, ?)',
      [username, email, hashedPassword, rol_id]
    );
    
    res.status(201).json({ 
      success: true,
      message: 'Usuario registrado con éxito',
      userId: result.insertId 
    });
  } catch (err) {
    console.error('Error en registro:', err);
    res.status(500).json({ 
      error: 'Error en el registro',
      details: err.message 
    });
  }
});

router.post('/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    const [rows] = await pool.query('SELECT * FROM cliente WHERE username = ?', [username]);
    if (rows.length === 0) return res.status(401).json({ error: 'Credenciales inválidas' });

    const user = rows[0];
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) return res.status(401).json({ error: 'Credenciales inválidas' });

    const token = jwt.sign(
      { id: user.id, username: user.username, rol_id: user.rol_id },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    res.json({ 
      token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        rol_id: user.rol_id
      }
    });
  } catch (err) {
    res.status(500).json({ error: 'Error en el servidor' });
  }
});


// Ruta de logout
router.post('/logout', authenticateToken, (req, res) => {
  const token = req.headers['authorization'].split(' ')[1];
  tokenBlacklist.add(token);
  res.json({ message: 'Sesión cerrada exitosamente' });
});

// Ruta protegida de ejemplo
router.get('/profile', authenticateToken, (req, res) => {
  res.json({ 
    user: req.user,
    message: 'Información protegida' 
  });
});
module.exports = router; // Esta línea debe estar al final
router.get('/verify-token', authenticateToken, (req, res) => {
  // Si pasa el middleware authenticateToken, el token es válido
  res.json({ valid: true, user: req.user });
});
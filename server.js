import express from 'express';
import dotenv from 'dotenv';
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
import bodyParser from 'body-parser';
import { 
  syncUserToMySQL,
  findOrCreateUser,
  findUserById,
  checkGlobalChatbotQuota,
  incrementChatbotMessagesUsed,
  getUserStats,
  mysqlPool, // <-- Ajouté ici
  updateConversationTitleMySQL,
  deleteConversationMySQL,
  getConversationsForUserBot, // Ajouté
  getBotById,
  getMessagesForUserBot, // Ajouté
  getUserBotPreferences, // Ajouté
  saveQuizResult,
  getQuizResultsForUser,
  setMaintenance,
  getMaintenance
} from './database.js';
import cors from 'cors';
import openai from './openai.js';
import path from 'path';
import { fileURLToPath } from 'url';
import jwt from 'jsonwebtoken';
import passport from 'passport';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import fs from 'fs';


dotenv.config();

const app = express();

// Augmente la limite de taille du body parser à 2mb
app.use(bodyParser.json({ limit: '2mb' }));
app.use(bodyParser.urlencoded({ limit: '2mb', extended: true }));

// Désactive l'ETag globalement pour éviter les 304 (important pour Safari/cookies)
app.disable('etag');

app.set('trust proxy', 1);

// Middleware pour vérifier le JWT dans l'en-tête Authorization
function authenticateJWT(req, res, next) {
  if (req.method === 'OPTIONS') {
    return next();
  }
  const authHeader = req.headers['authorization'];
  console.log('--- [AUTH] ---');
  console.log('Authorization header reçu:', authHeader);
  if (!authHeader) {
    console.log('Aucun header Authorization reçu');
    return res.status(401).json({ message: 'Token manquant' });
  }
  const token = authHeader.split(' ')[1];
  console.log('Token extrait:', token);
  if (!token) {
    console.log('Header Authorization mal formé');
    return res.status(401).json({ message: 'Token manquant' });
  }
  const JWT_SECRET = process.env.JWT_SECRET || 'une_clé_ultra_secrète';
  jwt.verify(token, JWT_SECRET, async (err, decoded) => {
    if (err) {
      console.log('Erreur de vérification JWT:', err.message);
      return res.status(401).json({ message: 'Token invalide ou expiré', error: err.message });
    }
    console.log('Payload décodé:', decoded);
    // On peut aller chercher l'utilisateur en base si besoin
    const user = await findUserById(decoded.id);
    if (!user) {
      console.log('Utilisateur non trouvé pour l’ID:', decoded.id);
      return res.status(404).json({ message: 'Utilisateur non trouvé' });
    }
    console.log('Utilisateur trouvé:', user.id, user.email);
    req.user = user;
    next();
  });
}

// Middleware pour vérifier l'admin
function requireAdmin(req, res, next) {
  if (!req.user || !req.user.isAdmin) {
    return res.status(403).json({ message: 'Accès réservé à l’admin' });
  }
  next();
}

// Configuration CORS - Origines autorisées
const allowedOrigins = [
  'https://www.quran-pro.harrmos.com',
  'https://www.ummati.pro',
  'https://quran-pro.harrmos.com',
  'https://ummati.pro',
  'https://ummatiios.onrender.com',
  'http://localhost:5173',
  'http://localhost:3000',
  "capacitor://localhost",
  "http://localhost",
  // Ajoute ici d'autres domaines si besoin (Vercel, Netlify, etc.)
];

// Ajouter FRONTEND_URL depuis les variables d'environnement si défini
if (process.env.FRONTEND_URL) {
  const frontendUrl = process.env.FRONTEND_URL;
  if (!allowedOrigins.includes(frontendUrl)) {
    allowedOrigins.push(frontendUrl);
  }
  // Ajouter aussi la version avec www si applicable
  if (frontendUrl.startsWith('https://') && !frontendUrl.includes('www.')) {
    allowedOrigins.push(frontendUrl.replace('https://', 'https://www.'));
  }
}

const corsOptions = {
  origin: function (origin, callback) {
    console.log('CORS origin:', origin);
    // Autorise les requêtes sans origin (ex: mobile, redirection OAuth)
    // Autorise aussi les origines Capacitor (capacitor://localhost, capacitor://, etc.)
    if (!origin || 
        allowedOrigins.includes(origin) ||
        origin.startsWith('capacitor://') ||
        origin.startsWith('ionic://') ||
        origin.includes('localhost') ||
        origin.includes('127.0.0.1')) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true, // Important pour les cookies HttpOnly si utilisés
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
};
app.use(cors(corsOptions));

// Ajouter le middleware pour parser le JSON
app.use(express.json());

// Configure Google OAuth strategy
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const JWT_SECRET = process.env.JWT_SECRET || 'une_clé_ultra_secrète';

// Utiliser TOUJOURS Render (pas de localhost)
const BACKEND_URL = process.env.BACKEND_URL || 'https://ummatiios.onrender.com';
const FRONTEND_URL = process.env.FRONTEND_URL || 'https://ummati.pro';
const isDevelopment = false; // Toujours en production (Render)

// Debug de l'environnement
console.log('=== ENVIRONMENT DEBUG ===');
console.log('NODE_ENV:', process.env.NODE_ENV);
console.log('RENDER:', process.env.RENDER);
console.log('PORT:', process.env.PORT);
console.log('BACKEND_URL:', BACKEND_URL);
console.log('FRONTEND_URL:', FRONTEND_URL);
console.log('⚠️ NOTE: Configuration utilise TOUJOURS Render (pas de localhost)');
console.log('========================');


// Configurer le middleware de session


// Ajout de logs pour la configuration de session

// Vérifier que les variables Google OAuth sont définies
if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET) {
  console.error('⚠️  ERREUR: GOOGLE_CLIENT_ID et GOOGLE_CLIENT_SECRET doivent être définis dans les variables d\'environnement');
  console.error('⚠️  L\'authentification Google ne fonctionnera pas sans ces variables');
}

// GoogleStrategy sera configuré dynamiquement dans la route /auth/google
// On garde une instance par défaut pour la compatibilité
passport.use(new GoogleStrategy({
  clientID: GOOGLE_CLIENT_ID,
  clientSecret: GOOGLE_CLIENT_SECRET,
  callbackURL: `${BACKEND_URL}/auth/google/callback`,
}, async (accessToken, refreshToken, profile, done) => {
  try {
    // On crée ou récupère l'utilisateur dans la base
    const user = await findOrCreateUser(profile.id, profile.displayName, profile.emails[0].value);
    return done(null, user);
  } catch (err) {
    return done(err, null);
  }
}));

app.use(passport.initialize());

// Endpoint de health check pour vérifier la connectivité
app.get('/health', (req, res) => {
  res.status(200).json({ 
    status: 'ok', 
    timestamp: new Date().toISOString(),
    server: 'running'
  });
});

// Initialiser Passport et la gestion de session


// Sérialisation et désérialisation de l'utilisateur (déplacées depuis database.js)


// Initialiser la base de données au démarrage du serveur

// Fonction utilitaire pour ajouter un message dans MySQL
async function addMessageMySQL(userId, botId, conversationId, sender, text, context = null) {
  try {
    await mysqlPool.query(
      'INSERT INTO messages (userId, botId, conversationId, sender, text, context) VALUES (?, ?, ?, ?, ?, ?)',
      [userId, botId, conversationId, sender, text, context ? JSON.stringify(context) : null]
    );
  } catch (error) {
    console.error('Erreur lors de l\'ajout du message MySQL:', error);
    throw error;
  }
}

// Désactive le cache pour la route /auth/status (important pour Safari/cookies)
app.use('/auth/status', (req, res, next) => {
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.set('Pragma', 'no-cache');
  res.set('Expires', '0');
  res.set('Surrogate-Control', 'no-store');
  next();
});
// Route pour vérifier l'état de l'authentification (pour le frontend)
app.get('/auth/status', authenticateJWT, async (req, res) => {
  const responseUser = {
    id: req.user.id,
    name: req.user.name || req.user.username,
    email: req.user.email,
    username: req.user.username, // Ajouté
    profile_picture: req.user.profile_picture, // Ajouté
    mysql_id: req.user.mysql_id
  };
  res.status(200).json({ user: responseUser });
});

// Route pour initier l'authentification Google
app.get('/auth/google', (req, res, next) => {
  // Détecter si c'est une requête mobile
  const platform = req.query.platform;
  const isMobile = platform === 'mobile' || 
                   req.headers['user-agent']?.includes('Capacitor') ||
                   req.headers['user-agent']?.includes('Mobile');
  
  // Pour mobile, utiliser le redirect URI spécial Google
  // Format: com.googleusercontent.apps.<CLIENT_ID>:/auth/callback
  // Extraire l'ID du client (partie avant .apps.googleusercontent.com)
  const clientIdOnly = GOOGLE_CLIENT_ID.split('.apps.googleusercontent.com')[0];
  const redirectUriMobile = `com.googleusercontent.apps.${clientIdOnly}:/auth/callback`;
  const redirectUriWeb = `${BACKEND_URL}/auth/google/callback`;
  
  const redirectUri = isMobile ? redirectUriMobile : redirectUriWeb;
  
  console.log('🔐 [OAuth] Platform:', platform || 'web');
  console.log('🔐 [OAuth] Redirect URI:', redirectUri);
  
  // Passer le redirect URI à Passport
  passport.authenticate('google', { 
    scope: ['profile', 'email'],
    callbackURL: redirectUri,
    state: req.query.state
  })(req, res, next);
});
// Route de callback après l'authentification Google
app.get('/auth/google/callback',
  passport.authenticate('google', { session: false, failureRedirect: '/login' }),
  (req, res) => {
    // Générer un JWT pour l'utilisateur connecté
    const token = jwt.sign(
      { id: req.user.id, email: req.user.email },
      JWT_SECRET,
      { expiresIn: '7d' }
    );
    
    // Détecter si la requête vient d'une app mobile
    // Vérifier plusieurs sources : User-Agent, Referer, Origin, et paramètre state
    const userAgent = req.headers['user-agent'] || '';
    const referer = req.headers['referer'] || '';
    const origin = req.headers['origin'] || '';
    const state = req.query.state || '';
    
    console.log('🔍 [OAuth Callback] Détection mobile:', {
      userAgent: userAgent.substring(0, 100),
      referer: referer.substring(0, 100),
      origin: origin.substring(0, 100),
      state: state.substring(0, 50)
    });
    
    const isMobileApp = 
      userAgent.includes('Capacitor') || 
      userAgent.includes('Ummati') ||
      userAgent.includes('Mobile') ||
      referer.includes('capacitor://') ||
      referer.includes('ummati://') ||
      origin.includes('capacitor://') ||
      origin.includes('ummati://') ||
      state.includes('mobile') ||
      state.includes('native');
    
    console.log('📱 [OAuth Callback] isMobileApp:', isMobileApp);
    console.log('🔧 [OAuth Callback] BACKEND_URL actuel:', BACKEND_URL);
    console.log('🔧 [OAuth Callback] Toujours Render (pas de localhost)');
    
    // Si c'est une app mobile, rediriger vers la page HTML qui sauvegarde le token
    // Cette page sauvegardera le token dans localStorage et fermera le navigateur
    // L'app détectera le token via appStateChange quand elle revient au premier plan
    if (isMobileApp) {
      // App mobile - rediriger vers la page HTML qui sauvegarde le token
      const mobileCallbackUrl = `${BACKEND_URL}/auth/mobile-callback?token=${encodeURIComponent(token)}`;
      console.log('🔗 [OAuth Callback] App mobile - redirection vers mobile-callback:', mobileCallbackUrl.substring(0, 80) + '...');
      res.redirect(mobileCallbackUrl);
    } else {
      // App web - rediriger vers le frontend
      console.log('🌐 [OAuth Callback] App web - redirection vers frontend:', FRONTEND_URL);
      res.redirect(`${FRONTEND_URL}/auth/callback?token=${token}`);
    }
  }
);

// Route pour échanger le code d'autorisation OAuth contre un JWT (pour apps mobiles avec @byteowls/capacitor-oauth2)
app.post('/auth/google/exchange', async (req, res) => {
  try {
    const { code } = req.body;
    
    if (!code) {
      return res.status(400).json({ error: 'Code d\'autorisation manquant' });
    }
    
    console.log('🔄 [OAuth Exchange] Échange du code contre un token...');
    
    // Échanger le code contre un access token via Google
    // Extraire l'ID du client (partie avant .apps.googleusercontent.com)
    const clientIdOnly = GOOGLE_CLIENT_ID.split('.apps.googleusercontent.com')[0];
    const redirectUriMobile = `com.googleusercontent.apps.${clientIdOnly}:/auth/callback`;
    
    console.log('🔄 [OAuth Exchange] Client ID:', clientIdOnly);
    console.log('🔄 [OAuth Exchange] Redirect URI:', redirectUriMobile);
    
    const tokenResponse = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        code: code,
        client_id: GOOGLE_CLIENT_ID,
        client_secret: GOOGLE_CLIENT_SECRET,
        redirect_uri: redirectUriMobile,
        grant_type: 'authorization_code',
      }),
    });
    
    if (!tokenResponse.ok) {
      const error = await tokenResponse.text();
      console.error('❌ [OAuth Exchange] Erreur Google:', error);
      return res.status(400).json({ error: 'Échec de l\'échange du code', details: error });
    }
    
    const tokenData = await tokenResponse.json();
    const accessToken = tokenData.access_token;
    
    if (!accessToken) {
      return res.status(400).json({ error: 'Access token non reçu de Google' });
    }
    
    // Récupérer les informations du profil utilisateur
    const profileResponse = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    });
    
    if (!profileResponse.ok) {
      return res.status(400).json({ error: 'Échec de la récupération du profil' });
    }
    
    const profile = await profileResponse.json();
    
    // Créer ou récupérer l'utilisateur
    const user = await findOrCreateUser(profile.id, profile.name, profile.email);
    
    // Générer un JWT pour l'utilisateur
    const jwtToken = jwt.sign(
      { id: user.id, email: user.email },
      JWT_SECRET,
      { expiresIn: '7d' }
    );
    
    console.log('✅ [OAuth Exchange] Token JWT généré pour:', user.email);
    
    res.json({ 
      token: jwtToken,
      user: {
        id: user.id,
        email: user.email,
        name: user.name || profile.name,
      }
    });
  } catch (error) {
    console.error('❌ [OAuth Exchange] Erreur:', error);
    res.status(500).json({ error: 'Erreur lors de l\'échange du code', details: error.message });
  }
});

// Route pour le callback mobile - page HTML qui sauvegarde le token et ferme le navigateur
app.get('/auth/mobile-callback', (req, res) => {
  const token = req.query.token;
  if (!token) {
    return res.status(400).send('Token manquant');
  }
  
  // Échapper le token pour éviter les problèmes de syntaxe
  const escapedToken = String(token).replace(/'/g, "\\'").replace(/"/g, '\\"').replace(/\n/g, '\\n');
  
  // Page HTML qui sauvegarde le token dans localStorage et ferme le navigateur
  // L'app détectera le token via appStateChange quand elle revient au premier plan
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Connexion réussie</title>
      <style>
        body {
          font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
          display: flex;
          flex-direction: column;
          align-items: center;
          justify-content: center;
          min-height: 100vh;
          margin: 0;
          background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
          color: white;
          text-align: center;
          padding: 2rem;
        }
        .spinner {
          border: 4px solid rgba(255,255,255,0.3);
          border-top: 4px solid white;
          border-radius: 50%;
          width: 40px;
          height: 40px;
          animation: spin 1s linear infinite;
          margin: 0 auto 1rem;
        }
        @keyframes spin {
          0% { transform: rotate(0deg); }
          100% { transform: rotate(360deg); }
        }
      </style>
    </head>
    <body>
      <div class="spinner"></div>
      <h2>Connexion réussie !</h2>
      <p>Fermeture en cours...</p>
      <script>
        (async function() {
          const token = '${escapedToken}';
          
          console.log('🔐 [Callback] Sauvegarde du token...');
          console.log('🔐 [Callback] Token reçu:', token.substring(0, 30) + '...');
          
          // Sauvegarder dans localStorage
          try {
            localStorage.setItem('jwt', token);
            const saved = localStorage.getItem('jwt');
            console.log('✅ [Callback] Token sauvegardé dans localStorage:', saved ? saved.substring(0, 30) + '...' : 'ERREUR');
          } catch (e) {
            console.error('❌ [Callback] Erreur localStorage:', e);
          }
          
          // Essayer de sauvegarder dans Preferences via Capacitor (si disponible)
          // IMPORTANT: Dans le navigateur in-app, Capacitor peut ne pas être disponible
          // On va essayer plusieurs méthodes
          let savedInPreferences = false;
          
          // Méthode 1: Via window.Capacitor (si disponible dans le navigateur in-app)
          try {
            if (window.Capacitor && window.Capacitor.Plugins && window.Capacitor.Plugins.Preferences) {
              await window.Capacitor.Plugins.Preferences.set({
                key: 'jwt',
                value: token
              });
              console.log('✅ [Callback] Token sauvegardé dans Preferences (méthode 1)');
              savedInPreferences = true;
            }
          } catch (e) {
            console.log('⚠️ [Callback] Méthode 1 échouée:', e);
          }
          
          // Méthode 2: Via Capacitor global (si disponible)
          if (!savedInPreferences) {
            try {
              if (typeof Capacitor !== 'undefined' && Capacitor.Plugins && Capacitor.Plugins.Preferences) {
                await Capacitor.Plugins.Preferences.set({
                  key: 'jwt',
                  value: token
                });
                console.log('✅ [Callback] Token sauvegardé dans Preferences (méthode 2)');
                savedInPreferences = true;
              }
            } catch (e) {
              console.log('⚠️ [Callback] Méthode 2 échouée:', e);
            }
          }
          
          // Si on n'a pas pu sauvegarder dans Preferences, on affiche un message
          if (!savedInPreferences) {
            console.log('⚠️ [Callback] Impossible de sauvegarder dans Preferences - le token est dans localStorage uniquement');
            console.log('ℹ️ [Callback] L\'app devra vérifier localStorage via appStateChange');
          }
          
          // Essayer aussi de rediriger vers le deep link pour déclencher appUrlOpen
          // Si ça ne fonctionne pas, appStateChange détectera le token dans localStorage
          setTimeout(() => {
            try {
              // Essayer de rediriger vers le deep link
              const deepLink = 'ummati://auth/callback?token=' + encodeURIComponent(token);
              console.log('🔗 [Callback] Tentative de redirection vers deep link:', deepLink.substring(0, 50) + '...');
              
              // Essayer de fermer le navigateur d'abord, puis rediriger
              try {
                if (window.Capacitor && window.Capacitor.Plugins && window.Capacitor.Plugins.Browser) {
                  window.Capacitor.Plugins.Browser.close().then(() => {
                    console.log('✅ [Callback] Navigateur fermé, redirection vers deep link...');
                    // Après fermeture, essayer la redirection
                    setTimeout(() => {
                      try {
                        window.location.href = deepLink;
                      } catch (e) {
                        console.log('⚠️ [Callback] Impossible de rediriger vers deep link:', e);
                      }
                    }, 300);
                  }).catch((e) => {
                    console.log('⚠️ [Callback] Erreur lors de la fermeture du navigateur, redirection directe:', e);
                    // Si la fermeture échoue, essayer quand même la redirection
                    try {
                      window.location.href = deepLink;
                    } catch (e2) {
                      console.log('⚠️ [Callback] Impossible de rediriger vers deep link:', e2);
                    }
                  });
                } else {
                  // Si Capacitor n'est pas disponible, essayer quand même la redirection
                  console.log('⚠️ [Callback] Capacitor non disponible, redirection directe vers deep link');
                  window.location.href = deepLink;
                }
              } catch (e) {
                console.log('⚠️ [Callback] Erreur lors de la fermeture/redirection:', e);
              }
            } catch (e) {
              console.log('⚠️ [Callback] Erreur lors de la redirection vers deep link:', e);
            }
          }, 500);
        })();
      </script>
    </body>
    </html>
  `);
});

// Route de déconnexion
app.get('/logout', (req, res) => {
  res.status(200).json({ message: 'Déconnexion réussie (stateless JWT)' });
});

// ===================== ROUTES UTILISATEURS =====================
app.post('/api/users', async (req, res) => {
  try {
    const { email, username, preferences } = req.body;
    const [existingUsers] = await mysqlPool.execute(
      'SELECT id FROM users WHERE email = ?',
      [email]
    );
    if (existingUsers.length > 0) {
      const existingUser = existingUsers[0];
      return res.status(200).json({
        success: true,
        user: {
          id: existingUser.id,
          email,
          username,
          preferences: JSON.parse(existingUsers[0].preferences || '{}'),
          existing: true
        }
      });
    }
    const userId = require('crypto').randomUUID();
    const [result] = await mysqlPool.execute(
      'INSERT INTO users (id, email, username, preferences) VALUES (?, ?, ?, ?)',
      [userId, email, username, JSON.stringify(preferences || {})]
    );
    res.status(201).json({
      success: true,
      user: { id: userId, email, username, preferences, existing: false }
    });
  } catch (error) {
    res.status(500).json({ error: 'Erreur lors de la création de l\'utilisateur', details: error.message });
  }
});
app.get('/api/users/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    const [rows] = await mysqlPool.execute(
      'SELECT id, email, username, preferences, created_at, last_login FROM users WHERE id = ?',
      [userId]
    );
    if (rows.length === 0) {
      return res.status(404).json({ error: 'Utilisateur non trouvé' });
    }
    res.json({ success: true, user: rows[0] });
  } catch (error) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});
app.put('/api/users/:userId/preferences', authenticateJWT, async (req, res) => {
  try {
    const userId = req.user.id;
    const { preferences } = req.body;
    console.log('userId:', userId, typeof userId, 'params:', req.params.userId, typeof req.params.userId);
    if (!preferences) {
      return res.status(400).json({ success: false, message: 'Préférences manquantes' });
    }
    // Vérifier que l'utilisateur modifie bien ses propres préférences (comparaison en string)
    if (String(userId) !== String(req.params.userId)) {
      return res.status(403).json({ success: false, message: 'Accès interdit' });
    }
    console.log('UPDATE preferences for user', userId, preferences);
    await mysqlPool.execute(
      'UPDATE users SET preferences = ? WHERE id = ?',
      [JSON.stringify(preferences), userId]
    );
    res.json({ success: true, message: 'Préférences mises à jour.' });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Erreur lors de la mise à jour des préférences.' });
  }
});
// ===================== ROUTES STATISTIQUES =====================
app.post('/api/stats', authenticateJWT, async (req, res) => {
  console.log('POST /api/stats', req.body);
  try {
    const { userId, hasanat = 0, verses = 0, time = 0, pages = 0 } = req.body;
    if (hasanat === 0 && verses === 0 && time === 0 && pages === 0) {
      return res.json({ success: true, message: 'Aucune stat à incrémenter' });
    }
    
    // Utiliser la date locale au lieu de CURDATE() (UTC)
    const today = new Date();
    today.setHours(0,0,0,0); // Forcer à minuit
    const dateStr = today.toISOString().slice(0, 10); // 'YYYY-MM-DD'
    
    await mysqlPool.execute(
      'INSERT IGNORE INTO quran_stats (user_id, date) VALUES (?, ?)',
      [userId, dateStr]
    );
    await mysqlPool.execute(
      'CALL IncrementDailyStats(?, ?, ?, ?)',
      [userId, hasanat, verses, time]
    );
    if (pages > 0) {
      await mysqlPool.execute(
        'UPDATE quran_stats SET pages_read = pages_read + ? WHERE user_id = ? AND date = ?',
        [pages, userId, dateStr]
      );
    }
    res.json({ success: true, message: 'Stats mises à jour' });
  } catch (error) {
    console.error('Erreur SQL stats:', error); // Log détaillé
    res.status(500).json({ error: 'Erreur lors de la mise à jour des stats', details: error.message });
  }
});
// ===================== ROUTES PROGRESSION =====================
app.post('/api/progress', authenticateJWT, async (req, res) => {
  try {
    const { userId, surah, ayah } = req.body;
    const [result] = await mysqlPool.execute(
      'INSERT INTO reading_progress (user_id, surah, ayah) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE surah = VALUES(surah), ayah = VALUES(ayah)',
      [userId, surah, ayah]
    );
    res.json({ success: true, message: 'Progression sauvegardée' });
  } catch (error) {
    res.status(500).json({ error: 'Erreur lors de la sauvegarde' });
  }
});
app.get('/api/progress/:userId', authenticateJWT, async (req, res) => {
  if (req.user.id !== req.params.userId) {
    return res.status(403).json({ message: 'Accès interdit' });
  }
  try {
    const { userId } = req.params;
    const [rows] = await mysqlPool.execute(
      'SELECT surah, ayah, updated_at FROM reading_progress WHERE user_id = ?',
      [userId]
    );
    res.json({ success: true, progress: rows[0] || { surah: 1, ayah: 1, updated_at: null } });
  } catch (error) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});
// ===================== ROUTES HISTORIQUE =====================
app.post('/api/history', authenticateJWT, async (req, res) => {
  try {
    const { userId, surah, ayah, actionType, duration = 0 } = req.body;
    const [result] = await mysqlPool.execute(
      'INSERT INTO reading_history (user_id, surah, ayah, action_type, duration_seconds) VALUES (?, ?, ?, ?, ?)',
      [userId, surah, ayah, actionType, duration]
    );
    res.json({ success: true, message: 'Historique ajouté' });
  } catch (error) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});
app.get('/api/history/:userId/:limit', authenticateJWT, async (req, res) => {
  if (req.user.id !== req.params.userId) {
    return res.status(403).json({ message: 'Accès interdit' });
  }
  try {
    const { userId, limit } = req.params;
    const limitNum = Math.min(parseInt(limit) || 50, 100);
    const [rows] = await mysqlPool.execute(
      `SELECT surah, ayah, action_type, duration_seconds, created_at 
       FROM reading_history 
       WHERE user_id = ? 
       ORDER BY created_at DESC 
       LIMIT ?`,
      [userId, limitNum]
    );
    res.json({ success: true, history: rows });
  } catch (error) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});
// ===================== ROUTES FAVORIS =====================
app.post('/api/favorites', authenticateJWT, async (req, res) => {
  try {
    const userId = req.user.id;
    const { type, referenceId, referenceText, notes } = req.body;
    const [result] = await mysqlPool.execute(
      'INSERT INTO favorites (user_id, type, reference_id, reference_text, notes) VALUES (?, ?, ?, ?, ?)',
      [userId, type, referenceId, referenceText, notes]
    );
    res.json({ success: true, message: 'Favori ajouté' });
  } catch (error) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});
app.get('/api/favorites/:userId', authenticateJWT, async (req, res) => {
  if (req.user.id !== req.params.userId) {
    return res.status(403).json({ message: 'Accès interdit' });
  }
  try {
    const { userId } = req.params;
    const [rows] = await mysqlPool.execute(
      'SELECT * FROM favorites WHERE user_id = ? ORDER BY created_at DESC',
      [userId]
    );
    res.json({ success: true, favorites: rows });
  } catch (error) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});
app.delete('/api/favorites/:favoriteId', authenticateJWT, async (req, res) => {
  try {
    const { favoriteId } = req.params;
    const [result] = await mysqlPool.execute(
      'DELETE FROM favorites WHERE id = ?',
      [favoriteId]
    );
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Favori non trouvé' });
    }
    res.json({ success: true, message: 'Favori supprimé' });
  } catch (error) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});
// ===================== ROUTES SESSIONS =====================
app.post('/api/sessions/start', authenticateJWT, async (req, res) => {
  try {
    const { userId, deviceInfo } = req.body;
    const [result] = await mysqlPool.execute(
      'INSERT INTO reading_sessions (user_id, device_info) VALUES (?, ?)',
      [userId, JSON.stringify(deviceInfo || {})]
    );
    res.json({ success: true, sessionId: result.insertId, message: 'Session démarrée' });
  } catch (error) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});
app.put('/api/sessions/:sessionId/end', authenticateJWT, async (req, res) => {
  try {
    const { sessionId } = req.params;
    const { versesRead, hasanatEarned } = req.body;
    const [result] = await mysqlPool.execute(
      `UPDATE reading_sessions 
       SET end_time = NOW(), 
           duration_seconds = TIMESTAMPDIFF(SECOND, start_time, NOW()),
           verses_read = ?, 
           hasanat_earned = ? 
       WHERE id = ?`,
      [versesRead || 0, hasanatEarned || 0, sessionId]
    );
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Session non trouvée' });
    }
    res.json({ success: true, message: 'Session terminée' });
  } catch (error) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});
// ===================== ROUTES OBJECTIFS =====================
app.post('/api/goals', authenticateJWT, async (req, res) => {
  try {
    const userId = req.user.id;
    const { goalType, targetValue, startDate, endDate } = req.body;
    const [result] = await mysqlPool.execute(
      'INSERT INTO reading_goals (user_id, goal_type, target_value, start_date, end_date) VALUES (?, ?, ?, ?, ?)',
      [userId, goalType, targetValue, startDate, endDate]
    );
    res.json({ success: true, goalId: result.insertId, message: 'Objectif créé' });
  } catch (error) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});
app.get('/api/goals/:userId', authenticateJWT, async (req, res) => {
  if (req.user.id !== req.params.userId) {
    return res.status(403).json({ message: 'Accès interdit' });
  }
  try {
    const { userId } = req.params;
    const [rows] = await mysqlPool.execute(
      'SELECT * FROM reading_goals WHERE user_id = ? ORDER BY created_at DESC',
      [userId]
    );
    res.json({ success: true, goals: rows });
  } catch (error) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});
app.put('/api/goals/:goalId', authenticateJWT, async (req, res) => {
  try {
    const userId = req.user.id;
    const { goalId } = req.params;
    const { currentValue, isCompleted } = req.body;
    // Vérifier que l'objectif appartient à l'utilisateur
    const [rows] = await mysqlPool.execute('SELECT * FROM reading_goals WHERE id = ? AND user_id = ?', [goalId, userId]);
    if (!rows.length) {
      return res.status(404).json({ error: 'Objectif non trouvé' });
    }
    const [result] = await mysqlPool.execute(
      'UPDATE reading_goals SET current_value = ?, is_completed = ? WHERE id = ?',
      [currentValue, isCompleted, goalId]
    );
    res.json({ success: true, message: 'Objectif mis à jour' });
  } catch (error) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// Correction de la route GET /api/bots si getBots est async
app.get('/api/bots', async (req, res) => {
  try {
    const bots = await getBots();
    res.status(200).json(bots);
  } catch (error) {
    console.error('Erreur lors de la récupération des bots:', error);
    res.status(500).json({ message: 'Erreur lors de la récupération des bots' });
  }
});

// Incrémenter les stats quotidiennes
// app.post('/api/stats', async (req, res) => {
//   try {
//     const { userId, hasanat = 0, verses = 0, time = 0, pages = 0 } = req.body;
//     // Si aucune stat à incrémenter, ignorer la requête
//     if (hasanat === 0 && verses === 0 && time === 0 && pages === 0) {
//       return res.json({ success: true, message: 'Aucune stat à incrémenter' });
//     }
//     // S'assurer qu'une ligne existe pour l'utilisateur et la date du jour
//     await pool.execute(
//       'INSERT IGNORE INTO quran_stats (user_id, date) VALUES (?, CURDATE())',
//       [userId]
//     );
//     // Utiliser la procédure stockée
//     await pool.execute(
//       'CALL IncrementDailyStats(?, ?, ?, ?)',
//       [userId, hasanat, verses, time]
//     );
//     // Mettre à jour les pages si fournies
//     if (pages > 0) {
//       await pool.execute(
//         'UPDATE quran_stats SET pages_read = pages_read + ? WHERE user_id = ? AND date = CURDATE()',
//         [pages, userId]
//       );
//     }
//     res.json({ success: true, message: 'Stats mises à jour' });
//   } catch (error) {
//     console.error('Erreur mise à jour stats:', error);
//     res.status(500).json({ error: 'Erreur lors de la mise à jour des stats' });
//   }
// });


// ===================== CRUD DUA =====================

// Récupérer toutes les duas
app.get('/api/duas', authenticateJWT, requireAdmin, async (req, res) => {
  try {
    const [rows] = await mysqlPool.execute('SELECT * FROM duas ORDER BY created_at DESC');
    res.json({ duas: rows });
  } catch (error) {
    res.status(500).json({ message: 'Erreur lors de la récupération des duas.' });
  }
});

// Ajouter une dua
app.post('/api/duas', authenticateJWT, requireAdmin, async (req, res) => {
  const { title, arabic, translit, translation, category, audio } = req.body;
  if (!title || !arabic || !translation) {
    return res.status(400).json({ message: 'Champs obligatoires manquants.' });
  }
  try {
    const [result] = await mysqlPool.execute(
      'INSERT INTO duas (title, arabic, translit, translation, category, audio) VALUES (?, ?, ?, ?, ?, ?)',
      [title, arabic, translit || '', translation, category || 'other', audio || '']
    );
    res.status(201).json({ success: true, id: result.insertId });
  } catch (error) {
    res.status(500).json({ message: 'Erreur lors de l’ajout de la dua.' });
  }
});

// Supprimer une dua
app.delete('/api/duas/:id', authenticateJWT, requireAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    await mysqlPool.execute('DELETE FROM duas WHERE id = ?', [id]);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ message: 'Erreur lors de la suppression.' });
  }
});
// Route pour activer/désactiver la maintenance (admin uniquement)
app.post('/api/maintenance', authenticateJWT, requireAdmin, async (req, res) => {
  const { enabled, id, pwd } = req.body;
  try {
    await setMaintenance(enabled, id, pwd);
    res.json({ success: true, maintenance: { enabled, id, pwd } });
  } catch (e) {
    console.error('Erreur SQL maintenance:', e);
    res.status(500).json({ success: false, error: e.message });
  }
});

// Route pour lire l'état maintenance
app.get('/api/maintenance-status', async (req, res) => {
  try {
    const data = await getMaintenance();
    res.json(data);
  } catch (e) {
    res.json({ enabled: false, id: '', pwd: '' });
  }
}); 

// ===================== ROUTES QUIZZES =====================
// Liste tous les quiz
app.get('/api/quizzes', authenticateJWT, async (req, res) => {
  try {
    const [rows] = await mysqlPool.execute('SELECT * FROM quizzes ORDER BY created_at DESC');
    res.json({ success: true, quizzes: rows });
  } catch (error) {
    res.status(500).json({ error: 'Erreur lors de la récupération des quiz', details: error.message });
  }
});
// Détail d'un quiz
app.get('/api/quizzes/:id', authenticateJWT, async (req, res) => {
  try {
    const { id } = req.params;
    const [rows] = await mysqlPool.execute('SELECT * FROM quizzes WHERE id = ?', [id]);
    if (!rows.length) return res.status(404).json({ error: 'Quiz non trouvé' });
    res.json({ success: true, quiz: rows[0] });
  } catch (error) {
    res.status(500).json({ error: 'Erreur lors de la récupération du quiz', details: error.message });
  }
});
// Création d'un quiz (admin)
app.post('/api/quizzes', authenticateJWT, requireAdmin, async (req, res) => {
  try {
    const { theme, difficulty, title, description, questions } = req.body;
    if (!theme || !difficulty || !title || !questions) {
      return res.status(400).json({ error: 'Paramètres manquants' });
    }
    const [result] = await mysqlPool.execute(
      'INSERT INTO quizzes (theme, difficulty, title, description, questions) VALUES (?, ?, ?, ?, ?)',
      [theme, difficulty, title, description || '', JSON.stringify(questions)]
    );
    res.status(201).json({ success: true, quizId: result.insertId });
  } catch (error) {
    res.status(500).json({ error: 'Erreur lors de la création du quiz', details: error.message });
  }
});
// Edition d'un quiz (admin)
app.put('/api/quizzes/:id', authenticateJWT, requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { theme, difficulty, title, description, questions } = req.body;
    const [result] = await mysqlPool.execute(
      'UPDATE quizzes SET theme=?, difficulty=?, title=?, description=?, questions=?, updated_at=NOW() WHERE id=?',
      [theme, difficulty, title, description || '', JSON.stringify(questions), id]
    );
    if (result.affectedRows === 0) return res.status(404).json({ error: 'Quiz non trouvé' });
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Erreur lors de la modification du quiz', details: error.message });
  }
});
// Suppression d'un quiz (admin)
app.delete('/api/quizzes/:id', authenticateJWT, requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const [result] = await mysqlPool.execute('DELETE FROM quizzes WHERE id = ?', [id]);
    if (result.affectedRows === 0) return res.status(404).json({ error: 'Quiz non trouvé' });
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Erreur lors de la suppression du quiz', details: error.message });
  }
}); 

// ===================== ROUTES QUIZ =====================
app.get('/api/quiz/history', authenticateJWT, async (req, res) => {
  try {
    const userId = req.user.id;
    const results = await getQuizResultsForUser(userId);
    res.json({ success: true, history: results });
  } catch (error) {
    res.status(500).json({ error: 'Erreur lors de la récupération de l’historique', details: error.message });
  }
});
app.post('/api/quiz/result', authenticateJWT, async (req, res) => {
  try {
    const userId = req.user.id;
    const { theme, level, score, total, details, quiz_id } = req.body;
    if (!theme || !level || score === undefined || total === undefined || !quiz_id) {
      return res.status(400).json({ error: 'Paramètres manquants' });
    }
    await saveQuizResult(userId, theme, level, score, total, details, quiz_id);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Erreur lors de l’enregistrement du résultat', details: error.message });
  }
});
//Route pour les stats du jour
 app.get('/api/stats/:userId/today', async (req, res) => {
   try {
     const { userId } = req.params;
     const [rows] = await mysqlPool.execute(
       'SELECT * FROM quran_stats WHERE user_id = ? AND date = CURDATE()',
       [userId]
     );
     res.json({ success: true, stats: rows });
   } catch (error) {
     console.error('Erreur récupération stats today:', error);
     res.status(500).json({ error: 'Erreur serveur' });
   }
});
// Route pour créer un nouveau bot (admin uniquement)
app.post('/api/bots', authenticateJWT, requireAdmin, async (req, res) => {
  const { name, description, price, category, image, prompt } = req.body;
  
  try {
    const botId = await addBot(name, description, price, category, image, prompt);
    res.status(201).json({ message: 'Bot créé avec succès', botId });
  } catch (error) {
    console.error('Erreur lors de la création du bot:', error);
    res.status(500).json({ message: 'Erreur lors de la création du bot' });
  }
});

// Correction de la route PUT /api/bots/:id pour requireAdmin
app.put('/api/bots/:id', authenticateJWT, requireAdmin, async (req, res) => {
  const botId = Number(req.params.id);
  const { name, description, price, category, image, prompt } = req.body;
  try {
    await updateBot(botId, name, description, price, category, image, prompt);
    res.status(200).json({ message: 'Bot mis à jour avec succès' });
  } catch (error) {
    console.error('Erreur lors de la mise à jour du bot:', error);
    res.status(500).json({ message: 'Erreur lors de la mise à jour du bot' });
  }
});

// Correction de la route DELETE /api/bots/:id pour requireAdmin
app.delete('/api/bots/:id', authenticateJWT, requireAdmin, async (req, res) => {
  const botId = req.params.id;
  
  try {
    await deleteBot(botId);
    res.status(200).json({ message: 'Bot supprimé avec succès' });
  } catch (error) {
    console.error('Erreur lors de la suppression du bot:', error);
    res.status(500).json({ message: 'Erreur lors de la suppression du bot' });
  }
});

// Nouvelle route pour activer un bot pour un utilisateur


// Nouvelle route pour récupérer les messages pour un utilisateur et un bot spécifiques
app.get('/api/messages', authenticateJWT, async (req, res) => {
  console.log('=== Début de la requête /api/messages ===');
  console.log('Headers:', req.headers);
  console.log('Cookies:', req.cookies);
  console.log('Session (avant Passport): ', req.session);
  // Utilisateur authentifié via JWT
  const userId = req.user.id;
  const botId = Number(req.query.botId);
  const conversationId = Number(req.query.conversationId) || 0;

  if (!userId || isNaN(botId)) {
    console.error('/api/messages - Missing userId or invalid botId', { userId, botId });
    return res.status(400).json({ message: 'userId et botId sont requis' });
  }

  try {
    const messages = await getMessagesForUserBot(userId, botId, conversationId);
    console.log('/api/messages - Messages récupérés:', messages.length);
    res.status(200).json(messages);
  } catch (error) {
    console.error('Erreur lors de la récupération des messages:', error);
    res.status(500).json({ message: 'Erreur lors de la récupération des messages' });
  }
  console.log('=== Fin de la requête /api/messages ===');
});

// Route pour interagir avec l'API OpenAI (renommée en /api/chat)
app.post('/api/chat', authenticateJWT, async (req, res) => {
  console.log('=== Début de la requête /api/chat ===');
  console.log('Headers:', req.headers);
  console.log('Cookies:', req.cookies);
  console.log('Session (avant Passport): ', req.session);
  // On n'utilise plus Passport ici
  // console.log('isAuthenticated (après Passport): ', req.isAuthenticated());
  // console.log('User (après Passport): ', req.user);

  // Utilisateur authentifié via JWT
  const userId = req.user.id;
  console.log('/api/chat - Utilisateur authentifié, ID:', userId);

  // Vérification du quota global de messages chatbot
  const quota = await checkGlobalChatbotQuota(userId, req.user.email);
  if (!quota.canSend) {
    return res.status(402).json({ message: `Quota de messages gratuits dépassé. Veuillez acheter plus de messages pour continuer à utiliser le chatbot.` });
  }

  const { message, botId, conversationId, title } = req.body;
  const usedBotId = botId ? Number(botId) : 1;

  if (!message || usedBotId === undefined) {
    return res.status(400).json({ message: 'Message et botId sont requis' });
  }

  let currentConversationId = Number(conversationId);
  let conversationTitle = title;

  if (currentConversationId <= 0) {
    try {
      const newConvTitle = conversationTitle || 'Nouvelle conversation';
      // Création de la conversation dans MySQL
      const [result] = await mysqlPool.execute(
        'INSERT INTO conversations (userId, botId, title) VALUES (?, ?, ?)',
        [userId, usedBotId, newConvTitle]
      );
      currentConversationId = result.insertId;
      console.log('Nouvelle conversation créée avec ID (MySQL):', currentConversationId);
    } catch (convError) {
      console.error('Erreur lors de la création de la conversation (MySQL):', convError);
      return res.status(500).json({ 
        message: 'Erreur lors de la création de la conversation.',
        details: convError.message || 'Erreur inconnue'
      });
    }
  } else if (title && currentConversationId > 0) {
    try {
      await updateConversationTitleMySQL(userId, usedBotId, Number(conversationId), title);
      console.log(`Titre de la conversation ${currentConversationId} mis à jour.`);
    } catch (titleUpdateError) {
      console.error(`Erreur lors de la mise à jour du titre de la conversation ${currentConversationId}:`, titleUpdateError);
    }
  }

  try {
    // const bot = getBotById(usedBotId);
    // const prompt = bot.prompt || 'You are a helpful assistant.';
    const prompt = `Tu es un assistant islamique bienveillant. Tu expliques l'islam avec douceur, sagesse et respect. Tu cites toujours tes sources : versets du Coran (avec numéro de sourate et verset), hadiths authentiques (avec référence), ou avis de savants connus. Si tu ne connais pas la réponse, dis-le avec bienveillance. Tu t'exprimes comme un ami proche, rassurant et sincère. Et tu ne réponds à aucune question qui n'est pas islamique.`;

    // Récupérer les 10 derniers messages pour le contexte de cette conversation
    let conversationHistory = [];
    try {
      conversationHistory = await getMessagesForUserBot(userId, usedBotId, currentConversationId, 10);
    } catch (historyError) {
      console.error('Erreur lors de la récupération de l\'historique, on continue sans historique:', historyError);
      conversationHistory = []; // On continue sans historique si erreur
    }

    const messagesForGpt = [
      { role: "system", content: prompt }
    ];

    // Ajouter l'historique de la conversation au format attendu par l'API OpenAI
    conversationHistory.forEach(msg => {
      messagesForGpt.push({
        role: msg.sender === 'user' ? 'user' : 'assistant',
        content: msg.text
      });
    });

    // Ajouter le message actuel de l'utilisateur
    messagesForGpt.push({ role: "user", content: message });

    let reply;
    try {
      const completion = await openai.chat.completions.create({
        model: "gpt-3.5-turbo", // Utilisation d'un modèle plus récent
        messages: messagesForGpt,
        temperature: 0.7,
        max_tokens: 500
      });
      reply = completion.choices[0].message.content;
    } catch (openaiError) {
      console.error('Erreur OpenAI:', openaiError);
      throw new Error(`Erreur lors de la génération de la réponse: ${openaiError.message || 'Erreur inconnue'}`);
    }

    try {
      await addMessageMySQL(userId, usedBotId, currentConversationId, 'user', message);
      await addMessageMySQL(userId, usedBotId, currentConversationId, 'bot', reply);
    } catch (msgError) {
      console.error('Erreur lors de la sauvegarde des messages:', msgError);
      // On continue quand même car le message a été généré
    }

    // Incrémenter le compteur de messages chatbot
    try {
      await incrementChatbotMessagesUsed(userId);
    } catch (quotaError) {
      console.error('Erreur lors de l\'incrémentation du quota:', quotaError);
      // On continue quand même
    }

    res.status(200).json({ message: reply });

  } catch (error) {
    console.error('Erreur lors de l\'interaction avec OpenAI:', error);
    // Gérer spécifiquement les erreurs de limite de message si nécessaire
    if (error.message && error.message.includes('Message limit reached')) {
       res.status(403).json({ message: error.message });
    } else {
       res.status(500).json({ 
         message: 'Une erreur est survenue lors de l\'interaction avec le bot',
         details: error.message || 'Erreur inconnue'
       });
    }
  }
});

// Route pour récupérer le quota de messages chatbot restant
app.get('/api/chatbot/quota', authenticateJWT, async (req, res) => {
  // Utilisateur authentifié via JWT
  const userId = req.user.id;
  // Aller chercher l'utilisateur dans MySQL
  const [rows] = await mysqlPool.query('SELECT chatbotMessagesUsed, chatbotMessagesQuota FROM users WHERE id = ?', [userId]);
  if (!rows[0]) return res.status(404).json({ message: 'Utilisateur non trouvé' });
  const used = rows[0].chatbotMessagesUsed ?? 0;
  const quota = rows[0].chatbotMessagesQuota ?? 1000;
  res.json({
    remaining: Math.max(0, quota - used),
    total: quota,
    used
  });
});

// Middleware de gestion des erreurs global
app.use((err, req, res, next) => {
  console.error('Erreur serveur:', err);
  
  // Déterminer le type d'erreur et envoyer une réponse appropriée
  if (err.name === 'UnauthorizedError') {
    return res.status(401).json({ message: 'Non authentifié' });
  }
  
  if (err.name === 'ValidationError') {
    return res.status(400).json({ message: err.message });
  }
  
  // Erreur par défaut
  res.status(500).json({ 
    message: 'Une erreur interne est survenue',
    error: process.env.NODE_ENV === 'development' ? err.message : undefined
  });
});

// Nouvelle route pour générer des clés d'activation (pour l'administrateur)
app.post('/api/generate-keys', authenticateJWT, async (req, res) => {
  if (req.user.email !== 'mohammadharris200528@gmail.com') { // Vérifier si l'utilisateur est admin
    return res.status(403).json({ message: 'Accès refusé. Réservé à l\'administrateur.' });
  }

  const { botId, numberOfKeys } = req.body;

  if (!botId || !numberOfKeys || numberOfKeys <= 0) {
    return res.status(400).json({ message: 'botId et numberOfKeys (nombre > 0) sont requis' });
  }

  try {
    const generatedKeys = [];
    for (let i = 0; i < numberOfKeys; i++) {
        // Générer une clé unique (simple UUID pour l'exemple)
        const key = `${botId}-${Date.now()}-${Math.random().toString(36).substring(2, 15)}`; // Génération simple, à améliorer pour la production si nécessaire
        addActivationKey(key, botId);
        generatedKeys.push(key);
    }
    res.status(201).json({ message: 'Clés générées avec succès', keys: generatedKeys });
  } catch (error) {
    console.error('Erreur détaillée lors de la génération des clés:', error); // Log détaillé de l'erreur
    res.status(500).json({ message: 'Erreur lors de la génération des clés', error: error.message }); // Inclure le message d'erreur dans la réponse
  }
});

// Harmonisation des préférences utilisateur :
// Supprimer PUT /api/users/:userId/preferences (doublon)
// Nouvelle route pour sauvegarder les préférences utilisateur par bot
app.post('/api/bot-preferences', authenticateJWT, async (req, res) => {
  const userId = req.user.id;
  const botId = Number(req.query.botId) || 1; // On force le bot islamique
  const { preferences } = req.body;

  if (!preferences) {
    return res.status(400).json({ message: 'Préférences sont requises.' });
  }

  try {
    await saveUserBotPreferences(userId, botId, preferences);
    res.status(200).json({ message: 'Préférences sauvegardées avec succès.' });
  } catch (error) {
    console.error('Erreur lors de la sauvegarde des préférences:', error);
    res.status(500).json({ message: 'Erreur lors de la sauvegarde des préférences.' });
  }
});

// Modifier la route pour récupérer les conversations afin d'inclure les préférences
app.get('/api/conversations/:botId', authenticateJWT, async (req, res) => {
  const userId = req.user.id;
  const botId = Number(req.params.botId) || 1; // On force le bot islamique

  try {
    const conversations = await getConversationsForUserBot(userId, botId);
    const preferences = await getUserBotPreferences(userId, botId);
    
    res.status(200).json({ conversations, preferences });
  } catch (error) {
    console.error('Erreur lors de la récupération des conversations et préférences:', error);
    res.status(500).json({ message: 'Erreur lors de la récupération des conversations et préférences.' });
  }
});

// Route pour supprimer une conversation
app.delete('/api/conversations/:botId/:conversationId', authenticateJWT, async (req, res) => {
  try {
    const { conversationId } = req.params;
    const userId = req.user.id;
    const botId = Number(req.params.botId) || 1; // On force le bot islamique

    const success = await deleteConversationMySQL(userId, botId, conversationId);
    if (success) {
      res.json({ success: true });
    } else {
      res.status(404).json({ success: false, message: 'Conversation non trouvée ou non supprimée.' });
    }
  } catch (error) {
    res.status(500).json({ message: 'Erreur lors de la suppression de la conversation.' });
  }
});

// Route pour mettre à jour le titre d'une conversation
app.put('/api/conversations/:botId/:conversationId/title', authenticateJWT, async (req, res) => {
  try {
    const { botId, conversationId } = req.params;
    const userId = req.user.id;
    const { title } = req.body;

    console.log(`Received PUT request to update title for conversation ${conversationId}, bot ${botId}, user ${userId} with new title: ${title}`);

    if (!title) {
      console.log('Title is missing from request body.');
      return res.status(400).json({ error: 'Le titre est requis' });
    }

    // Utiliser la version MySQL
    const success = await updateConversationTitleMySQL(userId, Number(botId), Number(conversationId), title);

    if (success) {
      console.log(`Title updated successfully for conversation ${conversationId}.`);
      res.json({ success: true });
    } else {
      console.warn(`Conversation ${conversationId} not found or title not updated.`);
      res.status(404).json({ error: 'Conversation non trouvée ou aucun message à mettre à jour' });
    }

  } catch (error) {
    console.error('Erreur lors de la mise à jour du titre de la conversation:', error);
    res.status(500).json({ error: 'Erreur lors de la mise à jour du titre de la conversation' });
  }
});

// Route pour rechercher des messages dans une conversation spécifique
app.get('/api/messages/:botId/:conversationId/search', authenticateJWT, async (req, res) => {
  const userId = req.user.id;
  const botId = Number(req.params.botId) || 1; // On force le bot islamique
  const conversationId = parseInt(req.params.conversationId);
  const query = req.query.query;

  if (!userId || isNaN(botId) || isNaN(conversationId) || !query || typeof query !== 'string') {
    return res.status(400).send('Paramètres manquants ou invalides.');
  }

  try {
    const messages = await searchMessages(userId, botId, conversationId, query);
    res.json(messages);
  } catch (error) {
    console.error('Erreur lors de la recherche de messages:', error);
    res.status(500).send('Erreur interne du serveur.');
  }
});

// Route pour récupérer l'ID MySQL d'un utilisateur connecté (désormais l'id utilisateur)
app.get('/api/user/mysql-id', authenticateJWT, async (req, res) => {
  try {
    // Si req.user est un id (string), on le renvoie directement. Sinon, on va le chercher en base.
    let userId = req.user && typeof req.user === 'object' ? req.user.id : req.user;
    if (!userId) {
      return res.status(404).json({ success: false, message: 'Utilisateur non trouvé' });
    }
    res.json({ success: true, mysqlUserId: userId });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Erreur serveur' });
  }
});

// Route pour récupérer les stats utilisateur depuis MySQL
app.get('/api/user/stats', authenticateJWT, async (req, res) => {
  try {
    const stats = await getUserStats(req.user.id);
    res.json({ success: true, stats });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Erreur serveur' });
  }
});

// Route pour récupérer les stats journalières des 30 derniers jours pour l’utilisateur connecté


// Route de test pour forcer la synchronisation d'un utilisateur vers MySQL
app.get('/api/test/sync-user', authenticateJWT, async (req, res) => {
  try {
    console.log('🔄 Test de synchronisation forcée pour:', req.user.name);
    
    // Forcer la synchronisation
    const mysqlUserId = await syncUserToMySQL(req.user.id, req.user.name, req.user.email);
    
    if (mysqlUserId) {
      // Mettre à jour l'utilisateur SQLite avec l'ID MySQL
      updateUserMySQLId(req.user.id, mysqlUserId);
      console.log('✅ Synchronisation forcée réussie:', mysqlUserId);
      
      res.json({ 
        success: true, 
        message: 'Synchronisation réussie',
        mysqlUserId,
        user: req.user
      });
    } else {
      res.status(500).json({ 
        success: false, 
        message: 'Échec de la synchronisation'
      });
    }
  } catch (error) {
    console.error('❌ Erreur synchronisation forcée:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Erreur serveur',
      error: error.message
    });
  }
});

// Route pour créer une nouvelle conversation
app.post('/api/conversations', authenticateJWT, async (req, res) => {
  try {
    const userId = req.user.id;
    const { title } = req.body;
    const usedBotId = 1; // On force le bot islamique
    // Vérifier que le bot existe dans MySQL
    const [bots] = await mysqlPool.execute('SELECT * FROM bots WHERE id = ?', [usedBotId]);
    if (!bots || bots.length === 0) {
      return res.status(404).json({ message: 'Bot inexistant' });
    }
    // Vérifier que l'utilisateur existe dans MySQL
    const [users] = await mysqlPool.execute('SELECT * FROM users WHERE id = ?', [userId]);
    if (!users || users.length === 0) {
      return res.status(404).json({ message: 'Utilisateur inexistant' });
    }
    const convTitle = title || 'Nouvelle conversation';
    // Insérer la conversation dans MySQL
    const [result] = await mysqlPool.execute(
      'INSERT INTO conversations (userId, botId, title) VALUES (?, ?, ?)',
      [userId, usedBotId, convTitle]
    );
    // Récupérer la conversation créée
    const [convs] = await mysqlPool.execute('SELECT * FROM conversations WHERE id = ?', [result.insertId]);
    res.status(201).json(convs[0]);
  } catch (error) {
    console.error('Erreur lors de la création de la conversation (MySQL):', error);
    res.status(500).json({ message: 'Erreur lors de la création de la conversation.' });
  }
});

// Route de test pour générer des stats sur 30 jours
app.post('/api/test/generate-stats', authenticateJWT, async (req, res) => {
  try {
    const userId = req.user.id;
    await mysqlPool.execute('DELETE FROM quran_stats WHERE user_id = ?', [userId]);
    // Générer les valeurs à insérer
    const values = [];
    for (let i = 0; i < 30; i++) {
      // Date au format YYYY-MM-DD
      const date = new Date(Date.now() - i * 24 * 60 * 60 * 1000).toISOString().slice(0, 10);
      values.push([userId, date, 100 + i * 10, 2 + i, 0, 0]);
    }
    await mysqlPool.query(
      'INSERT INTO quran_stats (user_id, date, hasanat, verses, time_seconds, pages_read) VALUES ?',
      [values]
    );
    res.json({ success: true, message: 'Stats générées pour 30 jours.' });
  } catch (error) {
    res.status(500).json({ message: 'Erreur lors de la génération des stats.' });
  }
});

// Stats du jour
app.get('/api/user/stats/today', authenticateJWT, async (req, res) => {
  try {
    const userId = req.user.id;
    const [rows] = await mysqlPool.execute(
      `SELECT 
        COALESCE(SUM(hasanat), 0) as hasanat,
        COALESCE(SUM(verses), 0) as verses,
        COALESCE(SUM(time_seconds), 0) as time_seconds,
        COALESCE(SUM(pages_read), 0) as pages_read
      FROM quran_stats
      WHERE user_id = ? AND DATE(date) = CURDATE()`, [userId]
    );
    res.json({ success: true, stats: rows[0] });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Erreur serveur' });
  }
});

// Stats de la semaine
app.get('/api/user/stats/week', authenticateJWT, async (req, res) => {
  console.log('Route /api/user/stats/week - req.user:', req.user);
  try {
    const userId = req.user.id;
    const [rows] = await mysqlPool.execute(
      `SELECT 
        COALESCE(SUM(hasanat), 0) as hasanat,
        COALESCE(SUM(verses), 0) as verses,
        COALESCE(SUM(time_seconds), 0) as time_seconds,
        COALESCE(SUM(pages_read), 0) as pages_read
      FROM quran_stats
      WHERE user_id = ? AND DATE(date) >= DATE_SUB(CURDATE(), INTERVAL 6 DAY)`, [userId]
    );
    res.json({ success: true, stats: rows[0] });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Erreur serveur' });
  }
});

// Stats totales
app.get('/api/user/stats/all', authenticateJWT, async (req, res) => {
  console.log('Route /api/user/stats/all - req.user:', req.user);
  try {
    const userId = req.user.id;
    const [rows] = await mysqlPool.execute(
      `SELECT 
        COALESCE(SUM(hasanat), 0) as hasanat,
        COALESCE(SUM(verses), 0) as verses,
        COALESCE(SUM(time_seconds), 0) as time_seconds,
        COALESCE(SUM(pages_read), 0) as pages_read
      FROM quran_stats
      WHERE user_id = ?`, [userId]
    );
    res.json({ success: true, stats: rows[0] });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Erreur serveur' });
  }
});

// Route pour récupérer les stats journalières des 30 derniers jours pour l'utilisateur connecté
app.get('/api/user/stats/daily', authenticateJWT, async (req, res) => {
  console.log('Route /api/user/stats/daily - req.user:', req.user);
  try {
    const userId = req.user.id;
    const [rows] = await mysqlPool.execute(
      `SELECT 
        DATE(date) as date,
        SUM(hasanat) as hasanat,
        SUM(verses) as verses,
        SUM(time_seconds) as time_seconds,
        SUM(pages_read) as pages_read
      FROM quran_stats
      WHERE user_id = ? AND DATE(date) >= DATE_SUB(CURDATE(), INTERVAL 29 DAY)
      GROUP BY DATE(date)
      ORDER BY DATE(date) DESC
      LIMIT 30`,
      [userId]
    );
    res.json({ success: true, stats: rows });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Erreur serveur', error: error.message });
  }
});

// ===================== ROUTES PREFERENCES UTILISATEUR =====================
// Récupérer les préférences de l'utilisateur connecté
app.get('/api/user/preferences', authenticateJWT, async (req, res) => {
  console.log('Route /api/user/preferences - req.user:', req.user);
  try {
    const userId = req.user.id;
    const [rows] = await mysqlPool.execute(
      'SELECT preferences FROM users WHERE id = ?',
      [userId]
    );
    if (rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Utilisateur non trouvé' });
    }
    res.json({ success: true, preferences: JSON.parse(rows[0].preferences || '{}') });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Erreur serveur', error: error.message });
  }
});
// Mettre à jour les préférences de l'utilisateur connecté
app.put('/api/user/preferences', authenticateJWT, async (req, res) => {
  try {
    const userId = req.user.id;
    const { preferences } = req.body;
    if (!preferences) {
      return res.status(400).json({ success: false, message: 'Préférences manquantes' });
    }
    await mysqlPool.execute(
      'UPDATE users SET preferences = ? WHERE id = ?',
      [JSON.stringify(preferences), userId]
    );
    res.json({ success: true, message: 'Préférences mises à jour' });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Erreur serveur', error: error.message });
  }
});

// Route pour récupérer l'historique des messages d'une conversation (MySQL)
// Route pour récupérer une conversation spécifique par son ID
app.get('/api/conversations/:id', authenticateJWT, async (req, res) => {
  const { id } = req.params;
  const userId = req.user.id;
  try {
    const [rows] = await mysqlPool.execute(
      'SELECT * FROM conversations WHERE id = ? AND userId = ?',
      [id, userId]
    );
    if (rows.length === 0) {
      return res.status(404).json({ message: 'Conversation non trouvée' });
    }
    res.json(rows[0]);
  } catch (error) {
    console.error('Erreur lors de la récupération de la conversation:', error);
    res.status(500).json({ message: 'Erreur lors de la récupération de la conversation', details: error.message });
  }
});

app.get('/api/conversations/:conversationId/messages', authenticateJWT, async (req, res) => {
  const conversationId = Number(req.params.conversationId);
  const userId = req.user.id;
  
  if (isNaN(conversationId)) {
    return res.status(400).json({ 
      message: 'ID de conversation invalide',
      details: `L'ID "${req.params.conversationId}" n'est pas un nombre valide.`
    });
  }

  try {
    // Vérifier que la conversation appartient à l'utilisateur
    const [convs] = await mysqlPool.execute(
      'SELECT * FROM conversations WHERE id = ? AND userId = ?', 
      [conversationId, userId]
    );
    if (!convs || convs.length === 0) {
      // Vérifier si la conversation existe mais appartient à un autre utilisateur
      const [allConvs] = await mysqlPool.execute(
        'SELECT * FROM conversations WHERE id = ?', 
        [conversationId]
      );
      if (allConvs && allConvs.length > 0) {
        console.log(`Conversation ${conversationId} existe mais appartient à l'utilisateur ${allConvs[0].userId}, pas à ${userId}`);
        return res.status(403).json({ 
          message: 'Accès interdit à cette conversation.',
          details: `La conversation ${conversationId} ne vous appartient pas.`
        });
      } else {
        console.log(`Conversation ${conversationId} n'existe pas`);
        return res.status(404).json({ 
          message: 'Conversation non trouvée',
          details: `La conversation ${conversationId} n'existe pas.`
        });
      }
    }
    const [rows] = await mysqlPool.execute(
      'SELECT * FROM messages WHERE conversationId = ? ORDER BY timestamp ASC',
      [conversationId]
    );
    res.json(rows);
  } catch (error) {
    console.error('Erreur lors de la récupération des messages:', error);
    res.status(500).json({ 
      message: 'Erreur lors de la récupération des messages', 
      details: error.message || 'Erreur inconnue'
    });
  }
});

// Route pour récupérer tous les messages d'un utilisateur, groupés par conversationId
app.get('/api/user/:userId/messages', authenticateJWT, async (req, res) => {
  if (req.user.id !== req.params.userId) {
    return res.status(403).json({ message: 'Accès interdit' });
  }
  try {
    const { userId } = req.params;
    const [rows] = await mysqlPool.execute(
      'SELECT * FROM messages WHERE userId = ? OR (sender = "bot" AND conversationId IN (SELECT id FROM conversations WHERE userId = ?)) ORDER BY conversationId, timestamp ASC',
      [userId, userId]
    );
    res.json(rows);
  } catch (error) {
    console.error('Erreur lors de la récupération des messages:', error);
    res.status(500).json({ message: 'Erreur lors de la récupération des messages', details: error.message });
  }
});

// Route pour récupérer toutes les conversations d'un utilisateur
app.get('/api/user/:userId/conversations', authenticateJWT, async (req, res) => {
  if (req.user.id !== req.params.userId) {
    return res.status(403).json({ message: 'Accès interdit' });
  }
  try {
    const [rows] = await mysqlPool.execute(
      'SELECT * FROM conversations WHERE userId = ? ORDER BY createdAt DESC',
      [req.params.userId]
    );
    res.json(rows);
  } catch (error) {
    console.error('Erreur lors de la récupération des conversations:', error);
    res.status(500).json({ message: 'Erreur lors de la récupération des conversations', details: error.message });
  }
});

// ===================== ROUTE MISE À JOUR PROFIL UTILISATEUR =====================
app.put('/api/user/profile', authenticateJWT, async (req, res) => {
  try {
    const userId = req.user.id;
    const { username, profile_picture } = req.body;
    console.log('--- [UPDATE PROFILE] ---');
    console.log('userId:', userId);
    console.log('username:', username);
    console.log('profile_picture:', profile_picture ? '[image]' : null);
    
    // Vérifier si la colonne profile_picture existe dans la table users
    let profilePictureColumnExists = false;
    try {
      const [columns] = await mysqlPool.execute(
        `SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users' AND COLUMN_NAME = 'profile_picture'`
      );
      profilePictureColumnExists = columns.length > 0;
    } catch (err) {
      console.log('Erreur lors de la vérification de la colonne profile_picture:', err);
    }
    
    // Si la colonne n'existe pas et qu'on essaie de la mettre à jour, la créer
    if (profile_picture && !profilePictureColumnExists) {
      try {
        await mysqlPool.execute(
          `ALTER TABLE users ADD COLUMN profile_picture LONGTEXT NULL`
        );
        console.log('Colonne profile_picture ajoutée à la table users (LONGTEXT)');
        profilePictureColumnExists = true;
      } catch (alterError) {
        console.error('Erreur lors de l\'ajout de la colonne profile_picture:', alterError);
        // On continue quand même, on ne mettra juste pas à jour profile_picture
      }
    }
    
    // Si la colonne existe mais est de type TEXT (trop petit), la modifier en LONGTEXT
    if (profile_picture && profilePictureColumnExists) {
      try {
        const [columnInfo] = await mysqlPool.execute(
          `SELECT DATA_TYPE FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users' AND COLUMN_NAME = 'profile_picture'`
        );
        if (columnInfo.length > 0 && columnInfo[0].DATA_TYPE === 'text') {
          await mysqlPool.execute(
            `ALTER TABLE users MODIFY COLUMN profile_picture LONGTEXT NULL`
          );
          console.log('Colonne profile_picture modifiée en LONGTEXT');
        }
      } catch (alterError) {
        console.error('Erreur lors de la modification de la colonne profile_picture:', alterError);
        // On continue quand même
      }
    }
    
    if (!username && !profile_picture) {
      return res.status(400).json({ success: false, message: 'Aucune donnée à mettre à jour.' });
    }
    const fields = [];
    const values = [];
    if (username) {
      fields.push('username = ?');
      values.push(username);
    }
    if (profile_picture && profilePictureColumnExists) {
      fields.push('profile_picture = ?');
      values.push(profile_picture);
    }
    if (fields.length === 0) {
      return res.status(400).json({ success: false, message: 'Aucune donnée à mettre à jour.' });
    }
    values.push(userId);
    const [result] = await mysqlPool.execute(
      `UPDATE users SET ${fields.join(', ')} WHERE id = ?`,
      values
    );
    console.log('Résultat SQL:', result);
    res.json({ success: true, message: 'Profil mis à jour.' });
  } catch (error) {
    console.error('Erreur update profile:', error);
    res.status(500).json({ success: false, message: 'Erreur lors de la mise à jour du profil.', error: error.message });
  }
});

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Servir les fichiers statiques du build React

// ================== ADMIN ENDPOINTS ==================
// Liste des utilisateurs
app.get('/admin/users', authenticateJWT, requireAdmin, async (req, res) => {
  try {
    const [rows] = await mysqlPool.query('SELECT id, email, username, chatbotMessagesUsed, is_active FROM users');
    res.json({ users: rows });
  } catch (e) {
    res.status(500).json({ error: 'Erreur SQL users' });
  }
});
// Reset quota utilisateur
app.post('/admin/users/:userId/reset-quota', authenticateJWT, requireAdmin, async (req, res) => {
  try {
    const DEFAULT_QUOTA = 0; // Remettre à zéro
    await mysqlPool.query('UPDATE users SET chatbotMessagesUsed = ? WHERE id = ?', [DEFAULT_QUOTA, req.params.userId]);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: 'Erreur SQL reset quota' });
  }
});
// Voir achats d'un utilisateur
app.get('/admin/users/:userId/purchases', authenticateJWT, requireAdmin, async (req, res) => {
  try {
    const [rows] = await mysqlPool.query('SELECT * FROM purchases WHERE user_id = ?', [req.params.userId]);
    res.json({ purchases: rows });
  } catch (e) {
    res.status(500).json({ error: 'Erreur SQL purchases user' });
  }
});
// Liste des achats
app.get('/admin/purchases', authenticateJWT, requireAdmin, async (req, res) => {
  try {
    const [rows] = await mysqlPool.query('SELECT * FROM purchases');
    res.json({ purchases: rows });
  } catch (e) {
    res.status(500).json({ error: 'Erreur SQL purchases' });
  }
});
// Liste des bots
app.get('/admin/bots', authenticateJWT, requireAdmin, async (req, res) => {
  try {
    const [rows] = await mysqlPool.query('SELECT id, name, is_active, (SELECT COUNT(*) FROM user_bots WHERE bot_id = bots.id) AS usersCount FROM bots');
    res.json({ bots: rows });
  } catch (e) {
    res.status(500).json({ error: 'Erreur SQL bots' });
  }
});
// Activer/désactiver un bot
app.post('/admin/bots/:botId/toggle', authenticateJWT, requireAdmin, async (req, res) => {
  try {
    await mysqlPool.query('UPDATE bots SET is_active = NOT is_active WHERE id = ?', [req.params.botId]);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: 'Erreur SQL toggle bot' });
  }
});
// Statistiques globales
// ===================== ROUTES NASHEEDS =====================
// Fonction pour créer la table nasheeds si elle n'existe pas
async function ensureNasheedsTable() {
  try {
    await mysqlPool.execute('SELECT 1 FROM nasheeds LIMIT 1');
    console.log('✅ [Backend] Table nasheeds existe');
  } catch (tableError) {
    if (tableError.code === 'ER_NO_SUCH_TABLE') {
      console.log('⚠️ [Backend] Table nasheeds n\'existe pas, création...');
      await mysqlPool.execute(`
        CREATE TABLE IF NOT EXISTS nasheeds (
          id INT AUTO_INCREMENT PRIMARY KEY,
          title VARCHAR(255) NOT NULL COMMENT 'Titre du nasheed',
          artist VARCHAR(255) DEFAULT NULL COMMENT 'Artiste/Chanteur',
          audio_url VARCHAR(500) NOT NULL COMMENT 'URL de l''audio',
          cover_image_url VARCHAR(500) DEFAULT NULL COMMENT 'URL de l''image de couverture',
          description TEXT DEFAULT NULL COMMENT 'Description du nasheed',
          duration INT DEFAULT NULL COMMENT 'Durée en secondes',
          category VARCHAR(100) DEFAULT 'general' COMMENT 'Catégorie (general, praise, dua, etc.)',
          language VARCHAR(50) DEFAULT 'ar' COMMENT 'Langue (ar, en, fr, etc.)',
          is_active BOOLEAN DEFAULT TRUE COMMENT 'Nasheed actif ou non',
          created_by VARCHAR(36) DEFAULT NULL COMMENT 'ID de l''admin qui a créé',
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
          INDEX idx_category (category),
          INDEX idx_language (language),
          INDEX idx_is_active (is_active),
          INDEX idx_created_at (created_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        COMMENT='Table des nasheeds disponibles dans la bibliothèque'
      `);
      console.log('✅ [Backend] Table nasheeds créée avec succès');
    } else {
      console.error('❌ [Backend] Erreur lors de la vérification de la table:', tableError);
      throw tableError;
    }
  }
}

// Récupérer tous les nasheeds actifs
app.get('/api/nasheeds', authenticateJWT, async (req, res) => {
  try {
    console.log('📥 [Backend] Récupération nasheeds');
    await ensureNasheedsTable();
    const [rows] = await mysqlPool.execute(
      'SELECT * FROM nasheeds WHERE is_active = TRUE ORDER BY created_at DESC'
    );
    console.log('✅ [Backend] Nasheeds récupérés:', rows.length);
    res.json({ nasheeds: rows });
  } catch (error) {
    console.error('❌ [Backend] Erreur récupération nasheeds:', error);
    console.error('❌ [Backend] Erreur message:', error.message);
    console.error('❌ [Backend] Erreur code:', error.code);
    res.status(500).json({ 
      message: 'Erreur serveur',
      error: error.message,
      code: error.code
    });
  }
});

// Ajouter un nasheed (admin seulement)
app.post('/api/nasheeds', authenticateJWT, requireAdmin, async (req, res) => {
  try {
    console.log('📤 [Backend] Ajout nasheed - Body:', req.body);
    console.log('📤 [Backend] Ajout nasheed - User:', req.user);
    
    const { title, artist, audio_url, cover_image_url, description, duration, category, language } = req.body;
    if (!title || !audio_url) {
      return res.status(400).json({ message: 'Titre et URL audio sont requis.' });
    }
    
    const userId = req.user.id;
    console.log('📤 [Backend] Ajout nasheed - UserId:', userId);
    
    // Vérifier que la table existe, sinon la créer
    await ensureNasheedsTable();
    
    const values = [
      title, 
      artist || null, 
      audio_url, 
      cover_image_url || null, 
      description || null, 
      duration ? parseInt(duration) : null, 
      category || 'general', 
      language || 'ar', 
      userId
    ];
    
    console.log('📤 [Backend] Ajout nasheed - Values:', values);
    
    const [result] = await mysqlPool.execute(
      'INSERT INTO nasheeds (title, artist, audio_url, cover_image_url, description, duration, category, language, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
      values
    );
    
    console.log('✅ [Backend] Nasheed ajouté avec succès - ID:', result.insertId);
    res.json({ success: true, id: result.insertId, message: 'Nasheed ajouté avec succès' });
  } catch (error) {
    console.error('❌ [Backend] Erreur ajout nasheed:', error);
    console.error('❌ [Backend] Erreur stack:', error.stack);
    console.error('❌ [Backend] Erreur message:', error.message);
    console.error('❌ [Backend] Erreur code:', error.code);
    res.status(500).json({ 
      message: 'Erreur serveur', 
      error: error.message,
      code: error.code,
      details: process.env.NODE_ENV === 'development' ? error.stack : undefined
    });
  }
});

// Route pour obtenir un token Spotify (proxy pour éviter d'exposer les credentials)
app.post('/api/spotify/token', authenticateJWT, requireAdmin, async (req, res) => {
  try {
    const SPOTIFY_CLIENT_ID = process.env.SPOTIFY_CLIENT_ID;
    const SPOTIFY_CLIENT_SECRET = process.env.SPOTIFY_CLIENT_SECRET;

    console.log('🔐 [Spotify] Demande de token - Client ID présent:', !!SPOTIFY_CLIENT_ID, 'Client Secret présent:', !!SPOTIFY_CLIENT_SECRET);

    if (!SPOTIFY_CLIENT_ID || !SPOTIFY_CLIENT_SECRET) {
      console.error('❌ [Spotify] Configuration manquante');
      return res.status(500).json({ 
        error: 'Configuration Spotify manquante. Veuillez configurer SPOTIFY_CLIENT_ID et SPOTIFY_CLIENT_SECRET dans les variables d\'environnement.',
        message: 'Les credentials Spotify ne sont pas configurés dans le backend.'
      });
    }

    // Obtenir un token d'accès Spotify via Client Credentials Flow
    console.log('🔄 [Spotify] Demande de token à Spotify...');
    const response = await fetch('https://accounts.spotify.com/api/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': 'Basic ' + Buffer.from(`${SPOTIFY_CLIENT_ID}:${SPOTIFY_CLIENT_SECRET}`).toString('base64')
      },
      body: 'grant_type=client_credentials'
    });

    const responseText = await response.text();
    console.log('📡 [Spotify] Réponse Spotify - Status:', response.status, 'OK:', response.ok);

    if (!response.ok) {
      let errorData;
      try {
        errorData = JSON.parse(responseText);
      } catch {
        errorData = { error: responseText || `HTTP ${response.status}` };
      }
      
      console.error('❌ [Spotify] Erreur Spotify API:', {
        status: response.status,
        statusText: response.statusText,
        error: errorData
      });
      
      return res.status(response.status).json({ 
        error: errorData.error || 'Erreur lors de l\'obtention du token Spotify',
        message: errorData.error_description || errorData.error || `Erreur HTTP ${response.status}`,
        details: errorData
      });
    }

    let data;
    try {
      data = JSON.parse(responseText);
    } catch (parseError) {
      console.error('❌ [Spotify] Erreur parsing réponse:', parseError);
      return res.status(500).json({ 
        error: 'Erreur lors du parsing de la réponse Spotify',
        message: 'Réponse invalide reçue de Spotify'
      });
    }

    if (!data.access_token) {
      console.error('❌ [Spotify] Token non présent dans la réponse:', data);
      return res.status(500).json({ 
        error: 'Token d\'accès non reçu',
        message: 'La réponse de Spotify ne contient pas de token d\'accès'
      });
    }

    console.log('✅ [Spotify] Token obtenu avec succès');
    res.json(data);
  } catch (error) {
    console.error('❌ [Spotify] Erreur serveur:', error);
    console.error('❌ [Spotify] Stack:', error.stack);
    res.status(500).json({ 
      error: 'Erreur serveur lors de l\'obtention du token Spotify',
      message: error.message || 'Erreur inconnue',
      details: process.env.NODE_ENV === 'development' ? error.stack : undefined
    });
  }
});

// Modifier un nasheed (admin seulement)
app.put('/api/nasheeds/:id', authenticateJWT, requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { title, artist, audio_url, cover_image_url, description, duration, category, language, is_active } = req.body;
    await mysqlPool.execute(
      'UPDATE nasheeds SET title = ?, artist = ?, audio_url = ?, cover_image_url = ?, description = ?, duration = ?, category = ?, language = ?, is_active = ? WHERE id = ?',
      [title, artist, audio_url, cover_image_url, description, duration, category, language, is_active !== undefined ? is_active : true, id]
    );
    res.json({ success: true, message: 'Nasheed modifié avec succès' });
  } catch (error) {
    console.error('Erreur modification nasheed:', error);
    res.status(500).json({ message: 'Erreur serveur' });
  }
});

// ===================== ROUTES SPOTIFY USER AUTH =====================
// Obtenir le Client ID Spotify (pour l'authentification utilisateur)
app.get('/api/spotify/client-id', authenticateJWT, async (req, res) => {
  try {
    const SPOTIFY_CLIENT_ID = process.env.SPOTIFY_CLIENT_ID;
    if (!SPOTIFY_CLIENT_ID) {
      return res.status(500).json({ error: 'Spotify Client ID non configuré' });
    }
    res.json({ client_id: SPOTIFY_CLIENT_ID });
  } catch (error) {
    console.error('❌ [Spotify] Erreur récupération Client ID:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// Route de callback Spotify (pour redirection depuis Spotify OAuth)
// Cette route reçoit le callback de Spotify et redirige vers le frontend
app.get('/spotify/callback', async (req, res) => {
  try {
    const { code, error } = req.query;
    const FRONTEND_URL = process.env.FRONTEND_URL || 'https://ummati.pro';
    
    if (error) {
      console.error('❌ [Spotify Callback] Erreur OAuth:', error);
      // Rediriger vers le frontend avec l'erreur
      return res.redirect(`${FRONTEND_URL}/spotify/callback?error=${encodeURIComponent(error)}`);
    }

    if (!code) {
      console.error('❌ [Spotify Callback] Code manquant');
      return res.redirect(`${FRONTEND_URL}/spotify/callback?error=no_code`);
    }

    console.log('✅ [Spotify Callback] Code reçu, redirection vers frontend');
    // Rediriger vers le frontend avec le code
    res.redirect(`${FRONTEND_URL}/spotify/callback?code=${code}`);
  } catch (error) {
    console.error('❌ [Spotify Callback] Erreur:', error);
    const FRONTEND_URL = process.env.FRONTEND_URL || 'https://ummati.pro';
    res.redirect(`${FRONTEND_URL}/spotify/callback?error=server_error`);
  }
});

// Échanger un code d'autorisation contre un token utilisateur Spotify
app.post('/api/spotify/user-token', authenticateJWT, async (req, res) => {
  try {
    const { code, redirect_uri } = req.body;
    const SPOTIFY_CLIENT_ID = process.env.SPOTIFY_CLIENT_ID;
    const SPOTIFY_CLIENT_SECRET = process.env.SPOTIFY_CLIENT_SECRET;

    if (!SPOTIFY_CLIENT_ID || !SPOTIFY_CLIENT_SECRET) {
      return res.status(500).json({ error: 'Configuration Spotify manquante' });
    }

    if (!code || !redirect_uri) {
      return res.status(400).json({ error: 'Code et redirect_uri requis' });
    }

    // Échanger le code contre un token
    const response = await fetch('https://accounts.spotify.com/api/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': 'Basic ' + Buffer.from(`${SPOTIFY_CLIENT_ID}:${SPOTIFY_CLIENT_SECRET}`).toString('base64')
      },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code: code,
        redirect_uri: redirect_uri,
      })
    });

    if (!response.ok) {
      const errorData = await response.json();
      return res.status(response.status).json({ error: errorData.error || 'Erreur lors de l\'échange du code' });
    }

    const tokenData = await response.json();
    res.json(tokenData);
  } catch (error) {
    console.error('❌ [Spotify] Erreur échange token utilisateur:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// Rafraîchir un token utilisateur Spotify
app.post('/api/spotify/refresh-token', authenticateJWT, async (req, res) => {
  try {
    const { refresh_token } = req.body;
    const SPOTIFY_CLIENT_ID = process.env.SPOTIFY_CLIENT_ID;
    const SPOTIFY_CLIENT_SECRET = process.env.SPOTIFY_CLIENT_SECRET;

    if (!SPOTIFY_CLIENT_ID || !SPOTIFY_CLIENT_SECRET) {
      return res.status(500).json({ error: 'Configuration Spotify manquante' });
    }

    if (!refresh_token) {
      return res.status(400).json({ error: 'refresh_token requis' });
    }

    const response = await fetch('https://accounts.spotify.com/api/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': 'Basic ' + Buffer.from(`${SPOTIFY_CLIENT_ID}:${SPOTIFY_CLIENT_SECRET}`).toString('base64')
      },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: refresh_token,
      })
    });

    if (!response.ok) {
      const errorData = await response.json();
      return res.status(response.status).json({ error: errorData.error || 'Erreur lors du rafraîchissement' });
    }

    const tokenData = await response.json();
    res.json(tokenData);
  } catch (error) {
    console.error('❌ [Spotify] Erreur rafraîchissement token:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// Supprimer un nasheed (admin seulement)
app.delete('/api/nasheeds/:id', authenticateJWT, requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    await mysqlPool.execute('DELETE FROM nasheeds WHERE id = ?', [id]);
    res.json({ success: true, message: 'Nasheed supprimé avec succès' });
  } catch (error) {
    console.error('Erreur suppression nasheed:', error);
    res.status(500).json({ message: 'Erreur serveur' });
  }
});

app.get('/admin/stats', authenticateJWT, requireAdmin, async (req, res) => {
  try {
    const [[{ users }]] = await mysqlPool.query('SELECT COUNT(*) AS users FROM users');
    const [[{ bots }]] = await mysqlPool.query('SELECT COUNT(*) AS bots FROM bots');
    const [[{ purchases }]] = await mysqlPool.query('SELECT COUNT(*) AS purchases FROM purchases');
    const [[{ hasanat }]] = await mysqlPool.query('SELECT SUM(hasanat) AS hasanat FROM quran_stats');
    res.json({ users, bots, purchases, hasanat: hasanat || 0 });
  } catch (e) {
    res.status(500).json({ error: 'Erreur SQL stats' });
  }
}); 

// Fallback SPA : toutes les autres routes renvoient index.html
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../dist', 'index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Serveur backend démarré sur le port ${PORT}`);
}); 

// Route temporaire pour générer un JWT admin (à supprimer après usage)
app.get('/admin/generate-token', (req, res) => {
  const { secret } = req.query;
  // Change la valeur ci-dessous pour plus de sécurité
  if (secret !== 'GEN_TOKEN_2025') {
    return res.status(403).json({ error: 'Accès refusé' });
  }
  const payload = {
    id: 'admin-id', // Remplace par l'id réel si besoin
    email: 'mohammadharris200528@gmail.com'
  };
  const JWT_SECRET = process.env.JWT_SECRET || 'une_clé_ultra_secrète';
  const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token });
}); 

// Route permanente pour login admin sécurisé
app.post('/admin/login', async (req, res) => {
  const { email, password } = req.body;
  if (
    email === 'mohammadharris200528@gmail.com' &&
    password === process.env.ADMIN_PASSWORD
  ) {
    const payload = {
      id: 'admin-id', // Mets l'id réel si tu veux
      email
    };
    const JWT_SECRET = process.env.JWT_SECRET || 'une_clé_ultra_secrète';
    const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '7d' });
    return res.json({ token });
  }
  return res.status(403).json({ error: 'Identifiants invalides' });
}); 


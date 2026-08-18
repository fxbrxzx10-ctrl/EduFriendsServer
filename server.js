import express from 'express';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import pg from 'pg';

const { Pool } = pg;
const app = express();
const PORT = Number(process.env.PORT || 10000);
const DATABASE_URL = process.env.DATABASE_URL;
const JWT_SECRET = process.env.JWT_SECRET;
const ADMIN_KEY = process.env.ADMIN_KEY;

if (!DATABASE_URL) throw new Error('DATABASE_URL no está configurada.');
if (!JWT_SECRET) throw new Error('JWT_SECRET no está configurada.');
if (!ADMIN_KEY) throw new Error('ADMIN_KEY no está configurada.');

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});

app.set('trust proxy', 1);
app.use(cors({
  origin: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Admin-Key']
}));
app.use(express.json({ limit: '1mb' }));
app.use('/admin', express.static(new URL('./public', import.meta.url).pathname));

function cleanUsername(value) {
  return String(value || '').trim().replace(/\s+/g, ' ');
}
function validUsername(value) {
  return /^[A-Za-zÁÉÍÓÚáéíóúÑñ0-9_. -]{3,30}$/.test(value);
}
function validPassword(value) {
  return typeof value === 'string' && value.length >= 6 && value.length <= 100;
}
function signToken(user) {
  return jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '30d' });
}
function publicProfile(profile, username) {
  return {
    username,
    nombre: profile?.nombre || username,
    avatar: profile?.avatar || '',
    nivel: Number(profile?.nivel) || 1,
    xp: Number(profile?.xp) || 0,
    monedas: Number(profile?.monedas) || 0,
    habilidades: profile?.habilidades && typeof profile.habilidades === 'object'
      ? profile.habilidades
      : { pista: 0, reintento: 0, salto: 0 },
    progresoCursos: profile?.progresoCursos || {},
    registrosGeneral: Array.isArray(profile?.registrosGeneral) ? profile.registrosGeneral : []
  };
}
function parseProfile(value) {
  if (!value) return {};
  if (typeof value === 'object') return value;
  try { return JSON.parse(value); } catch { return {}; }
}

async function getUserById(id) {
  const { rows } = await pool.query(
    'SELECT id, username, profile_json, password_hash FROM users WHERE id = $1',
    [id]
  );
  if (!rows[0]) return null;
  return { ...rows[0], profile: parseProfile(rows[0].profile_json) };
}

async function auth(req, res, next) {
  const raw = String(req.headers.authorization || '');
  const token = raw.startsWith('Bearer ') ? raw.slice(7) : '';
  if (!token) return res.status(401).json({ error: 'Falta el token.' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const user = await getUserById(payload.id);
    if (!user) return res.status(401).json({ error: 'Cuenta no encontrada.' });
    req.user = user;
    next();
  } catch {
    return res.status(401).json({ error: 'Sesión inválida o expirada.' });
  }
}

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY,
      username TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      profile_json JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
    CREATE INDEX IF NOT EXISTS idx_users_updated_at ON users(updated_at DESC);
  `);
}

app.get('/api/health', async (_req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ ok: true, service: 'EduFriends', database: 'postgres', time: new Date().toISOString() });
  } catch {
    res.status(503).json({ ok: false, service: 'EduFriends', database: 'unavailable' });
  }
});

app.post('/api/register', async (req, res) => {
  try {
    const username = cleanUsername(req.body?.username);
    const password = String(req.body?.password || '');
    const profile = req.body?.profile && typeof req.body.profile === 'object' ? req.body.profile : {};
    if (!validUsername(username)) return res.status(400).json({ error: 'El usuario debe tener entre 3 y 30 caracteres.' });
    if (!validPassword(password)) return res.status(400).json({ error: 'La contraseña debe tener al menos 6 caracteres.' });
    const exists = await pool.query('SELECT id FROM users WHERE LOWER(username) = LOWER($1)', [username]);
    if (exists.rows[0]) return res.status(409).json({ error: 'Ese usuario ya existe. Usa Iniciar sesión.' });
    const hash = await bcrypt.hash(password, 12);
    const safeProfile = publicProfile(profile, username);
    const result = await pool.query(
      'INSERT INTO users (username,password_hash,profile_json) VALUES ($1,$2,$3::jsonb) RETURNING id, username, profile_json',
      [username, hash, JSON.stringify(safeProfile)]
    );
    const user = {
      id: result.rows[0].id,
      username: result.rows[0].username,
      profile: parseProfile(result.rows[0].profile_json)
    };
    return res.status(201).json({
      token: signToken(user),
      profile: publicProfile(user.profile, user.username)
    });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'No se pudo crear la cuenta.' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const username = cleanUsername(req.body?.username);
    const password = String(req.body?.password || '');
    const { rows } = await pool.query(
      'SELECT id, username, password_hash, profile_json FROM users WHERE LOWER(username) = LOWER($1)',
      [username]
    );
    const row = rows[0];
    if (!row || !(await bcrypt.compare(password, row.password_hash))) {
      return res.status(401).json({ error: 'Usuario o contraseña incorrectos.' });
    }
    const user = { id: row.id, username: row.username, profile: parseProfile(row.profile_json) };
    return res.json({
      token: signToken(user),
      profile: publicProfile(user.profile, user.username)
    });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'No se pudo iniciar sesión.' });
  }
});

app.get('/api/me', auth, (req, res) => {
  res.json({ profile: publicProfile(req.user.profile, req.user.username) });
});

app.put('/api/me', auth, async (req, res) => {
  try {
    const incoming = req.body?.profile;
    if (!incoming || typeof incoming !== 'object') {
      return res.status(400).json({ error: 'Perfil inválido.' });
    }
    const profile = publicProfile(incoming, req.user.username);
    await pool.query(
      'UPDATE users SET profile_json = $1::jsonb, updated_at = NOW() WHERE id = $2',
      [JSON.stringify(profile), req.user.id]
    );
    return res.json({ ok: true, profile });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'No se pudo guardar el progreso.' });
  }
});

// Elimina permanentemente la cuenta y todo lo almacenado en su perfil.
app.delete('/api/me', auth, async (req, res) => {
  try {
    const result = await pool.query(
      'DELETE FROM users WHERE id = $1 RETURNING id, username',
      [req.user.id]
    );
    if (!result.rows[0]) return res.status(404).json({ error: 'Cuenta no encontrada.' });
    return res.json({
      ok: true,
      message: 'Cuenta y todos sus datos eliminados correctamente.'
    });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'No se pudo eliminar la cuenta.' });
  }
});

function normalizeCourse(value) {
  return String(value || '')
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .toLowerCase()
    .trim();
}

function courseMatches(value, course) {
  const a = normalizeCourse(value);
  const b = normalizeCourse(course);
  if (!a || !b) return false;
  return a === b ||
    a.startsWith(b + ' (') ||
    a.startsWith(b + '|') ||
    a.startsWith(b + ' -') ||
    a.startsWith(b + ' —');
}

function resultValue(result) {
  if (result === true) return true;
  if (result === false) return false;
  if (!result || typeof result !== 'object') return null;

  if (result.correct === true || result.correcto === true || result.esCorrecta === true) return true;
  if (result.correct === false || result.correcto === false || result.esCorrecta === false) return false;

  const estado = normalizeCourse(result.estado || result.resultado || '');
  if (estado === 'correcto' || estado === 'correcta') return true;
  if (estado === 'incorrecto' || estado === 'incorrecta' || estado === 'fallo' || estado === 'fallida') return false;

  return null;
}

function countProgressItem(item) {
  if (!item || typeof item !== 'object') return { correct: 0, answered: 0 };

  const arrays = [
    item.resultados,
    item.respuestas,
    item.answers,
    item.historial
  ].filter(Array.isArray);

  let correct = 0;
  let answered = 0;
  let foundArray = false;

  for (const arr of arrays) {
    if (foundArray) break;
    const values = arr.map(resultValue).filter(v => v === true || v === false);
    if (values.length > 0) {
      foundArray = true;
      answered = values.length;
      correct = values.filter(v => v === true).length;
    }
  }

  if (!foundArray) {
    const numericAnswered = Number(item.respondidas ?? item.respondidasTotal ?? item.preguntasRespondidas);
    const numericCorrect = Number(item.correctas ?? item.correctasTotal ?? item.preguntasCorrectas);
    if (Number.isFinite(numericAnswered) && numericAnswered > 0) answered = numericAnswered;
    if (Number.isFinite(numericCorrect) && numericCorrect >= 0) correct = Math.min(numericCorrect, answered);
  }

  return { correct, answered };
}

function buildRankingEntry(row, profile, correct, answered) {
  return {
    username: row.username,
    nombre: profile.nombre || row.username,
    avatar: profile.avatar || '',
    nivel: Number(profile.nivel) || 1,
    xp: Number(profile.xp) || 0,
    correctas: correct,
    respondidas: answered
  };
}

function rankingForCourse(course, users) {
  const ranking = [];

  for (const row of users) {
    const profile = parseProfile(row.profile_json);
    const registros = Array.isArray(profile.registrosGeneral) ? profile.registrosGeneral : [];

    let correct = 0;
    let answered = 0;

    // 1) Usamos los registros explícitos del curso cuando existen.
    // Esto evita duplicar las mismas preguntas que también estén en progresoCursos.
    const registrosCurso = registros.filter(reg =>
      courseMatches(reg?.cursoNivel, course) ||
      courseMatches(reg?.curso, course) ||
      courseMatches(reg?.cursoNombre, course)
    );

    if (registrosCurso.length > 0) {
      answered = registrosCurso.length;
      correct = registrosCurso.reduce((total, reg) => {
        return total + (resultValue(reg) === true ? 1 : 0);
      }, 0);
    } else {
      // 2) Si no hay registrosGeneral para ese curso, usamos progresoCursos.
      // Se aceptan claves como "Comunicación|facil" o "Comunicación (Básico)".
      const progresoCursos = profile.progresoCursos && typeof profile.progresoCursos === 'object'
        ? profile.progresoCursos
        : {};

      for (const key of Object.keys(progresoCursos)) {
        if (!courseMatches(key, course)) continue;
        const stats = countProgressItem(progresoCursos[key]);
        answered += stats.answered;
        correct += stats.correct;
      }
    }

    // IMPORTANTE: un usuario sin respuestas en este curso NO pertenece al ranking.
    // Esto elimina los usuarios fantasma que aparecían con 0 correctas.
    if (answered <= 0) continue;

    ranking.push(buildRankingEntry(row, profile, correct, answered));
  }

  ranking.sort((a, b) =>
    b.correctas - a.correctas ||
    b.respondidas - a.respondidas ||
    b.xp - a.xp ||
    a.username.localeCompare(b.username)
  );

  return ranking.slice(0, 50).map((x, i) => ({ posicion: i + 1, ...x }));
}

app.get('/api/rankings', async (req, res) => {
  try {
    const course = cleanUsername(req.query.course);
    if (!course) return res.status(400).json({ error: 'Falta course.' });

    const { rows } = await pool.query('SELECT username, profile_json FROM users');
    const ranking = rankingForCourse(course, rows);

    res.json({
      ok: true,
      course,
      totalUsuarios: ranking.length,
      ranking
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'No se pudo cargar el ranking.' });
  }
});

app.get('/api/admin/users', async (req, res) => {
  try {
    if (String(req.headers['x-admin-key'] || '') !== ADMIN_KEY) {
      return res.status(403).json({ error: 'No autorizado.' });
    }
    const { rows } = await pool.query(
      'SELECT id, username, profile_json, created_at, updated_at FROM users ORDER BY updated_at DESC'
    );
    res.json({
      users: rows.map(r => ({
        id: r.id,
        username: r.username,
        profile: parseProfile(r.profile_json),
        created_at: r.created_at,
        updated_at: r.updated_at
      }))
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'No se pudo cargar la lista de usuarios.' });
  }
});

app.use((err, _req, res, _next) => {
  console.error(err);
  res.status(500).json({ error: 'Error interno del servidor.' });
});

await initDb();
app.listen(PORT, '0.0.0.0', () => console.log(`EduFriends server listening on 0.0.0.0:${PORT}`));

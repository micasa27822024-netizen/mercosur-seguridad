import { initializeApp } from "https://www.gstatic.com/firebasejs/10.8.0/firebase-app.js";
import { getAuth, signInWithEmailAndPassword, signOut, onAuthStateChanged } from "https://www.gstatic.com/firebasejs/10.8.0/firebase-auth.js";
import { getDatabase, ref, get } from "https://www.gstatic.com/firebasejs/10.8.0/firebase-database.js";

const firebaseConfig = {
  apiKey: "AIzaSyBu4IS3qftwYLwsGkeiu2ht5FyZgCChlBY",
  authDomain: "mercosur-seguridad.firebaseapp.com",
  databaseURL: "https://mercosur-seguridad-default-rtdb.firebaseio.com",
  projectId: "mercosur-seguridad",
  storageBucket: "mercosur-seguridad.firebasestorage.app",
  messagingSenderId: "197382650125",
  appId: "1:197382650125:web:edc6cf98d1c236b0f0d844"
};

const app  = initializeApp(firebaseConfig);
const auth = getAuth(app);
const db   = getDatabase(app);

// Helper: limita una promesa a un maximo de ms. Si se excede, resuelve con
// el valor de reserva en vez de quedar colgada (clave en navegadores moviles
// con storage/red restringidos). Aditivo, no altera la logica existente.
function conLimite(promesa, ms, reserva) {
  return new Promise((resolve) => {
    let listo = false;
    const t = setTimeout(() => { if (!listo) { listo = true; resolve(reserva); } }, ms);
    Promise.resolve(promesa).then(
      (v) => { if (!listo) { listo = true; clearTimeout(t); resolve(v); } },
      () => { if (!listo) { listo = true; clearTimeout(t); resolve(reserva); } }
    );
  });
}

// --- Sesión lista: al recargar, Firebase Auth restaura la sesión de forma
// asíncrona. Esta promesa se resuelve en el primer onAuthStateChanged, para
// que cargarDatos() no pida datos SIN token (lo que la regla rechaza).
// Aditivo: no modifica ninguna lógica existente.
window.authListoPanel = new Promise((resolve) => {
  let resuelto = false;
  const marcar = () => { if (!resuelto) { resuelto = true; resolve(); } };
  onAuthStateChanged(auth, () => marcar());
  // Red de seguridad: si por algún motivo no llega el evento, no bloquear.
  setTimeout(marcar, 4000);
});

/**
 * Login REAL del supervisor: valida credenciales en Firebase Auth y lee
 * el rol guardado en /usuarios/<uid>/rol. Se permite entrar con rol
 * 'supervisor' o 'admin' (el admin puede ver todo).
 * @returns {Promise<{ok:boolean, uid?:string, rol?:string, mensaje?:string}>}
 */
async function loginSupervisorReal(email, password) {
  if (!email || !password) {
    return { ok: false, mensaje: 'Ingresá el correo y la contraseña.' };
  }
  try {
    const cred = await signInWithEmailAndPassword(auth, email, password);
    const uid  = cred.user.uid;

    let rol = null;
    let rolTimeout = false;
    try {
      const snap = await conLimite(get(ref(db, `usuarios/${uid}`)), 12000, '__TIMEOUT__');
      if (snap === '__TIMEOUT__') { rolTimeout = true; }
      else if (snap && snap.exists()) { rol = (snap.val() || {}).rol || null; }
    } catch (_) { /* si falla la lectura, se rechaza abajo */ }

    if (rolTimeout) {
      try { await signOut(auth); } catch (_) {}
      return { ok: false, mensaje: 'La conexión está lenta y no se pudo verificar tu acceso. Reintentá en unos segundos.' };
    }

    if (rol !== 'admin' && rol !== 'supervisor') {
      try { await signOut(auth); } catch (_) {}
      return { ok: false, mensaje: 'Tu usuario no tiene permisos para este panel.' };
    }
    _tokenTimestamp = Date.now();
    _iniciarRenovacionToken();
    return { ok: true, uid, rol };
  } catch (e) {
    let mensaje = 'Correo o contraseña incorrectos.';
    switch (e && e.code) {
      case 'auth/invalid-email':          mensaje = 'El correo no es válido.'; break;
      case 'auth/user-disabled':          mensaje = 'Esta cuenta está deshabilitada.'; break;
      case 'auth/user-not-found':
      case 'auth/wrong-password':
      case 'auth/invalid-credential':     mensaje = 'Correo o contraseña incorrectos.'; break;
      case 'auth/too-many-requests':      mensaje = 'Demasiados intentos. Esperá unos minutos e intentá de nuevo.'; break;
      case 'auth/network-request-failed': mensaje = 'Sin conexión. Revisá tu internet.'; break;
    }
    return { ok: false, mensaje };
  }
}
window.loginSupervisorReal = loginSupervisorReal;

// --- Restauracion de sesion basada en Firebase Auth (no solo sessionStorage) ---
// El panel solo se muestra si Auth confirma un usuario REAL con rol
// supervisor o admin. Un flag editable (sessionStorage.auth_supervisor) ya
// no alcanza para exponer la UI del panel.
onAuthStateChanged(auth, async (user) => {
  const contenido = document.getElementById('contenidoPanel');
  const yaVisible = () => contenido && !contenido.classList.contains('hidden');
  if (!user) {
    sessionStorage.removeItem('auth_supervisor');
    sessionStorage.removeItem('rol_supervisor');
    sessionStorage.removeItem('uid_supervisor');
    return;
  }
  let rol = null;
  try {
    const snap = await get(ref(db, `usuarios/${user.uid}`));
    if (snap.exists()) { rol = (snap.val() || {}).rol || null; }
  } catch (_) {}
  if (rol !== 'admin' && rol !== 'supervisor') {
    sessionStorage.removeItem('auth_supervisor');
    return;
  }
  sessionStorage.setItem('auth_supervisor', 'true');
  sessionStorage.setItem('rol_supervisor', rol);
  sessionStorage.setItem('uid_supervisor', user.uid);
  _tokenTimestamp = Date.now();
  _iniciarRenovacionToken();
  if (!yaVisible() && typeof window.mostrarPanel === 'function') window.mostrarPanel();
});

async function logoutSupervisorReal() {
  _detenerRenovacionToken();
  try { await signOut(auth); } catch (_) {}
}
window.logoutSupervisorReal = logoutSupervisorReal;

// --- Token del supervisor para autenticar escrituras REST (reglas .write endurecidas) ---
// Aditivo: no modifica ninguna lógica existente. Devuelve la URL con ?auth=<idToken> si hay sesión.
// ─────────────────────────────────────────────────────────────────────────────
//  RENOVACIÓN AUTOMÁTICA DEL TOKEN (igual que admin.module.js)
//  Cada 50 min se renueva proactivamente; si una lectura falla por token
//  vencido, se refresca y reintenta automáticamente.
// ─────────────────────────────────────────────────────────────────────────────
const TOKEN_MAX_ANTIGUEDAD_MS = 50 * 60 * 1000;
let _tokenTimestamp = 0;
let _tokenRefreshing = null;

async function _forzarRefreshToken() {
  if (_tokenRefreshing) return _tokenRefreshing;
  _tokenRefreshing = (async () => {
    try {
      const u = auth.currentUser;
      if (!u) return null;
      const token = await u.getIdToken(true);
      _tokenTimestamp = Date.now();
      return token;
    } catch (e) {
      console.warn('[Token Panel] Error al renovar:', e && (e.code || e.message));
      _tokenTimestamp = 0;
      return null;
    } finally {
      _tokenRefreshing = null;
    }
  })();
  return _tokenRefreshing;
}
window._forzarRefreshTokenPanel = _forzarRefreshToken;

let _timerRenovacion = null;
function _iniciarRenovacionToken() {
  if (_timerRenovacion) return;
  _timerRenovacion = setInterval(() => {
    if (auth.currentUser) {
      _forzarRefreshToken().catch(() => {});
    } else {
      clearInterval(_timerRenovacion);
      _timerRenovacion = null;
    }
  }, TOKEN_MAX_ANTIGUEDAD_MS);
}
function _detenerRenovacionToken() {
  if (_timerRenovacion) { clearInterval(_timerRenovacion); _timerRenovacion = null; }
}

window.obtenerTokenSupervisor = async () => {
  try {
    const u = auth.currentUser;
    if (!u) return null;
    if (Date.now() - _tokenTimestamp > TOKEN_MAX_ANTIGUEDAD_MS) {
      const fresco = await _forzarRefreshToken();
      if (fresco) return fresco;
    }
    return await u.getIdToken();
  } catch (_) { return null; }
};
window.urlConAuthPanel = async (url) => {
  let token = null;
  try { token = await window.obtenerTokenSupervisor(); } catch (_) {}
  if (!token) return url;
  return url + (url.includes('?') ? '&' : '?') + 'auth=' + encodeURIComponent(token);
};

// fetch con reintento automático en 401: renueva el token y reintenta UNA vez.
window.fetchConAuthPanel = async (url, options = {}) => {
  const urlConAuth = await window.urlConAuthPanel(url);
  const res1 = await fetch(urlConAuth, options);
  if (res1.status === 401) {
    // Token vencido: renovar y reintentar
    const tokenFresco = await _forzarRefreshToken();
    if (tokenFresco) {
      const urlFresca = url + (url.includes('?') ? '&' : '?') + 'auth=' + encodeURIComponent(tokenFresco);
      return fetch(urlFresca, options);
    }
  }
  return res1;
};

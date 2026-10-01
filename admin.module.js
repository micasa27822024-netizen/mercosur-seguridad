// ---- Módulos requeridos desde la CDN de Firebase (v10.8.0) ----
import { initializeApp } from "https://www.gstatic.com/firebasejs/10.8.0/firebase-app.js";
import { getAuth, createUserWithEmailAndPassword, signInWithEmailAndPassword, signOut, onAuthStateChanged, setPersistence, browserSessionPersistence } from "https://www.gstatic.com/firebasejs/10.8.0/firebase-auth.js";
import { getDatabase, ref, set, get, remove } from "https://www.gstatic.com/firebasejs/10.8.0/firebase-database.js";

// ---- Configuración de tu proyecto Firebase ----
const firebaseConfig = {
  apiKey: "AIzaSyBu4IS3qftwYLwsGkeiu2ht5FyZgCChlBY",
  authDomain: "mercosur-seguridad.firebaseapp.com",
  databaseURL: "https://mercosur-seguridad-default-rtdb.firebaseio.com",
  projectId: "mercosur-seguridad",
  storageBucket: "mercosur-seguridad.firebasestorage.app",
  messagingSenderId: "197382650125",
  appId: "1:197382650125:web:edc6cf98d1c236b0f0d844"
};

// ---- App PRINCIPAL (sesión del Administrador) ----
const mainApp = initializeApp(firebaseConfig);
const mainDb  = getDatabase(mainApp);
const mainAuth = getAuth(mainApp);

// La sesion del admin NO debe sobrevivir al cierre de la pestana/navegador.
// Con persistencia de SESION (no local), al salir y volver a entrar el panel
// arranca limpio en la pantalla de login, sin quedar 'pegado' a una sesion
// vieja (esto evita tener que borrar el historial para poder reingresar).
try { setPersistence(mainAuth, browserSessionPersistence).catch(function () {}); } catch (_) {}

/**
 * Login REAL de admin: valida credenciales en Firebase Auth
 * y lee el rol guardado en la base de datos: /usuarios/<uid>/rol.
 * Solo se permite entrar con rol 'admin' (los supervisores quedan excluidos).
 * @returns {Promise<{ok:boolean, uid?:string, rol?:string, mensaje?:string}>}
 */
// Utilidad: limita el tiempo de una promesa. Si supera el tiempo, resuelve
// con un valor de reserva (nunca deja el login colgado). Clave en celulares,
// donde ciertas operaciones de almacenamiento/persistencia pueden trabarse.
function conLimite(promesa, ms, valorReserva) {
  return Promise.race([
    Promise.resolve(promesa).catch(function () { return valorReserva; }),
    new Promise(function (res) { setTimeout(function () { res(valorReserva); }, ms); })
  ]);
}

async function loginAdminReal(email, password) {
  if (!email || !password) {
    return { ok: false, mensaje: 'Ingresá el correo y la contraseña.' };
  }
  try {
    // Persistencia de SESION: se intenta, pero NO debe bloquear el login. En
    // algunos navegadores de celular esta operacion puede trabarse; por eso
    // la limitamos en el tiempo y seguimos igual (login primero, todo lo demas
    // es secundario).
    await conLimite(setPersistence(mainAuth, browserSessionPersistence), 1500, null);
    const cred = await signInWithEmailAndPassword(mainAuth, email, password);
    const uid  = cred.user.uid;

    // Leer el rol desde /usuarios/<uid> (con limite de tiempo: en celular la
    // lectura puede colgarse y dejaria el boton "sin hacer nada").
    let rol = null, existeNodo = false, errorLectura = null;
    try {
      const snap = await conLimite(get(ref(mainDb, `usuarios/${uid}`)), 12000, '__TIMEOUT__');
      if (snap === '__TIMEOUT__') {
        errorLectura = 'tiempo de espera agotado al leer el rol';
      } else {
        existeNodo = snap.exists();
        if (existeNodo) { rol = (snap.val() || {}).rol || null; }
      }
    } catch (e2) { errorLectura = (e2 && (e2.code || e2.message)) || 'desconocido'; }

    // Separación de roles: este panel es EXCLUSIVO de administradores.
    // Un supervisor NO puede ingresar al panel completo de admin.
    if (rol !== 'admin') {
      try { await signOut(mainAuth); } catch (_) {}
      // Diagnóstico temporal: mostramos el UID real para poder compararlo con la base
      let detalle;
      if (errorLectura) {
        detalle = 'No se pudo leer /usuarios (las reglas bloquean la lectura): ' + errorLectura;
      } else if (!existeNodo) {
        detalle = 'No existe el nodo usuarios/' + uid + ' . Copiá EXACTO este UID en la base: ' + uid;
      } else if (rol === 'supervisor') {
        detalle = 'Tu usuario es de rol "supervisor" y este panel es exclusivo de administradores. No tenés acceso al panel de administración.';
      } else {
        detalle = 'El nodo existe pero el rol leído fue "' + (rol === null ? '(vacío)' : rol) + '". Se requiere rol "admin". UID: ' + uid;
      }
      return { ok: false, mensaje: detalle };
    }
    // Marcar la hora del token recién emitido e iniciar renovación automática
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
window.loginAdminReal = loginAdminReal;

// --- Restauracion de sesion basada en Firebase Auth (no solo sessionStorage) ---
// El panel solo se muestra si Auth confirma un usuario REAL con rol admin.
// Asi un flag editable (sessionStorage.auth_admin) ya no alcanza para exponer la UI.
onAuthStateChanged(mainAuth, async (user) => {
  const contenido = document.getElementById('contenidoAdmin');
  const yaVisible = () => contenido && !contenido.classList.contains('hidden');
  if (!user) {
    // Sin sesion real: limpiar flags. El estado inicial del HTML ya muestra el login.
    sessionStorage.removeItem('auth_admin');
    sessionStorage.removeItem('rol_admin');
    sessionStorage.removeItem('uid_admin');
    sessionStorage.removeItem('email_admin');
    return;
  }
  // Hay usuario autenticado: validar rol admin contra /usuarios/<uid>/rol.
  let rol = null;
  try {
    const snap = await get(ref(mainDb, `usuarios/${user.uid}/rol`));
    rol = snap.exists() ? snap.val() : null;
  } catch (_) {}
  if (rol !== 'admin') {
    // Autenticado pero sin rol admin: no se expone el panel de administracion.
    sessionStorage.removeItem('auth_admin');
    return;
  }
  // Sesion admin confirmada: repoblar flags de sesion y mostrar la UI una sola vez.
  sessionStorage.setItem('auth_admin', 'true');
  sessionStorage.setItem('rol_admin', rol);
  sessionStorage.setItem('uid_admin', user.uid);
  if (user.email) sessionStorage.setItem('email_admin', user.email);
  // Iniciar la renovación automática del token (se refresca cada 50 min)
  _tokenTimestamp = Date.now();
  _iniciarRenovacionToken();
  if (!yaVisible() && typeof window.mostrarAdmin === 'function') window.mostrarAdmin();
});

// --- Token del admin/supervisor para autenticar escrituras REST (reglas .write endurecidas) ---
// Aditivo: no modifica ninguna lógica existente. Devuelve la URL con ?auth=<idToken> si hay sesión.
// ─────────────────────────────────────────────────────────────────────────────
//  RENOVACIÓN AUTOMÁTICA DEL TOKEN
//  Firebase Auth emite tokens de ~1h. El SDK los refresca solo si está
//  "activo", pero en una pestaña abierta sin tocar, el token se queda
//  vencido y la próxima lectura/escritura falla con 401.
//  Solución: refrescar proactivamente cada 50 min y también antes de
//  cada operación si el token tiene más de 50 min de antigüedad.
// ─────────────────────────────────────────────────────────────────────────────
const TOKEN_MAX_ANTIGUEDAD_MS = 50 * 60 * 1000; // 50 minutos
let _tokenTimestamp = 0;    // cuándo se emitió el último token (ms)
let _tokenRefreshing = null; // Promise en curso (evita refreshes simultáneos)

// Renueva el token del admin forzando la petición al servidor.
// Si ya hay un refresh en curso, espera ese en vez de lanzar otro.
async function _forzarRefreshToken() {
  if (_tokenRefreshing) return _tokenRefreshing;
  _tokenRefreshing = (async () => {
    try {
      const u = mainAuth.currentUser;
      if (!u) return null;
      const token = await u.getIdToken(true); // fuerza refresh contra Google
      _tokenTimestamp = Date.now();
      return token;
    } catch (e) {
      // Si falla el refresh, puede ser que la sesión se perdió
      console.warn('[Token Admin] Error al renovar:', e && (e.code || e.message));
      _tokenTimestamp = 0;
      return null;
    } finally {
      _tokenRefreshing = null;
    }
  })();
  return _tokenRefreshing;
}

// Arranca el timer que renueva el token cada 50 minutos, mientras haya sesión.
// Se apaga automáticamente si el usuario cierra sesión.
let _timerRenovacion = null;
function _iniciarRenovacionToken() {
  if (_timerRenovacion) return; // ya está corriendo
  _timerRenovacion = setInterval(() => {
    if (mainAuth.currentUser) {
      _forzarRefreshToken().catch(() => {});
    } else {
      // No hay sesión: detener el timer
      clearInterval(_timerRenovacion);
      _timerRenovacion = null;
    }
  }, TOKEN_MAX_ANTIGUEDAD_MS);
}
function _detenerRenovacionToken() {
  if (_timerRenovacion) { clearInterval(_timerRenovacion); _timerRenovacion = null; }
}

// Devuelve un idToken válido. Si el token tiene >50 min, lo renueva antes.
// Si no hay sesión, devuelve null.
window.obtenerTokenAdmin = async () => {
  try {
    const u = mainAuth.currentUser;
    if (!u) return null;
    // ¿El token actual tiene más de 50 minutos? Renovar primero.
    if (Date.now() - _tokenTimestamp > TOKEN_MAX_ANTIGUEDAD_MS) {
      const fresco = await _forzarRefreshToken();
      if (fresco) return fresco;
    }
    // Token dentro de la ventana de validez: usar cacheado.
    return await u.getIdToken();
  } catch (_) { return null; }
};
// Construye la URL con ?auth=<idToken>. Si el token puede estar
// vencido, obtenerTokenAdmin lo renueva automáticamente.
window.urlConAuthAdmin = async (url) => {
  let token = null;
  try { token = await window.obtenerTokenAdmin(); } catch (_) {}
  if (!token) return url;
  return url + (url.includes('?') ? '&' : '?') + 'auth=' + encodeURIComponent(token);
};

// --- LLAMADA UNIFICADA AL WORKER PARA ACCIONES ADMIN (server-side, autoritativo) ---
// Envia la accion al Worker, que valida el idToken + rol admin y escribe la
// AUDITORIA con la service account (las reglas de Firebase ya NO permiten
// escritura directa desde el panel para estas operaciones). Devuelve el JSON
// de respuesta o lanza Error con el mensaje del Worker.
// Llama al Worker con reintentos automáticos: si el token estaba
// vencido (401), lo renueva y reintenta UNA vez antes de fallar.
window.llamarWorkerAdmin = async (payload) => {
  const base = String(URL_WORKER_AUTH || '').trim();
  if (!base) throw new Error('El Worker de autenticacion no esta configurado (URL_WORKER_AUTH vacio).');
  const idToken = await window.obtenerTokenAdmin();
  if (!idToken) throw new Error('No hay sesion de administrador activa (falta idToken).');

  const hacerPeticion = async (token) => {
    const res = await fetch(base, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ...payload, idToken: token })
    });
    let data = null;
    try { data = await res.json(); } catch (_) {}
    if (!res.ok || !data || data.error) {
      const msg = (data && data.error) ? data.error : ('HTTP ' + res.status);
      throw new Error(msg);
    }
    return data;
  };

  try {
    return await hacerPeticion(idToken);
  } catch (e1) {
    // Si fue error de auth (401/token vencido), renovar y reintentar UNA vez
    if (e1 && /401|Permission denied|token|auth/i.test(e1.message)) {
      const tokenFresco = await _forzarRefreshToken();
      if (tokenFresco) return await hacerPeticion(tokenFresco);
    }
    throw e1;
  }
};

async function logoutAdminReal() {
  _detenerRenovacionToken();
  try { await signOut(mainAuth); } catch (_) {}
}
window.logoutAdminReal = logoutAdminReal;

// ---- App SECUNDARIA (crea empleados SIN cerrar la sesión del admin) ----
const secondaryApp  = initializeApp(firebaseConfig, "SecondaryApp");
const secondaryAuth = getAuth(secondaryApp);

/**
 * Registra un empleado creando su credencial real de acceso en Firebase Auth
 * (usando la instancia secundaria) y guardando su ficha en Realtime Database.
 * @param {string} legajo  N° de legajo (ej: "0297")
 * @param {string} nombre  Nombre completo (ej: "Juan Pérez")
 * @param {string} pin     PIN numérico de 4+ dígitos (ej: "3456")
 * @param {string|null} fotoMaster  Foto máster en base64 (opcional)
 * @param {string} rol     Rol a asignar: 'empleado' (por defecto), 'supervisor' o 'admin'.
 */
async function registrarEmpleado(legajo, nombre, pin, fotoMaster = null, rol = 'empleado') {
  // a. Formateo de datos -> email y password sintéticos
  const legajoLimpio = String(legajo).trim();
  const nombreLimpio = String(nombre).trim();
  const pinLimpio    = String(pin).trim();

  // Rol: solo se aceptan los tres valores válidos. Cualquier otro -> 'empleado'.
  const rolesValidos = ['empleado', 'supervisor', 'admin'];
  const rolLimpio = rolesValidos.includes(String(rol).trim()) ? String(rol).trim() : 'empleado';

  const emailEmpleado    = `${legajoLimpio}@mercosurseg.com`;
  const passwordEmpleado = pinLimpio.padStart(6, '0'); // "3456" -> "003456"

  try {
    // b. Crear la credencial en la instancia SECUNDARIA
    const credencial = await createUserWithEmailAndPassword(secondaryAuth, emailEmpleado, passwordEmpleado);
    const uid = credencial.user.uid;

    // c. Guardar la ficha del empleado en personal/${uid}
    // El PIN no se guarda en texto plano: se deriva un hash con salt.
    const pinSaltNuevo = window.generarSaltVigix();
    const pinHashNuevo = await window.hashPinVigix(pinLimpio, pinSaltNuevo);
    await set(ref(mainDb, `personal/${uid}`), {
      legajo: legajoLimpio,
      nombre: nombreLimpio,
      estado: "activo",
      authUid: uid,
      fechaAlta: new Date().toISOString(),
      // --- Campos adicionales para compatibilidad con el panel actual ---
      // (necesarios para que la tabla y "Configurar" sigan funcionando)
      // El hash/salt del PIN NO va en /personal (lo leen los supervisores):
      // se marca solo que tiene PIN y las credenciales van en /credenciales/<uid>.
      tienePin: true,
      fotoMaster: fotoMaster || null,
      horarioHabitual: { inicio: '', fin: '' },
      objetivosAsignados: []
    });
    // Credenciales en nodo aislado (acceso solo admin/dueño por Reglas).
    await set(ref(mainDb, `credenciales/${uid}`), {
      pinHash: pinHashNuevo,
      pinSalt: pinSaltNuevo
    });

    // Mapa de identidad /usuarios/<uid> = { legajo, rol }. IMPRESCINDIBLE:
    // las Reglas de Seguridad usan root.child('usuarios').child(auth.uid).child('legajo')
    // para autorizar que el empleado lea SOLO su propia ficha e historial.
    // Sin esta entrada, el empleado no podría ver sus datos ni fichar con
    // validación completa. El rol se toma del selector del alta (por defecto
    // 'empleado'; 'supervisor'/'admin' solo cuando el admin lo elige).
    await set(ref(mainDb, `usuarios/${uid}`), {
      legajo: legajoLimpio,
      rol: rolLimpio
    });

    // d. Cerrar de inmediato la sesión secundaria
    await signOut(secondaryAuth);

    const etiquetaRol = rolLimpio === 'admin' ? 'Administrador'
                      : rolLimpio === 'supervisor' ? 'Supervisor'
                      : 'Empleado (vigilador)';
    alert(`✅ Usuario registrado con éxito.\nLegajo: ${legajoLimpio}\nNombre: ${nombreLimpio}\nRol: ${etiquetaRol}\nPIN de acceso: ${pinLimpio}`);
    return { ok: true, uid, rol: rolLimpio };
  } catch (error) {
    // e. Manejo claro de errores
    let mensaje;
    switch (error && error.code) {
      case 'auth/email-already-in-use':
        mensaje = `⚠️ El legajo "${legajoLimpio}" ya está registrado. Usá otro número de legajo.`;
        break;
      case 'auth/invalid-email':
        mensaje = '⚠️ El legajo genera un correo inválido. Revisá el dato ingresado.';
        break;
      case 'auth/weak-password':
        mensaje = '⚠️ El PIN es demasiado corto: la contraseña debe tener al menos 6 caracteres.';
        break;
      default:
        mensaje = '❌ Ocurrió un problema al registrar el empleado: ' + ((error && error.message) || (error && error.code) || error);
    }
    alert(mensaje);
    // Por seguridad, intentar cerrar la sesión secundaria si quedó abierta
    try { await signOut(secondaryAuth); } catch (_) {}
    return { ok: false, error };
  }
}

// Exponer la función por si querés invocarla desde otras partes del panel
window.registrarEmpleado = registrarEmpleado;

/**
 * MIGRACIÓN de empleados creados con el sistema anterior (sin credencial de acceso).
 * - Crea la cuenta de acceso (legajo@mercosurseg.com / PIN a 6 dígitos) en la instancia secundaria.
 * - Mueve la ficha a personal/{uid} conservando TODOS sus datos (foto, horario, objetivos, etc.).
 * - Borra la ficha vieja SOLO después de confirmar que la nueva quedó guardada.
 * NOTA: las fichadas, turnos y alertas se vinculan por LEGAJO, no por la clave de la ficha,
 *       por lo que la migración NO afecta ni borra ninguna fichada histórica.
 */
async function migrarEmpleadosAnteriores() {
  const logEl = document.getElementById('migracionLog');
  const escribir = (txt, color) => {
    if (!logEl) return;
    const p = document.createElement('div');
    p.className = 'text-xs ' + (color || 'text-slate-300');
    p.textContent = txt;
    logEl.appendChild(p);
    logEl.scrollTop = logEl.scrollHeight;
  };

  if (!confirm('Se crearán las credenciales de acceso de los empleados anteriores y se normalizarán sus fichas. Las fichadas históricas NO se tocan. ¿Continuar?')) return;

  if (logEl) logEl.innerHTML = '';
  escribir('⏳ Leyendo personal...', 'text-slate-400');

  let snapshot;
  try {
    snapshot = await get(ref(mainDb, 'personal'));
  } catch (e) {
    escribir('❌ No se pudo leer el personal: ' + (e.message || e), 'text-rose-400');
    return;
  }

  const data = snapshot.exists() ? snapshot.val() : null;
  if (!data) { escribir('No hay personal registrado.', 'text-slate-400'); return; }

  const entradas = Object.entries(data);
  let migrados = 0, omitidos = 0, errores = 0;

  for (const [clave, ficha] of entradas) {
    const legajo = ficha && ficha.legajo ? String(ficha.legajo).trim() : '';
    const nombre = ficha && ficha.nombre ? String(ficha.nombre) : '';

    // Ya migrado: la clave del nodo coincide con su authUid
    if (ficha && ficha.authUid && clave === ficha.authUid) {
      escribir(`↷ ${legajo || clave} (${nombre}) ya está en el sistema nuevo. Se omite.`, 'text-slate-500');
      omitidos++;
      continue;
    }

    if (!legajo) { escribir(`⚠️ Ficha ${clave} sin legajo. Se omite.`, 'text-amber-400'); omitidos++; continue; }
    if (!ficha.pin) { escribir(`⚠️ ${legajo} (${nombre}) no tiene PIN guardado. No se puede crear su acceso; se omite.`, 'text-amber-400'); omitidos++; continue; }

    const email = `${legajo}@mercosurseg.com`;
    const password = String(ficha.pin).trim().padStart(6, '0');

    let uid = null;
    try {
      const cred = await createUserWithEmailAndPassword(secondaryAuth, email, password);
      uid = cred.user.uid;
    } catch (e) {
      if (e && e.code === 'auth/email-already-in-use') {
        // La cuenta ya existe: iniciamos sesión para recuperar su uid
        try {
          const cred = await signInWithEmailAndPassword(secondaryAuth, email, password);
          uid = cred.user.uid;
          escribir(`ℹ️ ${legajo} ya tenía cuenta de acceso. Se normaliza su ficha.`, 'text-sky-400');
        } catch (e2) {
          escribir(`❌ ${legajo}: la cuenta ya existe pero el PIN no coincide. Revisar manualmente.`, 'text-rose-400');
          errores++;
          continue;
        }
      } else {
        escribir(`❌ ${legajo}: ${e.message || e.code || e}`, 'text-rose-400');
        errores++;
        continue;
      }
    }

    // Cerrar la sesión secundaria de inmediato
    try { await signOut(secondaryAuth); } catch (_) {}

    // Si la clave ya es el uid, solo aseguramos authUid
    if (clave === uid) {
      try {
        await set(ref(mainDb, `personal/${uid}/authUid`), uid);
        // Mapa de identidad /usuarios/<uid> para las Reglas (no pisa un rol
        // admin/supervisor ya existente; por defecto 'empleado').
        try {
          const uSnap = await get(ref(mainDb, `usuarios/${uid}`));
          const rolPrev = uSnap.exists() ? (uSnap.val() || {}).rol : null;
          await set(ref(mainDb, `usuarios/${uid}`), { legajo: String(legajo).trim(), rol: rolPrev || 'empleado' });
        } catch (_) {}
        escribir(`✅ ${legajo} (${nombre}) actualizado.`, 'text-emerald-400');
        migrados++;
      } catch (e) { escribir(`❌ ${legajo}: ${e.message || e}`, 'text-rose-400'); errores++; }
      continue;
    }

    // Mover la ficha a personal/{uid} conservando los datos operativos, pero
    // SIN las credenciales: pinHash/pinSalt/pin salen de /personal y van a
    // /credenciales/<uid> (nodo aislado, solo admin/dueño por Reglas).
    const credencialMig = (ficha.pinHash && ficha.pinSalt)
      ? { pinHash: ficha.pinHash, pinSalt: ficha.pinSalt }
      : (String(ficha.pin || '').trim()
          ? await (async () => { const s = window.generarSaltVigix(); return { pinHash: await window.hashPinVigix(String(ficha.pin).trim(), s), pinSalt: s }; })()
          : null);
    const nuevaFicha = { ...ficha, authUid: uid, estado: ficha.estado || 'activo', tienePin: !!(credencialMig || ficha.tienePin) };
    delete nuevaFicha.pin; delete nuevaFicha.pinHash; delete nuevaFicha.pinSalt; delete nuevaFicha.clave;

    try {
      await set(ref(mainDb, `personal/${uid}`), nuevaFicha);
      if (credencialMig) { await set(ref(mainDb, `credenciales/${uid}`), credencialMig); }
      // Mapa de identidad /usuarios/<uid> para las Reglas (no pisa un rol
      // admin/supervisor ya existente; por defecto 'empleado').
      try {
        const uSnap = await get(ref(mainDb, `usuarios/${uid}`));
        const rolPrev = uSnap.exists() ? (uSnap.val() || {}).rol : null;
        await set(ref(mainDb, `usuarios/${uid}`), { legajo: String(legajo).trim(), rol: rolPrev || 'empleado' });
      } catch (_) {}
      // Verificar que quedó escrita antes de borrar la vieja
      const verif = await get(ref(mainDb, `personal/${uid}`));
      if (!verif.exists()) throw new Error('no se pudo verificar la escritura');
      // Borrar la ficha vieja (las fichadas por legajo NO se ven afectadas)
      await remove(ref(mainDb, `personal/${clave}`));
      escribir(`✅ ${legajo} (${nombre}) migrado correctamente.`, 'text-emerald-400');
      migrados++;
    } catch (e) {
      escribir(`❌ ${legajo}: error al mover la ficha (${e.message || e}). La ficha original NO se borró.`, 'text-rose-400');
      errores++;
    }
  }

  escribir(`— Migración finalizada: ${migrados} migrado(s), ${omitidos} omitido(s), ${errores} con error. —`, 'text-white');
  if (typeof window.recargarDatosEfectivo === 'function') window.recargarDatosEfectivo();
  alert(`Migración finalizada.\nMigrados: ${migrados}\nOmitidos: ${omitidos}\nErrores: ${errores}`);
}

window.migrarEmpleadosAnteriores = migrarEmpleadosAnteriores;

// ---- Botón de migración ----
const btnMigrar = document.getElementById('btnMigrarEmpleados');
if (btnMigrar) {
  btnMigrar.addEventListener('click', async () => {
    btnMigrar.disabled = true;
    const original = btnMigrar.innerHTML;
    btnMigrar.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Migrando...';
    try { await migrarEmpleadosAnteriores(); } finally {
      btnMigrar.disabled = false;
      btnMigrar.innerHTML = original;
    }
  });
}

/**
 * SINCRONIZAR /usuarios DESDE /personal (backfill de identidades).
 * Recorre /personal y asegura /usuarios/<uid> = { legajo, rol } para cada
 * ficha con legajo. Requisito de las Reglas: sin esta entrada el empleado
 * no puede leer su propia ficha/historial (query.equalTo compara contra
 * /usuarios/<uid>/legajo). Es idempotente y NO pisa un rol admin/supervisor
 * ya existente (solo completa 'empleado' donde falta).
 */
async function sincronizarUsuariosDesdePersonal() {
  const logEl = document.getElementById('sincronizarUsuariosLog');
  const escribir = (txt, color) => {
    if (!logEl) return;
    logEl.classList.remove('hidden');
    const p = document.createElement('div');
    p.className = 'text-xs ' + (color || 'text-slate-300');
    p.textContent = txt;
    logEl.appendChild(p);
    logEl.scrollTop = logEl.scrollHeight;
  };
  escribir('— Sincronizando identidades /usuarios desde /personal… —', 'text-white');
  let personal;
  try {
    const snap = await get(ref(mainDb, 'personal'));
    personal = snap.exists() ? snap.val() : null;
  } catch (e) { escribir(`❌ No se pudo leer /personal: ${e.message || e}`, 'text-rose-400'); alert('No se pudo leer /personal.'); return; }
  if (!personal) { escribir('↷ /personal sin registros.', 'text-slate-500'); alert('No hay empleados en /personal.'); return; }

  let creados = 0, existentes = 0, omitidos = 0, errores = 0;
  for (const [uid, ficha] of Object.entries(personal)) {
    const legajo = ficha && ficha.legajo != null ? String(ficha.legajo).trim() : '';
    if (!legajo) { omitidos++; escribir(`↷ ${uid}: ficha sin legajo, se omite.`, 'text-slate-500'); continue; }
    try {
      const uSnap = await get(ref(mainDb, `usuarios/${uid}`));
      if (uSnap.exists()) {
        const prev = uSnap.val() || {};
        // Ya existe: solo aseguramos que el legajo coincida, sin tocar el rol.
        if (String(prev.legajo || '').trim() !== legajo) {
          await set(ref(mainDb, `usuarios/${uid}`), { legajo, rol: prev.rol || 'empleado' });
          escribir(`🔄 ${legajo}: legajo actualizado (rol '${prev.rol || 'empleado'}' conservado).`, 'text-sky-400');
        }
        existentes++;
      } else {
        await set(ref(mainDb, `usuarios/${uid}`), { legajo, rol: 'empleado' });
        creados++;
        escribir(`✅ ${legajo}: identidad creada (rol 'empleado').`, 'text-emerald-400');
      }
    } catch (e) { errores++; escribir(`❌ ${legajo || uid}: ${e.message || e}`, 'text-rose-400'); }
  }
  escribir(`— Sincronización finalizada: ${creados} creada(s), ${existentes} ya existían, ${omitidos} sin legajo, ${errores} error(es). —`, 'text-white');
  alert(`Sincronización de identidades finalizada.\nCreadas: ${creados}\nYa existían: ${existentes}\nSin legajo: ${omitidos}\nErrores: ${errores}`);
}
window.sincronizarUsuariosDesdePersonal = sincronizarUsuariosDesdePersonal;

// ---- Botón de sincronización de identidades ----
const btnSincUsuarios = document.getElementById('btnSincronizarUsuarios');
if (btnSincUsuarios) {
  btnSincUsuarios.addEventListener('click', async () => {
    if (!confirm('Se va a crear/completar el mapa /usuarios para que cada empleado pueda ver solo sus propios datos. No modifica a admin ni supervisores. ¿Continuar?')) return;
    btnSincUsuarios.disabled = true;
    const original = btnSincUsuarios.innerHTML;
    btnSincUsuarios.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Sincronizando...';
    try { await sincronizarUsuariosDesdePersonal(); } finally {
      btnSincUsuarios.disabled = false;
      btnSincUsuarios.innerHTML = original;
    }
  });
}

// ---- Listener del formulario de alta con acceso ----
const formAltaEmpleado = document.getElementById('formAltaEmpleado');
if (formAltaEmpleado) {
  formAltaEmpleado.addEventListener('submit', async (event) => {
    event.preventDefault();

    const btn    = document.getElementById('btnAltaEmpleado');
    const legajo = document.getElementById('altaLegajo').value;
    const nombre = document.getElementById('altaNombre').value;
    const pin    = document.getElementById('altaPin').value;
    const inputFoto = document.getElementById('altaFotoMaster');
    const selRol = document.getElementById('altaRol');
    const rol    = selRol ? selRol.value : 'empleado';

    // Confirmación extra al crear un usuario con permisos elevados: un admin o
    // supervisor NO es un vigilador más (puede ver/gestionar datos de todos).
    if (rol === 'admin' || rol === 'supervisor') {
      const etq = rol === 'admin' ? 'ADMINISTRADOR (acceso total al panel)' : 'SUPERVISOR (control operativo)';
      if (!confirm('Vas a crear un usuario con rol ' + etq + '.\n\nLegajo: ' + String(legajo).trim() + '\n\n¿Confirmás que querés darle estos permisos?')) {
        return;
      }
    }

    if (btn) {
      btn.disabled = true;
      btn.dataset.original = btn.innerHTML;
      btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Creando...';
    }

    // Convertir la Foto Máster (IA) a base64 si el admin cargó una
    let fotoMasterBase64 = null;
    if (inputFoto && inputFoto.files && inputFoto.files[0] && typeof window.convertirImagenBase64 === 'function') {
      try { fotoMasterBase64 = await window.convertirImagenBase64(inputFoto.files[0]); } catch (_) { fotoMasterBase64 = null; }
    }

    const resultado = await registrarEmpleado(legajo, nombre, pin, fotoMasterBase64, rol);

    if (resultado && resultado.ok) {
      formAltaEmpleado.reset();
      // Tras reset, el selector vuelve a su valor por defecto ('empleado').
      if (selRol) selRol.value = 'empleado';
      // Generar un nuevo PIN para la próxima alta
      if (typeof window.generarPinEmpleado === 'function') window.generarPinEmpleado();
      // Refrescar la tabla de personal si la función del panel existe
      if (typeof window.recargarDatosEfectivo === 'function') {
        window.recargarDatosEfectivo();
      }
    }

    if (btn) {
      btn.disabled = false;
      btn.innerHTML = btn.dataset.original || '<i class="fa-solid fa-user-shield"></i> Crear empleado';
    }
  });
}

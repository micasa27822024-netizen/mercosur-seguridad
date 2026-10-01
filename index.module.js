    import { initializeApp } from "https://www.gstatic.com/firebasejs/10.8.0/firebase-app.js";
    import { getAuth, signInWithEmailAndPassword, signOut, setPersistence, browserSessionPersistence } from "https://www.gstatic.com/firebasejs/10.8.0/firebase-auth.js";

    const firebaseConfig = {
      apiKey: "AIzaSyBu4IS3qftwYLwsGkeiu2ht5FyZgCChlBY",
      authDomain: "mercosur-seguridad.firebaseapp.com",
      databaseURL: "https://mercosur-seguridad-default-rtdb.firebaseio.com",
      projectId: "mercosur-seguridad",
      storageBucket: "mercosur-seguridad.firebasestorage.app",
      messagingSenderId: "197382650125",
      appId: "1:197382650125:web:edc6cf98d1c236b0f0d844"
    };

    // Instancia dedicada para NO interferir con ninguna otra sesión de la app.
    const vigApp  = initializeApp(firebaseConfig, "VigAuthApp");
    const vigAuth = getAuth(vigApp);
    // La sesión sólo vive mientras la pestaña esté abierta (dispositivo
    // compartido). Al cerrar la pestaña, Firebase no restaura la sesión.
    try { setPersistence(vigAuth, browserSessionPersistence); } catch (_) {}

    /**
     * Inicia y MANTIENE la sesión del vigilador contra Firebase Auth.
     * El empleado se autentica con el correo sintético legajo@mercosurseg.com
     * y el PIN completado a 6 dígitos con ceros a la izquierda (igual que en el alta).
     * Devuelve el idToken para leer/escribir SOLO sus propios datos (?auth=).
     * @returns {Promise<{ok:boolean, idToken?:string, uid?:string, razon?:string}>}
     */
    async function loginVigilador(legajo, pin) {
      const legajoLimpio = String(legajo || '').trim();
      const pinLimpio    = String(pin || '').trim();
      if (!legajoLimpio || !pinLimpio) return { ok: false, razon: 'faltan_datos' };
      const email    = `${legajoLimpio}@mercosurseg.com`;
      const password = pinLimpio.padStart(6, '0');
      try {
        const cred = await signInWithEmailAndPassword(vigAuth, email, password);
        const idToken = await cred.user.getIdToken();
        _tokenTimestamp = Date.now();
        idTokenGlobal = idToken;
        _iniciarRenovacionToken();
        sincronizarRelojDesdeToken(idToken); // fijamos la hora oficial del servidor al iniciar sesion
        return { ok: true, idToken, uid: cred.user.uid };
      } catch (e) {
        return { ok: false, razon: (e && e.code) || 'error' };
      }
    }

    // Cierra la sesión activa del vigilador (dispositivo compartido / logout).
    async function logoutVigilador() {
      _detenerRenovacionToken();
      idTokenGlobal = null;
      try { await signOut(vigAuth); } catch (_) {}
    }

    // ---- HORA OFICIAL DEL SERVIDOR (validacion de reloj de la fichada) ----
    // No confiamos en el reloj del telefono para la hora de la fichada. Tomamos la
    // hora del servidor desde el sello 'iat' del idToken de Google (se emite con la
    // hora del servidor y lo renovamos justo ANTES de fichar). Con eso calculamos el
    // desfase del reloj local, sellamos la fichada con la hora oficial estimada y, si
    // el telefono tiene la hora cambiada mas alla de la tolerancia, marcamos la
    // fichada para revision (alertaFraude) para que el admin la vea.
    const UMBRAL_DESFASE_RELOJ_MS = 120000; // 2 minutos de tolerancia
    let offsetRelojServidorMs = null;       // horaServidor - horaDispositivo (ms)

    function decodificarPayloadJwt(token) {
      try {
        const parte = String(token).split('.')[1];
        if (!parte) return null;
        const base = parte.replace(/-/g, '+').replace(/_/g, '/');
        const relleno = base + '==='.slice((base.length + 3) % 4);
        return JSON.parse(atob(relleno));
      } catch (_) { return null; }
    }
    // Recalcula el desfase del reloj local usando la hora del servidor (iat del token).
    function sincronizarRelojDesdeToken(token) {
      const p = decodificarPayloadJwt(token);
      if (p && Number.isFinite(p.iat)) {
        offsetRelojServidorMs = (p.iat * 1000) - Date.now();
      }
    }
    // Hora oficial estimada (ms) = reloj local corregido por el desfase del servidor.
    function ahoraServidorMs() {
      return (typeof offsetRelojServidorMs === 'number') ? (Date.now() + offsetRelojServidorMs) : Date.now();
    }
    // Sella la fichada con la hora oficial y detecta relojes manipulados.
    // 'validado' es true SOLO cuando pudimos obtener hora fresca del servidor
    // (fichaje online con token recien renovado); offline no se puede validar.
    function aplicarHoraServidor(datos, validado) {
      const desfase = (typeof offsetRelojServidorMs === 'number') ? offsetRelojServidorMs : null;
      datos.horaServidorFichaje = new Date(ahoraServidorMs()).toISOString();
      datos.desfaseRelojMs = desfase;
      datos.horaValidadaPorServidor = !!validado;
      datos.relojDesincronizado = (!!validado) && (desfase !== null) && (Math.abs(desfase) > UMBRAL_DESFASE_RELOJ_MS);
      if (datos.relojDesincronizado) {
        const seg = Math.round(Math.abs(desfase) / 1000);
        datos.alertaFraude = true;
        const nota = 'Reloj del dispositivo desincronizado ~' + seg + 's respecto de la hora oficial del servidor.';
        datos.motivoFraude = datos.motivoFraude ? (datos.motivoFraude + ' | ' + nota) : nota;
      }
      return datos;
    }

    // ─────────────────────────────────────────────────────────────────────────────
    //  RENOVACIÓN AUTOMÁTICA DEL TOKEN (igual que admin/panel.module.js)
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
          if (vigAuth.currentUser) {
            const t = await vigAuth.currentUser.getIdToken(true);
            sincronizarRelojDesdeToken(t);
            _tokenTimestamp = Date.now();
            return t;
          }
        } catch (e) {
          console.warn('[Token Vigilador] Error al renovar:', e && (e.code || e.message));
          _tokenTimestamp = 0;
        } finally {
          _tokenRefreshing = null;
        }
        return null;
      })();
      return _tokenRefreshing;
    }

    let _timerRenovacion = null;
    function _iniciarRenovacionToken() {
      if (_timerRenovacion) return;
      _timerRenovacion = setInterval(() => {
        if (vigAuth.currentUser) {
          _forzarRefreshToken().then(t => { if (t) idTokenGlobal = t; }).catch(() => {});
        } else {
          clearInterval(_timerRenovacion);
          _timerRenovacion = null;
        }
      }, TOKEN_MAX_ANTIGUEDAD_MS);
    }
    function _detenerRenovacionToken() {
      if (_timerRenovacion) { clearInterval(_timerRenovacion); _timerRenovacion = null; }
    }

    // idToken global del vigilador: se actualiza automáticamente con el timer
    let idTokenGlobal = null;

    // Devuelve un idToken válido. Si el token tiene >50 min, lo renueva antes.
    async function obtenerTokenVigilador(forzar = false) {
      try {
        if (!vigAuth.currentUser) return null;
        if (forzar || Date.now() - _tokenTimestamp > TOKEN_MAX_ANTIGUEDAD_MS) {
          const fresco = await _forzarRefreshToken();
          if (fresco) { idTokenGlobal = fresco; return fresco; }
        }
        const cacheado = await vigAuth.currentUser.getIdToken();
        if (cacheado) idTokenGlobal = cacheado;
        return cacheado;
      } catch (_) { return null; }
    }

    // Compatibilidad: refrescarTokenVigilador() fuerza refresh (igual que antes)
    async function refrescarTokenVigilador() {
      const t = await _forzarRefreshToken();
      if (t) idTokenGlobal = t;
      return t;
    }

    window.loginVigilador = loginVigilador;
    window.logoutVigilador = logoutVigilador;
    window.refrescarTokenVigilador = refrescarTokenVigilador;
    window.obtenerTokenVigilador = obtenerTokenVigilador;
    window._forzarRefreshTokenVig = _forzarRefreshToken;
    window._iniciarRenovacionToken = _iniciarRenovacionToken;
    window._detenerRenovacionToken = _detenerRenovacionToken;
    window._getIdTokenGlobal = () => idTokenGlobal;
    window._setIdTokenGlobal = (t) => { idTokenGlobal = t; };
    window.aplicarHoraServidor = aplicarHoraServidor;
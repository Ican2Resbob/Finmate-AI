/**
 * @license
 * FinMate AI - Smart Personal Financial Management
 * Core Architecture & Application Logic (ES6+ Vanilla JavaScript)
 * Security: Web Crypto API (PBKDF2, SHA-256, AES-GCM)
 */

'use strict';

/* ==========================================================================
   1. GLOBAL APPLICATION STATE
   ========================================================================== */
const appState = {
  currentUser: null,        // { id, email, name, status, createdAt, lastLogin }
  sessionKey: null,         // In-memory CryptoKey for AES-GCM (never written to disk)
  transactions: [],         // Array of { id, type, amount, category, description, date, createdAt }
  goals: [],                // Array of { id, name, targetAmount, collectedAmount, deadline, icon, createdAt }
  reminders: [],            // Array of { id, title, time, frequency, notes, active, createdAt }
  challenges: [],           // Array of { id, name, desc, targetDays, currentDays, rewardBadge, completed, completedAt }
  badges: [],               // Array of { id, name, icon, desc, unlocked, unlockedAt }
  settings: {
    theme: 'light',
    currency: 'IDR'
  },
  streak: {
    count: 0,
    lastLoggedDate: null
  },
  activeView: 'overview',
  sessionTimer: null,
  loginAttempts: {
    count: 0,
    lockUntil: null
  }
};

/* Default Badges Configuration */
const DEFAULT_BADGES = [
  { id: 'first_tx', name: 'Langkah Pertama', icon: 'fa-seedling', desc: 'Mencatat transaksi pertama kali', unlocked: false, unlockedAt: null },
  { id: 'streak_3', name: 'Mulai Terbiasa', icon: 'fa-fire', desc: 'Mencatat transaksi 3 hari berturut-turut', unlocked: false, unlockedAt: null },
  { id: 'streak_7', name: 'Konsisten 7 Hari', icon: 'fa-medal', desc: 'Mencatat transaksi selama 7 hari aktif', unlocked: false, unlockedAt: null },
  { id: 'first_goal', name: 'Punya Visi', icon: 'fa-bullseye', desc: 'Membuat target finansial pertama', unlocked: false, unlockedAt: null },
  { id: 'goal_completed', name: 'Goal Getter', icon: 'fa-trophy', desc: 'Berhasil mencapai 1 target finansial', unlocked: false, unlockedAt: null },
  { id: 'healthy_cashflow', name: 'Financial Master', icon: 'fa-shield-halved', desc: 'Meraih skor Financial Health 90+', unlocked: false, unlockedAt: null }
];

/* Default Challenges Configuration */
const DEFAULT_CHALLENGES = [
  {
    id: 'ch_streak_7',
    name: 'Tantangan 7 Hari Mencatat Rutin',
    desc: 'Catat setidaknya 1 transaksi setiap hari selama 7 hari berturut-turut untuk melatih disiplin.',
    targetDays: 7,
    rewardBadge: 'Konsisten 7 Hari'
  },
  {
    id: 'ch_save_30',
    name: 'Tantangan Tabungan Berkelanjutan',
    desc: 'Alokasikan tabungan ke salah satu target impianmu minimal 3 kali dalam bulan ini.',
    targetDays: 3,
    rewardBadge: 'Goal Getter'
  },
  {
    id: 'ch_budget_control',
    name: 'Tantangan Kontrol Pengeluaran',
    desc: 'Jaga rasio pengeluaran agar tidak melebihi 70% dari total pemasukan bulan berjalan.',
    targetDays: 1,
    rewardBadge: 'Financial Master'
  }
];

/* ==========================================================================
   2. CRYPTOGRAPHY SERVICE (Web Crypto API)
   ========================================================================== */
const cryptoService = {
  // Check Web Crypto API Availability
  isSupported() {
    return window.crypto && window.crypto.subtle;
  },

  // Generate random salt in Hex
  generateSalt(byteLength = 16) {
    const array = new Uint8Array(byteLength);
    window.crypto.getRandomValues(array);
    return Array.from(array, b => b.toString(16).padStart(2, '0')).join('');
  },

  // Convert Hex string to Uint8Array
  hexToBuffer(hexString) {
    const bytes = new Uint8Array(Math.ceil(hexString.length / 2));
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(hexString.substr(i * 2, 2), 16);
    }
    return bytes;
  },

  // Convert Uint8Array to Hex string
  bufferToHex(buffer) {
    const bytes = new Uint8Array(buffer);
    return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
  },

  // PBKDF2 Password / PIN Hash
  async hashCredential(plainText, saltHex, iterations = 100000) {
    const encoder = new TextEncoder();
    const keyMaterial = await window.crypto.subtle.importKey(
      'raw',
      encoder.encode(plainText),
      { name: 'PBKDF2' },
      false,
      ['deriveBits']
    );

    const saltBuffer = this.hexToBuffer(saltHex);
    const derivedBits = await window.crypto.subtle.deriveBits(
      {
        name: 'PBKDF2',
        salt: saltBuffer,
        iterations: iterations,
        hash: 'SHA-256'
      },
      keyMaterial,
      256
    );

    return this.bufferToHex(derivedBits);
  },

  // Derive AES-GCM 256-bit CryptoKey from User Password & PIN
  async deriveEncryptionKey(password, pin, saltHex) {
    const encoder = new TextEncoder();
    const combinedSecret = `${password}:::${pin}`;
    const keyMaterial = await window.crypto.subtle.importKey(
      'raw',
      encoder.encode(combinedSecret),
      { name: 'PBKDF2' },
      false,
      ['deriveKey']
    );

    const saltBuffer = this.hexToBuffer(saltHex);
    return await window.crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: saltBuffer,
        iterations: 100000,
        hash: 'SHA-256'
      },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  },

  // Encrypt JSON payload using AES-GCM with 12-byte random IV
  async encryptPayload(dataObject, aesKey) {
    const encoder = new TextEncoder();
    const encodedData = encoder.encode(JSON.stringify(dataObject));
    const iv = window.crypto.getRandomValues(new Uint8Array(12));

    const cipherBuffer = await window.crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: iv },
      aesKey,
      encodedData
    );

    return {
      ivHex: this.bufferToHex(iv),
      cipherHex: this.bufferToHex(cipherBuffer)
    };
  },

  // Decrypt AES-GCM payload back to JavaScript Object
  async decryptPayload(encryptedPayload, aesKey) {
    const ivBuffer = this.hexToBuffer(encryptedPayload.ivHex);
    const cipherBuffer = this.hexToBuffer(encryptedPayload.cipherHex);

    const decryptedBuffer = await window.crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: ivBuffer },
      aesKey,
      cipherBuffer
    );

    const decoder = new TextDecoder();
    return JSON.parse(decoder.decode(decryptedBuffer));
  }
};

/* ==========================================================================
   3. STORAGE SERVICE
   ========================================================================== */
const storageService = {
  REGISTRY_KEY: 'finmate_users_registry',
  USER_DATA_PREFIX: 'finmate_user_data_',
  THEME_KEY: 'finmate_app_theme',

  getUsersRegistry() {
    try {
      const data = localStorage.getItem(this.REGISTRY_KEY);
      return data ? JSON.parse(data) : {};
    } catch (err) {
      console.error('Gagal membaca users registry:', err);
      return {};
    }
  },

  saveUsersRegistry(registry) {
    try {
      localStorage.setItem(this.REGISTRY_KEY, JSON.stringify(registry));
    } catch (err) {
      uiService.showToast('Gagal menyimpan registry ke LocalStorage: ' + err.message, 'error');
    }
  },

  getUserEncryptedData(userId) {
    try {
      const data = localStorage.getItem(this.USER_DATA_PREFIX + userId);
      return data ? JSON.parse(data) : null;
    } catch (err) {
      console.error('Gagal membaca encrypted user data:', err);
      return null;
    }
  },

  saveUserEncryptedData(userId, encryptedPayload) {
    try {
      localStorage.setItem(this.USER_DATA_PREFIX + userId, JSON.stringify(encryptedPayload));
    } catch (err) {
      uiService.showToast('Penyimpanan penuh atau error storage: ' + err.message, 'error');
    }
  },

  // Persist Current In-Memory State to Encrypted Storage
  async persistCurrentState() {
    if (!appState.currentUser || !appState.sessionKey) return;
    try {
      const payloadToEncrypt = {
        transactions: appState.transactions,
        goals: appState.goals,
        reminders: appState.reminders,
        challenges: appState.challenges,
        badges: appState.badges,
        settings: appState.settings,
        streak: appState.streak,
        updatedAt: new Date().toISOString()
      };

      const encrypted = await cryptoService.encryptPayload(payloadToEncrypt, appState.sessionKey);
      this.saveUserEncryptedData(appState.currentUser.id, encrypted);
    } catch (err) {
      console.error('Gagal mengenkripsi state:', err);
      uiService.showToast('Terjadi kesalahan saat mengamankan data: ' + err.message, 'error');
    }
  },

  // Export Encrypted Backup (.json)
  exportEncryptedBackup() {
    if (!appState.currentUser) return;
    const encryptedData = this.getUserEncryptedData(appState.currentUser.id);
    if (!encryptedData) {
      uiService.showToast('Tidak ada data terenkripsi yang dapat diekspor.', 'warning');
      return;
    }

    const registry = this.getUsersRegistry();
    const userMeta = registry[appState.currentUser.email];

    const backupObject = {
      app: 'FinMate AI',
      version: '2.0',
      exportedAt: new Date().toISOString(),
      user: {
        id: appState.currentUser.id,
        email: appState.currentUser.email,
        name: appState.currentUser.name,
        status: appState.currentUser.status,
        pwdHash: userMeta.pwdHash,
        pwdSalt: userMeta.pwdSalt,
        pinHash: userMeta.pinHash,
        pinSalt: userMeta.pinSalt,
        encSalt: userMeta.encSalt,
        createdAt: userMeta.createdAt
      },
      encryptedData: encryptedData
    };

    const blob = new Blob([JSON.stringify(backupObject, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    const filename = `FinMate_Backup_${appState.currentUser.name.replace(/\s+/g, '_')}_${new Date().toISOString().split('T')[0]}.json`;
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    uiService.showToast('File backup terenkripsi berhasil diunduh.', 'success');
  },

  // Import Backup (.json)
  async handleImportBackup(event) {
    const file = event.target.files[0];
    if (!file) return;

    uiService.showLoader('Membaca & memvalidasi file cadangan...');

    const reader = new FileReader();
    reader.onload = async (e) => {
      try {
        const parsed = JSON.parse(e.target.result);

        // Validate structure & version
        if (!parsed.app || parsed.app !== 'FinMate AI' || !parsed.user || !parsed.encryptedData) {
          throw new Error('Format file cadangan tidak valid atau tidak kompatibel dengan FinMate AI.');
        }

        // Save into registry and storage
        const registry = storageService.getUsersRegistry();
        registry[parsed.user.email] = parsed.user;
        storageService.saveUsersRegistry(registry);
        storageService.saveUserEncryptedData(parsed.user.id, parsed.encryptedData);

        uiService.hideLoader();
        uiService.showToast('Cadangan berhasil diimpor! Silakan login dengan akun dari file cadangan tersebut.', 'success');

        // If current user matches imported user, decrypt and reload immediately
        if (appState.currentUser && appState.currentUser.email === parsed.user.email) {
          const decrypted = await cryptoService.decryptPayload(parsed.encryptedData, appState.sessionKey);
          appState.transactions = decrypted.transactions || [];
          appState.goals = decrypted.goals || [];
          appState.reminders = decrypted.reminders || [];
          appState.challenges = decrypted.challenges || DEFAULT_CHALLENGES;
          appState.badges = decrypted.badges || DEFAULT_BADGES;
          appState.settings = decrypted.settings || { theme: 'light', currency: 'IDR' };
          appState.streak = decrypted.streak || { count: 0, lastLoggedDate: null };

          uiService.renderAllViews();
          uiService.showToast('Data aplikasi berhasil disinkronkan dari cadangan.', 'success');
        } else {
          // Switch to login tab
          authService.logout();
        }
      } catch (err) {
        uiService.hideLoader();
        uiService.showToast('Gagal memulihkan data: ' + err.message, 'error');
      } finally {
        event.target.value = '';
      }
    };

    reader.onerror = () => {
      uiService.hideLoader();
      uiService.showToast('Gagal membaca file dari disk.', 'error');
    };

    reader.readAsText(file);
  }
};

/* ==========================================================================
   4. AUTHENTICATION SERVICE
   ========================================================================== */
const authService = {
  // Register New User
  async handleRegister() {
    const name = document.getElementById('reg-name').value.trim();
    const status = document.getElementById('reg-status').value;
    const email = document.getElementById('reg-email').value.trim().toLowerCase();
    const password = document.getElementById('reg-password').value;
    const passwordConfirm = document.getElementById('reg-password-confirm').value;
    const pin = document.getElementById('reg-pin').value.trim();

    // Validations
    if (!name || !email || !password || !pin) {
      uiService.showToast('Semua kolom bertanda * wajib diisi.', 'warning');
      return;
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      uiService.showToast('Format alamat email tidak valid.', 'warning');
      return;
    }

    if (password.length < 8) {
      uiService.showToast('Password minimal harus 8 karakter.', 'warning');
      return;
    }

    if (password !== passwordConfirm) {
      uiService.showToast('Password dan konfirmasi password tidak cocok.', 'warning');
      return;
    }

    if (!/^\d{8}$/.test(pin)) {
      uiService.showToast('PIN keamanan harus tepat 8 digit angka.', 'warning');
      return;
    }

    const registry = storageService.getUsersRegistry();
    if (registry[email]) {
      uiService.showToast('Email sudah terdaftar. Silakan login.', 'warning');
      return;
    }

    uiService.showLoader('Membangun kunci enkripsi Web Crypto (PBKDF2 & AES-GCM)...');

    try {
      // Generate distinct random salts
      const pwdSalt = cryptoService.generateSalt(16);
      const pinSalt = cryptoService.generateSalt(16);
      const encSalt = cryptoService.generateSalt(16);

      // Compute Hashes
      const pwdHash = await cryptoService.hashCredential(password, pwdSalt);
      const pinHash = await cryptoService.hashCredential(pin, pinSalt);

      // Derive AES-GCM Master Key
      const aesKey = await cryptoService.deriveEncryptionKey(password, pin, encSalt);

      const userId = 'usr_' + Date.now() + '_' + Math.random().toString(36).substr(2, 6);
      const newUserMeta = {
        id: userId,
        email: email,
        name: name,
        status: status,
        pwdHash: pwdHash,
        pwdSalt: pwdSalt,
        pinHash: pinHash,
        pinSalt: pinSalt,
        encSalt: encSalt,
        createdAt: new Date().toISOString()
      };

      // Save user metadata to registry
      registry[email] = newUserMeta;
      storageService.saveUsersRegistry(registry);

      // Create Initial Encrypted Data with welcome structure
      const initialData = {
        transactions: [],
        goals: [],
        reminders: [
          {
            id: 'rem_welcome',
            title: 'Catat pengeluaran harian',
            time: '20:00',
            frequency: 'DAILY',
            notes: 'Membangun kebiasaan disiplin finansial',
            active: true,
            createdAt: new Date().toISOString()
          }
        ],
        challenges: JSON.parse(JSON.stringify(DEFAULT_CHALLENGES)),
        badges: JSON.parse(JSON.stringify(DEFAULT_BADGES)),
        settings: { theme: 'light', currency: 'IDR' },
        streak: { count: 0, lastLoggedDate: null },
        updatedAt: new Date().toISOString()
      };

      const encryptedInitial = await cryptoService.encryptPayload(initialData, aesKey);
      storageService.saveUserEncryptedData(userId, encryptedInitial);

      uiService.hideLoader();
      uiService.showToast('Akun berhasil dibuat! Silakan login untuk memulai.', 'success');

      // Clear register form & switch to login
      document.getElementById('form-register').reset();
      uiService.switchAuthTab('login');
      document.getElementById('login-email').value = email;
      document.getElementById('login-password').focus();
    } catch (err) {
      uiService.hideLoader();
      uiService.showToast('Gagal mendaftar: ' + err.message, 'error');
    }
  },

  // Login User
  async handleLogin() {
    // Check Lockout
    if (appState.loginAttempts.lockUntil && Date.now() < appState.loginAttempts.lockUntil) {
      const remainingSecs = Math.ceil((appState.loginAttempts.lockUntil - Date.now()) / 1000);
      uiService.showToast(`Akun terkunci sementara karena percobaan gagal. Coba lagi dalam ${remainingSecs} detik.`, 'error');
      return;
    }

    const email = document.getElementById('login-email').value.trim().toLowerCase();
    const password = document.getElementById('login-password').value;
    const pin = document.getElementById('login-pin').value.trim();

    if (!email || !password || !pin) {
      uiService.showToast('Mohon lengkapi email, password, dan PIN.', 'warning');
      return;
    }

    if (!/^\d{8}$/.test(pin)) {
      uiService.showToast('PIN keamanan harus tepat 8 digit angka.', 'warning');
      return;
    }

    const registry = storageService.getUsersRegistry();
    const userMeta = registry[email];

    if (!userMeta) {
      this.recordFailedAttempt();
      uiService.showToast('Email atau password tidak cocok.', 'error');
      return;
    }

    uiService.showLoader('Memverifikasi kredensial & mendekripsi brankas data...');

    try {
      // Verify Password Hash
      const computedPwdHash = await cryptoService.hashCredential(password, userMeta.pwdSalt);
      if (computedPwdHash !== userMeta.pwdHash) {
        this.recordFailedAttempt();
        uiService.hideLoader();
        uiService.showToast('Email atau password salah.', 'error');
        return;
      }

      // Verify PIN Hash
      const computedPinHash = await cryptoService.hashCredential(pin, userMeta.pinSalt);
      if (computedPinHash !== userMeta.pinHash) {
        this.recordFailedAttempt();
        uiService.hideLoader();
        uiService.showToast('PIN keamanan 8-digit salah.', 'error');
        return;
      }

      // Reset Failed Attempts on Success
      appState.loginAttempts.count = 0;
      appState.loginAttempts.lockUntil = null;
      document.getElementById('login-lock-msg').classList.add('hidden');

      // Derive AES Key & Decrypt Data
      const aesKey = await cryptoService.deriveEncryptionKey(password, pin, userMeta.encSalt);
      const encryptedData = storageService.getUserEncryptedData(userMeta.id);

      let decrypted = {
        transactions: [],
        goals: [],
        reminders: [],
        challenges: DEFAULT_CHALLENGES,
        badges: DEFAULT_BADGES,
        settings: { theme: 'light', currency: 'IDR' },
        streak: { count: 0, lastLoggedDate: null }
      };

      if (encryptedData) {
        decrypted = await cryptoService.decryptPayload(encryptedData, aesKey);
      }

      // Set App State
      appState.currentUser = {
        id: userMeta.id,
        email: userMeta.email,
        name: userMeta.name,
        status: userMeta.status,
        createdAt: userMeta.createdAt,
        lastLogin: new Date().toISOString()
      };
      appState.sessionKey = aesKey;
      appState.transactions = decrypted.transactions || [];
      appState.goals = decrypted.goals || [];
      appState.reminders = decrypted.reminders || [];
      appState.challenges = decrypted.challenges && decrypted.challenges.length ? decrypted.challenges : DEFAULT_CHALLENGES;
      appState.badges = decrypted.badges && decrypted.badges.length ? decrypted.badges : DEFAULT_BADGES;
      appState.settings = decrypted.settings || { theme: 'light', currency: 'IDR' };
      appState.streak = decrypted.streak || { count: 0, lastLoggedDate: null };

      // Apply User Settings
      if (appState.settings.theme === 'dark') {
        document.body.classList.add('theme-dark');
        document.body.classList.remove('theme-light');
      } else {
        document.body.classList.add('theme-light');
        document.body.classList.remove('theme-dark');
      }

      // Start Session Timer
      this.resetInactivityTimer();

      // UI Transition
      document.getElementById('auth-screen').classList.add('hidden');
      document.getElementById('main-app').classList.remove('hidden');

      uiService.renderAllViews();
      reminderService.startScheduler();

      uiService.hideLoader();
      uiService.showToast(`Selamat datang kembali, ${appState.currentUser.name}!`, 'success');
      document.getElementById('form-login').reset();
    } catch (err) {
      uiService.hideLoader();
      uiService.showToast('Gagal memproses dekripsi keamanan: ' + err.message, 'error');
    }
  },

  recordFailedAttempt() {
    appState.loginAttempts.count += 1;
    if (appState.loginAttempts.count >= 5) {
      const lockDurationMs = 60 * 1000; // 1 minute lockout
      appState.loginAttempts.lockUntil = Date.now() + lockDurationMs;
      const lockBox = document.getElementById('login-lock-msg');
      const lockText = document.getElementById('login-lock-text');
      lockText.textContent = 'Terlalu banyak percobaan gagal. Akun dikunci sementara selama 60 detik demi keamanan.';
      lockBox.classList.remove('hidden');
    }
  },

  // Auto Logout on Inactivity (15 Minutes)
  resetInactivityTimer() {
    if (appState.sessionTimer) clearTimeout(appState.sessionTimer);
    appState.sessionTimer = setTimeout(() => {
      if (appState.currentUser) {
        uiService.showToast('Sesi Anda berakhir karena tidak aktif selama 15 menit.', 'warning');
        authService.logout();
      }
    }, 15 * 60 * 1000);
  },

  // Logout
  logout() {
    if (appState.sessionTimer) clearTimeout(appState.sessionTimer);
    reminderService.stopScheduler();

    // Clear sensitive memory
    appState.currentUser = null;
    appState.sessionKey = null;
    appState.transactions = [];
    appState.goals = [];
    appState.reminders = [];

    // Switch UI
    document.getElementById('main-app').classList.add('hidden');
    document.getElementById('auth-screen').classList.remove('hidden');
    uiService.switchAuthTab('login');
    uiService.showToast('Anda telah berhasil keluar dari akun.', 'info');
  },

  // Update Profile Info
  async handleUpdateProfile() {
    if (!appState.currentUser) return;
    const name = document.getElementById('profile-name').value.trim();
    const status = document.getElementById('profile-status').value;

    if (!name) {
      uiService.showToast('Nama lengkap tidak boleh kosong.', 'warning');
      return;
    }

    appState.currentUser.name = name;
    appState.currentUser.status = status;

    const registry = storageService.getUsersRegistry();
    if (registry[appState.currentUser.email]) {
      registry[appState.currentUser.email].name = name;
      registry[appState.currentUser.email].status = status;
      storageService.saveUsersRegistry(registry);
    }

    uiService.updateSidebarUser();
    uiService.showToast('Profil berhasil diperbarui.', 'success');
  },

  // Change Password
  async handleChangePassword() {
    if (!appState.currentUser || !appState.sessionKey) return;

    const currentPwd = document.getElementById('pwd-current').value;
    const newPwd = document.getElementById('pwd-new').value;
    const confirmPwd = document.getElementById('pwd-new-confirm').value;

    if (!currentPwd || !newPwd) {
      uiService.showToast('Mohon lengkapi semua kolom password.', 'warning');
      return;
    }

    if (newPwd.length < 8) {
      uiService.showToast('Password baru minimal harus 8 karakter.', 'warning');
      return;
    }

    if (newPwd !== confirmPwd) {
      uiService.showToast('Password baru dan konfirmasi tidak cocok.', 'warning');
      return;
    }

    const registry = storageService.getUsersRegistry();
    const userMeta = registry[appState.currentUser.email];

    uiService.showLoader('Mengubah password dan mengenkripsi ulang data...');

    try {
      const checkHash = await cryptoService.hashCredential(currentPwd, userMeta.pwdSalt);
      if (checkHash !== userMeta.pwdHash) {
        uiService.hideLoader();
        uiService.showToast('Password saat ini salah.', 'error');
        return;
      }

      // Generate new password salt and hash
      const newPwdSalt = cryptoService.generateSalt(16);
      const newPwdHash = await cryptoService.hashCredential(newPwd, newPwdSalt);

      // Need the user's PIN to derive new master key
      // We derive new key using new password & existing pin
      const newEncSalt = cryptoService.generateSalt(16);
      // Derive new key (Note: In pure client, we re-derive using new password)
      const promptPin = prompt('Masukkan 8-digit PIN keamanan Anda untuk mengotorisasi perubahan password:');
      if (!promptPin || !/^\d{8}$/.test(promptPin)) {
        uiService.hideLoader();
        uiService.showToast('PIN tidak valid. Perubahan password dibatalkan.', 'warning');
        return;
      }

      const checkPinHash = await cryptoService.hashCredential(promptPin, userMeta.pinSalt);
      if (checkPinHash !== userMeta.pinHash) {
        uiService.hideLoader();
        uiService.showToast('PIN keamanan salah. Perubahan password dibatalkan.', 'error');
        return;
      }

      const newAesKey = await cryptoService.deriveEncryptionKey(newPwd, promptPin, newEncSalt);

      // Update registry
      userMeta.pwdHash = newPwdHash;
      userMeta.pwdSalt = newPwdSalt;
      userMeta.encSalt = newEncSalt;
      registry[appState.currentUser.email] = userMeta;
      storageService.saveUsersRegistry(registry);

      // Update in-memory session key & re-encrypt
      appState.sessionKey = newAesKey;
      await storageService.persistCurrentState();

      uiService.hideLoader();
      uiService.closeModal('modal-change-password');
      document.getElementById('form-change-pwd').reset();
      uiService.showToast('Password berhasil diubah & data dienkripsi ulang.', 'success');
    } catch (err) {
      uiService.hideLoader();
      uiService.showToast('Gagal mengubah password: ' + err.message, 'error');
    }
  },

  // Change PIN
  async handleChangePin() {
    if (!appState.currentUser || !appState.sessionKey) return;

    const currentPin = document.getElementById('pin-current').value.trim();
    const newPin = document.getElementById('pin-new').value.trim();
    const confirmPin = document.getElementById('pin-new-confirm').value.trim();

    if (!/^\d{8}$/.test(currentPin) || !/^\d{8}$/.test(newPin)) {
      uiService.showToast('PIN harus berupa 8 digit angka.', 'warning');
      return;
    }

    if (newPin !== confirmPin) {
      uiService.showToast('PIN baru dan konfirmasi tidak cocok.', 'warning');
      return;
    }

    const registry = storageService.getUsersRegistry();
    const userMeta = registry[appState.currentUser.email];

    uiService.showLoader('Mengubah PIN keamanan dan memperbarui enkripsi...');

    try {
      const checkPinHash = await cryptoService.hashCredential(currentPin, userMeta.pinSalt);
      if (checkPinHash !== userMeta.pinHash) {
        uiService.hideLoader();
        uiService.showToast('PIN saat ini salah.', 'error');
        return;
      }

      const promptPwd = prompt('Masukkan Password Akun Anda untuk mengotorisasi perubahan PIN:');
      if (!promptPwd) {
        uiService.hideLoader();
        uiService.showToast('Password diperlukan untuk perubahan PIN.', 'warning');
        return;
      }

      const checkPwdHash = await cryptoService.hashCredential(promptPwd, userMeta.pwdSalt);
      if (checkPwdHash !== userMeta.pwdHash) {
        uiService.hideLoader();
        uiService.showToast('Password salah. Perubahan PIN dibatalkan.', 'error');
        return;
      }

      const newPinSalt = cryptoService.generateSalt(16);
      const newPinHash = await cryptoService.hashCredential(newPin, newPinSalt);
      const newEncSalt = cryptoService.generateSalt(16);

      const newAesKey = await cryptoService.deriveEncryptionKey(promptPwd, newPin, newEncSalt);

      userMeta.pinHash = newPinHash;
      userMeta.pinSalt = newPinSalt;
      userMeta.encSalt = newEncSalt;
      registry[appState.currentUser.email] = userMeta;
      storageService.saveUsersRegistry(registry);

      appState.sessionKey = newAesKey;
      await storageService.persistCurrentState();

      uiService.hideLoader();
      uiService.closeModal('modal-change-pin');
      document.getElementById('form-change-pin').reset();
      uiService.showToast('PIN Keamanan berhasil diperbarui!', 'success');
    } catch (err) {
      uiService.hideLoader();
      uiService.showToast('Gagal mengubah PIN: ' + err.message, 'error');
    }
  },

  // Delete Account Permanently (Danger Zone)
  async handleDeleteAccount() {
    if (!appState.currentUser) return;
    const pin = document.getElementById('del-pin').value.trim();
    const confirmText = document.getElementById('del-confirm-text').value.trim();

    if (confirmText !== 'HAPUS AKUN SAYA') {
      uiService.showToast('Teks konfirmasi harus tepat: HAPUS AKUN SAYA', 'warning');
      return;
    }

    const registry = storageService.getUsersRegistry();
    const userMeta = registry[appState.currentUser.email];

    try {
      const checkPin = await cryptoService.hashCredential(pin, userMeta.pinSalt);
      if (checkPin !== userMeta.pinHash) {
        uiService.showToast('PIN Keamanan salah. Penghapusan akun dibatalkan.', 'error');
        return;
      }

      // Delete storage items
      localStorage.removeItem(storageService.USER_DATA_PREFIX + userMeta.id);
      delete registry[appState.currentUser.email];
      storageService.saveUsersRegistry(registry);

      uiService.closeModal('modal-delete-account');
      uiService.showToast('Akun dan seluruh data finansial berhasil dimusnahkan secara permanen.', 'info');
      this.logout();
    } catch (err) {
      uiService.showToast('Gagal memproses penghapusan akun: ' + err.message, 'error');
    }
  }
};

/* ==========================================================================
   5. TRANSACTION SERVICE
   ========================================================================== */
const transactionService = {
  // Category presets
  CATEGORIES: {
    EXPENSE: ['Makanan', 'Transportasi', 'Pendidikan', 'Hiburan', 'Belanja', 'Tagihan', 'Tabungan', 'Lainnya'],
    INCOME: ['Uang Saku', 'Gaji', 'Tabungan', 'Lainnya']
  },

  handleTypeToggle() {
    const isExpense = document.getElementById('tx-type-expense').checked;
    const categorySelect = document.getElementById('tx-category');
    const categories = isExpense ? this.CATEGORIES.EXPENSE : this.CATEGORIES.INCOME;

    categorySelect.innerHTML = '';
    categories.forEach(cat => {
      const option = document.createElement('option');
      option.value = cat;
      option.textContent = cat;
      categorySelect.appendChild(option);
    });
  },

  async handleSaveTransaction() {
    const id = document.getElementById('tx-id').value;
    const type = document.querySelector('input[name="tx-type"]:checked').value;
    const amount = parseFloat(document.getElementById('tx-amount').value);
    const category = document.getElementById('tx-category').value;
    const description = document.getElementById('tx-desc').value.trim();
    const date = document.getElementById('tx-date').value;

    if (!amount || isNaN(amount) || amount <= 0) {
      uiService.showToast('Nominal harus berupa angka lebih dari 0.', 'warning');
      return;
    }

    if (!description || !date) {
      uiService.showToast('Mohon lengkapi deskripsi dan tanggal transaksi.', 'warning');
      return;
    }

    if (id) {
      // Edit existing transaction
      const idx = appState.transactions.findIndex(t => t.id === id);
      if (idx !== -1) {
        appState.transactions[idx] = {
          ...appState.transactions[idx],
          type,
          amount,
          category,
          description,
          date,
          updatedAt: new Date().toISOString()
        };
        uiService.showToast('Transaksi berhasil diperbarui.', 'success');
      }
    } else {
      // Create new transaction
      const newTx = {
        id: 'tx_' + Date.now() + '_' + Math.random().toString(36).substr(2, 5),
        type,
        amount,
        category,
        description,
        date,
        createdAt: new Date().toISOString()
      };
      appState.transactions.unshift(newTx);
      uiService.showToast('Transaksi berhasil dicatat!', 'success');

      // Update streak and challenges
      this.updateStreak(date);
      badgeService.checkBadgeConditions();
    }

    // Persist and update UI
    await storageService.persistCurrentState();
    uiService.closeModal('modal-transaction');
    document.getElementById('form-transaction').reset();
    document.getElementById('tx-id').value = '';
    uiService.renderAllViews();
  },

  updateStreak(txDateString) {
    const today = new Date().toISOString().split('T')[0];
    const lastDate = appState.streak.lastLoggedDate;

    if (!lastDate) {
      appState.streak.count = 1;
      appState.streak.lastLoggedDate = today;
    } else if (lastDate === today) {
      // Already logged today
    } else {
      const yesterday = new Date(Date.now() - 86400000).toISOString().split('T')[0];
      if (lastDate === yesterday) {
        appState.streak.count += 1;
      } else {
        // Reset streak if gap > 1 day
        appState.streak.count = 1;
      }
      appState.streak.lastLoggedDate = today;
    }
  },

  async deleteTransaction(id) {
    if (!confirm('Apakah Anda yakin ingin menghapus transaksi ini?')) return;
    appState.transactions = appState.transactions.filter(t => t.id !== id);
    await storageService.persistCurrentState();
    uiService.renderAllViews();
    uiService.showToast('Transaksi telah dihapus.', 'info');
  },

  openEditModal(id) {
    const tx = appState.transactions.find(t => t.id === id);
    if (!tx) return;

    document.getElementById('tx-id').value = tx.id;
    document.getElementById('modal-tx-title').innerHTML = '<i class="fa-solid fa-pen-to-square text-indigo"></i> Edit Transaksi';

    if (tx.type === 'INCOME') {
      document.getElementById('tx-type-income').checked = true;
    } else {
      document.getElementById('tx-type-expense').checked = true;
    }
    this.handleTypeToggle();

    document.getElementById('tx-amount').value = tx.amount;
    document.getElementById('tx-category').value = tx.category;
    document.getElementById('tx-desc').value = tx.description;
    document.getElementById('tx-date').value = tx.date;

    uiService.openModal('modal-transaction');
  },

  async resetAllTransactions() {
    appState.transactions = [];
    await storageService.persistCurrentState();
    uiService.renderAllViews();
    uiService.showToast('Seluruh riwayat transaksi telah direset.', 'info');
  },

  getFilteredTransactions() {
    const search = (document.getElementById('tx-search-input')?.value || '').toLowerCase().trim();
    const typeFilter = document.getElementById('tx-filter-type')?.value || 'ALL';
    const categoryFilter = document.getElementById('tx-filter-category')?.value || 'ALL';
    const sortFilter = document.getElementById('tx-filter-sort')?.value || 'date-desc';

    let filtered = [...appState.transactions];

    if (typeFilter !== 'ALL') {
      filtered = filtered.filter(t => t.type === typeFilter);
    }

    if (categoryFilter !== 'ALL') {
      filtered = filtered.filter(t => t.category === categoryFilter);
    }

    if (search) {
      filtered = filtered.filter(t => 
        t.description.toLowerCase().includes(search) ||
        t.category.toLowerCase().includes(search) ||
        t.amount.toString().includes(search)
      );
    }

    filtered.sort((a, b) => {
      if (sortFilter === 'date-desc') return new Date(b.date) - new Date(a.date);
      if (sortFilter === 'date-asc') return new Date(a.date) - new Date(b.date);
      if (sortFilter === 'amount-desc') return b.amount - a.amount;
      if (sortFilter === 'amount-asc') return a.amount - b.amount;
      return 0;
    });

    return filtered;
  },

  handleFilterChange() {
    uiService.renderExpensesView();
  },

  exportToCSV() {
    const transactions = appState.transactions;
    if (!transactions.length) {
      uiService.showToast('Tidak ada transaksi untuk diekspor.', 'warning');
      return;
    }

    let csv = 'ID,Tanggal,Tipe,Kategori,Deskripsi,Nominal\n';
    transactions.forEach(t => {
      const desc = `"${t.description.replace(/"/g, '""')}"`;
      csv += `${t.id},${t.date},${t.type},${t.category},${desc},${t.amount}\n`;
    });

    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `FinMate_Transaksi_${new Date().toISOString().split('T')[0]}.csv`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    uiService.showToast('Data transaksi berhasil diekspor ke format CSV.', 'success');
  }
};

/* ==========================================================================
   6. FINANCIAL GOALS SERVICE
   ========================================================================== */
const goalService = {
  async handleSaveGoal() {
    const id = document.getElementById('goal-id').value;
    const name = document.getElementById('goal-name').value.trim();
    const targetAmount = parseFloat(document.getElementById('goal-target-amount').value);
    const collectedAmount = parseFloat(document.getElementById('goal-collected-amount').value) || 0;
    const deadline = document.getElementById('goal-deadline').value;
    const icon = document.getElementById('goal-icon').value;

    if (!name || !deadline) {
      uiService.showToast('Nama target dan deadline wajib diisi.', 'warning');
      return;
    }

    if (!targetAmount || targetAmount <= 0) {
      uiService.showToast('Nominal target harus lebih dari 0.', 'warning');
      return;
    }

    if (id) {
      // Edit
      const idx = appState.goals.findIndex(g => g.id === id);
      if (idx !== -1) {
        appState.goals[idx] = {
          ...appState.goals[idx],
          name,
          targetAmount,
          collectedAmount,
          deadline,
          icon,
          updatedAt: new Date().toISOString()
        };
        uiService.showToast('Target impian berhasil diperbarui.', 'success');
      }
    } else {
      // Create
      const newGoal = {
        id: 'goal_' + Date.now() + '_' + Math.random().toString(36).substr(2, 5),
        name,
        targetAmount,
        collectedAmount,
        deadline,
        icon: icon || 'fa-bullseye',
        createdAt: new Date().toISOString()
      };
      appState.goals.push(newGoal);
      uiService.showToast('Target impian baru berhasil ditambahkan!', 'success');
    }

    badgeService.checkBadgeConditions();
    await storageService.persistCurrentState();
    uiService.closeModal('modal-goal');
    document.getElementById('form-goal').reset();
    document.getElementById('goal-id').value = '';
    uiService.renderAllViews();
  },

  openDepositModal(goalId) {
    const goal = appState.goals.find(g => g.id === goalId);
    if (!goal) return;

    document.getElementById('deposit-goal-id').value = goal.id;
    document.getElementById('deposit-goal-name').textContent = goal.name;
    document.getElementById('deposit-goal-status').textContent = `Terkumpul saat ini: ${uiService.formatCurrency(goal.collectedAmount)} / Target: ${uiService.formatCurrency(goal.targetAmount)}`;
    document.getElementById('deposit-amount').value = '';

    uiService.openModal('modal-deposit-goal');
  },

  async handleDeposit() {
    const goalId = document.getElementById('deposit-goal-id').value;
    const amount = parseFloat(document.getElementById('deposit-amount').value);
    const recordTx = document.getElementById('deposit-record-tx').checked;

    if (!amount || amount <= 0) {
      uiService.showToast('Masukkan nominal tabungan yang valid.', 'warning');
      return;
    }

    const goal = appState.goals.find(g => g.id === goalId);
    if (!goal) return;

    goal.collectedAmount += amount;

    // Optionally record as expense (Tabungan)
    if (recordTx) {
      const newTx = {
        id: 'tx_' + Date.now() + '_' + Math.random().toString(36).substr(2, 5),
        type: 'EXPENSE',
        amount: amount,
        category: 'Tabungan',
        description: `Menabung untuk: ${goal.name}`,
        date: new Date().toISOString().split('T')[0],
        createdAt: new Date().toISOString()
      };
      appState.transactions.unshift(newTx);
    }

    badgeService.checkBadgeConditions();
    await storageService.persistCurrentState();
    uiService.closeModal('modal-deposit-goal');
    uiService.renderAllViews();
    uiService.showToast(`Berhasil menambahkan ${uiService.formatCurrency(amount)} ke target ${goal.name}!`, 'success');
  },

  async deleteGoal(id) {
    if (!confirm('Hapus target keuangan ini?')) return;
    appState.goals = appState.goals.filter(g => g.id !== id);
    await storageService.persistCurrentState();
    uiService.renderAllViews();
    uiService.showToast('Target keuangan telah dihapus.', 'info');
  }
};

/* ==========================================================================
   7. FINANCIAL HEALTH SERVICE
   ========================================================================== */
const healthService = {
  calculateMetrics() {
    const transactions = appState.transactions;
    let totalIncome = 0;
    let totalExpense = 0;

    transactions.forEach(t => {
      if (t.type === 'INCOME') totalIncome += t.amount;
      if (t.type === 'EXPENSE') totalExpense += t.amount;
    });

    const netBalance = totalIncome - totalExpense;
    let totalGoalSavings = 0;
    appState.goals.forEach(g => { totalGoalSavings += g.collectedAmount; });

    // Financial Ratios
    let expenseRatio = 0;
    let savingsRate = 0;

    if (totalIncome > 0) {
      expenseRatio = Math.round((totalExpense / totalIncome) * 100);
      savingsRate = Math.max(0, Math.round(((totalIncome - totalExpense) / totalIncome) * 100));
    } else if (totalExpense > 0) {
      expenseRatio = 100;
      savingsRate = 0;
    }

    // Health Score Algorithm (0 - 100)
    let score = 100;
    let category = 'Sangat Baik';
    let summaryText = 'Kondisi keuangan Anda sangat stabil dengan arus kas positif.';

    if (totalIncome === 0 && totalExpense === 0) {
      score = 100;
      category = 'Mulai Menata';
      summaryText = 'Belum ada transaksi tercatat. Mulai catat transaksi untuk mendapatkan analisis nyata.';
    } else if (totalExpense > totalIncome) {
      const deficitRatio = totalIncome > 0 ? (totalExpense - totalIncome) / totalIncome : 1;
      score = Math.max(10, Math.round(50 - (deficitRatio * 30)));
      category = 'Berisiko';
      summaryText = 'Pengeluaranmu saat ini melebihi pemasukan (defisit arus kas). Perlu evaluasi ketat pos pengeluaran sekunder.';
    } else {
      // Expense ratio deduction
      if (expenseRatio > 80) {
        score = 65;
        category = 'Perlu Perbaikan';
        summaryText = 'Pengeluaran memakan lebih dari 80% pemasukan. Ruang gerak tabungan Anda cukup sempit.';
      } else if (expenseRatio > 60) {
        score = 80;
        category = 'Baik';
        summaryText = 'Arus kas Anda cukup sehat, namun masih ada ruang untuk meningkatkan porsi tabungan.';
      } else {
        score = 95;
        category = 'Sangat Baik';
        summaryText = 'Pengelolaan keuangan sangat disiplin. Rasio tabungan Anda berada di zona ideal.';
      }

      // Bonus for having active goals with progress
      if (appState.goals.some(g => g.collectedAmount > 0)) {
        score = Math.min(100, score + 5);
      }
    }

    return {
      totalIncome,
      totalExpense,
      netBalance,
      totalGoalSavings,
      expenseRatio,
      savingsRate,
      score,
      category,
      summaryText
    };
  },

  generateRecommendations(metrics) {
    const recs = [];

    if (metrics.totalExpense > metrics.totalIncome && metrics.totalIncome > 0) {
      recs.push({
        title: 'Atasi Defisit Arus Kas',
        icon: 'fa-triangle-exclamation text-rose',
        desc: `Pengeluaranmu melebihi pemasukan sebesar ${uiService.formatCurrency(metrics.totalExpense - metrics.totalIncome)}. Kurangi pos hiburan & belanja non-esensial.`
      });
    }

    if (metrics.savingsRate < 20 && metrics.totalIncome > 0) {
      recs.push({
        title: 'Tingkatkan Rasio Tabungan',
        icon: 'fa-piggy-bank text-amber',
        desc: `Tingkat tabunganmu saat ini ${metrics.savingsRate}%. Standar ideal finansial muda adalah minimal 20% dari setiap pemasukan yang diterima.`
      });
    } else if (metrics.savingsRate >= 20) {
      recs.push({
        title: 'Pertahankan Disiplin Menabung',
        icon: 'fa-circle-check text-emerald',
        desc: `Bagus sekali! Rasio tabunganmu mencapai ${metrics.savingsRate}%. Pertimbangkan membagi tabungan ke instrumen reksadana/emas atau dana darurat.`
      });
    }

    if (appState.goals.length === 0) {
      recs.push({
        title: 'Buat Target Dana Darurat',
        icon: 'fa-shield-halved text-indigo',
        desc: 'Kamu belum memiliki target finansial aktif. Miliki target minimal 3x pengeluaran bulanan sebagai dana darurat.'
      });
    } else {
      const activeGoal = appState.goals[0];
      const percent = Math.min(100, Math.round((activeGoal.collectedAmount / activeGoal.targetAmount) * 100));
      recs.push({
        title: `Fokus Target: ${activeGoal.name}`,
        icon: 'fa-bullseye text-primary',
        desc: `Target telah mencapai ${percent}%. Sisihkan dana secara berkala agar target tercapai sebelum ${uiService.formatDate(activeGoal.deadline)}.`
      });
    }

    return recs;
  }
};

/* ==========================================================================
   8. SMART AI FINANCIAL COACH SERVICE (Local Heuristic Engine)
   ========================================================================== */
const aiCoachService = {
  chatHistory: [],

  askPreset(questionText) {
    document.getElementById('chat-input').value = questionText;
    this.handleSendMessage();
  },

  handleSendMessage() {
    const input = document.getElementById('chat-input');
    const text = input.value.trim();
    if (!text) return;

    // Add user message
    this.addMessage(text, 'user');
    input.value = '';

    // Show typing
    document.getElementById('chat-typing').classList.remove('hidden');
    this.scrollToBottom();

    // Generate smart contextual response after short realistic delay
    setTimeout(() => {
      document.getElementById('chat-typing').classList.add('hidden');
      const response = this.generateSmartResponse(text);
      this.addMessage(response, 'bot');
      this.playChime();
    }, 600);
  },

  addMessage(contentHtml, sender = 'bot') {
    const container = document.getElementById('chat-messages');
    const bubble = document.createElement('div');
    bubble.className = `message-bubble ${sender}-message`;

    const now = new Date().toLocaleTimeString('id-ID', { hour: '2-digit', minute: '2-digit' });
    const avatar = sender === 'bot' 
      ? '<div class="msg-avatar"><i class="fa-solid fa-robot"></i></div>'
      : '<div class="msg-avatar"><i class="fa-solid fa-user"></i></div>';

    bubble.innerHTML = `
      ${avatar}
      <div class="msg-content">
        <p>${contentHtml}</p>
        <span class="msg-time">${now}</span>
      </div>
    `;

    container.appendChild(bubble);
    this.scrollToBottom();
  },

  scrollToBottom() {
    const container = document.getElementById('chat-messages');
    container.scrollTop = container.scrollHeight;
  },

  generateSmartResponse(query) {
    const q = query.toLowerCase();
    const metrics = healthService.calculateMetrics();
    const transactions = appState.transactions;

    // Find category breakdowns
    const catMap = {};
    let totalExp = 0;
    transactions.filter(t => t.type === 'EXPENSE').forEach(t => {
      catMap[t.category] = (catMap[t.category] || 0) + t.amount;
      totalExp += t.amount;
    });

    let topCategory = 'Belum ada';
    let topCatAmount = 0;
    Object.keys(catMap).forEach(cat => {
      if (catMap[cat] > topCatAmount) {
        topCatAmount = catMap[cat];
        topCategory = cat;
      }
    });

    // Heuristic Rules
    if (q.includes('sehat') || q.includes('kesehatan') || q.includes('kondisi')) {
      if (transactions.length === 0) {
        return `Data transaksi Anda saat ini masih kosong. Silakan catat transaksi pemasukan dan pengeluaran terlebih dahulu agar saya dapat menganalisis kesehatan finansialmu secara akurat!`;
      }
      return `Skor Kesehatan Finansialmu saat ini adalah <strong>${metrics.score}/100 (${metrics.category})</strong>.<br><br>
        • Total Pemasukan: <strong>${uiService.formatCurrency(metrics.totalIncome)}</strong><br>
        • Total Pengeluaran: <strong>${uiService.formatCurrency(metrics.totalExpense)}</strong><br>
        • Rasio Pengeluaran: <strong>${metrics.expenseRatio}%</strong><br><br>
        <em>${metrics.summaryText}</em>`;
    }

    if (q.includes('terbesar') || q.includes('boros') || q.includes('kategori')) {
      if (totalExp === 0) {
        return `Belum ada data pengeluaran yang tercatat dalam sistem Anda.`;
      }
      const percent = Math.round((topCatAmount / totalExp) * 100);
      return `Berdasarkan catatan keuanganmu, kategori pengeluaran terbesar adalah <strong>${topCategory}</strong> dengan total <strong>${uiService.formatCurrency(topCatAmount)}</strong> (${percent}% dari seluruh pengeluaranmu). Coba evaluasi pos ini jika ingin berhemat!`;
    }

    if (q.includes('saldo') || q.includes('uang') || q.includes('kas')) {
      return `Saldo bersih kas Anda saat ini adalah <strong>${uiService.formatCurrency(metrics.netBalance)}</strong> (Total Pemasukan: ${uiService.formatCurrency(metrics.totalIncome)} dikurangi Total Pengeluaran: ${uiService.formatCurrency(metrics.totalExpense)}).`;
    }

    if (q.includes('menabung') || q.includes('tips') || q.includes('hemat')) {
      return `Berikut 3 tips praktis untuk menabung lebih efektif:<br>
        1. <strong>Terapkan Aturan 24 Jam:</strong> Tunda keinginan membeli barang non-pokok selama 24 jam untuk menghindari <em>impulse buying</em>.<br>
        2. <strong>Prinsip Pay Yourself First:</strong> Sisihkan minimal 20% langsung di awal begitu uang saku atau gaji masuk.<br>
        3. <strong>Catat Transaksi Kecil:</strong> Uang jajan kopi dan camilan sering menjadi kebocoran halus yang tidak disadari.`;
    }

    if (q.includes('target') || q.includes('goal') || q.includes('impian')) {
      if (appState.goals.length === 0) {
        return `Kamu belum membuat Target Finansial. Buka menu <strong>Financial Goals</strong> dan tetapkan target impianmu seperti Dana Darurat, Gadget, atau Liburan!`;
      }
      const goalList = appState.goals.map(g => {
        const pct = Math.min(100, Math.round((g.collectedAmount / g.targetAmount) * 100));
        return `• <strong>${g.name}</strong>: ${pct}% terkumpul (${uiService.formatCurrency(g.collectedAmount)} dari ${uiService.formatCurrency(g.targetAmount)})`;
      }).join('<br>');

      return `Status Target Finansial Anda saat ini:<br>${goalList}<br><br>Pertahankan konsistensi menabung setiap pekan!`;
    }

    // Default intelligent response
    return `Saya memahami pertanyaan Anda. Berdasarkan data yang tersimpan, total saldo Anda saat ini <strong>${uiService.formatCurrency(metrics.netBalance)}</strong> dengan skor kesehatan <strong>${metrics.score}/100</strong>. Anda dapat menanyakan tentang rincian pengeluaran, saldo, tips menabung, atau evaluasi target impian kapan saja!`;
  },

  clearChat() {
    const container = document.getElementById('chat-messages');
    container.innerHTML = `
      <div class="message-bubble bot-message">
        <div class="msg-avatar"><i class="fa-solid fa-robot"></i></div>
        <div class="msg-content">
          <p>Percakapan telah direset. Ada yang bisa saya bantu terkait pengelolaan keuanganmu hari ini?</p>
          <span class="msg-time">Baru saja</span>
        </div>
      </div>
    `;
    uiService.showToast('Riwayat chat berhasil dibersihkan.', 'info');
  },

  playChime() {
    try {
      const audioCtx = new (window.AudioContext || window.webkitAudioContext)();
      const osc = audioCtx.createOscillator();
      const gain = audioCtx.createGain();
      osc.connect(gain);
      gain.connect(audioCtx.destination);
      osc.type = 'sine';
      osc.frequency.setValueAtTime(587.33, audioCtx.currentTime); // D5
      gain.gain.setValueAtTime(0.05, audioCtx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.0001, audioCtx.currentTime + 0.3);
      osc.start();
      osc.stop(audioCtx.currentTime + 0.3);
    } catch (e) {
      // Audio not permitted or supported
    }
  }
};

/* ==========================================================================
   9. BADGES & CHALLENGES SERVICE
   ========================================================================== */
const badgeService = {
  checkBadgeConditions() {
    const txs = appState.transactions;
    const goals = appState.goals;
    const streak = appState.streak.count;
    const metrics = healthService.calculateMetrics();

    let newBadgeUnlocked = false;

    appState.badges.forEach(b => {
      if (!b.unlocked) {
        if (b.id === 'first_tx' && txs.length >= 1) {
          this.unlockBadge(b);
          newBadgeUnlocked = true;
        } else if (b.id === 'streak_3' && streak >= 3) {
          this.unlockBadge(b);
          newBadgeUnlocked = true;
        } else if (b.id === 'streak_7' && streak >= 7) {
          this.unlockBadge(b);
          newBadgeUnlocked = true;
        } else if (b.id === 'first_goal' && goals.length >= 1) {
          this.unlockBadge(b);
          newBadgeUnlocked = true;
        } else if (b.id === 'goal_completed' && goals.some(g => g.collectedAmount >= g.targetAmount)) {
          this.unlockBadge(b);
          newBadgeUnlocked = true;
        } else if (b.id === 'healthy_cashflow' && metrics.score >= 90 && txs.length >= 3) {
          this.unlockBadge(b);
          newBadgeUnlocked = true;
        }
      }
    });

    if (newBadgeUnlocked) {
      uiService.renderChallengesView();
    }
  },

  unlockBadge(badge) {
    badge.unlocked = true;
    badge.unlockedAt = new Date().toISOString();
    uiService.showToast(`Selamat! Anda membuka lencana baru: "${badge.name}" 🎉`, 'success');
  }
};

/* ==========================================================================
   10. REMINDER SERVICE
   ========================================================================== */
const reminderService = {
  intervalId: null,

  startScheduler() {
    this.stopScheduler();
    this.intervalId = setInterval(() => {
      this.checkScheduledReminders();
    }, 30000); // check every 30 seconds
  },

  stopScheduler() {
    if (this.intervalId) {
      clearInterval(this.intervalId);
      this.intervalId = null;
    }
  },

  async requestPermission() {
    if ('Notification' in window) {
      const permission = await Notification.requestPermission();
      if (permission === 'granted') {
        uiService.showToast('Izin notifikasi browser berhasil diaktifkan.', 'success');
        document.getElementById('notif-perm-banner').classList.add('hidden');
      } else {
        uiService.showToast('Izin notifikasi ditolak. Pengingat akan tetap aktif dalam aplikasi.', 'warning');
      }
    }
  },

  checkScheduledReminders() {
    if (!appState.currentUser || !appState.reminders.length) return;

    const now = new Date();
    const currentHours = String(now.getHours()).padStart(2, '0');
    const currentMins = String(now.getMinutes()).padStart(2, '0');
    const currentTimeStr = `${currentHours}:${currentMins}`;

    appState.reminders.forEach(r => {
      if (r.active && r.time === currentTimeStr) {
        // Dispatch Notification
        if ('Notification' in window && Notification.permission === 'granted') {
          new Notification('FinMate AI: ' + r.title, {
            body: r.notes || 'Waktunya memeriksa dan mencatat keuangan Anda!',
            icon: '/assets/icon.png'
          });
        }
        uiService.showToast(`Pengingat: ${r.title}`, 'info');
        aiCoachService.playChime();
      }
    });
  },

  async handleSaveReminder() {
    const id = document.getElementById('reminder-id').value;
    const title = document.getElementById('reminder-title').value.trim();
    const time = document.getElementById('reminder-time').value;
    const frequency = document.getElementById('reminder-frequency').value;
    const notes = document.getElementById('reminder-notes').value.trim();

    if (!title || !time) {
      uiService.showToast('Judul dan jam pengingat wajib diisi.', 'warning');
      return;
    }

    if (id) {
      const idx = appState.reminders.findIndex(r => r.id === id);
      if (idx !== -1) {
        appState.reminders[idx] = {
          ...appState.reminders[idx],
          title,
          time,
          frequency,
          notes,
          updatedAt: new Date().toISOString()
        };
        uiService.showToast('Pengingat berhasil diperbarui.', 'success');
      }
    } else {
      const newRem = {
        id: 'rem_' + Date.now() + '_' + Math.random().toString(36).substr(2, 5),
        title,
        time,
        frequency,
        notes,
        active: true,
        createdAt: new Date().toISOString()
      };
      appState.reminders.push(newRem);
      uiService.showToast('Pengingat baru berhasil dibuat.', 'success');
    }

    await storageService.persistCurrentState();
    uiService.closeModal('modal-reminder');
    document.getElementById('form-reminder').reset();
    document.getElementById('reminder-id').value = '';
    uiService.renderRemindersView();
  },

  async toggleReminder(id) {
    const rem = appState.reminders.find(r => r.id === id);
    if (!rem) return;
    rem.active = !rem.active;
    await storageService.persistCurrentState();
    uiService.renderRemindersView();
  },

  async deleteReminder(id) {
    if (!confirm('Hapus pengingat ini?')) return;
    appState.reminders = appState.reminders.filter(r => r.id !== id);
    await storageService.persistCurrentState();
    uiService.renderRemindersView();
    uiService.showToast('Pengingat telah dihapus.', 'info');
  }
};

/* ==========================================================================
   11. CHART SERVICE (Chart.js Integration)
   ========================================================================== */
const chartService = {
  cashflowChart: null,
  categoryChart: null,

  initCharts() {
    this.renderCashflowChart();
    this.renderCategoryChart();
  },

  renderCashflowChart() {
    const canvas = document.getElementById('overview-cashflow-chart');
    const emptyState = document.getElementById('overview-cashflow-empty');
    if (!canvas) return;

    const txs = appState.transactions;
    if (txs.length === 0) {
      if (this.cashflowChart) this.cashflowChart.destroy();
      emptyState.classList.remove('hidden');
      return;
    }
    emptyState.classList.add('hidden');

    // Aggregate monthly data
    const monthNames = ['Jan', 'Feb', 'Mar', 'Apr', 'Mei', 'Jun', 'Jul', 'Agu', 'Sep', 'Okt', 'Nov', 'Des'];
    const monthlyIncome = new Array(12).fill(0);
    const monthlyExpense = new Array(12).fill(0);

    const currentYear = new Date().getFullYear();

    txs.forEach(t => {
      const d = new Date(t.date);
      if (d.getFullYear() === currentYear) {
        const m = d.getMonth();
        if (t.type === 'INCOME') monthlyIncome[m] += t.amount;
        if (t.type === 'EXPENSE') monthlyExpense[m] += t.amount;
      }
    });

    const isDark = document.body.classList.contains('theme-dark');
    const gridColor = isDark ? 'rgba(255, 255, 255, 0.08)' : 'rgba(0, 0, 0, 0.05)';
    const textColor = isDark ? '#94a3b8' : '#64748b';

    if (this.cashflowChart) this.cashflowChart.destroy();

    this.cashflowChart = new Chart(canvas, {
      type: 'bar',
      data: {
        labels: monthNames,
        datasets: [
          {
            label: 'Pemasukan (Rp)',
            data: monthlyIncome,
            backgroundColor: '#10b981',
            borderRadius: 6
          },
          {
            label: 'Pengeluaran (Rp)',
            data: monthlyExpense,
            backgroundColor: '#f43f5e',
            borderRadius: 6
          }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: 'top',
            labels: { color: textColor, font: { family: 'Plus Jakarta Sans', weight: '600' } }
          },
          tooltip: {
            callbacks: {
              label: (ctx) => `${ctx.dataset.label}: ${uiService.formatCurrency(ctx.raw)}`
            }
          }
        },
        scales: {
          x: {
            grid: { display: false },
            ticks: { color: textColor, font: { family: 'Plus Jakarta Sans' } }
          },
          y: {
            grid: { color: gridColor },
            ticks: {
              color: textColor,
              font: { family: 'Plus Jakarta Sans' },
              callback: (val) => val >= 1000000 ? `${(val/1000000).toFixed(1)}M` : val >= 1000 ? `${(val/1000).toFixed(0)}k` : val
            }
          }
        }
      }
    });
  },

  renderCategoryChart() {
    const canvas = document.getElementById('expense-category-chart');
    const emptyState = document.getElementById('expense-category-empty');
    if (!canvas) return;

    const expenseTxs = appState.transactions.filter(t => t.type === 'EXPENSE');
    if (expenseTxs.length === 0) {
      if (this.categoryChart) this.categoryChart.destroy();
      emptyState.classList.remove('hidden');
      return;
    }
    emptyState.classList.add('hidden');

    const catTotals = {};
    expenseTxs.forEach(t => {
      catTotals[t.category] = (catTotals[t.category] || 0) + t.amount;
    });

    const labels = Object.keys(catTotals);
    const data = Object.values(catTotals);
    const colors = ['#6366f1', '#10b981', '#f59e0b', '#f43f5e', '#0ea5e9', '#8b5cf6', '#ec4899', '#14b8a6', '#64748b'];

    const isDark = document.body.classList.contains('theme-dark');
    const textColor = isDark ? '#f8fafc' : '#0f172a';

    if (this.categoryChart) this.categoryChart.destroy();

    this.categoryChart = new Chart(canvas, {
      type: 'doughnut',
      data: {
        labels: labels,
        datasets: [{
          data: data,
          backgroundColor: colors.slice(0, labels.length),
          borderWidth: 2,
          borderColor: isDark ? '#111827' : '#ffffff'
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: 'right',
            labels: { color: textColor, font: { family: 'Plus Jakarta Sans', weight: '600' } }
          },
          tooltip: {
            callbacks: {
              label: (ctx) => `${ctx.label}: ${uiService.formatCurrency(ctx.raw)}`
            }
          }
        },
        cutout: '68%'
      }
    });
  }
};

/* ==========================================================================
   12. UI & NAVIGATION SERVICE
   ========================================================================== */
const uiService = {
  init() {
    this.bindGlobalEvents();
    this.initTheme();

    // Check if user is in session storage or fresh
    // Set default date for transaction form
    const txDateInput = document.getElementById('tx-date');
    if (txDateInput) txDateInput.value = new Date().toISOString().split('T')[0];

    const goalDeadlineInput = document.getElementById('goal-deadline');
    if (goalDeadlineInput) {
      const nextMonth = new Date();
      nextMonth.setMonth(nextMonth.getMonth() + 3);
      goalDeadlineInput.value = nextMonth.toISOString().split('T')[0];
    }
  },

  bindGlobalEvents() {
    // Escape key closes modals
    window.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') {
        document.querySelectorAll('.modal-overlay').forEach(modal => {
          modal.classList.add('hidden');
        });
      }
    });

    // Reset inactivity timer on user interaction
    ['mousedown', 'keydown', 'scroll', 'touchstart'].forEach(event => {
      window.addEventListener(event, () => {
        if (appState.currentUser) authService.resetInactivityTimer();
      }, { passive: true });
    });

    // Global Unhandled Error handler
    window.addEventListener('error', (e) => {
      console.error('Unhandled runtime error:', e.error);
    });

    window.addEventListener('unhandledrejection', (e) => {
      console.error('Unhandled async rejection:', e.reason);
    });
  },

  initTheme() {
    const savedTheme = localStorage.getItem(storageService.THEME_KEY) || 'light';
    appState.settings.theme = savedTheme;
    if (savedTheme === 'dark') {
      document.body.classList.add('theme-dark');
      document.body.classList.remove('theme-light');
      document.getElementById('btn-theme-toggle').innerHTML = '<i class="fa-solid fa-sun text-amber"></i>';
    } else {
      document.body.classList.add('theme-light');
      document.body.classList.remove('theme-dark');
      document.getElementById('btn-theme-toggle').innerHTML = '<i class="fa-solid fa-moon"></i>';
    }
  },

  toggleTheme() {
    const isDark = document.body.classList.contains('theme-dark');
    const newTheme = isDark ? 'light' : 'dark';
    appState.settings.theme = newTheme;
    localStorage.setItem(storageService.THEME_KEY, newTheme);

    if (newTheme === 'dark') {
      document.body.classList.add('theme-dark');
      document.body.classList.remove('theme-light');
      document.getElementById('btn-theme-toggle').innerHTML = '<i class="fa-solid fa-sun text-amber"></i>';
    } else {
      document.body.classList.add('theme-light');
      document.body.classList.remove('theme-dark');
      document.getElementById('btn-theme-toggle').innerHTML = '<i class="fa-solid fa-moon"></i>';
    }

    if (appState.currentUser) {
      storageService.persistCurrentState();
      chartService.initCharts();
    }
  },

  switchAuthTab(tab) {
    const tabLogin = document.getElementById('tab-btn-login');
    const tabRegister = document.getElementById('tab-btn-register');
    const formLogin = document.getElementById('form-login');
    const formRegister = document.getElementById('form-register');

    if (tab === 'login') {
      tabLogin.classList.add('active');
      tabRegister.classList.remove('active');
      formLogin.classList.remove('hidden');
      formRegister.classList.add('hidden');
    } else {
      tabRegister.classList.add('active');
      tabLogin.classList.remove('active');
      formRegister.classList.remove('hidden');
      formLogin.classList.add('hidden');
    }
  },

  togglePasswordVisibility(inputId, buttonEl) {
    const input = document.getElementById(inputId);
    if (!input) return;
    if (input.type === 'password') {
      input.type = 'text';
      buttonEl.innerHTML = '<i class="fa-regular fa-eye-slash"></i>';
    } else {
      input.type = 'password';
      buttonEl.innerHTML = '<i class="fa-regular fa-eye"></i>';
    }
  },

  navigate(viewName) {
    appState.activeView = viewName;

    // Update active nav item
    document.querySelectorAll('.nav-item').forEach(item => {
      if (item.getAttribute('data-view') === viewName) {
        item.classList.add('active');
      } else {
        item.classList.remove('active');
      }
    });

    document.querySelectorAll('.bottom-nav-item').forEach(item => {
      if (item.getAttribute('data-view') === viewName) {
        item.classList.add('active');
      } else {
        item.classList.remove('active');
      }
    });

    // Switch view section
    document.querySelectorAll('.app-view').forEach(view => {
      if (view.id === 'view-' + viewName) {
        view.classList.remove('hidden');
        view.classList.add('active');
      } else {
        view.classList.add('hidden');
        view.classList.remove('active');
      }
    });

    // Update Header Headings
    const headingMap = {
      overview: { title: 'Dashboard Overview', sub: 'Pantau arus kas dan kesehatan finansial Anda secara real-time' },
      expenses: { title: 'Expense Tracker', sub: 'Kelola dan analisis pencatatan arus masuk dan keluar dana Anda' },
      goals: { title: 'Financial Goals', sub: 'Wujudkan target masa depan dengan menabung secara konsisten' },
      health: { title: 'Financial Health Analysis', sub: 'Evaluasi rasio keuangan dan panduan alokasi dana 50/30/20' },
      coach: { title: 'AI Financial Coach', sub: 'Asisten cerdas analisis keuangan berbasis data riil Anda' },
      challenges: { title: 'Saving Challenges & Badges', sub: 'Bangun kebiasaan finansial positif melalui gamifikasi' },
      reminders: { title: 'Pengingat Jadwal', sub: 'Atur jadwal notifikasi pencatatan harian dan bayar tagihan' },
      profile: { title: 'Profil & Keamanan', sub: 'Kelola identitas, kunci enkripsi, dan backup cadangan data' }
    };

    if (headingMap[viewName]) {
      document.getElementById('page-heading').textContent = headingMap[viewName].title;
      document.getElementById('page-subheading').textContent = headingMap[viewName].sub;
    }

    // Close mobile sidebar if open
    this.toggleSidebar(false);

    // Render corresponding view data
    this.renderCurrentView(viewName);
  },

  toggleSidebar(open) {
    const sidebar = document.getElementById('sidebar');
    const overlay = document.getElementById('sidebar-overlay');
    if (open) {
      sidebar.classList.add('open');
      overlay.classList.remove('hidden');
    } else {
      sidebar.classList.remove('open');
      overlay.classList.add('hidden');
    }
  },

  openModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
      modal.classList.remove('hidden');
      const firstInput = modal.querySelector('input, select, button');
      if (firstInput) firstInput.focus();
    }
  },

  closeModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) modal.classList.add('hidden');
  },

  showLoader(text = 'Memproses data...') {
    const loader = document.getElementById('global-loader');
    const loaderText = document.getElementById('global-loader-text');
    if (loaderText) loaderText.textContent = text;
    if (loader) loader.classList.remove('hidden');
  },

  hideLoader() {
    const loader = document.getElementById('global-loader');
    if (loader) loader.classList.add('hidden');
  },

  showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;

    const iconMap = {
      success: 'fa-circle-check',
      error: 'fa-circle-exclamation',
      warning: 'fa-triangle-exclamation',
      info: 'fa-circle-info'
    };

    toast.innerHTML = `
      <i class="fa-solid ${iconMap[type] || 'fa-circle-info'}"></i>
      <span>${message}</span>
    `;

    container.appendChild(toast);

    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateX(100%)';
      setTimeout(() => toast.remove(), 300);
    }, 4000);
  },

  formatCurrency(number) {
    return new Intl.NumberFormat('id-ID', {
      style: 'currency',
      currency: 'IDR',
      maximumFractionDigits: 0
    }).format(number || 0);
  },

  formatDate(dateString) {
    if (!dateString) return '-';
    const date = new Date(dateString);
    return date.toLocaleDateString('id-ID', {
      day: 'numeric',
      month: 'short',
      year: 'numeric'
    });
  },

  confirmResetTransactions() {
    if (confirm('Apakah Anda yakin ingin mereset seluruh transaksi? Semua riwayat pengeluaran dan pemasukan akan dihapus.')) {
      transactionService.resetAllTransactions();
    }
  },

  updateSidebarUser() {
    if (!appState.currentUser) return;
    const name = appState.currentUser.name || 'Pengguna';
    const email = appState.currentUser.email || '';
    const status = appState.currentUser.status || 'Mahasiswa';

    document.getElementById('sidebar-user-name').textContent = name;
    document.getElementById('sidebar-user-email').textContent = email;
    document.getElementById('sidebar-user-avatar').textContent = name.charAt(0).toUpperCase();
    document.getElementById('user-role-badge').textContent = status;

    const profName = document.getElementById('profile-name');
    const profEmail = document.getElementById('profile-email');
    const profStatus = document.getElementById('profile-status');
    if (profName) profName.value = name;
    if (profEmail) profEmail.value = email;
    if (profStatus) profStatus.value = status;
  },

  renderAllViews() {
    this.updateSidebarUser();
    this.renderOverview();
    this.renderExpensesView();
    this.renderGoalsView();
    this.renderHealthView();
    this.renderChallengesView();
    this.renderRemindersView();
    chartService.initCharts();
  },

  renderCurrentView(viewName) {
    if (viewName === 'overview') this.renderOverview();
    if (viewName === 'expenses') this.renderExpensesView();
    if (viewName === 'goals') this.renderGoalsView();
    if (viewName === 'health') this.renderHealthView();
    if (viewName === 'challenges') this.renderChallengesView();
    if (viewName === 'reminders') this.renderRemindersView();
    chartService.initCharts();
  },

  renderOverview() {
    const metrics = healthService.calculateMetrics();

    // Summary Stat Values
    document.getElementById('overview-balance').textContent = this.formatCurrency(metrics.netBalance);
    document.getElementById('overview-income').textContent = this.formatCurrency(metrics.totalIncome);
    document.getElementById('overview-expense').textContent = this.formatCurrency(metrics.totalExpense);
    document.getElementById('overview-savings').textContent = this.formatCurrency(metrics.totalGoalSavings);

    const txs = appState.transactions;
    const incomeCount = txs.filter(t => t.type === 'INCOME').length;
    const expenseCount = txs.filter(t => t.type === 'EXPENSE').length;
    document.getElementById('overview-income-count').textContent = `${incomeCount} Transaksi`;
    document.getElementById('overview-expense-count').textContent = `${expenseCount} Transaksi`;
    document.getElementById('overview-goals-count').textContent = `${appState.goals.length} Target Aktif`;

    // Health Score Widget
    document.getElementById('overview-health-score').textContent = metrics.score;
    const badgeHealth = document.getElementById('overview-health-badge');
    badgeHealth.textContent = metrics.category;
    if (metrics.score >= 90) {
      badgeHealth.className = 'badge-health-status bg-emerald-subtle text-emerald';
    } else if (metrics.score >= 70) {
      badgeHealth.className = 'badge-health-status bg-indigo-subtle text-indigo';
    } else if (metrics.score >= 50) {
      badgeHealth.className = 'badge-health-status bg-amber-subtle text-amber';
    } else {
      badgeHealth.className = 'badge-health-status bg-rose-subtle text-rose';
    }

    document.getElementById('overview-health-desc').textContent = metrics.summaryText;
    document.getElementById('overview-expense-ratio').textContent = `${metrics.expenseRatio}%`;
    document.getElementById('overview-savings-ratio').textContent = `${metrics.savingsRate}%`;

    // Streak
    document.getElementById('overview-streak-count').textContent = `${appState.streak.count} Hari`;

    // Priority Goal
    const goalBox = document.getElementById('overview-priority-goal-box');
    const goalEmpty = document.getElementById('overview-goal-empty');
    if (appState.goals.length > 0) {
      const topGoal = appState.goals[0];
      goalBox.classList.remove('hidden');
      goalEmpty.classList.add('hidden');

      const percent = Math.min(100, Math.round((topGoal.collectedAmount / topGoal.targetAmount) * 100));
      document.getElementById('overview-goal-name').textContent = topGoal.name;
      document.getElementById('overview-goal-deadline').textContent = `Deadline: ${this.formatDate(topGoal.deadline)}`;
      document.getElementById('overview-goal-percent').textContent = `${percent}%`;
      document.getElementById('overview-goal-bar').style.width = `${percent}%`;
      document.getElementById('overview-goal-collected').textContent = `Terkumpul: ${this.formatCurrency(topGoal.collectedAmount)}`;
      document.getElementById('overview-goal-target').textContent = `Target: ${this.formatCurrency(topGoal.targetAmount)}`;
    } else {
      goalBox.classList.add('hidden');
      goalEmpty.classList.remove('hidden');
    }

    // Recent 5 Transactions
    const recentBody = document.getElementById('overview-recent-tx-body');
    const recentEmpty = document.getElementById('overview-tx-empty');
    recentBody.innerHTML = '';

    const recents = appState.transactions.slice(0, 5);
    if (recents.length === 0) {
      recentEmpty.classList.remove('hidden');
    } else {
      recentEmpty.classList.add('hidden');
      recents.forEach(t => {
        const tr = document.createElement('tr');
        const isIncome = t.type === 'INCOME';
        tr.innerHTML = `
          <td>${this.formatDate(t.date)}</td>
          <td><span class="badge-tag ${isIncome ? 'badge-type-income' : 'badge-type-expense'}">${isIncome ? '+ Masuk' : '- Keluar'}</span></td>
          <td><strong>${t.category}</strong></td>
          <td>${t.description}</td>
          <td class="font-bold ${isIncome ? 'text-emerald' : 'text-rose'}">${isIncome ? '+' : '-'}${this.formatCurrency(t.amount)}</td>
          <td>
            <button type="button" class="btn btn-outline btn-xs" onclick="transactionService.openEditModal('${t.id}')"><i class="fa-solid fa-pen"></i></button>
            <button type="button" class="btn btn-ghost btn-xs text-danger" onclick="transactionService.deleteTransaction('${t.id}')"><i class="fa-solid fa-trash"></i></button>
          </td>
        `;
        recentBody.appendChild(tr);
      });
    }
  },

  renderExpensesView() {
    const filtered = transactionService.getFilteredTransactions();
    const tbody = document.getElementById('tx-table-body');
    const emptyState = document.getElementById('tx-empty-state');
    tbody.innerHTML = '';

    let totalInc = 0;
    let totalExp = 0;

    filtered.forEach(t => {
      if (t.type === 'INCOME') totalInc += t.amount;
      if (t.type === 'EXPENSE') totalExp += t.amount;
    });

    document.getElementById('tx-filtered-count').textContent = `${filtered.length} Transaksi`;
    document.getElementById('tx-filtered-income').textContent = this.formatCurrency(totalInc);
    document.getElementById('tx-filtered-expense').textContent = this.formatCurrency(totalExp);
    document.getElementById('tx-filtered-net').textContent = this.formatCurrency(totalInc - totalExp);

    if (filtered.length === 0) {
      emptyState.classList.remove('hidden');
    } else {
      emptyState.classList.add('hidden');
      filtered.forEach(t => {
        const isIncome = t.type === 'INCOME';
        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td>${this.formatDate(t.date)}</td>
          <td><span class="badge-tag ${isIncome ? 'badge-type-income' : 'badge-type-expense'}">${isIncome ? 'Pemasukan' : 'Pengeluaran'}</span></td>
          <td><strong>${t.category}</strong></td>
          <td>${t.description}</td>
          <td class="font-bold ${isIncome ? 'text-emerald' : 'text-rose'}">${isIncome ? '+' : '-'}${this.formatCurrency(t.amount)}</td>
          <td class="text-center">
            <button type="button" class="btn btn-outline btn-xs" onclick="transactionService.openEditModal('${t.id}')" title="Edit Transaksi"><i class="fa-solid fa-pen"></i></button>
            <button type="button" class="btn btn-ghost btn-xs text-danger" onclick="transactionService.deleteTransaction('${t.id}')" title="Hapus Transaksi"><i class="fa-solid fa-trash"></i></button>
          </td>
        `;
        tbody.appendChild(tr);
      });
    }

    // Render Top Categories List
    const topListContainer = document.getElementById('top-categories-list');
    if (topListContainer) {
      topListContainer.innerHTML = '';
      const expTxs = appState.transactions.filter(t => t.type === 'EXPENSE');
      const catMap = {};
      let totalExpense = 0;
      expTxs.forEach(t => {
        catMap[t.category] = (catMap[t.category] || 0) + t.amount;
        totalExpense += t.amount;
      });

      const sortedCats = Object.entries(catMap).sort((a, b) => b[1] - a[1]);

      if (sortedCats.length === 0) {
        topListContainer.innerHTML = '<p class="text-sm text-muted text-center py-4">Belum ada pengeluaran yang dicatat.</p>';
      } else {
        sortedCats.slice(0, 4).forEach(([cat, amt]) => {
          const percent = totalExpense > 0 ? Math.round((amt / totalExpense) * 100) : 0;
          const item = document.createElement('div');
          item.className = 'top-cat-item';
          item.innerHTML = `
            <div class="top-cat-left">
              <div class="top-cat-icon bg-rose-subtle text-rose"><i class="fa-solid fa-bag-shopping"></i></div>
              <div>
                <strong>${cat}</strong>
                <div class="text-xs text-muted">${percent}% dari total belanja</div>
              </div>
            </div>
            <strong class="text-rose">${this.formatCurrency(amt)}</strong>
          `;
          topListContainer.appendChild(item);
        });
      }
    }
  },

  renderGoalsView() {
    const goals = appState.goals;
    const grid = document.getElementById('goals-cards-grid');
    const emptyState = document.getElementById('goals-empty-state');
    grid.innerHTML = '';

    let totalTarget = 0;
    let totalCollected = 0;
    let completedCount = 0;

    goals.forEach(g => {
      totalTarget += g.targetAmount;
      totalCollected += g.collectedAmount;
      if (g.collectedAmount >= g.targetAmount) completedCount++;
    });

    document.getElementById('goals-total-target-amount').textContent = this.formatCurrency(totalTarget);
    document.getElementById('goals-total-collected-amount').textContent = this.formatCurrency(totalCollected);
    document.getElementById('goals-completed-count').textContent = completedCount;

    const avgProgress = totalTarget > 0 ? Math.min(100, Math.round((totalCollected / totalTarget) * 100)) : 0;
    document.getElementById('goals-avg-progress').textContent = `${avgProgress}%`;

    if (goals.length === 0) {
      emptyState.classList.remove('hidden');
    } else {
      emptyState.classList.add('hidden');
      goals.forEach(g => {
        const percent = Math.min(100, Math.round((g.collectedAmount / g.targetAmount) * 100));
        const remaining = Math.max(0, g.targetAmount - g.collectedAmount);
        const isCompleted = g.collectedAmount >= g.targetAmount;

        // Calculate needed saving rate per day & week
        const deadlineDate = new Date(g.deadline);
        const today = new Date();
        const diffTime = deadlineDate - today;
        const daysLeft = Math.max(1, Math.ceil(diffTime / (1000 * 60 * 60 * 24)));
        const weeksLeft = Math.max(1, Math.ceil(daysLeft / 7));

        const neededPerDay = Math.ceil(remaining / daysLeft);
        const neededPerWeek = Math.ceil(remaining / weeksLeft);

        const card = document.createElement('div');
        card.className = `goal-card ${isCompleted ? 'completed' : ''}`;
        card.innerHTML = `
          <div class="goal-card-top">
            <div class="goal-card-icon"><i class="fa-solid ${g.icon || 'fa-bullseye'}"></i></div>
            <div class="goal-card-meta">
              <h4 class="goal-card-title">${g.name}</h4>
              <span class="goal-card-deadline"><i class="fa-regular fa-calendar"></i> Batas: ${this.formatDate(g.deadline)} (${daysLeft} hari lagi)</span>
            </div>
            <span class="badge-percent">${percent}%</span>
          </div>

          <div class="progress-bar-wrap">
            <div class="progress-bar-fill ${isCompleted ? 'bg-emerald' : ''}" style="width: ${percent}%;"></div>
          </div>

          <div class="goal-amounts-row mt-2">
            <span class="text-xs font-semibold">Terkumpul: ${this.formatCurrency(g.collectedAmount)}</span>
            <span class="text-xs text-muted">Target: ${this.formatCurrency(g.targetAmount)}</span>
          </div>

          <div class="goal-calc-box">
            <div class="goal-calc-item">
              <span>Nabung / Hari:</span>
              <strong>${isCompleted ? 'Selesai' : this.formatCurrency(neededPerDay)}</strong>
            </div>
            <div class="goal-calc-item">
              <span>Nabung / Pekan:</span>
              <strong>${isCompleted ? 'Tercapai 🎉' : this.formatCurrency(neededPerWeek)}</strong>
            </div>
          </div>

          <div class="goal-card-actions">
            <button type="button" class="btn btn-primary btn-sm flex-1" onclick="goalService.openDepositModal('${g.id}')">
              <i class="fa-solid fa-plus"></i> Tabung Dana
            </button>
            <button type="button" class="btn btn-outline btn-sm text-danger" onclick="goalService.deleteGoal('${g.id}')" title="Hapus Target">
              <i class="fa-solid fa-trash"></i>
            </button>
          </div>
        `;
        grid.appendChild(card);
      });
    }
  },

  renderHealthView() {
    const metrics = healthService.calculateMetrics();

    document.getElementById('health-page-score').innerHTML = `${metrics.score}<span>/100</span>`;
    document.getElementById('health-page-badge').textContent = metrics.category;
    document.getElementById('health-page-summary').textContent = metrics.summaryText;

    document.getElementById('health-metric-savings-rate').textContent = `${metrics.savingsRate}%`;
    document.getElementById('health-metric-savings-bar').style.width = `${Math.min(100, metrics.savingsRate * 2)}%`;

    document.getElementById('health-metric-expense-ratio').textContent = `${metrics.expenseRatio}%`;
    document.getElementById('health-metric-expense-bar').style.width = `${Math.min(100, metrics.expenseRatio)}%`;

    const bufferStatus = metrics.netBalance > metrics.totalExpense ? 'Sangat Aman (>1 Bulan)' : metrics.netBalance > 0 ? 'Cukup Aman' : 'Perlu Diwaspadai';
    document.getElementById('health-metric-buffer').textContent = bufferStatus;

    // Recommendations
    const recs = healthService.generateRecommendations(metrics);
    const recList = document.getElementById('health-recommendations-list');
    recList.innerHTML = '';
    recs.forEach(r => {
      const card = document.createElement('div');
      card.className = 'rec-card';
      card.innerHTML = `
        <div class="rec-header">
          <i class="fa-solid ${r.icon}"></i>
          <span>${r.title}</span>
        </div>
        <p class="rec-desc">${r.desc}</p>
      `;
      recList.appendChild(card);
    });

    // 50-30-20 Rule Evaluation
    const txs = appState.transactions;
    let needsAmt = 0;
    let wantsAmt = 0;
    let savingsAmt = 0;

    txs.forEach(t => {
      if (t.type === 'EXPENSE') {
        if (['Makanan', 'Transportasi', 'Pendidikan', 'Tagihan'].includes(t.category)) {
          needsAmt += t.amount;
        } else if (['Hiburan', 'Belanja', 'Lainnya'].includes(t.category)) {
          wantsAmt += t.amount;
        } else if (t.category === 'Tabungan') {
          savingsAmt += t.amount;
        }
      }
    });

    const totalBudget = needsAmt + wantsAmt + savingsAmt;
    if (totalBudget > 0) {
      const needsPct = Math.round((needsAmt / totalBudget) * 100);
      const wantsPct = Math.round((wantsAmt / totalBudget) * 100);
      const savingsPct = Math.round((savingsAmt / totalBudget) * 100);

      document.getElementById('rule-needs-val').textContent = `${needsPct}%`;
      document.getElementById('rule-wants-val').textContent = `${wantsPct}%`;
      document.getElementById('rule-savings-val').textContent = `${savingsPct}%`;
    }
  },

  renderChallengesView() {
    // Badges Container
    const badgeBox = document.getElementById('badges-container');
    badgeBox.innerHTML = '';
    let unlockedCount = 0;

    appState.badges.forEach(b => {
      if (b.unlocked) unlockedCount++;
      const item = document.createElement('div');
      item.className = `badge-card-item ${b.unlocked ? 'unlocked' : 'locked'}`;
      item.innerHTML = `
        <div class="badge-icon-big text-amber"><i class="fa-solid ${b.icon}"></i></div>
        <strong class="badge-name">${b.name}</strong>
        <span class="badge-req">${b.desc}</span>
        ${b.unlocked ? `<span class="badge-tag bg-emerald-subtle text-emerald mt-2"><i class="fa-solid fa-check"></i> Terbuka</span>` : `<span class="badge-tag mt-2">Terkunci</span>`}
      `;
      badgeBox.appendChild(item);
    });

    document.getElementById('badges-unlocked-count').textContent = `${unlockedCount} / ${appState.badges.length} Terbuka`;
    document.getElementById('challenges-streak-num').textContent = `${appState.streak.count} Hari`;

    // Active Challenges Grid
    const chContainer = document.getElementById('challenges-container');
    chContainer.innerHTML = '';
    appState.challenges.forEach(ch => {
      const progressDays = Math.min(ch.targetDays, appState.streak.count);
      const percent = Math.min(100, Math.round((progressDays / ch.targetDays) * 100));

      const card = document.createElement('div');
      card.className = 'challenge-card';
      card.innerHTML = `
        <div class="challenge-header">
          <h4 class="challenge-title">${ch.name}</h4>
          <span class="challenge-reward"><i class="fa-solid fa-award"></i> Hadiah: ${ch.rewardBadge}</span>
        </div>
        <p class="text-sm text-muted">${ch.desc}</p>
        <div class="progress-bar-wrap">
          <div class="progress-bar-fill" style="width: ${percent}%;"></div>
        </div>
        <div class="flex justify-between text-xs text-muted">
          <span>Progress: ${progressDays} / ${ch.targetDays} Hari</span>
          <strong>${percent}%</strong>
        </div>
      `;
      chContainer.appendChild(card);
    });
  },

  renderRemindersView() {
    const listContainer = document.getElementById('reminders-list-container');
    const emptyState = document.getElementById('reminders-empty-state');
    listContainer.innerHTML = '';

    const countBadge = document.getElementById('badge-reminder-count');
    const activeCount = appState.reminders.filter(r => r.active).length;
    if (activeCount > 0) {
      countBadge.textContent = activeCount;
      countBadge.classList.remove('hidden');
    } else {
      countBadge.classList.add('hidden');
    }

    if (appState.reminders.length === 0) {
      emptyState.classList.remove('hidden');
    } else {
      emptyState.classList.add('hidden');
      appState.reminders.forEach(r => {
        const card = document.createElement('div');
        card.className = 'reminder-card';
        card.innerHTML = `
          <div class="reminder-info">
            <h4>${r.title}</h4>
            <div class="reminder-meta">
              <i class="fa-regular fa-clock"></i> ${r.time} • <span>${r.frequency}</span>
            </div>
            ${r.notes ? `<p class="text-xs text-muted mt-1">${r.notes}</p>` : ''}
          </div>
          <div class="flex items-center gap-3">
            <label class="switch-wrap" title="Aktifkan / Matikan">
              <input type="checkbox" ${r.active ? 'checked' : ''} onchange="reminderService.toggleReminder('${r.id}')" />
              <span class="switch-slider"></span>
            </label>
            <button type="button" class="btn btn-ghost btn-xs text-danger" onclick="reminderService.deleteReminder('${r.id}')" title="Hapus">
              <i class="fa-solid fa-trash"></i>
            </button>
          </div>
        `;
        listContainer.appendChild(card);
      });
    }
  }
};

/* ==========================================================================
   13. APPLICATION BOOTSTRAP
   ========================================================================== */
// Expose services used by inline HTML event handlers.
// Because script.js is loaded as a JavaScript module, top-level const
// declarations are not properties of window. Without these exports,
// handlers such as `authService.handleRegister()` fail in production.
Object.assign(window, {
  cryptoService,
  storageService,
  authService,
  transactionService,
  goalService,
  healthService,
  aiCoachService,
  badgeService,
  reminderService,
  chartService,
  uiService
});

document.addEventListener('DOMContentLoaded', () => {
  uiService.init();
});

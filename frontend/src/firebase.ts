// ─── Firebase configuration ─────────────────────────────────────
// To get these values:
// 1. Go to https://console.firebase.google.com/
// 2. Create a new project named "AgentShield"
// 3. Add a Web App (click </> icon)
// 4. Copy the firebaseConfig object values here
// 5. In Authentication > Sign-in method, enable Email/Password and Google

import { initializeApp } from "firebase/app";
import {
  getAuth,
  GoogleAuthProvider,
  signInWithEmailAndPassword,
  createUserWithEmailAndPassword,
  signInWithPopup,
  signOut,
  onAuthStateChanged,
  type User,
} from "firebase/auth";

// ⚠ Fill these in from your Firebase project console
const firebaseConfig = {
  apiKey:            import.meta.env.VITE_FIREBASE_API_KEY            || "REPLACE_ME",
  authDomain:        import.meta.env.VITE_FIREBASE_AUTH_DOMAIN        || "REPLACE_ME",
  projectId:         import.meta.env.VITE_FIREBASE_PROJECT_ID         || "REPLACE_ME",
  storageBucket:     import.meta.env.VITE_FIREBASE_STORAGE_BUCKET     || "REPLACE_ME",
  messagingSenderId: import.meta.env.VITE_FIREBASE_MESSAGING_SENDER_ID|| "REPLACE_ME",
  appId:             import.meta.env.VITE_FIREBASE_APP_ID             || "REPLACE_ME",
};

const isFirebaseConfigured = !Object.values(firebaseConfig).includes("REPLACE_ME");

let app: ReturnType<typeof initializeApp> | null = null;
let auth: ReturnType<typeof getAuth> | null = null;
let googleProvider: GoogleAuthProvider | null = null;

if (isFirebaseConfigured) {
  app = initializeApp(firebaseConfig);
  auth = getAuth(app);
  googleProvider = new GoogleAuthProvider();
}

export {
  auth,
  googleProvider,
  isFirebaseConfigured,
  signInWithEmailAndPassword,
  createUserWithEmailAndPassword,
  signInWithPopup,
  signOut,
  onAuthStateChanged,
  type User,
};

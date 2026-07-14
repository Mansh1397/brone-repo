import express from 'express';
import { requestOtp, verifyOtp, powValidator } from './auth/identityProvider';
import { createPost } from './security/postController';

const app = express();
app.use(express.json());

// 🛡️ Route Ingress Channels
app.post('/api/v1/auth/request-otp', powValidator, requestOtp);
app.post('/api/v1/auth/verify-otp', verifyOtp);
app.post('/api/v1/posts', createPost);

// Legacy Fallback Channels
app.post('/api/auth/request-otp', powValidator, requestOtp);
app.post('/api/auth/verify-otp', verifyOtp);
app.post('/api/posts', createPost);

const PORT = parseInt(process.env.PORT || '3000', 10);

// ⚡ Bind to 0.0.0.0 so Docker can forward external traffic seamlessly
app.listen(PORT, '0.0.0.0', () => {
    console.log(`================================================================`);
    console.log(`🛡️  BRONE ZERO-KNOWLEDGE API GATEWAY ONLINE ON PORT ${PORT}  🛡️`);
    console.log(`🔒 SECURED ISOLATION ZONE ACTIVE | ANTIGRAVITY ENGINES LIVE    `);
    console.log(`================================================================`);
});
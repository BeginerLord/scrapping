import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { AuthService } from '../services/authService';
import { User, IUser } from '../models/User';
import { LoginCredentials } from '../types/auth';
import { encrypt, decrypt } from '../utils/crypto';

interface LoginRequestBody {
  username: string;
  password: string;
  simaUsername: string;
  simaPassword: string;
}

interface AuthTokenPayload {
  userId: string;
  username: string;
}

export async function authRoutes(fastify: FastifyInstance) {
  const authService = new AuthService();

  fastify.post('/register', async (request: FastifyRequest<{ Body: LoginRequestBody }>, reply: FastifyReply) => {
    try {
      const { username, password, simaUsername, simaPassword } = request.body;

      if (!username || !password || !simaUsername || !simaPassword) {
        return reply.status(400).send({
          success: false,
          error: 'Missing required fields'
        });
      }

      const existingUser = await User.findOne({ username });
      if (existingUser) {
        return reply.status(409).send({
          success: false,
          error: 'User already exists'
        });
      }

      const simaLoginResult = await authService.login({
        username: simaUsername,
        password: simaPassword
      });

      if (!simaLoginResult.success) {
        return reply.status(401).send({
          success: false,
          error: `SIMA authentication failed: ${simaLoginResult.error}`
        });
      }

      const passwordHash = await bcrypt.hash(password, 12);
      const encryptedSimaPassword = encrypt(simaPassword);

      const user = new User({
        username,
        passwordHash,
        simaCredentials: {
          username: simaUsername,
          encryptedPassword: encryptedSimaPassword
        },
        sessions: [{
          cookies: simaLoginResult.cookies || [],
          loginToken: simaLoginResult.sessionData?.loginToken,
          expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
          isActive: true
        }]
      });

      await user.save();

      const token = jwt.sign(
        { userId: user._id, username: user.username } as AuthTokenPayload,
        process.env.JWT_SECRET || 'fallback-secret',
        { expiresIn: '7d' }
      );

      reply.send({
        success: true,
        token,
        user: {
          id: (user._id as any),
          username: user.username
        }
      });
    } catch (error) {
      reply.status(500).send({
        success: false,
        error: error instanceof Error ? error.message : 'Registration failed'
      });
    }
  });

  fastify.post('/login', async (request: FastifyRequest<{ Body: { username: string; password: string } }>, reply: FastifyReply) => {
    try {
      const { username, password } = request.body;

      if (!username || !password) {
        return reply.status(400).send({
          success: false,
          error: 'Username and password required'
        });
      }

      const user = await User.findOne({ username });
      if (!user) {
        return reply.status(401).send({
          success: false,
          error: 'Invalid credentials'
        });
      }

      const isPasswordValid = await bcrypt.compare(password, user.passwordHash);
      if (!isPasswordValid) {
        return reply.status(401).send({
          success: false,
          error: 'Invalid credentials'
        });
      }

      const activeSession = user.sessions.find(s =>
        s.isActive && s.expiresAt > new Date()
      );

      if (!activeSession || !(await authService.validateSession(activeSession.cookies))) {
        const simaLoginResult = await authService.login({
          username: user.simaCredentials.username,
          password: decrypt(user.simaCredentials.encryptedPassword)
        });

        if (!simaLoginResult.success) {
          return reply.status(401).send({
            success: false,
            error: 'SIMA session expired and re-authentication failed'
          });
        }

        user.sessions.forEach(s => s.isActive = false);
        user.sessions.push({
          cookies: simaLoginResult.cookies || [],
          loginToken: simaLoginResult.sessionData?.loginToken,
          expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
          isActive: true
        });

        await user.save();
      }

      const token = jwt.sign(
        { userId: user._id, username: user.username } as AuthTokenPayload,
        process.env.JWT_SECRET || 'fallback-secret',
        { expiresIn: '7d' }
      );

      reply.send({
        success: true,
        token,
        user: {
          id: (user._id as any),
          username: user.username
        }
      });
    } catch (error) {
      reply.status(500).send({
        success: false,
        error: error instanceof Error ? error.message : 'Login failed'
      });
    }
  });

  fastify.get('/validate', async (request: FastifyRequest, reply: FastifyReply) => {
    try {
      const token = request.headers.authorization?.replace('Bearer ', '');

      if (!token) {
        return reply.status(401).send({
          success: false,
          error: 'No token provided'
        });
      }

      const decoded = jwt.verify(token, process.env.JWT_SECRET || 'fallback-secret') as AuthTokenPayload;
      const user = await User.findById(decoded.userId) as IUser | null;

      if (!user) {
        return reply.status(401).send({
          success: false,
          error: 'Invalid token'
        });
      }

      const activeSession = user.sessions.find(s =>
        s.isActive && s.expiresAt > new Date()
      );

      const isSessionValid = activeSession ?
        await authService.validateSession(activeSession.cookies) : false;

      reply.send({
        success: true,
        user: {
          id: (user._id as any),
          username: user.username
        },
        sessionValid: isSessionValid
      });
    } catch (error) {
      reply.status(401).send({
        success: false,
        error: 'Invalid token'
      });
    }
  });
}
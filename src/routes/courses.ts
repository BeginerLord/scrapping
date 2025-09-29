import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import jwt from 'jsonwebtoken';
import { ScraperService } from '../services/scraperService';
import { AuthService } from '../services/authService';
import { User, IUser } from '../models/User';
import { Course } from '../models/Course';
import { decrypt } from '../utils/crypto';

interface AuthTokenPayload {
  userId: string;
  username: string;
}

export async function coursesRoutes(fastify: FastifyInstance) {
  const scraperService = new ScraperService();
  const authService = new AuthService();

  async function authenticate(request: FastifyRequest): Promise<{ userId: string; cookies: string[] }> {
    const token = request.headers.authorization?.replace('Bearer ', '');

    if (!token) {
      throw new Error('No token provided');
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'fallback-secret') as AuthTokenPayload;
    const user = await User.findById(decoded.userId) as IUser | null;

    if (!user) {
      throw new Error('Invalid token');
    }

    let activeSession = user.sessions.find(s =>
      s.isActive && s.expiresAt > new Date()
    );

    console.log('🔍 Active session found:', !!activeSession);
    console.log('📅 Session count:', user.sessions.length);

    // TEMPORARY: Skip validateSession due to SIMA redirect loop issue
    // const isSessionValid = activeSession ? await authService.validateSession(activeSession.cookies) : false;
    const isSessionValid = !!activeSession; // Just check if session exists

    console.log('✅ Session validation result (SKIPPED):', isSessionValid);

    if (!activeSession || !isSessionValid) {
      let simaLoginResult;
      try {
        simaLoginResult = await authService.login({
          username: user.simaCredentials.username,
          password: decrypt(user.simaCredentials.encryptedPassword)
        });

        if (!simaLoginResult.success) {
          throw new Error('Session expired and re-authentication failed');
        }
      } catch (decryptError) {
        if (decryptError instanceof Error && decryptError.message.includes('bcrypt hash')) {
          throw new Error('Legacy user account detected. Please re-register your account to use the new system.');
        }
        throw decryptError;
      }

      user.sessions.forEach(s => s.isActive = false);
      user.sessions.push({
        cookies: simaLoginResult.cookies || [],
        loginToken: simaLoginResult.sessionData?.loginToken,
        expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
        isActive: true
      });

      console.log('💾 Saving new session with cookies count:', simaLoginResult.cookies?.length);
      console.log('🍪 New session cookies preview:', simaLoginResult.cookies?.slice(0, 3));

      await user.save();
      activeSession = user.sessions[user.sessions.length - 1];

      console.log('✅ New session saved and activated');
    }

    return {
      userId: (user._id as any).toString(),
      cookies: activeSession.cookies
    };
  }

  fastify.get('/courses', async (request: FastifyRequest, reply: FastifyReply) => {
    try {
      const { userId, cookies } = await authenticate(request);

      const existingCourses = await Course.find({ userId, isActive: true });
      const lastSync = existingCourses.length > 0 ?
        Math.max(...existingCourses.map(c => c.lastSyncAt.getTime())) : 0;

      const shouldRefresh = (Date.now() - lastSync) > 60 * 60 * 1000; // 1 hour

      if (!shouldRefresh && existingCourses.length > 0) {
        return reply.send({
          success: true,
          courses: existingCourses.map(course => ({
            id: course.courseId,
            name: course.name,
            shortname: course.shortname,
            lastSyncAt: course.lastSyncAt
          })),
          cached: true
        });
      }

      const freshCourses = await scraperService.getUserCourses(cookies);

      await Course.updateMany({ userId }, { isActive: false });

      for (const courseInfo of freshCourses) {
        await Course.findOneAndUpdate(
          { userId, courseId: courseInfo.id },
          {
            userId,
            courseId: courseInfo.id,
            name: courseInfo.name,
            shortname: courseInfo.shortname,
            isActive: true,
            lastSyncAt: new Date()
          },
          { upsert: true, new: true }
        );
      }

      reply.send({
        success: true,
        courses: freshCourses,
        cached: false
      });
    } catch (error) {
      reply.status(500).send({
        success: false,
        error: error instanceof Error ? error.message : 'Failed to fetch courses'
      });
    }
  });

  fastify.post('/courses/sync', async (request: FastifyRequest, reply: FastifyReply) => {
    try {
      const { userId, cookies } = await authenticate(request);

      const courses = await scraperService.getUserCourses(cookies);

      await Course.updateMany({ userId }, { isActive: false });

      const syncedCourses = [];
      for (const courseInfo of courses) {
        const course = await Course.findOneAndUpdate(
          { userId, courseId: courseInfo.id },
          {
            userId,
            courseId: courseInfo.id,
            name: courseInfo.name,
            shortname: courseInfo.shortname,
            isActive: true,
            lastSyncAt: new Date()
          },
          { upsert: true, new: true }
        );
        syncedCourses.push(course);
      }

      reply.send({
        success: true,
        courses: syncedCourses.map(course => ({
          id: course.courseId,
          name: course.name,
          shortname: course.shortname,
          lastSyncAt: course.lastSyncAt
        })),
        message: `Synchronized ${courses.length} courses`
      });
    } catch (error) {
      reply.status(500).send({
        success: false,
        error: error instanceof Error ? error.message : 'Failed to sync courses'
      });
    }
  });

  fastify.get('/courses/:courseId', async (
    request: FastifyRequest<{
      Params: { courseId: string };
    }>,
    reply: FastifyReply
  ) => {
    try {
      const { courseId } = request.params;
      const { userId } = await authenticate(request);

      const course = await Course.findOne({ userId, courseId, isActive: true });

      if (!course) {
        return reply.status(404).send({
          success: false,
          error: 'Course not found'
        });
      }

      reply.send({
        success: true,
        course: {
          id: course.courseId,
          name: course.name,
          shortname: course.shortname,
          lastSyncAt: course.lastSyncAt
        }
      });
    } catch (error) {
      reply.status(500).send({
        success: false,
        error: error instanceof Error ? error.message : 'Failed to fetch course'
      });
    }
  });
}
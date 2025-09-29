import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import jwt from 'jsonwebtoken';
import { ScraperService } from '../services/scraperService';
import { AuthService } from '../services/authService';
import { User, IUser } from '../models/User';
import { Schedule } from '../models/Schedule';
import { decrypt } from '../utils/crypto';

interface AuthTokenPayload {
  userId: string;
  username: string;
}

interface ScheduleParams {
  period: 'day' | 'week' | 'month';
}

interface ScheduleQuerystring {
  date?: string;
  refresh?: string;
  course?: string;
}

export async function scheduleRoutes(fastify: FastifyInstance) {
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

    if (!activeSession || !(await authService.validateSession(activeSession.cookies))) {
      const simaLoginResult = await authService.login({
        username: user.simaCredentials.username,
        password: decrypt(user.simaCredentials.encryptedPassword)
      });

      if (!simaLoginResult.success) {
        throw new Error('Session expired and re-authentication failed');
      }

      user.sessions.forEach(s => s.isActive = false);
      user.sessions.push({
        cookies: simaLoginResult.cookies || [],
        loginToken: simaLoginResult.sessionData?.loginToken,
        expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
        isActive: true
      });

      await user.save();
      activeSession = user.sessions[user.sessions.length - 1];
    }

    return {
      userId: (user._id as any).toString(),
      cookies: activeSession.cookies
    };
  }

  fastify.get('/schedule/:period', async (
    request: FastifyRequest<{
      Params: ScheduleParams;
      Querystring: ScheduleQuerystring;
    }>,
    reply: FastifyReply
  ) => {
    try {
      const { period } = request.params;
      const { date, refresh, course } = request.query;

      const { userId, cookies } = await authenticate(request);

      if (!['day', 'week', 'month', 'upcoming'].includes(period)) {
        return reply.status(400).send({
          success: false,
          error: 'Invalid period. Must be day, week, month, or upcoming'
        });
      }

      const targetDate = date ? new Date(date) : new Date();
      const shouldRefresh = refresh === 'true';

      if (!shouldRefresh && period === 'day') {
        const startOfDay = new Date(targetDate);
        startOfDay.setHours(0, 0, 0, 0);

        const endOfDay = new Date(targetDate);
        endOfDay.setHours(23, 59, 59, 999);

        const query: any = {
          userId,
          date: {
            $gte: startOfDay,
            $lt: endOfDay
          }
        };

        if (course) {
          query.courseId = course;
        }

        const existingSchedule = await Schedule.findOne(query);

        if (existingSchedule && (Date.now() - existingSchedule.lastUpdated.getTime()) < 30 * 60 * 1000) {
          return reply.send({
            success: true,
            data: [{
              date: existingSchedule.date.toISOString().split('T')[0],
              activities: existingSchedule.activities,
              courseId: existingSchedule.courseId
            }],
            cached: true
          });
        }
      }

      const scheduleData = await scraperService.scrapeSchedule(
        cookies,
        period as any,
        course,
        date
      );

      if (period === 'day' && scheduleData.length > 0) {
        const cacheDate = new Date(targetDate);
        cacheDate.setHours(12, 0, 0, 0); // Use noon to avoid timezone issues

        const startOfDay = new Date(targetDate);
        startOfDay.setHours(0, 0, 0, 0);

        const endOfDay = new Date(targetDate);
        endOfDay.setHours(23, 59, 59, 999);

        await Schedule.findOneAndUpdate(
          {
            userId,
            courseId: course || null,
            date: {
              $gte: startOfDay,
              $lt: endOfDay
            }
          },
          {
            userId,
            courseId: course || null,
            date: cacheDate,
            activities: scheduleData[0].activities,
            lastUpdated: new Date()
          },
          {
            upsert: true,
            new: true
          }
        );
      }

      reply.send({
        success: true,
        data: scheduleData,
        cached: false,
        courseId: course
      });
    } catch (error) {
      reply.status(500).send({
        success: false,
        error: error instanceof Error ? error.message : 'Failed to fetch schedule'
      });
    }
  });

  fastify.get('/schedule/history/:days', async (
    request: FastifyRequest<{
      Params: { days: string };
    }>,
    reply: FastifyReply
  ) => {
    try {
      const { days } = request.params;
      const { userId } = await authenticate(request);

      const daysNumber = parseInt(days);
      if (isNaN(daysNumber) || daysNumber <= 0 || daysNumber > 365) {
        return reply.status(400).send({
          success: false,
          error: 'Invalid days parameter. Must be between 1 and 365'
        });
      }

      const startDate = new Date();
      startDate.setDate(startDate.getDate() - daysNumber);

      const schedules = await Schedule.find({
        userId,
        date: {
          $gte: startDate,
          $lte: new Date()
        }
      }).sort({ date: 1 });

      const scheduleData = schedules.map(schedule => ({
        date: schedule.date.toISOString().split('T')[0],
        activities: schedule.activities,
        lastUpdated: schedule.lastUpdated
      }));

      reply.send({
        success: true,
        data: scheduleData
      });
    } catch (error) {
      reply.status(500).send({
        success: false,
        error: error instanceof Error ? error.message : 'Failed to fetch schedule history'
      });
    }
  });

  fastify.get('/schedule/upcoming/:courseId', async (
    request: FastifyRequest<{
      Params: { courseId: string };
    }>,
    reply: FastifyReply
  ) => {
    try {
      const { courseId } = request.params;
      const { userId, cookies } = await authenticate(request);

      const scheduleData = await scraperService.scrapeSchedule(
        cookies,
        'upcoming',
        courseId
      );

      reply.send({
        success: true,
        data: scheduleData,
        courseId
      });
    } catch (error) {
      reply.status(500).send({
        success: false,
        error: error instanceof Error ? error.message : 'Failed to fetch upcoming events'
      });
    }
  });

  fastify.delete('/schedule/cache', async (request: FastifyRequest, reply: FastifyReply) => {
    try {
      const { userId } = await authenticate(request);

      await Schedule.deleteMany({ userId });

      reply.send({
        success: true,
        message: 'Schedule cache cleared'
      });
    } catch (error) {
      reply.status(500).send({
        success: false,
        error: error instanceof Error ? error.message : 'Failed to clear cache'
      });
    }
  });
}
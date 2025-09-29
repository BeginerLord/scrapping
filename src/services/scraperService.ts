import axios from 'axios';
import * as cheerio from 'cheerio';
import { Activity, ScheduleData } from '../types/auth';

export interface CourseInfo {
  id: string;
  name: string;
  shortname: string;
}

export interface CalendarEvent {
  id: string;
  name: string;
  description?: string;
  timestart: number;
  timeduration: number;
  course?: {
    id: string;
    fullname: string;
    shortname: string;
  };
  location?: string;
  eventtype: string;
  url?: string;
  activityDates?: {
    apertura?: string;
    cierre?: string;
  };
}

export class ScraperService {
  private baseUrl: string;

  constructor() {
    this.baseUrl = process.env.SIMA_BASE_URL || 'https://sima.unicartagena.edu.co';
  }

  async getSessionKey(cookies: string[]): Promise<string> {
    try {
      const cookieHeader = this.parseCookies(cookies);

      const response = await axios.get(`${this.baseUrl}/calendar/view.php`, {
        headers: {
          'Cookie': cookieHeader,
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36'
        }
      });

      const $ = cheerio.load(response.data);
      const sesskey = $('input[name="sesskey"]').attr('value') ||
                      $('[data-sesskey]').attr('data-sesskey') ||
                      response.data.match(/sesskey["\']?\s*[:=]\s*["\']?([^"',\s]+)/i)?.[1];

      if (!sesskey) {
        throw new Error('Session key not found');
      }

      return sesskey;
    } catch (error) {
      throw new Error(`Failed to get session key: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  async getUserCourses(cookies: string[]): Promise<CourseInfo[]> {
    try {
      const cookieHeader = this.parseCookies(cookies);
      console.log('🍪 Attempting to fetch courses with cookies:', cookieHeader.substring(0, 100) + '...');

      // Try different URLs to find one that works
      const testUrls = [
        `${this.baseUrl}/course/index.php`,  // Common Moodle courses page
        `${this.baseUrl}/my/courses.php`,    // Alternative courses page
        `${this.baseUrl}/`,                  // Homepage
        `${this.baseUrl}/my/`                // Original (might work now)
      ];

      let response;
      let workingUrl = null;

      for (const testUrl of testUrls) {
        try {
          console.log(`🧪 Testing URL: ${testUrl}`);
          response = await axios.get(testUrl, {
            headers: {
              'Cookie': cookieHeader,
              'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            },
            maxRedirects: 15,
            validateStatus: (status) => status < 400
          });

          console.log(`📄 ${testUrl} → ${response.request?.res?.responseUrl || response.config.url}`);
          console.log(`📊 Status: ${response.status}`);

          // Check if this URL redirects to login page
          const finalUrl = response.request?.res?.responseUrl || response.config.url;
          const isRedirectedToLogin = finalUrl?.includes('/login/');

          // Check for login form in the response (more specific than just "login" text)
          const hasUsernameField = response.data?.includes('name="username"') || response.data?.includes('id="username"');
          const hasPasswordField = response.data?.includes('name="password"') || response.data?.includes('id="password"');
          const hasLoginForm = hasUsernameField && hasPasswordField;

          console.log(`🔍 ${testUrl} analysis:`, {
            finalUrl: finalUrl?.substring(finalUrl.length - 50),
            redirectedToLogin: isRedirectedToLogin,
            hasLoginForm: hasLoginForm,
            status: response.status
          });

          if (!isRedirectedToLogin && !hasLoginForm) {
            console.log(`✅ Found working URL: ${testUrl}`);
            workingUrl = testUrl;
            break;
          } else {
            console.log(`❌ ${testUrl} requires authentication`);
          }
        } catch (error) {
          console.log(`❌ ${testUrl} failed:`, error.message);
        }
      }

      if (!workingUrl) {
        throw new Error('No working URL found - all URLs redirect to login');
      }

      console.log('✅ Using working URL:', workingUrl);
      console.log('📄 Final Response URL:', response.request?.res?.responseUrl || response.config.url);
      console.log('📊 Final Response status:', response.status);

      const $ = cheerio.load(response.data);
      const courses: CourseInfo[] = [];

      $('.course-info-container, .coursebox, [data-course-id]').each((index, element) => {
        const $course = $(element);
        const courseId = $course.attr('data-course-id') ||
                        $course.find('[data-course-id]').attr('data-course-id') ||
                        $course.find('a[href*="/course/"]').attr('href')?.match(/course\/view\.php\?id=(\d+)/)?.[1];

        const courseName = $course.find('.coursename, .course-title, h3').first().text().trim() ||
                          $course.find('a[href*="/course/"]').text().trim();

        const shortName = $course.find('.course-shortname, .shortname').text().trim() ||
                         courseName.split(' ')[0];

        if (courseId && courseName) {
          courses.push({
            id: courseId,
            name: courseName,
            shortname: shortName
          });
        }
      });

      if (courses.length === 0) {
        $('a[href*="/course/view.php"]').each((index, element) => {
          const $link = $(element);
          const href = $link.attr('href') || '';
          const courseId = href.match(/id=(\d+)/)?.[1];
          const courseName = $link.text().trim();

          if (courseId && courseName && courseName.length > 3) {
            courses.push({
              id: courseId,
              name: courseName,
              shortname: courseName.split(' ')[0]
            });
          }
        });
      }

      return courses;
    } catch (error) {
      console.log('❌ Error in getUserCourses:', error);
      if (axios.isAxiosError(error)) {
        console.log('📍 Axios error details:', {
          message: error.message,
          status: error.response?.status,
          url: error.config?.url,
          redirectCount: error.config?.maxRedirects
        });

        if (error.message.includes('redirect')) {
          throw new Error(`Maximum number of redirects exceeded - session may be invalid`);
        }
      }
      throw new Error(`Failed to get user courses: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  async getCalendarEvents(
    cookies: string[],
    view: 'day' | 'month' | 'upcoming' = 'month',
    courseId?: string,
    date?: string
  ): Promise<CalendarEvent[]> {
    try {
      const cookieHeader = this.parseCookies(cookies);

      if (view === 'upcoming' && courseId) {
        return this.getUpcomingEvents(cookies, courseId);
      }

      let url = `${this.baseUrl}/calendar/view.php?view=${view}&course=${courseId || 1}`;

      if (date && view !== 'upcoming') {
        const timestamp = new Date(date).getTime() / 1000;
        url += `&time=${timestamp}`;
      }

      const response = await axios.get(url, {
        headers: {
          'Cookie': cookieHeader,
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
          'Accept-Language': 'es-419,es;q=0.9'
        }
      });

      return this.parseCalendarHTML(response.data, view);
    } catch (error) {
      throw new Error(`Failed to get calendar events: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  async getUpcomingEvents(cookies: string[], courseId: string): Promise<CalendarEvent[]> {
    try {
      const cookieHeader = this.parseCookies(cookies);
      const sesskey = await this.getSessionKey(cookies);

      const payload = [{
        index: 0,
        methodname: "core_calendar_get_calendar_upcoming_view",
        args: {
          courseid: courseId
        }
      }];

      const response = await axios.post(
        `${this.baseUrl}/lib/ajax/service.php?sesskey=${sesskey}&info=core_calendar_get_calendar_upcoming_view`,
        payload,
        {
          headers: {
            'Accept': 'application/json, text/javascript, */*; q=0.01',
            'Accept-Language': 'es-419,es;q=0.9',
            'Content-Type': 'application/json',
            'Cookie': cookieHeader,
            'Origin': this.baseUrl,
            'Referer': `${this.baseUrl}/calendar/view.php?view=upcoming&course=${courseId}`,
            'Sec-CH-UA': '"Chromium";v="140", "Not=A?Brand";v="24", "Brave";v="140"',
            'Sec-CH-UA-Mobile': '?0',
            'Sec-CH-UA-Platform': '"Windows"',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'Sec-GPC': '1',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36',
            'X-Requested-With': 'XMLHttpRequest'
          }
        }
      );

      if (response.data && Array.isArray(response.data) && response.data[0]?.data) {
        return this.parseUpcomingEventsResponse(response.data[0].data);
      }

      return [];
    } catch (error) {
      console.error('Error getting upcoming events:', error);
      return [];
    }
  }

  private parseUpcomingEventsResponse(data: any): CalendarEvent[] {
    const events: CalendarEvent[] = [];

    try {
      if (data.events && Array.isArray(data.events)) {
        for (const event of data.events) {
          events.push({
            id: event.id?.toString() || '',
            name: event.name || '',
            description: event.description || '',
            timestart: parseInt(event.timestart) || 0,
            timeduration: parseInt(event.timeduration) || 0,
            course: event.course ? {
              id: event.course.id?.toString() || '',
              fullname: event.course.fullname || '',
              shortname: event.course.shortname || ''
            } : undefined,
            location: event.location || '',
            eventtype: event.eventtype || 'activity',
            url: event.url || ''
          });
        }
      }
    } catch (error) {
      console.error('Error parsing upcoming events response:', error);
    }

    return events;
  }

  private parseCalendarHTML(html: string, view: string): CalendarEvent[] {
    const $ = cheerio.load(html);
    const events: CalendarEvent[] = [];

    $('.calendar-event, .event, [data-event-id], [data-region="event-item"]').each((index, element) => {
      const $event = $(element);

      const eventId = $event.attr('data-event-id') ||
                     $event.attr('data-event') ||
                     $event.find('[data-event-id]').attr('data-event-id') ||
                     `event-${index}`;

      const name = $event.find('.event-name, .eventname, .event-title, h3, .title').first().text().trim() ||
                   $event.attr('title') ||
                   $event.text().trim().split('\n')[0];

      if (!name) return;

      const description = $event.find('.event-description, .description, .eventdescription, .content').text().trim();
      const location = $event.find('.event-location, .location, .eventlocation').text().trim();

      const timeText = $event.find('.event-time, .time, .eventtime, [data-time]').text().trim();
      const timestart = this.parseTimeToTimestamp(timeText) || 0;

      const eventType = this.determineEventType($event, name);

      // Extract activity URL from various possible sources
      let activityUrl = $event.find('a').attr('href') ||
                       $event.attr('href') ||
                       $event.find('[href*="/mod/"]').attr('href') ||
                       $event.find('[href*="view.php"]').attr('href');

      // Make URL absolute if it's relative
      if (activityUrl && !activityUrl.startsWith('http')) {
        activityUrl = activityUrl.startsWith('/') ?
          `${this.baseUrl}${activityUrl}` :
          `${this.baseUrl}/${activityUrl}`;
      }

      events.push({
        id: eventId,
        name,
        description: description || undefined,
        timestart,
        timeduration: 0,
        location: location || undefined,
        eventtype: eventType,
        url: activityUrl
      });
    });

    return events;
  }

  private parseTimeToTimestamp(timeText: string): number {
    try {
      if (!timeText) return 0;

      const timeMatch = timeText.match(/(\d{1,2}):(\d{2})/);
      if (timeMatch) {
        const today = new Date();
        today.setHours(parseInt(timeMatch[1]), parseInt(timeMatch[2]), 0, 0);
        return Math.floor(today.getTime() / 1000);
      }

      return 0;
    } catch (error) {
      return 0;
    }
  }

  async enhanceEventsWithActivityDates(cookies: string[], events: CalendarEvent[]): Promise<CalendarEvent[]> {
    const enhancedEvents: CalendarEvent[] = [];

    for (const event of events) {
      const enhancedEvent = { ...event };

      // Only fetch activity dates for activities that have URLs and are assignments/tasks
      if (event.url && (event.eventtype === 'assignment' || event.name.toLowerCase().includes('evaluación'))) {
        try {
          const activityDates = await this.getActivityDates(cookies, event.url);
          if (activityDates.apertura || activityDates.cierre) {
            enhancedEvent.activityDates = activityDates;
          }
        } catch (error) {
          console.error(`Failed to get activity dates for ${event.name}:`, error);
        }
      }

      enhancedEvents.push(enhancedEvent);
    }

    return enhancedEvents;
  }

  async scrapeSchedule(
    cookies: string[],
    period: 'day' | 'week' | 'month' | 'upcoming',
    courseId?: string,
    date?: string
  ): Promise<ScheduleData[]> {
    try {
      const view = period === 'week' ? 'month' : period;
      let events = await this.getCalendarEvents(cookies, view as any, courseId, date);

      // Enhance events with detailed activity dates
      events = await this.enhanceEventsWithActivityDates(cookies, events);

      const scheduleData: ScheduleData[] = [];
      const eventsGroupedByDate = new Map<string, Activity[]>();

      for (const event of events) {
        const eventDate = new Date(event.timestart * 1000);
        const dateKey = eventDate.toISOString().split('T')[0];

        if (!eventsGroupedByDate.has(dateKey)) {
          eventsGroupedByDate.set(dateKey, []);
        }

        const activity: Activity = {
          id: event.id,
          title: event.name,
          startTime: eventDate.toLocaleTimeString('es-ES', {
            hour: '2-digit',
            minute: '2-digit'
          }),
          endTime: event.timeduration > 0 ?
            new Date((event.timestart + event.timeduration) * 1000).toLocaleTimeString('es-ES', {
              hour: '2-digit',
              minute: '2-digit'
            }) : '',
          description: event.description,
          location: event.location,
          type: event.eventtype,
          activityDates: event.activityDates
        };

        eventsGroupedByDate.get(dateKey)!.push(activity);
      }

      for (const [date, activities] of eventsGroupedByDate.entries()) {
        scheduleData.push({
          date,
          activities: activities.sort((a, b) => a.startTime.localeCompare(b.startTime))
        });
      }

      return scheduleData.sort((a, b) => a.date.localeCompare(b.date));
    } catch (error) {
      throw new Error(`Failed to scrape schedule: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  private parseCookies(cookies: string[]): string {
    const cookieMap = new Map<string, string>();

    for (const cookie of cookies) {
      const cookiePart = cookie.split(';')[0];
      const [name, value] = cookiePart.split('=');
      if (name && value) {
        // Keep the latest value for each cookie name
        cookieMap.set(name.trim(), value.trim());
      }
    }

    return Array.from(cookieMap.entries())
      .map(([name, value]) => `${name}=${value}`)
      .join('; ');
  }

  async getActivityDates(cookies: string[], activityUrl: string): Promise<{ apertura?: string; cierre?: string }> {
    try {
      const cookieHeader = this.parseCookies(cookies);

      const response = await axios.get(activityUrl, {
        headers: {
          'Cookie': cookieHeader,
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36',
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
          'Accept-Language': 'es-419,es;q=0.5',
          'Cache-Control': 'max-age=0',
          'Sec-CH-UA': '"Chromium";v="140", "Not=A?Brand";v="24", "Brave";v="140"',
          'Sec-CH-UA-Mobile': '?0',
          'Sec-CH-UA-Platform': '"Windows"',
          'Sec-Fetch-Dest': 'document',
          'Sec-Fetch-Mode': 'navigate',
          'Sec-Fetch-Site': 'same-origin',
          'Sec-Fetch-User': '?1',
          'Sec-GPC': '1',
          'Upgrade-Insecure-Requests': '1'
        }
      });

      const $ = cheerio.load(response.data);
      const activityDates: { apertura?: string; cierre?: string } = {};

      // Look for the activity-dates section
      const activityDatesDiv = $('[data-region="activity-dates"]');

      if (activityDatesDiv.length > 0) {
        // Extract apertura date
        const aperturaDiv = activityDatesDiv.find('div').filter((i, el) => {
          return $(el).find('strong').text().trim() === 'Apertura:';
        });

        if (aperturaDiv.length > 0) {
          const aperturaText = aperturaDiv.text().replace('Apertura:', '').trim();
          activityDates.apertura = aperturaText;
        }

        // Extract cierre date
        const cierreDiv = activityDatesDiv.find('div').filter((i, el) => {
          return $(el).find('strong').text().trim() === 'Cierre:';
        });

        if (cierreDiv.length > 0) {
          const cierreText = cierreDiv.text().replace('Cierre:', '').trim();
          activityDates.cierre = cierreText;
        }
      }

      return activityDates;
    } catch (error) {
      console.error(`Error extracting activity dates from ${activityUrl}:`, error);
      return {};
    }
  }

  private determineEventType($event: cheerio.Cheerio<cheerio.Element>, title: string): string {
    const classNames = $event.attr('class') || '';
    const titleLower = title.toLowerCase();

    if (classNames.includes('assignment') || titleLower.includes('tarea') || titleLower.includes('assignment')) {
      return 'assignment';
    }
    if (classNames.includes('quiz') || titleLower.includes('examen') || titleLower.includes('quiz')) {
      return 'quiz';
    }
    if (classNames.includes('forum') || titleLower.includes('foro') || titleLower.includes('forum')) {
      return 'forum';
    }
    if (classNames.includes('lesson') || titleLower.includes('lección') || titleLower.includes('clase')) {
      return 'lesson';
    }

    return 'activity';
  }
}
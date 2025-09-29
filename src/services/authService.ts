import axios, { AxiosResponse } from 'axios';
import * as cheerio from 'cheerio';
import { LoginCredentials, SimaLoginResponse, UserSession } from '../types/auth';

export class AuthService {
  private baseUrl: string;

  constructor() {
    this.baseUrl = process.env.SIMA_BASE_URL || 'https://sima.unicartagena.edu.co';
  }

  async getLoginToken(): Promise<{ token: string; cookies: string[] }> {
    try {
      const response: AxiosResponse = await axios.get(`${this.baseUrl}/login/index.php`, {
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36'
        }
      });

      const $ = cheerio.load(response.data);
      const loginToken = $('input[name="logintoken"]').attr('value');

      if (!loginToken) {
        throw new Error('Login token not found');
      }

      const cookies = response.headers['set-cookie'] || [];

      return {
        token: loginToken,
        cookies: cookies
      };
    } catch (error) {
      throw new Error(`Failed to get login token: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  async login(credentials: LoginCredentials): Promise<SimaLoginResponse> {
    try {
      console.log('🔐 Attempting SIMA login for user:', credentials.username);
      const { token: loginToken, cookies: initialCookies } = await this.getLoginToken();

      const cookieHeader = this.parseCookies(initialCookies);

      const loginData = new URLSearchParams({
        logintoken: loginToken,
        username: credentials.username,
        password: credentials.password
      });

      const response: AxiosResponse = await axios.post(
        `${this.baseUrl}/login/index.php`,
        loginData,
        {
          headers: {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
            'Accept-Language': 'es-419,es;q=0.9',
            'Cache-Control': 'max-age=0',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Cookie': cookieHeader,
            'Origin': this.baseUrl,
            'Referer': `${this.baseUrl}/login/index.php`,
            'Sec-CH-UA': '"Chromium";v="140", "Not=A?Brand";v="24", "Brave";v="140"',
            'Sec-CH-UA-Mobile': '?0',
            'Sec-CH-UA-Platform': '"Windows"',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'same-origin',
            'Sec-Fetch-User': '?1',
            'Sec-GPC': '1',
            'Upgrade-Insecure-Requests': '1',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36'
          },
          maxRedirects: 0,
          validateStatus: (status) => status < 400
        }
      );

      const responseCookies = response.headers['set-cookie'] || [];
      const allCookies = [...initialCookies, ...responseCookies];

      console.log('🔐 Login response status:', response.status);
      console.log('🔐 Login response headers location:', response.headers['location']);

      if (response.status === 302 || response.status === 303) {
        const redirectLocation = response.headers['location'];
        console.log('🔄 Login redirect to:', redirectLocation);

        // Check if redirected to testsession (this is normal for SIMA)
        if (redirectLocation && redirectLocation.includes('testsession=')) {
          console.log('🔄 Following testsession redirect...');

          // Follow the testsession redirect with manual redirect handling
          let testSessionResponse = await axios.get(redirectLocation, {
            headers: {
              'Cookie': this.parseCookies(allCookies),
              'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36',
              'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
              'Accept-Language': 'es-419,es;q=0.5',
              'Referer': `${this.baseUrl}/login/index.php`
            },
            maxRedirects: 0, // Handle redirects manually to capture all cookies
            validateStatus: (status) => status < 400 || status === 302 || status === 303
          });

          console.log('🔄 TestSession initial response:', {
            status: testSessionResponse.status,
            location: testSessionResponse.headers['location'],
            cookies: testSessionResponse.headers['set-cookie']?.length || 0
          });

          // If TestSession redirects automatically, follow it
          if (testSessionResponse.status === 302 || testSessionResponse.status === 303) {
            const finalRedirect = testSessionResponse.headers['location'];
            if (finalRedirect && !finalRedirect.includes('testsession=')) {
              console.log('🎯 TestSession auto-redirecting to dashboard:', finalRedirect);

              const testSessionCookies = testSessionResponse.headers['set-cookie'] || [];
              const updatedCookies = [...allCookies, ...testSessionCookies];

              // Follow the final redirect to the dashboard
              const dashboardResponse = await axios.get(finalRedirect, {
                headers: {
                  'Cookie': this.parseCookies(updatedCookies),
                  'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36',
                  'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
                  'Accept-Language': 'es-419,es;q=0.5',
                  'Referer': redirectLocation
                },
                maxRedirects: 5,
                validateStatus: (status) => status < 400
              });

              const dashboardCookies = dashboardResponse.headers['set-cookie'] || [];
              const completeCookies = [...updatedCookies, ...dashboardCookies];

              console.log('🎯 Dashboard response:', {
                status: dashboardResponse.status,
                url: dashboardResponse.request?.res?.responseUrl || dashboardResponse.config.url,
                cookies: dashboardCookies.length
              });

              return {
                success: true,
                cookies: completeCookies,
                sessionData: {
                  loginToken,
                  redirectUrl: dashboardResponse.request?.res?.responseUrl || dashboardResponse.config.url
                }
              };
            }
          }

          const testSessionCookies = testSessionResponse.headers['set-cookie'] || [];
          const finalCookies = [...allCookies, ...testSessionCookies];

          console.log('✅ TestSession completed, final cookies received');
          console.log('🔗 TestSession final URL:', testSessionResponse.request?.res?.responseUrl || testSessionResponse.config.url);
          console.log('📊 TestSession final status:', testSessionResponse.status);
          console.log('🍪 TestSession final cookies count:', testSessionCookies.length);

          // Check if TestSession redirects us to the dashboard
          const testSessionFinalUrl = testSessionResponse.request?.res?.responseUrl || testSessionResponse.config.url;

          // If we're still at testsession URL, we need to get the final redirect to dashboard
          if (testSessionFinalUrl?.includes('testsession=')) {
            console.log('🔄 TestSession still at testsession URL, checking for dashboard redirect...');

            // Try to access the dashboard directly to get the MoodleSession cookie
            try {
              const dashboardResponse = await axios.get(`${this.baseUrl}/my/`, {
                headers: {
                  'Cookie': this.parseCookies(finalCookies),
                  'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36',
                  'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
                  'Accept-Language': 'es-419,es;q=0.5',
                  'Referer': testSessionFinalUrl
                },
                maxRedirects: 15,
                validateStatus: (status) => status < 400 || status === 302 || status === 303
              });

              const dashboardCookies = dashboardResponse.headers['set-cookie'] || [];
              const completeCookies = [...finalCookies, ...dashboardCookies];

              console.log('🎯 Dashboard access attempt:');
              console.log('🔗 Dashboard final URL:', dashboardResponse.request?.res?.responseUrl || dashboardResponse.config.url);
              console.log('📊 Dashboard final status:', dashboardResponse.status);
              console.log('🍪 Dashboard cookies count:', dashboardCookies.length);
              console.log('🍪 Dashboard cookies:', dashboardCookies.slice(0, 3));

              // Check if we got MoodleSession or similar authentication cookies
              const hasMoodleSession = completeCookies.some(cookie =>
                cookie.toLowerCase().includes('moodlesession') ||
                cookie.toLowerCase().includes('sesskey')
              );

              console.log('🔑 Got MoodleSession-like cookies:', hasMoodleSession);

              return {
                success: true,
                cookies: completeCookies,
                sessionData: {
                  loginToken,
                  redirectUrl: dashboardResponse.request?.res?.responseUrl || dashboardResponse.config.url
                }
              };
            } catch (dashboardError) {
              console.log('❌ Dashboard access failed:', dashboardError.message);
              // Fall back to the TestSession cookies
            }
          }

          return {
            success: true,
            cookies: finalCookies,
            sessionData: {
              loginToken,
              redirectUrl: testSessionFinalUrl
            }
          };
        } else if (redirectLocation && !redirectLocation.includes('/login/')) {
          console.log('✅ Login successful - redirected to:', redirectLocation);
          return {
            success: true,
            cookies: allCookies,
            sessionData: {
              loginToken,
              redirectUrl: redirectLocation
            }
          };
        } else {
          console.log('❌ Login failed - redirected back to login');
        }
      }

      const $ = cheerio.load(response.data);
      const errorMessage = $('.alert-danger, .error').text().trim();

      if (errorMessage) {
        return {
          success: false,
          error: errorMessage
        };
      }

      const isLoggedIn = !$('input[name="username"]').length;

      if (isLoggedIn) {
        return {
          success: true,
          cookies: allCookies,
          sessionData: {
            loginToken
          }
        };
      }

      return {
        success: false,
        error: 'Authentication failed - invalid credentials'
      };

    } catch (error) {
      if (axios.isAxiosError(error) && error.response?.status === 302) {
        const responseCookies = error.response.headers['set-cookie'] || [];
        const redirectLocation = error.response.headers['location'];

        if (redirectLocation && !redirectLocation.includes('/login/')) {
          return {
            success: true,
            cookies: responseCookies,
            sessionData: {
              redirectUrl: redirectLocation
            }
          };
        }
      }

      return {
        success: false,
        error: `Login failed: ${error instanceof Error ? error.message : 'Unknown error'}`
      };
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

  async validateSession(cookies: string[]): Promise<boolean> {
    try {
      console.log('🔍 Validating session with cookies:', this.parseCookies(cookies).substring(0, 100) + '...');

      const response = await axios.get(`${this.baseUrl}/my/`, {
        headers: {
          'Cookie': this.parseCookies(cookies),
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36'
        },
        maxRedirects: 15,
        validateStatus: (status) => status < 400 || status === 302 || status === 303
      });

      console.log('📥 ValidateSession - got response successfully');

      console.log('✅ Session validation - URL:', response.request?.res?.responseUrl || response.config.url);
      console.log('✅ Session validation - Status:', response.status);
      console.log('📄 Session validation - Response contains form?', response.data?.includes('<form'));
      console.log('📄 Session validation - Response contains username field?', response.data?.includes('username'));
      console.log('📄 Session validation - Response contains MoodleSession?', response.data?.includes('MoodleSession'));

      const isRedirectedToLogin = response.request?.res?.responseUrl?.includes('/login');
      const hasLoginForm = response.data?.includes('<form') && response.data?.includes('username');
      const hasMoodleSession = response.data?.includes('MoodleSession');

      console.log('🔍 Validation checks:', {
        isRedirectedToLogin,
        hasLoginForm,
        hasMoodleSession
      });

      if (isRedirectedToLogin || hasMoodleSession || hasLoginForm) {
        console.log('❌ Session invalid - needs re-authentication');
        return false;
      }

      console.log('✅ Session is valid');
      return true;
    } catch (error) {
      console.log('❌ ValidateSession error:', error);
      if (axios.isAxiosError(error)) {
        console.log('📍 Axios validateSession error details:', {
          message: error.message,
          status: error.response?.status,
          url: error.config?.url
        });

        if (error.response?.status === 302 || error.response?.status === 303) {
          const location = error.response.headers['location'];
          console.log('🔄 ValidateSession redirect to:', location);
          const isValid = !location?.includes('/login/');
          console.log('✅ ValidateSession redirect validation result:', isValid);
          return isValid;
        }
      }
      console.log('❌ ValidateSession failed, returning false');
      return false;
    }
  }
}
export interface LoginCredentials {
  username: string;
  password: string;
}

export interface SimaLoginResponse {
  success: boolean;
  cookies?: string[];
  sessionData?: any;
  error?: string;
}

export interface UserSession {
  userId: string;
  username: string;
  cookies: string[];
  loginToken?: string;
  expiresAt: Date;
}

export interface ScheduleData {
  date: string;
  activities: Activity[];
}

export interface Activity {
  id: string;
  title: string;
  startTime: string;
  endTime: string;
  description?: string;
  location?: string;
  type: string;
  activityDates?: {
    apertura?: string;
    cierre?: string;
  };
}
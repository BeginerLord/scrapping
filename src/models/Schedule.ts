import mongoose, { Document, Schema } from 'mongoose';

export interface IActivity {
  id: string;
  title: string;
  startTime: string;
  endTime: string;
  description?: string;
  location?: string;
  type: string;
}

export interface ISchedule extends Document {
  userId: mongoose.Types.ObjectId;
  courseId?: string;
  date: Date;
  activities: IActivity[];
  lastUpdated: Date;
  createdAt: Date;
}

const ActivitySchema: Schema = new Schema({
  id: {
    type: String,
    required: true
  },
  title: {
    type: String,
    required: true
  },
  startTime: {
    type: String,
    required: true
  },
  endTime: {
    type: String,
    required: true
  },
  description: String,
  location: String,
  type: {
    type: String,
    required: true
  }
}, { _id: false });

const ScheduleSchema: Schema = new Schema({
  userId: {
    type: Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  courseId: {
    type: String,
    required: false
  },
  date: {
    type: Date,
    required: true
  },
  activities: [ActivitySchema],
  lastUpdated: {
    type: Date,
    default: Date.now
  }
}, {
  timestamps: true
});

ScheduleSchema.index({ userId: 1, courseId: 1, date: 1 }, { unique: true });

export const Schedule = mongoose.model<ISchedule>('Schedule', ScheduleSchema);
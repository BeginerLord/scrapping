import mongoose, { Document, Schema } from 'mongoose';

export interface ICourse extends Document {
  userId: mongoose.Types.ObjectId;
  courseId: string;
  name: string;
  shortname: string;
  isActive: boolean;
  lastSyncAt: Date;
  createdAt: Date;
  updatedAt: Date;
}

const CourseSchema: Schema = new Schema({
  userId: {
    type: Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  courseId: {
    type: String,
    required: true
  },
  name: {
    type: String,
    required: true
  },
  shortname: {
    type: String,
    required: true
  },
  isActive: {
    type: Boolean,
    default: true
  },
  lastSyncAt: {
    type: Date,
    default: Date.now
  }
}, {
  timestamps: true
});

CourseSchema.index({ userId: 1, courseId: 1 }, { unique: true });
CourseSchema.index({ userId: 1, isActive: 1 });

export const Course = mongoose.model<ICourse>('Course', CourseSchema);
import mongoose, { Document, Schema } from 'mongoose';

export interface IUser extends Document {
  username: string;
  passwordHash: string;
  simaCredentials: {
    username: string;
    encryptedPassword: string;
  };
  sessions: {
    cookies: string[];
    loginToken?: string;
    expiresAt: Date;
    isActive: boolean;
  }[];
  createdAt: Date;
  updatedAt: Date;
}

const UserSchema: Schema = new Schema({
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true
  },
  passwordHash: {
    type: String,
    required: true
  },
  simaCredentials: {
    username: {
      type: String,
      required: true
    },
    encryptedPassword: {
      type: String,
      required: true
    }
  },
  sessions: [{
    cookies: [String],
    loginToken: String,
    expiresAt: {
      type: Date,
      required: true
    },
    isActive: {
      type: Boolean,
      default: true
    }
  }]
}, {
  timestamps: true
});

UserSchema.index({ 'sessions.expiresAt': 1 }, { expireAfterSeconds: 0 });

export const User = mongoose.model<IUser>('User', UserSchema);
// Clear users collection to allow fresh registration with new encryption
const { MongoClient } = require('mongodb');
require('dotenv').config();

async function clearUsers() {
  const client = new MongoClient(process.env.MONGODB_URI || 'mongodb://localhost:27017/sima-scraper');

  try {
    await client.connect();
    const db = client.db();

    const result = await db.collection('users').deleteMany({});
    console.log(`Deleted ${result.deletedCount} users from database`);
    console.log('You can now register with the new encryption system');

  } catch (error) {
    console.error('Error clearing users:', error);
  } finally {
    await client.close();
  }
}

clearUsers();
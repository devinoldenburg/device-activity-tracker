import { execSync } from 'child_process';
import os from 'os';
import path from 'path';

const CONTAINER_NAME = 'signal-api';
const IMAGE_NAME = 'bbernhard/signal-cli-rest-api';
const DEFAULT_PORT = 8080;
const FALLBACK_PORT = 8082;

// Cross-platform path to local share
const hostVolPath = path.join(os.homedir(), '.local', 'share', 'signal-api');
const containerVolPath = '/home/.local/share/signal-cli';

try {
  // 1. First, check if Docker is actually running
  try {
    execSync('docker info', { stdio: 'ignore' });
  } catch (e) {
    console.error('⚠️  Docker is not running.');
    console.error('   Please start Docker Desktop and try again.');
    process.exit(1);
  }

  // 2. If container exists, start it. If it's bound to an occupied port, recreate on fallback.
  try {
    execSync(`docker inspect ${CONTAINER_NAME}`, { stdio: 'ignore' });
    console.log(`✅ Container '${CONTAINER_NAME}' found. Starting...`);
    try {
      execSync(`docker start ${CONTAINER_NAME}`, { stdio: 'inherit' });
      process.exit(0);
    } catch (startErr) {
      console.log('⚠️  Existing container failed to start, removing and recreating...');
      execSync(`docker rm -f ${CONTAINER_NAME}`, { stdio: 'inherit' });
      // fall through to create
    }
  } catch (e) {
    // 3. If inspect fails, container doesn't exist. Create it.
    console.log(`🆕 Container '${CONTAINER_NAME}' not found. Creating...`);
  }

  // Try to run on default port, otherwise fallback.
  const runWithPort = (port: number) => {
    const cmd = `docker run -d --name ${CONTAINER_NAME} -p ${port}:${DEFAULT_PORT} -v "${hostVolPath}:${containerVolPath}" -e MODE=json-rpc ${IMAGE_NAME}`;
    execSync(cmd, { stdio: 'inherit' });
    console.log(`✅ Signal API running on port ${port}`);
    console.log(`   Set SIGNAL_API_URL=http://localhost:${port}`);
  };

  try {
    runWithPort(DEFAULT_PORT);
  } catch (err) {
    console.log(`⚠️  Port ${DEFAULT_PORT} busy, retrying on ${FALLBACK_PORT}...`);
    try {
      runWithPort(FALLBACK_PORT);
      process.exit(0);
    } catch (err2) {
      console.error('❌ Failed to start Signal API on both ports.');
      throw err2;
    }
  }
} catch (error) {
  // Catch any other unexpected errors
  console.error('❌ Failed to initialize Signal API container:', error);
  process.exit(1);
}

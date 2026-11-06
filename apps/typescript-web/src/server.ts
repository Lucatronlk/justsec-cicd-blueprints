import { createApp } from './app';

const port = Number(process.env.PORT ?? '3000');
if (!Number.isInteger(port) || port < 1 || port > 65535) {
  console.error('PORT must be an integer from 1 to 65535');
  process.exit(1);
}

const host = process.env.HOST ?? '127.0.0.1';
const server = createApp();
server.listen(port, host, () => {
  console.info(JSON.stringify({ event: 'listening', host, port }));
});
server.on('error', (error: Error) => {
  console.error(JSON.stringify({ event: 'server_error', code: 'listen_failed', message: error.message }));
  process.exitCode = 1;
});

import { createCloudApp } from "./app";

const port = Number(process.env.API_PORT || 3001);
const app = createCloudApp();

console.log(`Chainmark Cloud Hono API listening on http://0.0.0.0:${port}`);

export default {
  port,
  fetch: app.fetch,
};

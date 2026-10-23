import type { Config } from '@netlify/functions'

export default async () => {
  return Response.json({
    status: 'ok',
    service: 'scamshield-api',
    timestamp: new Date().toISOString(),
  })
}

export const config: Config = {
  path: '/api/health',
}

export default async () => {
  return Response.json({
    status: 'ok',
    service: 'scamshield-api',
    timestamp: new Date().toISOString(),
  })
}

export const config = {
  path: '/api/health',
}

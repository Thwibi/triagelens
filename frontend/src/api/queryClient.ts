import { QueryClient } from '@tanstack/react-query'

/**
 * Build the app's query client.
 *
 * `refetchOnWindowFocus` is off because a local single-user app has no other
 * writer competing for the data, and the WebSocket already pushes the changes
 * that matter. A single retry covers a transient blip without turning a real
 * "backend is down" into a long spinner.
 */
export function createQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: {
        retry: 1,
        staleTime: 5_000,
        refetchOnWindowFocus: false,
      },
      mutations: {
        retry: 0,
      },
    },
  })
}

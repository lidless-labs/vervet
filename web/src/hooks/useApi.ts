/**
 * React Query hooks for all Vervet data types.
 * Automatically falls back to mock data when backend is unavailable.
 */
import { useQuery, type UseQueryOptions } from '@tanstack/react-query';
import { api, isBackendAvailable, ApiError } from '../api/client';
import {
  mockAlerts,
  mockBeacons,
  mockDnsThreats,
  mockTimeline,
  mockSeverityDistribution,
  mockDashboardStats,
  mockIndicators,
  mockMitreMappings,
} from '../data/mockData';
import type {
  ThreatScore,
  ThreatIndicator,
  MitreMapping,
  BeaconResult,
  DnsThreatResult,
  ThreatTimelinePoint,
  ThreatSeverityDistribution,
  DashboardStats,
  ThreatsResponse,
  IndicatorsResponse,
  MitreResponse,
  ApiResponse,
  LogStats,
} from '../types';

// ============================================================================
// Backend availability tracking
// ============================================================================

let _backendAvailable: boolean | null = null;
let _lastCheck = 0;
const CHECK_INTERVAL = 30_000; // Re-check every 30s

async function checkBackend(): Promise<boolean> {
  const now = Date.now();
  if (_backendAvailable !== null && now - _lastCheck < CHECK_INTERVAL) {
    return _backendAvailable;
  }
  _backendAvailable = await isBackendAvailable();
  _lastCheck = now;
  return _backendAvailable;
}

/**
 * Attempt an API call; return mock data on failure.
 */
async function fetchOrMock<T>(
  fetcher: () => Promise<T>,
  fallback: T,
): Promise<T> {
  const available = await checkBackend();
  if (!available) return fallback;

  try {
    return await fetcher();
  } catch (err) {
    // On network errors or 5xx, fall back to mock data
    if (err instanceof ApiError && err.status < 500) {
      throw err; // 4xx errors are real errors, re-throw
    }
    console.warn('[useApi] Backend unavailable, using mock data:', err);
    _backendAvailable = false;
    return fallback;
  }
}

// ============================================================================
// Query key factory
// ============================================================================

export const queryKeys = {
  alerts: ['alerts'] as const,
  alertDetail: (id: string) => ['alerts', id] as const,
  beacons: ['beacons'] as const,
  beaconDetail: (id: string) => ['beacons', id] as const,
  dnsThreats: ['dns-threats'] as const,
  dnsThreatDetail: (id: string) => ['dns-threats', id] as const,
  timeline: ['timeline'] as const,
  severityDistribution: ['severity-distribution'] as const,
  dashboardStats: ['dashboard-stats'] as const,
  indicators: ['indicators'] as const,
  mitreMappings: ['mitre-mappings'] as const,
  logStats: ['log-stats'] as const,
  health: ['health'] as const,
};

// ============================================================================
// Hooks
// ============================================================================

/**
 * Fetch all threat alerts.
 */
export function useAlerts(
  options?: Omit<UseQueryOptions<ThreatScore[]>, 'queryKey' | 'queryFn'>,
) {
  return useQuery<ThreatScore[]>({
    queryKey: queryKeys.alerts,
    queryFn: () =>
      fetchOrMock(
        async () => {
          const res = await api.get<ThreatsResponse>('/api/threats');
          return res.threats;
        },
        mockAlerts,
      ),
    staleTime: 60_000,
    ...options,
  });
}

/**
 * Fetch a single alert by entity (IP/domain).
 */
export function useAlertDetail(
  entity: string,
  options?: Omit<UseQueryOptions<ThreatScore | undefined>, 'queryKey' | 'queryFn'>,
) {
  return useQuery<ThreatScore | undefined>({
    queryKey: queryKeys.alertDetail(entity),
    queryFn: () =>
      fetchOrMock(
        async () => {
          const res = await api.get<ApiResponse<ThreatScore>>(
            `/api/threats/${encodeURIComponent(entity)}`,
          );
          return res.data;
        },
        mockAlerts.find((a) => a.entity === entity),
      ),
    enabled: !!entity,
    ...options,
  });
}

/**
 * Fetch beacon detection results.
 */
export function useBeacons(
  options?: Omit<UseQueryOptions<BeaconResult[]>, 'queryKey' | 'queryFn'>,
) {
  return useQuery<BeaconResult[]>({
    queryKey: queryKeys.beacons,
    queryFn: () =>
      fetchOrMock(
        async () => api.get<BeaconResult[]>('/api/analysis/beacons'),
        mockBeacons,
      ),
    staleTime: 60_000,
    ...options,
  });
}

/**
 * Fetch DNS threat results.
 */
export function useDnsThreats(
  options?: Omit<UseQueryOptions<DnsThreatResult[]>, 'queryKey' | 'queryFn'>,
) {
  return useQuery<DnsThreatResult[]>({
    queryKey: queryKeys.dnsThreats,
    queryFn: () =>
      fetchOrMock(
        async () => api.get<DnsThreatResult[]>('/api/analysis/dns-threats'),
        mockDnsThreats,
      ),
    staleTime: 60_000,
    ...options,
  });
}

/**
 * Fetch threat timeline data.
 */
export function useTimeline(
  options?: Omit<UseQueryOptions<ThreatTimelinePoint[]>, 'queryKey' | 'queryFn'>,
) {
  return useQuery<ThreatTimelinePoint[]>({
    queryKey: queryKeys.timeline,
    queryFn: () =>
      fetchOrMock(
        async () => api.get<ThreatTimelinePoint[]>('/api/analysis/timeline'),
        mockTimeline,
      ),
    staleTime: 60_000,
    ...options,
  });
}

/**
 * Fetch severity distribution.
 */
export function useSeverityDistribution(
  options?: Omit<UseQueryOptions<ThreatSeverityDistribution[]>, 'queryKey' | 'queryFn'>,
) {
  return useQuery<ThreatSeverityDistribution[]>({
    queryKey: queryKeys.severityDistribution,
    queryFn: () =>
      fetchOrMock(
        async () =>
          api.get<ThreatSeverityDistribution[]>('/api/analysis/severity-distribution'),
        mockSeverityDistribution,
      ),
    staleTime: 120_000,
    ...options,
  });
}

/**
 * Fetch aggregate dashboard statistics.
 */
export function useDashboardStats(
  options?: Omit<UseQueryOptions<DashboardStats>, 'queryKey' | 'queryFn'>,
) {
  return useQuery<DashboardStats>({
    queryKey: queryKeys.dashboardStats,
    queryFn: () =>
      fetchOrMock(
        async () => api.get<DashboardStats>('/api/analysis/dashboard'),
        mockDashboardStats,
      ),
    staleTime: 30_000,
    ...options,
  });
}

/**
 * Fetch threat indicators.
 */
export function useIndicators(
  options?: Omit<UseQueryOptions<ThreatIndicator[]>, 'queryKey' | 'queryFn'>,
) {
  return useQuery<ThreatIndicator[]>({
    queryKey: queryKeys.indicators,
    queryFn: () =>
      fetchOrMock(
        async () => {
          const res = await api.get<IndicatorsResponse>('/api/indicators');
          return res.indicators;
        },
        mockIndicators,
      ),
    staleTime: 60_000,
    ...options,
  });
}

/**
 * Fetch MITRE ATT&CK mappings.
 */
export function useMitreMappings(
  options?: Omit<UseQueryOptions<MitreMapping[]>, 'queryKey' | 'queryFn'>,
) {
  return useQuery<MitreMapping[]>({
    queryKey: queryKeys.mitreMappings,
    queryFn: () =>
      fetchOrMock(
        async () => {
          const res = await api.get<MitreResponse>('/api/mitre');
          return res.mappings;
        },
        mockMitreMappings,
      ),
    staleTime: 120_000,
    ...options,
  });
}

/**
 * Fetch log ingestion stats.
 */
export function useLogStats(
  options?: Omit<UseQueryOptions<LogStats | null>, 'queryKey' | 'queryFn'>,
) {
  return useQuery<LogStats | null>({
    queryKey: queryKeys.logStats,
    queryFn: () =>
      fetchOrMock(
        async () => api.get<LogStats>('/api/data/stats'),
        null,
      ),
    staleTime: 60_000,
    ...options,
  });
}

/**
 * Check backend health.
 */
export function useHealth(
  options?: Omit<UseQueryOptions<boolean>, 'queryKey' | 'queryFn'>,
) {
  return useQuery<boolean>({
    queryKey: queryKeys.health,
    queryFn: () => isBackendAvailable(),
    staleTime: 15_000,
    refetchInterval: 30_000,
    ...options,
  });
}

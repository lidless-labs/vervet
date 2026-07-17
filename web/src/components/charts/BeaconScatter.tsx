/**
 * BeaconScatter — Scatter plot of beacon analysis.
 * X-axis: average interval, Y-axis: beacon score, bubble size: connection count.
 */
import React, { useMemo } from 'react';
import {
  ScatterChart,
  Scatter,
  XAxis,
  YAxis,
  ZAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
} from 'recharts';
import type { ChartTheme, BeaconResult } from '../../types';
import { defaultChartTheme } from '../../data/mockData';

export interface BeaconScatterProps {
  data: BeaconResult[];
  theme?: ChartTheme;
  height?: number;
  showLegend?: boolean;
}

interface ScatterPoint {
  x: number;
  y: number;
  z: number;
  label: string;
  src_ip: string;
  dst_ip: string;
  jitter: number;
}

const CustomTooltip: React.FC<{
  active?: boolean;
  payload?: Array<{ payload: ScatterPoint }>;
  theme: ChartTheme;
}> = ({ active, payload, theme }) => {
  if (!active || !payload?.length) return null;
  const d = payload[0].payload;
  return (
    <div
      style={{
        backgroundColor: theme.colors.surface,
        border: `1px solid ${theme.colors.gridLine}`,
        borderRadius: 6,
        padding: theme.spacing.tooltipPadding,
        color: theme.colors.text,
        fontSize: theme.fonts.sizeBase,
      }}
    >
      <p style={{ fontWeight: 600, marginBottom: 4 }}>
        {d.src_ip} → {d.dst_ip}
      </p>
      <p>Interval: {d.x.toFixed(0)}s</p>
      <p>Score: {d.y.toFixed(1)}</p>
      <p>Connections: {d.z}</p>
      <p>Jitter: {d.jitter.toFixed(1)}%</p>
    </div>
  );
};

export const BeaconScatter: React.FC<BeaconScatterProps> = ({
  data,
  theme = defaultChartTheme,
  height = 350,
  showLegend = true,
}) => {
  const { highThreats, mediumThreats, lowThreats } = useMemo(() => {
    const high: ScatterPoint[] = [];
    const medium: ScatterPoint[] = [];
    const low: ScatterPoint[] = [];

    data.forEach((b) => {
      const point: ScatterPoint = {
        x: b.avg_interval_seconds,
        y: b.beacon_score,
        z: b.connection_count,
        label: `${b.src_ip}→${b.dst_ip}`,
        src_ip: b.src_ip,
        dst_ip: b.dst_ip,
        jitter: b.jitter_pct,
      };

      if (b.beacon_score >= 85) high.push(point);
      else if (b.beacon_score >= 65) medium.push(point);
      else low.push(point);
    });

    return { highThreats: high, mediumThreats: medium, lowThreats: low };
  }, [data]);

  return (
    <ResponsiveContainer width="100%" height={height}>
      <ScatterChart margin={{ top: 10, right: 20, left: 0, bottom: 10 }}>
        <CartesianGrid
          strokeDasharray="3 3"
          stroke={theme.colors.gridLine}
        />
        <XAxis
          type="number"
          dataKey="x"
          name="Interval (s)"
          domain={[0, 'dataMax + 20']}
          allowDecimals={false}
          tickFormatter={(v: number) => `${Math.round(v)}`}
          tick={{ fill: theme.colors.textSecondary, fontSize: theme.fonts.sizeSmall }}
          label={{
            value: 'Avg Interval (s)',
            position: 'insideBottom',
            offset: -5,
            fill: theme.colors.textSecondary,
            fontSize: theme.fonts.sizeSmall,
          }}
        />
        <YAxis
          type="number"
          dataKey="y"
          name="Score"
          domain={[0, 100]}
          tick={{ fill: theme.colors.textSecondary, fontSize: theme.fonts.sizeSmall }}
          label={{
            value: 'Beacon Score',
            angle: -90,
            position: 'insideLeft',
            fill: theme.colors.textSecondary,
            fontSize: theme.fonts.sizeSmall,
          }}
        />
        <ZAxis type="number" dataKey="z" range={[40, 400]} name="Connections" />
        <Tooltip content={<CustomTooltip theme={theme} />} />
        {showLegend && (
          <Legend
            wrapperStyle={{ fontSize: theme.fonts.sizeSmall, color: theme.colors.textSecondary }}
          />
        )}
        <Scatter
          name="High (≥85)"
          data={highThreats}
          fill={theme.colors.danger}
          fillOpacity={0.7}
          isAnimationActive={false}
        />
        <Scatter
          name="Medium (65-84)"
          data={mediumThreats}
          fill={theme.colors.warning}
          fillOpacity={0.7}
          isAnimationActive={false}
        />
        <Scatter
          name="Low (<65)"
          data={lowThreats}
          fill={theme.colors.success}
          fillOpacity={0.7}
          isAnimationActive={false}
        />
      </ScatterChart>
    </ResponsiveContainer>
  );
};

export default BeaconScatter;

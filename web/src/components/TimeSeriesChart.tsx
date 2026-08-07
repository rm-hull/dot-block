import { useEffect, useMemo, useState } from "react";
import { Chart, useChart } from "@chakra-ui/charts";
import { Area, AreaChart, CartesianGrid, Line, XAxis, YAxis } from "recharts";

interface TimeSeriesPoint {
  time: number;
  count: number;
  avg5min: number;
}

interface TimeSeriesChartProps {
  data?: Record<string, number>;
  height?: number;
  width?: number;
  windowMs?: number;
}

const formatTime = (ms: number) =>
  new Date(ms).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });

export default function TimeSeriesChart({
  data = {},
  height = 200,
  width = 400,
  windowMs = 60 * 60 * 1000,
}: TimeSeriesChartProps) {
  // Track wall-clock time so the visible window keeps scrolling even when
  // no new data arrives. Without this the domain is pinned to the last
  // data point's timestamp, which freezes the chart during quiet periods.
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), 15000);
    return () => clearInterval(id);
  }, []);

  // Convert { "unixMs": count } -> array of { time, count, avg5min },
  // sorted, then keep only the last `windowMs` relative to the latest
  // point or the current wall-clock time, whichever is more recent. The
  // axis domain is fixed so the chart always spans a full `windowMs`
  // window, even if there's less data than that, and keeps scrolling in
  // real time when no new data arrives.
  const { points, domain } = useMemo(() => {
    // 1. Get raw entries, sorted
    const rawEntries = Object.entries(data)
      .map(([time, count]) => ({ time: Number(time), count }))
      .sort((a, b) => a.time - b.time);

    if (rawEntries.length === 0) {
      // No data yet: still anchor the window to the current time so the
      // chart shows a live, scrolling time axis rather than a frozen one.
      return {
        points: [] as TimeSeriesPoint[],
        domain: [now - windowMs, now] as [number, number],
      };
    }

    // Anchor the window end to the current wall-clock time (or the most
    // recent data point, whichever is later) so the chart keeps scrolling
    // and ages data out as time passes, even between data updates.
    const latest = Math.max(rawEntries[rawEntries.length - 1].time, now);
    const cutoff = latest - windowMs;

    // 2. Densify: fill gaps and trailing quiet periods up to 'latest' with 0
    const all: Array<{ time: number; count: number }> = [];
    const first = rawEntries[0].time;
    const dataMap = new Map(rawEntries.map((e) => [e.time, e.count]));

    for (let t = first; t <= latest; t += 60000) {
      if (t >= cutoff) {
        all.push({ time: t, count: dataMap.get(t) ?? 0 });
      }
    }

    // Compute a 5-minute rolling average across the full (sorted) dataset
    // using a sliding window, so points near the start of the visible window
    // still have an accurate average based on preceding data.
    const ROLLING_WINDOW_MS = 5 * 60 * 1000;
    const points: TimeSeriesPoint[] = [];
    let left = 0;
    let runningSum = 0;
    for (let right = 0; right < all.length; right++) {
      runningSum += all[right].count;
      const windowStart = all[right].time - ROLLING_WINDOW_MS;
      while (all[left].time < windowStart) {
        runningSum -= all[left].count;
        left++;
      }
      const windowCount = right - left + 1;
      if (all[right].time >= cutoff) {
        points.push({
          ...all[right],
          avg5min: runningSum / windowCount,
        });
      }
    }

    return {
      points,
      domain: [cutoff, latest] as [number, number],
    };
  }, [data, now, windowMs]);

  const chart = useChart({
    data: points,
    sort: { by: "time", direction: "asc" },
    // Render order matters: SVG uses the painter's model, so iterate the
    // rolling-average line first so it draws *behind* the count area.
    series: [
      { name: "avg5min", color: "red.solid" },
      { name: "count", color: "teal.solid" },
    ],
  });

  return (
    <Chart.Root chart={chart} maxH={`${height}px`} width={`${width}px`}>
      <AreaChart data={chart.data} responsive>
        <defs>
          <Chart.Gradient
            id="count-gradient"
            stops={[
              { offset: "0%", color: "teal.solid", opacity: 0.4 },
              { offset: "100%", color: "teal.solid", opacity: 0.02 },
            ]}
          />
        </defs>
        <CartesianGrid stroke={chart.color("border.muted")} vertical={false} />
        <XAxis
          dataKey={chart.key("time")}
          type="number"
          domain={domain}
          scale="time"
          minTickGap={40}
          tickFormatter={formatTime}
          stroke={chart.color("border")}
        />
        <YAxis allowDecimals={false} stroke={chart.color("border")} />
        {chart.series.map((item) => {
          const isRollingAvg = item.name === "avg5min";
          if (isRollingAvg) {
            // Rolling average rendered as a dotted red line, no fill.
            return (
              <Line
                key={item.name}
                type="monotone"
                dataKey={chart.key(item.name)}
                stroke={chart.color(item.color)}
                strokeWidth={2}
                strokeDasharray="4 4"
                strokeLinecap="round"
                dot={false}
                animationDuration={600}
                animationEasing="ease-out"
              />
            );
          }
          return (
            <Area
              key={item.name}
              type="monotone"
              dataKey={chart.key(item.name)}
              stroke={chart.color(item.color)}
              fill="url(#count-gradient)"
              strokeWidth={2}
              dot={false}
              animationDuration={600}
              animationEasing="ease-out"
            />
          );
        })}
      </AreaChart>
    </Chart.Root>
  );
}

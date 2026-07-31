import { useMemo } from "react";
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
  // Convert { "unixMs": count } -> array of { time, count, avg5min },
  // sorted, then keep only the last `windowMs` relative to the latest
  // point. Also compute a fixed axis domain so the chart always spans a
  // full `windowMs` window, even if there's less data than that.
  const { points, domain } = useMemo(() => {
    const all = Object.entries(data)
      .map(([time, count]) => ({ time: Number(time), count }))
      .sort((a, b) => a.time - b.time);

    if (all.length === 0) {
      return { points: [] as TimeSeriesPoint[], domain: undefined as [number, number] | undefined };
    }

    const latest = all[all.length - 1].time;
    const cutoff = latest - windowMs;

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
  }, [data, windowMs]);

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
          domain={domain ?? ["dataMin", "dataMax"]}
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

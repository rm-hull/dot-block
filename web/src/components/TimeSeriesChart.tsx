import { useMemo } from "react";
import { Chart, useChart } from "@chakra-ui/charts";
import { Area, AreaChart, CartesianGrid, XAxis, YAxis } from "recharts";

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
  // Convert { "unixMs": count } -> array of { time, count }, sorted,
  // then keep only the last `windowMs` relative to the latest point.
  // Also compute a fixed axis domain so the chart always spans a full
  // `windowMs` window, even if there's less data than that.
  const { points, domain } = useMemo(() => {
    const all = Object.entries(data)
      .map(([time, count]) => ({ time: Number(time), count }))
      .sort((a, b) => a.time - b.time);

    if (all.length === 0) {
      return { points: all, domain: undefined as [number, number] | undefined };
    }

    const latest = all[all.length - 1].time;
    const cutoff = latest - windowMs;
    return {
      points: all.filter((p) => p.time >= cutoff),
      domain: [cutoff, latest] as [number, number],
    };
  }, [data, windowMs]);

  const chart = useChart({
    data: points,
    sort: { by: "time", direction: "asc" },
    series: [{ name: "count", color: "teal.solid" }],
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
        <Chart.Tooltip labelFormatter={(label) => formatTime(label)} />
        {chart.series.map((item) => (
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
        ))}
      </AreaChart>
    </Chart.Root>
  );
}

/*
Usage:

import EventsTimeSeriesChart from "./EventsTimeSeriesChart";

const data = {
  "1784579040000": 41,
  "1784579100000": 61,
  // ...
};

<EventsTimeSeriesChart data={data} />
*/
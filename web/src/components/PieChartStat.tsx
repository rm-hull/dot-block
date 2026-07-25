import { Chart, useChart } from "@chakra-ui/charts"
import { Pie, PieChart, Sector, Legend } from "recharts"

export interface DataPoint {
  name: string
  value: number
  color?: string
}

interface PieChartStatProps {
  data: DataPoint[]
}

export function PieChartStat({ data }: PieChartStatProps) {
  const chart = useChart({ data })

  return (
    <Chart.Root boxSize="200px" mx="auto" chart={chart}>
      <PieChart responsive>
        <Legend content={<Chart.Legend />} />
        <Pie
          isAnimationActive={false}
          data={chart.data}
          dataKey={chart.key("value")}
          nameKey="name"
          shape={(props) => (
            <Sector {...props} fill={chart.color(props.payload!.color)} />
          )}
        />
      </PieChart>
    </Chart.Root>
  )
}
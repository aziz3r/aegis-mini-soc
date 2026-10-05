/** Charts.
 *
 *  Rules applied here, deliberately:
 *
 *  * **One axis per chart, always.** The anomaly score (0–1) and the flow count
 *    (an integer) are different units, so they are two charts rather than one
 *    chart with two y-scales. A dual axis lets the reader invent a correlation
 *    that the data does not contain.
 *  * **The threshold is an annotation, not a series.** It is drawn in a
 *    low-chroma grey, dashed, and labelled in place, so it recedes behind the
 *    data it qualifies.
 *  * **Single hue where identity comes from labels.** The family breakdown and
 *    the feature contributions are magnitudes with named rows; colouring each
 *    row differently would add a legend and no information.
 *  * **Two series means a legend and direct labels.** The flows/alerts pair was
 *    validated for colour-vision separation (normal ΔE 29.0, CVD ΔE 19.2).
 */
import type { ReactNode } from 'react'
import {
  Area, AreaChart, Bar, BarChart, CartesianGrid, Cell, Line, LineChart,
  ReferenceLine, ResponsiveContainer, Tooltip, XAxis, YAxis,
} from 'recharts'
import { clock, num, score as fmtScore } from '../lib/format'
import type { Contribution } from '../lib/types'

const SERIES_1 = 'var(--series-1)'
const SERIES_2 = 'var(--series-2)'
const ANNOTATION = 'var(--annotation)'

const tooltipStyle = {
  backgroundColor: '#0b1220',
  border: '1px solid #2b4270',
  borderRadius: 10,
  fontSize: 12,
  padding: '8px 10px',
  boxShadow: '0 10px 30px rgba(0,0,0,.45)',
} as const

function Legend({ items }: { items: { label: string; color: string }[] }) {
  return (
    <ul className="flex flex-wrap items-center gap-4 text-xs text-slate-400">
      {items.map((it) => (
        <li key={it.label} className="inline-flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rounded-sm" style={{ background: it.color }} aria-hidden />
          {it.label}
        </li>
      ))}
    </ul>
  )
}

export interface ScorePoint {
  ts: string; score_mean: number; score_max: number; threshold: number
}

/** Anomaly level over time.
 *
 *  Two series, one unit, one axis: the mean score says how unusual the traffic
 *  is overall, the peak says how unusual its single worst flow was.
 *
 *  The peak alone would be useless. Stage A scores are the empirical CDF of
 *  benign traffic, so the maximum of N flows is near 1 almost every second by
 *  construction - measured here, 58% of seconds sit above 0.95 with nothing
 *  wrong. A chart that is pinned to its ceiling teaches an operator to ignore it.
 *  The mean is what actually moves when something happens.
 *
 *  The threshold is drawn as a dashed annotation and labelled as applying *per
 *  flow*, because that is what it is compared against - never the mean.
 */
export function ScoreChart({ data, height = 260 }: { data: ScorePoint[]; height?: number }) {
  const threshold = data.length ? (data[data.length - 1]?.threshold ?? 0.98) : 0.98
  return (
    <figure className="m-0">
      <figcaption className="mb-3 flex flex-wrap items-center justify-between gap-3">
        <Legend items={[
          { label: 'Score moyen du trafic', color: SERIES_1 },
          { label: 'Score du flux le plus anormal', color: SERIES_2 },
        ]} />
        <span className="text-xs text-slate-500">
          seuil par flux <span className="tabular-nums text-slate-400">{fmtScore(threshold)}</span>
        </span>
      </figcaption>
      <div style={{ height }}>
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={data} margin={{ top: 6, right: 10, left: 0, bottom: 0 }}>
            <defs>
              <linearGradient id="scoreFill" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#3987e5" stopOpacity={0.3} />
                <stop offset="100%" stopColor="#3987e5" stopOpacity={0.02} />
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="2 4" vertical={false} />
            <XAxis dataKey="ts" tickFormatter={clock} minTickGap={48} tickLine={false} />
            <YAxis domain={[0, 1]} ticks={[0, 0.25, 0.5, 0.75, 1]} width={42}
                   tickLine={false} axisLine={false} />
            <Tooltip
              contentStyle={tooltipStyle}
              labelFormatter={(v: unknown) => clock(String(v))}
              formatter={(value: number, name: unknown) => [
                fmtScore(value), name === 'score_max' ? 'flux le plus anormal' : 'score moyen',
              ]}
            />
            <ReferenceLine y={threshold} stroke={ANNOTATION} strokeDasharray="5 4" strokeWidth={1.5}
              label={{ value: 'seuil par flux', position: 'insideTopRight', fill: '#94a3b8', fontSize: 11 }} />
            <Area type="monotone" dataKey="score_mean" stroke={SERIES_1} strokeWidth={2}
              fill="url(#scoreFill)" dot={false} isAnimationActive={false} name="score_mean" />
            <Line type="monotone" dataKey="score_max" stroke={SERIES_2} strokeWidth={1.5}
              dot={false} isAnimationActive={false} name="score_max" />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </figure>
  )
}

export interface ActivityPoint { ts: string; flows: number; alerts: number }

/** Flows and alerts share one axis legitimately: both are counts of the same
 *  thing per second. */
export function ActivityChart({ data, height = 180 }: { data: ActivityPoint[]; height?: number }) {
  return (
    <figure className="m-0">
      <figcaption className="mb-3">
        <Legend items={[{ label: 'Flux analysés/s', color: SERIES_1 }, { label: 'Alertes/s', color: SERIES_2 }]} />
      </figcaption>
      <div style={{ height }}>
        <ResponsiveContainer width="100%" height="100%">
          <LineChart data={data} margin={{ top: 6, right: 10, left: 0, bottom: 0 }}>
            <CartesianGrid strokeDasharray="2 4" vertical={false} />
            <XAxis dataKey="ts" tickFormatter={clock} minTickGap={48} tickLine={false} />
            <YAxis allowDecimals={false} width={42} tickLine={false} axisLine={false} />
            <Tooltip contentStyle={tooltipStyle} labelFormatter={(v: unknown) => clock(String(v))}
              formatter={(value: number, name: unknown) => [num(value), name === 'flows' ? 'flux' : 'alertes']} />
            <Line type="monotone" dataKey="flows" stroke={SERIES_1} strokeWidth={2} dot={false}
              isAnimationActive={false} name="flows" />
            <Line type="monotone" dataKey="alerts" stroke={SERIES_2} strokeWidth={2} dot={false}
              isAnimationActive={false} name="alerts" />
          </LineChart>
        </ResponsiveContainer>
      </div>
    </figure>
  )
}

/** Horizontal magnitude bars, single hue: the row labels carry identity. */
export function RankedBars({ rows, height, valueFormat = num, emptyLabel = 'aucune donnée' }: {
  rows: { label: string; value: number; hint?: string }[]
  height?: number
  valueFormat?: (v: number) => string
  emptyLabel?: string
}) {
  if (!rows.length) return <p className="py-8 text-center text-xs text-slate-600">{emptyLabel}</p>
  const max = Math.max(...rows.map((r) => r.value), 1)
  return (
    <ul className="space-y-2.5" style={height ? { height, overflowY: 'auto' } : undefined}>
      {rows.map((row) => (
        <li key={row.label}>
          <div className="flex items-baseline justify-between gap-3 text-xs">
            <span className="truncate text-slate-300" title={row.label}>{row.label}</span>
            <span className="tabular-nums text-slate-400 shrink-0">{valueFormat(row.value)}</span>
          </div>
          <div className="mt-1 h-1.5 rounded-full bg-ink-800 overflow-hidden">
            {/* 4px rounded data-end, anchored to the baseline */}
            <div className="h-full rounded-r-[4px]" role="presentation"
                 style={{ width: `${Math.max((row.value / max) * 100, 2)}%`, background: SERIES_1 }} />
          </div>
          {row.hint && <p className="mt-0.5 text-[11px] text-slate-600">{row.hint}</p>}
        </li>
      ))}
    </ul>
  )
}

/** "Why was this flagged": occlusion attribution, one row per feature.
 *  Direction is encoded by an arrow and words, not by colour. */
export function ContributionBars({ contributions }: { contributions: Contribution[] }) {
  if (!contributions.length) {
    return (
      <p className="text-xs text-slate-600">
        Aucune attribution enregistrée pour cet incident (le budget d'explication est réservé
        aux alertes les plus fortes de chaque lot).
      </p>
    )
  }
  const max = Math.max(...contributions.map((c) => c.impact), 0.001)
  return (
    <ul className="space-y-3">
      {contributions.map((c) => (
        <li key={c.feature}>
          <div className="flex items-baseline justify-between gap-3">
            <span className="text-sm text-slate-200">{c.feature}</span>
            <span className="shrink-0 text-xs tabular-nums text-slate-400">
              {(c.impact * 100).toFixed(0)} %
            </span>
          </div>
          <div className="mt-1.5 h-2 rounded-full bg-ink-800 overflow-hidden">
            <div className="h-full rounded-r-[4px]"
                 style={{ width: `${Math.max((c.impact / max) * 100, 3)}%`, background: SERIES_1 }} />
          </div>
          <p className="mt-1 text-[11px] text-slate-500 tabular-nums">
            mesuré <span className="text-slate-300">{fmtScore(c.value, c.value > 100 ? 0 : 3)}</span>
            {' · '}référence <span className="text-slate-400">{fmtScore(c.baseline, c.baseline > 100 ? 0 : 3)}</span>
            {' · '}
            <span className="text-slate-400">
              {c.direction === 'above' ? '↑ au-dessus de la normale' : '↓ en dessous de la normale'}
            </span>
          </p>
        </li>
      ))}
    </ul>
  )
}

/** Alert volume per hour: single hue sequential, magnitude by height. */
export function HourlyBars({ rows, height = 150 }: { rows: { hour: string; total: number }[]; height?: number }) {
  if (!rows.length) return <p className="py-8 text-center text-xs text-slate-600">aucun incident sur la période</p>
  const max = Math.max(...rows.map((r) => r.total), 1)
  return (
    <div style={{ height }}>
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={rows} margin={{ top: 6, right: 10, left: 0, bottom: 0 }} barCategoryGap="22%">
          <CartesianGrid strokeDasharray="2 4" vertical={false} />
          <XAxis dataKey="hour" tickFormatter={(v: string) => v.slice(11, 13) + 'h'} minTickGap={24} tickLine={false} />
          <YAxis allowDecimals={false} width={42} tickLine={false} axisLine={false} />
          <Tooltip contentStyle={tooltipStyle}
            labelFormatter={(v: unknown) => String(v).replace('T', ' ')}
            formatter={(value: number) => [num(value), 'incidents']} />
          <Bar dataKey="total" radius={[4, 4, 0, 0]} isAnimationActive={false}>
            {rows.map((r) => (
              // lightness carries magnitude: one hue, light -> dark
              <Cell key={r.hour} fill={SERIES_1} fillOpacity={0.35 + 0.65 * (r.total / max)} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  )
}

export function SparkLine({ data, dataKey, height = 46 }: {
  data: Record<string, number | string>[]; dataKey: string; height?: number
}) {
  return (
    <div style={{ height }}>
      <ResponsiveContainer width="100%" height="100%">
        <LineChart data={data} margin={{ top: 4, right: 2, left: 2, bottom: 0 }}>
          <Line type="monotone" dataKey={dataKey} stroke={SERIES_1} strokeWidth={2} dot={false}
                isAnimationActive={false} />
        </LineChart>
      </ResponsiveContainer>
    </div>
  )
}

/** Fallback for any table the charts summarise: identity never rests on colour. */
export function TableView({ caption, head, rows }: { caption: string; head: string[]; rows: ReactNode[][] }) {
  return (
    <details className="mt-3">
      <summary className="cursor-pointer text-xs text-slate-500 hover:text-slate-300">
        Voir les données sous forme de tableau
      </summary>
      <table className="mt-2 w-full">
        <caption className="sr-only">{caption}</caption>
        <thead><tr>{head.map((h) => <th key={h} className="th">{h}</th>)}</tr></thead>
        <tbody className="divide-y divide-ink-800">
          {rows.map((r, i) => (
            <tr key={i}>{r.map((cell, j) => <td key={j} className="td text-slate-300">{cell}</td>)}</tr>
          ))}
        </tbody>
      </table>
    </details>
  )
}

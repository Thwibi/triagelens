/**
 * Request-body types derived from the backend's generated OpenAPI document.
 *
 * `openapi.d.ts` is produced from the live FastAPI schema (see
 * `scripts/export_openapi.py` and `npm run gen:api`), so these aliases stay in
 * step with the backend automatically. The document only describes request
 * bodies (responses are untyped `dict`s server-side), so response shapes remain
 * hand-written in `./types`.
 */
import type { components } from './openapi'
import type { DetectionProfile } from './types'

type Schemas = components['schemas']

/** The generated schema under `components/schemas` with the given name. */
type Schema<K extends keyof Schemas> = Schemas[K]

export type PatchCaseBody = Schema<'CasePatch'>
export type ResolveSourceBody = Schema<'ResolveRequest'>
export type PatchSourceBody = Schema<'SourceUpdate'>
export type PreviewProfileBody = Schema<'PreviewRequest'>
export type SaveProfileBody = Schema<'ProfileWrite'>
export type AlertPatchBody = Schema<'AlertPatchBody'>
export type AlertBulkBody = Schema<'AlertBulkBody'>
export type RuleYamlBody = Schema<'RuleYamlBody'>
export type RuleEnabledBody = Schema<'RuleEnabledBody'>
export type RuleTestBody = Schema<'RuleTestBody'>
export type SettingsUpdateBody = Schema<'SettingsUpdateBody'>
export type AllowlistBody = Schema<'AllowlistBody'>

/**
 * The generate schema types `profile` and `rule_ids` loosely; re-narrow them to
 * the literals the UI actually offers while keeping the generated field set.
 */
export type DetectBody = Omit<Schema<'DetectRequest'>, 'profile' | 'rule_ids'> & {
  readonly profile?: DetectionProfile
  readonly rule_ids?: readonly string[]
}

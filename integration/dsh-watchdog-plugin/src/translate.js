/** Translate a DSH ToolExecution into the watchdog Action vocabulary. */
export function translateAction(exec, previewLimit = 400) {
  const name = exec?.name || 'unknown'
  const args = (exec?.arguments && typeof exec.arguments === 'object')
    ? exec.arguments : {}
  const clip = (v) => String(typeof v === 'string' ? v : JSON.stringify(v ?? null))
    .slice(0, previewLimit)

  // Server-side retrieval still sends the query to the provider — judge it as egress.
  if (name === 'web_search' || name === 'webSearch') {
    const q = clip(args.query ?? '')
    return { kind: 'network', tool: name, target: `api.deepseek.com/web_search?q=${q}`,
             payload: q, note: 'server-side retrieval via DeepSeek API' }
  }
  // Shell family: judge the command text.
  if (args.command !== undefined) {
    return { kind: 'tool_call', tool: name, target: clip(args.command),
             payload: clip(args.command), note: '' }
  }
  // Filesystem family.
  const pathArg = args.path ?? args.file_path ?? args.file ?? args.filename
  if (pathArg !== undefined) {
    const isWrite = /write|str[_-]?replace|edit|create|move|remove|delete|mkdir/i.test(name)
    return { kind: isWrite ? 'file_write' : 'file_read', tool: name,
             target: String(pathArg),
             payload: isWrite ? clip(args.content ?? args.new_string ?? '') : '',
             note: '' }
  }
  return { kind: 'tool_call', tool: name, target: clip(args), payload: clip(args), note: '' }
}

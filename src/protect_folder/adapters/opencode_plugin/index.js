// protect-folder: OpenCode (v2 server plugin) pre-execution inspection (L2).
//
// Every tool call is passed to the root-owned Python inspector (the SAME engine and hook script as the
// Claude Code adapter). Anything other than a clean "allow" blocks the call: an inspector that cannot run,
// times out, or crashes means DENY (fail closed). The plugin never executes or evaluates the inspected source.
//
// OpenCode itself starts normally when a plugin fails to load, so the launcher proves the plugin is live
// before starting the real session: if PF_HANDSHAKE and PF_NONCE are set, setup() writes them to that file.
import { spawnSync } from "node:child_process"
import fs from "node:fs"

const TIMEOUT_MS = 12000

export default {
  id: "protect-folder",
  async setup(ctx) {
    const o = ctx.options || {}
    if (typeof o.python !== "string" || typeof o.hook !== "string") {
      throw new Error("protect-folder plugin: missing python/hook options")
    }
    const args = ["-I", "-S", o.hook, ...(Array.isArray(o.args) ? o.args.map(String) : [])]
    const cwd = (ctx.location && ctx.location.directory) || process.cwd()

    const inspect = (tool, input) => {
      let r
      try {
        r = spawnSync(o.python, args, {
          input: JSON.stringify({ hook_event_name: "PreToolUse", tool_name: String(tool), tool_input: input ?? {}, cwd }),
          timeout: TIMEOUT_MS, encoding: "utf8", maxBuffer: 1 << 20,
          env: { PATH: "/usr/bin:/bin", HOME: process.env.HOME || "/", XDG_STATE_HOME: process.env.XDG_STATE_HOME || "" },
        })
      } catch (e) {
        return { block: true, reason: "protect-folder: inspector could not run; blocked (fail-closed)" }
      }
      if (r.error || r.status === null) return { block: true, reason: "protect-folder: inspector failed or timed out; blocked (fail-closed)" }
      if (r.status === 0) return { block: false }
      return { block: true, reason: ((r.stderr || "").trim() || "protect-folder: blocked").slice(0, 400) }
    }

    // 1) before any tool executes (covers every tool, including ones that are not permission-gated)
    await ctx.tool.hook("execute.before", (event) => {
      const d = inspect(event.tool, event.input)
      if (d.block) throw new Error(d.reason)
    })

    // 2) at permission evaluation (belt and braces: a second, independent decision point)
    await ctx.permission.hook("evaluate", (event) => {
      const res = Array.isArray(event.resources) ? event.resources.map(String) : []
      let d
      if (event.action === "shell") d = inspect("shell", { command: res.join("\n") })
      else if (["read", "edit", "external_directory"].includes(event.action)) {
        // glob/grep/list carry a pattern (not a path) as their permission resource; their structured
        // `path` input is inspected by execute.before above
        d = { block: false }
        for (const r of res) {
          const x = inspect(event.action === "edit" ? "edit" : "read", { path: r })
          if (x.block) { d = x; break }
        }
      } else d = { block: false }
      if (d.block) { event.effect = "deny"; event.message = d.reason }
    })

    if (process.env.PF_HANDSHAKE && process.env.PF_NONCE) {
      fs.writeFileSync(process.env.PF_HANDSHAKE, JSON.stringify({ id: "protect-folder", nonce: process.env.PF_NONCE }))
    }
  },
}

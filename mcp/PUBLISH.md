# Publishing `@cubiczan/compliance-as-code-mcp`

Packaging is prepared. **Do not run `npm publish` in this repository's CI or agent runs** — there is no npm token by design.

When a human is ready:

```bash
cd mcp
npm run build
npm pack          # inspect the tarball
# npm publish --access public   # only with an interactive Cubiczan npm login
```

Cargo packaging for the engine is unchanged: `cargo build --release -p cac-cli`. The MCP package is the pipe; `cac` is the lock.

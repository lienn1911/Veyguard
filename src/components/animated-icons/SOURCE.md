# Animated icons

Source: https://github.com/pqoqubbw/icons

Pinned commit: `4662fff2b60fdcf4751b32013606756caf7c4c26`

Selected icon components retain their upstream animation variants. Local adaptations add a React import for Vite and replace the class-name helper with a local implementation, and use inline span wrappers instead of div wrappers. The shared Icon wrapper handles parent interaction and reduced motion.

MIT license: see LICENSE.

## UI meanings

Navigation uses Home, Workflow (Investigations), History (Audit log) and Settings. The review queue uses Layers; approved work uses Clipboard Check. Database storage uses Database Backup. Connection testing uses Plug Zap, settings saving uses File Cog, report saving uses File Check and PDF export uses Download. Record viewing uses Folder Open, copy confirmation uses Check Check, network direction uses Route, sign-in uses Log In, and navigation uses directional arrows/chevrons. Close, password visibility and dropdown controls retain a consistent symbol wherever the same action appears.

Animations play on the parent control's pointer entry, focus and click. They stop on pointer leave or focus exit. The wrapper respects prefers-reduced-motion and keeps decorative icons out of the accessibility tree.

# ShowDown design reference and review

Reference: showdown-concept.png in the delivered outputs. Generated full-screen 1536 x 1024 dashboard concept, used as the visual direction rather than a user-approved pixel specification.

Tokens: background #080e10; panel #10191b; border #243335; mint #9af6ce; body #e7eeec; muted #8b9f9f. Severity colors coral #fc7379, amber #f9ac68, yellow #ecd371 and mint #80e4be. Space Grotesk headings, DM Sans interface, monospace hostnames. Small 5-7px control/panel radii, restrained borders and no raster UI.

## Comparison ledger

| Point | Concept / implementation review |
|---|---|
| Layout | Left navigation, four metrics, activity + donut, asset + finding panels, history preserved. Added scope/export controls and an explicit demo banner for functional requirements; full overview scrolls vertically. |
| Palette | Charcoal/green surfaces, mint primary actions, restrained semantic colors preserved. |
| Typography | Distinctive sans headings and legible UI labels; table/control fonts increased after screenshot review. |
| Icons | Consistent outlined shield, navigation and metric icons using Lucide. |
| Tables | Compact data rows, port chips, severity indicators, inspect actions and horizontal mobile scrolling. |
| Charts | Code-native area chart and donut; values are derived, not copied from concept. |
| Copy | Main title, subtitle, six navigation labels and New scan preserved. Added connection, demo and severity provenance text deliberately. |
| Responsive | 1536x1024 desktop viewport and 390x844 mobile checked. Mobile uses a two-column metric grid, stacked panels and toggle navigation. |

Intentional deviations: remove fabricated deltas and unsupported critical vulnerabilities from concept; sample hosts use reserved .example domains; findings show flags that actually exist in worker code; chart history derives from sample/API records; history includes IDs and completion timestamps. The extra workspace/scope/export controls support the requested operational workflows. This is not a pixel-identical copy of the generated concept.

Concept and final desktop/mobile screenshots inspected with view_image. No clipping or page-level horizontal overflow observed in tested viewports; wide tables scroll within their own panel. Visual direction faithfully carried through with the above documented functional differences.

# Design Tokens

## Canvas

- Calm by default
- Soft grid
- Light and dark mode ready
- Muted background
- No heavy engineering-paper grid

## Nodes

Default node:
- width: 188px
- radius: 14px
- compact card style
- role icon
- hostname
- health badge
- vendor/model line
- site/rack/role line
- small metric row

## Health

Use health rings and badges, not full red/orange node fills.

States:
- ok
- warning
- critical
- unknown
- maintenance

## Edges

Default:
- muted gray
- no always-on labels
- hover shows detail

Selected path:
- stronger stroke
- higher contrast
- unrelated graph dimmed

Confidence:
- solid = confirmed
- dashed = inferred
- dotted = low confidence

## Typography

- hostname: 13px / 600
- metadata: 11px
- badges: 10px uppercase
- drawer title: 16px / 600

## Interaction

Hover:
- highlight first-degree neighbors
- show edge ports and confidence

Click node:
- open side drawer
- dim unrelated graph

Click edge:
- open evidence and confidence panel

Incident mode:
- highlight RCA path
- dim background
- show affected nodes

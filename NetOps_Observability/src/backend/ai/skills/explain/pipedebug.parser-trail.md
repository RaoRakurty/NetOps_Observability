---
topic: pipedebug.parser-trail
question: What is the parser decision trail?
keywords: parser marker, decision trail, real unmarked record, bounded window
---
Arm it with a piece of text and, for a bounded window, the parser records how
it decided about every real record containing that text — which pattern
matched, which fields it produced, why it fell through. It works on ordinary
traffic, so it is the tool for a record you cannot re-send. It turns itself
off when the window ends.

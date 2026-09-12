---
topic: exposures.pagination
question: How does Load more work?
keywords: cursor pagination, load more, rows appended, never re-ordered
---
The list is cursor-paginated: Load more fetches the next page from where the
last one ended and appends it. Rows already on screen are never re-ordered or
re-fetched, so a row you were reading does not move under the cursor while more
arrive. The count beside the toolbar says how many of the matching total are
loaded so far.

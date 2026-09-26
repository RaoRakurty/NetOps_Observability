---
title: Query Correlix in the GraphQL Explorer
sidebar_label: GraphQL Explorer
description: Run a GraphQL query against the typed /api/graphql endpoint from the console and read the JSON response, starting from ready-made example queries.
page_type: task
sidebar_position: 23
---

# Query Correlix in the GraphQL Explorer

**Platform → Tools → GraphQL Explorer** is a query console for the typed
`/api/graphql` endpoint. It runs in the console, under your own sign-in, with
no external GraphiQL bundle. Use it to try a query before you put it in a
script.

## Before you begin

- A platform administrator account to open the page, which sits under
  **Platform → Tools**.
- The endpoint itself needs `infrastructure:read`. Results are tenant-scoped:
  a query returns only the rows the signed-in account may read.

## Steps

1. Go to **Platform → Tools → GraphQL Explorer**.
2. Select an example to load it into the editor: **Devices**, **Active
   alerts**, **Rules**, **Health** or **Schema**.
3. Edit the query. For example:

   ```graphql
   { devices { id name address vendor } }
   ```

4. Select **Run query**.

## What you see

The JSON response in the right-hand pane. A query that fails shows the reason
under the editor and leaves the result pane empty.

To call the same endpoint from a script, `POST` the query to `/api/graphql`
with an API key. See [Mint an API key](/administration/api-access) and the
[API reference](/reference/api).

## Related

- [API reference](/reference/api)
- [Mint an API key](/administration/api-access)

---
topic: notify.sns-credentials
question: Where do the AWS credentials come from?
keywords: aws credentials, sns, environment, never stored
---
From the deployment environment — `AWS_ACCESS_KEY_ID` and
`AWS_SECRET_ACCESS_KEY`, or whatever the host's instance role provides. They
are never entered here, never stored by the platform and never returned by the
API, so this page can only report whether they are present. Change them where
the stack is deployed; the status chip will follow.

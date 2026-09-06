---
topic: backup.external-job
question: What does external, not governed here mean?
keywords: external job, not governed here, host cron backup
---
Something outside this platform — usually a host cron job — owns that backup.
The platform can see that it exists and report what it last said, but it cannot
schedule, run, verify or restore it from here. It is named as external rather
than claimed, so nobody reads the page as proof the platform is protecting
that data. Change it where it is defined.

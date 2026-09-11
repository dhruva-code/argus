# db/migrations

Reserved for raw-SQL migrations or seed SQL used outside the application
(e.g. analytics replicas). The **authoritative** schema migrations are Alembic
revisions under [`apis/gateway/alembic/versions`](../../apis/gateway/alembic/versions).

Apply with `make migrate` (or `alembic upgrade head` from `apis/gateway`).

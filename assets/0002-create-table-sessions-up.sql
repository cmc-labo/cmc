CREATE TABLE sessions (
    id integer PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    session_token text NOT NULL
);